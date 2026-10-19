"""S3 operation models over the clients' existing HTTP transports.

S3 answers in XML whose shape AWS publishes as a service model, and
``botocore`` ships both the model and a parser for it. Using them, rather
than hand-walking ``ElementTree`` nodes, gets namespaces, timestamps, number
fields, list-vs-scalar ambiguities and error documents right the way every
AWS SDK does. What this module adds is the seam: our own HTTP client fetches
the bytes, :func:`xrdcore.safexml.fromstring` parses them with the
billion-laughs/external-entity defences botocore's parser does not apply,
and the already-parsed tree is handed to botocore so it never touches the
raw payload.

Every S3 client sits on it - xrdclient's ``S3FileSystem`` and xgfalclient's
S3 plugin both call :func:`decode`, :func:`listing_items`, :func:`manifest`
and :func:`modified` - so these signatures are load-bearing beyond this
package.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any
from xml.etree import ElementTree as ET

from botocore.loaders import create_loader
from botocore.model import ServiceModel
from botocore.parsers import RestXMLParser
from botocore.serialize import create_serializer
from botocore.utils import parse_timestamp

from xrdcore.safexml import fromstring

__all__ = ["decode", "listing_items", "manifest", "modified"]


@lru_cache(maxsize=1)
def _model() -> Any:
    """The S3 service model, loaded on first use and then kept for the process.

    It is several megabytes of JSON, so it is read only when an S3 answer
    first needs decoding - importing this module does not - and only once.
    It comes straight from botocore's bundled data: a ``Session`` would also
    read the AWS configuration files and environment, none of which a model
    needs, and would let ``$AWS_DATA_PATH`` substitute a different one.
    Nothing here discovers credentials or contacts AWS.
    """
    return ServiceModel(create_loader().load_service_model("s3", "service-2"), "s3")


def _timestamp(value: str) -> datetime:
    """botocore's timestamp parsing, with the epoch for an unparsable value.

    Some S3 implementations put odd or empty ``LastModified`` values in a
    listing; one bad entry should read as "unknown" (the epoch) rather than
    fail the whole listing.
    """
    try:
        return parse_timestamp(value)
    except ValueError:
        return datetime.fromtimestamp(0, UTC)


class _Parser(RestXMLParser):
    """botocore's REST-XML parser, fed a tree we parsed ourselves.

    botocore would parse the payload with a plain ``XMLParser``; overriding
    its one parsing hook to return our pre-checked ``root`` is what keeps
    the entity and DTD defences of :mod:`xrdcore.safexml` in force.
    """

    def __init__(self, root: ET.Element | None, lenient: bool) -> None:
        """Remember the tree to hand back and whether bad integers are tolerated."""
        super().__init__(timestamp_parser=_timestamp)
        self.root = root
        self.lenient = lenient

    def _parse_xml_string_to_dom(self, payload: bytes) -> ET.Element | None:
        # The hook botocore calls with the raw body; ``payload`` is ignored.
        return self.root

    def _handle_integer(self, shape: Any, node: ET.Element) -> int:
        """An integer field; under ``lenient``, junk reads as 0 instead of raising.

        gfal2's reading is lenient, so an empty or non-numeric ``Size`` from
        a third-party implementation does not fail a whole listing; a
        filesystem facade decodes strictly, because a wrong count or size
        must not pass quietly there.
        """
        text = (node.text or "").strip()
        return 0 if self.lenient and not text.isdigit() else int(text or 0)

    _handle_long = _handle_integer


def decode(
    operation: str,
    payload: bytes,
    *,
    status: int = 200,
    headers: Mapping[str, str] | None = None,
    lenient: bool = False,
) -> dict[str, Any]:
    """Decode a modeled answer, including errors embedded in HTTP 200.

    Declaration checks run before botocore sees the tree; namespaces and
    modeled timestamps, numbers, lists and headers are handled by botocore.

    S3 can answer ``200 OK`` and put an ``<Error>`` document in the body (a
    ``CopyObject`` or ``CompleteMultipartUpload`` that failed after the
    headers went out). Such an answer is decoded as the 400 it really is, so
    the result carries an ``"Error"`` key the caller checks for. An empty
    body decodes to just the modeled headers - except for the operations
    whose answer *must* have a body, where an empty one is a parse error
    rather than an empty listing.
    """
    root = (
        fromstring(payload)
        if payload.strip() or operation in ("ListObjects", "ListObjectsV2", "CreateMultipartUpload")
        else None
    )
    embedded_error = False
    if root is not None:
        local = root.tag.rpartition("}")[2]
        if local in ("Error", "ErrorResponse"):
            # Botocore's S3 error discriminator compares the root tag literally.
            root.tag, embedded_error = local, True
    response = {
        "status_code": 400 if embedded_error else status,
        "headers": dict(headers or {}),
        "body": payload if root is not None else b"",
    }
    result: dict[str, Any] = _Parser(root, lenient).parse(
        response, _model().operation_model(operation).output_shape
    )
    return result


def manifest(etags: Sequence[str]) -> bytes:
    """Serialize completion parts with the S3 model and XML escaping.

    The ``CompleteMultipartUpload`` body: one ``<Part>`` per ETag, numbered
    from 1 in upload order. Bucket, key and upload id are placeholders - they
    go in the URL, not the body, and only the body is kept.
    """
    request = create_serializer("rest-xml").serialize_to_request(
        {
            "Bucket": "unused",
            "Key": "unused",
            "UploadId": "unused",
            "MultipartUpload": {
                "Parts": [{"PartNumber": n, "ETag": tag} for n, tag in enumerate(etags, 1)]
            },
        },
        _model().operation_model("CompleteMultipartUpload"),
    )
    return bytes(request["body"])


def listing_items(page: dict[str, Any], prefix: str) -> Iterator[tuple[str, dict[str, Any] | None]]:
    """Common prefixes first, then immediate objects; hide folder markers.

    Yields ``(name relative to prefix, object dict)`` for objects and
    ``(name, None)`` for "directories". A key equal to the prefix itself
    (the ``dir/`` folder marker) has an empty relative name and is skipped,
    as is anything with a slash left in it - with a ``/`` delimiter S3
    should not return such keys, but some implementations do.
    """
    for directory in page.get("CommonPrefixes", []):
        name = directory.get("Prefix", "")[len(prefix) :].rstrip("/")
        if name:
            yield name, None
    for item in page.get("Contents", []):
        name = item.get("Key", "")[len(prefix) :]
        if name and "/" not in name:
            yield name, item


def modified(item: dict[str, Any]) -> int:
    """An object's ``LastModified`` as a Unix time, or 0 when it has none."""
    stamp = item.get("LastModified")
    return int(stamp.timestamp()) if stamp is not None else 0
