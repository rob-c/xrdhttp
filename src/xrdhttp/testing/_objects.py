"""The object-store dialects: S3 (and GCS signed URLs) and Swift.

With :attr:`~xrdhttp.testing.StorageServer.s3` set the server is a
path-style S3 endpoint (``http://host:port/bucket/key``) over the store's
buckets: ``ListObjects`` v1 and v2 (a delimiter, continuation tokens and
markers, ``max-keys`` capped at :attr:`~xrdhttp.testing.S3.page_size`),
ranged ``GetObject``, ``PutObject``, server-side ``CopyObject``, multipart
upload, and an idempotent ``DeleteObject``. Every request must carry a
valid signature - SigV4 in the ``Authorization`` header or pre-signed in
the query, or a GCS V4 signed URL when :attr:`~xrdhttp.testing.S3.gcs_key`
is set. The verification is written out again from the AWS "Create a
signed request" steps, against the request as it arrived on the wire, and
independently of :mod:`xrdhttp.s3.sigv4` - a check that called the code
under test would agree with it however wrong it was.

With :attr:`~xrdhttp.testing.StorageServer.swift` set, containers are
the store's buckets under ``/v1/<account>``, ``X-Auth-Token`` is checked
and listings are Swift's XML.

What a maintainer must keep: the error *spelling* (``<Error><Code>``, the
status that goes with each code) and the quirks that are there on purpose -
a ``200`` that carries an ``<Error>`` body, one range per ``GET``, an
idempotent ``DELETE`` - because those are what clients' error mapping is
tested against. Expiry (``X-Amz-Expires``) and clock skew are not checked,
which keeps the tests independent of the machine's clock.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from email.utils import formatdate
from xml.sax.saxutils import escape

from xrdcore import safexml
from xrdcore.crc32c import crc32c

from ._base import HandlerBase
from ._model import S3
from ._replies import ranged_reply


@dataclass(frozen=True, slots=True)
class _Signed:
    """The parts of a request that SigV4 signs, as the server received them.

    ``headers`` are the ``SignedHeaders`` in the order the client listed them
    (lowercase names, which is what makes the order canonical); ``payload``
    is the ``x-amz-content-sha256`` value or ``UNSIGNED-PAYLOAD``; ``scope``
    is ``date/region/service/aws4_request``.
    """

    method: str
    path: str
    query: list[tuple[str, str]]
    headers: list[tuple[str, str]]
    payload: str
    scope: str


def _canonical_query(query: list[tuple[str, str]]) -> str:
    """Sorted pairs, each side percent-encoded with only RFC 3986's unreserved characters kept."""
    return "&".join(
        f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}"
        for k, v in sorted(query)
    )


def _canonical_path(path: str) -> str:
    """Decoded, then re-encoded with ``/`` kept, so ``%7E`` and a raw ``~`` sign alike."""
    return urllib.parse.quote(urllib.parse.unquote(path), safe="/-_.~")


def sigv4(secret: str, stamp: str, request: _Signed) -> str:
    """The hex AWS Signature Version 4 of ``request`` for ``secret`` at ``stamp``.

    Canonical request (method, encoded path, sorted query, ``name:value``
    header lines with whitespace runs folded, signed-header list, payload
    hash), string to sign (``AWS4-HMAC-SHA256``, ``stamp``, the scope, the
    canonical request's SHA-256), and the HMAC chain ``AWS4<secret>`` ->
    date -> region -> service -> ``aws4_request``. ``stamp`` is the
    ``YYYYMMDDTHHMMSSZ`` request time.
    """
    lines = "".join(f"{k}:{' '.join(v.split())}\n" for k, v in request.headers)
    names = ";".join(k for k, _ in request.headers)
    canonical = "\n".join(
        [
            request.method,
            _canonical_path(request.path),
            _canonical_query(request.query),
            lines,
            names,
            request.payload,
        ]
    )
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    to_sign = "\n".join(["AWS4-HMAC-SHA256", stamp, request.scope, digest])
    key = ("AWS4" + secret).encode()
    for part in request.scope.split("/"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    return hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()


def _scope(s3: S3, credential: str, stamp: str) -> str | None:
    """The credential's scope if it is ours and fits the request, else ``None``.

    ``credential`` is ``<access key>/<date>/<region>/<service>/aws4_request``:
    the key must be ours, the date the request's own day, the region ours
    (when :attr:`~xrdhttp.testing.S3.region` is set) and the terminator fixed.
    """
    key, _, scope = credential.partition("/")
    parts = scope.split("/")
    if key != s3.access_key or len(parts) != 4 or parts[0] != stamp[:8]:
        return None
    if parts[3] != "aws4_request" or s3.region not in (None, parts[1]):
        return None
    return scope


def _fields(header: str) -> dict[str, str] | None:
    """The fields of an ``AWS4-HMAC-SHA256`` ``Authorization`` header, or ``None`` if not one."""
    algorithm, _, rest = header.partition(" ")
    fields = dict(item.strip().split("=", 1) for item in rest.split(",") if "=" in item)
    if algorithm != "AWS4-HMAC-SHA256":
        return None
    if not fields.keys() >= {"Credential", "SignedHeaders", "Signature"}:
        return None
    return fields


def _md5(data: bytes) -> str:
    """The plain ``ETag`` S3 gives an object stored in one piece."""
    return hashlib.md5(data).hexdigest()


def _part_numbers(body: bytes) -> list[int]:
    """The ``PartNumber`` values of a ``CompleteMultipartUpload`` document, in order.

    S3 accepts the document with or without its ``xmlns``, so local names
    are matched. A body that is not XML, or that declares a document type
    (refused, as every XML the chain reads is, by :mod:`xrdcore.safexml`),
    lists no parts, which completes an upload empty, rather than crashing
    the server thread.
    """
    try:
        root = safexml.fromstring(body)
    except (ET.ParseError, safexml.UnsafeXML):
        return []
    return [int(n.text or 0) for n in root.iter() if n.tag.rpartition("}")[2] == "PartNumber"]


@dataclass(frozen=True, slots=True)
class _Page:
    """One page of a listing, before it is rendered: keys, common prefixes, where it ended."""

    #: Keys listed as objects, in order.
    contents: list[str]
    #: Common prefixes (``"d/sub/"``), each standing for every key beneath it.
    prefixes: list[str]
    #: The last key the page covered - including keys folded into a prefix -
    #: which is where the next page starts; ``""`` for an empty page.
    last: str


def listing_page(keys: list[str], prefix: str, delimiter: str, limit: int) -> _Page:
    """Select one page from sorted ``keys``, rolling up keys beneath a common prefix.

    ``keys`` are already past the marker or continuation token. Each object
    and each common prefix counts once towards ``limit`` - S3's ``MaxKeys``
    counts both - and a common prefix appears in exactly one page, because
    the page that names it covers every key beneath it.
    """
    contents: list[str] = []
    prefixes: list[str] = []
    last = ""
    for key in keys:
        if len(contents) + len(prefixes) >= limit:
            break
        if key <= last:
            continue  # inside a group already rolled past
        tail = key[len(prefix) :]
        if delimiter and delimiter in tail:
            group = prefix + tail.split(delimiter, 1)[0] + delimiter
            prefixes.append(group)
            last = max(k for k in keys if k.startswith(group))
        else:
            contents.append(key)
            last = key
    return _Page(contents, prefixes, last)


class ObjectStoreMixin(HandlerBase):
    """S3, GCS and Swift request handling."""

    # -- authorisation (called from the front) -----------------------------------------------

    def _s3_refused(self) -> bool:
        """Refuse a request the S3 dialect will not serve; ``True`` if refused.

        A blanket refusal (``forbidden``) first, then the signature.
        """
        s3 = self._store_s3()
        if s3.forbidden:
            self._s3_error(403, "AccessDenied")
            return True
        if self._s3_signed(s3):
            return False
        self._s3_error(403, "SignatureDoesNotMatch")
        return True

    def _store_s3(self) -> S3:
        """The server's S3 state (the dialect is on whenever this is called)."""
        s3 = self.app.s3
        assert s3 is not None
        return s3

    def _s3_signed(self, s3: S3) -> bool:
        """Whether the request carries a valid signature for the configured credentials."""
        parts = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        values = dict(query)
        if s3.gcs_key is not None:
            return self._gcs_signed(s3, parts.path, query, values)
        if not s3.access_key:
            return True
        if "X-Amz-Signature" in values:
            return self._presigned(s3, parts.path, query, values)
        return self._header_signed(s3, parts.path, query)

    def _presigned(
        self, s3: S3, path: str, query: list[tuple[str, str]], values: dict[str, str]
    ) -> bool:
        """A pre-signed URL: every query parameter but the signature is signed, and ``host``."""
        stamp = values.get("X-Amz-Date", "")
        scope = _scope(s3, values.get("X-Amz-Credential", ""), stamp)
        if scope is None:
            return False
        signed = [(k, v) for k, v in query if k != "X-Amz-Signature"]
        host = [("host", self.headers.get("Host", ""))]
        request = _Signed(self.command, path, signed, host, "UNSIGNED-PAYLOAD", scope)
        expected = sigv4(s3.secret_key, stamp, request)
        return hmac.compare_digest(expected, values["X-Amz-Signature"])

    def _header_signed(self, s3: S3, path: str, query: list[tuple[str, str]]) -> bool:
        """An ``Authorization: AWS4-HMAC-SHA256 ...`` header for our key, and the session token."""
        fields = _fields(self.headers.get("Authorization", ""))
        stamp = self.headers.get("x-amz-date", "")
        scope = _scope(s3, fields["Credential"], stamp) if fields else None
        if fields is None or scope is None:
            return False
        if s3.token and self.headers.get("x-amz-security-token") != s3.token:
            return False
        names = fields["SignedHeaders"].split(";")
        headers = [(name, self.headers.get(name, "")) for name in names]
        payload = self.headers.get("x-amz-content-sha256", "")
        request = _Signed(self.command, path, query, headers, payload, scope)
        return hmac.compare_digest(sigv4(s3.secret_key, stamp, request), fields["Signature"])

    def _gcs_signed(
        self, s3: S3, path: str, query: list[tuple[str, str]], values: dict[str, str]
    ) -> bool:
        """A Google Cloud Storage V4 signed URL (``GOOG4-RSA-SHA256``).

        The same canonical-request shape as SigV4, but query names and values
        are percent-encoded with nothing kept, and the string to sign is
        verified with the service account's RSA public key instead of an
        HMAC. Only ``host`` is signed, as GCS signers do.
        """
        signature = values.get("X-Goog-Signature", "")
        credential = values.get("X-Goog-Credential", "")
        if not signature or not credential.startswith(s3.gcs_email + "/"):
            return False
        signed = sorted((k, v) for k, v in query if k != "X-Goog-Signature")
        canonical_query = "&".join(
            f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}" for k, v in signed
        )
        host = self.headers.get("Host", "")
        canonical = "\n".join(
            [
                self.command,
                _canonical_path(path),
                canonical_query,
                f"host:{host}\n",
                "host",
                "UNSIGNED-PAYLOAD",
            ]
        )
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        scope = credential.partition("/")[2]
        to_sign = "\n".join(["GOOG4-RSA-SHA256", values.get("X-Goog-Date", ""), scope, digest])
        return bool(s3.gcs_key.verify(to_sign.encode(), bytes.fromhex(signature), digest="sha256"))

    def _payload_matches(self, body: bytes) -> bool:
        """Whether a header-signed request's body is the one its ``x-amz-content-sha256`` names."""
        s3 = self._store_s3()
        claimed = self.headers.get("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        if not self.app.verify_payload or not s3.access_key or s3.gcs_key is not None:
            return True
        if "Authorization" not in self.headers:
            return True
        if claimed == "UNSIGNED-PAYLOAD" or claimed.startswith("STREAMING-"):
            return True
        return claimed == hashlib.sha256(body).hexdigest()

    def _s3_error(self, status: int, code: str) -> None:
        """An S3 error document: a client maps ``code``, not just ``status``."""
        self._settle_body()
        body = f"<Error><Code>{code}</Code></Error>".encode()
        self._reply(status, body, {"Content-Type": "application/xml"})

    # -- S3 ----------------------------------------------------------------------------------

    def _s3(self) -> None:
        """Route an authenticated S3 request by method, key and query.

        The query decides the operation, as in S3 itself: no key (or
        ``list-type``/``delimiter``) is a listing, ``uploads``/``uploadId``
        the multipart protocol, and ``x-amz-copy-source`` a server-side copy.
        """
        parts = urllib.parse.urlsplit(self.path)
        bucket, _, key = urllib.parse.unquote(parts.path).lstrip("/").partition("/")
        query = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
        method = self.command
        if method == "PUT" and not key:
            self._read_body()
            self.app.store.make_bucket(bucket)  # CreateBucket; an existing one is kept
            self._reply(200)
        elif not self.app.store.has_bucket(bucket):
            self._s3_error(404, "NoSuchBucket")
        elif method in ("GET", "HEAD") and (not key or query.keys() & {"list-type", "delimiter"}):
            self._s3_list(bucket, query)
        elif method in ("GET", "HEAD"):
            self._object_get(bucket, key)
        elif method in ("PUT", "POST"):
            self._s3_write(bucket, key, query)
        elif method == "DELETE":
            self._s3_delete(bucket, key, query)
        else:
            self._s3_error(405, "MethodNotAllowed")

    def _s3_write(self, bucket: str, key: str, query: dict[str, str]) -> None:
        """``PUT`` and ``POST``: read the body (the signature may cover it), then dispatch."""
        body = self._read_body()
        if not self._payload_matches(body):
            self._s3_error(403, "SignatureDoesNotMatch")
        elif self.command == "POST":
            self._s3_post(bucket, key, query, body)
        elif "uploadId" in query:
            self._s3_part(query["uploadId"], int(query.get("partNumber") or 0), body)
        elif "x-amz-copy-source" in self.headers:
            self._s3_copy(bucket, key, self.headers["x-amz-copy-source"])
        else:
            self.app.store.put_object(bucket, key, body)
            self._store_s3().etags.pop(f"{bucket}/{key}", None)
            self._reply(200, b"", {"ETag": f'"{_md5(body)}"'})

    def _s3_post(self, bucket: str, key: str, query: dict[str, str], body: bytes) -> None:
        """Begin (``?uploads``) or complete (``?uploadId``) a multipart upload."""
        if "uploads" in query:
            self._s3_begin(key)
        elif "uploadId" in query:
            self._s3_complete(bucket, key, query["uploadId"], body)
        else:
            self._s3_error(400, "MalformedPOSTRequest")

    def _s3_begin(self, key: str) -> None:
        """Open an upload and name it - unless :attr:`~xrdhttp.testing.S3.nameless_uploads`."""
        s3 = self._store_s3()
        handle = f"upload-{len(s3.uploads) + 1:04d}"
        s3.uploads[handle] = {}
        named = "" if s3.nameless_uploads else f"<UploadId>{handle}</UploadId>"
        body = f"<InitiateMultipartUploadResult><Key>{escape(key)}</Key>{named}"
        self._xml(body + "</InitiateMultipartUploadResult>")

    def _s3_part(self, upload: str, number: int, body: bytes) -> None:
        """``UploadPart``: keep one part, or fail it once if a test asked for that.

        A part number may be re-sent and the later bytes win, as on S3 -
        which is what lets a client retry the part that failed.
        """
        s3 = self._store_s3()
        parts = s3.uploads.get(upload)
        if parts is None or not number:
            self._s3_error(404, "NoSuchUpload")
        elif number in s3.failing_parts:
            s3.failing_parts.discard(number)
            self._s3_error(500, "InternalError")
        else:
            parts[number] = body
            self._reply(200, b"", {"ETag": f'"{_md5(body)}"'})

    def _s3_complete(self, bucket: str, key: str, upload: str, body: bytes) -> None:
        """Assemble the parts the request lists, in its order, into the object.

        Only the listed parts are used, so a part uploaded but left out of
        the list is dropped, as on S3. The ``ETag`` is S3's multipart form:
        MD5 of the concatenated part digests, then ``-`` and the part count.
        A completion that fails does so inside a ``200``: S3 answers before
        it knows, so that it can hold the connection open while it assembles.
        """
        s3 = self._store_s3()
        parts = s3.uploads.pop(upload, None)
        if parts is None:
            self._s3_error(404, "NoSuchUpload")
            return
        if s3.complete_fails:
            self._reply(200, b"<Error><Code>InternalError</Code></Error>")
            return
        wanted = _part_numbers(body)
        self.app.store.put_object(bucket, key, b"".join(parts[n] for n in wanted))
        digests = b"".join(hashlib.md5(parts[n]).digest() for n in wanted)
        tag = f"{hashlib.md5(digests).hexdigest()}-{len(wanted)}"
        s3.etags[f"{bucket}/{key}"] = tag
        result = f"<CompleteMultipartUploadResult><Key>{escape(key)}</Key>"
        self._xml(result + f"<ETag>&quot;{tag}&quot;</ETag></CompleteMultipartUploadResult>")

    def _s3_copy(self, bucket: str, key: str, source: str) -> None:
        """``CopyObject`` from ``/<bucket>/<key>``, which is what makes a rename possible."""
        store = self.app.store
        origin, _, name = urllib.parse.unquote(source).lstrip("/").partition("/")
        if not store.has_bucket(origin) or store.object_entry(origin, name) is None:
            self._s3_error(404, "NoSuchKey")
            return
        if self._store_s3().copy_fails:
            self._reply(200, b"<Error><Code>InternalError</Code></Error>")
            return
        data = store.get_object(origin, name)
        store.put_object(bucket, key, data)
        tag = f"<ETag>&quot;{_md5(data)}&quot;</ETag>"
        self._xml(f"<CopyObjectResult>{tag}</CopyObjectResult>")

    def _s3_delete(self, bucket: str, key: str, query: dict[str, str]) -> None:
        """``DeleteObject`` (of what is not there too, as on S3) or ``AbortMultipartUpload``."""
        s3 = self._store_s3()
        upload = query.get("uploadId")
        if upload is not None:
            s3.uploads.pop(upload, None)
            s3.aborted.append(upload)
        else:
            self.app.store.delete_object(bucket, key)
            s3.etags.pop(f"{bucket}/{key}", None)
        self._reply(204)

    def _xml(self, document: str) -> None:
        """A ``200`` with an XML body."""
        self._reply(200, document.encode(), {"Content-Type": "application/xml"})

    # -- reading objects (S3 and Swift) --------------------------------------------------------

    def _object_get(self, bucket: str, key: str) -> None:
        """``GetObject``/``HeadObject``: whole or one range, with ``ETag`` and digests.

        One range only, as S3 serves (it has never served several at once);
        GCS also gets ``x-goog-hash`` (CRC32C and MD5), because its clients
        read checksums from there.
        """
        store = self.app.store
        found = store.object_entry(bucket, key)
        if found is None:
            self._missing()
            return
        data = store.get_object(bucket, key)
        s3 = self.app.s3
        tag = s3.etags.get(f"{bucket}/{key}") if s3 is not None else None
        headers = {
            "ETag": f'"{tag or _md5(data)}"',
            "Last-Modified": formatdate(found.modified, usegmt=True),
            "Accept-Ranges": "bytes",
            **self._digest_headers(lambda: [data]),
        }
        if s3 is not None and s3.gcs_key is not None:
            headers["x-goog-hash"] = _goog_hash(data)
        self._ranged(data, headers)

    def _ranged(self, data: bytes, headers: dict[str, str]) -> None:
        """``data``, whole or the first range asked for; 416 if that is past the end."""
        reply = ranged_reply(data, self.headers.get("Range"), headers=headers, several="first")
        self._reply(reply.status, reply.body, reply.headers)

    def _missing(self) -> None:
        """The dialect's answer for a key that is not there."""
        if self.app.s3 is not None:
            self._s3_error(404, "NoSuchKey")
        else:
            self._reply(404, b"<html><h1>Not Found</h1></html>")

    def _s3_list(self, bucket: str, query: dict[str, str]) -> None:
        """``ListObjects`` (v1, ``marker``) or ``ListObjectsV2`` (``list-type=2``) of one bucket.

        A v2 continuation token is simply the last key the previous page
        covered, as a v1 ``NextMarker`` is. Real tokens are opaque; a client
        that parsed one would pass here and break there, so it must only
        echo it back.
        """
        s3 = self._store_s3()
        v2 = query.get("list-type") == "2"
        prefix = query.get("prefix", "")
        start = query.get("continuation-token" if v2 else "marker", "")
        limit = min(int(query.get("max-keys") or s3.page_size), s3.page_size)
        keys = [k for k in self.app.store.keys(bucket) if k.startswith(prefix) and k > start]
        page = listing_page(keys, prefix, query.get("delimiter", ""), limit)
        truncated = bool(page.last) and page.last != keys[-1]
        parts = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">',
            f"<Name>{escape(bucket)}</Name><Prefix>{escape(prefix)}</Prefix>",
            f"<IsTruncated>{'true' if truncated else 'false'}</IsTruncated>",
        ]
        if truncated:
            name = "NextContinuationToken" if v2 else "NextMarker"
            parts.append(f"<{name}>{escape(page.last)}</{name}>")
        parts += [self._contents(bucket, key, s3) for key in page.contents]
        parts += [
            f"<CommonPrefixes><Prefix>{escape(p)}</Prefix></CommonPrefixes>" for p in page.prefixes
        ]
        parts.append("</ListBucketResult>")
        self._xml("".join(parts))

    def _contents(self, bucket: str, key: str, s3: S3) -> str:
        """One ``<Contents>`` element: key, size, time, ``ETag`` and storage class."""
        store = self.app.store
        found = store.object_entry(bucket, key)
        assert found is not None  # listed a moment ago, in the same request
        data = store.get_object(bucket, key)
        modified = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(found.modified))
        tag = s3.etags.get(f"{bucket}/{key}") or _md5(data)
        return (
            f"<Contents><Key>{escape(key)}</Key><Size>{found.size}</Size>"
            f"<LastModified>{modified}</LastModified><ETag>&quot;{tag}&quot;</ETag>"
            "<StorageClass>STANDARD</StorageClass></Contents>"
        )

    # -- Swift ---------------------------------------------------------------------------------

    def _swift(self) -> None:
        """Route a Swift request under ``/v1/<account>`` (or ``/`` without an account).

        ``GET ...?prefix=`` lists, ``HEAD <container>`` tests a container,
        ``PUT`` with ``X-Copy-From`` copies server-side; plain objects are
        read, written (201) and deleted (404 if missing). Paths outside the
        account are 404, as a Swift proxy answers for another account.
        """
        swift = self.app.swift
        assert swift is not None
        parts = urllib.parse.urlsplit(self.path)
        root = f"/v1/{swift.account}/" if swift.account else "/"
        path = urllib.parse.unquote(parts.path)
        container, _, key = path[len(root) :].partition("/")
        query = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
        if not path.startswith(root):
            self._missing()
        elif self.command == "PUT" and not key:
            self._read_body()
            self.app.store.make_bucket(container)  # a new container; an existing one is kept
            self._reply(201)
        elif not self.app.store.has_bucket(container):
            self._missing()
        elif self.command == "GET" and "prefix" in query:
            self._swift_list(container, query)
        elif self.command == "HEAD" and not key:
            self._reply(204)
        else:
            self._swift_object(container, key)

    def _swift_object(self, container: str, key: str) -> None:
        """One object: read, server-side copy, write or delete."""
        store, method = self.app.store, self.command
        if method in ("GET", "HEAD"):
            self._object_get(container, key)
        elif method == "PUT" and "X-Copy-From" in self.headers:
            self._swift_copy(container, key, self.headers["X-Copy-From"])
        elif method == "PUT":
            store.put_object(container, key, self._read_body())
            self._reply(201)
        elif method == "DELETE" and store.object_entry(container, key) is not None:
            store.delete_object(container, key)
            self._reply(204)
        elif method == "DELETE":
            self._missing()
        else:
            self._reply(405, b"method not allowed")

    def _swift_copy(self, container: str, key: str, source: str) -> None:
        """``X-Copy-From: /<container>/<object>``: a server-side copy, 201."""
        store = self.app.store
        self._read_body()
        origin, _, name = urllib.parse.unquote(source).lstrip("/").partition("/")
        if not store.has_bucket(origin) or store.object_entry(origin, name) is None:
            self._missing()
            return
        store.put_object(container, key, store.get_object(origin, name))
        self._reply(201)

    def _swift_list(self, container: str, query: dict[str, str]) -> None:
        """A ``format=xml`` container listing, ``<subdir>`` entries rolled up by ``delimiter``.

        An empty result is 204 with no body, as Swift answers, which a
        client must not mistake for an error. ``<hash>`` is a dummy ``0``:
        no client reads Swift's MD5 from listings.
        """
        store, prefix = self.app.store, query["prefix"]
        keys = [key for key in store.keys(container) if key.startswith(prefix)]
        page = listing_page(keys, prefix, query.get("delimiter", ""), len(keys))
        if not page.contents and not page.prefixes:
            self._reply(204)
            return
        body = [f'<?xml version="1.0" encoding="UTF-8"?><container name="{escape(container)}">']
        for name in page.prefixes:
            body.append(f'<subdir name="{escape(name)}"><name>{escape(name)}</name></subdir>')
        for name in page.contents:
            found = store.object_entry(container, name)
            assert found is not None  # listed a moment ago, in the same request
            modified = time.strftime("%Y-%m-%dT%H:%M:%S.000000", time.gmtime(found.modified))
            body.append(
                f"<object><name>{escape(name)}</name><hash>0</hash><bytes>{found.size}</bytes>"
                f"<content_type>application/octet-stream</content_type>"
                f"<last_modified>{modified}</last_modified></object>"
            )
        body.append("</container>")
        self._xml("".join(body))


def _goog_hash(data: bytes) -> str:
    """GCS's ``x-goog-hash``: CRC32C (four big-endian bytes) and MD5, each base64."""
    crc = base64.b64encode(crc32c(data).to_bytes(4, "big")).decode()
    md5 = base64.b64encode(hashlib.md5(data).digest()).decode()
    return f"crc32c={crc},md5={md5}"
