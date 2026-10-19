"""S3 answers decoded by botocore's model, over a tree xrdcore.safexml parsed."""

from __future__ import annotations

from datetime import UTC, datetime
from xml.etree import ElementTree as ET

import pytest
from botocore.loaders import Loader, create_loader

from xrdcore.safexml import UnsafeXML
from xrdhttp.s3 import codec

LISTING = b"""<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>b</Name><Prefix>runs/</Prefix><KeyCount>3</KeyCount><IsTruncated>true</IsTruncated>
  <NextContinuationToken>tok</NextContinuationToken>
  <Contents><Key>runs/</Key><Size>0</Size></Contents>
  <Contents><Key>runs/a.root</Key><Size>5</Size><ETag>"abc"</ETag>
    <LastModified>2024-01-02T03:04:05.000Z</LastModified></Contents>
  <Contents><Key>runs/deep/x</Key><Size>1</Size></Contents>
  <CommonPrefixes><Prefix>runs/2024/</Prefix></CommonPrefixes>
  <CommonPrefixes><Prefix>runs/</Prefix></CommonPrefixes>
</ListBucketResult>"""


def test_a_listing_decodes_and_lists_immediate_children():
    page = codec.decode("ListObjectsV2", LISTING)
    assert page["IsTruncated"] is True and page["NextContinuationToken"] == "tok"
    items = list(codec.listing_items(page, "runs/"))
    assert [(name, item is None) for name, item in items] == [("2024", True), ("a.root", False)]
    entry = items[1][1]
    assert entry is not None and codec.modified(entry) == 1704164645
    assert codec.modified({}) == 0


def test_an_error_inside_a_200_is_decoded_as_the_error_it_is():
    body = b"<Error><Code>InternalError</Code><Message>try again</Message></Error>"
    result = codec.decode("CompleteMultipartUpload", body)
    assert result["Error"]["Code"] == "InternalError"
    assert result["ResponseMetadata"]["HTTPStatusCode"] == 400


def test_an_empty_body_is_just_the_modeled_headers():
    result = codec.decode("PutObject", b"", headers={"ETag": '"e"'})
    assert result["ETag"] == '"e"'


def test_an_operation_whose_answer_must_have_a_body_refuses_an_empty_one():
    with pytest.raises(ET.ParseError):
        codec.decode("ListObjectsV2", b"")


def test_a_declaration_is_refused_before_botocore_sees_the_tree():
    with pytest.raises(UnsafeXML):
        codec.decode("ListObjectsV2", b"<!DOCTYPE x><ListBucketResult/>")


def test_lenient_decoding_reads_a_junk_size_as_zero_and_strict_refuses_it():
    body = b"<ListBucketResult><Contents><Key>k</Key><Size>?</Size></Contents></ListBucketResult>"
    assert codec.decode("ListObjectsV2", body, lenient=True)["Contents"][0]["Size"] == 0
    with pytest.raises(ValueError):
        codec.decode("ListObjectsV2", body)


@pytest.mark.parametrize(
    ("stamp", "seconds"),
    [("2024-01-02T03:04:05.000Z", 1704164645), ("last tuesday", 0), ("", 0)],
)
def test_a_timestamp_that_is_not_one_is_simply_unknown(stamp, seconds):
    body = (
        f"<ListBucketResult><Contents><LastModified>{stamp}</LastModified>"
        "</Contents></ListBucketResult>"
    ).encode()
    stamp_value = codec.decode("ListObjectsV2", body)["Contents"][0]["LastModified"]
    assert int(stamp_value.timestamp()) == seconds
    assert isinstance(stamp_value, datetime) and stamp_value.tzinfo is not None
    assert codec._timestamp("garbage") == datetime.fromtimestamp(0, UTC)


def test_the_completion_manifest_numbers_parts_in_order_and_escapes():
    body = codec.manifest(['"a"', '"b&c"'])
    assert b"<PartNumber>1</PartNumber>" in body and b"<PartNumber>2</PartNumber>" in body
    assert b"&quot;b&amp;c&quot;" in body or b'"b&amp;c"' in body
    assert body.index(b'a"') < body.index(b"b&amp;c")


# Ported from xrdclient's suite (tests/test_rebased_backends.py) when the codec
# moved here: the contracts the S3 filesystems built on it rely on.


def test_s3_models_do_not_discover_ambient_credentials(monkeypatch):
    """No botocore session at all: a session reads the AWS configuration, and
    is where credential discovery lives; credentials are the caller's policy."""

    def forbidden(*arguments):
        raise AssertionError("credentials must remain the transport adapter's policy")

    import botocore.session

    monkeypatch.setattr(botocore.session.Session, "__init__", forbidden)
    monkeypatch.setattr(botocore.session.Session, "get_credentials", forbidden)
    codec._model.cache_clear()
    answer = codec.decode(
        "CreateMultipartUpload",
        b"<InitiateMultipartUploadResult><UploadId>x</UploadId></InitiateMultipartUploadResult>",
    )
    assert answer["UploadId"] == "x"


def test_the_s3_model_is_loaded_on_first_use_and_only_once(monkeypatch):
    loads: list[int] = []

    def counting() -> Loader:
        loads.append(1)
        return create_loader()

    monkeypatch.setattr("xrdhttp.s3.codec.create_loader", counting)
    codec._model.cache_clear()
    assert codec._model.cache_info().currsize == 0  # importing did not load it
    for _ in range(3):
        codec.manifest(['"etag"'])
    assert loads == [1]


@pytest.mark.parametrize("operation", ["CopyObject", "CompleteMultipartUpload"])
@pytest.mark.parametrize("root", ["Error", "ErrorResponse"])
def test_namespaced_errors_inside_http_200_are_modeled(operation, root):
    error = "<Error><Code>SlowDown</Code><Message>try later</Message></Error>"
    body = error if root == "Error" else f"<ErrorResponse>{error}</ErrorResponse>"
    body = body.replace(f"<{root}>", f'<{root} xmlns="urn:s3:test">', 1)
    answer = codec.decode(operation, body.encode())
    assert answer["Error"]["Code"] == "SlowDown"
    assert answer["Error"]["Message"] == "try later"


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-le", "utf-16-be"])
def test_s3_declarations_never_reach_the_library_parser(encoding):
    with pytest.raises(UnsafeXML):
        codec.decode("ListObjectsV2", '<!DOCTYPE x [<!ENTITY a "value">]><x/>'.encode(encoding))


@pytest.mark.parametrize("size", ["", "-1", "unknown", "5"])
def test_s3_size_tolerance_is_a_facade_policy(size):
    body = f"<ListBucketResult><Contents><Size>{size}</Size></Contents></ListBucketResult>".encode()
    answer = codec.decode("ListObjectsV2", body, lenient=True)
    assert answer["Contents"][0]["Size"] == (int(size) if size.isdigit() else 0)
    if size == "unknown":
        with pytest.raises(ValueError):
            codec.decode("ListObjectsV2", body)
    else:
        assert codec.decode("ListObjectsV2", body)["Contents"][0]["Size"] == int(size or 0)


@pytest.mark.parametrize("payload", [b"", b" \n\t"])
def test_empty_copy_completion_remains_accepted(payload):
    assert "Error" not in codec.decode("CopyObject", payload)
    assert "Error" not in codec.decode("CompleteMultipartUpload", payload)


def test_listing_items_hide_markers_and_descendants():
    page = {
        "CommonPrefixes": [{"Prefix": "p/"}, {"Prefix": "p/sub/"}],
        "Contents": [{"Key": "p/"}, {"Key": "p/a"}, {"Key": "p/deep/b"}],
    }
    assert list(codec.listing_items(page, "p/")) == [("sub", None), ("a", {"Key": "p/a"})]
    assert list(codec.listing_items({}, "")) == []
