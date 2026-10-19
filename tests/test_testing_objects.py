"""The fake storage element's object stores: S3 (signatures, multipart, listings), GCS and Swift."""

from __future__ import annotations

import hashlib
import urllib.parse
from collections.abc import Iterator
from pathlib import Path

import pytest

from xrdhttp.s3.sigv4 import Credentials, presign, sign
from xrdhttp.testing import S3, DirectoryStore, MemoryStore, StorageServer, Swift, _objects
from xrdhttp.testing._objects import listing_page

from tests._storage import Answer, ask

KEYS = Credentials("AKIDTEST", "SECRETTEST")


@pytest.fixture
def s3() -> Iterator[StorageServer]:
    """An S3 endpoint over memory, holding bucket ``b`` with ``d/a`` and ``top``."""
    store = MemoryStore(buckets={"b": {"d/a": b"aa", "top": b"0123456789"}})
    with StorageServer(store) as srv:
        srv.s3 = S3()
        yield srv


def signed(
    server: StorageServer,
    method: str,
    target: str,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
    *,
    keys: Credentials = KEYS,
    payload: str | None = None,
    region: str = "us-east-1",
) -> Answer:
    """One request signed in its ``Authorization`` header."""
    host = f"{server.host}:{server.port}"
    sent = dict(headers or {})
    digest = payload if payload is not None else hashlib.sha256(body).hexdigest()
    sent.update(sign(method, target, host, sent, digest, credentials=keys, region=region))
    sent.pop("host", None)
    return ask(server, method, target, body, sent)


def store(server: StorageServer) -> S3:
    """The server's S3 state."""
    assert server.s3 is not None
    return server.s3


# -- authorisation -------------------------------------------------------------------------------


def test_a_signed_request_is_served_and_anything_else_refused(s3):
    assert signed(s3, "GET", "/b/top").body == b"0123456789"
    refused = ask(s3, "GET", "/b/top")
    assert (refused.status, b"SignatureDoesNotMatch" in refused.body) == (403, True)
    assert signed(s3, "GET", "/b/top", keys=Credentials("AKIDTEST", "wrong")).status == 403
    assert signed(s3, "GET", "/b/top", keys=Credentials("OTHER", "SECRETTEST")).status == 403
    assert signed(s3, "GET", "/b/top", region="eu-west-1").status == 403
    store(s3).region = None  # any region the scope names
    assert signed(s3, "GET", "/b/top", region="eu-west-1").status == 200
    assert ask(s3, "GET", "/b/top", headers={"Authorization": "Basic aGk="}).status == 403
    partial = "AWS4-HMAC-SHA256 Credential=AKIDTEST/20240102/us-east-1/s3/aws4_request"
    assert ask(s3, "GET", "/b/top", headers={"Authorization": partial}).status == 403


@pytest.mark.parametrize(
    "credential",
    [
        "AKIDTEST/20240102/us-east-1/s3",
        "AKIDTEST/20240103/us-east-1/s3/aws4_request",
        "AKIDTEST/20240102/us-east-1/s3/aws5_request",
    ],
)
def test_a_scope_that_does_not_fit_the_request_is_refused(s3, credential):
    header = f"AWS4-HMAC-SHA256 Credential={credential}, SignedHeaders=host, Signature=0"
    headers = {"Authorization": header, "x-amz-date": "20240102T030405Z"}
    assert ask(s3, "HEAD", "/b/top", headers=headers).status == 403


def test_a_session_token_must_come_with_the_signature(s3):
    store(s3).token = "session"
    assert signed(s3, "GET", "/b/top").status == 403
    assert signed(s3, "GET", "/b/top", headers={"x-amz-security-token": "session"}).status == 200


def test_a_presigned_url_carries_its_signature(s3):
    host = f"{s3.host}:{s3.port}"
    url = presign("GET", "/b/top", host, credentials=KEYS, region="us-east-1")
    parts = urllib.parse.urlsplit(url)
    assert ask(s3, "GET", f"{parts.path}?{parts.query}").body == b"0123456789"
    assert (
        ask(s3, "GET", f"{parts.path}?{parts.query.replace('Signature=', 'Signature=0')}").status
        == 403
    )
    stale = parts.query.replace("X-Amz-Date=2", "X-Amz-Date=1")
    assert ask(s3, "GET", f"{parts.path}?{stale}").status == 403


def test_a_blanket_refusal_and_an_open_bucket(s3):
    store(s3).forbidden = True
    assert b"AccessDenied" in signed(s3, "GET", "/b/top").body
    store(s3).forbidden = False
    store(s3).access_key = ""
    assert ask(s3, "GET", "/b/top").status == 200
    assert ask(s3, "PUT", "/b/new", b"n", {"x-amz-content-sha256": "0" * 64}).status == 200


def test_a_body_that_is_not_the_one_signed_is_refused(s3):
    assert signed(s3, "PUT", "/b/k", b"real", payload="0" * 64).status == 403
    assert signed(s3, "PUT", "/b/k", b"real", payload="UNSIGNED-PAYLOAD").status == 200
    streaming = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
    assert signed(s3, "PUT", "/b/k", b"real", payload=streaming).status == 200
    s3.verify_payload = False
    assert signed(s3, "PUT", "/b/k", b"real", payload="0" * 64).status == 200
    s3.verify_payload = True
    host = f"{s3.host}:{s3.port}"
    url = urllib.parse.urlsplit(presign("PUT", "/b/p", host, credentials=KEYS, region="us-east-1"))
    assert ask(s3, "PUT", f"{url.path}?{url.query}", b"any").status == 200  # unsigned payload


# -- objects -------------------------------------------------------------------------------------


def test_objects_are_read_written_copied_and_deleted(s3):
    head = signed(s3, "HEAD", "/b/top")
    assert head.header("ETag") == f'"{hashlib.md5(b"0123456789").hexdigest()}"'
    assert head.header("Content-Length") == "10" and head.body == b""
    assert signed(s3, "GET", "/b/top", headers={"Range": "bytes=2-3,5-6"}).body == b"23"
    assert signed(s3, "GET", "/b/top", headers={"Range": "bytes=20-"}).status == 416
    assert signed(s3, "GET", "/b/top", headers={"Want-Digest": "md5"}).header("Digest")
    missing = signed(s3, "GET", "/b/none")
    assert (missing.status, b"NoSuchKey" in missing.body) == (404, True)
    assert (
        signed(s3, "PUT", "/b/new", b"new").header("ETag") == f'"{hashlib.md5(b"new").hexdigest()}"'
    )
    copied = signed(s3, "PUT", "/b/copy", headers={"x-amz-copy-source": "/b/new"})
    assert b"<CopyObjectResult>" in copied.body
    assert signed(s3, "GET", "/b/copy").body == b"new"
    assert signed(s3, "PUT", "/b/c2", headers={"x-amz-copy-source": "/b/none"}).status == 404
    assert signed(s3, "PUT", "/b/c2", headers={"x-amz-copy-source": "/x/new"}).status == 404
    store(s3).copy_fails = True
    failed = signed(s3, "PUT", "/b/c2", headers={"x-amz-copy-source": "/b/new"})
    assert (failed.status, b"InternalError" in failed.body) == (200, True)
    assert signed(s3, "DELETE", "/b/new").status == 204
    assert signed(s3, "DELETE", "/b/new").status == 204  # deleting nothing is fine on S3
    assert signed(s3, "MKCOL", "/b/d").status == 405


def test_buckets_are_made_and_looked_for(s3):
    assert b"NoSuchBucket" in signed(s3, "GET", "/nobucket/k").body
    assert signed(s3, "PUT", "/fresh").status == 200
    assert signed(s3, "PUT", "/fresh/k", b"v").status == 200
    assert signed(s3, "GET", "/fresh/k").body == b"v"


def test_a_multipart_upload(s3):
    begun = signed(s3, "POST", "/b/big?uploads").body.decode()
    upload = begun.split("<UploadId>")[1].split("<")[0]
    assert upload == "upload-0001"
    for number, part in ((1, b"aa"), (2, b"bb"), (3, b"cc")):
        target = f"/b/big?partNumber={number}&uploadId={upload}"
        assert signed(s3, "PUT", target, part).header("ETag")
    manifest = (
        b'<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        b"<Part><PartNumber>2</PartNumber></Part><Part><PartNumber>1</PartNumber></Part>"
        b"</CompleteMultipartUpload>"
    )
    done = signed(s3, "POST", f"/b/big?uploadId={upload}", manifest).body.decode()
    assert done.endswith("-2&quot;</ETag></CompleteMultipartUploadResult>")
    assert signed(s3, "GET", "/b/big").body == b"bbaa"
    assert str(signed(s3, "HEAD", "/b/big").header("ETag")).endswith('-2"')


def test_multipart_corners(s3):
    assert signed(s3, "PUT", "/b/k?partNumber=1&uploadId=never", b"x").status == 404
    assert signed(s3, "POST", "/b/k?uploadId=never", b"<Part/>").status == 404
    assert b"MalformedPOSTRequest" in signed(s3, "POST", "/b/k").body
    store(s3).nameless_uploads = True
    assert b"<UploadId>" not in signed(s3, "POST", "/b/k?uploads").body
    upload = next(iter(store(s3).uploads))
    assert signed(s3, "PUT", f"/b/k?partNumber=0&uploadId={upload}", b"x").status == 404
    store(s3).failing_parts.add(1)
    assert signed(s3, "PUT", f"/b/k?partNumber=1&uploadId={upload}", b"x").status == 500
    assert signed(s3, "PUT", f"/b/k?partNumber=1&uploadId={upload}", b"x").status == 200
    assert signed(s3, "POST", f"/b/k?uploadId={upload}", b"<truncated").status == 200
    assert signed(s3, "GET", "/b/k").body == b""  # a manifest that is not XML names no parts
    begun = signed(s3, "POST", "/b/k?uploads").body
    assert signed(s3, "DELETE", "/b/k?uploadId=upload-0001").status == 204
    assert store(s3).aborted == ["upload-0001"] and begun
    store(s3).complete_fails = True
    signed(s3, "POST", "/b/k?uploads")
    upload = next(iter(store(s3).uploads))
    assert b"InternalError" in signed(s3, "POST", f"/b/k?uploadId={upload}", b"<x/>").body


# -- listings ------------------------------------------------------------------------------------


def _listing(server: StorageServer, query: str) -> str:
    return signed(server, "GET", f"/b?{query}").body.decode()


def test_listings_page_with_tokens_and_markers(s3):
    for key in ("d/b", "d/sub/x", "d/sub/y", "e"):
        signed(s3, "PUT", f"/b/{key}", b"!")
    first = _listing(s3, "list-type=2&prefix=d%2F&delimiter=%2F&max-keys=2")
    assert "<Key>d/a</Key>" in first and "<Key>d/b</Key>" in first
    token = first.split("<NextContinuationToken>")[1].split("<")[0]
    assert token == "d/b"
    second = _listing(s3, f"list-type=2&prefix=d%2F&delimiter=%2F&continuation-token={token}")
    assert "<Prefix>d/sub/</Prefix>" in second and "<IsTruncated>false" in second
    flat = _listing(s3, "prefix=d%2F&max-keys=3")
    assert flat.count("<Key>") == 3 and "<NextMarker>d/sub/x</NextMarker>" in flat
    assert "<Key>d/sub/y</Key>" in _listing(s3, "prefix=d%2F&marker=d%2Fsub%2Fx")
    assert "<IsTruncated>false" in _listing(s3, "prefix=nothing")
    assert signed(s3, "HEAD", "/b").status == 200
    assert "<Key>d/a</Key>" in signed(s3, "GET", "/b/d/?delimiter=%2F&prefix=d%2F").body.decode()


def test_a_page_counts_a_common_prefix_once():
    keys = ["a/1", "a/2", "b", "c/1", "d"]
    page = listing_page(keys, "", "/", 2)
    assert (page.contents, page.prefixes, page.last) == (["b"], ["a/"], "b")
    assert listing_page(keys, "", "", 10).contents == keys


# -- GCS -----------------------------------------------------------------------------------------


class _Key:
    """A stand-in public key: a signature is valid if it is the SHA-256 of the data."""

    def verify(self, data: bytes, signature: bytes, digest: str = "sha256") -> bool:
        return signature == hashlib.sha256(data).digest()


def _gcs_url(server: StorageServer, method: str, path: str, email: str) -> str:
    """A V4 signed URL for ``path``, signed with :class:`_Key`'s idea of a signature."""
    query = {
        "X-Goog-Algorithm": "GOOG4-RSA-SHA256",
        "X-Goog-Credential": f"{email}/20240102/auto/storage/goog4_request",
        "X-Goog-Date": "20240102T030405Z",
        "X-Goog-Expires": "60",
        "X-Goog-SignedHeaders": "host",
    }
    canonical_query = "&".join(
        f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
        for k, v in sorted(query.items())
    )
    host = f"{server.host}:{server.port}"
    canonical = f"{method}\n{path}\n{canonical_query}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD"
    scope = "20240102/auto/storage/goog4_request"
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    to_sign = f"GOOG4-RSA-SHA256\n20240102T030405Z\n{scope}\n{digest}"
    signature = hashlib.sha256(to_sign.encode()).hexdigest()
    return f"{path}?{canonical_query}&X-Goog-Signature={signature}"


def test_gcs_signed_urls(s3):
    store(s3).gcs_key = _Key()
    store(s3).gcs_email = "svc@p"
    answer = ask(s3, "GET", _gcs_url(s3, "GET", "/b/top", "svc@p"))
    assert answer.body == b"0123456789"
    assert str(answer.header("x-goog-hash")).startswith("crc32c=")
    assert ask(s3, "GET", _gcs_url(s3, "GET", "/b/top", "other@p")).status == 403
    assert ask(s3, "GET", _gcs_url(s3, "GET", "/b/top", "svc@p")[:-2] + "00").status == 403
    assert ask(s3, "GET", "/b/top").status == 403


# -- Swift ---------------------------------------------------------------------------------------


@pytest.fixture
def swift(tmp_path: Path) -> Iterator[StorageServer]:
    """A Swift account ``AUTH_p`` over a directory, with container ``c``."""
    with StorageServer(DirectoryStore(tmp_path / "root"), style="davix") as srv:
        srv.swift = Swift(token="TOK", account="AUTH_p")
        srv.store.make_bucket("c")
        yield srv


def _swift(
    server: StorageServer, method: str, path: str, body: bytes = b"", copy: str = ""
) -> Answer:
    """One request under the account, with its token (and an ``X-Copy-From``, if given)."""
    headers = {"X-Auth-Token": "TOK", **({"X-Copy-From": copy} if copy else {})}
    return ask(server, method, f"/v1/AUTH_p{path}", body, headers)


def test_swift(swift):
    assert ask(swift, "GET", "/v1/AUTH_p/c/x").status == 401
    assert _swift(swift, "PUT", "/c/dir/f", b"data").status == 201
    assert _swift(swift, "GET", "/c/dir/f").body == b"data"
    assert _swift(swift, "HEAD", "/c").status == 204
    assert _swift(swift, "HEAD", "/nocontainer").status == 404
    assert _swift(swift, "PUT", "/new").status == 201
    assert _swift(swift, "PUT", "/c/marker/").status == 201
    listing = _swift(swift, "GET", "/c?prefix=&delimiter=/").body.decode()
    assert '<subdir name="dir/">' in listing and '<subdir name="marker/">' in listing
    flat = _swift(swift, "GET", "/c?prefix=dir/").body.decode()
    assert "<name>dir/f</name><hash>0</hash><bytes>4</bytes>" in flat
    assert _swift(swift, "GET", "/c?prefix=none").status == 204
    assert _swift(swift, "PUT", "/c/g", copy="/c/dir/f").status == 201
    assert _swift(swift, "PUT", "/c/h", copy="/c/none").status == 404
    assert _swift(swift, "DELETE", "/c/g").status == 204
    assert _swift(swift, "DELETE", "/c/g").status == 404
    assert _swift(swift, "POST", "/c/dir/f").status == 405
    assert ask(swift, "GET", "/v1/elsewhere/c/x", headers={"X-Auth-Token": "TOK"}).status == 404


def test_swift_without_an_account_or_a_token(tmp_path: Path):
    with StorageServer(DirectoryStore(tmp_path / "root")) as srv:
        srv.swift = Swift()
        srv.add_file("/c/f", b"x")
        assert ask(srv, "GET", "/c/f").body == b"x"


def test_a_manifest_that_declares_a_document_type_names_no_parts():
    """The fake reads XML as the clients do (:mod:`xrdcore.safexml`): no DOCTYPE, no parts."""
    assert _objects._part_numbers(b"<!DOCTYPE x><x><PartNumber>1</PartNumber></x>") == []
