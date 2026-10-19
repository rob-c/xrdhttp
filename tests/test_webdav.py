"""WebDAV multistatus and ``Digest`` parsing."""

from __future__ import annotations

import base64
import hashlib

import pytest

from xrdcore.safexml import fromstring
from xrdhttp import webdav

MULTISTATUS = b"""<?xml version="1.0"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>https://se.example/store/a%20dir/</D:href>
    <D:propstat>
      <D:prop><D:resourcetype><D:collection/></D:resourcetype>
        <D:getlastmodified>Tue, 02 Jan 2024 03:04:05 GMT</D:getlastmodified>
        <D:creationdate>2024-01-01T00:00:00Z</D:creationdate>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>/store/f.root</D:href>
    <D:propstat><D:prop><D:getcontentlength>12</D:getcontentlength></D:prop>
      <D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>
    <D:propstat><D:prop><D:resourcetype/><D:getcontentlength>42</D:getcontentlength>
      <D:getlastmodified>not a date</D:getlastmodified></D:prop></D:propstat>
  </D:response>
  <D:response><D:href>/empty</D:href></D:response>
</D:multistatus>"""


def test_resources_are_read_from_the_first_successful_propstat():
    responses = fromstring(MULTISTATUS).findall(webdav.DAV + "response")
    directory, file, empty = (webdav.resource(r) for r in responses)
    assert directory == webdav.Resource(True, 0, 1704164645, 1704067200)
    assert file == webdav.Resource(False, 42, 0, 0)
    assert empty == webdav.Resource()
    assert webdav.text(responses[0], "href") == "https://se.example/store/a%20dir/"
    assert webdav.text(None, "href") == "" and webdav.text(responses[0], "nothing") == ""


@pytest.mark.parametrize(
    ("href", "path"),
    [
        ("https://se.example/store/a%20dir/", "/store/a dir/"),
        ("/store/f%2Broot", "/store/f+root"),
        ("", "/"),
    ],
)
def test_href_path(href, path):
    assert webdav.href_path(href) == path


@pytest.mark.parametrize(
    ("stamp", "seconds"),
    [
        ("Tue, 02 Jan 2024 03:04:05 GMT", 1704164645),
        ("2024-01-02T03:04:05Z", 1704164645),
        ("", 0),
        ("whenever", 0),
    ],
)
def test_epoch(stamp, seconds):
    assert webdav.epoch(stamp) == seconds


def test_digest_picking_canonicalises_names_and_encodings():
    sha = hashlib.sha256(b"x").digest()
    header = f"adler32=0A0B0C0D, SHA-256={base64.b64encode(sha).decode()}, sha={'f' * 40}"
    assert webdav.pick_digest(header, "adler32") == "0a0b0c0d"
    assert webdav.pick_digest(header, "sha256") == sha.hex()
    assert webdav.pick_digest(header, "SHA1") == "f" * 40
    assert webdav.pick_digest(header, "md5") == ""
    assert webdav.pick_digest("garbage, md5", "md5") == ""


@pytest.mark.parametrize(
    ("value", "algorithm", "expected"),
    [
        ("0123456789ABCDEF", "crc64", "0123456789abcdef"),
        (base64.b64encode(bytes(8)).decode(), "crc64", "0" * 16),
        ("not base64!", "md5", "not base64!"),
        ("CAFE", "crc32c", "cafe"),
    ],
)
def test_as_hex(value, algorithm, expected):
    assert webdav.as_hex(value, algorithm) == expected


def test_is_hex_needs_the_exact_width():
    assert webdav.is_hex("a" * 32, "md5")
    assert not webdav.is_hex("a" * 31, "md5")
    assert not webdav.is_hex("z" * 32, "md5")
    assert not webdav.is_hex("abc", "no-such-hash")


def test_the_want_digest_spellings():
    assert webdav.WANT_DIGEST["sha256"] == "sha-256"
    assert webdav.canonical_digest(" SHA-512 ") == "sha512"
    assert "adler32" in webdav.HEX_DIGESTS
