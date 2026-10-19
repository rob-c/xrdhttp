"""The fake storage element's WebDAV: verbs, ranges, digests, Metalink, and both stores."""

from __future__ import annotations

import base64
import hashlib
import os
import zlib
from collections.abc import Iterator
from pathlib import Path

import pytest

from xrdhttp.testing import BOUNDARY, DirectoryStore, MemoryStore, StorageServer
from xrdhttp.testing._digests import legacy_digest, repr_digest
from xrdhttp.testing._replies import parse_ranges, spans

from tests._storage import ask, raw

BODY = b"0123456789"


@pytest.fixture(params=["memory", "directory"])
def server(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[StorageServer]:
    """The XrdCl-style fake over each store, holding ``/d/f`` and the empty ``/d/sub``."""
    store = MemoryStore() if request.param == "memory" else DirectoryStore(tmp_path / "root")
    with StorageServer(store) as srv:
        srv.add_file("/d/f", BODY)
        srv.add_dir("/d/sub")
        yield srv


@pytest.fixture
def davix(tmp_path: Path) -> Iterator[StorageServer]:
    """The davix-style fake over a directory, holding ``/d/f`` and the empty ``/d/sub``."""
    with StorageServer(DirectoryStore(tmp_path / "root"), style="davix") as srv:
        srv.add_file("/d/f", BODY)
        srv.add_dir("/d/sub")
        yield srv


# -- the namespace verbs -----------------------------------------------------------------------


def test_options_advertises_webdav_unless_it_is_off(server):
    assert ask(server, "OPTIONS", "/").header("DAV") == "1,2"
    server.no_dav = True
    answer = ask(server, "OPTIONS", "/")
    assert answer.header("DAV") is None and "PROPFIND" in str(answer.header("Allow"))


def test_propfind_lists_a_collection_once_encoded(server):
    server.add_file("/d/with space", b"")
    answer = ask(server, "PROPFIND", "/d/", b"<propfind/>", {"Depth": "1"})
    assert answer.status == 207
    body = answer.body.decode()
    assert "<D:href>/d/</D:href>" in body and "<D:href>/d/sub/</D:href>" in body
    assert "<D:href>/d/with%20space</D:href>" in body
    assert "<D:getcontentlength>10</D:getcontentlength>" in body
    assert body.count("<D:collection/>") == 2
    alone = ask(server, "PROPFIND", "/d", headers={"Depth": "0"}).body.decode()
    assert alone.count("<D:response>") == 1
    assert ask(server, "PROPFIND", "/d/f").body.count(b"<D:response>") == 1
    assert ask(server, "PROPFIND", "/missing").status == 404
    server.no_dav = True
    assert ask(server, "PROPFIND", "/d").status == 405


def test_davix_style_reports_a_collection_length_and_creation(davix):
    body = ask(davix, "PROPFIND", "/d", headers={"Depth": "0"}).body.decode()
    assert "<D:getcontentlength>4096</D:getcontentlength>" in body
    assert "<D:creationdate>" in body


def test_a_child_that_is_neither_file_nor_collection_is_not_listed(davix, tmp_path):
    os.mkfifo(tmp_path / "root" / "d" / "pipe")
    body = ask(davix, "PROPFIND", "/d", headers={"Depth": "1"}).body.decode()
    assert "pipe" not in body and "/d/f" in body
    assert ask(davix, "GET", "/d/pipe").status == 404


def test_mkcol(server):
    assert ask(server, "MKCOL", "/d/new").status == 201
    assert ask(server, "MKCOL", "/d/new").status == 405
    assert ask(server, "MKCOL", "/d/f").status == 405
    assert ask(server, "MKCOL", "/x/y").status == 409
    assert ask(server, "MKCOL", "/d/f/y").status == 409  # the parent is a file
    server.mkcol_parents = True
    assert ask(server, "MKCOL", "/x/y").status == 201
    assert server.store.entry("/x") is not None


def test_delete(server, davix):
    server.add_file("/d/sub/child", b"c")
    assert ask(server, "DELETE", "/d/sub").status == 204  # with all beneath it
    assert server.store.entry("/d/sub/child") is None
    assert ask(server, "DELETE", "/d/f").status == 204
    assert ask(server, "DELETE", "/d/f").status == 404
    davix.add_file("/d/sub/child", b"c")
    assert ask(davix, "DELETE", "/d/sub").status == 409  # grid-style: only if empty
    assert ask(davix, "DELETE", "/d/sub/child").status == 204
    assert ask(davix, "DELETE", "/d/sub").status == 204


def test_move(server):
    server.add_file("/d/g", b"old")
    assert ask(server, "MOVE", "/d/f", headers={"Destination": "http://h/d/g"}).status == 204
    assert server.contents("/d/g") == BODY
    assert ask(server, "MOVE", "/d/g", headers={"Destination": "/e/h%20i"}).status == 201
    assert server.contents("/e/h i") == BODY
    server.add_file("/d/sub/x", b"x")
    assert ask(server, "MOVE", "/d/sub", headers={"Destination": "/m/sub"}).status == 201
    assert server.contents("/m/sub/x") == b"x" and server.store.entry("/d/sub") is None
    assert ask(server, "MOVE", "/nothing", headers={"Destination": "/e/x"}).status == 404


def test_a_post_is_not_allowed_here(server):
    assert ask(server, "POST", "/d", b"hi", {"Content-Type": "text/plain"}).status == 405


def test_put(server):
    assert ask(server, "PUT", "/d/new", b"n").status == 201
    assert ask(server, "PUT", "/d/new", b"m").status == 204
    assert server.contents("/d/new") == b"m"
    assert ask(server, "PUT", "/d/new", b"o", {"If-None-Match": "*"}).status == 412
    assert ask(server, "PUT", "/d/fresh", b"o", {"If-None-Match": "*"}).status == 201
    assert ask(server, "PUT", "/d/sub", b"o").status == 405
    assert ask(server, "PUT", "/x/y", b"o").status == 409
    assert ask(server, "PUT", "/d/f/y", b"o").status == 409
    head = b"PUT /d/chunked HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
    assert raw(server, head + b"2;ext=1\r\nab\r\n2\r\ncd\r\n0\r\n\r\n").startswith(b"HTTP/1.1 201")
    assert server.contents("/d/chunked") == b"abcd"
    # A sender that hangs up mid-way ends the body where the data ends.
    assert raw(server, head + b"2\r\nab\r\n").startswith(b"HTTP/1.1 204")
    assert server.contents("/d/chunked") == b"ab"


# -- reading -----------------------------------------------------------------------------------


def test_get_and_head(server, davix):
    answer = ask(server, "GET", "/d/f")
    assert (answer.status, answer.body, answer.header("Accept-Ranges")) == (200, BODY, "bytes")
    head = ask(server, "HEAD", "/d/f")
    assert (head.body, head.header("Content-Length")) == (b"", "10")
    assert ask(server, "GET", "/missing").status == 404
    collection = ask(server, "GET", "/d")
    assert (collection.status, collection.body) == (200, b"")
    assert ask(davix, "GET", "/d").status == 403
    server.add_file("/d/empty", b"")
    assert ask(server, "GET", "/d/empty").body == b""


def test_ranges(server):
    def get(span: str) -> tuple[int, bytes, str | None]:
        answer = ask(server, "GET", "/d/f", headers={"Range": span})
        return answer.status, answer.body, answer.header("Content-Range")

    assert get("bytes=2-4") == (206, b"234", "bytes 2-4/10")
    assert get("bytes=-3") == (206, b"789", "bytes 7-9/10")
    assert get("bytes=8-") == (206, b"89", "bytes 8-9/10")
    assert get("bytes=20-") == (416, b"", "bytes */10")
    assert get("lines=1-2")[0] == 200  # not byte ranges: the whole body
    status, body, _ = get("bytes=0-1,4-5")
    assert status == 206 and body.count(f"--{BOUNDARY}".encode()) == 3
    assert b"Content-Range: bytes 4-5/10\r\n\r\n45" in body
    server.multipart_ranges = False
    assert get("bytes=0-1,4-5") == (206, b"01", "bytes 0-1/10")
    server.coalesce_ranges = True
    assert get("bytes=0-1,4-5") == (206, b"012345", "bytes 0-5/10")
    server.ignore_ranges = True
    assert get("bytes=0-1")[:2] == (200, BODY)


def test_a_truncated_get_promises_more_than_it_sends(server):
    server.truncate_at = 4
    answer = raw(server, b"GET /d/f HTTP/1.1\r\nHost: h\r\n\r\n")
    assert b"Content-Length: 10" in answer and answer.endswith(b"\r\n\r\n0123")
    answer = raw(server, b"GET /missing HTTP/1.1\r\nHost: h\r\n\r\n")
    assert b"Content-Length: 9" in answer and answer.endswith(b"\r\n\r\nnot ")
    assert ask(server, "HEAD", "/d/f").status == 200  # a HEAD has no body to cut
    server.truncate_at = 100
    assert ask(server, "GET", "/d/f").body == BODY


def test_digests(server, davix):
    def digest(target: StorageServer, method: str, **headers: str) -> dict[str, str | None]:
        answer = ask(target, method, "/d/f", headers=headers)
        return {name: answer.header(name) for name in ("Digest", "Repr-Digest")}

    md5 = base64.b64encode(hashlib.md5(BODY).digest()).decode()
    adler = f"{zlib.adler32(BODY):08x}"
    assert digest(server, "GET", **{"Want-Digest": "unixcksum;q=0.5,adler32,md5"}) == {
        "Digest": f"adler32={adler}",
        "Repr-Digest": None,
    }
    assert digest(davix, "GET", **{"Want-Digest": "adler32,md5,unixcksum"}) == {
        "Digest": f"adler32={adler},md5={md5}",
        "Repr-Digest": None,
    }
    assert digest(server, "HEAD", **{"Want-Digest": "unixcksum"})["Digest"] is None
    assert digest(davix, "HEAD", **{"Want-Digest": "adler32"})["Digest"] == f"adler32={adler}"
    davix.digest_on_head = False
    assert digest(davix, "HEAD", **{"Want-Digest": "adler32"})["Digest"] is None
    sha = base64.b64encode(hashlib.sha256(BODY).digest()).decode()
    wanted = {"Want-Repr-Digest": "md5=1, sha-256=9, adler=0, unknown=10, crc32c"}
    assert digest(server, "GET", **wanted)["Repr-Digest"] == f"sha-256=:{sha}:"
    assert digest(server, "GET", **{"Want-Repr-Digest": "adler=0"})["Repr-Digest"] is None
    server.legacy_digests = server.repr_digests = False
    assert digest(server, "GET", **{"Want-Digest": "md5", **wanted}) == {
        "Digest": None,
        "Repr-Digest": None,
    }


def test_a_metalink_is_advertised_for_a_file_or_a_bare_name(server):
    server.metalinks["/d/f"] = "http://h/f.meta4"
    server.metalinks["/logical"] = "http://h/l.meta4"
    link = ask(server, "HEAD", "/d/f").header("Link")
    assert link == '<http://h/f.meta4>; rel="describedby"; type="application/metalink4+xml"'
    bare = ask(server, "HEAD", "/logical")
    assert bare.status == 200 and str(bare.header("Link")).startswith("<http://h/l.meta4>")


# -- the pure helpers --------------------------------------------------------------------------


def test_range_parsing_refuses_what_is_not_a_range():
    assert parse_ranges("bytes=", 10) is None
    assert parse_ranges("bytes=5", 10) is None
    assert parse_ranges("bytes=-", 10) is None
    assert parse_ranges("bytes=a-b", 10) is None
    assert parse_ranges("bytes=0-100", 10) == [(0, 10)]
    assert spans("bytes=20-30", 10, "coalesce") == []
    assert spans("bytes=0-1,5-5", 10) == [(0, 2), (5, 6)]


def test_digest_values_are_hex_or_base64_by_algorithm():
    raw_bytes = {"crc32": b"\x00\x00\x00\x01", "sha1": b"\x01\x02"}
    assert legacy_digest("crc32,sha", {"crc32", "sha"}, True, raw_bytes.__getitem__) == (
        "crc32=00000001,sha=AQI="
    )
    assert repr_digest("sha=2, md5", {"sha"}, raw_bytes.__getitem__) == "sha=:AQI=:"
