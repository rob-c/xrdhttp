"""The reply helpers in-process HTTP fakes answer with: byte ranges and WebDAV multistatus.

Moved here from xrdsec's suite with :func:`~xrdhttp.testing.ranged_reply`,
:func:`~xrdhttp.testing.propfind_reply` and :func:`~xrdhttp.testing.dav_entries`,
which are HTTP and live in :mod:`xrdhttp.testing` now.
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from xrdcore import safexml
from xrdhttp.testing import (
    BOUNDARY,
    DAVEntry,
    Response,
    dav_entries,
    multistatus,
    propfind_reply,
    ranged_reply,
)

DATA = bytes(range(10))
DAV = "{DAV:}"


@pytest.mark.parametrize(
    ("header", "status", "body", "content_range"),
    [
        (None, 200, DATA, None),
        ("bytes=2-4", 206, DATA[2:5], "bytes 2-4/10"),
        ("bytes=7-", 206, DATA[7:], "bytes 7-9/10"),
        ("bytes=-3", 206, DATA[7:], "bytes 7-9/10"),
        ("bytes=-30", 206, DATA, "bytes 0-9/10"),
        ("bytes=5-100", 206, DATA[5:], "bytes 5-9/10"),
        ("bytes=10-", 416, b"", "bytes */10"),
        ("bytes=10-12,20-", 416, b"", "bytes */10"),
        ("bytes=1-1,40-", 206, DATA[1:2], "bytes 1-1/10"),
        ("items=0-1", 200, DATA, None),
        ("bytes=a-b", 200, DATA, None),
        ("bytes=-", 200, DATA, None),
        ("bytes=", 200, DATA, None),
        ("bytes=3", 200, DATA, None),
    ],
)
def test_ranged_reply(header, status, body, content_range) -> None:
    reply = ranged_reply(DATA, header, content_type="application/x-test", headers={"X": "y"})
    assert (reply.status, reply.body, reply.headers.get("Content-Range")) == (
        status,
        body,
        content_range,
    )
    if status != 416:
        assert reply.headers["X"] == "y" and reply.headers["Content-Type"] == "application/x-test"


def test_ranged_reply_with_several_ranges() -> None:
    multi = ranged_reply(DATA, "bytes=0-1,4-5")
    assert multi.headers["Content-Type"] == f"multipart/byteranges; boundary={BOUNDARY}"
    assert b"Content-Range: bytes 4-5/10\r\n\r\n\x04\x05" in multi.body
    assert b"Content-Type: application/octet-stream" in multi.body
    assert multi.body.endswith(f"--{BOUNDARY}--\r\n".encode())
    first = ranged_reply(DATA, "bytes=0-1,4-5", several="first")
    assert (first.body, first.headers["Content-Range"]) == (DATA[0:2], "bytes 0-1/10")
    span = ranged_reply(DATA, "bytes=4-5,0-1", several="coalesce")
    assert (span.body, span.headers["Content-Range"]) == (DATA[0:6], "bytes 0-5/10")
    assert "Content-Type" not in ranged_reply(DATA, "bytes=0-1").headers


def _responses(reply: Response) -> list[ET.Element]:
    return safexml.fromstring(reply.body).findall(f"{DAV}response")


def test_propfind_reply() -> None:
    reply = propfind_reply(
        [
            DAVEntry("/", collection=True),
            DAVEntry("/d/", collection=False, size=3, name="a<b"),
            DAVEntry("/c", collection=True, created=0.0),
            DAVEntry("/gone", status=404),
            DAVEntry("/sized", collection=True, length=4096),
        ]
    )
    assert reply.status == 207 and reply.headers["Content-Type"].startswith("text/xml")
    root, file, collection, gone, sized = _responses(reply)
    assert root.findtext(f"{DAV}href") == "/"
    assert root.findtext(f".//{DAV}displayname") == "/"
    assert root.find(f".//{DAV}getcontentlength") is None  # a collection has no size
    assert file.findtext(f"{DAV}href") == "/d"  # a file's href never ends in a slash
    assert file.findtext(f".//{DAV}getcontentlength") == "3"
    assert file.findtext(f".//{DAV}displayname") == "a<b"
    assert collection.findtext(f"{DAV}href") == "/c/"
    assert collection.find(f".//{DAV}collection") is not None
    assert collection.findtext(f".//{DAV}creationdate") == "1970-01-01T00:00:00Z"
    assert gone.findtext(f"{DAV}status") == "HTTP/1.1 404 Not Found"
    assert sized.findtext(f".//{DAV}getcontentlength") == "4096"
    assert propfind_reply([], status=200, content_type="application/xml").status == 200
    # RFC 4918's status is a whole status line; an unregistered code keeps the space.
    (odd,) = _responses(propfind_reply([DAVEntry("/odd", status=499)]))
    assert odd.findtext(f"{DAV}status") == "HTTP/1.1 499 "
    assert multistatus([]).endswith(b'<D:multistatus xmlns:D="DAV:"></D:multistatus>')


def test_dav_entries_walk_a_directory(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "deep.txt").write_bytes(b"deep")
    (tmp_path / "a b.txt").write_bytes(b"abc")
    shallow = list(dav_entries(tmp_path, "https://h/s", 1))
    assert [entry.href for entry in shallow] == [
        "https://h/s",
        "https://h/s/a%20b.txt",
        "https://h/s/sub",
    ]
    assert shallow[1].size == 3 and not shallow[1].collection and shallow[1].name == "a b.txt"
    assert len(list(dav_entries(tmp_path, "/s", 10))) == 4
    (missing,) = dav_entries(tmp_path / "absent", "/absent", 1)
    assert missing.status == 404
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    assert next(dav_entries(fifo, "/fifo", 0)).status == 404
