"""The session's bodies: reading an answer, ``100-continue``, and uploads the caller streams.

What is pinned here is ownership as much as bytes: which answers give their
connection back to the pool (read to the end, or a short rest drained) and
which drop it (cut short, abandoned with much unread, answered before the
body went), because a wrong call hands the next request a connection with
somebody else's bytes on it.
"""

from __future__ import annotations

import contextlib
import http.client
import os
import socket
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any, cast

import pytest

from xrdcore import errors as core_errors
from xrdhttp import expect, session
from xrdhttp.session import Hop, Policy, RedirectPolicy, Session, Upload

from tests._http import Seen, answer, serve
from tests._sockets import Scripted, read_exactly, read_request

Start = Callable[[Callable[[socket.socket], None]], Scripted]
BIG = os.urandom(expect.EXPECT_OVER * 2 + 3)


def _url(server: Scripted, path: str = "/f") -> str:
    return f"http://127.0.0.1:{server.port}{path}"


def _raw_answers(*payloads: bytes) -> Callable[[socket.socket], None]:
    """A script sending ``payloads`` in turn, one per request on whichever connection."""
    pending = list(payloads)

    def script(sock: socket.socket) -> None:
        # A client that gives a body up hangs up under the send: that is
        # the test's to check, not the server's to report.
        with contextlib.suppress(OSError):
            while pending:
                line, _ = read_request(sock)
                if not line:
                    return
                sock.sendall(pending.pop(0))

    return script


# ---------------------------------------------------------------------------
# Reading an answer
# ---------------------------------------------------------------------------


def test_headers_length_and_reading_in_pieces(scripted: Start) -> None:
    server = scripted(_raw_answers(answer(200, b"0123456789", headers={"X-A": "one"})))
    with Session() as client:
        response = client.request("GET", _url(server))
        assert response.header("x-a") == "one"
        assert response.header("X-Missing", "none") == "none"
        assert response.length == 10 and response.owed == 10
        assert response.read(3) == b"012"
        assert response.readline() == b"3456789"
        assert response.read(5) == b""  # the true end: nothing owed
        response.close()
        response.close()  # idempotent
        assert client.idle_count() == 1


def test_an_unusual_length_is_no_length(scripted: Start) -> None:
    head = b"HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\nhello"
    server = scripted(_raw_answers(head))
    with Session() as client, client.request("GET", _url(server)) as response:
        assert response.length is None
        assert response.body() == b"hello"


def test_large_reads_go_through_the_direct_reader(scripted: Start) -> None:
    payload = os.urandom(300_000)
    server = scripted(_raw_answers(answer(200, payload)))
    with Session() as client, client.request("GET", _url(server)) as response:
        got = bytearray()
        buffer = bytearray(1 << 17)
        while count := response.readinto(buffer):
            got += buffer[:count]
        assert bytes(got) == payload


def _cut(sock: socket.socket) -> None:
    """Declare a hundred bytes, send ten, hang up."""
    read_request(sock)
    sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" + b"x" * 10)


@pytest.mark.parametrize("how", ["read", "readinto", "body"])
def test_a_body_cut_short_is_a_transport_error(scripted: Start, how: str) -> None:
    server = scripted(_cut)
    with Session() as client:
        response = client.request("GET", _url(server))
        with pytest.raises(core_errors.ConnectionError) as caught:
            if how == "read":
                while response.read(64):
                    pass
            elif how == "readinto":
                while response.readinto(bytearray(64)):
                    pass
            else:
                response.body()
        assert isinstance(caught.value.__cause__, http.client.IncompleteRead)
        assert response.closed and client.idle_count() == 0


def test_body_truncates_at_its_limit_and_head_has_none(scripted: Start) -> None:
    big = os.urandom(100_000)
    server = scripted(
        _raw_answers(
            answer(200, big),
            answer(200, b"x" * 50),
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n",
        )
    )
    with Session() as client:
        assert client.request("GET", _url(server)).body(limit=10) == big[:10]
        assert client.idle_count() == 0  # too much left to drain: dropped
        assert client.request("GET", _url(server)).body(limit=10) == b"x" * 10
        assert client.idle_count() == 1  # a short rest was drained: kept
        assert client.request("HEAD", _url(server)).body() == b""


@pytest.mark.parametrize("method", ["read", "readinto", "readline"])
def test_a_failed_read_drops_the_connection(
    scripted: Start, monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    server = scripted(_raw_answers(answer(200, b"abc")))

    def broken(*args: object) -> Any:
        raise ConnectionResetError("reset")

    with Session() as client:
        response = client.request("GET", _url(server))
        monkeypatch.setattr(response._raw, method, broken)
        monkeypatch.setattr(response, "_reader", SimpleNamespace(readinto=broken))
        with pytest.raises(core_errors.ConnectionError, match="reset"):
            getattr(response, method)(bytearray(4) if method == "readinto" else 4)
        assert response.closed and client.idle_count() == 0


def test_shutdown_wakes_a_reader_and_abort_is_reported_as_such(scripted: Start) -> None:
    server = scripted(_cut)
    with Session() as client:
        response = client.request("GET", _url(server))
        response.shutdown()
        with pytest.raises(core_errors.ConnectionError):
            while response.read(100):
                pass
    other = scripted(_cut)
    client = Session()
    response = client.request("GET", _url(other))
    client.abort()
    with pytest.raises(session.SessionClosedError, match="aborted"):
        while response.read(100):
            pass


def test_what_goes_back_to_the_pool(scripted: Start, monkeypatch: pytest.MonkeyPatch) -> None:
    chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
    closing = answer(200, b"bye", headers={"Connection": "close"})
    server = scripted(_raw_answers(chunked, answer(200, b"rest"), closing))
    with Session() as client:
        # A chunked body abandoned unread: its rest is unknown, so it is dropped.
        client.request("GET", _url(server)).close()
        assert client.idle_count() == 0
    server = scripted(_raw_answers(answer(200, b"rest"), closing))
    with Session() as client:
        response = client.request("GET", _url(server))

        def broken(*args: object) -> bytes:
            raise ConnectionResetError("reset")

        monkeypatch.setattr(response._raw, "read", broken)
        response.close()  # the drain failed: dropped
        assert client.idle_count() == 0
    server = scripted(_raw_answers(closing))
    with Session() as client:
        assert client.request("GET", _url(server)).body() == b"bye"
        assert client.idle_count() == 0  # the server said it would close


# ---------------------------------------------------------------------------
# Expect: 100-continue
# ---------------------------------------------------------------------------


def _door(sock: socket.socket) -> None:
    """EOS's head node: a large ``PUT`` is redirected before its body; the disk server takes it."""
    while True:
        line, headers = read_request(sock)
        if not line:
            return
        if line.startswith("PUT /f "):
            sock.sendall(answer(307, headers={"Location": "/disk"}))
            return  # and hangs up, as EOS does
        if line.startswith("PUT /refused "):
            sock.sendall(answer(403, b"quota", "Forbidden"))
            return
        if headers.get("expect"):
            sock.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
        body = read_exactly(sock, int(headers["content-length"]))
        sock.sendall(answer(201, str(len(body)).encode(), "Created"))


def test_a_large_upload_is_redirected_before_its_body(scripted: Start) -> None:
    server = scripted(_door)
    with Session() as client:
        response = client.request("PUT", _url(server), body=BIG)
        assert (response.status, response.url) == (201, _url(server, "/disk"))
        assert response.body() == str(len(BIG)).encode()
        response = client.request("PUT", _url(server, "/refused"), body=BIG)
        assert (response.status, response.body()) == (403, b"quota")
        assert client.idle_count() == 0  # the refusal's connection was spent


def test_a_server_that_never_says_continue_gets_the_body_anyway(scripted: Start) -> None:
    seen: list[Seen] = []

    def deaf(sock: socket.socket) -> None:
        _, headers = read_request(sock)
        seen.append(Seen("PUT", "/f", headers, read_exactly(sock, len(BIG)), 1))
        sock.sendall(answer(201))

    server = scripted(deaf)
    with Session(policy=Policy(continue_wait=0.1)) as client:
        assert client.request("PUT", _url(server), body=BIG).body() == b""
    assert seen[0].body == BIG and seen[0].headers["expect"] == "100-continue"


class _FakeConn:
    """Just enough of a connection for :func:`session._exchange`, failing the body send."""

    sock = None

    def __init__(self, answers: list[object]) -> None:
        self.answers = answers

    def putrequest(self, *args: object, **kwargs: object) -> None:
        pass

    def putheader(self, *args: object) -> None:
        pass

    def endheaders(self) -> None:
        pass

    def send(self, data: object) -> None:
        raise BrokenPipeError("hung up")

    def getresponse(self) -> object:
        found = self.answers.pop(0)
        if isinstance(found, Exception):
            raise found
        return found

    def close(self) -> None:
        pass


def test_a_hang_up_mid_body_returns_the_answer_given_first() -> None:
    hop = Hop("PUT", "http://h/f", "http://h/f", {}, b"data", True)
    early = object()
    conn = cast(http.client.HTTPConnection, _FakeConn([early]))
    assert session._exchange(conn, hop, "/f", 1.0) == (early, False)
    silent = cast(http.client.HTTPConnection, _FakeConn([http.client.RemoteDisconnected("gone")]))
    with pytest.raises(BrokenPipeError):
        session._exchange(silent, hop, "/f", 1.0)


# ---------------------------------------------------------------------------
# Streamed uploads
# ---------------------------------------------------------------------------


def _store(seen: list[Seen]) -> Callable[[socket.socket], None]:
    """Take any upload, declared or chunked, and answer ``201`` with what arrived."""
    return serve(lambda r: answer(201, r.body, "Created"), seen)


def test_an_upload_of_declared_length(scripted: Start) -> None:
    seen: list[Seen] = []
    server = scripted(_store(seen))
    with Session() as client:
        upload = client.upload("PUT", _url(server), 6, headers={"X-Mine": "1"})
        upload.write(b"abc")
        upload.write(b"")
        upload.write(memoryview(b"def"))
        with upload.finish() as response:
            assert (response.status, response.body()) == (201, b"abcdef")
        with pytest.raises(ValueError, match="finished or aborted"):
            upload.write(b"more")
    assert seen[0].headers["content-length"] == "6"
    assert seen[0].headers["expect"] == "100-continue"


def test_a_chunked_upload(scripted: Start) -> None:
    seen: list[Seen] = []
    server = scripted(_store(seen))
    with Session() as client:
        upload = client.upload("PUT", _url(server), None)
        for piece in (b"one", b"two", b"three"):
            upload.write(piece)
        assert upload.finish().body() == b"onetwothree"
    assert seen[0].headers["transfer-encoding"] == "chunked"


def test_an_empty_upload_is_answered_at_once(scripted: Start) -> None:
    seen: list[Seen] = []
    server = scripted(_store(seen))
    with Session() as client:
        upload = client.upload("PUT", _url(server), 0)
        assert upload.done and upload.early is not None
        upload.write(b"")
        with upload.finish() as response:
            assert response.status == 201
    assert "expect" not in seen[0].headers


def test_an_upload_refused_or_redirected_before_its_body(scripted: Start) -> None:
    server = scripted(_door)
    with Session() as client:
        upload = client.upload("PUT", _url(server, "/refused"), 5)
        upload.write(b"ignored")  # the server has answered: dropped, not an error
        response = upload.finish()
        assert (response.status, response.body()) == (403, b"quota")
        upload = client.upload("PUT", _url(server), 4)
        assert upload.url == _url(server, "/disk")
        upload.write(b"data")
        assert upload.finish().body() == b"4"


def test_an_upload_redirected_too_often(scripted: Start) -> None:
    def loop(sock: socket.socket) -> None:
        read_request(sock)
        sock.sendall(answer(307, headers={"Location": "/again"}))

    server = scripted(loop)
    policy = Policy(redirects=RedirectPolicy(limit=1))
    with Session(policy=policy) as client, pytest.raises(session.RedirectError):
        client.upload("PUT", _url(server), 3)


def test_an_upload_that_cannot_connect() -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with Session() as client, pytest.raises(core_errors.ConnectionError):
        client.upload("PUT", f"http://127.0.0.1:{port}/f", 3)


def test_upload_misuse_and_abandonment(scripted: Start) -> None:
    seen: list[Seen] = []
    server = scripted(_store(seen))
    with Session() as client:
        upload = client.upload("PUT", _url(server), 3)
        with pytest.raises(ValueError, match="past the declared 3 bytes"):
            upload.write(b"four")
        upload.write(b"ab")
        with pytest.raises(ValueError, match="after 2 of 3 bytes"):
            upload.finish()
        upload = client.upload("PUT", _url(server), 3)
        upload.abort()
        assert upload.done
        refused = scripted(_door)
        upload = client.upload("PUT", _url(refused, "/refused"), 3)
        upload.abort()  # the early answer is closed with it
        assert upload.early is not None and upload.early.closed
        assert client.idle_count() == 0


def _fake_upload(conn: Any, length: int | None = 3) -> Upload:
    """An upload whose head went out on ``conn``, for the failures a real socket rarely gives."""
    exchange = session._Exchange(
        ("http", "h", 80, None), cast(http.client.HTTPConnection, conn), False
    )
    hop = Hop("PUT", "http://h/f", "http://h/f", {}, None, True)
    return Upload(Session(), exchange, hop, length)


def test_an_upload_hung_up_on_keeps_the_servers_answer() -> None:
    raw = SimpleNamespace(status=413, reason="Too Large", msg=http.client.HTTPMessage(), fp=None)
    upload = _fake_upload(_FakeConn([raw]))
    upload.write(b"abc")
    assert upload.early is not None and upload.early.status == 413
    assert upload.finish() is upload.early
    silent = _fake_upload(_FakeConn([http.client.RemoteDisconnected("gone")]))
    with pytest.raises(core_errors.ConnectionError, match="hung up"):
        silent.write(b"abc")
    assert silent.done


def test_an_upload_failing_otherwise_is_abandoned() -> None:
    class Failing(_FakeConn):
        def send(self, data: object) -> None:
            raise OSError("disk on fire")

    upload = _fake_upload(Failing([]))
    with pytest.raises(core_errors.ConnectionError, match="disk on fire"):
        upload.write(b"x")
    assert upload.done


def test_an_upload_whose_answer_never_comes() -> None:
    class Quiet(_FakeConn):
        def send(self, data: object) -> None:
            pass

    upload = _fake_upload(Quiet([http.client.RemoteDisconnected("gone")]), None)
    upload.write(b"x")
    with pytest.raises(core_errors.ConnectionError, match="gone"):
        upload.finish()
