"""``Expect: 100-continue``: the go-ahead, an early answer, and a server that ignores it.

EOS's head node answers a ``PUT`` with ``307`` to the disk server that will
hold the file and hangs up without reading the body; the scripted servers
here play that node, an obliging server, and one that never says ``100``.
"""

from __future__ import annotations

import http.client
import os
import socket
from types import SimpleNamespace
from typing import cast

import pytest

from xrdhttp import connection, expect

from tests._sockets import read_exactly, read_request

BIG = os.urandom(expect.EXPECT_OVER * 4 + 7)


@pytest.fixture
def put():
    """``put(port, body, wait)``: a ``PUT`` that asks first, as a client's upload path does."""
    opened: list[connection.HTTPConnection] = []

    def run(port: int, body: bytes, wait: float = expect.CONTINUE_WAIT) -> http.client.HTTPResponse:
        conn = connection.HTTPConnection("127.0.0.1", port, timeout=5)
        opened.append(conn)
        conn.putrequest("PUT", "/f")
        conn.putheader("Content-Length", str(len(body)))
        conn.putheader("Expect", "100-continue")
        conn.endheaders()
        try:
            expect.await_continue(conn, "PUT", wait)
        except expect.InterimAnswer as early:
            return early.response
        conn.send(body)
        return conn.getresponse()

    yield run
    for conn in opened:
        conn.close()


def test_wants_expect():
    assert expect.wants_expect("PUT", expect.EXPECT_OVER)
    assert expect.wants_expect("POST", None)
    assert not expect.wants_expect("PUT", expect.EXPECT_OVER - 1)
    assert not expect.wants_expect("GET", None)


def test_a_body_follows_the_go_ahead(scripted, put):
    got = {}

    def obliging(sock: socket.socket) -> None:
        _, headers = read_request(sock)
        sock.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
        got["body"] = read_exactly(sock, int(headers["content-length"]))
        sock.sendall(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")

    server = scripted(obliging)
    response = put(server.port, BIG)
    assert response.status == 201
    response.read()
    assert got["body"] == BIG


def test_an_early_answer_is_the_answer_and_the_body_is_never_sent(scripted, put):
    def head_node(sock: socket.socket) -> None:
        read_request(sock)
        sock.sendall(
            b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://disk/f\r\n"
            b"Content-Length: 4\r\n\r\nmove"
        )
        sock.settimeout(2)
        assert sock.recv(1) == b""  # the client hung up instead of sending

    server = scripted(head_node)
    response = put(server.port, BIG)
    assert response.status == 307 and response.getheader("Location") == "http://disk/f"
    assert response.read() == b"move"
    assert response.will_close
    response.close()


def test_a_server_that_ignores_the_expectation_still_gets_the_body(scripted, put):
    got = {}

    def deaf(sock: socket.socket) -> None:
        _, headers = read_request(sock)
        got["body"] = read_exactly(sock, int(headers["content-length"]))
        sock.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")

    server = scripted(deaf)
    response = put(server.port, BIG, wait=0.05)
    assert response.status == 204
    assert got["body"] == BIG


def test_interim_replay_closes_socket_once_and_reads_after_prefix():
    calls = []
    sock = SimpleNamespace(close=lambda: calls.append("closed"), recv_into=lambda view: 0)
    replay = expect._Replay(b"abc", sock)
    assert replay.readable()
    view = bytearray(4)
    assert replay.readinto(view) == 3
    assert replay.readinto(view) == 0
    replay.close()
    replay.close()
    assert calls == ["closed"]


@pytest.mark.parametrize("data", [b"", b"H"])
def test_interim_header_distinguishes_disconnect_from_partial_header(data):
    incoming = iter([data, b""])
    timeouts: list[float | None] = []
    sock = SimpleNamespace(
        gettimeout=lambda: 5,
        settimeout=timeouts.append,
        recv=lambda count: next(incoming, b""),
    )
    if data:
        assert expect._read_head(sock, 1) == data
    else:
        with pytest.raises(ConnectionError):
            expect._read_head(sock, 1)
    assert timeouts[-1] == 5


def test_interim_header_size_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(expect, "_HEAD_LIMIT", 0)
    sock = SimpleNamespace(
        gettimeout=lambda: 5, settimeout=lambda value: None, recv=lambda count: b"H"
    )
    with pytest.raises(http.client.LineTooLong):
        expect._read_head(sock, 1)


def test_the_interim_answer_carries_its_response():
    # Only ``status`` is read; a whole response would need a socket.
    response = cast(http.client.HTTPResponse, SimpleNamespace(status=403))
    answer = expect.InterimAnswer(response)
    assert answer.response is response and "403" in str(answer)


def test_interim_reader_accepts_lf_terminated_headers():
    """Moved from xgfalclient: a server that ends lines with a bare LF is still read."""
    incoming = iter(bytes([byte]) for byte in b"HTTP/1.1 100 Continue\n\n")
    sock = SimpleNamespace(
        gettimeout=lambda: 5, settimeout=lambda wait: None, recv=lambda count: next(incoming, b"")
    )
    assert expect._read_head(sock, 1) == b"HTTP/1.1 100 Continue\n\n"


def test_interim_reader_rejects_an_incomplete_status_line(monkeypatch):
    """Moved from xgfalclient: an interim answer that is no status line is ``BadStatusLine``."""
    monkeypatch.setattr(expect, "_read_head", lambda sock, wait: b"bad\r\n\r\n")
    sock = SimpleNamespace(recv_into=lambda view: 0, close=lambda: None)
    with pytest.raises(http.client.BadStatusLine):
        expect.await_continue(cast(http.client.HTTPConnection, SimpleNamespace(sock=sock)), "PUT")
