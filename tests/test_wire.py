"""The socket-level body transfer every HTTP client shares (``xrdhttp.wire``).

Each test speaks HTTP over a real socket pair - plain, or TLS with a
throwaway certificate - so what is checked is what a storage element's bytes
go through: a body read straight off the socket, a file sent with
``sendfile`` or in large TLS writes, and an idle connection kept for reuse.
"""

from __future__ import annotations

import http.client
import io
import socket
import ssl
import threading
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING, cast

import pytest

from xrdhttp import wire as _wire
from xrdhttp.wire import DIRECT_READ, DirectReader, IdlePool, ShortFileError, send_file

from tests._sockets import context_pair

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer

BODY = bytes(range(256)) * 4096  # 1 MiB


@pytest.fixture(params=["plain", "tls"])
def pair(request, tmp_path) -> Iterator[tuple[socket.socket, socket.socket]]:
    """``(client, server)``: connected sockets, TLS-wrapped for the ``tls`` case."""
    near, far = socket.socketpair()
    if request.param == "tls":
        server_context, client_context = context_pair(tmp_path)
        wrapped: list[socket.socket] = []
        handshake = threading.Thread(
            target=lambda: wrapped.append(server_context.wrap_socket(far, server_side=True))
        )
        handshake.start()
        near = client_context.wrap_socket(near, server_hostname="localhost")
        handshake.join()
        far = wrapped[0]
    yield near, far
    near.close()
    far.close()


def _serve(sock: socket.socket, payload: bytes, *, close: bool = False) -> threading.Thread:
    def run() -> None:
        sock.sendall(payload)
        if close:
            # The far end hangs up - over TLS without a close_notify, which
            # is how a storage element that dies mid-transfer leaves it.
            sock.shutdown(socket.SHUT_WR)

    thread = threading.Thread(target=run)
    thread.start()
    return thread


def _response(sock: socket.socket) -> http.client.HTTPResponse:
    response = http.client.HTTPResponse(sock)
    response.begin()
    return response


def _counting(response: http.client.HTTPResponse) -> list[int]:
    """What each read through http.client's own ``readinto`` returned."""
    calls: list[int] = []
    original = response.readinto

    def readinto(buffer: WriteableBuffer) -> int:
        calls.append(original(buffer))
        return calls[-1]

    # An instance attribute shadows the method for this one response.
    vars(response)["readinto"] = readinto
    return calls


def _drain(read: Callable[[memoryview], int], size: int) -> bytes:
    out = bytearray()
    buffer = bytearray(size)
    while count := read(memoryview(buffer)):
        out += buffer[:count]
    return bytes(out)


def test_a_known_length_body_is_read_straight_off_the_socket(pair):
    near, far = pair
    sender = _serve(far, b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(BODY) + BODY)
    response = _response(near)
    calls = _counting(response)
    reader = DirectReader(response, near)
    assert _drain(reader.readinto, 256 << 10) == BODY
    sender.join()
    assert sum(calls) == 0  # not a byte through http.client's buffered stream
    assert reader.owed == 0 and response.isclosed()  # finished: the connection is reusable


def test_small_reads_chunked_bodies_and_no_socket_stay_with_http_client(pair):
    near, far = pair
    sender = _serve(far, b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789")
    response = _response(near)
    calls = _counting(response)
    assert _drain(DirectReader(response, near).readinto, DIRECT_READ - 1) == b"0123456789"
    sender.join()
    assert sum(calls) == 10  # a read under DIRECT_READ is http.client's

    sender = _serve(
        far, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
    )
    chunked = _response(near)
    calls = _counting(chunked)
    assert _drain(DirectReader(chunked, near).readinto, DIRECT_READ) == b"abc"
    sender.join()
    assert sum(calls) == 3 and chunked.length is None

    sender = _serve(far, b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nxyz")
    unsocketed = _response(near)
    calls = _counting(unsocketed)
    assert _drain(DirectReader(unsocketed, None).readinto, DIRECT_READ) == b"xyz"
    sender.join()
    assert sum(calls) == 3


class _Replayed:
    """A socket stand-in whose stream is not the socket: what ``expect`` replays."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def makefile(self, *_args: object, **_kwargs: object) -> io.BufferedReader:
        return io.BufferedReader(io.BytesIO(self.data))


def test_a_replayed_stream_is_never_bypassed():
    """The socket would skip whatever the replay still holds."""
    body = b"r" * (DIRECT_READ * 2)
    head = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body)
    near, _far = socket.socketpair()
    try:
        # HTTPResponse only calls ``makefile``; typeshed asks for a whole socket.
        response = http.client.HTTPResponse(cast(socket.socket, _Replayed(head + body)))
        response.begin()
        calls = _counting(response)
        assert _drain(DirectReader(response, near).readinto, DIRECT_READ) == body
        assert sum(calls) == len(body)
    finally:
        near.close()
        _far.close()


def test_a_body_cut_short_is_an_end_of_file_with_the_rest_still_owed(pair):
    near, far = pair
    head = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(BODY)
    sender = _serve(far, head + BODY[: len(BODY) // 2], close=True)
    response = _response(near)
    reader = DirectReader(response, near)
    assert _drain(reader.readinto, 256 << 10) == BODY[: len(BODY) // 2]
    sender.join()
    assert reader.owed == len(BODY) - len(BODY) // 2
    assert reader.readinto(bytearray(DIRECT_READ)) == 0  # and stays at the end


def test_a_tls_session_closed_under_a_read_is_an_end_of_file(pair):
    near, far = pair
    head = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % (DIRECT_READ * 4)
    sender = _serve(far, head + b"0123456789", close=True)
    response = _response(near)
    sender.join()
    reader = DirectReader(response, near)

    def dead(count: int, view: memoryview) -> int:
        raise ssl.SSLEOFError("EOF occurred in violation of protocol")

    reader._receive = dead  # what OpenSSL says of a session the peer dropped
    buffer = bytearray(DIRECT_READ)
    assert reader.readinto(buffer) == 10 and buffer[:10] == b"0123456789"
    assert reader._receive is _wire._at_end
    assert reader.readinto(buffer) == 0 and reader.owed == DIRECT_READ * 4 - 10


def test_the_receiver_reads_tls_records_from_the_ssl_object():
    class Tls:
        class _sslobj:
            @staticmethod
            def read(count: int, view: memoryview) -> int:
                return 7

    # Only ``_sslobj`` is looked at on a TLS socket, so that is all the fake has.
    fake = cast(socket.socket, Tls())
    assert _wire._receiver(fake)(1, memoryview(bytearray(1))) == 7


def _received(sock: socket.socket, size: int) -> tuple[threading.Thread, bytearray]:
    got = bytearray()

    def run() -> None:
        while len(got) < size:
            chunk = sock.recv(1 << 16)
            if not chunk:
                return
            got.extend(chunk)

    thread = threading.Thread(target=run)
    thread.start()
    return thread, got


def test_a_file_is_sent_whole_from_its_offset(pair, tmp_path):
    near, far = pair
    path = tmp_path / "source"
    path.write_bytes(BODY)
    receiver, got = _received(far, len(BODY) - 100)
    progress: list[int] = []
    with path.open("rb") as handle:
        send_file(near, handle, 100, len(BODY) - 100, progress=progress.append, slice_size=1 << 18)
    receiver.join()
    assert bytes(got) == BODY[100:]
    assert sum(progress) == len(BODY) - 100 and len(progress) > 1


def test_a_file_that_ends_early_is_a_short_file_error(pair, tmp_path):
    near, far = pair
    path = tmp_path / "short"
    path.write_bytes(b"abc")
    receiver, _got = _received(far, 3)
    with path.open("rb") as handle, pytest.raises(ShortFileError, match="at offset 3") as caught:
        send_file(near, handle, 0, 10)
    receiver.join()
    assert caught.value.offset == 3 and str(caught.value.strerror).startswith("Short read")


def test_nothing_to_send_sends_nothing(pair, tmp_path):
    near, _far = pair
    path = tmp_path / "empty"
    path.write_bytes(b"")
    with path.open("rb") as handle:
        send_file(near, handle, 0, 0)


class _Conn:
    def __init__(self, connected: bool = True) -> None:
        self.is_connected = connected
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_the_idle_pool_reuses_the_newest_live_connection():
    made: list[_Conn] = []

    def factory() -> _Conn:
        made.append(_Conn())
        return made[-1]

    pool: IdlePool[_Conn] = IdlePool(factory, limit=2)
    first = pool.get()
    assert made == [first]
    old, new, extra = _Conn(), _Conn(), _Conn()
    pool.put(old)
    pool.put(new)
    pool.put(extra)  # no room: closed
    assert extra.closed and pool.idle_count() == 2
    assert pool.get() is new and pool.get() is old
    dead = _Conn(connected=False)
    pool.put(dead)
    assert pool.get() is made[-1] and dead.closed  # a dead one is closed, a new one made
    pool.put(old)
    pool.close()
    assert old.closed and pool.idle_count() == 0
    late = _Conn()
    pool.put(late)
    assert late.closed  # returned to a closed pool
