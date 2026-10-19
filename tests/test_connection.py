"""The stdlib connections: pool keywords, liveness, TLS, cancellation, real requests."""

from __future__ import annotations

import contextlib
import http.client as http_client
import socket
import ssl
import threading

import pytest

from xrdcore.cancel import Cancelled, CancelScope, within
from xrdhttp import connection

from tests._sockets import context_pair, read_request


def _ok(sock: socket.socket) -> None:
    """Answer every request on the connection with its own request line."""
    while True:
        line, headers = read_request(sock)
        if not line:
            return
        body = f"{line}|{headers.get('x-test', '')}".encode()
        sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)


def test_a_plain_request_round_trips(scripted):
    server = scripted(_ok)
    conn = connection.HTTPConnection("127.0.0.1", server.port, timeout=5)
    try:
        conn.request("GET", "/f", headers={"X-Test": "1"})
        assert conn.getresponse().read() == b"GET /f HTTP/1.1|1"
        conn.request("HEAD", "/g")  # ``headers=None`` is "no extra headers"
        conn.getresponse().read()
    finally:
        conn.close()


def test_a_tls_request_verifies_the_name_with_the_context_given(scripted, tmp_path):
    server_context, client_context = context_pair(tmp_path)

    def tls(sock: socket.socket) -> None:
        with server_context.wrap_socket(sock, server_side=True) as wrapped:
            _ok(wrapped)

    server = scripted(tls)
    conn = connection.HTTPSConnection(
        "localhost", server.port, timeout=5, ssl_context=client_context
    )
    try:
        conn.request("GET", "/secure")
        assert conn.getresponse().read().startswith(b"GET /secure")
    finally:
        conn.close()


def test_a_certificate_for_another_name_is_an_oserror(scripted, tmp_path):
    server_context, client_context = context_pair(tmp_path)

    def tls(sock: socket.socket) -> None:
        with contextlib.suppress(ssl.SSLError, OSError):
            server_context.wrap_socket(sock, server_side=True).close()

    server = scripted(tls)
    conn = connection.HTTPSConnection(
        "127.0.0.1", server.port, timeout=5, ssl_context=client_context
    )
    with pytest.raises(OSError):
        conn.connect()
    conn.close()


def test_a_cancelled_scope_sends_nothing(scripted):
    received = threading.Event()

    def note(sock: socket.socket) -> None:
        if sock.recv(1):
            received.set()

    server = scripted(note)
    conn = connection.HTTPConnection("127.0.0.1", server.port, timeout=5)
    scope = CancelScope()
    scope.cancel()
    try:
        with pytest.raises(Cancelled, match="GET /f"):
            within(scope, lambda: conn.request("GET", "/f"))
    finally:
        conn.close()
    assert not received.wait(0.1)


@pytest.mark.parametrize("kind", ["os_error", "os_cause", "other"])
def test_connection_error_translation_preserves_os_cause_and_codes(kind):
    """Whatever a connector raises reaches the request engine as an OSError."""
    cause = ConnectionRefusedError(111, "refused")
    if kind == "os_error":
        failure: Exception = cause
    else:
        failure = UnicodeError("label empty or too long")  # IDNA, for one
        if kind == "os_cause":
            failure.__cause__ = cause

    def connect():
        raise failure

    with pytest.raises(OSError) as caught:
        connection._connect(connect)
    if kind == "other":
        assert caught.value.errno == 5
        assert caught.value.__cause__ is failure
    else:
        assert caught.value is cause


@pytest.mark.parametrize(
    ("cls", "stdlib"),
    [
        (connection.HTTPConnection, http_client.HTTPConnection),
        (connection.HTTPSConnection, http_client.HTTPSConnection),
    ],
)
def test_connections_delegate_to_the_stdlib_connector(cls, stdlib, monkeypatch):
    calls = []
    monkeypatch.setattr(stdlib, "connect", lambda self: calls.append(self))
    conn = cls("localhost")
    conn.connect()
    assert calls == [conn]


def test_an_unencodable_host_name_is_an_oserror():
    """Not a UnicodeError escaping the retry and wrap logic."""
    conn = connection.HTTPConnection("a..b", 80, timeout=1)
    with pytest.raises(OSError):
        conn.connect()


def test_an_https_connection_uses_the_context_it_is_given():
    context = ssl.create_default_context()
    # ``_context`` is http.client's own attribute, which typeshed leaves out.
    assert vars(connection.HTTPSConnection("h", ssl_context=context))["_context"] is context


def test_timeouts_and_block_sizes():
    """The stdlib's "no timeout given" by default; a larger default block size."""
    conn = connection.HTTPSConnection("h", 443, blocksize=1 << 16)
    assert conn.timeout is vars(socket)["_GLOBAL_DEFAULT_TIMEOUT"]
    assert conn.blocksize == 1 << 16
    assert connection.HTTPConnection("h", timeout=2.5).timeout == 2.5
    assert connection.HTTPConnection("h", timeout=None).timeout is None  # no limit
    assert connection.HTTPConnection("h").blocksize == connection.BLOCKSIZE


def test_liveness_follows_the_socket():
    """Idle and open is connected; closed, or with unread bytes, is not."""
    conn = connection.HTTPConnection("h")
    assert not conn.is_connected
    near, far = socket.socketpair()
    try:
        conn.sock = near
        assert conn.is_connected
        far.sendall(b"stray")
        assert not conn.is_connected
    finally:
        conn.sock = None
        near.close()
        far.close()


@pytest.mark.parametrize("headers", [None, {"User-Agent": "contract-test"}])
def test_the_stdlib_request_contract_takes_no_headers_too(headers):
    """Moved from xgfalclient: ``request(..., headers=None)`` frames like the stdlib's."""
    sent = []

    class Connection(connection._ResponseCompatibility, http_client.HTTPConnection):
        def send(self, data):
            sent.append(bytes(data))  # record the framing without opening a socket

    conn = Connection("localhost")
    conn.request("GET", "/", headers=headers)
    conn.close()
    assert sent[0].startswith(b"GET / HTTP/1.1\r\n")


def test_the_stdlib_vocabulary_is_re_exported_as_itself():
    """Clients name these through xrdhttp (their lint bans http.client): the same classes."""
    for name in (
        "BadStatusLine",
        "HTTPException",
        "HTTPMessage",
        "HTTPResponse",
        "IncompleteRead",
        "RemoteDisconnected",
    ):
        assert getattr(connection, name) is getattr(http_client, name)
        assert name in connection.__all__
