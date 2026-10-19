"""A keep-alive HTTP/1.1 server for the session tests, scripted request by request.

:func:`serve` turns a ``handler(request) -> bytes | None`` into a
:class:`~tests._sockets.Scripted` script: each request on a connection is read
(its body by ``Content-Length`` or chunked framing, after a ``100 Continue``
when it asked for one) and recorded, and the handler's bytes are the answer;
``None`` hangs up. :func:`answer` builds those bytes. Tests that need a server
misbehaving at a precise byte write their own script instead.
"""

from __future__ import annotations

import contextlib
import socket
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from tests._sockets import read_exactly, read_request

__all__ = ["Seen", "answer", "read_chunked", "serve"]


@dataclass
class Seen:
    """One request as the server read it."""

    method: str
    target: str
    headers: dict[str, str]
    body: bytes
    connection: int


def answer(
    status: int = 200,
    body: bytes = b"",
    reason: str = "OK",
    headers: Mapping[str, str] | None = None,
) -> bytes:
    """A complete response with a ``Content-Length``, ready to send."""
    lines = [f"HTTP/1.1 {status} {reason}", f"Content-Length: {len(body)}"]
    lines += [f"{name}: {value}" for name, value in (headers or {}).items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


def read_chunked(sock: socket.socket) -> bytes:
    """A chunked body off ``sock``, up to and including its last chunk and blank line."""
    body = bytearray()
    while True:
        size_line = bytearray()
        while not size_line.endswith(b"\r\n"):
            size_line += sock.recv(1)
        size = int(size_line.strip(), 16)
        if not size:
            read_exactly(sock, 2)
            return bytes(body)
        body += read_exactly(sock, size)
        read_exactly(sock, 2)


def serve(
    handler: Callable[[Seen], bytes | None], seen: list[Seen]
) -> Callable[[socket.socket], None]:
    """A script answering every request on a connection with ``handler``; records in ``seen``."""
    counter = [0]

    def script(sock: socket.socket) -> None:
        counter[0] += 1
        # A client that hangs up mid-request (an abandoned upload) ends the
        # connection, not the test: what it did is the test's to check.
        with contextlib.suppress(OSError):
            _converse(sock, handler, seen, counter[0])

    return script


def _converse(
    sock: socket.socket, handler: Callable[[Seen], bytes | None], seen: list[Seen], number: int
) -> None:
    """Answer requests on ``sock`` until the client or the handler hangs up."""
    while True:
        line, headers = read_request(sock)
        if not line:
            return
        method, target, _ = line.split(" ", 2)
        if headers.get("expect") == "100-continue":
            sock.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
        if headers.get("transfer-encoding") == "chunked":
            body = read_chunked(sock)
        else:
            body = read_exactly(sock, int(headers.get("content-length", "0")))
        request = Seen(method, target, headers, body, number)
        seen.append(request)
        out = handler(request)
        if out is None:
            return
        sock.sendall(out)
