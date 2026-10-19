"""Test helpers shared by several modules: TLS contexts, canned responses, socket servers.

Everything here is local and in-process. No client package's test servers are
used: what xrdhttp promises is checked against bytes on a socket, not against
another implementation of the same protocol. The fixtures over these live in
``conftest.py``; tests import the helpers from here, never from a conftest.
"""

from __future__ import annotations

import datetime
import http.client
import io
import socket
import ssl
import threading
from collections.abc import Callable
from pathlib import Path
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def context_pair(tmp_path: Path) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """``(server, client)`` TLS contexts over a fresh self-signed ``localhost`` certificate."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    chain = tmp_path / "server.pem"
    chain.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
        + key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(str(chain))
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.load_verify_locations(cadata=cert.public_bytes(serialization.Encoding.PEM).decode())
    return server, client


class _Canned:
    """A socket stand-in whose ``makefile`` replays fixed bytes."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def makefile(self, *_args: object, **_kwargs: object) -> io.BufferedReader:
        return io.BufferedReader(io.BytesIO(self.data))


def canned_response(data: bytes, method: str = "GET") -> http.client.HTTPResponse:
    """A begun :class:`http.client.HTTPResponse` reading ``data`` (status line and all)."""
    # HTTPResponse only calls ``makefile``; typeshed asks for a whole socket.
    response = http.client.HTTPResponse(cast(socket.socket, _Canned(data)), method=method)
    response.begin()
    return response


def read_request(sock: socket.socket) -> tuple[str, dict[str, str]]:
    """One request's line and headers off ``sock``, a byte at a time (the body is left)."""
    head = bytearray()
    while not head.endswith(b"\r\n\r\n"):
        byte = sock.recv(1)
        if not byte:
            break
        head += byte
    lines = head.decode("latin-1").split("\r\n")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    return lines[0], headers


def read_exactly(sock: socket.socket, count: int) -> bytes:
    """``count`` bytes off ``sock``, or fewer if it closes first."""
    out = bytearray()
    while len(out) < count:
        chunk = sock.recv(count - len(out))
        if not chunk:
            break
        out += chunk
    return bytes(out)


class Scripted:
    """A one-port TCP server that runs ``script(sock)`` for each connection.

    The script is the server: it reads and writes the raw bytes, so a test
    can answer before a body arrives, stay silent, or close mid-response.
    Whatever a script raises is kept and re-raised by :meth:`check`.
    """

    def __init__(self, script: Callable[[socket.socket], None]) -> None:
        self.script = script
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.errors: list[BaseException] = []
        self.connections = 0
        self._threads: list[threading.Thread] = []
        self._accepting = threading.Thread(target=self._accept, daemon=True)
        self._accepting.start()

    def _accept(self) -> None:
        while True:
            try:
                sock, _ = self.listener.accept()
            except OSError:
                return
            self.connections += 1
            worker = threading.Thread(target=self._run, args=(sock,), daemon=True)
            self._threads.append(worker)
            worker.start()

    def _run(self, sock: socket.socket) -> None:
        with sock:
            try:
                self.script(sock)
            except BaseException as exc:  # reported by check()
                self.errors.append(exc)

    def close(self) -> None:
        self.listener.close()
        self._accepting.join(5)
        for worker in self._threads:
            worker.join(5)

    def check(self) -> None:
        if self.errors:
            raise self.errors[0]
