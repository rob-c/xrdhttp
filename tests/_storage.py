"""Helpers for the fake storage element's own tests: raw requests and TLS identities.

The fake is driven here with :mod:`http.client` and raw sockets, below any
client of this library, because what is under test is what the fake puts on
the wire. Test modules import these; the fixtures stay in each module.
"""

from __future__ import annotations

import datetime
import http.client
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from xrdhttp.testing import StorageServer


@dataclass
class Answer:
    """One response: status, headers (names as sent) and the whole body."""

    status: int
    headers: dict[str, str]
    body: bytes

    def header(self, name: str) -> str | None:
        """A header, case-insensitively."""
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return None


def ask(
    server: StorageServer,
    method: str,
    target: str,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    *,
    context: ssl.SSLContext | None = None,
) -> Answer:
    """One request on a fresh connection; HTTPS when ``context`` is given."""
    host, port = server.address
    connection = (
        http.client.HTTPSConnection("localhost", port, context=context, timeout=10)
        if context is not None
        else http.client.HTTPConnection(host, port, timeout=10)
    )
    try:
        connection.request(method, target, body=body, headers=headers or {})
        response = connection.getresponse()
        return Answer(response.status, dict(response.getheaders()), response.read())
    finally:
        connection.close()


def raw(server: StorageServer, data: bytes, *, shut: bool = True) -> bytes:
    """Send ``data`` on a raw socket, half-close it unless told not to, read the whole answer."""
    with socket.create_connection(server.address, timeout=10) as sock:
        sock.sendall(data)
        if shut:
            sock.shutdown(socket.SHUT_WR)
        out = bytearray()
        while chunk := sock.recv(65536):
            out += chunk
        return bytes(out)


def _certificate(name: str, key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    """A self-signed certificate for ``name`` (also its DNS name), valid for an hour each way."""
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(key, hashes.SHA256())
    )


def _pem(directory: Path, name: str) -> tuple[Path, bytes]:
    """A key and self-signed certificate for ``name`` in one PEM file, and the certificate's PEM."""
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _certificate(name, key).public_bytes(serialization.Encoding.PEM)
    path = directory / f"{name}.pem"
    path.write_bytes(
        cert
        + key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path, cert


@dataclass
class Identities:
    """A server context that asks for a client certificate, and clients with and without one."""

    server: ssl.SSLContext
    anonymous: ssl.SSLContext
    user: ssl.SSLContext


def identities(directory: Path) -> Identities:
    """TLS contexts for ``localhost`` and a client called ``Test User``."""
    host, host_cert = _pem(directory, "localhost")
    user, user_cert = _pem(directory, "Test User")
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(str(host))
    server.verify_mode = ssl.CERT_OPTIONAL
    server.load_verify_locations(cadata=user_cert.decode())
    anonymous = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    anonymous.load_verify_locations(cadata=host_cert.decode())
    authenticated = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    authenticated.load_verify_locations(cadata=host_cert.decode())
    authenticated.load_cert_chain(str(user))
    return Identities(server, anonymous, authenticated)
