"""Digest values for the fake's answers: RFC 3230 ``Digest`` and RFC 9530 ``Repr-Digest``.

Functions of their arguments only, so the handlers stay about *when* to
answer and these about *what* a digest says: hex for the rolling checksums
and base64 for the rest, the convention storage elements use and
:mod:`xrdhttp.webdav` parses.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Iterable

from xrdcore.checksum import new as new_digest

from ..webdav import HEX_DIGESTS, canonical_digest

#: RFC 9530's algorithm names, as :mod:`xrdcore.checksum` spells them. ``crc64``
#: is not registered, but a client that asks for it gets it.
_REPR_NAMES = {
    "sha-256": "sha256",
    "sha-512": "sha512",
    "md5": "md5",
    "sha": "sha1",
    "adler": "adler32",
    "crc32c": "crc32c",
    "crc64": "crc64",
}

#: Folds a file's bytes into a checksum: called with an algorithm name, it
#: returns the digest's raw bytes (big-endian for the checksums).
Digester = Callable[[str], bytes]


def checksum(chunks: Iterable[bytes], algorithm: str) -> bytes:
    """The raw digest of ``chunks`` with :mod:`xrdcore.checksum`'s ``algorithm``."""
    digest = new_digest(algorithm)
    for chunk in chunks:
        digest.update(chunk)
    return digest.digest()


def _encoded(name: str, raw: bytes) -> str:
    """A ``Digest`` value: hex for the rolling checksums, base64 for the rest (RFC 3230)."""
    return raw.hex() if name in HEX_DIGESTS else base64.b64encode(raw).decode()


def legacy_digest(wanted: str, offered: set[str], every: bool, digest: Digester) -> str:
    """The RFC 3230 ``Digest`` value answering ``Want-Digest: wanted``; ``""`` for none.

    ``q=`` weights are ignored and the client's order is kept. With
    ``every`` all the offered algorithms asked for are answered,
    comma-joined, as XrdHttp does; otherwise only the first, as dCache does.
    Each value is labelled with the client's own spelling of its name.
    """
    values = []
    for item in wanted.split(","):
        name = item.split(";")[0].strip().lower()
        if name not in offered:
            continue
        values.append(f"{name}={_encoded(canonical_digest(name), digest(canonical_digest(name)))}")
        if not every:
            break
    return ",".join(values)


def repr_digest(wanted: str, offered: set[str], digest: Digester) -> str:
    """The RFC 9530 ``Repr-Digest`` answering ``Want-Repr-Digest: wanted``; ``""`` for none.

    ``wanted`` is a dictionary of preferences, ``sha-256=10, adler=3``;
    zero means "not this one" and the highest weight wins. The value is the
    digest's bytes base64-encoded between colons - a checksum's bytes
    big-endian.
    """
    best: tuple[int, str] | None = None
    for item in wanted.split(","):
        name, _, weight = item.partition("=")
        name = name.strip().lower()
        text = weight.split(";")[0].strip()
        rank = int(text) if text.isdigit() else 1
        known = name in _REPR_NAMES and name in offered and rank > 0
        if known and (best is None or rank > best[0]):
            best = (rank, name)
    if best is None:
        return ""
    return f"{best[1]}=:{base64.b64encode(digest(_REPR_NAMES[best[1]])).decode()}:"
