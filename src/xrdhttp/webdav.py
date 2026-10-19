"""WebDAV multistatus and HTTP digest parsing, shared by both HTTP clients.

This is the half of WebDAV that is pure parsing, and it is the same for every
client of a storage element: what a ``<D:response>`` says about a resource,
which server path its ``<D:href>`` names, what an HTTP or ISO 8601 date is in
seconds, and which value of a ``Digest`` (RFC 3230) field is the checksum
asked for, in hex. (RFC 9530's ``Repr-Digest`` is a client's own business.)

Every client reads it: xrdclient turns a :class:`Resource` into its
``StatInfo``, xgfalclient's HTTP plugin into the ``stat`` davix reports (mode
``0777`` plus the file type, zero owner). Each keeps what is genuinely its
own - the result type, the exception a malformed body raises (a
``ProtocolError`` in one, a gfal2 ``EIO`` in the other), and whether a
``<D:response>`` without an ``href`` is an error or skipped - and nothing
else. The body itself should be parsed with :func:`xrdcore.safexml.fromstring`.
"""

from __future__ import annotations

import base64
import email.utils
import hashlib
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime

__all__ = [
    "DAV",
    "HEX_DIGESTS",
    "WANT_DIGEST",
    "Resource",
    "as_hex",
    "canonical_digest",
    "epoch",
    "href_path",
    "is_hex",
    "pick_digest",
    "resource",
    "text",
]

#: The WebDAV XML namespace, in ElementTree's ``{uri}`` spelling.
DAV = "{DAV:}"

#: RFC 3230 spells some of these differently from :mod:`hashlib`.
WANT_DIGEST = {
    "adler32": "adler32",
    "crc32": "crc32",
    "crc32c": "crc32c",
    "md5": "md5",
    "sha1": "sha",
    "sha256": "sha-256",
    "sha512": "sha-512",
    "unixcksum": "unixcksum",
}

#: Every spelling of an algorithm a ``Digest`` field has been seen to use,
#: mapped to the :mod:`hashlib`-style name callers ask for.
_DIGEST_ALIASES = {"sha": "sha1", "sha-1": "sha1", "sha-256": "sha256", "sha-512": "sha512"}

#: Digests XRootD and dCache send as hex; the rest arrive base64 per RFC 3230.
HEX_DIGESTS = frozenset({"adler32", "crc32", "crc32c", "unixcksum", "cksum"})

#: Hex widths :mod:`hashlib` cannot report, because these are not hashes.
#: Both encodings of a ``crc64`` are in the wild - sixteen hex digits over
#: ``root://`` and WebDAV, base64 of eight big-endian bytes under RFC 9530 -
#: and they are different lengths, so the value itself says which it is.
_HEX_WIDTHS = {"crc64": 16, "crc64nvme": 16}


# ---------------------------------------------------------------------------
# Multistatus
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Resource:
    """What one ``<D:response>`` says about the resource it describes.

    Only what both clients' ``stat`` results are made of; a property the
    server did not send is ``0`` (or a file, for the resource type), which is
    how davix and XrdCl both read an absent one.
    """

    is_dir: bool = False
    size: int = 0
    mtime: int = 0
    ctime: int = 0


def text(element: ET.Element | None, name: str) -> str:
    """The stripped text of ``element``'s ``<D:name>`` child; ``""`` if there is none."""
    if element is None:
        return ""
    found = element.find(DAV + name)
    return (found.text or "").strip() if found is not None else ""


def href_path(href: str) -> str:
    """The unquoted server path an ``<D:href>`` names, however it was written.

    Servers write both absolute URLs and absolute paths there; either way it
    is the path that identifies the resource, decoded once.
    """
    raw = urllib.parse.urlsplit(href).path if "://" in href else href
    return urllib.parse.unquote(raw) or "/"


def epoch(stamp: str) -> int:
    """Seconds since the epoch from an HTTP date or an ISO 8601 one; ``0`` if neither.

    ``<D:getlastmodified>`` and ``Last-Modified`` carry RFC 9110 dates,
    ``<D:creationdate>`` ISO 8601 ones; a value that is neither is not an
    error, just a time the server did not usefully report.
    """
    value = stamp.strip()
    if not value:
        return 0
    try:
        return int(email.utils.parsedate_to_datetime(value).timestamp())
    except (TypeError, ValueError, IndexError):
        pass
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return 0


def resource(response: ET.Element) -> Resource:
    """One ``<D:response>`` read into a :class:`Resource`.

    The properties are those of the first ``<D:propstat>`` that succeeded -
    a ``200`` status, or none at all, which some servers leave out; the
    ``404`` block a server lists unknown properties under says nothing.
    """
    prop = None
    for propstat in response.findall(DAV + "propstat"):
        status = text(propstat, "status")
        if not status or " 200 " in f"{status} ":
            prop = propstat.find(DAV + "prop")
            break
    kind = prop.find(DAV + "resourcetype") if prop is not None else None
    size = text(prop, "getcontentlength")
    return Resource(
        is_dir=kind is not None and kind.find(DAV + "collection") is not None,
        size=int(size) if size.isdigit() else 0,
        mtime=epoch(text(prop, "getlastmodified")),
        ctime=epoch(text(prop, "creationdate")),
    )


# ---------------------------------------------------------------------------
# Digests
# ---------------------------------------------------------------------------


def canonical_digest(name: str) -> str:
    """An algorithm name as callers spell it: ``SHA-256`` and ``sha`` are ``sha256``/``sha1``."""
    key = name.strip().lower()
    return _DIGEST_ALIASES.get(key, key)


def pick_digest(header: str, algorithm: str) -> str:
    """``algorithm``'s value out of a ``Digest:`` header, as lower-case hex; ``""`` if absent.

    Names are compared in canonical form, so ``sha-256=``, ``SHA256=`` and,
    for SHA-1, RFC 3230's ``sha=`` all answer a request for theirs.
    """
    wanted = canonical_digest(algorithm)
    for item in header.split(","):
        name, sep, raw = item.strip().partition("=")
        if not sep or canonical_digest(name) != wanted:
            continue
        return as_hex(raw.strip(), wanted)
    return ""


def as_hex(value: str, algorithm: str) -> str:
    """RFC 3230 sends most digests base64-encoded; storage sends some as hex."""
    if algorithm in HEX_DIGESTS or is_hex(value, algorithm):
        return value.lower()
    try:
        return base64.b64decode(value, validate=True).hex()
    except (ValueError, TypeError):
        return value.lower()  # already hex, as XRootD's HTTP layer sends it


def is_hex(value: str, algorithm: str) -> bool:
    """Is this the hex form of an ``algorithm`` digest?

    Base64 cannot be mistaken for it: this algorithm's digest is a fixed
    number of bytes, and its base64 form is never as long as its hex form.
    """
    wanted = _HEX_WIDTHS.get(algorithm, 0)
    if not wanted:
        try:
            wanted = 2 * hashlib.new(algorithm).digest_size
        except ValueError:
            return False
    return len(value) == wanted and all(ch in "0123456789abcdefABCDEF" for ch in value)
