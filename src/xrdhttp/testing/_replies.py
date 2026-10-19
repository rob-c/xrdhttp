"""Reply helpers for in-process HTTP fakes: byte ranges and WebDAV multistatus.

The one home of these in the family: :class:`~xrdhttp.testing.StorageServer`
answers with them, and so do fakes built directly on
:class:`xrdsec.testing.https.FakeHTTPSServer` (xrdarc's A-REX), whose
:class:`~xrdsec.testing.https.Response` they return.

* :func:`ranged_reply` turns a ``Range`` header into a ``200``, ``206``,
  ``multipart/byteranges`` or ``416`` answer per RFC 9110 section 14;
  :func:`spans` and :func:`multipart` are its two halves, for a server that
  streams the content rather than holding it, and :func:`byteranges` the
  body itself, for a test that hand-crafts one (parts never asked for, a
  missing close);
* :func:`propfind_reply` renders RFC 4918 ``multistatus`` from
  :class:`DAVEntry` items, which :func:`dav_entries` can produce from a real
  directory.

Functions of their arguments only - no socket, no server state.
"""

from __future__ import annotations

import os
import stat
import time
import urllib.parse
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from email.utils import formatdate
from http import HTTPStatus
from pathlib import Path
from xml.sax.saxutils import escape

from xrdsec.testing.https import Response

#: The ``multipart/byteranges`` boundary; fixed, so tests can assert on bodies.
BOUNDARY = "xrdhttp-test-boundary"

#: Half-open ``(start, end)`` byte spans.
Spans = list[tuple[int, int]]


# -- byte ranges ------------------------------------------------------------------------


def parse_ranges(header: str, size: int) -> Spans | None:
    """``bytes=a-b,c-,-n`` as half-open ``(start, end)`` pairs; ``None`` if not byte ranges.

    ``a-b`` is inclusive, ``a-`` runs to the end and ``-n`` is the last
    ``n`` bytes (a suffix). Ends past the data are clipped; a range starting
    at or past the end stays in the list so the caller can tell an
    unsatisfiable request (416) from a malformed one (ignored: the whole body).
    """
    unit, _, spec = header.strip().partition("=")
    if unit.strip().lower() != "bytes" or not spec:
        return None
    found = []
    for item in spec.split(","):
        first, dash, last = item.strip().partition("-")
        if not dash or not (first or last) or not (first + last).isdigit():
            return None
        if not first:  # a suffix: the last ``last`` bytes
            found.append((max(size - int(last), 0), size))
        else:
            found.append((int(first), min(int(last) + 1, size) if last else size))
    return found


def spans(header: str | None, size: int, several: str = "multipart") -> Spans | None:
    """The spans to send of ``size`` bytes for ``Range: header``.

    ``None`` means the whole body (no header, or not byte ranges) and ``[]``
    a 416 (nothing satisfiable). Several satisfiable ranges are sent as
    ``several`` says: ``"multipart"`` - all of them; ``"first"`` - only the
    first, as many real servers do; ``"coalesce"`` - one span covering them
    all, which RFC 9110 allows when the gaps are small.
    """
    wanted = parse_ranges(header, size) if header else None
    if wanted is None:
        return None
    satisfiable = [(start, end) for start, end in wanted if start < size]
    if several == "coalesce" and satisfiable:
        return [(min(s for s, _ in satisfiable), max(e for _, e in satisfiable))]
    return satisfiable[:1] if several == "first" else satisfiable


def byteranges(
    *parts: tuple[int, bytes],
    size: int,
    boundary: str = BOUNDARY,
    part_type: str = "application/octet-stream",
    preamble: bytes = b"",
    epilogue: bytes = b"",
    closing: bool = True,
) -> bytes:
    """A ``multipart/byteranges`` body (RFC 9110 section 14.6) of ``(first byte, payload)`` parts.

    Each part says ``Content-Range: bytes first-last/size`` with ``last``
    from its payload's length - whatever the content really is, so a test
    can hand a client parts it never asked for. ``preamble`` and
    ``epilogue`` are the text RFC 2046 lets a body carry before the first
    delimiter and after the close, which a parser must skip; ``closing=False``
    leaves the close delimiter off, as a connection dropped after the last
    part would.
    """
    body = preamble
    for first, payload in parts:
        head = (
            f"--{boundary}\r\nContent-Type: {part_type}\r\n"
            f"Content-Range: bytes {first}-{first + len(payload) - 1}/{size}\r\n\r\n"
        )
        body += head.encode() + payload + b"\r\n"
    if closing:
        body += f"--{boundary}--\r\n".encode() + epilogue
    return body


def multipart(read: Callable[[int, int], bytes], wanted: Spans, size: int, part_type: str) -> bytes:
    """A ``multipart/byteranges`` body (RFC 9110 section 14.6) of ``wanted``.

    ``read(start, count)`` returns that much of the content, which need not
    be held whole. The body opens with a CRLF, as servers send it.
    """
    parts = [(start, read(start, end - start)) for start, end in wanted]
    return byteranges(*parts, size=size, part_type=part_type, preamble=b"\r\n")


def ranged_reply(
    data: bytes,
    header: str | None,
    *,
    content_type: str | None = None,
    headers: dict[str, str] | None = None,
    several: str = "multipart",
) -> Response:
    """The answer to a ``GET`` of ``data`` carrying ``Range: header``.

    No (or an unparseable) header: ``200`` with everything. One satisfiable
    range: ``206`` with ``Content-Range``. Several: by ``several`` (see
    :func:`spans`). Nothing satisfiable: ``416`` with ``Content-Range: bytes
    */<size>``. ``content_type`` labels the payload (whole body or each
    part); ``headers`` are added to every non-416 answer (``Last-Modified``,
    digests...).
    """
    extra = dict(headers or {})
    if content_type is not None:
        extra["Content-Type"] = content_type
    chosen = spans(header, len(data), several)
    if chosen is None:
        return Response(200, data, extra)
    if not chosen:
        return Response(416, b"", {"Content-Range": f"bytes */{len(data)}"})
    if len(chosen) == 1:
        start, end = chosen[0]
        extra["Content-Range"] = f"bytes {start}-{end - 1}/{len(data)}"
        return Response(206, data[start:end], extra)

    def read(start: int, count: int) -> bytes:
        return data[start : start + count]

    part_type = content_type or "application/octet-stream"
    extra["Content-Type"] = f"multipart/byteranges; boundary={BOUNDARY}"
    return Response(206, multipart(read, chosen, len(data), part_type), extra)


# -- WebDAV multistatus -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DAVEntry:
    """One ``<D:response>`` of a multistatus: a resource and the properties a client stats.

    ``href`` is written as given (already percent-encoded; a path or an
    absolute URL) except that a collection's always ends in ``/`` and a
    file's never does. ``status`` other than 200 writes a ``<D:status>``
    with no properties, as servers report a missing member. ``modified``
    becomes ``getlastmodified`` (RFC 1123 date, RFC 4918 section 15.7) and
    ``created`` ``creationdate`` (RFC 3339, section 15.1); ``name``
    defaults to the href's last segment, decoded. A file's
    ``getcontentlength`` is ``size``; a collection has none unless
    ``length`` gives one (dCache and XrdHttp say 4096, which a client must
    not take for a size).
    """

    href: str
    collection: bool = False
    size: int = 0
    modified: float = 0.0
    created: float | None = None
    name: str | None = None
    status: int = 200
    length: int | None = None


def _status_line(status: int) -> str:
    """``HTTP/1.1 404 Not Found``: a ``<D:status>`` value, reason phrase included.

    RFC 4918 section 14.28 makes ``<D:status>`` an RFC 2616 status line,
    whose grammar has the reason phrase, and real servers write it - so a
    client's parser is tested against what it will meet. A code with no
    registered phrase keeps the separating space and an empty phrase.
    """
    try:
        phrase = HTTPStatus(status).phrase
    except ValueError:
        phrase = ""
    return f"HTTP/1.1 {status} {phrase}"


def _entry_xml(entry: DAVEntry) -> str:
    """One entry's ``<D:response>`` element."""
    base = entry.href.rstrip("/")
    href = base + "/" if entry.collection else base or entry.href
    if entry.status != 200:
        return (
            f"<D:response><D:href>{escape(href)}</D:href>"
            f"<D:status>{_status_line(entry.status)}</D:status></D:response>"
        )
    kind = "<D:collection/>" if entry.collection else ""
    size = entry.length if entry.collection else entry.size
    length = "" if size is None else f"<D:getcontentlength>{size}</D:getcontentlength>"
    created = ""
    if entry.created is not None:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(entry.created))
        created = f"<D:creationdate>{stamp}</D:creationdate>"
    name = entry.name if entry.name is not None else _display_name(base)
    return (
        f"<D:response><D:href>{escape(href)}</D:href><D:propstat>"
        f"<D:prop><D:resourcetype>{kind}</D:resourcetype>{length}"
        f"<D:getlastmodified>{formatdate(entry.modified, usegmt=True)}</D:getlastmodified>"
        f"{created}<D:displayname>{escape(name)}</D:displayname>"
        "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>"
    )


def _display_name(href: str) -> str:
    """The last path segment of ``href``, decoded; ``/`` for the root."""
    path = urllib.parse.urlsplit(href).path
    return urllib.parse.unquote(path.rsplit("/", 1)[-1]) or "/"


def multistatus(entries: Iterable[DAVEntry]) -> bytes:
    """A ``<D:multistatus>`` document (RFC 4918 section 13) for ``entries``, in order."""
    parts = ['<?xml version="1.0" encoding="utf-8"?>', '<D:multistatus xmlns:D="DAV:">']
    parts.extend(_entry_xml(entry) for entry in entries)
    parts.append("</D:multistatus>")
    return "".join(parts).encode()


def propfind_reply(
    entries: Iterable[DAVEntry],
    *,
    status: int = 207,
    content_type: str = 'text/xml; charset="utf-8"',
) -> Response:
    """The answer to a ``PROPFIND``: :func:`multistatus` of ``entries``.

    ``207 Multi-Status`` is what RFC 4918 says; ``status`` exists for the
    servers that answer otherwise (A-REX answers ``200``).
    """
    return Response(status, multistatus(entries), {"Content-Type": content_type})


def _servable(path: Path) -> os.stat_result | None:
    """``path``'s status if it is a regular file or a directory, else ``None``."""
    try:
        info = path.stat()
    except OSError:
        return None
    return info if stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) else None


def dav_entries(path: Path, href: str, depth: int) -> Iterator[DAVEntry]:
    """``path`` on the local file system as :class:`DAVEntry` items, ``depth`` levels down.

    One entry for ``path`` itself (a ``404`` entry if it is missing or is
    neither a file nor a directory), then, for a directory and ``depth >
    0``, each child in name order, recursing with ``depth - 1``. ``href``
    names ``path``; children's hrefs append their percent-encoded names.
    Modification and creation times are the file system's.
    """
    info = _servable(path)
    if info is None:
        yield DAVEntry(href, status=404)
        return
    directory = stat.S_ISDIR(info.st_mode)
    size = 0 if directory else info.st_size
    yield DAVEntry(href, directory, size, info.st_mtime, info.st_ctime, path.name or "/")
    if directory and depth > 0:
        for name in sorted(os.listdir(path)):
            child = href.rstrip("/") + "/" + urllib.parse.quote(name)
            yield from dav_entries(path / name, child, depth - 1)
