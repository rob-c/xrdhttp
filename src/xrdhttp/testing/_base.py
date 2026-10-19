"""The plumbing every handler mixin shares: replies, request bodies, file content.

:class:`HandlerBase` is the one :class:`http.server.BaseHTTPRequestHandler`
subclass every mixin of this package derives from: it carries the
per-request attributes (set by :mod:`._front`), the :attr:`~HandlerBase.app`
back-reference to the :class:`~xrdhttp.testing.StorageServer`, and the
reply and body helpers. Deriving every mixin from it keeps mypy able to
check each one on its own, and gives the assembled handler a single,
consistent MRO.

HTTP/1.1 with keep-alive throughout, which is the mode both clients' pools
run in: every reply carries an exact ``Content-Length``, and a request
whose body was not read closes the connection after its reply, or the next
request on it would be parsed from this one's leftovers.
"""

from __future__ import annotations

import contextlib
import json
import socket
import time
from collections.abc import Callable, Iterable, Iterator
from http.server import BaseHTTPRequestHandler
from typing import TYPE_CHECKING, Any, BinaryIO, cast

from xrdsec.testing.https import Fault, Listener, Request, hold

from ._digests import checksum, legacy_digest, repr_digest
from ._model import decoded
from ._store import CHUNK

if TYPE_CHECKING:
    from ._server import StorageServer, _Backend


class HandlerBase(BaseHTTPRequestHandler):
    """Per-request state and the helpers every mixin replies with.

    The annotated attributes are per *request*, not per connection: one
    handler object serves every request of a keep-alive connection, so
    :meth:`~._front.RequestHandler.parse_request` resets them each time.
    ``_checked`` says the request has been recorded and passed the front
    (possibly early, from ``Expect: 100-continue``); ``_prefetched`` holds a
    small body read before that; ``_consumed`` says the body has been read
    off the socket, so the connection can be kept alive after the reply.
    ``_fault`` is a fault whose ``stall``, ``truncate`` and ``hold`` apply to
    whatever this request is answered with.
    """

    protocol_version = "HTTP/1.1"
    server: Listener
    _checked: bool
    _consumed: bool
    _prefetched: bytes | None
    _fault: Fault | None
    _record: Request

    @property
    def app(self) -> StorageServer:
        """The :class:`~xrdhttp.testing.StorageServer` whose state this request reads."""
        # The listener's fake is always the storage element's own backend.
        return cast("_Backend", self.server.fake).app

    @property
    def target(self) -> str:
        """The request's path, decoded once and normalised - the namespace key."""
        return decoded(self.path)

    def version_string(self) -> str:
        """The ``Server`` header: the fake's name."""
        return self.app.name

    def log_message(self, format: str, *args: Any) -> None:
        """Silence :mod:`http.server`'s per-request stderr log: tests read the records."""

    # -- replies ---------------------------------------------------------------------------

    def _reply(
        self,
        status: int,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
        *,
        length: int | None = None,
        reason: str = "",
    ) -> None:
        """Send a complete reply: status and ``reason``, headers, ``Content-Length``, body.

        ``length`` overrides the advertised length - a ``HEAD`` reports the
        size of the ``GET`` it stands for while sending no body, which
        RFC 9110 section 9.3.2 requires and this method enforces.
        :attr:`~xrdhttp.testing.StorageServer.truncate_at` takes effect here
        for a ``GET``: the full length is promised and the connection closed
        short of it, which is how a client learns to treat a short body as
        an error rather than as the file. So do a fault's ``stall``,
        ``truncate`` and ``hold`` (:class:`~xrdsec.testing.https.Fault`).
        """
        self._head(status, headers or {}, len(body) if length is None else length, reason)
        if self.command == "HEAD" or not body:
            return
        self._before_body()
        cut = self._cut(len(body))
        self.wfile.write(body[:cut])
        if cut < len(body):
            self._cut_short()

    def _head(self, status: int, headers: dict[str, str], length: int, reason: str = "") -> None:
        """The status line and headers, ``Content-Length: length`` last."""
        self.send_response(status, reason.replace("\r", " ").replace("\n", " ") or None)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(length))
        self.end_headers()

    def _before_body(self) -> None:
        """A stalling fault's pause: the headers reach the client, the body does not, yet."""
        if self._fault is not None and self._fault.stall:
            self.wfile.flush()
            time.sleep(self._fault.stall)

    def _cut(self, size: int) -> int:
        """How much of a ``size``-byte body to send: all of it, unless truncation is on."""
        limits = [size]
        if self.command == "GET" and self.app.truncate_at is not None:
            limits.append(self.app.truncate_at)
        if self._fault is not None and self._fault.truncate is not None:
            limits.append(self._fault.truncate)
        return min(limits)

    def _cut_short(self) -> None:
        """Flush what was sent of a truncated body and close the connection on it.

        A truncating fault hangs up outright (after holding the connection
        silent, if it says to), so the client sees the end at once.
        """
        self.wfile.flush()
        self.close_connection = True
        if self._fault is not None:
            if self._fault.hold:
                hold(self.connection, self._fault.hold)
            self._hang_up()

    def _hang_up(self) -> None:
        """Close without (another) word, as a crashed or hostile server does."""
        self.close_connection = True
        with contextlib.suppress(OSError):
            self.connection.shutdown(socket.SHUT_RDWR)

    def _json(self, status: int, document: Any, headers: dict[str, str] | None = None) -> None:
        """Reply with ``document`` serialised as ``application/json`` (tape REST, tokens)."""
        extra = {"Content-Type": "application/json", **(headers or {})}
        self._reply(status, json.dumps(document).encode(), extra)

    def _send_content(
        self, status: int, headers: dict[str, str], source: BinaryIO, span: tuple[int, int]
    ) -> None:
        """Send ``span`` (``start``, ``count``) of ``source`` as the body, without holding it.

        :meth:`socket.socket.sendfile` moves a real file without a
        Python-level copy (and falls back to reads for TLS or an in-memory
        file), so multi-GiB test files are cheap; truncation applies as in
        :meth:`_reply`.
        """
        start, count = span
        self._head(status, headers, count)
        if self.command == "HEAD" or not count:
            return
        self._before_body()
        cut = self._cut(count)
        self.connection.sendfile(source, start, cut)
        if cut < count:
            self._cut_short()

    def _digest_headers(self, chunks: Callable[[], Iterable[bytes]]) -> dict[str, str]:
        """``Digest`` and ``Repr-Digest`` for what the request wants and the server offers.

        ``chunks`` produces the content afresh for each algorithm. Digests
        are only sent when asked for, as storage elements do; both header
        generations can be answered at once, and each can be switched off
        to model a server that only knows the other. With
        :attr:`~xrdhttp.testing.StorageServer.digest_on_head` off a ``HEAD``
        gets none, as from servers that checksum only while streaming.
        """
        app = self.app
        if self.command == "HEAD" and not app.digest_on_head:
            return {}

        def digest(algorithm: str) -> bytes:
            return checksum(chunks(), algorithm)

        headers = {}
        wanted = self.headers.get("Want-Digest")
        if wanted and app.legacy_digests:
            value = legacy_digest(wanted, app.digests, app.digest_all, digest)
            if value:
                headers["Digest"] = value
        wanted = self.headers.get("Want-Repr-Digest")
        if wanted and app.repr_digests:
            value = repr_digest(wanted, app.digests, digest)
            if value:
                headers["Repr-Digest"] = value
        return headers

    # -- request bodies ----------------------------------------------------------------------

    def _has_body(self) -> bool:
        """Whether the request announced a body (chunked, or a non-zero ``Content-Length``)."""
        chunked = self.headers.get("Transfer-Encoding", "").lower() == "chunked"
        return chunked or int(self.headers.get("Content-Length") or 0) > 0

    def _settle_body(self) -> None:
        """Read the rest of the body before an early answer, so the connection stays usable.

        A body read ahead by the front always counts as read (and is
        recorded). Beyond that, with
        :attr:`~xrdhttp.testing.StorageServer.drain_refused` the whole body
        is read and dropped, as most servers do once they have sent
        ``100 Continue``; without it the connection is closed after the
        answer instead, as a server that decided before the body does.
        """
        if self._consumed:
            return
        if self._prefetched is not None or (self.app.drain_refused and self._has_body()):
            self._read_body()

    def _read_body(self) -> bytes:
        """The whole request body (read once: handlers call this at most once)."""
        return b"".join(self._body_chunks())

    def _body_chunks(self) -> Iterator[bytes]:
        """Yield the request body as it arrives, keeping it in the record if it is small.

        The record keeps up to
        :attr:`~xrdhttp.testing.StorageServer.body_record_limit` bytes; a
        larger upload is streamed to the store and not held in memory.
        """
        limit = self.app.body_record_limit
        kept: list[bytes] = []
        size = 0
        for chunk in self._raw_body():
            size += len(chunk)
            if size <= limit:
                kept.append(chunk)
            yield chunk
        if size <= limit:
            self._record.body = b"".join(kept)

    def _raw_body(self) -> Iterator[bytes]:
        """Yield the body as sent, setting ``_consumed`` once it is all read.

        Three shapes: a body already prefetched by the front, RFC 9112
        section 7.1 chunked coding (chunk extensions after ``;`` ignored,
        trailer fields read and dropped) and a plain ``Content-Length``. A
        client that hangs up early just ends the iteration: ``_consumed``
        then stays false and the connection is closed after the reply.
        """
        if self._prefetched is not None:
            yield self._prefetched
            self._consumed = True
            return
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            yield from self._chunked()
            return
        remaining = int(self.headers.get("Content-Length") or 0)
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, CHUNK))
            if not chunk:
                return
            remaining -= len(chunk)
            yield chunk
        self._consumed = True

    def _chunked(self) -> Iterator[bytes]:
        """Yield a chunked body's chunks; a hang-up reads as the last chunk."""
        while size := int(self.rfile.readline().split(b";")[0].strip() or b"0", 16):
            yield self.rfile.read(size)
            self.rfile.readline()  # the CRLF after each chunk's data
        while self.rfile.readline().strip():
            pass  # trailer fields, then the empty line ending the message
        self._consumed = True
