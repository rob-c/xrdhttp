"""Moving body bytes on the socket: what both HTTP clients do below http.client.

:mod:`http.client` is correct but not fast at the two ends of a bulk transfer,
and every client - xrdclient's and xgfalclient's HTTP plugin - shares the
same three remedies, kept here as one implementation:

* :class:`DirectReader` reads a known-length body **straight off the
  socket** once http.client has parsed the headers: one TLS record per call,
  with none of the three Python-level wrappers ``HTTPResponse.readinto`` goes
  through for each record. That time is spent holding the GIL, and parallel
  download streams otherwise queue for it.
* :func:`send_file` sends part of a local file as a request body with
  ``socket.sendfile`` in the clear, and in large ``sendall`` writes over TLS,
  where ``sendfile`` cannot encrypt and Python quietly falls back to 8 KiB
  sends.
* :class:`IdlePool` keeps the idle connections to one endpoint for reuse,
  newest first, safely across threads.

None of it raises a client's own exceptions - a socket error is the
socket's, a short local file a :class:`ShortFileError` - so each client words
failures its own way.

Ownership: nothing here closes a socket it was handed or a response it reads.
The connection belongs to whichever client pool lent it out; :class:`IdlePool`
owns only the connections that are idle inside it. Each of the three parts is
independent - read the one you are changing - and each is exercised by
``tests/test_wire.py`` over real plain and TLS socket pairs.
"""

from __future__ import annotations

import errno
import http.client
import io
import socket
import ssl
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, Generic, Protocol, TypeVar, cast

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer

__all__ = [
    "DIRECT_READ",
    "MAX_IDLE",
    "SEND_BLOCK",
    "SEND_SLICE",
    "DirectReader",
    "IdlePool",
    "ShortFileError",
    "send_file",
]

#: Reads at least this big bypass http.client's buffered stream. Below it the
#: wrappers cost little next to the copy, and a small read is often a header
#: probe that is better served from http.client's buffer.
DIRECT_READ = 1 << 16
#: How much of a file one TLS ``sendall`` carries: gfal2's ``COPY_BUFFERSIZE``.
SEND_BLOCK = 4 << 20
#: How much of a file one ``sendfile`` (or one progress report) covers, so a
#: cancelled upload notices within a slice rather than at the end.
SEND_SLICE = 16 << 20
#: Idle connections an :class:`IdlePool` keeps per endpoint.
MAX_IDLE = 16

#: One read from the socket into a view: ``receive(count, view) -> bytes read``.
_Receive = Callable[[int, memoryview], int]


class ShortFileError(OSError):
    """The local file ended before the body it was to supply had been sent."""

    def __init__(self, offset: int) -> None:
        """Record the file offset at which the local read came back empty.

        ``EIO`` because, to the caller, a file that shrank while being
        uploaded is an I/O failure of the source, not of the network.
        """
        super().__init__(errno.EIO, f"Short read from the local file at offset {offset}")
        self.offset = offset


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def _at_end(count: int, view: memoryview) -> int:
    """The receiver once the peer has gone: every later read is an end of file."""
    return 0


def _receiver(sock: socket.socket) -> _Receive:
    """``receive(count, view)``: one read from ``sock`` into ``view``.

    On a TLS socket that is the underlying ``_ssl`` object's ``read`` - one
    record per call, and the wrappers in :mod:`ssl` are per-call Python code
    run while holding the GIL, which is what several download streams contend
    for.
    """
    tls = getattr(sock, "_sslobj", None)
    if tls is not None:
        return cast("_Receive", tls.read)

    def receive(count: int, view: memoryview) -> int:
        """A plain socket's ``recv_into``, reordered to the ``_Receive`` shape."""
        return sock.recv_into(view, count)

    return receive


class DirectReader:
    """``readinto`` for one response, from its socket where that is worth it.

    A read of at least :data:`DIRECT_READ` bytes of a body whose length is
    known goes straight to the socket: whatever http.client has already
    buffered comes first (one ``readinto1``, which takes the buffer and never
    reads past it once it holds anything), then the socket is read with
    nothing in between. The response's ``length`` is kept up to date, so it
    still says how much is owed, and a body read to its end is finished
    through http.client - which then lets the connection be reused. Any other
    read (a small one, a chunked body, a closed stream) is the response's own.

    ``sock`` is the connection's socket. A response whose stream is not that
    socket - one replayed from bytes read while waiting for ``100 Continue``
    (:mod:`xrdhttp.expect`) - is only ever read through http.client,
    since the socket would skip what the replay still holds.

    Errors are the socket's and http.client's own; the peer closing the
    stream is an end of file, after which every read returns ``0`` and
    ``raw.length`` says what never arrived.
    """

    __slots__ = ("_raw", "_receive")

    def __init__(self, raw: http.client.HTTPResponse, sock: socket.socket | None) -> None:
        """Decide once, up front, whether reads of ``raw`` may bypass http.client.

        ``raw.fp.raw`` is the :class:`socket.SocketIO` http.client made from
        the connection's socket; anything else (``None`` once closed, an
        in-memory replay) means the socket is not where the body's next
        bytes are.
        """
        self._raw = raw
        self._receive: _Receive | None = None
        stream = getattr(raw.fp, "raw", None)
        # Each condition is its own reason to stay on http.client's path, and
        # the tests take each one alone.
        if sock is not None and isinstance(stream, socket.SocketIO):
            self._receive = _receiver(sock)

    @property
    def owed(self) -> int | None:
        """What the response still owes of its declared length; ``None`` if it declared none."""
        return self._raw.length

    def readinto(self, buffer: WriteableBuffer) -> int:
        """Fill ``buffer`` as far as one call can; ``0`` only at the end of the body."""
        raw = self._raw
        length, fp = raw.length, raw.fp
        view = memoryview(buffer)
        # http.client has no length for a chunked body, and no stream once it
        # has closed one (an end of file with bytes still owed, say).
        if view.nbytes >= DIRECT_READ and length and fp is not None and self._receive is not None:
            return self._direct(view, fp, length)
        return raw.readinto(view)

    def _direct(self, view: memoryview, fp: io.BufferedReader, length: int) -> int:
        """Fill ``view`` from http.client's buffer, then from the socket.

        Never reads past the declared ``length``: the bytes after it are
        the next response on a keep-alive connection. The ``length`` bookkeeping
        must stay exact, because http.client decides from it whether the
        connection may be reused.
        """
        want = min(view.nbytes, length)
        view = view.cast("B")[:want]
        # Whatever http.client already pulled into its buffer comes first;
        # reading the socket before it would reorder the body.
        got = fp.readinto1(view)
        receive = cast("_Receive", self._receive)
        while got < want:
            try:
                count = receive(want - got, view[got:])
            except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
                count = 0  # the peer closed the TLS session: an end of file
            if not count:
                # Once the peer has gone every later read is an end of file
                # too, not whatever OpenSSL says about a dead session.
                self._receive = _at_end
                break
            got += count
        self._raw.length = length - got
        if not self._raw.length:
            self._raw.read()  # nothing left to read: http.client closes its stream
        return got


# ---------------------------------------------------------------------------
# Sending
# ---------------------------------------------------------------------------


def send_file(
    sock: socket.socket,
    file: io.BufferedIOBase | io.RawIOBase,
    offset: int,
    count: int,
    *,
    progress: Callable[[int], None] | None = None,
    slice_size: int = SEND_SLICE,
    block: int = SEND_BLOCK,
) -> None:
    """Send ``count`` bytes of ``file`` from ``offset`` down ``sock``.

    In the clear that is ``socket.sendfile``, ``slice_size`` at a time, so
    the kernel copies the bytes; over TLS, ``sendfile`` cannot encrypt and
    would quietly fall back to 8 KiB sends, so the file is read into one
    ``block``-sized buffer and sent with ``sendall``. ``progress`` hears about
    every slice as it leaves and may raise to stop the upload (a cancelled or
    timed-out copy). A file that ends first raises :class:`ShortFileError`.
    """
    if isinstance(sock, ssl.SSLSocket):
        span = range(offset, offset + count)
        _send_file_tls(sock, file, span, progress, min(slice_size, block, count))
        return
    remaining = count
    while remaining > 0:
        # ``socket.sendfile`` seeks ``file`` itself and leaves it positioned
        # after what was sent; it returns 0 only when the file ran out.
        sent = sock.sendfile(file, offset, min(slice_size, remaining))
        if sent <= 0:
            raise ShortFileError(offset)
        offset += sent
        remaining -= sent
        if progress is not None:
            progress(sent)


def _send_file_tls(
    sock: ssl.SSLSocket,
    file: io.BufferedIOBase | io.RawIOBase,
    span: range,
    progress: Callable[[int], None] | None,
    size: int,
) -> None:
    """:func:`send_file`'s TLS path: the file offsets in ``span``, ``size`` at a time.

    One buffer is allocated and reused for the whole upload, so a multi-GiB
    file costs one ``size``-byte allocation, and each ``sendall`` hands
    OpenSSL megabytes at once to cut into 16 KiB TLS records, where
    ``socket.sendfile``'s fallback would hand it 8 KiB per Python call.
    """
    buffer = bytearray(size)
    view = memoryview(buffer)
    offset, remaining = span.start, len(span)
    file.seek(offset)
    while remaining > 0:
        got = file.readinto(view[: min(size, remaining)])
        if not got:
            raise ShortFileError(offset)
        sock.sendall(view[:got])
        offset += got
        remaining -= got
        if progress is not None:
            progress(got)


# ---------------------------------------------------------------------------
# Pooling
# ---------------------------------------------------------------------------


class _Pooled(Protocol):
    """What a pool holds: a connection that can say whether it is still usable."""

    def close(self) -> None:
        """Release the connection's socket; called on eviction and pool close."""


_Conn = TypeVar("_Conn", bound=_Pooled)


class IdlePool(Generic[_Conn]):
    """Idle connections to one endpoint (and TLS context), newest first.

    A request takes the most recently returned connection that is still
    usable - fewest chances for the server to have timed it out - or a new
    one from ``factory``; at most ``limit`` wait between requests, and a
    connection returned to a full or closed pool is closed. Checkouts are not
    limited: parallel streams each get a connection of their own.

    "Usable" is the connection's ``is_connected`` (see
    :class:`xrdhttp.connection.HTTPConnection`): a poll of the
    socket that says no for one the server has closed or that holds bytes
    nobody asked for. Thread-safe; the poll runs outside the lock.
    """

    def __init__(self, factory: Callable[[], _Conn], limit: int = MAX_IDLE) -> None:
        """An empty pool that will make new connections with ``factory``.

        ``factory`` is expected not to connect: :meth:`get` documents its
        result as not yet connected, and the caller connects it on first use.
        """
        self._factory = factory
        self._limit = limit
        self._lock = threading.Lock()
        self._idle: list[_Conn] = []
        self._closed = False

    def get(self) -> _Conn:
        """A usable idle connection, or a new (not yet connected) one."""
        while True:
            with self._lock:
                if not self._idle:
                    break
                conn = self._idle.pop()
            if getattr(conn, "is_connected", False):
                return conn
            conn.close()  # closed by the server, or holding bytes nobody asked for
        return self._factory()

    def put(self, conn: _Conn) -> None:
        """Keep ``conn`` for the next request, or close it if there is no room."""
        # Appended, and :meth:`get` pops from the end: newest first, so the
        # connections most likely to be timed out by the server age out.
        with self._lock:
            if not self._closed and len(self._idle) < self._limit:
                self._idle.append(conn)
                return
        conn.close()

    def close(self) -> None:
        """Close every idle connection; any returned later is closed as it comes."""
        with self._lock:
            self._closed = True
            idle, self._idle = self._idle, []
        for conn in idle:
            conn.close()

    def idle_count(self) -> int:
        """How many connections are waiting to be reused."""
        with self._lock:
            return len(self._idle)
