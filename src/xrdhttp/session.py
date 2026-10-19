"""One pooled, thread-safe HTTP/1.1 session: what every client's HTTP facade sits on.

xrdclient's ``HTTPClient``, xgfalclient's HTTP plug-in and xrdarc's A-REX
transport each grew the same machinery on top of :mod:`http.client`: a pool of
keep-alive connections per endpoint and credential, one retry when a pooled
connection turns out to have gone stale, a redirect loop that decides which
credentials may follow, ``Expect: 100-continue`` before a large upload, a
bounded retry of idempotent requests on ``429``/``503`` honouring
``Retry-After``, and a table turning statuses into the client's own errors.
:class:`Session` is that machinery once, built from the pieces next door:

* :mod:`.engine` - the redirect loop and the one retry on a stale connection;
* :mod:`.connection` - the :mod:`http.client` connections, TLS included;
* :mod:`.wire` - :class:`~xrdhttp.wire.IdlePool` (the pool),
  :class:`~xrdhttp.wire.DirectReader` (large body reads straight off the
  socket) and :func:`~xrdhttp.wire.send_file` (file bodies);
* :mod:`.expect` - the ``100 Continue`` wait and the early answer;
* :mod:`.redirects` - the default credential policy and ``Location``
  resolution.

What stays each client's is *policy*, handed in rather than decided here:

* **TLS** - a context factory (``tls(url) -> SSLContext``) or a context per
  request (:class:`Auth`); the pool is keyed by the context's identity, so
  two credentials never share a connection;
* **credentials** - :class:`Auth`: headers that follow a redirect only where
  :class:`RedirectPolicy` lets them, and a ``prepare`` hook that sees every
  hop just before it is sent (an S3 signature, a virtual-host rewrite, a
  client's standing headers);
* **errors** - an :class:`Errors` object spells every failure: an unwanted
  status (davix maps ``409`` to ``ENOENT``, A-REX means ``EEXIST``), a
  transport failure, a redirect problem, a closed session. The defaults
  raise :mod:`xrdcore.errors` and :class:`HTTPStatusError`;
* **retries** - :class:`RetryPolicy`: how many times an idempotent request
  is repeated on which statuses and whether on a dropped connection, with
  :mod:`xrdcore.retry`'s jittered backoff or the server's ``Retry-After``.

Where to start reading: :meth:`Session.request` (one request, redirects and
retries included) and :class:`Response` (how a connection finds its way back
to the pool), then :meth:`Session.upload` (a body the caller streams).

What a maintainer must not break - ownership: a checked-out connection
belongs to exactly one :class:`_Exchange`, which belongs to one
:class:`Response` or :class:`Upload`; only a response read to its end goes
back to the pool, and everything else is closed. Getting that wrong does not
fail loudly - it hands the next request a connection with somebody else's
unread bytes on it. And no request is replayed unless it is safe to: the
stale-connection retry needs a *reused* connection that failed before any of
the answer arrived, and the backoff retries need an idempotent request.
"""

from __future__ import annotations

import contextlib
import http.client
import io
import socket
import ssl
import threading
import time
import urllib.parse
import warnings
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, BinaryIO, TypedDict, Unpack, cast

from xrdcore import cancel
from xrdcore import errors as _errors
from xrdcore import retry as _retry
from xrdcore.log import get_logger, redact

from . import expect as _expect
from . import redirects as _policy
from .connection import HTTPConnection, HTTPSConnection
from .engine import REDIRECTS, Request, attempt, redirects
from .wire import (
    MAX_IDLE,
    SEND_BLOCK,
    SEND_SLICE,
    DirectReader,
    IdlePool,
    ShortFileError,
    send_file,
)

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer

__all__ = [
    "ERROR_BODY",
    "IDEMPOTENT",
    "MAX_BODY",
    "Answer",
    "Auth",
    "Body",
    "Errors",
    "Failure",
    "FileBody",
    "HTTPStatusError",
    "Hop",
    "Options",
    "Policy",
    "RedirectError",
    "RedirectPolicy",
    "Response",
    "RetryPolicy",
    "Route",
    "Session",
    "SessionClosedError",
    "UnverifiedTLSWarning",
    "Upload",
    "Watch",
    "body_length",
]

_log = get_logger(__name__)

#: Methods safe to send twice (RFC 9110 sections 9.2.1 and 9.2.2) - the safe
#: ones, ``PUT`` and ``DELETE`` - and WebDAV's read-only ``PROPFIND``. ``POST``
#: is not: a repeated A-REX ``action=new`` submits the jobs twice. ``MKCOL``,
#: ``MOVE`` and ``COPY`` are left to a client that knows its servers.
IDEMPOTENT = frozenset({"GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE", "PROPFIND"})

#: What :meth:`Response.body` reads at most by default. A ``PROPFIND`` of a huge
#: collection is the realistic way for a whole-body read to exhaust memory.
MAX_BODY = 1 << 26

#: How much of an unwanted answer's body is read into its error: enough for any
#: explanation a server writes, little enough that an HTML page costs nothing.
ERROR_BODY = 64 * 1024

#: An abandoned body shorter than this is read out to keep its connection;
#: reading more costs more than the handshake a new connection would.
_DRAIN_LIMIT = 64 * 1024

#: How a pooled connection the server has since closed shows itself on first
#: use. Only these are retried at once, and only on a *reused* connection: a
#: fresh one failing this way is a real failure that a retry would repeat.
_STALE = (
    http.client.RemoteDisconnected,
    http.client.BadStatusLine,
    ConnectionResetError,
    BrokenPipeError,
    ConnectionAbortedError,
)

#: TLS failures that are a closed connection rather than a refused handshake.
_TLS_DROPS = (ssl.SSLEOFError, ssl.SSLZeroReturnError)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class UnverifiedTLSWarning(UserWarning):
    """A connection was made with a TLS context that does not verify the server.

    Issued once per new connection, as ``urllib3``'s ``InsecureRequestWarning``
    was per request: a user who turned verification off (``--insecure``) is
    told every time it matters, never silenced. :attr:`Policy.warn_unverified`
    turns it off for a client that reports this its own way.
    """


class HTTPStatusError(_errors.ProtocolError):
    """An answer whose status the caller did not expect: the default status error.

    Clients replace it through :meth:`Errors.status` with their own vocabulary;
    this one keeps everything a message needs - the status line, the URL and
    up to :data:`ERROR_BODY` bytes of the body, decoded - and pickles whole.
    """

    def __init__(self, status: int, reason: str, *, url: str = "", body: str = "") -> None:
        """Record the answer; the message is the status line and the URL."""
        super().__init__(f"HTTP {status} {reason} for {url}")
        self.status = status
        self.reason = reason
        self.url = url
        self.body = body

    def __reduce__(self) -> tuple[Callable[..., BaseException], tuple[object, ...]]:
        """Pickle with the status, reason, URL and body intact (see :mod:`xrdcore.errors`)."""
        state = {"url": self.url, "body": self.body}
        return _errors.rebuild, (type(self), (self.status, self.reason), state)


class RedirectError(_errors.ProtocolError):
    """A redirect chain that cannot be followed: too long, or to a URL that is not HTTP."""


class SessionClosedError(_errors.XrdError, ValueError):
    """A request on a session that was closed or aborted.

    A :class:`ValueError` as well, as I/O on a closed file is: the caller used
    the object after its end, which no retry will mend.
    """


@dataclass(frozen=True, slots=True)
class Answer:
    """An answer whose status the caller did not expect, as :meth:`Errors.status` sees it.

    ``body`` is at most :data:`ERROR_BODY` bytes, and empty when the
    connection died while it was read: the status alone still says what
    happened.
    """

    method: str
    url: str
    status: int
    reason: str
    headers: http.client.HTTPMessage
    body: bytes

    @property
    def text(self) -> str:
        """The body as UTF-8, undecodable bytes replaced: an error page must not fail to print."""
        return self.body.decode("utf-8", "replace")


@dataclass(frozen=True, slots=True)
class Failure:
    """A transport failure, as :meth:`Errors.transport` sees it.

    ``error`` is what the socket, TLS or :mod:`http.client` raised (an
    :class:`http.client.IncompleteRead` for a body cut short). ``reading`` is
    ``True`` once the answer's head had arrived - the request was delivered
    and the body was being read - and ``False`` while sending or connecting.
    """

    method: str
    url: str
    error: Exception
    reading: bool = False


class Errors:
    """How a session spells its failures; a client subclasses it for its own exceptions.

    One object rather than four callbacks, because the four answers belong
    together: they are a client's error vocabulary. Every method returns the
    exception, and the session raises it, chained to the cause.
    """

    def status(self, answer: Answer) -> Exception:
        """The error for a status the request did not ``expect``."""
        return HTTPStatusError(answer.status, answer.reason, url=answer.url, body=answer.text)

    def transport(self, failure: Failure) -> Exception:
        """The error for a connection that failed: :mod:`xrdcore.errors`' by default.

        A timeout is a :class:`xrdcore.errors.TimeoutError`; anything else a
        :class:`xrdcore.errors.ConnectionError`, which a caller that retries
        on :class:`xrdcore.errors.TransientError` does not repeat (a refused
        handshake fails the same way every time).
        """
        what = f"{failure.method} {redact(failure.url)}"
        if isinstance(failure.error, TimeoutError):
            return _errors.TimeoutError(f"{what} timed out")
        return _errors.ConnectionError(f"{what} failed: {failure.error}")

    def redirect(
        self, method: str, url: str, problem: str, error: Exception | None = None
    ) -> Exception:
        """The error for a redirect chain that cannot be followed (``problem`` says why).

        ``error`` is what refused the ``Location`` - the route's or the
        redirect policy's :class:`ValueError` - and ``None`` for a chain
        that was only too long; a client whose route raises its own
        vocabulary (chained as the cause) can hand that back instead.
        """
        return RedirectError(f"{method} {redact(url)}: {problem}")

    def closed(self, aborted: bool) -> Exception:
        """The error for a request on a closed (or, ``aborted``, an aborted) session."""
        return SessionClosedError("the session was aborted" if aborted else "the session is closed")


class _Transport(Exception):
    """A transport failure on its way out of :func:`~xrdhttp.engine.attempt`.

    Carries the original exception so that :meth:`Session.request` can
    decide whether to retry before it is spelled as the client's error.
    """

    def __init__(self, error: Exception) -> None:
        """Wrap ``error``, the socket's, TLS's or :mod:`http.client`'s."""
        super().__init__(str(error))
        self.error = error


# ---------------------------------------------------------------------------
# Bodies, routes, hops
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FileBody:
    """``count`` bytes of an open file from ``offset``, sent by :func:`~xrdhttp.wire.send_file`.

    A retried request sends it again from ``offset`` (``send_file`` seeks), so
    a file body is as replayable as bytes. ``progress`` hears about every
    slice as it leaves and may raise to stop the upload; the file ending
    early is a :class:`~xrdhttp.wire.ShortFileError`, never retried.
    """

    file: BinaryIO
    offset: int
    count: int
    progress: Callable[[int], None] | None = None
    #: How much one ``sendfile`` (or one progress report) covers.
    slice: int = SEND_SLICE


#: Every body a request can carry: bytes in memory, or a slice of a file.
Body = bytes | bytearray | memoryview | FileBody


def body_length(body: Body | None) -> int | None:
    """The ``Content-Length`` ``body`` has; ``None`` for a bodiless request.

    A buffer is measured in bytes (``nbytes``), not items, so a memoryview of
    a wider type still declares what goes on the wire.
    """
    if body is None:
        return None
    if isinstance(body, FileBody):
        return body.count
    return memoryview(body).nbytes


@dataclass(frozen=True, slots=True)
class Route:
    """Where one hop goes on the wire: the endpoint and the origin-form request target.

    The default (:meth:`of`) reads ``http``/``https`` and the grid's
    ``dav``/``davs``/``webdav``; a client with schemes of its own (``s3://``,
    ``swift://``) supplies :attr:`Policy.route`.
    """

    scheme: str
    host: str
    port: int
    target: str

    @classmethod
    def of(cls, url: str) -> Route:
        """The route of an absolute HTTP URL whose path and query are already wire-encoded.

        ``ValueError`` for a URL that is not HTTP or names no host. The path
        and query go exactly as written - a CDN's signed redirect covers the
        precise spelling - and a fragment never leaves the client.
        """
        scheme, host, port = _policy.endpoint(url)
        if not host:
            raise ValueError(f"{redact(url)!r} names no host")
        parts = urllib.parse.urlsplit(url)
        target = parts.path or "/"
        if parts.query:
            target = f"{target}?{parts.query}"
        return cls(scheme, host, port, target)


@dataclass(slots=True)
class Hop:
    """One request as it is about to go on the wire; :attr:`Auth.prepare` may change it.

    ``origin`` is the URL the chain started from (or the one a ``401`` was
    answered at); ``credentials`` says whether the caller's credentials may
    still be sent here. A ``prepare`` hook may rewrite ``url`` (a virtual-host
    bucket) and add ``headers`` (a signature over the final ones); it runs
    last, so a signature covers every header that is sent.
    """

    method: str
    url: str
    origin: str
    headers: dict[str, str]
    body: Body | None
    credentials: bool


@dataclass(frozen=True, slots=True)
class Auth:
    """How one request is authorised.

    ``headers`` (a bearer token, Basic auth) follow a redirect only where the
    session's :class:`RedirectPolicy` lets them; ``tls`` is the context the
    handshake uses, in place of the session's factory (an X.509 proxy rides
    there, whatever else is sent); ``prepare`` sees every hop last.
    """

    headers: Mapping[str, str] = field(default_factory=dict)
    tls: ssl.SSLContext | None = None
    prepare: Callable[[Hop], None] | None = None


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RedirectPolicy:
    """How far redirects are followed and what may follow them.

    ``carries(origin, target)`` decides whether the caller's credential
    headers go to ``target`` (default: :func:`xrdhttp.redirects.carries_credentials`,
    the same origin only; gfal2 clients pass
    :func:`~xrdhttp.redirects.davix_carries_credentials`). ``relays`` does the
    same for a ``COPY``'s ``TransferHeader*`` family once the credentials
    stayed behind. Both rights only ever narrow along a chain: once dropped,
    a credential is not picked up again by a later hop. ``limit`` redirects
    are followed, so at most ``limit + 1`` requests are sent.
    """

    limit: int = 10
    carries: Callable[[str, str], bool] = _policy.carries_credentials
    relays: Callable[[str, str], bool] = _policy.relays_transfer_headers


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Which failures a request is repeated after, how often, and how long between.

    ``retries`` more attempts are made of a replayable request (an
    idempotent method - :attr:`methods` - with no ``If-*`` condition, or one
    the caller marks ``idempotent=True``) that was answered with one of
    ``statuses`` or, when ``transport`` is set, that failed on the network.
    The pause is the answer's ``Retry-After`` capped at ``cap``, or else
    :func:`xrdcore.retry.delay`'s jittered backoff from ``backoff``; it is
    spent with ``sleep`` (default :func:`time.sleep` as it is when called).

    Never retried by this policy: a timeout (a server that did not answer in
    the time allowed would only be given it twice), a refused TLS handshake
    (it fails the same way every time), a local file that ran short.

    A request that met a *stale* pooled connection - closed by the server
    after the pool's liveness poll passed it - is sent once more at once, if
    replayable, or whatever its method with ``replay_unanswered`` (davix's
    rule: no byte of an answer had arrived). With ``transport`` set it is
    instead one more transport failure, counted against ``retries`` and
    paused for like any other: a server that drops requests is not to be
    given an extra attempt because the first one rode a reused connection.
    """

    retries: int = 0
    statuses: frozenset[int] = frozenset({429, 503})
    transport: bool = False
    backoff: float = 0.5
    cap: float = 30.0
    methods: frozenset[str] = IDEMPOTENT
    replay_unanswered: bool = False
    sleep: Callable[[float], object] | None = None


@dataclass(frozen=True, slots=True)
class Policy:
    """A session's settings, grouped so that the constructor stays short.

    * ``headers`` - sent with every request (a ``User-Agent``), beneath the
      credentials and the caller's own;
    * ``connect_timeout`` / ``timeout`` - the TCP and TLS handshake, then
      every read; a request may override the latter. A ``timeout`` of
      ``None`` (or zero or less) is no limit; a ``connect_timeout`` of
      ``None`` bounds the handshake by the request's own read timeout, as
      gfal2 bounds both with one setting;
    * ``keep_alive`` - whether a finished connection is pooled, asked on every
      check-in so a client's live option applies from the next request;
    * ``expects(method, length)`` - which requests send
      ``Expect: 100-continue``, waiting up to ``continue_wait`` seconds;
    * ``route(url)`` - where a URL goes on the wire (:meth:`Route.of`);
    * ``max_idle`` - idle connections kept per endpoint and credential;
    * ``warn_unverified`` - issue :class:`UnverifiedTLSWarning`.
    """

    headers: Mapping[str, str] = field(default_factory=dict)
    connect_timeout: float | None = 30.0
    timeout: float | None = 300.0
    keep_alive: Callable[[], bool] | bool = True
    expects: Callable[[str, int | None], bool] = _expect.wants_expect
    continue_wait: float = _expect.CONTINUE_WAIT
    route: Callable[[str], Route] = Route.of
    max_idle: int = MAX_IDLE
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    redirects: RedirectPolicy = field(default_factory=RedirectPolicy)
    warn_unverified: bool = True


class Options(TypedDict, total=False):
    """The keyword options of :meth:`Session.request`; every one may be left out.

    A ``TypedDict`` rather than nine keyword parameters, so the one place that
    says what a request can carry is also where each option is explained;
    mypy checks every caller's keywords against it all the same.
    """

    #: Sent on top of the standing headers; credential headers among them are
    #: dropped where a redirect's policy drops :attr:`Auth.headers`.
    headers: Mapping[str, str] | None
    #: The body; a :class:`FileBody` goes out with ``sendfile``.
    body: Body | None
    #: The request's credentials (default: none beyond the session's TLS).
    auth: Auth | None
    #: The statuses that are an answer. Anything else is raised through
    #: :meth:`Errors.status` after its body is read. ``None`` (the default)
    #: checks nothing: every answer is returned for the caller to word.
    expect: Collection[int] | None
    #: The longest any one read may wait, in place of :attr:`Policy.timeout`.
    timeout: float | None
    #: Follow redirects (default ``True``); ``False`` hands a 3xx back.
    follow: bool
    #: Whether the request may be sent twice, in place of the method's own
    #: answer: a read-only ``POST`` (a bulk status query) is.
    idempotent: bool | None
    #: Called once, on a first ``401``: new credentials to repeat the hop
    #: with (the host that asked becomes the origin), or ``None`` to return
    #: the ``401``.
    reauth: Callable[[str, Response], Auth | None] | None
    #: This request's words for an unwanted status or an unfollowable
    #: redirect, in place of the session's: WebDAV reuses statuses per verb
    #: (a ``405`` from ``MKCOL`` means "exists"). Transport failures and a
    #: closed session are the session's :class:`Errors` whatever is passed.
    errors: Errors | None


@dataclass(slots=True)
class _Call:
    """One :meth:`Session.request` call's options, resolved once."""

    method: str
    url: str
    headers: Mapping[str, str]
    body: Body | None
    auth: Auth
    expect: Collection[int] | None
    timeout: float | None
    follow: bool
    replayable: bool
    reauth: Callable[[str, Response], Auth | None] | None
    errors: Errors
    origin: str = ""
    reauthed: bool = False


# ---------------------------------------------------------------------------
# Exchanges
# ---------------------------------------------------------------------------

#: ``(scheme, host, port, TLS context)``: a pool per endpoint *and* credential,
#: so a connection authenticated with one proxy in its handshake is never
#: handed to a request made for another. The context is held by identity
#: (``SSLContext`` does not define equality), and the key keeps it alive.
_Key = tuple[str, str, int, ssl.SSLContext | None]


def _nothing() -> None:
    """The release of an exchange that nothing was registered for."""


@dataclass(eq=False)
class _Exchange:
    """One connection, checked out for one request.

    While it is checked out, :meth:`Session.abort` and the session's
    ``watch`` hook may :meth:`abort` it from another thread; :meth:`release`
    - on check-in or close - ends that.
    """

    key: _Key
    conn: http.client.HTTPConnection
    reused: bool
    release: Callable[[], None] = field(default=_nothing, repr=False)

    def abort(self) -> None:
        """Shut the socket down under a thread blocked on it; closing is the owner's.

        A shutdown wakes a blocked ``recv``/``send`` at once with an end of
        stream; closing the descriptor under it could lose that wakeup. It is
        the plain socket's shutdown even under TLS: ``SSLSocket.shutdown``
        would drop the TLS state from under the thread still reading it.
        """
        sock = self.conn.sock
        if sock is not None:
            # Already gone, there is nothing left to wake.
            with contextlib.suppress(OSError):
                socket.socket.shutdown(sock, socket.SHUT_RDWR)

    def close(self) -> None:
        """Give the connection up for good: no longer abortable, and not pooled.

        Release comes first, so an abort racing with this close finds nothing
        registered rather than a socket being torn down twice.
        """
        self.release()
        self.conn.close()


def _has(headers: Mapping[str, str], name: str) -> bool:
    """Whether ``headers`` has ``name``, whatever its case."""
    return any(key.lower() == name for key in headers)


def _send_head(conn: http.client.HTTPConnection, hop: Hop, target: str) -> None:
    """The request line and the hop's headers, flushed; no body.

    :mod:`http.client`'s automatic ``Accept-Encoding: identity`` is left out,
    and its ``Host`` too when the hop carries one, so the headers on the
    wire are exactly the hop's - which is what a signature over them needs.
    """
    conn.putrequest(
        hop.method, target, skip_host=_has(hop.headers, "host"), skip_accept_encoding=True
    )
    for name, value in hop.headers.items():
        conn.putheader(name, value)
    conn.endheaders()


def _send_body(conn: http.client.HTTPConnection, body: Body) -> None:
    """A whole request body: ``sendfile`` (or large TLS writes) for a file, ``send`` for bytes."""
    if isinstance(body, FileBody):
        sock = conn.sock
        assert sock is not None  # the head was just sent on it
        send_file(
            sock,
            cast("io.BufferedIOBase", body.file),
            body.offset,
            body.count,
            progress=body.progress,
            slice_size=body.slice,
            block=SEND_BLOCK,
        )
    else:
        conn.send(body)


def _early(conn: http.client.HTTPConnection, exc: OSError) -> http.client.HTTPResponse:
    """The answer of a server that hung up mid-body, or ``exc`` if it sent none.

    A storage element that refuses an upload (a quota, a permission) often
    says why and closes; that answer explains far better than ``EPIPE``.
    """
    try:
        return conn.getresponse()
    except (OSError, http.client.HTTPException):
        raise exc from None


def _exchange(
    conn: http.client.HTTPConnection, hop: Hop, target: str, wait: float
) -> tuple[http.client.HTTPResponse, bool]:
    """Send ``hop`` on ``conn`` and read the answer's head: the answer, and whether it is reusable.

    An answer that came before the body was sent (after ``Expect:
    100-continue``, or a hang-up mid-body) is not reusable: the server may
    still be waiting for a body nobody is going to send.
    """
    _send_head(conn, hop, target)
    body = hop.body
    if body is None:
        return conn.getresponse(), True
    if _has(hop.headers, "expect"):
        try:
            _expect.await_continue(conn, hop.method, wait)
        except _expect.InterimAnswer as answered:
            return answered.response, False
    try:
        _send_body(conn, body)
    except (BrokenPipeError, ConnectionResetError) as exc:
        return _early(conn, exc), False
    return conn.getresponse(), True


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------


class Response:
    """An answer whose body has not been read yet.

    Read it with :meth:`read`, :meth:`readinto`, :meth:`readline` or
    :meth:`body`, then :meth:`close` it - which puts the connection back in
    the pool if the body was read to the end, and drops it otherwise. A read
    that fails, or a body that ends before its ``Content-Length``, raises
    :meth:`Errors.transport`'s error (``reading=True``) and drops the
    connection. Not thread-safe, like any stream, except :meth:`shutdown`.
    """

    def __init__(
        self,
        session: Session,
        exchange: _Exchange,
        raw: http.client.HTTPResponse,
        hop: Hop,
        reusable: bool = True,
    ) -> None:
        """Take ownership of ``exchange``, which only :meth:`close` gives up.

        ``hop`` is the request that was answered (after redirects).
        ``reusable`` is ``False`` for an answer that arrived before the body
        was sent: that connection is closed whatever the answer says.
        """
        self._session = session
        self._exchange = exchange
        self._raw = raw
        self._reusable = reusable
        self._reader = DirectReader(raw, exchange.conn.sock)
        self.method = hop.method
        self.url = hop.url
        self.status = raw.status
        self.reason = raw.reason
        self.headers = raw.msg
        self.closed = False

    def header(self, name: str, default: str = "") -> str:
        """Header ``name`` (case-insensitive), or ``default``; a repeated one comes back first."""
        value = self.headers.get(name)
        return default if value is None else str(value)

    @property
    def length(self) -> int | None:
        """The declared ``Content-Length``; ``None`` when absent or not a plain number.

        ``isdigit`` rather than ``int()``: a signed or spaced value is not a
        valid length (RFC 9110 section 8.6), and a server that sends one is
        better treated as having declared nothing.
        """
        raw = self.header("Content-Length").strip()
        return int(raw) if raw.isascii() and raw.isdigit() else None

    @property
    def owed(self) -> int | None:
        """What the body still owes of its declared length; ``None`` if it declared none."""
        return self._raw.length

    def read(self, amount: int | None = None) -> bytes:
        """Up to ``amount`` bytes of the body (all of it for ``None``); empty only at its end.

        :mod:`http.client` reports a body cut short as a quiet end of file;
        here that is a transport error, so a copy can tell a cut from the end.
        """
        try:
            data = self._raw.read(amount)
        except (OSError, http.client.HTTPException) as exc:
            raise self._failed(exc) from exc
        if amount and not data:
            self._short()
        return data

    def readinto(self, buffer: WriteableBuffer) -> int:
        """Fill ``buffer`` from the body; ``0`` only at a true end of the body.

        Large reads of a known-length body go straight to the socket
        (:class:`~xrdhttp.wire.DirectReader`).
        """
        view = memoryview(buffer)
        try:
            count = self._reader.readinto(view)
        except (OSError, http.client.HTTPException) as exc:
            raise self._failed(exc) from exc
        if count == 0 and view.nbytes:
            self._short()
        return count

    def readline(self, limit: int = 1 << 16) -> bytes:
        """One line of the body, at most ``limit`` bytes (a TPC performance marker)."""
        try:
            return self._raw.readline(limit)
        except (OSError, http.client.HTTPException) as exc:
            raise self._failed(exc) from exc

    def body(self, limit: int = MAX_BODY) -> bytes:
        """The whole body, at most ``limit`` bytes of it, and the response closed.

        A ``HEAD`` answer has no body whatever its ``Content-Length`` says. A
        body over ``limit`` is truncated deliberately (nothing was lost on
        the wire); one that ends before its declared length is a transport
        error.
        """
        try:
            if self.method == "HEAD":
                return b""
            data = self.read(limit)
            if len(data) < limit and self._raw.length:
                self._short()
            return data
        finally:
            self.close()

    def _short(self) -> None:
        """Raise the error for a body that ended before its declared length."""
        owed = self._raw.length
        if owed:
            error = http.client.IncompleteRead(b"", owed)
            raise self._failed(error) from error

    def _failed(self, exc: Exception) -> Exception:
        """Give the connection up, and the error a failed read becomes.

        After a read error the connection's framing cannot be trusted. An
        abort's end of stream is the abort, not a server that went away.
        """
        self._reusable = False
        self.close()
        return self._session._failure(Failure(self.method, self.url, exc, reading=True))

    def shutdown(self) -> None:
        """Wake a thread blocked reading this body; safe from any thread.

        For a cancel watcher (:func:`xrdcore.cancel.watching`): the socket is
        shut down, the blocked read sees an end of stream, and the owner's
        :meth:`close` then drops the connection.
        """
        self._reusable = False
        self._exchange.abort()

    def close(self) -> None:
        """Return the connection to the pool if it can take another request; idempotent."""
        if self.closed:
            return
        self.closed = True
        raw = self._raw
        finished = _finish(raw) if self._reusable else False
        raw.close()
        if finished:
            self._session._checkin(self._exchange)
        else:
            self._exchange.close()

    def __enter__(self) -> Response:
        """The response itself: ``with`` guarantees :meth:`close`."""
        return self

    def __exit__(self, *exc: object) -> None:
        """:meth:`close`, whether or not the body was read; exceptions propagate."""
        self.close()


def _finish(raw: http.client.HTTPResponse) -> bool:
    """Whether ``raw``'s connection can carry another request, reading out a short rest.

    :mod:`http.client` marks a response closed once its body is read to the
    end; ``will_close`` says the server will not take another request
    (``Connection: close``, HTTP/1.0, a body delimited by the end of stream).
    """
    if not raw.isclosed():
        remaining = raw.length
        if remaining is None or remaining > _DRAIN_LIMIT:
            return False
        try:
            raw.read()
        except (OSError, http.client.HTTPException):
            return False
    return not raw.will_close


# ---------------------------------------------------------------------------
# The session
# ---------------------------------------------------------------------------

#: The hook a client registers an exchange's abort with while it is checked
#: out; it answers the call that unregisters it, and may raise to refuse the
#: request (a cancel already under way).
Watch = Callable[[Callable[[], None]], Callable[[], None]]


class Session:
    """Pooled HTTP/1.1 to any number of endpoints; safe to share between threads.

    ``tls(url)`` builds the TLS context for an ``https`` request that does
    not bring its own (:attr:`Auth.tls`); ``None`` (or a factory answering
    ``None``) is the stdlib's default, verified against the system CAs
    only. ``policy`` holds the settings, ``errors`` the error vocabulary, and
    ``watch`` (optional) is told of every checked-out connection's abort, so
    a client's ``cancel()`` can wake a blocked request.

    Requests run on the caller's thread; the shared state is the dict of
    pools and the set of checked-out exchanges, both under one lock, and
    each :class:`~xrdhttp.wire.IdlePool` is thread-safe on its own. Parallel
    streams each get a connection of their own: checkouts are not limited,
    only idle connections are.
    """

    def __init__(
        self,
        *,
        tls: Callable[[str], ssl.SSLContext | None] | None = None,
        policy: Policy | None = None,
        errors: Errors | None = None,
        watch: Watch | None = None,
    ) -> None:
        """Nothing is connected until the first request."""
        self.tls = tls
        self.policy = policy or Policy()
        self.errors = errors or Errors()
        self.watch = watch
        self._lock = threading.Lock()
        self._pools: dict[_Key, IdlePool[http.client.HTTPConnection]] = {}
        self._busy: set[_Exchange] = set()
        self._closed = False
        self._aborted = False

    # -- life ----------------------------------------------------------------------

    def __enter__(self) -> Session:
        """The session itself; leaving the block closes it."""
        return self

    def __exit__(self, *exc: object) -> None:
        """:meth:`close`, whether or not the block raised."""
        self.close()

    def __repr__(self) -> str:
        """The pool's size, and nothing that could be a secret."""
        return f"Session({self.idle_count()} idle connection(s))"

    def clear(self) -> None:
        """Close every idle connection; the session stays usable.

        Connections checked out are closed by their owners when they finish,
        since their pool is gone. The pools are swapped out under the lock
        and closed outside it, so a slow TLS shutdown never blocks a checkout.
        """
        with self._lock:
            pools, self._pools = self._pools, {}
        for pool in pools.values():
            pool.close()

    def close(self) -> None:
        """Close every idle connection and refuse every later request; idempotent."""
        with self._lock:
            self._closed = True
        self.clear()

    def abort(self) -> None:
        """Wake every request in flight, and refuse every later one; safe from any thread.

        Each checked-out connection is shut down, which wakes a thread blocked
        on it to an end of stream; that request then raises
        :meth:`Errors.closed` (``aborted=True``), as does every later one.
        """
        with self._lock:
            self._closed = self._aborted = True
            busy = list(self._busy)
        for exchange in busy:
            exchange.abort()
        self.clear()

    def idle_count(self) -> int:
        """How many connections wait in the pools (tests pin keep-alive with it)."""
        with self._lock:
            pools = list(self._pools.values())
        return sum(pool.idle_count() for pool in pools)

    # -- connections -----------------------------------------------------------------

    def _context(self, route: Route, url: str, auth: Auth) -> ssl.SSLContext | None:
        """The TLS context a hop to ``route`` uses: the request's, else the factory's."""
        if route.scheme != "https":
            return None
        if auth.tls is not None:
            return auth.tls
        return self.tls(url) if self.tls is not None else None

    def _pool(self, key: _Key) -> IdlePool[http.client.HTTPConnection]:
        """The pool for ``key``, made on first use; refuses once the session is closed."""
        with self._lock:
            if self._closed:
                raise self.errors.closed(self._aborted)
            pool = self._pools.get(key)
            if pool is None:
                pool = self._pools[key] = IdlePool(self._factory(key), self.policy.max_idle)
            return pool

    def _factory(self, key: _Key) -> Callable[[], http.client.HTTPConnection]:
        """What makes a new, not yet connected, connection for ``key``."""
        scheme, host, port, context = key
        timeout = self.policy.connect_timeout

        def make() -> http.client.HTTPConnection:
            """One connection; :mod:`http.client` connects it on first use."""
            if scheme == "https":
                return HTTPSConnection(host, port, timeout, ssl_context=context)
            return HTTPConnection(host, port, timeout)

        return make

    def _checkout(self, key: _Key) -> _Exchange:
        """A connection for ``key``, pooled or new, registered for :meth:`abort` and ``watch``.

        A ``watch`` that refuses (a cancel under way) gets its error raised
        after the connection is put back: nothing was sent on it.
        """
        pool = self._pool(key)
        conn = pool.get()
        exchange = _Exchange(key, conn, conn.sock is not None)
        unwatch = _nothing
        if self.watch is not None:
            try:
                unwatch = self.watch(exchange.abort)
            except BaseException:
                pool.put(conn)
                raise
        with self._lock:
            self._busy.add(exchange)

        def release() -> None:
            """Forget the exchange: no abort reaches it any more."""
            with self._lock:
                self._busy.discard(exchange)
            unwatch()

        exchange.release = release
        return exchange

    def _checkin(self, exchange: _Exchange) -> None:
        """Pool a connection whose answer was read to the end, or close it.

        A pool missing from the dict means :meth:`clear` ran meanwhile; with
        keep-alive off the connection is closed as well.
        """
        with self._lock:
            pool = self._pools.get(exchange.key)
        if pool is None or not self._keep_alive():
            exchange.close()
            return
        exchange.release()
        pool.put(exchange.conn)

    def _keep_alive(self) -> bool:
        """:attr:`Policy.keep_alive`, asked now."""
        keep = self.policy.keep_alive
        return keep() if callable(keep) else keep

    def _ready(self, exchange: _Exchange, route: Route, timeout: float | None) -> None:
        """Connect ``exchange`` if it is new, and set the read timeout for this request.

        The handshake is bounded by :attr:`Policy.connect_timeout`; every read
        after it by ``timeout``, set on every request so one request's
        override does not outlive it on a pooled connection.
        """
        conn = exchange.conn
        # Zero or less is "no limit", as for the clients' other deadlines; a
        # socket given zero would be non-blocking instead.
        limit = timeout if timeout is None or timeout > 0 else None
        if conn.sock is None:
            if self.policy.connect_timeout is None:
                conn.timeout = limit
            conn.connect()
            self._warn_unverified(route, exchange.key[3])
        sock = conn.sock
        assert sock is not None  # connected just above, or reused connected
        sock.settimeout(limit)

    def _warn_unverified(self, route: Route, context: ssl.SSLContext | None) -> None:
        """Issue :class:`UnverifiedTLSWarning` for a new connection that verifies nothing."""
        if not self.policy.warn_unverified or context is None:
            return
        if context.verify_mode == ssl.CERT_NONE:
            warnings.warn(
                UnverifiedTLSWarning(
                    f"unverified HTTPS connection to {route.host}:{route.port}: "
                    "the server's certificate is not checked"
                ),
                stacklevel=2,
            )

    # -- requests ----------------------------------------------------------------------

    def request(self, method: str, url: str, **options: Unpack[Options]) -> Response:
        """Send one request - redirects and retries included - and return the unread answer.

        ``url`` is absolute, its path and query already as they go on the
        wire. Whatever is returned must be read or :meth:`~Response.close`\\ d.
        A status outside ``expect`` is raised (see :class:`Options`); a
        network failure is :meth:`Errors.transport`'s error. A retry
        (:class:`RetryPolicy`) starts the chain again from ``url``: a busy
        data server is best left for whichever one the door picks next.
        """
        call = self._call(method, url, options)
        tries = 0
        while True:
            try:
                response = self._chain(call)
            except _Transport as failed:
                if not self._again(call, tries, failed.error):
                    raise self._failure(Failure(method, url, failed.error)) from failed.error
                tries += 1
                self._pause(call, tries, None)
                continue
            if not self._again(call, tries, response):
                return self._checked(call, response)
            asked = _retry.retry_after(response.headers)
            response.close()
            tries += 1
            self._pause(call, tries, asked)

    def _call(self, method: str, url: str, options: Options) -> _Call:
        """``options`` resolved against the session's defaults."""
        headers = options.get("headers") or {}
        idempotent = options.get("idempotent")
        if idempotent is None:
            idempotent = method in self.policy.retry.methods and not any(
                name.lower().startswith("if-") for name in headers
            )
        return _Call(
            method=method,
            url=url,
            headers=headers,
            body=options.get("body"),
            auth=options.get("auth") or Auth(),
            expect=options.get("expect"),
            timeout=options.get("timeout", self.policy.timeout),
            follow=options.get("follow", True),
            replayable=idempotent,
            reauth=options.get("reauth"),
            errors=options.get("errors") or self.errors,
            origin=url,
        )

    def _again(self, call: _Call, tries: int, outcome: Response | Exception) -> bool:
        """Whether ``outcome`` - an answer or a transport failure - is worth another attempt."""
        retry = self.policy.retry
        if not call.replayable or tries >= retry.retries:
            return False
        if isinstance(outcome, Response):
            wanted = call.expect is not None and outcome.status in call.expect
            return outcome.status in retry.statuses and not wanted
        return retry.transport and _transient(outcome) and not self._aborted

    def _pause(self, call: _Call, tries: int, asked: float | None) -> None:
        """Wait before attempt ``tries + 1``: ``Retry-After`` (capped), else jittered backoff."""
        retry = self.policy.retry
        if asked is not None:
            wait = min(asked, retry.cap)
        else:
            wait = _retry.delay(tries, retry.backoff, retry.cap)
        _log.debug("%s %s: attempt %d in %.2fs", call.method, redact(call.url), tries + 1, wait)
        if wait > 0:
            (retry.sleep or time.sleep)(wait)

    def _failure(self, failure: Failure) -> Exception:
        """The error a transport failure becomes: the abort it was, or the client's word for it."""
        if self._aborted:
            return self.errors.closed(True)
        return self.errors.transport(failure)

    def _checked(self, call: _Call, response: Response) -> Response:
        """``response``, unless its status is one the caller did not ask for.

        The unwanted answer's body is read (up to :data:`ERROR_BODY`) before
        it is raised, which also keeps its connection usable; a body the
        connection dies under is left empty - the status still says enough.
        """
        if call.expect is None or response.status in call.expect:
            return response
        try:
            body = response._raw.read(ERROR_BODY)
        except (OSError, http.client.HTTPException):
            body = b""
            response._reusable = False
        response.close()
        answer = Answer(
            response.method, response.url, response.status, response.reason, response.headers, body
        )
        raise call.errors.status(answer)

    # -- the redirect chain ------------------------------------------------------------

    def _chain(self, call: _Call) -> Response:
        """One attempt of the whole request: hops, redirects, a ``401`` answered once."""
        call.origin, call.reauthed = call.url, False

        def exhausted() -> Exception:
            """The error for one redirect too many."""
            limit = self.policy.redirects.limit
            return call.errors.redirect(call.method, call.url, f"more than {limit} redirects")

        return redirects(
            Request[str, Body](call.method, call.url, call.body),
            lambda request: self._hop(call, request),
            lambda request, response: self._advance(call, request, response),
            self.policy.redirects.limit,
            exhausted,
        )

    def _hop(self, call: _Call, request: Request[str, Body]) -> Response:
        """One hop: prepared, routed, sent on a pooled connection, its answer's head read.

        :func:`~xrdhttp.engine.attempt` sends it once more on a fresh
        connection when a *reused* one turns out stale (:data:`_STALE`),
        which happens before any of the answer arrived - unless the policy
        retries transport failures, which then counts it like any other
        (see :class:`RetryPolicy`).
        """
        hop = self._prepare(call, request, _framing(self.policy, request))
        route, key = self._route(call, hop)
        retry = self.policy.retry
        replay = (call.replayable or retry.replay_unanswered) and not retry.transport

        def send(exchange: _Exchange) -> Response:
            """The exchange itself, under the abort registration."""
            cancel.check(f"{hop.method} {redact(hop.url)}")
            self._ready(exchange, route, call.timeout)
            raw, reusable = _exchange(exchange.conn, hop, route.target, self.policy.continue_wait)
            return Response(self, exchange, raw, hop, reusable)

        return attempt(
            lambda: self._checkout(key),
            send,
            _Exchange.close,
            lambda exchange, error: replay and exchange.reused and isinstance(error, _STALE),
            _Transport,
        )

    def _prepare(self, call: _Call, request: Request[str, Body], framing: Mapping[str, str]) -> Hop:
        """The hop's headers: standing, credentials if still allowed, the caller's, then framing.

        ``framing`` (``Content-Length``, ``Transfer-Encoding``, ``Expect``) is
        the session's to decide and goes last but one; the caller's
        ``prepare`` hook runs last, so a signature covers every header sent.
        """
        headers = dict(self.policy.headers)
        if request.credentials:
            headers.update(call.auth.headers)
            headers.update(call.headers)
        else:
            headers.update(_policy.without_credentials(call.headers, keep_transfer=request.relay))
        headers.update(framing)
        hop = Hop(
            request.method, request.url, call.origin, headers, request.body, request.credentials
        )
        if call.auth.prepare is not None:
            call.auth.prepare(hop)
        return hop

    def _route(self, call: _Call, hop: Hop) -> tuple[Route, _Key]:
        """Where ``hop`` goes, and the pool that serves it: endpoint and TLS context.

        A URL the route refuses raises its :class:`ValueError` as it is: a
        redirect's target was already checked (:meth:`_advance`), so this is
        the caller's own URL, or one its ``prepare`` hook wrote.
        """
        route = self.policy.route(hop.url)
        context = self._context(route, hop.url, call.auth)
        return route, (route.scheme, route.host, route.port, context)

    def _advance(self, call: _Call, request: Request[str, Body], response: Response) -> str | None:
        """The next hop's URL, or ``None`` when ``response`` is the answer.

        A redirect's own body is drained and its connection pooled before the
        next hop is sent, so a chain through one door reuses one connection.
        """
        if response.status == 401 and self._reauth(call, request, response):
            return request.url
        location = response.header("Location")
        if not (call.follow and response.status in REDIRECTS and location):
            return None
        response.close()
        try:
            target = _policy.resolve_location(request.url, location)
            self.policy.route(target)  # a Location that is not HTTP stops here
            redirect = self.policy.redirects
            allowed = request.credentials and redirect.carries(call.origin, target)
            relay = request.relay and (allowed or redirect.relays(call.origin, target))
        except ValueError as exc:
            problem = f"unusable Location: {exc}"
            raise call.errors.redirect(call.method, location, problem, exc) from exc
        request.credentials, request.relay = allowed, relay
        _log.debug("%s redirected to %s", request.method, redact(target))
        return target

    def _reauth(self, call: _Call, request: Request[str, Body], response: Response) -> bool:
        """Answer a first ``401`` with new credentials, if the caller's hook has some.

        Once per attempt, so a server that rejects every credential cannot
        loop the client. The host that asked becomes the origin: it was handed
        the credential on purpose and may keep receiving it.
        """
        if call.reauth is None or call.reauthed:
            return False
        call.reauthed = True
        auth = call.reauth(request.url, response)
        if auth is None:
            return False
        response.close()
        call.auth, call.origin = auth, request.url
        request.credentials = request.relay = True
        return True

    # -- streamed uploads --------------------------------------------------------------

    def upload(
        self, method: str, url: str, length: int | None, **options: Unpack[Options]
    ) -> Upload:
        """Start a request whose body the caller then writes piecemeal.

        ``length`` is declared up front (``Content-Length``), or ``None`` for
        a chunked body of unknown length. The head goes out with ``Expect:
        100-continue``, so a redirect or a refusal is dealt with here, before
        any of the body is committed to the wrong host; a refusal is kept and
        :meth:`Upload.finish` hands it back. Of ``options``, ``body``,
        ``expect`` and ``idempotent`` do not apply: an upload's body cannot
        be sent twice, and its answer is the caller's to word.
        """
        call = self._call(method, url, options)
        request = Request[str, Body](method, url, None)
        for _ in range(self.policy.redirects.limit + 1):
            exchange, hop, early = self._start(call, request, length)
            if early is None:
                return Upload(self, exchange, hop, length)
            target = self._advance(call, request, early)
            if target is None:
                return Upload(self, exchange, hop, length, early)
            request.url = target
        limit = self.policy.redirects.limit
        raise call.errors.redirect(method, url, f"more than {limit} redirects")

    def _start(
        self, call: _Call, request: Request[str, Body], length: int | None
    ) -> tuple[_Exchange, Hop, Response | None]:
        """Send an upload's head: the exchange, the hop, and the server's answer if it gave one.

        ``None`` means go ahead and write the body. An empty upload has no
        body to wait for, so its answer is read at once. A stale reused
        connection is replaced as for :meth:`_hop`: nothing was sent yet.
        """
        hop = self._prepare(call, request, _upload_framing(length))
        route, key = self._route(call, hop)

        def send(exchange: _Exchange) -> tuple[_Exchange, Hop, Response | None]:
            """The head, then the ``100-continue`` wait (or the answer, for an empty body)."""
            cancel.check(f"{hop.method} {redact(hop.url)}")
            self._ready(exchange, route, call.timeout)
            conn = exchange.conn
            _send_head(conn, hop, route.target)
            if length == 0:
                return exchange, hop, Response(self, exchange, conn.getresponse(), hop)
            try:
                _expect.await_continue(conn, hop.method, self.policy.continue_wait)
            except _expect.InterimAnswer as answered:
                return exchange, hop, Response(self, exchange, answered.response, hop, False)
            return exchange, hop, None

        try:
            return attempt(
                lambda: self._checkout(key),
                send,
                _Exchange.close,
                lambda exchange, error: exchange.reused and isinstance(error, _STALE),
                _Transport,
            )
        except _Transport as failed:
            raise self._failure(Failure(call.method, hop.url, failed.error)) from failed.error


def _framing(policy: Policy, request: Request[str, Body]) -> dict[str, str]:
    """A whole-body request's framing: its length, and ``Expect`` where the policy asks."""
    length = body_length(request.body)
    if length is None:
        return {}
    framing = {"Content-Length": str(length)}
    if policy.expects(request.method, length):
        framing["Expect"] = "100-continue"
    return framing


def _upload_framing(length: int | None) -> dict[str, str]:
    """A streamed upload's framing: declared or chunked, and ``Expect`` unless it is empty.

    An upload always asks first when it has a body: the caller cannot replay
    a body it streams, so a redirect must come before any of it is sent.
    """
    if length is None:
        return {"Transfer-Encoding": "chunked", "Expect": "100-continue"}
    if length == 0:
        return {"Content-Length": "0"}
    return {"Content-Length": str(length), "Expect": "100-continue"}


def _transient(error: Exception) -> bool:
    """Whether a transport failure may pass on a retry with backoff.

    A timeout, a refused TLS handshake and a short local file fail the same
    way again; a refused or dropped connection may not.
    """
    if isinstance(error, TimeoutError | ShortFileError):
        return False
    return not isinstance(error, ssl.SSLError) or isinstance(error, _TLS_DROPS)


class Upload:
    """A request in flight whose body the caller writes: :meth:`write`, then :meth:`finish`.

    What a streamed ``PUT`` (gfal2's ``open(O_WRONLY)``, an XRootD-style
    chunked write) goes through. With a declared length, writing past it is
    a :class:`ValueError`; without one the body is chunked. Not thread-safe:
    one writer at a time, as with any file handle.
    """

    def __init__(
        self,
        session: Session,
        exchange: _Exchange,
        hop: Hop,
        length: int | None,
        early: Response | None = None,
    ) -> None:
        """Own ``exchange`` (the head already sent); ``early`` is an answer that came first.

        An upload that starts with an ``early`` answer (a refusal of the
        ``100-continue``) is ``done`` from the start: :meth:`write` drops
        data and :meth:`finish` hands that answer back.
        """
        self._session = session
        self._exchange = exchange
        self._hop = hop
        self.url = hop.url
        self.length = length
        self.sent = 0
        self.early = early
        self.done = early is not None

    def write(self, data: bytes | bytearray | memoryview) -> None:
        """Send the next part of the body.

        A server that hangs up mid-body usually said why first (a quota, a
        permission): that answer is kept for :meth:`finish` and later writes
        are dropped, so the caller sees the server's status rather than
        ``EPIPE``. Any other failure abandons the upload.
        """
        if self.early is not None:
            return  # the server has answered already; finish() reports it
        if self.done:
            raise ValueError("write to an upload that was finished or aborted")
        size = memoryview(data).nbytes
        if self.length is not None and self.sent + size > self.length:
            raise ValueError(f"writing past the declared {self.length} bytes of the upload")
        if not size:
            return  # an empty chunk would end a chunked body
        try:
            self._send(data, size)
        except (BrokenPipeError, ConnectionResetError) as exc:
            self._answered(exc)
            return
        except OSError as exc:
            self.abort()
            raise self._failure(exc) from exc
        self.sent += size

    def _send(self, data: bytes | bytearray | memoryview, size: int) -> None:
        """``data`` on the wire, framed as a chunk when the length was not declared."""
        conn = self._exchange.conn
        if self.length is None:
            conn.send(f"{size:x}\r\n".encode("ascii"))
            conn.send(data)
            conn.send(b"\r\n")
        else:
            conn.send(data)

    def _answered(self, exc: OSError) -> None:
        """Keep the answer of a server that hung up mid-body, or raise if it sent none."""
        try:
            raw = self._exchange.conn.getresponse()
        except (OSError, http.client.HTTPException):
            self.done = True
            self._exchange.close()
            raise self._failure(exc) from exc
        self.early = Response(self._session, self._exchange, raw, self._hop, False)

    def _failure(self, exc: Exception) -> Exception:
        """The session's error for a failure of this upload."""
        return self._session._failure(Failure(self._hop.method, self.url, exc))

    def finish(self) -> Response:
        """The server's answer, once the whole body has gone (the unread :class:`Response`).

        Finishing a declared-length upload short of its length is a
        :class:`ValueError`, and the connection is dropped: the server would
        otherwise wait for the rest.
        """
        if self.early is not None:
            return self.early
        self.done = True
        if self.length is not None and self.sent != self.length:
            self._exchange.close()
            raise ValueError(f"upload finished after {self.sent} of {self.length} bytes")
        conn = self._exchange.conn
        try:
            if self.length is None:
                conn.send(b"0\r\n\r\n")
            raw = conn.getresponse()
        except (OSError, http.client.HTTPException) as exc:
            self._exchange.close()
            raise self._failure(exc) from exc
        return Response(self._session, self._exchange, raw, self._hop)

    def abort(self) -> None:
        """Drop the connection, which is how an HTTP upload is abandoned; idempotent."""
        self.done = True
        if self.early is not None:
            self.early.close()
        else:
            self._exchange.close()
