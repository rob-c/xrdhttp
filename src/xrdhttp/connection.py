"""Standard-library HTTP connections with the clients' streaming response contract.

Connection establishment, socket options and TLS are :mod:`http.client`'s
own: a TCP connect bounded by the connection's ``timeout``, ``TCP_NODELAY``,
and - for HTTPS - :meth:`ssl.SSLContext.wrap_socket` with the endpoint's name
as ``server_hostname``, so SNI is sent and the context's ``check_hostname``
is what verifies the certificate names the host. Everything a client needs
on top (pooling, one retry on a stale connection, redirects, ``Expect:
100-continue``) is :mod:`xrdhttp.session`'s, so nothing here depends on
another HTTP library's internals.

What these classes add to the stdlib's: every connect failure surfaces as an
:class:`OSError` (the one exception the session retries and wraps), a
``request`` with ``headers=None`` means "no extra headers", and
:attr:`HTTPConnection.is_connected` answers the liveness poll a pool makes
before reusing a connection (:class:`xrdhttp.wire.IdlePool`). TLS is the
``ssl_context`` the caller built - nothing else configures it. The
positional order of the constructor parameters is :mod:`http.client`'s, so
it may not be reordered.

Cancellation is :mod:`xrdcore.cancel`'s: a request made inside a cancelled
scope is refused before a byte is written, whichever client started it.

This is also where the chain names :mod:`http.client`. The clients' lint
bans that module (HTTP is xrdhttp's to speak), so the stdlib types a
client still has to name - the response and header types a
:class:`~xrdhttp.session.Answer` carries, and the exceptions a
:class:`~xrdhttp.session.Failure` may hold (:class:`IncompleteRead` for a
body cut short, :class:`RemoteDisconnected` and :class:`BadStatusLine` for a
connection that died or spoke nonsense, :class:`HTTPException` for any of
them) - are re-exported from here. They *are* the stdlib's classes, not
copies: an ``except`` or ``isinstance`` against either name means the same.
"""

from __future__ import annotations

import errno
import http.client
import selectors
import socket
import ssl
from collections.abc import Callable

# The stdlib vocabulary a client names, re-exported (see the module docstring).
from http.client import BadStatusLine as BadStatusLine
from http.client import HTTPException as HTTPException
from http.client import HTTPMessage as HTTPMessage
from http.client import HTTPResponse as HTTPResponse
from http.client import IncompleteRead as IncompleteRead
from http.client import RemoteDisconnected as RemoteDisconnected
from typing import Any, cast

from xrdcore import cancel

__all__ = [
    "BLOCKSIZE",
    "BadStatusLine",
    "HTTPConnection",
    "HTTPException",
    "HTTPMessage",
    "HTTPResponse",
    "HTTPSConnection",
    "IncompleteRead",
    "RemoteDisconnected",
]

#: How much of a file-like request body is read per ``send``. Larger than the
#: stdlib's 8 KiB, so an upload is fewer system calls.
BLOCKSIZE = 16 * 1024

#: The stdlib's "no timeout given" sentinel, which :mod:`http.client` and
#: :func:`socket.create_connection` take as their default. It is private to
#: :mod:`socket` and typeshed does not declare it, so it is read from the
#: module's namespace rather than as an attribute (and typed as the
#: timeout parameter it is the default of).
_DEFAULT_TIMEOUT: float | None = vars(socket)["_GLOBAL_DEFAULT_TIMEOUT"]


def _connect(connect: Callable[[], None]) -> None:
    """Run ``connect``, so that whatever it raises is an :class:`OSError`.

    The request engine retries and wraps :class:`OSError` and nothing else.
    The stdlib raises one for every network failure, but not for a host name
    that cannot be encoded at all (IDNA's ``UnicodeError``), and a wrapped
    connector may raise its own exception types: one with an :class:`OSError`
    behind it becomes that error, keeping its ``errno``; anything else is
    ``EIO``.
    """
    try:
        connect()
    except OSError:
        raise
    except Exception as exc:
        if isinstance(exc.__cause__, OSError):
            raise exc.__cause__ from exc
        raise OSError(errno.EIO, str(exc)) from exc


class _ResponseCompatibility:
    """The :mod:`http.client` request contract, with ``headers=None`` allowed.

    A mixin so that the plain and TLS classes share one definition; it must
    stay first in their bases so that its ``request`` wins over the stdlib's.
    """

    def request(
        self,
        method: str,
        url: str,
        body: Any = None,
        headers: Any = None,
        *,
        encode_chunked: bool = False,
    ) -> None:
        """Send one request, as :meth:`http.client.HTTPConnection.request` does.

        Two differences: ``headers=None`` means "no extra headers", as
        every other optional argument's ``None`` does, and a caller whose
        :class:`~xrdcore.cancel.CancelScope` is cancelled is refused before a
        byte is written.
        """
        # A cancelled caller sends nothing more; one request already sent
        # runs to its answer or its timeout, since stopping it part-way would
        # cost the connection (see xrdcore.cancel).
        cancel.check(f"{method} {url}")
        http.client.HTTPConnection.request(
            cast("http.client.HTTPConnection", self),
            method,
            url,
            body,
            headers or {},
            encode_chunked=encode_chunked,
        )

    def getresponse(self) -> http.client.HTTPResponse:
        """The stdlib's own ``getresponse``, unchanged.

        Present so that the mixin states the whole request/response pair it
        promises; it adds no behaviour to :mod:`http.client`'s.
        """
        return http.client.HTTPConnection.getresponse(cast("http.client.HTTPConnection", self))


class _Liveness:
    """``is_connected``, which a pool asks of a connection before it reuses it."""

    sock: socket.socket | None

    @property
    def is_connected(self) -> bool:
        """Open, and with nothing waiting to be read.

        An idle keep-alive connection has nothing to say; one that is
        readable has either been closed by the server (EOF is readable) or
        holds bytes nobody asked for, and is unusable either way.
        """
        sock = self.sock
        if sock is None:
            return False
        with selectors.DefaultSelector() as selector:
            selector.register(sock, selectors.EVENT_READ)
            return not selector.select(0)


class HTTPConnection(_ResponseCompatibility, _Liveness, http.client.HTTPConnection):
    """A plain-text connection; see the module documentation."""

    def __init__(
        self,
        host: str,
        port: int | None = None,
        timeout: float | None = _DEFAULT_TIMEOUT,
        source_address: tuple[str, int] | None = None,
        blocksize: int = BLOCKSIZE,
    ) -> None:
        """The stdlib connection, with a larger default ``blocksize``.

        Nothing is connected here: :mod:`http.client` connects lazily, on
        the first request or an explicit :meth:`connect`.
        """
        super().__init__(
            host, port, timeout=timeout, source_address=source_address, blocksize=blocksize
        )

    def connect(self) -> None:
        """Open the TCP connection; any failure surfaces as :class:`OSError`."""
        _connect(super().connect)


class HTTPSConnection(_ResponseCompatibility, _Liveness, http.client.HTTPSConnection):
    """A TLS connection, verified by ``ssl_context`` (or the stdlib default).

    ``ssl_context`` names the one context every handshake on this connection
    uses (:mod:`http.client` calls it ``context``).
    """

    def __init__(
        self,
        host: str,
        port: int | None = None,
        timeout: float | None = _DEFAULT_TIMEOUT,
        source_address: tuple[str, int] | None = None,
        blocksize: int = BLOCKSIZE,
        *,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        """The stdlib TLS connection, handshaking with ``ssl_context``.

        Six parameters because the first five are :mod:`http.client`'s, in
        its order. ``None`` falls back to :func:`ssl.create_default_context`,
        which verifies against the system CAs only: grid callers always pass
        a context built from the grid's trust anchors (xrdsec builds one).
        """
        super().__init__(
            host,
            port,
            timeout=timeout,
            source_address=source_address,
            context=ssl_context,
            blocksize=blocksize,
        )

    def connect(self) -> None:
        """Connect and handshake; any failure surfaces as :class:`OSError`.

        An :class:`ssl.SSLError` (a certificate that fails verification
        included) is already an :class:`OSError`, so it reaches the request
        engine unchanged and is reported, like a refused connection, as
        whatever the client's ``wrap`` callback makes of it (see
        :func:`xrdhttp.engine.attempt`).
        """
        _connect(super().connect)
