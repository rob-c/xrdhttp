"""The fake storage element a test drives: state, switches, records and lifecycle.

:class:`StorageServer` is the object a test holds. Every switch is a plain
public attribute read per request, so a test can change the server's
behaviour between two calls of a client - the first attempt redirected,
the second served. The request handling lives in the handler modules
(:mod:`._front` and the dialect mixins), which reach this object through
their listener's fake (:attr:`_Backend.app`); nothing here knows how a verb
is answered.

The wire plumbing is xrdsec's generic test server,
:class:`xrdsec.testing.https.FakeHTTPSServer`, with this package's request
handler as its :attr:`~xrdsec.testing.https.FakeHTTPSServer.handler_class`:
TLS applied per connection from the :class:`ssl.SSLContext` the caller
supplies (this package mints no certificates), the client's certificate
chain (:class:`~xrdsec.testing.https.PeerIdentity`), the request log, the
fault queue, connection tracking and a bounded, joined ``stop``. That
server binds when it is made, so one is made on first use and again after
every :meth:`StorageServer.stop`: the port is bound when the address is
first needed (``port=0`` lets the kernel choose, so a suite's parallel
workers never collide), the records outlive a restart, and a stopped
server remembers where it was.

The two clients this fake was built from disagree about what a storage
element does in a dozen corners, because the servers they meet do too: see
:data:`STYLES` for the switches each style sets, and the switch comments
below for what each models.
"""

from __future__ import annotations

import re
import ssl
import threading
from typing import Any, Self

from xrdsec.testing.https import FakeHTTPSServer, Fault, Request

from ._front import RequestHandler
from ._model import S3, DelegationService, Handler, Swift, Tape, clean
from ._store import MemoryStore, Store

#: The switches that differ between the two client styles, as attribute -> value.
#: ``"xrdcl"`` is the default: what XrdCl and xrdclient meet at dCache, EOS,
#: StoRM and XrdHttp, closest to the RFCs. ``"davix"`` is what davix and
#: gfal2 (so xgfalclient) are tested against: grid-flavoured WebDAV (no
#: recursive ``DELETE``, a 4096-byte collection length, ``403`` for a
#: collection ``GET``), every offered digest at once, authorisation and
#: faults decided before ``100 Continue``, one performance marker, and a
#: ``403`` where there is no tape.
STYLES: dict[str, dict[str, Any]] = {
    "xrdcl": {},
    "davix": {
        "recursive_delete": False,
        "collection_length": 4096,
        "collection_get_status": 403,
        "digest_all": True,
        "digests": {"adler32", "md5", "crc32c", "sha256", "crc32"},
        "check_before_continue": True,
        "drain_refused": False,
        "tpc_markers": 1,
        "marker_every": 1 << 20,
        "tape_absent_status": 403,
        "tape_endpoint": "/api/v1/",
        "missing_archive_entry": {"error": "USER ERROR: file not found"},
        "release_unknown": True,
    },
}

#: Every algorithm the fake can answer a digest request with.
ALL_DIGESTS = frozenset(
    {
        *("adler", "adler32", "crc32", "crc32c", "crc64", "md5"),
        *("sha", "sha-256", "sha256", "sha-512", "sha512"),
    }
)


class StorageServer:
    """An HTTP(S) storage element on loopback: WebDAV, TPC, tape, S3, Swift, GCS.

    ``store`` holds what is served (an empty :class:`~xrdhttp.testing.MemoryStore`
    by default); ``tls`` makes it HTTPS - pass a context that requests a
    client certificate to see it in :attr:`Request.peer
    <xrdsec.testing.https.Request.peer>`. ``style``
    picks a column of :data:`STYLES`. Records (:attr:`requests`,
    :attr:`faults`, ...) are guarded by an internal lock because handler
    threads append to them concurrently; read them after the client call
    being checked has returned.
    """

    def __init__(
        self,
        store: Store | None = None,
        *,
        tls: ssl.SSLContext | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
        style: str = "xrdcl",
        name: str = "xrdhttp-fake-storage",
    ) -> None:
        """Hold ``store``; nothing is bound until the address is first needed."""
        #: What is served.
        self.store: Store = store if store is not None else MemoryStore()
        #: A server-side context makes this an ``https`` endpoint; each
        #: connection is wrapped in it as it is accepted.
        self.tls = tls
        #: The ``Server`` header and the threads' name.
        self.name = name
        #: How long :meth:`stop` waits, in all, for connection threads to end
        #: after hanging up on them; ``None`` does not wait.
        self.join_timeout: float | None = 10.0
        self._wanted = (host, port)
        self._last: tuple[str, int] | None = None
        self._backend: _Backend | None = None
        self._lock = threading.RLock()
        self._delegation = threading.Event()
        self._records()
        self._switches()
        self._dialects()
        for attribute, value in STYLES[style].items():
            setattr(self, attribute, set(value) if isinstance(value, set) else value)

    def _records(self) -> None:
        """What the server writes down as it serves."""
        #: Every request received, in arrival order (see
        #: :class:`~xrdsec.testing.https.Request`; ``target`` is the wire form).
        self.requests: list[Request] = []
        #: Queued faults, consumed by matching requests (see :meth:`fault` and
        #: :class:`~xrdsec.testing.https.Fault`).
        self.faults: list[Fault] = []
        #: Connections accepted (after a TLS handshake), for keep-alive and reuse tests.
        self.connections = 0
        #: The certificate each TLS client presented, as DER (``b""`` for none),
        #: in the order the connections were accepted.
        self.peer_certificates: list[bytes] = []
        #: The headers of every ``COPY`` served, in order.
        self.copies: list[dict[str, str]] = []
        #: Every token issued (macaroons and OAuth), with what was asked for it.
        self.macaroons: list[dict[str, Any]] = []
        #: Delegation id -> the credential a client put back (see :meth:`accept_delegation`).
        self.delegated: dict[str, Any] = {}

    def _switches(self) -> None:
        """The behaviour switches, at their ``"xrdcl"`` values."""
        #: Method -> :data:`Handler`, for an answer the fake would never give.
        self.handlers: dict[str, Handler] = {}
        # -- authorisation -------------------------------------------------------------
        #: Tokens accepted as ``Authorization: Bearer``; empty accepts anything.
        #: A macaroon or OAuth token this server issued is accepted too, and so
        #: is a client certificate with no ``Authorization`` at all.
        self.tokens: set[str] = set()
        #: ``(user, password)`` for Basic auth, when set.
        self.basic: tuple[str, str] | None = None
        # -- redirects -----------------------------------------------------------------
        #: Path -> ``Location``: a 307 for the next request on that path, once.
        self.redirects: dict[str, str] = {}
        #: Target prefix -> base URL: every request under it is answered with a
        #: 307 to the base plus the request target, for as long as it is set.
        self.redirect_prefixes: dict[str, str] = {}
        #: Answer a redirect as soon as the headers are in and hang up without
        #: reading the body, as EOS's head node does with a ``PUT``.
        self.early_redirects = False
        # -- Expect: 100-continue ------------------------------------------------------
        #: Honour ``Expect: 100-continue``. ``False`` is a server that ignores
        #: the expectation, which HTTP allows: the client must time out and send.
        self.expect_continue = True
        #: Decide faults, hooks, authorisation and redirects *before* sending
        #: ``100 Continue``, so a refused upload is answered instead of the
        #: interim reply - what clients rely on to avoid uploading into a 401.
        self.check_before_continue = False
        #: Read and drop the body of a request answered early (refused,
        #: redirected, faulted), keeping the connection; ``False`` closes it.
        self.drain_refused = True
        # -- WebDAV --------------------------------------------------------------------
        #: Refuse ``PROPFIND``, the way a plain HTTP server would.
        self.no_dav = False
        #: ``DELETE`` of a non-empty collection removes it all (RFC 4918);
        #: ``False`` answers 409, as grid servers do to keep ``rmdir`` POSIX.
        self.recursive_delete = True
        #: ``MKCOL`` makes missing parents (as XrdHttp does) rather than answering 409.
        self.mkcol_parents = False
        #: ``getcontentlength`` reported for a collection (dCache and XrdHttp say
        #: 4096); ``None`` leaves it out.
        self.collection_length: int | None = None
        #: The status of a ``GET`` on a collection: 200 with an empty page, as
        #: most servers answer a browser, or 403 (there, but not a file).
        self.collection_get_status = 200
        #: Path -> Metalink descriptor URL, advertised in a ``Link`` header on
        #: ``HEAD``/``GET`` of that path (which need not exist as a file).
        self.metalinks: dict[str, str] = {}
        # -- ranges and bodies -----------------------------------------------------------
        #: Answer a ranged ``GET`` with the whole body, as some caches do.
        self.ignore_ranges = False
        #: Answer several ranges as ``multipart/byteranges``; ``False`` serves only the first.
        self.multipart_ranges = True
        #: Answer several ranges with one part spanning all of them (RFC 9110 allows it).
        self.coalesce_ranges = False
        #: Promise the full ``Content-Length`` on a ``GET`` but send only this
        #: many bytes and drop the connection - a server dying mid-reply.
        self.truncate_at: int | None = None
        #: Request bodies up to this size are kept in :attr:`Request.body`.
        self.body_record_limit = 1 << 20
        # -- digests -------------------------------------------------------------------
        #: Algorithms offered for ``Want-Digest``/``Want-Repr-Digest`` (their HTTP names).
        self.digests: set[str] = set(ALL_DIGESTS)
        #: Answer RFC 3230 ``Want-Digest`` with ``Digest``.
        self.legacy_digests = True
        #: Answer RFC 9530 ``Want-Repr-Digest`` with ``Repr-Digest``.
        self.repr_digests = True
        #: Answer every offered algorithm the client asked for, in its order (as
        #: XrdHttp does), rather than only the first.
        self.digest_all = False
        #: ``False`` offers digests on ``GET`` only, as servers that checksum
        #: while streaming do.
        self.digest_on_head = True
        # -- third-party copy ----------------------------------------------------------
        #: Refuse ``COPY`` (501), the way an endpoint without third-party copy would.
        self.no_tpc = False
        #: ``"normal"``; ``"xrootd"`` answers ``COPY`` with a bare 200 ``OK`` and
        #: hangs up (XrdHttp without TPC); ``"eof"`` sends the markers, then no outcome.
        self.tpc = "normal"
        #: Report this in the ``failure:`` line instead of doing the transfer.
        self.tpc_failure: str | None = None
        #: How many performance markers a ``COPY`` sends before the outcome.
        self.tpc_markers = 2
        #: Seconds to wait before each marker and the outcome of a ``COPY``.
        self.tpc_marker_gap = 0.0
        #: Stream a marker per this many bytes while a pull is under way,
        #: instead of the :attr:`tpc_markers` after it; a push still sends those.
        self.marker_every: int | None = None
        #: TLS context for the fake's own outbound ``COPY`` connections.
        self.client_tls: ssl.SSLContext | None = None
        #: Ask for a delegated proxy on ``COPY`` when the client allows it.
        self.delegation = False
        #: How long a ``COPY`` waits for the delegated proxy to arrive.
        self.delegation_timeout = 10.0
        # -- tokens --------------------------------------------------------------------
        #: The macaroon every request mints; ``None`` mints a fresh one each time.
        self.macaroon: str | None = None
        #: Advertise an OAuth token endpoint at ``/token``.
        self.oauth = False
        #: Advertise this ``token_endpoint`` instead of our own ``/token``.
        self.oauth_endpoint: str | None = None

    def _dialects(self) -> None:
        """The optional protocols, all off."""
        #: Serve the WLCG Tape REST API with this state (``None``: no tape).
        self.tape: Tape | None = None
        #: The status of a tape request when :attr:`tape` is ``None``.
        self.tape_absent_status = 404
        #: The endpoint path the discovery document advertises (the API is
        #: served under ``/api/v1`` however it is spelt).
        self.tape_endpoint = "/api/v1"
        #: What ``archiveinfo`` says of a file that does not exist, besides its path.
        self.missing_archive_entry: dict[str, str] = {"locality": "LOST", "error": "no such file"}
        #: Record a release of a request id never issued (or withdrawn), as
        #: gfal2's placeholder id needs, rather than answering 404.
        self.release_unknown = False
        #: CDMI QoS state: path -> ``{"capabilitiesURI": ..., "metadata": ...}``.
        self.qos: dict[str, dict[str, Any]] = {}
        #: Speak S3 (or GCS) instead of WebDAV for data paths.
        self.s3: S3 | None = None
        #: Refuse a header-signed S3 upload whose body is not the one its
        #: ``x-amz-content-sha256`` names, as S3 does (in both styles).
        self.verify_payload = True
        #: Speak Swift instead of WebDAV for data paths.
        self.swift: Swift | None = None
        #: The gridsite delegation endpoint, when a client's preset supplies one.
        self.delegation_service: DelegationService | None = None

    # -- contents ------------------------------------------------------------------------

    def add_dir(self, path: str) -> None:
        """Create a collection and every missing parent of it."""
        self.store.mkdir(clean(path))

    def add_file(self, path: str, data: bytes = b"") -> None:
        """Create or replace a file, creating its parent collections - as a ``PUT`` here does."""
        self.store.write(clean(path), [bytes(data)])

    def contents(self, path: str) -> bytes:
        """What the server holds at ``path``; ``KeyError`` if no file is there."""
        target = clean(path)
        found = self.store.entry(target)
        if found is None or found.collection:
            raise KeyError(path)
        with self.store.open(target) as handle:
            return handle.read()

    # -- addresses -----------------------------------------------------------------------

    @property
    def _https(self) -> _Backend:
        """The generic server underneath, made (and so bound) on first use.

        It shares this object's request log and fault queue, so they outlive
        a stop and a fresh start.
        """
        if self._backend is None:
            host, port = self._wanted
            backend = _Backend(tls=self.tls, host=host, port=port, name=self.name)
            backend.app = self
            backend.requests = self.requests
            backend.faults = self.faults
            self._backend = backend
        return self._backend

    @property
    def address(self) -> tuple[str, int]:
        """Where the server listens - or, after :meth:`stop`, where it last did.

        Reading it before :meth:`start` binds the port, so a test can build a
        URL first and serve second.
        """
        if self._backend is None and self._last is not None:
            return self._last
        return self._https.address

    @property
    def host(self) -> str:
        """The listening host."""
        return self.address[0]

    @property
    def port(self) -> int:
        """The listening port."""
        return self.address[1]

    @property
    def scheme(self) -> str:
        """The wire scheme: ``https`` under TLS, else ``http``."""
        return "https" if self.tls is not None else "http"

    @property
    def base(self) -> str:
        """``scheme://host:port`` - the origin the server names in redirects and documents."""
        host, port = self.address
        return f"{self.scheme}://{host}:{port}"

    # -- lifecycle -----------------------------------------------------------------------

    def start(self) -> Self:
        """Serve in a background thread. Idempotent; a stopped server binds a fresh port."""
        self._https.start()
        return self

    def stop(self) -> None:
        """Stop listening and hang up on every open connection, as a dead server would.

        Then wait up to :attr:`join_timeout` for the connection threads, so a
        handler still writing its reply finishes before the test moves on.
        Idempotent; a server that was never bound has nothing to release.
        """
        backend = self._backend
        if backend is None:
            return
        self._last = backend.address
        backend.join_timeout = self.join_timeout
        backend.stop()
        self._backend = None

    def __enter__(self) -> Self:
        """Start serving; the ``with`` block is the server's lifetime."""
        return self.start()

    def __exit__(self, *exc: object) -> None:
        """Stop and release the port, whether or not the block raised."""
        self.stop()

    def __repr__(self) -> str:
        """Where it listens and how much it has seen; never binds a port to say so."""
        return f"{type(self).__name__}({self._where()}, requests={len(self.requests)})"

    def _where(self) -> str:
        """``host:port`` where it listens (or last did), ``unbound`` if it never has."""
        bound = self._backend.address if self._backend is not None else self._last
        return f"{bound[0]}:{bound[1]}" if bound else "unbound"

    # -- test hooks ----------------------------------------------------------------------

    def fault(self, method: str | None = None, path: str | None = None, **kwargs: Any) -> Fault:
        """Queue a :class:`~xrdsec.testing.https.Fault` for ``method`` on targets starting ``path``.

        ``kwargs`` are the fault's fields (``status``, ``body``, ``drop``,
        ``delay``, ``truncate``, ``stall``, ``hold``, ``times``, ...), except
        that ``status`` defaults to none - the real answer, delayed, stalled,
        truncated or held as asked - rather than 500. The fault is returned so
        a test can inspect ``times`` afterwards to see whether it was used up.
        """
        pattern = None if path is None else "^" + re.escape(path)
        found = Fault(method, pattern, **{"status": None, **kwargs})
        with self._lock:
            self.faults.append(found)
        return found

    def methods(self) -> list[str]:
        """The methods of every request so far, in order - the usual thing a test asserts."""
        with self._lock:
            return [request.method for request in self.requests]

    def clear(self) -> None:
        """Forget the recorded requests, e.g. after a test's setup traffic."""
        with self._lock:
            self.requests.clear()

    def accept_delegation(self, delegation_id: str, credential: Any) -> None:
        """Record a delegated credential and wake the ``COPY`` waiting for it.

        Called by a :data:`~xrdhttp.testing.DelegationService` once a
        client's proxy has checked out.
        """
        self.delegated[delegation_id] = credential
        self._delegation.set()

    # -- what the handler threads call ---------------------------------------------------

    def _take_redirect(self, path: str) -> str | None:
        """The one-shot redirect for ``path``, consumed, so the retry gets the real answer."""
        with self._lock:
            return self.redirects.pop(path, None)

    def _connected(self, connection: Any) -> None:
        """Count a new connection, recording a TLS client's certificate."""
        with self._lock:
            self.connections += 1
            if self.tls is not None:
                self.peer_certificates.append(connection.getpeercert(binary_form=True) or b"")

    def _delegation_wait(self, timeout: float) -> bool:
        """Block until a delegated proxy arrives (``True``) or ``timeout`` passes."""
        return self._delegation.wait(timeout)

    def _delegation_reset(self) -> None:
        """Forget an earlier delegation, before a ``COPY`` asks for a new one."""
        self._delegation.clear()


class _Backend(FakeHTTPSServer):
    """xrdsec's generic server, answering with this package's handler, for one :attr:`app`."""

    handler_class = RequestHandler
    #: The storage element whose state the handler reads.
    app: StorageServer

    def opened(self, connection: Any) -> None:
        """Count the connection for :attr:`app` (and record a TLS client's certificate)."""
        self.app._connected(connection)
