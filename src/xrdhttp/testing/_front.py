"""The request handler: the front every request passes, then routing to a dialect.

:class:`RequestHandler` is the class the listener instantiates per
connection. Its own methods are the front of every request, in this order:

1. reset per keep-alive request, and answer ``Expect: 100-continue``;
2. record it in :attr:`~xrdhttp.testing.StorageServer.requests`;
3. apply the next matching :class:`~xrdhttp.testing.Fault`;
4. a canned answer from :attr:`~xrdhttp.testing.StorageServer.handlers`;
5. authorisation - a Swift token, an S3/GCS signature, bearer tokens (or a
   client certificate), Basic;
6. redirects - one-shot, then by prefix;

and :meth:`RequestHandler._route` hands what survives to the mixin that
speaks it. The order is part of the contract tests rely on: a fault fails
a request that would otherwise be refused or redirected, and a server
authenticates before it redirects, as a dCache door does.

The front runs at most once per request but may run early: with
:attr:`~xrdhttp.testing.StorageServer.check_before_continue` a request with
``Expect: 100-continue`` passes it in :meth:`RequestHandler.handle_expect_100`,
before the client has sent its body, so a refusal is answered instead of
the ``100 Continue``. Otherwise ``100`` goes first and the front runs once
the body is in, as most servers do.

A small body (up to 1 MiB) is read before the front answers early:
hanging up on unread data makes the client's kernel discard that answer.
The one exception is an early redirect, whose whole point is to hang up
on a client that is still sending.
"""

from __future__ import annotations

import base64
import time

from xrdsec.testing.https import Fault, hold

from ._base import HandlerBase
from ._dav import DAVMixin
from ._objects import ObjectStoreMixin
from ._tape import TapeMixin
from ._tokens import TokenMixin
from ._tpc import TPCMixin

#: The largest body read ahead of an early answer.
_PREFETCH = 1 << 20


class RequestHandler(DAVMixin, TPCMixin, TokenMixin, TapeMixin, ObjectStoreMixin, HandlerBase):
    """One connection's handler: the front, with every dialect mixed in."""

    def parse_request(self) -> bool:
        """Reset the per-request state, then let :mod:`http.server` parse the request line."""
        self._checked = False
        self._prefetched = None
        self._consumed = False
        self._fault = None
        return super().parse_request()

    def handle_expect_100(self) -> bool:
        """Answer ``Expect: 100-continue``; ``False`` means the request is already answered.

        :class:`http.server.BaseHTTPRequestHandler` calls this before the
        method handler and skips it on ``False``. The interim reply carries
        a header, as XrdHttp sends it, because a client must skip those too.
        """
        app = self.app
        if app.check_before_continue and self._front():
            return False
        if app.early_redirects and app.redirects.get(self.target):
            return True  # the front answers before the body is read
        if app.expect_continue:
            self.send_response_only(100)
            self.send_header("Server", app.name)
            self.end_headers()
        return True

    def _dispatch(self) -> None:
        """Every method's entry point: the front (unless it ran already), then route.

        A body the handler did not read makes the connection close after
        the reply: the unread bytes would otherwise be parsed as the next
        request on the keep-alive connection.
        """
        if not self._checked:
            length = int(self.headers.get("Content-Length") or 0)
            if 0 < length <= _PREFETCH and not self._hangs_up():
                self._prefetched = self.rfile.read(length)
            if self._front():
                return
        self._route()
        if self._has_body() and not self._consumed:
            self.close_connection = True

    def _hangs_up(self) -> bool:
        """Whether an early redirect is about to answer this request unread."""
        return self.app.early_redirects and bool(self.app.redirects.get(self.target))

    def _front(self) -> bool:
        """Record the request, then the rest of the front; ``True`` if it answered."""
        self._checked = True
        fake = self.server.fake
        self._record = fake.record(self.command, self.path, self.headers, b"", self)
        answered = self._intercept()
        if answered and self._has_body() and not self._consumed:
            self.close_connection = True
        return answered

    def _intercept(self) -> bool:
        """Faults, the canned hook, authorisation, redirects, in order; ``True`` if answered."""
        found = self.server.fake.take_fault(self._record)
        if found is not None and self._faulted(found):
            return True
        hook = self.app.handlers.get(self.command)
        canned = hook(self.command, self.target, dict(self.headers.items())) if hook else None
        if canned is not None:
            self._settle_body()
            self._reply(*canned)
            return True
        return self._refused() or self._redirected()

    # -- faults ------------------------------------------------------------------------------

    def _faulted(self, found: Fault) -> bool:
        """Act out ``found`` (:class:`~xrdsec.testing.https.Fault`); ``True`` if it answered.

        The generic server's order: ``delay``; ``drop`` hangs up; ``hold``
        without ``truncate`` goes silent; a ``status`` replaces the real
        answer. Otherwise the real answer is given, with the fault's
        ``stall``, ``truncate`` and ``hold`` applied to it (see
        :meth:`~._base.HandlerBase._reply`). Hang-ups shut the socket down
        rather than just closing it, so the client sees them at once.
        """
        time.sleep(found.delay)
        self._fault = found
        if found.drop:
            self._hang_up()
        elif found.hold and found.truncate is None:
            hold(self.connection, found.hold)
            self._hang_up()
        elif found.status is not None:
            self._settle_body()
            self._reply(found.status, found.body, dict(found.headers), reason=found.reason)
        else:
            return False
        return True

    # -- authorisation -----------------------------------------------------------------------

    def _refused(self) -> bool:
        """Check the credentials the configured dialect wants; ``True`` if refused.

        Exactly one scheme applies, in this precedence: a Swift token, an S3
        (or GCS) signature, bearer tokens, then Basic. With none configured
        every request is allowed.
        """
        app = self.app
        auth = self.headers.get("Authorization", "")
        if app.swift is not None and app.swift.token:
            if self.headers.get("X-Auth-Token") == app.swift.token:
                return False
            self._reply(401, b"<html><h1>Unauthorized</h1></html>")
            return True
        if app.s3 is not None:
            return self._s3_refused()
        if app.tokens:
            return self._bearer_refused(auth)
        if app.basic is not None:
            return self._basic_refused(auth, app.basic)
        return False

    def _bearer_refused(self, auth: str) -> bool:
        """Refuse (401) a request with none of the accepted bearer tokens; ``True`` if refused.

        Accepted: a configured token, a macaroon or OAuth token this server
        issued, or - with no ``Authorization`` at all - a client certificate.
        """
        app = self.app
        issued = {m["macaroon"] for m in app.macaroons}
        if auth.startswith("Bearer ") and auth[7:] in (app.tokens | issued):
            return False
        if not auth and self._record.peer is not None:
            return False  # a certificate is as good as a token here
        self._settle_body()
        self._reply(401, b"token required", {"WWW-Authenticate": "Bearer"})
        return True

    def _basic_refused(self, auth: str, login: tuple[str, str]) -> bool:
        """Refuse (401) a request without HTTP Basic ``login``; ``True`` if refused."""
        expected = base64.b64encode(":".join(login).encode()).decode()
        if auth == f"Basic {expected}":
            return False
        self._settle_body()
        self._reply(401, b"login required", {"WWW-Authenticate": "Basic"})
        return True

    # -- redirects ---------------------------------------------------------------------------

    def _redirected(self) -> bool:
        """Answer a one-shot or prefix redirect, if one applies; ``True`` if answered.

        A 307 keeps the method and body (RFC 9110 section 15.4.8), which is
        what dCache's door-to-pool redirects rely on for ``PUT``. A one-shot
        redirect is consumed, so the client's retry at the new location
        (often this same server) gets the real answer; with
        :attr:`~xrdhttp.testing.StorageServer.early_redirects` it is answered
        unread, with ``Connection: close``.
        """
        location = self.app._take_redirect(self.target)
        if location and self.app.early_redirects:
            self.close_connection = True
            self._reply(307, b"", {"Location": location, "Connection": "close"})
            return True
        if not location:
            location = self._prefix_location()
        if not location:
            return False
        self._settle_body()
        self._reply(307, b"", {"Location": location})
        return True

    def _prefix_location(self) -> str | None:
        """The ``Location`` a prefix redirect gives this request, or ``None``."""
        for prefix, base in self.app.redirect_prefixes.items():
            if self.path.startswith(prefix):
                return base + self.path
        return None

    # -- routing -----------------------------------------------------------------------------

    def do_GET(self) -> None:
        """Every method goes to :meth:`_dispatch`; :mod:`http.server` looks up ``do_<METHOD>``."""
        self._dispatch()

    do_HEAD = do_PUT = do_POST = do_DELETE = do_OPTIONS = do_GET
    do_MKCOL = do_MOVE = do_COPY = do_PROPFIND = do_GET

    def _route(self) -> None:
        """Hand the request to the mixin that speaks it.

        Fixed endpoints (tape REST, OAuth, delegation, CDMI) win over the
        object-store dialects, which win over WebDAV; so an S3 server can
        still issue tokens and serve tape REST. WebDAV methods map to
        ``_dav_<method>``.
        """
        if self._fixed_endpoint():
            return
        if self.app.s3 is not None:
            self._s3()
        elif self.app.swift is not None:
            self._swift()
        elif self.command == "POST" and self.headers.get("Content-Type", "").startswith(
            "application/macaroon-request"
        ):
            self._macaroon()
        else:
            # Every do_<METHOD> above has its _dav_<method>; http.server
            # answers any other method 501 before it gets here.
            getattr(self, f"_dav_{self.command.lower()}")()

    def _fixed_endpoint(self) -> bool:
        """Serve a fixed endpoint's request; ``False``, having done nothing, for any other path."""
        path, method = self.target, self.command
        if path == "/.well-known/wlcg-tape-rest-api" or path.split("/")[1:3] == ["api", "v1"]:
            self._tape()
        elif path.startswith("/.well-known/oauth-authorization-server"):
            self._oauth_discovery()
        elif path == "/token" and method == "POST":
            self._oauth_token()
        elif path == "/gridsite-delegation" and method == "POST":
            self._delegation()
        elif path in self.app.qos or path.startswith("/cdmi_capabilities/"):
            self._cdmi()
        else:
            return False
        return True
