"""Credentials a client obtains from the server: macaroons, OAuth tokens, delegated proxies.

* a ``POST`` of ``application/macaroon-request`` mints a macaroon - the
  fixed :attr:`~xrdhttp.testing.StorageServer.macaroon` when set, else a
  fresh one - and records it in
  :attr:`~xrdhttp.testing.StorageServer.macaroons`, where the front's
  authorisation accepts it as a bearer token;
* ``/.well-known/oauth-authorization-server`` and ``/token`` play an OAuth
  issuer, when :attr:`~xrdhttp.testing.StorageServer.oauth` is on;
* ``POST /gridsite-delegation`` is handed to the server's
  :data:`~xrdhttp.testing.DelegationService`, which a client's preset
  supplies, since delegation is X.509 work this package does not do.

None of this is real token cryptography: macaroons and OAuth tokens are
opaque strings remembered by the server, which is all a client can observe
of them anyway. What a test checks is that the client asked correctly
(the request document is kept with the token) and then presented the token
it was given.
"""

from __future__ import annotations

import json
import urllib.parse
import uuid

from ._base import HandlerBase


class TokenMixin(HandlerBase):
    """Token issuance, and the door to delegation."""

    def _macaroon(self) -> None:
        """dCache's macaroon request: ``POST`` JSON (caveats, validity) to the path it is for.

        The reply carries ``macaroon`` and ``uri.targetWithMacaroon``, as
        dCache's does; the request document is kept with the token so tests
        can assert the caveats (``activity:...``) and ``validity`` asked for.
        """
        body = self._read_body()
        request = json.loads(body) if body.strip() else {}
        fixed = self.app.macaroon
        token = fixed if fixed is not None else f"mac-{uuid.uuid4().hex}"
        self.app.macaroons.append({"path": self.target, "macaroon": token, **request})
        self._json(200, {"macaroon": token, "uri": {"targetWithMacaroon": self.target}})

    def _oauth_discovery(self) -> None:
        """RFC 8414 authorisation-server metadata: just ``issuer`` and ``token_endpoint``.

        :attr:`~xrdhttp.testing.StorageServer.oauth_endpoint` points the
        client elsewhere (another server, an unreachable URL) to test
        failover; 404 when OAuth is off, as on most storage elements.
        """
        if not self.app.oauth:
            self._reply(404, b"no oauth here")
            return
        endpoint = self.app.oauth_endpoint or f"{self.app.base}/token"
        self._json(200, {"issuer": self.app.base, "token_endpoint": endpoint})

    def _oauth_token(self) -> None:
        """RFC 6749 token endpoint: any form is granted a bearer token.

        The form (grant type, scope, audience) is recorded next to the token
        in :attr:`~xrdhttp.testing.StorageServer.macaroons`, so it is then
        accepted as a bearer token like a macaroon.
        """
        form = urllib.parse.parse_qs(self._read_body().decode())
        token = f"oauth-{uuid.uuid4().hex}"
        self.app.macaroons.append({"macaroon": token, "form": form})
        self._json(200, {"access_token": token, "token_type": "bearer"})

    def _delegation(self) -> None:
        """Hand a delegation request to the server's service; 404 when there is none."""
        body = self._read_body()
        service = self.app.delegation_service
        if service is None:
            self._reply(404, b"no delegation service here")
            return
        self._reply(*service(self.app, body))
