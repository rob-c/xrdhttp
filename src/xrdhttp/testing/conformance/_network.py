"""The connection under every operation: redirects, credentials, pooling, failures.

Storage elements redirect as a matter of course (a head node to a disk
server, a door to the pool that has the file), close idle keep-alive
connections without warning, and are sometimes simply not there. What
every client must get right: a redirect is followed to wherever it says,
relative ``Location`` and all, but not for ever; the caller's token goes
with a redirect within the same server; a connection is reused while it
lasts and replaced, without the caller noticing, when the server has
closed it; a server that is gone, or too slow, is reported as such.

Which other hosts a credential may follow a redirect to is where the
clients deliberately differ (XrdCl's same-origin rule, davix's looser
one, :mod:`xrdhttp.redirects`), so only the case they agree on is here.
"""

from __future__ import annotations

from .._model import Handler, Reply
from .._server import StorageServer
from ._adapter import Adapter, Kind
from ._base import Conformance, failure


def _relative(path: str, location: str) -> Handler:
    """A handler redirecting every ``GET`` of ``path`` to ``location``, as written.

    Only the ``GET``: a client that stats before it reads must find the
    file where it asked, and be sent on only for the bytes.
    """

    def handler(method: str, asked: str, headers: dict[str, str]) -> Reply | None:
        """A 302 for ``path``; anything else is the fake's to answer."""
        return (302, b"", {"Location": location}) if asked == path else None

    return handler


class RedirectSuite(Conformance):
    """Redirects followed - across servers, relative, with the token - and refused for ever."""

    def test_a_read_follows_a_redirect_to_another_server(
        self, server: StorageServer, peer: StorageServer, client: Adapter
    ) -> None:
        """A door redirects the ``GET`` to the server with the file; the bytes come from there."""
        server.add_file("/d/f", b"here")
        peer.add_file("/d/f", b"from the other one")
        server.redirect_prefixes["/d/f"] = peer.base
        assert client.read(client.url(server, "/d/f")) == b"from the other one"
        assert "/d/f" in [r.path for r in peer.requests if r.method == "GET"]

    def test_a_stat_follows_a_redirect(
        self, server: StorageServer, peer: StorageServer, client: Adapter
    ) -> None:
        """A ``PROPFIND`` redirected is answered where it was sent."""
        peer.add_file("/d/f", b"12345")
        server.redirect_prefixes["/d"] = peer.base
        assert client.stat(client.url(server, "/d/f")).size == 5

    def test_a_relative_location_is_resolved_against_the_url_that_sent_it(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """``Location: b`` is relative to the URL that was redirected (RFC 9110 section 10.2.2)."""
        server.add_file("/d/a", b"first")
        server.add_file("/d/b", b"second")
        server.handlers["GET"] = _relative("/d/a", "b")
        assert client.read(client.url(server, "/d/a")) == b"second"

    def test_a_redirect_that_never_ends_is_refused(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A server that redirects to itself for ever is refused after a bounded number of hops."""
        server.add_file("/d/loop", b"x")
        server.redirect_prefixes["/d/loop"] = server.base
        url = client.url(server, "/d/loop")
        assert failure(client, lambda: client.read(url)) is Kind.REDIRECTS

    def test_an_upload_redirected_for_ever_is_refused(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """The same for a ``PUT``, which stores nothing."""
        server.add_dir("/d")
        server.redirect_prefixes["/d/loop"] = server.base
        url = client.url(server, "/d/loop")
        assert failure(client, lambda: client.write(url, b"abc")) is Kind.REDIRECTS
        assert server.store.entry("/d/loop") is None

    def test_the_token_follows_a_redirect_within_the_server(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A redirect within the same server keeps the caller's ``Authorization`` - the one case the
        clients' credential rules agree on.
        """
        server.add_file("/d/a", b"first")
        server.add_file("/d/b", b"second")
        server.tokens = {"T0KEN"}
        server.handlers["GET"] = _relative("/d/a", "/d/b")
        client.authorise("T0KEN")
        assert client.read(client.url(server, "/d/a")) == b"second"
        final = [r for r in server.requests if r.path == "/d/b"][-1]
        assert final.header("Authorization") == "Bearer T0KEN"


class ConnectionSuite(Conformance):
    """Keep-alive, a pooled connection the server closed, no server, a slow server, tokens."""

    def test_one_connection_serves_request_after_request(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """Keep-alive: a run of requests to one server reuses one connection."""
        server.add_file("/d/f", b"x")
        for _ in range(4):
            client.stat(client.url(server, "/d/f"))
        assert server.connections == 1

    def test_a_pooled_connection_the_server_closed_is_replaced(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A server that closed an idle keep-alive connection is not a failure: the request goes
        again on a new one.
        """
        server.add_file("/d/f", b"x")
        client.stat(client.url(server, "/d/f"))
        server.fault("PROPFIND", drop=True)
        assert client.stat(client.url(server, "/d/f")).size == 1

    def test_a_server_that_is_not_there_is_a_connection_failure(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """Nothing listening is a connection failure, not a missing file."""
        url = client.url(server, "/d/f")
        server.stop()
        assert failure(client, lambda: client.stat(url)) is Kind.CONNECTION

    def test_a_server_too_slow_to_answer_times_out(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """An answer slower than the client's limit is a timeout, not a hang."""
        server.add_file("/d/f", b"x")
        client.time_limit(1)
        server.fault("PROPFIND", delay=1.5)
        url = client.url(server, "/d/f")
        assert failure(client, lambda: client.stat(url)) is Kind.TIMEOUT

    def test_a_bearer_token_is_what_the_server_asked_for(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A server that demands a token refuses the request without one, and accepts it as
        ``Authorization: Bearer``.
        """
        server.add_file("/d/f", b"x")
        server.tokens = {"T0KEN"}
        url = client.url(server, "/d/f")
        assert failure(client, lambda: client.stat(url)) is Kind.PERMISSION
        client.authorise("T0KEN")
        assert client.stat(url).size == 1
        assert server.requests[-1].header("Authorization") == "Bearer T0KEN"
