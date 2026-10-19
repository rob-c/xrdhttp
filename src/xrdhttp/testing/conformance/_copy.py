"""HTTP third-party copy: one ``COPY``, the bytes moving server to server.

``server`` is the source and ``peer`` the destination. Pull mode sends the
``COPY`` to the destination naming the ``Source``; push mode sends it to
the source naming the ``Destination``. The answer is a ``202`` whatever
happens next, then a stream of performance markers, then one ``success``
or ``failure`` line - so every check here is about reading that stream
right: progress from the markers (and none from a marker with no count), a
failure after the ``202`` reported as one, a stream that stops before its
verdict not mistaken for success, the far end's token handed over.

Fallbacks to another mode or to a copy through the client, the checksum
verification a client runs afterwards, and the macaroons a client mints
for the far side are each client's policy; :meth:`Adapter.copy` asks for
exactly one ``COPY``.
"""

from __future__ import annotations

from .._server import StorageServer
from ._adapter import Adapter, Kind
from ._base import Conformance, failure

#: What the copies move: three performance markers' worth at a marker per kilobyte.
DATA = b"s" * 3000


class CopySuite(Conformance):
    """Pull, push, markers, failures after the ``202``, and the far side's token."""

    def test_a_pull_moves_the_bytes_server_to_server(
        self, server: StorageServer, peer: StorageServer, client: Adapter
    ) -> None:
        """Pull: the ``COPY`` goes to the destination, naming the source in ``http`` form, and the
        source sees the destination's ``GET`` - never ours. ``Credential: none`` stops a
        delegation-capable server waiting for a proxy nobody will send.
        """
        server.add_file("/d/src", DATA)
        peer.add_dir("/d")
        client.copy(client.url(server, "/d/src"), client.url(peer, "/d/dst"))
        assert peer.contents("/d/dst") == DATA
        headers = {name.lower(): value for name, value in peer.copies[-1].items()}
        assert headers["source"] == f"{server.base}/d/src"
        assert headers["credential"] == "none"
        assert "/d/src" in [r.path for r in server.requests if r.method == "GET"]

    def test_a_push_hands_the_destination_to_the_source(
        self, server: StorageServer, peer: StorageServer, client: Adapter
    ) -> None:
        """Push, for a destination that cannot open outbound connections: the ``COPY`` goes to the
        source instead, and the destination is never asked to copy anything.
        """
        server.add_file("/d/src", DATA)
        peer.add_dir("/d")
        client.copy(client.url(server, "/d/src"), client.url(peer, "/d/dst"), push=True)
        assert peer.contents("/d/dst") == DATA
        headers = {name.lower(): value for name, value in server.copies[-1].items()}
        assert headers["destination"] == f"{peer.base}/d/dst"
        assert not peer.copies

    def test_progress_follows_the_performance_markers(
        self, server: StorageServer, peer: StorageServer, client: Adapter
    ) -> None:
        """Each marker's byte count is a running total; progress is reported from them, in order,
        ending at the size.
        """
        server.add_file("/d/src", DATA)
        peer.add_dir("/d")
        peer.marker_every = 1000
        seen: list[int] = []
        client.copy(client.url(server, "/d/src"), client.url(peer, "/d/dst"), progress=seen.append)
        assert seen[-1] == len(DATA)
        assert seen == sorted(seen) and 1000 in seen

    def test_markers_that_count_nothing_are_not_fatal(
        self, server: StorageServer, peer: StorageServer, client: Adapter
    ) -> None:
        """A keepalive marker with no byte count, unreadable numbers, a stray line, then success."""
        server.add_file("/d/src", DATA)
        peer.add_dir("/d")
        body = (
            b"Perf Marker\n\tStripe Index: x\n\tStripe Bytes Transferred: 5\nEnd\n"
            b"Perf Marker\n    Timestamp: 1\nEnd\nnot a field\n"
            b"Perf Marker\n    Stripe Bytes Transferred: many\nEnd\nsuccess: Created\n"
        )
        peer.handlers["COPY"] = lambda method, path, headers: (202, body, {})
        client.copy(client.url(server, "/d/src"), client.url(peer, "/d/dst"))

    def test_a_copy_of_nothing_fails_after_its_202(
        self, server: StorageServer, peer: StorageServer, client: Adapter
    ) -> None:
        """The status line said Accepted; the body says the source was not there."""
        server.add_dir("/d")
        peer.add_dir("/d")
        source, target = client.url(server, "/d/nope"), client.url(peer, "/d/dst")
        failure(client, lambda: client.copy(source, target))
        assert peer.store.entry("/d/dst") is None

    def test_a_failure_line_is_a_failure(
        self, server: StorageServer, peer: StorageServer, client: Adapter
    ) -> None:
        """The verdict is the last line of the body: a ``failure:`` there fails the copy, though the
        status was ``202``.
        """
        server.add_file("/d/src", DATA)
        peer.add_dir("/d")
        peer.tpc_failure = "the transfer was aborted by the operator"
        source, target = client.url(server, "/d/src"), client.url(peer, "/d/dst")
        failure(client, lambda: client.copy(source, target))
        assert peer.store.entry("/d/dst") is None

    def test_a_marker_stream_that_stops_before_its_verdict_is_a_failure(
        self, server: StorageServer, peer: StorageServer, client: Adapter
    ) -> None:
        """A connection that closes after the markers but before ``success`` is a transfer of
        unknown outcome, never a success.
        """
        server.add_file("/d/src", DATA)
        peer.add_dir("/d")
        peer.tpc = "eof"
        source, target = client.url(server, "/d/src"), client.url(peer, "/d/dst")
        failure(client, lambda: client.copy(source, target))

    def test_a_source_that_is_not_there_is_reported(
        self, server: StorageServer, peer: StorageServer, client: Adapter
    ) -> None:
        """The destination cannot reach the source at all: reported, and nothing is left behind at
        the destination.
        """
        peer.add_dir("/d")
        source = client.url(server, "/d/src")
        server.stop()
        target = client.url(peer, "/d/dst")
        failure(client, lambda: client.copy(source, target))
        assert peer.store.entry("/d/dst") is None

    def test_a_refused_copy_is_a_permission_failure(
        self, server: StorageServer, peer: StorageServer, client: Adapter
    ) -> None:
        """A ``403`` before the copy starts is the caller's permission problem, as for any other
        verb.
        """
        server.add_file("/d/src", DATA)
        peer.add_dir("/d")
        peer.fault("COPY", status=403)
        source, target = client.url(server, "/d/src"), client.url(peer, "/d/dst")
        assert failure(client, lambda: client.copy(source, target)) is Kind.PERMISSION

    def test_the_far_end_is_handed_the_token(
        self, server: StorageServer, peer: StorageServer, client: Adapter
    ) -> None:
        """Both ends demand it; the destination presents it to the source for us."""
        server.add_file("/d/src", DATA)
        peer.add_dir("/d")
        server.tokens = peer.tokens = {"T0KEN"}
        client.authorise("T0KEN")
        client.copy(client.url(server, "/d/src"), client.url(peer, "/d/dst"))
        assert peer.contents("/d/dst") == DATA
        headers = {name.lower(): value for name, value in peer.copies[-1].items()}
        assert headers["transferheaderauthorization"] == "Bearer T0KEN"
