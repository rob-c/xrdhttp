"""The WLCG Tape REST API and macaroons: what a storage element issues on request.

Staging is a request with an id: files are named in a ``POST stage``,
polled until they are on disk, withdrawn or released by that id. Every
client must read the fake's answers the same way: a file on disk is
online at once, a file on tape is not until it is recalled, a lost file
fails its request, ``archiveinfo`` says which files have a tape copy
without staging any. The fake simulates the recall with state the test
changes (:attr:`~xrdhttp.testing.Tape.nearline`), so nothing waits on a
clock.

Macaroons are dCache's (and XrdHttp's) bearer tokens minted on demand: a
``POST`` of ``application/macaroon-request`` naming the activities, and a
JSON answer holding the token, which the server then accepts.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from .._model import Tape
from .._server import StorageServer
from ._adapter import Adapter
from ._base import Conformance, failure


class TapeSuite(Conformance):
    """Stage, poll, release, abort and archive information."""

    @pytest.fixture
    def tape(self, server: StorageServer) -> Iterator[Tape]:
        """The server's tape: ``/d/a`` on disk, ``/d/t`` on tape, ``/d/lost`` lost."""
        for name in ("a", "t", "lost"):
            server.add_file(f"/d/{name}", b"x")
        server.tape = Tape(locality={"/d/t": "TAPE", "/d/lost": "LOST"})
        yield server.tape

    def test_a_file_on_disk_is_online_once_staged(
        self, server: StorageServer, client: Adapter, tape: Tape
    ) -> None:
        """``POST stage`` names the file; the request id comes back, and a file already on disk
        polls online.
        """
        url = client.url(server, "/d/a")
        request = client.stage([url])
        assert tape.staged() == {request: ["/d/a"]}
        assert client.poll(request, [url]) == [True]

    def test_a_file_on_tape_comes_online_when_it_is_recalled(
        self, server: StorageServer, client: Adapter, tape: Tape
    ) -> None:
        """A file on tape polls not-yet-online until the site recalls it."""
        tape.nearline.add("/d/a")
        url = client.url(server, "/d/a")
        request = client.stage([url])
        assert client.poll(request, [url]) == [False]
        tape.nearline.discard("/d/a")
        assert client.poll(request, [url]) == [True]

    def test_a_lost_file_fails_its_request(
        self, server: StorageServer, client: Adapter, tape: Tape
    ) -> None:
        """A lost file fails its staging request rather than staying "not yet" for ever."""
        url = client.url(server, "/d/lost")
        request = client.stage([url])
        failure(client, lambda: client.poll(request, [url]))

    def test_a_release_names_its_request_and_files(
        self, server: StorageServer, client: Adapter, tape: Tape
    ) -> None:
        """``POST release/<id>`` names the request and its files."""
        url = client.url(server, "/d/a")
        request = client.stage([url])
        client.release(request, [url])
        assert tape.released == [(request, ["/d/a"])]

    def test_an_abort_withdraws_the_files(
        self, server: StorageServer, client: Adapter, tape: Tape
    ) -> None:
        """``POST stage/<id>/cancel`` withdraws the files named."""
        url = client.url(server, "/d/a")
        request = client.stage([url])
        client.abort(request, [url])
        assert tape.cancelled == [(request, ["/d/a"])]

    def test_archive_information_says_which_files_have_a_tape_copy(
        self, server: StorageServer, client: Adapter, tape: Tape
    ) -> None:
        """``POST archiveinfo`` says where each file is, and stages nothing."""
        urls = [client.url(server, "/d/t"), client.url(server, "/d/a")]
        assert client.on_tape(urls) == [True, False]
        assert not tape.requests

    def test_polling_a_request_nobody_made_fails(
        self, server: StorageServer, client: Adapter, tape: Tape
    ) -> None:
        """An unknown request id is a failure, not a file that is not yet online."""
        url = client.url(server, "/d/a")
        failure(client, lambda: client.poll("no-such-request", [url]))

    def test_a_site_without_tape_refuses_to_stage(
        self, server: StorageServer, client: Adapter, tape: Tape
    ) -> None:
        """A site with no tape behind its door refuses the request."""
        server.tape = None
        url = client.url(server, "/d/a")
        failure(client, lambda: client.stage([url]))


class TokenSuite(Conformance):
    """Macaroons asked for, accepted, and refused when the answer holds none.

    Some clients ask for a token only over HTTPS: such a client's
    :meth:`~Conformance.make_server` hands the fake a TLS context.
    """

    def test_a_macaroon_is_minted_for_the_activities_asked_and_accepted(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """The request names the activities; the token the server mints is then accepted in place of
        any other.
        """
        server.add_file("/d/f", b"x")
        url = client.url(server, "/d/f")
        token = client.macaroon(url, ["DOWNLOAD", "LIST"])
        assert token == server.macaroons[-1]["macaroon"]
        assert server.macaroons[-1]["caveats"] == ["activity:DOWNLOAD,LIST"]
        mint = [r for r in server.requests if r.method == "POST"][-1]
        assert mint.header("Content-Type") == "application/macaroon-request"
        server.tokens = {"something else"}
        client.authorise(token)
        assert client.stat(url).size == 1

    def test_an_answer_with_no_macaroon_in_it_fails(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A JSON answer without a ``macaroon`` is a failure, not an empty token."""
        server.add_file("/d/f", b"x")
        server.fault("POST", status=200, body=b'{"other": 1}')
        url = client.url(server, "/d/f")
        failure(client, lambda: client.macaroon(url, ["DOWNLOAD"]))

    def test_an_answer_that_is_not_json_fails(self, server: StorageServer, client: Adapter) -> None:
        """An answer that is not JSON is a failure."""
        server.add_file("/d/f", b"x")
        server.fault("POST", status=200, body=b"{nope")
        url = client.url(server, "/d/f")
        failure(client, lambda: client.macaroon(url, ["DOWNLOAD"]))
