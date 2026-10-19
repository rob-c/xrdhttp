"""The WebDAV namespace: stat, listings, collections, removal and renames.

What both clients promise a user of the namespace whatever their API looks
like: a ``PROPFIND`` read for size, type and time; a listing of a
collection's children (never the collection itself, never anything
outside it); ``MKCOL``, ``DELETE`` and ``MOVE`` with POSIX's answers for
the ways each can fail; names that survive the trip however awkward; and
the multistatus a hostile server could send refused rather than believed.

The wording of each failure (davix's ``Result HTTP 404 : File not found``,
XrdCl's ``[ERROR] Server responded with an error``) is each client's own,
and stays in its own suite; here only the meaning - a :class:`Kind` - is
checked.
"""

from __future__ import annotations

from .._server import StorageServer
from ._adapter import Adapter, Kind
from ._base import Conformance, failure

#: Names that each break one naive way of encoding a path: an existing escape,
#: a space, a fragment and a query delimiter, a name outside ASCII, the
#: character a form decoder reads as a space, an unreserved one, a bare percent.
AWKWARD = ("a%41b", "a b", "a#b", "a?b", "日本", "a+b", "a~b", "100%", "a%2541b", "ünï")

#: A multistatus wrapper, for the canned answers below.
_MULTISTATUS = (
    '<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">{}</D:multistatus>'
)


def _entry(href: str, props: str, status: str = "HTTP/1.1 200 OK") -> str:
    """One ``<D:response>`` whose single propstat holds ``props``."""
    return (
        f"<D:response><D:href>{href}</D:href><D:propstat><D:prop>{props}</D:prop>"
        f"<D:status>{status}</D:status></D:propstat></D:response>"
    )


def _canned(server: StorageServer, body: str) -> None:
    """Answer the next ``PROPFIND`` with ``body`` as a 207, whatever was asked."""
    server.fault("PROPFIND", status=207, body=body.encode(), headers={"Content-Type": "text/xml"})


class NamespaceSuite(Conformance):
    """``stat``, ``listdir``, ``mkdir``/``makedirs``, ``rmdir``, ``unlink``, ``rename``."""

    # -- stat ----------------------------------------------------------------------------

    def test_a_file_is_stated_with_its_size(self, server: StorageServer, client: Adapter) -> None:
        """A depth-0 ``PROPFIND``: the length, the type and the modification time the server
        reports.
        """
        server.add_file("/d/f", b"hello\n")
        info = client.stat(client.url(server, "/d/f"))
        assert (info.size, info.directory) == (6, False)
        found = server.store.entry("/d/f")
        assert found is not None and info.modified == int(found.modified)

    def test_a_collection_is_stated_as_a_directory(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """``<D:collection/>`` in the resource type is a directory."""
        server.add_dir("/d/sub")
        assert client.stat(client.url(server, "/d/sub")).directory

    def test_a_stat_asks_for_depth_zero(self, server: StorageServer, client: Adapter) -> None:
        """A stat asks about the resource alone; ``Depth: 1`` on a large collection would list it
        all.
        """
        server.add_file("/d/f", b"x")
        client.stat(client.url(server, "/d/f"))
        found = [r for r in server.requests if r.method == "PROPFIND"]
        assert [r.header("Depth") for r in found] == ["0"]

    def test_nothing_there_is_not_found(self, server: StorageServer, client: Adapter) -> None:
        """A ``404`` to the ``PROPFIND`` is "not found"."""
        assert failure(client, lambda: client.stat(client.url(server, "/d/nope"))) is Kind.NOT_FOUND

    def test_a_403_is_a_permission_failure(self, server: StorageServer, client: Adapter) -> None:
        """A ``403`` to the ``PROPFIND`` is a permission failure, not a missing file."""
        server.add_file("/d/f", b"x")
        server.fault("PROPFIND", status=403)
        assert failure(client, lambda: client.stat(client.url(server, "/d/f"))) is Kind.PERMISSION

    def test_the_first_propstat_that_succeeded_is_believed(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A server lists the properties it lacks under a ``404`` propstat: ignore them."""
        body = (
            "<D:response><D:href>/d/f</D:href>"
            "<D:propstat><D:prop><D:getcontentlength>99</D:getcontentlength></D:prop>"
            "<D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>"
            "<D:propstat><D:prop><D:getcontentlength>7</D:getcontentlength></D:prop>"
            "<D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>"
        )
        _canned(server, _MULTISTATUS.format(body))
        assert client.stat(client.url(server, "/d/f")).size == 7

    def test_a_date_nobody_can_read_is_no_time_at_all(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """An unreadable ``getlastmodified`` is no time (zero), not a failed stat."""
        props = (
            "<D:getcontentlength>3</D:getcontentlength><D:getlastmodified>soon</D:getlastmodified>"
        )
        _canned(server, _MULTISTATUS.format(_entry("/d/f", props)))
        info = client.stat(client.url(server, "/d/f"))
        assert (info.size, info.modified) == (3, 0)

    def test_an_http_date_is_read(self, server: StorageServer, client: Adapter) -> None:
        """``getlastmodified`` is an RFC 9110 date, read to the second."""
        stamp = "<D:getlastmodified>Tue, 02 Jan 2024 03:04:05 GMT</D:getlastmodified>"
        _canned(server, _MULTISTATUS.format(_entry("/d/f", stamp)))
        assert client.stat(client.url(server, "/d/f")).modified == 1704164645

    def test_a_hostile_document_is_refused_unread(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """An external entity is never fetched: the declaration alone is refused."""
        target = f"{server.base}/secret"
        body = (
            f'<?xml version="1.0"?><!DOCTYPE m [<!ENTITY x SYSTEM "{target}">]>'
            '<D:multistatus xmlns:D="DAV:"><D:response><D:href>&x;</D:href></D:response>'
            "</D:multistatus>"
        )
        server.add_file("/secret", b"secret")
        _canned(server, body)
        failure(client, lambda: client.stat(client.url(server, "/d/f")))
        assert "/secret" not in [r.path for r in server.requests]

    def test_a_body_that_is_not_xml_is_refused(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A ``207`` whose body is not XML is a failure of the protocol, not an answer that nothing
        is there.
        """
        _canned(server, "<not xml")
        assert (
            failure(client, lambda: client.stat(client.url(server, "/d/f"))) is not Kind.NOT_FOUND
        )

    # -- listings ------------------------------------------------------------------------

    def test_a_listing_names_the_children_and_not_the_collection(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A depth-1 ``PROPFIND`` lists the collection and its children; only the children are names
        in it, decoded.
        """
        server.add_file("/d/a", b"1")
        server.add_file("/d/b c", b"22")
        server.add_dir("/d/sub")
        assert sorted(client.listdir(client.url(server, "/d"))) == ["a", "b c", "sub"]
        listing = [r for r in server.requests if r.method == "PROPFIND"][-1]
        assert listing.header("Depth") == "1"

    def test_an_empty_collection_lists_nothing(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """The collection's own entry is the only one: an empty listing, not an error."""
        server.add_dir("/d/empty")
        assert client.listdir(client.url(server, "/d/empty")) == []

    def test_listing_nothing_is_not_found(self, server: StorageServer, client: Adapter) -> None:
        """Listing a collection that is not there is "not found"."""
        server.add_dir("/d")
        url = client.url(server, "/d/nope")
        assert failure(client, lambda: client.listdir(url)) is Kind.NOT_FOUND

    def test_listed_names_are_decoded_once_and_reach_their_files(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A name is encoded exactly once on the way out and decoded once on the way back.

        Anything else lets ``a%41b`` reach ``aAb`` - which is here, holding
        the wrong bytes, to catch it.
        """
        for name in AWKWARD:
            server.add_file(f"/d/{name}", name.encode())
        server.add_file("/d/aAb", b"WRONG FILE")
        assert sorted(client.listdir(client.url(server, "/d"))) == sorted([*AWKWARD, "aAb"])
        for name in AWKWARD:
            url = client.url(server, f"/d/{name}")
            assert client.read(url) == name.encode(), name
            assert client.stat(url).size == len(name.encode()), name

    # -- collections ---------------------------------------------------------------------

    def test_mkdir_makes_a_collection(self, server: StorageServer, client: Adapter) -> None:
        """``MKCOL`` makes one collection."""
        server.add_dir("/d")
        client.mkdir(client.url(server, "/d/new"))
        found = server.store.entry("/d/new")
        assert found is not None and found.collection

    def test_mkdir_of_a_collection_that_is_there_is_exists(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """``MKCOL`` on an existing collection answers ``405``, which means "exists" here, not
        "method not allowed".
        """
        server.add_dir("/d/new")
        assert failure(client, lambda: client.mkdir(client.url(server, "/d/new"))) is Kind.EXISTS

    def test_mkdir_under_nothing_is_not_found(self, server: StorageServer, client: Adapter) -> None:
        """``MKCOL`` under a missing parent answers ``409`` (RFC 4918 section 9.3.1): "not found",
        and no parent is made.
        """
        server.add_dir("/d")
        url = client.url(server, "/d/a/b")
        assert failure(client, lambda: client.mkdir(url)) is Kind.NOT_FOUND
        assert server.store.entry("/d/a") is None

    def test_mkdir_refused_is_a_permission_failure(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A ``403`` to ``MKCOL`` is a permission failure."""
        server.add_dir("/d")
        server.fault("MKCOL", status=403)
        url = client.url(server, "/d/c")
        assert failure(client, lambda: client.mkdir(url)) is Kind.PERMISSION

    def test_makedirs_makes_every_missing_parent(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """``mkdir -p``: every missing collection on the way is made, and one that is already there
        is success.
        """
        server.add_dir("/d")
        client.makedirs(client.url(server, "/d/a/b/c"))
        for path in ("/d/a", "/d/a/b", "/d/a/b/c"):
            found = server.store.entry(path)
            assert found is not None and found.collection
        client.makedirs(client.url(server, "/d/a/b/c"))  # and again: already there is fine

    def test_rmdir_removes_an_empty_collection(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """``DELETE`` of an empty collection removes it."""
        server.add_dir("/d/empty")
        client.rmdir(client.url(server, "/d/empty"))
        assert server.store.entry("/d/empty") is None

    def test_rmdir_keeps_a_collection_with_something_in_it(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """POSIX lets ``rmdir`` say ``ENOTEMPTY`` or ``EEXIST``; gfal2 says the second.

        An XrdCl-style fake deletes a full collection whole, as RFC 4918
        says: the client must look before it deletes.
        """
        server.add_file("/d/full/child", b"x")
        kind = failure(client, lambda: client.rmdir(client.url(server, "/d/full")))
        assert kind in (Kind.NOT_EMPTY, Kind.EXISTS)
        assert server.contents("/d/full/child") == b"x"

    def test_rmdir_of_nothing_is_not_found(self, server: StorageServer, client: Adapter) -> None:
        """Removing a collection that is not there is "not found"."""
        server.add_dir("/d")
        url = client.url(server, "/d/nope")
        assert failure(client, lambda: client.rmdir(url)) is Kind.NOT_FOUND

    def test_unlink_removes_a_file(self, server: StorageServer, client: Adapter) -> None:
        """``DELETE`` of a file removes it and nothing else."""
        server.add_file("/d/f", b"x")
        client.unlink(client.url(server, "/d/f"))
        assert server.store.entry("/d/f") is None
        assert server.store.entry("/d") is not None

    def test_unlink_of_nothing_is_not_found(self, server: StorageServer, client: Adapter) -> None:
        """Removing a file that is not there is "not found"."""
        server.add_dir("/d")
        url = client.url(server, "/d/nope")
        assert failure(client, lambda: client.unlink(url)) is Kind.NOT_FOUND

    def test_unlink_refused_is_a_permission_failure(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A ``403`` to ``DELETE`` is a permission failure, and the file stays."""
        server.add_file("/d/f", b"x")
        server.fault("DELETE", status=403)
        url = client.url(server, "/d/f")
        assert failure(client, lambda: client.unlink(url)) is Kind.PERMISSION
        assert server.contents("/d/f") == b"x"

    # -- renames -------------------------------------------------------------------------

    def test_a_rename_moves_the_bytes(self, server: StorageServer, client: Adapter) -> None:
        """``MOVE`` with the destination named as an absolute ``http`` URL - what the server
        resolves, whatever scheme the caller used.
        """
        server.add_file("/d/old", b"x")
        client.rename(client.url(server, "/d/old"), client.url(server, "/d/new"))
        assert server.contents("/d/new") == b"x"
        assert server.store.entry("/d/old") is None
        move = [r for r in server.requests if r.method == "MOVE"][-1]
        assert move.header("Destination") == f"{server.base}/d/new"

    def test_a_rename_replaces_what_is_at_the_destination(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A rename onto an existing file replaces it, as ``rename(2)`` does."""
        server.add_file("/d/old", b"new bytes")
        server.add_file("/d/new", b"old bytes")
        client.rename(client.url(server, "/d/old"), client.url(server, "/d/new"))
        assert server.contents("/d/new") == b"new bytes"

    def test_a_collection_is_renamed_with_its_contents(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A ``MOVE`` of a collection takes everything in it along."""
        server.add_file("/d/old/child", b"x")
        client.rename(client.url(server, "/d/old"), client.url(server, "/d/new"))
        assert server.contents("/d/new/child") == b"x"
        assert server.store.entry("/d/old") is None

    def test_renaming_nothing_is_not_found(self, server: StorageServer, client: Adapter) -> None:
        """Renaming a missing file is "not found"."""
        server.add_dir("/d")
        source, target = client.url(server, "/d/nope"), client.url(server, "/d/new")
        assert failure(client, lambda: client.rename(source, target)) is Kind.NOT_FOUND

    def test_awkward_names_arrive_intact(self, server: StorageServer, client: Adapter) -> None:
        """A space, a ``#`` and a name outside Latin-1, through ``Destination`` and back."""
        server.add_file("/d/a b", b"x")
        client.rename(client.url(server, "/d/a b"), client.url(server, "/d/дані #1"))
        assert server.contents("/d/дані #1") == b"x"
        assert client.stat(client.url(server, "/d/дані #1")).size == 1
