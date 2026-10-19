"""S3: a bucket of flat keys read as a filesystem, and uploads in parts.

The fake checks every SigV4 signature it is sent (written out again from
the specification, not with the client's signer), so a client that signs
the wrong string fails here. What both clients owe a user of a bucket:
keys and the prefixes between them read as files and directories, a
listing followed through every page, a small object written in one
``PUT`` and a large one in parts - with the upload abandoned, never left
half made, when a part or the completion fails (S3 reports a failed
completion inside a ``200``) - a rename that is a server-side copy and a
delete, and never the delete when the copy failed, and the ``ETag`` of a
single ``PUT`` read as the MD5 it is.

The paths given to :meth:`Adapter.url` are ``/bucket/key``; the client's
adapter spells them as it addresses buckets (``s3://bucket/key`` with an
endpoint, ``s3://host:port/bucket/key``) and signs with the fake's keys
(:class:`~xrdhttp.testing.S3`'s ``access_key`` and ``secret_key``). A
client splits uploads into parts only past its own threshold: its subclass
shrinks that (and the part size) so that :data:`LARGE`, written in
:data:`PIECE`-sized pieces, goes up in several parts.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

import pytest

from .._model import S3
from .._server import StorageServer
from ._adapter import Adapter, Kind
from ._base import Conformance, failure

#: How large one piece of a large upload is.
PIECE = 1000

#: A large object: several parts once a client's threshold is shrunk to a piece or two.
LARGE = bytes(range(250)) * 20


def _s3(server: StorageServer) -> S3:
    """The server's S3 state, which the suite's ``server`` fixture always sets."""
    assert server.s3 is not None
    return server.s3


class S3Suite(Conformance):
    """Stat, listings, reads, single and multipart uploads, renames, ETags and signatures."""

    #: The bucket every test works in.
    bucket: ClassVar[str] = "bucket"

    @pytest.fixture
    def server(self, tmp_path: Path) -> Iterator[StorageServer]:
        """The client's fake speaking S3, holding an empty :attr:`bucket`."""
        root = tmp_path / "server"
        root.mkdir()
        made = self.make_server(root)
        made.s3 = S3()
        made.store.make_bucket(self.bucket)
        with made as started:
            yield started

    def put(self, server: StorageServer, key: str, data: bytes) -> None:
        """Store an object, as if another client had."""
        server.store.put_object(self.bucket, key, data)

    def at(self, client: Adapter, server: StorageServer, key: str) -> str:
        """The client's URL for ``key`` in :attr:`bucket`."""
        return client.url(server, f"/{self.bucket}/{key}")

    # -- the namespace -----------------------------------------------------------------

    def test_an_object_is_stated_with_a_signed_head(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A ``HEAD`` of the object, signed with SigV4 (which the fake checks)."""
        self.put(server, "top", b"333")
        info = client.stat(self.at(client, server, "top"))
        assert (info.size, info.directory) == (3, False)
        head = [r for r in server.requests if r.method == "HEAD"][-1]
        assert (head.header("Authorization") or "").startswith("AWS4-HMAC-SHA256 ")

    def test_a_prefix_with_keys_under_it_is_a_directory(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A key that is no object but has keys under it is a directory."""
        self.put(server, "dir/a", b"1")
        assert client.stat(self.at(client, server, "dir")).directory

    def test_a_key_that_is_neither_an_object_nor_a_prefix_is_not_found(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """Neither an object nor a prefix: "not found"."""
        self.put(server, "dir/a", b"1")
        url = self.at(client, server, "nope")
        assert failure(client, lambda: client.stat(url)) is Kind.NOT_FOUND

    def test_a_listing_reads_prefixes_as_directories_and_keys_as_files(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """``ListObjects``, ``/`` the delimiter: one level, deeper keys folded into prefixes."""
        for key in ("dir/a", "dir/sub/b", "top"):
            self.put(server, key, b"x")
        assert sorted(client.listdir(self.at(client, server, "dir"))) == ["a", "sub"]

    def test_a_listing_follows_every_page(self, server: StorageServer, client: Adapter) -> None:
        """A truncated listing is followed through every continuation token."""
        _s3(server).page_size = 1
        for name in ("a", "b", "c"):
            self.put(server, f"dir/{name}", b"x")
        assert sorted(client.listdir(self.at(client, server, "dir"))) == ["a", "b", "c"]
        listings = [r for r in server.requests if r.method == "GET"]
        assert len(listings) >= 3

    def test_unlink_removes_the_object(self, server: StorageServer, client: Adapter) -> None:
        """``DeleteObject``."""
        self.put(server, "dir/a", b"1")
        client.unlink(self.at(client, server, "dir/a"))
        assert server.store.object_entry(self.bucket, "dir/a") is None

    # -- data ----------------------------------------------------------------------------

    def test_an_object_is_read_whole_and_in_part(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """``GetObject``, whole and ranged."""
        self.put(server, "f", b"hello world")
        url = self.at(client, server, "f")
        assert client.read(url) == b"hello world"
        assert client.pread(url, 6, 5) == b"world"

    def test_a_small_object_is_one_put(self, server: StorageServer, client: Adapter) -> None:
        """Below the multipart threshold an object is one ``PutObject``."""
        client.write(self.at(client, server, "small"), b"0123456789")
        assert server.store.get_object(self.bucket, "small") == b"0123456789"
        assert [r.method for r in server.requests].count("PUT") == 1
        assert not [r for r in server.requests if "uploads" in r.target]

    def test_a_large_object_goes_up_in_parts(self, server: StorageServer, client: Adapter) -> None:
        """Past it: ``CreateMultipartUpload``, the parts, the completion; nothing left over."""
        pieces = [LARGE[at : at + PIECE] for at in range(0, len(LARGE), PIECE)]
        client.stream(self.at(client, server, "big"), pieces)
        assert server.store.get_object(self.bucket, "big") == LARGE
        assert len([r for r in server.requests if "partNumber=" in r.target]) > 1
        assert _s3(server).uploads == {} and _s3(server).aborted == []

    def test_a_part_that_fails_abandons_the_upload(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A part refused: the upload is aborted - no half-made object, no parts left billed."""
        _s3(server).failing_parts = {2}
        pieces = [LARGE[at : at + PIECE] for at in range(0, len(LARGE), PIECE)]
        url = self.at(client, server, "big")
        failure(client, lambda: client.stream(url, pieces))
        assert _s3(server).aborted and _s3(server).uploads == {}
        assert server.store.object_entry(self.bucket, "big") is None

    def test_a_completion_that_fails_inside_its_200_abandons_the_upload(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """S3 reports a failed completion in the body of a ``200``; that is a failure, and the
        upload is aborted.
        """
        _s3(server).complete_fails = True
        pieces = [LARGE[at : at + PIECE] for at in range(0, len(LARGE), PIECE)]
        url = self.at(client, server, "big")
        failure(client, lambda: client.stream(url, pieces))
        assert _s3(server).aborted
        assert server.store.object_entry(self.bucket, "big") is None

    # -- renames ---------------------------------------------------------------------------

    def test_a_rename_is_a_server_side_copy_then_a_delete(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """S3 has no rename: ``CopyObject`` (``x-amz-copy-source``), then ``DeleteObject``."""
        self.put(server, "old", b"x")
        client.rename(self.at(client, server, "old"), self.at(client, server, "new"))
        assert server.store.get_object(self.bucket, "new") == b"x"
        assert server.store.object_entry(self.bucket, "old") is None
        assert any(r.header("x-amz-copy-source") for r in server.requests if r.method == "PUT")

    def test_a_copy_that_fails_inside_its_200_keeps_the_source(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A ``CopyObject`` that failed inside its ``200``: the source is the only copy, so it is
        not deleted.
        """
        self.put(server, "old", b"x")
        _s3(server).copy_fails = True
        source, target = self.at(client, server, "old"), self.at(client, server, "new")
        failure(client, lambda: client.rename(source, target))
        assert server.store.get_object(self.bucket, "old") == b"x"
        assert "DELETE" not in [r.method for r in server.requests]

    # -- checksums and signatures -------------------------------------------------

    def test_the_etag_of_a_single_put_is_its_md5(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """The ``ETag`` of an object written in one ``PUT`` is its MD5."""
        self.put(server, "f", b"tiny")
        url = self.at(client, server, "f")
        assert client.checksum(url, "md5") == hashlib.md5(b"tiny").hexdigest()

    def test_a_digest_s3_does_not_keep_is_unsupported(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """S3 keeps no adler32: "unsupported"."""
        self.put(server, "f", b"tiny")
        url = self.at(client, server, "f")
        assert failure(client, lambda: client.checksum(url, "adler32")) is Kind.UNSUPPORTED

    def test_a_signature_the_store_disagrees_with_is_refused(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A signature made with the wrong secret is refused with ``403``: a permission failure."""
        self.put(server, "f", b"x")
        _s3(server).secret_key = "not the one the client signs with"
        url = self.at(client, server, "f")
        assert failure(client, lambda: client.read(url)) is Kind.PERMISSION
