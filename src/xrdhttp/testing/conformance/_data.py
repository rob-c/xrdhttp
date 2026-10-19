"""Data: reads (whole, ranged, resumed), uploads (sized, streamed, ``100-continue``), digests.

The checks every client of a storage element must pass with the bytes
themselves: a ranged read returns that range however the server answered
(``206``, a whole-body ``200``, a ``416`` past the end); a read whose
connection dies mid-body resumes where it got to instead of starting over
or returning short; an upload lands whole, announces itself with
``Expect: 100-continue`` so that a refusal or a redirect is heard before
the body is committed, and still goes through to a server that ignores
the expectation; a digest comes back as lower-case hex whatever form the
server wrote it in.

How many requests a client spends, how it frames a body (``Content-Length``
or chunked) and which retries it allows are its own strategy and are left
to its own suite.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from xrdcore.checksum import checksum_bytes

from .._server import StorageServer
from ._adapter import Adapter, Kind
from ._base import Conformance, failure

#: The file most read checks use.
BODY = b"hello world"

#: Large enough that every client asks ``Expect: 100-continue`` before sending it.
LARGE = bytes(range(256)) * 256


class ReadSuite(Conformance):
    """Whole and ranged reads, a server that ignores ranges, and reads that are cut short."""

    def test_a_file_is_read_whole(self, server: StorageServer, client: Adapter) -> None:
        """A plain ``GET`` of the whole file."""
        server.add_file("/d/f", BODY)
        assert client.read(client.url(server, "/d/f")) == BODY

    def test_a_range_is_read_with_a_range_request(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A read from an offset asks the server for that range rather than reading up to it."""
        server.add_file("/d/f", BODY)
        assert client.pread(client.url(server, "/d/f"), 6, 5) == b"world"
        ranges = [r.header("Range") or "" for r in server.requests if r.method == "GET"]
        assert any(value.startswith("bytes=6-") for value in ranges)

    def test_a_range_across_the_end_is_short(self, server: StorageServer, client: Adapter) -> None:
        """A range running past the end returns what there is: a short read, not an error."""
        server.add_file("/d/f", BODY)
        assert client.pread(client.url(server, "/d/f"), 8, 10) == b"rld"

    def test_a_range_past_the_end_is_empty(self, server: StorageServer, client: Adapter) -> None:
        """A range wholly past the end is empty, whether the server answers ``416`` or the client
        never asks.
        """
        server.add_file("/d/f", BODY)
        assert client.pread(client.url(server, "/d/f"), 100, 3) == b""

    def test_a_server_that_ignores_ranges_still_gives_the_right_bytes(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A server (or a cache in front of it) may answer a ranged ``GET`` with the whole file; the
        client must skip to the offset, not return the start.
        """
        server.add_file("/d/f", BODY)
        server.ignore_ranges = True
        assert client.pread(client.url(server, "/d/f"), 6, 3) == b"wor"

    def test_reading_nothing_is_not_found(self, server: StorageServer, client: Adapter) -> None:
        """A ``GET`` (or the stat before it) of a missing file is "not found"."""
        server.add_dir("/d")
        url = client.url(server, "/d/nope")
        assert failure(client, lambda: client.read(url)) is Kind.NOT_FOUND

    def test_a_refused_read_is_a_permission_failure(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A ``403`` on the ``GET`` itself, after a stat that succeeded, is a permission failure."""
        server.add_file("/d/f", BODY)
        server.fault("GET", status=403)
        url = client.url(server, "/d/f")
        assert failure(client, lambda: client.read(url)) is Kind.PERMISSION

    def test_a_read_cut_short_resumes_where_it_got_to(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """The answer promised the whole file and died at 3000 bytes: ask for the rest."""
        server.add_file("/d/f", LARGE)
        server.fault("GET", truncate=3000, times=1)
        assert client.read(client.url(server, "/d/f")) == LARGE
        ranges = [r.header("Range") or "" for r in server.requests if r.method == "GET"]
        assert ranges[-1].startswith("bytes=3000-")

    def test_a_range_cut_short_resumes_where_it_got_to(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """The same for a ranged read: the resumed request asks only for what is still missing."""
        server.add_file("/d/f", LARGE)
        server.fault("GET", truncate=3000, times=1)
        assert client.pread(client.url(server, "/d/f"), 0, len(LARGE)) == LARGE
        ranges = [r.header("Range") or "" for r in server.requests if r.method == "GET"]
        assert ranges[-1].startswith("bytes=3000-")


class UploadSuite(Conformance):
    """Uploads that land, that ask first, that are refused, redirected or have nowhere to go."""

    def test_a_small_file_lands(self, server: StorageServer, client: Adapter) -> None:
        """The bytes written are the bytes stored."""
        server.add_dir("/d")
        client.write(client.url(server, "/d/f"), BODY)
        assert server.contents("/d/f") == BODY

    def test_a_large_file_asks_before_it_is_sent(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """Past a few kilobytes the ``PUT`` carries ``Expect: 100-continue``, so a refusal or a
        redirect costs a round trip rather than the body.
        """
        server.add_dir("/d")
        client.write(client.url(server, "/d/f"), LARGE)
        assert server.contents("/d/f") == LARGE
        put = [r for r in server.requests if r.method == "PUT"][-1]
        assert (put.header("Expect") or "").lower() == "100-continue"

    def test_a_file_written_in_pieces_lands_whole(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """Pieces written one after another, an empty one among them (which must not end a chunked
        body), arrive as one file.
        """
        server.add_dir("/d")
        client.stream(client.url(server, "/d/f"), [LARGE, b"", BODY, LARGE])
        assert server.contents("/d/f") == LARGE + BODY + LARGE

    def test_an_empty_file_is_created(self, server: StorageServer, client: Adapter) -> None:
        """Writing nothing still creates the file, empty."""
        server.add_dir("/d")
        client.write(client.url(server, "/d/empty"), b"")
        assert server.contents("/d/empty") == b""

    def test_an_upload_replaces_what_was_there(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A ``PUT`` over an existing file replaces it whole."""
        server.add_file("/d/f", LARGE)
        client.write(client.url(server, "/d/f"), BODY)
        assert server.contents("/d/f") == BODY

    def test_a_server_that_ignores_the_expectation_still_gets_the_body(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """HTTP lets a server never send ``100 Continue``: the client waits, then sends."""
        server.add_dir("/d")
        server.expect_continue = False
        client.write(client.url(server, "/d/f"), LARGE)
        assert server.contents("/d/f") == LARGE

    def test_a_refusal_before_the_body_is_the_answer(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """Refused before ``100 Continue``: the refusal is reported, not a broken pipe."""
        server.add_dir("/d")
        server.check_before_continue, server.drain_refused = True, False
        server.fault("PUT", status=403)
        url = client.url(server, "/d/f")
        assert failure(client, lambda: client.write(url, LARGE)) is Kind.PERMISSION
        assert server.store.entry("/d/f") is None

    def test_a_server_that_fails_the_upload_is_reported(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A ``507`` is the server's failure, reported as such - not a missing file - and nothing is
        stored.
        """
        server.add_dir("/d")
        server.fault("PUT", status=507)
        url = client.url(server, "/d/f")
        assert failure(client, lambda: client.write(url, BODY)) is not Kind.NOT_FOUND
        assert server.store.entry("/d/f") is None

    def test_an_upload_into_nothing_is_not_found(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """A ``PUT``'s 409 is a missing parent, not an existing target."""
        server.add_dir("/d")
        url = client.url(server, "/d/no/such/f")
        assert failure(client, lambda: client.write(url, BODY)) is Kind.NOT_FOUND

    def test_an_upload_follows_a_redirect_before_its_body(
        self, server: StorageServer, peer: StorageServer, client: Adapter
    ) -> None:
        """A head node redirects the ``PUT`` to a disk server; the bytes go there only."""
        server.add_dir("/d")
        peer.add_dir("/d")
        server.redirect_prefixes["/d/moved"] = peer.base
        # A head node: it answers before the body and hangs up rather than read it.
        server.check_before_continue, server.drain_refused = True, False
        client.write(client.url(server, "/d/moved"), LARGE)
        client.stream(client.url(server, "/d/moved2"), [LARGE, BODY])
        assert peer.contents("/d/moved") == LARGE
        assert peer.contents("/d/moved2") == LARGE + BODY
        assert server.store.entry("/d/moved") is None


#: Every algorithm both clients ask a server for, with its local computation.
ALGORITHMS = ("adler32", "crc32c", "md5", "sha256")


class ChecksumSuite(Conformance):
    """Server-side digests: ``Want-Digest``, ``Content-MD5``, and none at all."""

    @pytest.mark.parametrize("algorithm", ALGORITHMS)
    def test_every_digest_comes_back_as_hex(
        self, server: StorageServer, client: Adapter, algorithm: str
    ) -> None:
        """Asked with ``Want-Digest`` on a ``HEAD``; the value comes back as lower-case hex whether
        the server sent hex (adler32, crc32c) or base64 (md5, sha256).
        """
        server.add_file("/d/f", BODY)
        expected = checksum_bytes(algorithm, BODY)
        assert client.checksum(client.url(server, "/d/f"), algorithm) == expected
        asked = [r.header("Want-Digest") or "" for r in server.requests if r.method == "HEAD"]
        assert asked and all(value for value in asked)

    def test_a_digest_field_in_capitals_is_still_ours(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """Algorithm names in ``Digest`` are case-insensitive (RFC 3230), and the hex is
        lower-cased.
        """
        server.add_file("/d/f", BODY)
        server.fault("HEAD", status=200, headers={"Digest": "ADLER32=DEADBEEF"})
        assert client.checksum(client.url(server, "/d/f"), "adler32") == "deadbeef"

    def test_a_content_md5_is_an_md5(self, server: StorageServer, client: Adapter) -> None:
        """A server sending only ``Content-MD5`` (base64, RFC 1864) has answered for MD5."""
        server.add_file("/d/f", BODY)
        digest = hashlib.md5(BODY).digest()
        server.fault("HEAD", status=200, headers={"Content-MD5": base64.b64encode(digest).decode()})
        assert client.checksum(client.url(server, "/d/f"), "md5") == digest.hex()

    def test_a_digest_the_server_does_not_offer_is_unsupported(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """No digest of that kind is "unsupported", never a made-up value or an empty one."""
        server.add_file("/d/f", BODY)
        server.digests = {"adler32"}
        url = client.url(server, "/d/f")
        assert failure(client, lambda: client.checksum(url, "sha256")) is Kind.UNSUPPORTED

    def test_the_digest_of_nothing_is_not_found(
        self, server: StorageServer, client: Adapter
    ) -> None:
        """The digest of a missing file is "not found"."""
        server.add_dir("/d")
        url = client.url(server, "/d/nope")
        assert failure(client, lambda: client.checksum(url, "adler32")) is Kind.NOT_FOUND
