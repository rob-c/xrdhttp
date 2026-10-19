"""The reference adapter's S3 dialect: SigV4 on every hop, a bucket read as a filesystem.

The smallest S3 client that passes :class:`~xrdhttp.testing.conformance.S3Suite`,
made of :mod:`xrdhttp.s3` (the signature, the answer codec) on the reference
session. Path-style addressing (``http://host:port/bucket/key``), as an
explicit endpoint is addressed; a prefix is a directory when anything is
listed under it.
"""

from __future__ import annotations

import errno
import urllib.parse
from collections.abc import Sequence
from typing import Any

from xrdhttp.s3 import codec, sigv4
from xrdhttp.session import Auth, Hop, Route
from xrdhttp.testing import StorageServer
from xrdhttp.testing.conformance import Stat

from tests._reference import ReferenceAdapter

#: The bytes sent per part: tiny, so the suite's large object goes up in several.
PART = 1500


class ReferenceS3(ReferenceAdapter):
    """:class:`~tests._reference.ReferenceAdapter`, signing for the fake's S3 keys."""

    def __init__(self, server: StorageServer) -> None:
        """Sign every hop with the keys ``server``'s S3 dialect expects."""
        super().__init__(server)
        assert server.s3 is not None
        self.credentials = sigv4.Credentials(server.s3.access_key, server.s3.secret_key)
        self.auth = Auth(prepare=self._sign)

    def _sign(self, hop: Hop) -> None:
        """SigV4 over the hop as it goes on the wire, its payload hashed when it is bytes."""
        route = Route.of(hop.url)
        body = hop.body if isinstance(hop.body, bytes | bytearray | memoryview) else None
        signed = sigv4.sign(
            hop.method,
            route.target,
            f"{route.host}:{route.port}",
            hop.headers,
            sigv4.hash_payload(body if hop.method in ("PUT", "POST") else b""),
            credentials=self.credentials,
            region="us-east-1",
        )
        hop.headers.update(signed)

    def _split(self, url: str) -> tuple[str, str, str]:
        """``(origin, bucket, key)`` of a path-style object URL."""
        parts = urllib.parse.urlsplit(url)
        bucket, _, key = urllib.parse.unquote(parts.path).lstrip("/").partition("/")
        return f"{parts.scheme}://{parts.netloc}", bucket, key

    def _page(self, url: str, prefix: str, token: str) -> dict[str, Any]:
        """One ``ListObjectsV2`` page under ``prefix``, decoded."""
        origin, bucket, _ = self._split(url)
        query = {"list-type": "2", "prefix": prefix, "delimiter": "/"}
        if token:
            query["continuation-token"] = token
        listing = f"{origin}/{bucket}?{urllib.parse.urlencode(query, quote_via=urllib.parse.quote)}"
        return codec.decode("ListObjectsV2", self._send("GET", listing, (200,)).body())

    def _listing(self, url: str) -> list[str]:
        """Every name directly under the prefix ``url`` names, every page followed."""
        prefix = self._split(url)[2].rstrip("/") + "/"
        names: list[str] = []
        token = ""
        while True:
            page = self._page(url, prefix, token)
            names += [name for name, _ in codec.listing_items(page, prefix)]
            token = page.get("NextContinuationToken", "")
            if not page.get("IsTruncated"):
                return names

    # -- the namespace -----------------------------------------------------------------

    def stat(self, url: str) -> Stat:
        """``HEAD`` the object; failing that, a prefix with anything under it is a directory."""
        response = self.session.request("HEAD", url, auth=self.auth)
        response.body()
        if response.status == 200:
            return Stat(response.length or 0)
        if self._listing(url):
            return Stat(0, True)
        raise OSError(errno.ENOENT, f"{url}: no object and nothing under it")

    def listdir(self, url: str) -> list[str]:
        """``ListObjectsV2`` with ``/`` as the delimiter."""
        return self._listing(url)

    def rename(self, source: str, destination: str) -> None:
        """``CopyObject`` (a failure may arrive inside its ``200``), then ``DeleteObject``."""
        _, bucket, key = self._split(source)
        copy = {"x-amz-copy-source": urllib.parse.quote(f"/{bucket}/{key}")}
        answer = self._send("PUT", destination, (200,), body=b"", headers=copy).body()
        if "Error" in codec.decode("CopyObject", answer):
            raise OSError(errno.EIO, "the server-side copy failed")
        self._done("DELETE", source, (200, 204))

    # -- data ----------------------------------------------------------------------------

    def stream(self, url: str, chunks: Sequence[bytes]) -> None:
        """A multipart upload of :data:`PART`-byte parts, abandoned if any step fails."""
        started = self._send("POST", f"{url}?uploads", (200,), body=b"").body()
        upload = codec.decode("CreateMultipartUpload", started)["UploadId"]
        named = f"uploadId={urllib.parse.quote(upload)}"
        data = b"".join(chunks)
        try:
            tags = [
                self._part(f"{url}?partNumber={number}&{named}", data[at : at + PART])
                for number, at in enumerate(range(0, len(data), PART), 1)
            ]
            done = self._send("POST", f"{url}?{named}", (200,), body=codec.manifest(tags)).body()
            if "Error" in codec.decode("CompleteMultipartUpload", done):
                raise OSError(errno.EIO, "the upload could not be completed")
        except OSError:
            self._done("DELETE", f"{url}?{named}", (200, 204))
            raise

    def _part(self, url: str, data: bytes) -> str:
        """One ``UploadPart``; its ``ETag``, which the completion lists."""
        response = self._send("PUT", url, (200,), body=data)
        response.body()
        return response.header("ETag")

    def checksum(self, url: str, algorithm: str) -> str:
        """The ``ETag`` of an object written in one ``PUT``, which is its MD5."""
        response = self._send("HEAD", url, (200,))
        response.body()
        tag = response.header("ETag").strip('"')
        if algorithm.lower() != "md5" or "-" in tag:
            raise OSError(errno.ENOTSUP, f"S3 keeps no {algorithm} of {url}")
        return tag
