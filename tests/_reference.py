"""The smallest client that passes the conformance suites: xrdhttp's own pieces, wired up.

:mod:`xrdhttp.testing.conformance` is run in this repository against this
adapter, so the suites are proved passable by a correct client and covered
by xrdhttp's own tests, with no client package installed. It is also the
worked example of an adapter: every operation is one or two requests on an
:class:`xrdhttp.session.Session`, its answer read with the library's own
parsers (:mod:`xrdhttp.webdav`, :mod:`xrdhttp.tape`, :mod:`xrdhttp.tpc`).

Errors are POSIX's: a status a verb did not want becomes an ``OSError``
with the errno WebDAV gives it for that verb (``MKCOL``'s 405 is "exists",
``PUT``'s 409 a missing parent), which the adapter base class reads.
"""

from __future__ import annotations

import base64
import errno
import json
import os
import urllib.parse
from collections.abc import Mapping, Sequence

from xrdcore import safexml
from xrdhttp import tape, tpc, webdav
from xrdhttp.session import Auth, Policy, RedirectError, Response, Session
from xrdhttp.testing import StorageServer
from xrdhttp.testing.conformance import Adapter, Kind, Progress, Stat

#: The errno each unwanted status means, whatever the verb; :data:`_VERB_ERRNO` refines it.
_STATUS_ERRNO = {401: errno.EACCES, 403: errno.EACCES, 404: errno.ENOENT, 501: errno.ENOTSUP}

#: WebDAV's per-verb readings of the statuses it reuses (RFC 4918 sections 9.3, 9.6, 9.7).
_VERB_ERRNO = {
    ("MKCOL", 405): errno.EEXIST,
    ("MKCOL", 409): errno.ENOENT,
    ("PUT", 409): errno.ENOENT,
    ("PUT", 412): errno.EEXIST,
    ("DELETE", 409): errno.ENOTEMPTY,
    ("COPY", 412): errno.EEXIST,
}

#: How many times a read whose connection died is resumed before it fails.
_RESUMES = 4

#: The ``PROPFIND`` body: only the properties a :class:`Stat` is made of.
_PROPFIND = (
    b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/>'
    b"<D:getcontentlength/><D:getlastmodified/></D:prop></D:propfind>"
)


def raise_for(method: str, response: Response, wanted: Sequence[int]) -> Response:
    """``response`` if its status is ``wanted``; otherwise read and close it, and raise."""
    if response.status in wanted:
        return response
    detail = response.body(1024).decode("utf-8", "replace")
    code = _VERB_ERRNO.get((method, response.status), _STATUS_ERRNO.get(response.status, errno.EIO))
    raise OSError(code, f"{method} answered {response.status}: {detail}")


class ReferenceAdapter(Adapter):
    """The conformance suites' reference client, over one :class:`~xrdhttp.session.Session`."""

    def __init__(self, server: StorageServer) -> None:
        """A session with xrdhttp's defaults; ``server`` is where tape requests go."""
        self.server = server
        self.session = Session(policy=Policy(connect_timeout=30.0, timeout=60.0))
        self.auth = Auth()

    def kind(self, error: BaseException) -> Kind:
        """POSIX's reading, plus the session's own word for a redirect chain."""
        if isinstance(error, RedirectError):
            return Kind.REDIRECTS
        if isinstance(error, ValueError):
            return Kind.PROTOCOL
        return super().kind(error)

    def close(self) -> None:
        """Drop the pooled connections."""
        self.session.close()

    def authorise(self, token: str) -> None:
        """Send ``token`` as a bearer token from now on."""
        self.auth = Auth(headers={"Authorization": f"Bearer {token}"})

    def time_limit(self, seconds: float) -> None:
        """A new session whose reads wait at most ``seconds``."""
        self.session.close()
        self.session = Session(policy=Policy(connect_timeout=seconds, timeout=seconds))

    def _send(
        self,
        method: str,
        url: str,
        wanted: Sequence[int],
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Response:
        """One request, its unwanted statuses raised as ``OSError``."""
        response = self.session.request(method, url, body=body, headers=headers, auth=self.auth)
        return raise_for(method, response, wanted)

    def _done(
        self, method: str, url: str, wanted: Sequence[int], headers: Mapping[str, str] | None = None
    ) -> None:
        """A request whose answer is its status alone."""
        self._send(method, url, wanted, headers=headers).body()

    # -- the namespace -----------------------------------------------------------------

    def _propfind(self, url: str, depth: str) -> list[tuple[str, webdav.Resource]]:
        """``(path, resource)`` for every response of a ``PROPFIND``."""
        headers = {"Depth": depth, "Content-Type": "application/xml"}
        answer = self._send("PROPFIND", url, (207,), body=_PROPFIND, headers=headers).body()
        root = safexml.fromstring(answer)
        if root.tag != webdav.DAV + "multistatus":
            raise ValueError("a PROPFIND answered with something that is not a multistatus")
        found = []
        for response in root.findall(webdav.DAV + "response"):
            href = webdav.text(response, "href")
            if not href:
                raise ValueError("a multistatus response names no resource")
            found.append((webdav.href_path(href).rstrip("/") or "/", webdav.resource(response)))
        return found

    def stat(self, url: str) -> Stat:
        """Depth 0: the one resource ``url`` names."""
        found = self._propfind(url, "0")
        if not found:
            raise ValueError("a multistatus with nothing in it")
        resource = found[0][1]
        return Stat(resource.size, resource.is_dir, resource.mtime)

    def listdir(self, url: str) -> list[str]:
        """Depth 1, the collection itself left out however its ``href`` is spelt."""
        own = urllib.parse.unquote(urllib.parse.urlsplit(url).path).rstrip("/") or "/"
        return [os.path.basename(path) for path, _ in self._propfind(url, "1") if path != own]

    def mkdir(self, url: str) -> None:
        """``MKCOL``."""
        self._done("MKCOL", url, (201,))

    def makedirs(self, url: str) -> None:
        """``MKCOL`` from the top down, a collection already there skipped."""
        parts = urllib.parse.urlsplit(url)
        path = ""
        for name in parts.path.strip("/").split("/"):
            path += "/" + name
            try:
                self.mkdir(urllib.parse.urlunsplit(parts._replace(path=path)))
            except FileExistsError:
                continue

    def rmdir(self, url: str) -> None:
        """``DELETE``, after checking there is nothing in it (a server may delete it all)."""
        if self.listdir(url):
            raise OSError(errno.ENOTEMPTY, f"{url} is not empty")
        self._done("DELETE", url.rstrip("/") + "/", (200, 204))

    def unlink(self, url: str) -> None:
        """``DELETE``."""
        self._done("DELETE", url, (200, 204))

    def rename(self, source: str, destination: str) -> None:
        """``MOVE``, the destination named in full."""
        self._done("MOVE", source, (201, 204), {"Destination": destination, "Overwrite": "T"})

    # -- data ----------------------------------------------------------------------------

    def read(self, url: str) -> bytes:
        """``GET``, resumed from where it got to if the connection dies."""
        return self._resumed(url, 0, None)

    def pread(self, url: str, offset: int, size: int) -> bytes:
        """A ranged ``GET``, resumed in the same way."""
        return self._resumed(url, offset, offset + size)

    def _resumed(self, url: str, start: int, end: int | None) -> bytes:
        """Bytes ``start`` to ``end`` (the end of the file for ``None``), a few drops forgiven."""
        got = bytearray()
        for _ in range(_RESUMES):
            try:
                self._range(url, start + len(got), end, got)
            except ConnectionError:
                continue
            return bytes(got if end is None else got[: end - start])
        raise OSError(errno.EIO, f"{url}: the connection kept dropping")

    def _range(self, url: str, start: int, end: int | None, into: bytearray) -> None:
        """One ``GET`` from ``start``, appended to ``into`` as it arrives.

        A server that ignored the range (``200``) is skipped forward and cut
        down to it; a ``416`` is the end of the file.
        """
        last = "" if end is None else str(end - 1)
        headers = {"Range": f"bytes={start}-{last}"} if start or end is not None else {}
        response = self._send("GET", url, (200, 206, 416), headers=headers)
        with response:
            if response.status == 416:
                return
            skip = start if response.status == 200 else 0
            while chunk := response.read(65536):
                chunk, skip = chunk[skip:], max(0, skip - len(chunk))
                into += chunk

    def write(self, url: str, data: bytes) -> None:
        """One ``PUT`` with a length (``Expect: 100-continue`` when it is large)."""
        self._send("PUT", url, (200, 201, 204), body=data).body()

    def stream(self, url: str, chunks: Sequence[bytes]) -> None:
        """A chunked ``PUT``, each chunk written as it comes."""
        upload = self.session.upload("PUT", url, None, auth=self.auth)
        for chunk in chunks:
            upload.write(chunk)
        raise_for("PUT", upload.finish(), (200, 201, 204)).body()

    def checksum(self, url: str, algorithm: str) -> str:
        """``Want-Digest`` on a ``HEAD``; ``Content-MD5`` for an MD5 a server sent no other way."""
        response = self._send("HEAD", url, (200,), headers={"Want-Digest": algorithm})
        response.body()
        value = webdav.pick_digest(response.header("Digest"), algorithm)
        if not value and algorithm.lower() == "md5" and response.header("Content-MD5"):
            value = base64.b64decode(response.header("Content-MD5")).hex()
        if not value:
            raise OSError(errno.ENOTSUP, f"no {algorithm} digest offered for {url}")
        return value

    # -- third-party copy --------------------------------------------------------------

    def copy(
        self, source: str, destination: str, *, push: bool = False, progress: Progress | None = None
    ) -> None:
        """A ``COPY`` to the active end, its markers followed to the outcome."""
        near, far = tpc.ends("push" if push else "pull", source, destination)
        token = self.auth.headers.get("Authorization", "").partition(" ")[2] or None
        headers = tpc.copy_headers(far, tpc.CopyOptions("push" if push else "pull", token=token))
        response = self._send("COPY", near, (201, 202), headers=headers)

        def report(total: int, marker: tpc.Marker | None) -> None:
            """Every marker that counted bytes, as the running total."""
            if progress is not None and marker is not None:
                progress(total)

        with response:
            outcome = tpc.follow_markers(response.readline, report)
        if outcome.kind != "success":
            detail, status = tpc.failure_detail(outcome.line)
            code = _STATUS_ERRNO.get(status or 0, errno.EIO)
            raise OSError(code if outcome.kind == "failure" else errno.EPROTO, detail)

    # -- the WLCG tape REST API -----------------------------------------------------

    def _tape(self) -> tape.TapeClient:
        """The tape verbs over this session, rooted at the server the adapter was made for."""

        def send(
            method: str,
            path: str,
            body: bytes | None,
            headers: Mapping[str, str],
            expect: tuple[int, ...],
        ) -> tape.Reply:
            """One tape call; the answer read whole, so it can be handed back."""
            response = self._send(
                method, self.server.base + path, expect, body=body, headers=headers
            )
            return _Read(response.body(), response.header("Location"))

        return tape.TapeClient(send)

    def _paths(self, urls: Sequence[str]) -> list[str]:
        """The server paths ``urls`` name, as the tape API names files."""
        return [urllib.parse.unquote(urllib.parse.urlsplit(url).path) for url in urls]

    def stage(self, urls: Sequence[str]) -> str:
        """``POST stage``."""
        return self._tape().stage(self._paths(urls))

    def poll(self, request: str, urls: Sequence[str]) -> list[bool]:
        """``GET stage/<id>``; a file the request failed for is ``ENOENT``."""
        found = self._tape().status(request, self._paths(urls))
        for status in found:
            if status.error:
                raise OSError(errno.ENOENT, f"{status.path}: {status.error}")
        return [status.online for status in found]

    def release(self, request: str, urls: Sequence[str]) -> None:
        """``POST release/<id>``."""
        self._tape().release(request, self._paths(urls))

    def abort(self, request: str, urls: Sequence[str]) -> None:
        """``POST stage/<id>/cancel``."""
        self._tape().cancel_files(request, self._paths(urls))

    def on_tape(self, urls: Sequence[str]) -> list[bool]:
        """``POST archiveinfo``."""
        return [status.on_tape for status in self._tape().archive_info(self._paths(urls))]

    # -- tokens ---------------------------------------------------------------------------

    def macaroon(self, url: str, activities: Sequence[str]) -> str:
        """The dCache macaroon request: a ``POST`` of ``application/macaroon-request``."""
        request = {"caveats": [f"activity:{','.join(activities)}"], "validity": "PT10M"}
        headers = {"Content-Type": "application/macaroon-request"}
        body = json.dumps(request).encode()
        answer = self._send("POST", url, (200,), body=body, headers=headers).body()
        document = json.loads(answer)
        if not isinstance(document, dict) or not document.get("macaroon"):
            raise ValueError("the server minted no macaroon")
        return str(document["macaroon"])


class _Read:
    """A tape answer already read: its body, and its ``Location``."""

    def __init__(self, body: bytes, location: str) -> None:
        """Keep what :class:`~xrdhttp.tape.TapeClient` reads."""
        self.body = body
        self._location = location

    def header(self, name: str) -> str:
        """``Location`` (the only header the tape verbs read)."""
        return self._location
