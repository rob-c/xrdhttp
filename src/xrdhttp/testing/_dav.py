"""WebDAV proper: the namespace and data methods.

``OPTIONS``, ``PROPFIND`` (depth 0 and 1), ``MKCOL``, ``DELETE``, ``MOVE``,
``GET`` and ``HEAD`` with ``Range`` (one, several as
``multipart/byteranges``, or none satisfiable as ``416``), RFC 3230
``Want-Digest`` and RFC 9530 ``Want-Repr-Digest``, and ``PUT`` (whole,
``Content-Length`` or chunked, ``If-None-Match: *``). Every handler works
on the decoded, normalised request path (:attr:`~._base.HandlerBase.target`)
through the server's :class:`~xrdhttp.testing.Store`.

Status codes follow RFC 4918 and what dCache, EOS, StoRM and XrdHttp send,
since clients map them to errors: 404 missing, 405 ``MKCOL`` on an existing
path or ``PUT`` onto a collection, 409 a missing parent (and, with
:attr:`~xrdhttp.testing.StorageServer.recursive_delete` off, a non-empty
collection on ``DELETE``), 412 an ``If-None-Match: *`` upload onto a file.
No locks, and no properties beyond the handful a client stats with.
"""

from __future__ import annotations

import posixpath
import urllib.parse
from collections.abc import Iterator
from email.utils import formatdate

from ._base import HandlerBase
from ._model import decoded
from ._replies import BOUNDARY, DAVEntry, multipart, propfind_reply, spans
from ._store import CHUNK, Entry


class DAVMixin(HandlerBase):
    """The ``_dav_<method>`` handlers :meth:`~._front.RequestHandler._route` falls back to."""

    def _dav_options(self) -> None:
        """Advertise WebDAV compliance classes 1 and 2 (unless WebDAV is off) and the methods."""
        headers = {"Allow": "GET,HEAD,PUT,DELETE,PROPFIND,MKCOL,MOVE,COPY,OPTIONS"}
        if not self.app.no_dav:
            headers["DAV"] = "1,2"
        self._reply(200, b"", headers)

    def _dav_propfind(self) -> None:
        """``PROPFIND`` (RFC 4918 section 9.1): a 207 multistatus for the path and its children.

        The request body is read and ignored: every entry carries the same
        few properties, which is what both clients ask for anyway. Children
        are listed unless ``Depth: 0``; ``Depth: infinity`` is treated as 1.
        """
        self._read_body()
        if self.app.no_dav:
            self._reply(405, b"PROPFIND not supported")
            return
        path = self.target
        found = self.app.store.entry(path)
        if found is None:
            self._reply(404, b"not found")
            return
        entries = [self._entry(path, found)]
        if found.collection and self.headers.get("Depth", "1") != "0":
            entries += self._children(path)
        reply = propfind_reply(entries)
        self._reply(reply.status, reply.body, reply.headers)

    def _entry(self, path: str, found: Entry) -> DAVEntry:
        """The multistatus entry for ``path``: its ``href`` encoded once, its name decoded."""
        return DAVEntry(
            urllib.parse.quote(path),
            found.collection,
            found.size,
            found.modified,
            found.created,
            path.rsplit("/", 1)[-1] or "/",
            length=self.app.collection_length,
        )

    def _children(self, path: str) -> list[DAVEntry]:
        """Entries for the children of collection ``path``, by name."""
        store = self.app.store
        found = []
        for name in store.children(path):
            child = posixpath.join(path, name)
            entry = store.entry(child)
            if entry is not None:  # neither a file nor a directory: not served
                found.append(self._entry(child, entry))
        return found

    def _dav_mkcol(self) -> None:
        """``MKCOL`` (RFC 4918 section 9.3): 201; 405 if the path exists, 409 if no parent."""
        path, store = self.target, self.app.store
        parent = store.entry(posixpath.dirname(path))
        if store.entry(path) is not None:
            self._reply(405, b"already exists")
        elif (parent is None or not parent.collection) and not self.app.mkcol_parents:
            self._reply(409, b"no parent collection")
        else:
            store.mkdir(path)
            self._reply(201, b"Created")

    def _dav_delete(self) -> None:
        """``DELETE`` a file, or a collection with all beneath it (grid-style: only if empty)."""
        path, store = self.target, self.app.store
        found = store.entry(path)
        if found is None:
            self._reply(404, b"not found")
        elif found.collection and not self.app.recursive_delete and store.children(path):
            self._reply(409, b"directory not empty")
        else:
            store.remove(path)
            self._reply(204)

    def _dav_move(self) -> None:
        """``MOVE`` to the ``Destination`` header's path, replacing a file there (204) or not (201).

        ``Overwrite`` is not consulted; a test that needs a refusal queues a
        fault or installs a :attr:`~xrdhttp.testing.StorageServer.handlers` entry.
        """
        source, store = self.target, self.app.store
        destination = decoded(self.headers.get("Destination", ""))
        if store.entry(source) is None:
            self._reply(404, b"not found")
            return
        existed = store.entry(destination) is not None
        store.move(source, destination)
        self._reply(204 if existed else 201)

    def _dav_post(self) -> None:
        """A ``POST`` that is neither a macaroon request nor a tape call."""
        self._read_body()
        self._reply(405, b"not allowed")

    # -- reading -----------------------------------------------------------------------------

    def _dav_head(self) -> None:
        """``HEAD``: the ``GET`` headers - length and digests intact - without the body."""
        self._dav_get()

    def _dav_get(self) -> None:
        """``GET`` a file (whole, ranged, multi-ranged), a collection, or a metalinked name.

        A collection answers
        :attr:`~xrdhttp.testing.StorageServer.collection_get_status`: 200
        with an empty page, as most storage elements answer a browser, or
        403; a client must use ``PROPFIND``, not this, to list.
        """
        path = self.target
        found = self.app.store.entry(path)
        link = self._link()
        if found is None:
            if link:
                self._reply(200, b"", link)
            else:
                self._reply(404, b"not found")
        elif found.collection:
            status = self.app.collection_get_status
            body = b"" if status == 200 else b"not a file"
            self._reply(status, body, {"Content-Type": "text/html", **link})
        else:
            self._get_file(path, found, link)

    def _link(self) -> dict[str, str]:
        """The ``Link`` header advertising this path's Metalink descriptor, if it has one."""
        descriptor = self.app.metalinks.get(self.target)
        if descriptor is None:
            return {}
        kind = 'rel="describedby"; type="application/metalink4+xml"'
        return {"Link": f"<{descriptor}>; {kind}"}

    def _get_file(self, path: str, found: Entry, link: dict[str, str]) -> None:
        """Serve one file, with digest, range and link headers as asked and switched."""
        headers = {
            "Last-Modified": formatdate(found.modified, usegmt=True),
            "Accept-Ranges": "bytes",
            **self._digest_headers(lambda: self._file_chunks(path)),
            **link,
        }
        span = None if self.app.ignore_ranges else self.headers.get("Range")
        chosen = spans(span, found.size, self._several())
        with self.app.store.open(path) as source:
            if chosen is None:
                self._send_content(200, headers, source, (0, found.size))
            elif not chosen:
                self._reply(416, b"", {"Content-Range": f"bytes */{found.size}"})
            elif len(chosen) == 1:
                start, end = chosen[0]
                headers["Content-Range"] = f"bytes {start}-{end - 1}/{found.size}"
                self._send_content(206, headers, source, (start, end - start))
            else:

                def read(start: int, count: int) -> bytes:
                    source.seek(start)
                    return source.read(count)

                body = multipart(read, chosen, found.size, "application/octet-stream")
                headers["Content-Type"] = f"multipart/byteranges; boundary={BOUNDARY}"
                self._reply(206, body, headers)

    def _file_chunks(self, path: str) -> Iterator[bytes]:
        """File ``path``'s bytes in pieces, for a digest."""
        with self.app.store.open(path) as handle:
            yield from iter(lambda: handle.read(CHUNK), b"")

    def _several(self) -> str:
        """What to do with several ranges, by the switches: coalesce, first only, or all."""
        if self.app.coalesce_ranges:
            return "coalesce"
        return "multipart" if self.app.multipart_ranges else "first"

    # -- writing -----------------------------------------------------------------------------

    def _dav_put(self) -> None:
        """Store a file, streamed: 201 if new, 204 if replaced.

        405 onto a collection; 409 with no parent collection (RFC 4918
        section 9.7.1); ``If-None-Match: *`` is honoured with 412 if the file
        exists, because that is how a no-overwrite upload is made atomic.
        """
        path, store = self.target, self.app.store
        found = store.entry(path)
        parent = store.entry(posixpath.dirname(path))
        if found is not None and found.collection:
            refusal: tuple[int, bytes] | None = (405, b"is a collection")
        elif self.headers.get("If-None-Match") == "*" and found is not None:
            refusal = (412, b"exists")
        elif parent is None or not parent.collection:
            refusal = (409, b"no parent collection")
        else:
            refusal = None
        if refusal is not None:
            self._settle_body()  # a refusal read in full keeps the connection
            self._reply(*refusal)
            return
        store.write(path, self._body_chunks())
        self._reply(201 if found is None else 204)
