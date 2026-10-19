"""HTTP third-party copy: ``COPY`` with ``Source`` (pull) or ``Destination`` (push).

The server answers ``202`` and streams the outcome as a chunked body -
performance markers, then ``success:`` or ``failure:`` - as dCache, StoRM
and XrdHttp do, in their text format (tab-indented fields, one stripe).
The transfer really happens, inside the request: the handler thread itself
fetches from (or pushes to) the other server - which may well be this one,
over a new connection and so a new thread - because the point of the
exercise is that the client never sees the bytes. Headers named
``TransferHeader<Name>`` on the ``COPY`` are forwarded to the other side as
``<Name>``, per the WLCG HTTP-TPC convention; that is how a client passes
the remote side's ``Authorization``.

When delegation is on (:attr:`~xrdhttp.testing.StorageServer.delegation`)
the reply first names the delegation endpoint (``X-Delegate-To``) and the
copy waits for the server's :data:`~xrdhttp.testing.DelegationService` to
receive the proxy. The ``tpc`` and ``tpc_failure`` switches turn this into
the misbehaving variants tests need.
"""

from __future__ import annotations

import contextlib
import http.client
import time
import urllib.parse
from collections.abc import Iterator

from ._base import HandlerBase
from ._store import CHUNK

#: The far side's answer to a pull, and the connection carrying it.
_Pulled = tuple[http.client.HTTPConnection, http.client.HTTPResponse]


class _Failure(Exception):
    """What the ``failure:`` line will say. Never reaches the status line."""


class TPCMixin(HandlerBase):
    """``COPY`` and the outbound requests it makes to the other storage element."""

    def _dav_copy(self) -> None:
        """``COPY``: pull from ``Source`` into the path, or push the path to ``Destination``.

        Refusals come before the ``202``: no third-party copy here (501),
        not exactly one of ``Source`` and ``Destination`` (400), and
        ``Overwrite: F`` onto an existing file (412). From the ``202`` on,
        the outcome is in the body.
        """
        app = self.app
        app.copies.append(dict(self.headers.items()))
        source = self.headers.get("Source")
        destination = self.headers.get("Destination")
        exists = app.store.entry(self.target) is not None
        if app.no_tpc:
            self._reply(501, b"no third-party copy here")
        elif bool(source) == bool(destination):
            self._reply(400, b"exactly one of Source and Destination is required")
        elif self.headers.get("Overwrite", "T") == "F" and exists:
            self._reply(412, b"exists")
        elif app.tpc == "xrootd":
            # XrdHttp without TPC: a bare "OK" and a hang-up.
            self.close_connection = True
            self._reply(200, b"OK", {"Connection": "Close"})
        else:
            self._copy(source, destination)

    def _copy(self, source: str | None, destination: str | None) -> None:
        """Answer ``202``, wait for a delegated proxy if one was asked for, then copy."""
        app = self.app
        # A client sends "Credential: none" for token-authorised copies; only
        # "gridsite" (the default when absent) lets the server delegate.
        delegate = app.delegation and self.headers.get("Credential", "gridsite") == "gridsite"
        self.send_response(202)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Transfer-Encoding", "chunked")
        if delegate:
            app._delegation_reset()
            self.send_header("X-Delegate-To", f"{app.base}/gridsite-delegation")
        self.end_headers()
        if delegate and not app._delegation_wait(app.delegation_timeout):
            # One write: the client hangs up on reading "failure", and a
            # second write could then hit a closed socket.
            line = b"failure: no delegated credential arrived\n"
            self.wfile.write(b"%x\r\n%s\r\n0\r\n\r\n" % (len(line), line))
            return
        try:
            moved, streamed = self._transfer(source, destination)
        except _Failure as exc:
            self._outcome(0, str(exc))
        else:
            self._outcome(moved, app.tpc_failure, markers=not streamed)

    def _transfer(self, source: str | None, destination: str | None) -> tuple[int, bool]:
        """Move the bytes: how many there were, and whether markers went out as they moved.

        Nothing moves with ``tpc_failure`` set.
        """
        if self.app.tpc_failure:
            return 0, False
        if source:
            return self._pull(source), self.app.marker_every is not None
        found = self.app.store.entry(self.target)
        if found is None or found.collection:
            missing = f"{self.target} is not here to push"
            raise _Failure(f"HTTP 404 : the source does not exist: {missing}")
        self._push(str(destination), found.size)
        return found.size, False

    def _outcome(self, size: int, failure: str | None, *, markers: bool = True) -> None:
        """The performance markers, then the outcome line (unless ``tpc="eof"``), then the end.

        :attr:`~xrdhttp.testing.StorageServer.tpc_markers` markers report
        evenly spaced progress up to ``size``, each after
        :attr:`~xrdhttp.testing.StorageServer.tpc_marker_gap` seconds - a
        transfer that is slow but alive, the way a long one looks.
        """
        app = self.app
        count = max(app.tpc_markers, 0) if markers else 0
        for step in range(1, count + 1):
            time.sleep(app.tpc_marker_gap)
            self._marker(size * step // count)
        time.sleep(app.tpc_marker_gap)
        if app.tpc != "eof":
            self._chunk(f"failure: {failure}\n" if failure else "success: Created\n")
        self.wfile.write(b"0\r\n\r\n")

    def _marker(self, moved: int) -> None:
        """One performance marker in the dCache/XrdHttp text format, one stripe.

        A client parses ``Stripe Bytes Transferred`` for progress and stall
        detection; the field names and tab indentation are the servers'.
        """
        self._chunk(
            "Perf Marker\n"
            f"\tTimestamp: {int(time.time())}\n"
            "\tStripe Index: 0\n"
            f"\tStripe Bytes Transferred: {moved}\n"
            "\tTotal Stripe Count: 1\n"
            "End\n"
        )

    def _chunk(self, text: str) -> None:
        """One chunk of the marker stream, flushed so the client sees progress as it happens."""
        payload = text.encode()
        self.wfile.write(b"%x\r\n%s\r\n" % (len(payload), payload))
        self.wfile.flush()

    # -- the far side --------------------------------------------------------------------------

    def _remote(self, url: str) -> http.client.HTTPConnection:
        """A connection to the far side; HTTPS with the server's ``client_tls``.

        ``client_tls=None`` means :mod:`http.client`'s default context, which
        will not trust a test CA. Any scheme but ``http(s)`` is a failure
        whose text leads with an HTTP status, as a real server's does,
        because clients report from that line.
        """
        parts = urllib.parse.urlsplit(url)
        if parts.scheme == "https":
            return http.client.HTTPSConnection(
                parts.netloc, context=self.app.client_tls, timeout=30
            )
        if parts.scheme == "http":
            return http.client.HTTPConnection(parts.netloc, timeout=30)
        raise _Failure(f"HTTP 400 cannot speak {parts.scheme or '<none>'} to the far side")

    def _forwarded(self) -> dict[str, str]:
        """The ``TransferHeader<Name>`` headers of the ``COPY``, as ``<Name>``."""
        prefix = "TransferHeader"
        return {
            name[len(prefix) :]: value
            for name, value in self.headers.items()
            if name.startswith(prefix)
        }

    def _pull(self, source: str) -> int:
        """Pull mode: ``GET`` the source into the path, creating its parents."""
        connection, response = self._get(source)
        with contextlib.closing(connection):
            if response.status != 200:
                raise _Failure(f"source answered HTTP {response.status}")
            moved = 0

            every = self.app.marker_every
            piece = every if every is not None else CHUNK

            def chunks() -> Iterator[bytes]:
                nonlocal moved
                for chunk in iter(lambda: response.read(piece), b""):
                    moved += len(chunk)
                    if every is not None:
                        self._marker(moved)
                    yield chunk

            self.app.store.write(self.target, chunks())
        return moved

    def _get(self, source: str) -> _Pulled:
        """Send the pull's ``GET``; an unreachable source is a failure."""
        connection = self._remote(source)
        parts = urllib.parse.urlsplit(source)
        target = parts.path + (f"?{parts.query}" if parts.query else "")
        try:
            connection.request("GET", target, headers=self._forwarded())
            return connection, connection.getresponse()
        except OSError as exc:
            connection.close()
            raise _Failure(
                f"could not reach the source (cannot reach {parts.netloc}: {exc})"
            ) from exc

    def _push(self, destination: str, size: int) -> None:
        """Push mode: ``PUT`` the file to the destination, which must accept it."""
        connection = self._remote(destination)
        parts = urllib.parse.urlsplit(destination)
        target = parts.path + (f"?{parts.query}" if parts.query else "")
        headers = {**self._forwarded(), "Content-Length": str(size)}
        with contextlib.closing(connection), self.app.store.open(self.target) as body:
            try:
                connection.request("PUT", target, body=body, headers=headers)
                response = connection.getresponse()
                response.read()
            except OSError as exc:
                raise _Failure(
                    f"could not reach the destination (cannot reach {parts.netloc}: {exc})"
                ) from exc
        if response.status not in (200, 201, 204):
            raise _Failure(f"destination answered HTTP {response.status}")
