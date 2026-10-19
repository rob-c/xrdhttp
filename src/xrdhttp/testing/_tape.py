"""Storage-class APIs: the WLCG Tape REST API and CDMI QoS.

The tape side follows the WLCG Tape REST API v1 as dCache and EOS/CTA
implement it, on the server's :class:`~xrdhttp.testing.Tape` state:

* ``GET /.well-known/wlcg-tape-rest-api`` - the discovery document (or the
  test's replacement for it);
* ``POST stage`` - ``201`` with a ``requestId`` (and ``Location``);
* ``GET stage/<id>`` - each file's ``state`` and ``onDisk``, worked out
  afresh at every poll (see :class:`~xrdhttp.testing.Tape` for the rules);
* ``POST stage/<id>/cancel``, ``POST release/<id>`` - ``{"paths": [...]}``;
  a release is recorded whatever its id, as gfal2 releases with a
  placeholder when it has none;
* ``DELETE stage/<id>`` - withdraw a whole request;
* ``POST archiveinfo`` - each path's ``locality``.

With no :attr:`~xrdhttp.testing.StorageServer.tape` every call is answered
:attr:`~xrdhttp.testing.StorageServer.tape_absent_status`, a site with no
tape behind its WebDAV door. Calls the API does not define are 404, as are
polls of unknown request ids. Staging is simulated by state the test
changes and by counting polls, so tests are deterministic and need no
timers.

CDMI QoS (SNIA CDMI 1.1 capabilities, as dCache exposes it to gfal2's QoS
calls) answers for the paths in :attr:`~xrdhttp.testing.StorageServer.qos`
and the ``/cdmi_capabilities/`` tree built from them.
"""

from __future__ import annotations

import json
from typing import Any

from ._base import HandlerBase
from ._model import Tape, clean

#: Localities that make a staging request fail.
_LOST = ("LOST", "NONE")


class TapeMixin(HandlerBase):
    """Tape REST and CDMI."""

    def _tape(self) -> None:
        """Serve the discovery document or one tape REST call."""
        tape = self.app.tape
        body = self._read_body()
        if tape is None:
            message = {"message": "there is no tape behind this endpoint"}
            self._json(self.app.tape_absent_status, message)
        elif self.target == "/.well-known/wlcg-tape-rest-api":
            self._discovery(tape)
        else:
            try:
                document: Any = json.loads(body) if body else {}
            except ValueError:
                self._json(400, {"message": "that is not a JSON document"})
                return
            self._tape_call(tape, self.target.split("/")[3:], document)

    def _tape_call(self, tape: Tape, route: list[str], document: Any) -> None:
        """One call under ``/api/v1``, by method and the path's remaining parts."""
        method = self.command
        one = route[1] if len(route) > 1 else ""
        if route[:1] == ["stage"]:
            self._stage_call(tape, route, one, document)
        elif route == ["release", one] and method == "POST":
            self._release(tape, one, document)
        elif route == ["archiveinfo"] and method == "POST":
            self._json(200, [self._locality(tape, path) for path in _paths(document)])
        else:
            self._no_endpoint()

    def _stage_call(self, tape: Tape, route: list[str], one: str, document: Any) -> None:
        """``stage``, ``stage/<id>`` and ``stage/<id>/cancel``, by method."""
        method = self.command
        if route == ["stage"] and method == "POST":
            self._stage(tape, document)
        elif route == ["stage", one] and method == "GET":
            self._poll(tape, one)
        elif route == ["stage", one] and method == "DELETE":
            self._withdraw(tape, one)
        elif route == ["stage", one, "cancel"] and method == "POST":
            self._cancel(tape, one, document)
        else:
            self._no_endpoint()

    def _no_endpoint(self) -> None:
        """A call the API does not define."""
        self._json(404, {"message": "no such endpoint"})

    def _discovery(self, tape: Tape) -> None:
        """The well-known document naming the site's tape endpoint, or the test's replacement.

        A :attr:`~xrdhttp.testing.Tape.discovery` of raw bytes is sent as it
        is - a malformed document, for the client's parser.
        """
        if isinstance(tape.discovery, bytes):
            self._reply(200, tape.discovery)
            return
        document = tape.discovery
        if document is None:
            uri = f"{self.app.base}{self.app.tape_endpoint}"
            endpoint = {"uri": uri, "version": tape.version, "metadata": {}}
            document = {
                "sitename": tape.sitename,
                "description": tape.description,
                "endpoints": [endpoint],
            }
        self._json(200, document)

    def _stage(self, tape: Tape, document: Any) -> None:
        """Take a bulk staging request: ``201`` with its id in the body and ``Location``."""
        files = [dict(entry) for entry in document.get("files", [])]
        if not files:
            self._json(400, {"message": "a staging request names at least one file"})
            return
        handle = f"stage-{len(tape.requests) + 1:04d}"
        while handle in tape.requests:  # a withdrawn request's id is never reissued
            handle += "x"
        tape.requests[handle] = {"files": files, "polls": 0}
        self._json(201, {"requestId": handle}, {"Location": f"/api/v1/stage/{handle}"})

    def _poll(self, tape: Tape, handle: str) -> None:
        """``GET stage/<id>``: count the poll and report each file's state."""
        request = tape.requests.get(handle)
        if request is None:
            self._json(404, {"message": "no such staging request"})
            return
        request["polls"] += 1
        online = request["polls"] > tape.stage_polls
        files = [self._staging(tape, entry, online) for entry in request["files"]]
        self._json(200, {"id": handle, "createdAt": 1, "startedAt": 1, "files": files})

    def _withdraw(self, tape: Tape, handle: str) -> None:
        """``DELETE stage/<id>``: withdraw a whole request; 404 for one never issued or gone."""
        if tape.requests.pop(handle, None) is None:
            self._json(404, {"message": "no such staging request"})
            return
        self._reply(204)

    def _release(self, tape: Tape, handle: str, document: Any) -> None:
        """``POST release/<id>``: record the paths released; 404 for an unknown id unless told."""
        if handle not in tape.requests and not self.app.release_unknown:
            self._json(404, {"message": "no such staging request"})
            return
        tape.released.append((handle, _paths(document)))
        self._reply(200)

    def _cancel(self, tape: Tape, handle: str, document: Any) -> None:
        """``POST stage/<id>/cancel``: mark the files ``{"paths": [...]}`` names cancelled."""
        request = tape.requests.get(handle)
        if request is None:
            self._json(404, {"message": "no such staging request"})
            return
        paths = _paths(document)
        for entry in request["files"]:
            if entry.get("path") in paths:
                entry["cancelled"] = True
        tape.cancelled.append((handle, paths))
        self._reply(200)

    def _where(self, tape: Tape, given: str) -> str | None:
        """A path's locality: the test's word for it, or the namespace's; ``None`` if missing."""
        if given in tape.locality:
            return tape.locality[given]
        path = clean(given)
        found = self.app.store.entry(path)
        if found is None or found.collection:
            return None
        return "TAPE" if path in tape.nearline or given in tape.nearline else "DISK"

    def _staging(self, tape: Tape, entry: dict[str, Any], online: bool) -> dict[str, Any]:
        """One file of a poll reply (:class:`~xrdhttp.testing.Tape` gives the rules' order)."""
        given = str(entry.get("path", ""))
        if entry.get("cancelled"):
            return {"path": given, "state": "CANCELLED", "onDisk": False}
        where = self._where(tape, given)
        if where is None or where in _LOST:
            error = "no such file" if where is None else f"file is {where}"
            return {"path": given, "state": "FAILED", "onDisk": False, "error": error}
        if clean(given) in tape.nearline or given in tape.nearline:
            return {"path": given, "state": "SUBMITTED", "onDisk": False, "startedAt": 1}
        state = "COMPLETED" if online else "STARTED"
        return {"path": given, "state": state, "onDisk": online, "startedAt": 1}

    def _locality(self, tape: Tape, given: str) -> dict[str, str]:
        """One path of an ``archiveinfo`` reply: its locality, or a not-found error."""
        where = self._where(tape, str(given))
        if where is None:
            return {"path": given, **self.app.missing_archive_entry}
        return {"path": given, "locality": where}

    # -- CDMI ---------------------------------------------------------------------------------

    def _cdmi(self) -> None:
        """CDMI QoS: a capability class list, one class, or a file's QoS (``PUT`` to move it).

        ``/cdmi_capabilities/<dataobject|container>/`` lists the class names
        found in :attr:`~xrdhttp.testing.StorageServer.qos`; a class URI
        returns that class's metadata; a file path returns its QoS state, and
        a ``PUT`` with ``capabilitiesURI`` records a transition request as
        ``cdmi_capabilities_target`` (the transition itself never happens: a
        test changes the state when it wants the move to be done).
        """
        qos, path = self.app.qos, self.target
        if path.startswith("/cdmi_capabilities/"):
            self._cdmi_class(qos, path)
            return
        state = qos[path]
        if self.command == "PUT":
            request = json.loads(self._read_body())
            state["metadata"]["cdmi_capabilities_target"] = request["capabilitiesURI"]
            self._reply(204)
            return
        self._json(200, state)

    def _cdmi_class(self, qos: dict[str, dict[str, Any]], path: str) -> None:
        """``/cdmi_capabilities/...``: the classes of one kind, or one class's metadata."""
        kind = path[len("/cdmi_capabilities/") :]
        if kind in ("dataobject", "container"):
            prefix = f"/cdmi_capabilities/{kind}/"
            children = sorted({p.split("/")[3] + "/" for p in qos if p.startswith(prefix)})
            self._json(200, {"children": children})
            return
        state = qos.get(path)
        if state is None:
            self._reply(404, b"no such class")
            return
        self._json(200, {"objectName": kind, "metadata": state})


def _paths(document: Any) -> list[str]:
    """The ``paths`` list of a cancel, release or archiveinfo request, as strings."""
    return [str(path) for path in document.get("paths", [])]
