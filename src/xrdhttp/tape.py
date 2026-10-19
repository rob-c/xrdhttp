"""The WLCG Tape REST API - staging over HTTP.

``root://`` stages with ``kXR_prepare`` and asks how it is going with
``kXR_QPrep``; the HTTP side of the same storage element does both over a
small JSON API, which is what FTS and Rucio drive when they bring a dataset
back from tape. This module is that API's vocabulary and, for a client that
wants it, its verbs.

It comes in two layers, so that clients with different error vocabularies
can share everything that is not an error message:

* **The vocabulary** - pure functions over JSON values, used by every
  client: reading the site's discovery document (:class:`TapeEndpoint`,
  :func:`listed_endpoints`, :func:`newest_endpoint`, :func:`api_version`,
  :func:`choose_endpoint`), JSON values as json-c spells them
  (:func:`json_text`, :func:`flag`), slash collapsing (:func:`collapse`),
  finding a reply's entry for a path (:func:`entry_for`, :func:`entries`),
  the request bodies (:func:`stage_body`, :func:`paths_body`) and reading
  the answers into :class:`FileStatus` values (:func:`stage_statuses`,
  :func:`archive_statuses`). gfal2's plugin words its own ``[Tape REST
  API]`` errors over this layer.
* **The verbs** - :class:`TapeClient`, one method per API call, over a
  ``send`` callable the client supplies (its own connection, credentials,
  retries and errors). This is XrdClHttp's reading: requests are rooted at
  :data:`API` on the server, as XrdClHttp roots them.

The verbs, as the WLCG Tape REST API v1 specification defines them (the
document the WLCG tape working group published for dCache, EOS-CTA and
StoRM): ``POST stage`` starts a request and answers its id (``201`` with a
``Location``); ``GET stage/<id>`` reports it; ``DELETE stage/<id>`` and
``POST stage/<id>/cancel`` withdraw all or part of it; ``POST
release/<id>`` lets staged files go; ``POST archiveinfo`` reports where
files are without staging anything.

Leniency is deliberate throughout: deployments predate the final
specification and still differ (field names, boolean spellings, locality
words), and a strict reader would report a staged file as missing. Each
tolerance is documented where it is applied, with the spelling that needs it.
"""

from __future__ import annotations

import itertools
import json
import posixpath
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, cast

from xrdcore.errors import ProtocolError

__all__ = [
    "API",
    "VERSION",
    "WELL_KNOWN",
    "FileStatus",
    "Reply",
    "Send",
    "TapeClient",
    "TapeEndpoint",
    "api_path",
    "api_version",
    "archive_statuses",
    "choose_endpoint",
    "collapse",
    "entries",
    "entry_for",
    "flag",
    "json_text",
    "listed_endpoints",
    "locality",
    "newest_endpoint",
    "parse_document",
    "paths_body",
    "request_id",
    "stage_body",
    "stage_entries",
    "stage_statuses",
]

#: Where the API is rooted. Fixed by the WLCG specification, not by the site.
API = "/api/v1"

#: Where a site describes its tape endpoints, per the same specification.
WELL_KNOWN = "/.well-known/wlcg-tape-rest-api"

#: The API version this module speaks, and so the endpoint discovery prefers.
VERSION = "v1"

#: JSON, for a body this client sends and a body it expects back.
_JSON = {"Content-Type": "application/json"}

#: The states of a staging request that mean the bytes are not coming.
_GIVEN_UP = ("FAILED", "CANCELLED")

#: A run of slashes, which the API's path matching does not distinguish from one.
_SLASHES = re.compile("/{2,}")


@dataclass(frozen=True, slots=True)
class TapeEndpoint:
    """One API root a site's discovery document lists, and who is serving it."""

    #: The API root, absolute (``https://tape.example:8443/api/v1``).
    uri: str
    #: As the document wrote it (``v1``); :func:`api_version` reads it.
    version: str
    #: The document's top-level ``sitename``, shared by all its endpoints.
    sitename: str


@dataclass(frozen=True, slots=True)
class FileStatus:
    """What the tape API says of one file: where it is, and what was asked of it.

    The same fields as XRootD's ``kXR_QPrep`` answer, so a client can turn one
    into its own staging-status type field for field. ``error`` is the
    server's own text for a file it could not report on, and is empty for
    the ones it could. ``state`` is the word the server used -
    ``"COMPLETED"``, ``"NEARLINE"`` and so on - kept verbatim because the
    vocabulary differs between the tape API and the storage behind it, and
    because the booleans are the part worth branching on.
    """

    path: str = ""
    exists: bool = False
    on_tape: bool = False
    online: bool = False
    requested: bool = False
    has_request_id: bool = False
    requested_at: str = ""
    error: str = ""
    state: str = ""

    def __bool__(self) -> bool:
        """``True`` once the file is on disk, which is what staging is for."""
        return self.online

    def __str__(self) -> str:
        """``path: online``, ``path: on tape`` or ``path: nowhere``, with any server error."""
        where = "online" if self.online else ("on tape" if self.on_tape else "nowhere")
        return f"{self.path}: {where}{f' ({self.error})' if self.error else ''}"


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------


def json_text(value: Any) -> str:
    """A JSON value as text, the way json-c's ``json_object_get_string`` spells it.

    A string is itself; anything else is its JSON (``true``, ``1``), which is
    what gfal2 - and so this - compares and reports.
    """
    return value if isinstance(value, str) else json.dumps(value)


def api_version(version: str) -> int:
    """The major API version an endpoint's ``version`` names; ``-1`` if it names none.

    ``v1``, ``V1``, ``1`` and ``v1.2`` are all 1 and ``v0`` is 0, as gfal2's
    ``parseVersion`` reads them; ``vX`` is -1, and an empty string 0.
    """
    text = version.lower()
    text = text[1:] if text.startswith("v") else text
    if text and not text[0].isdigit():
        return -1
    digits = "".join(itertools.takewhile(str.isdigit, text))
    return int(digits) if digits else 0


def listed_endpoints(document: Any, *, complete: bool = True) -> list[TapeEndpoint]:
    """Every endpoint a discovery document lists, in its order.

    Clients differ over a partial entry. gfal2 passes over anything that is
    not an object with both a ``uri`` and a ``version`` (``complete=True``);
    XrdClHttp, which :func:`choose_endpoint` follows, takes any object and
    reads what is missing as empty (``complete=False``). A document that is
    not an object, or lists nothing, has no endpoints.
    """
    if not isinstance(document, dict):
        return []
    found = document.get("endpoints")
    site = json_text(document["sitename"]) if "sitename" in document else ""
    return [
        TapeEndpoint(json_text(entry.get("uri", "")), json_text(entry.get("version", "")), site)
        for entry in (found if isinstance(found, list) else [])
        if isinstance(entry, dict) and (not complete or ("version" in entry and "uri" in entry))
    ]


def newest_endpoint(endpoints: Sequence[TapeEndpoint], newest: int = 1) -> TapeEndpoint | None:
    """The endpoint speaking the highest API version up to ``newest``; ``None`` if none does.

    Versions are read by :func:`api_version`; of two of the same version the
    later one in the document wins, as it does in gfal2. An endpoint with no
    ``uri`` is no endpoint at all.
    """
    best = 0
    chosen: TapeEndpoint | None = None
    for endpoint in endpoints:
        number = api_version(endpoint.version)
        if best <= number <= newest:
            chosen, best = endpoint, number
    return chosen if chosen is not None and chosen.uri else None


def choose_endpoint(document: Any, where: str = WELL_KNOWN) -> TapeEndpoint:
    """XrdClHttp's choice from a discovery document: the newest up to :data:`VERSION`.

    Every endpoint the document lists counts, partial ones included; the
    first is taken when none speaks a version this module knows. A document
    that lists nothing is a :class:`~xrdcore.errors.ProtocolError` naming
    ``where`` it came from.
    """
    endpoints = listed_endpoints(document, complete=False)
    if not endpoints:
        raise ProtocolError(f"{where} lists no tape endpoints")
    return newest_endpoint(endpoints, api_version(VERSION)) or endpoints[0]


def collapse(path: str) -> str:
    """``//a//b`` as ``/a/b``: how a file is named to, and matched against, the tape API."""
    return _SLASHES.sub("/", path)


def entry_for(items: Any, path: str) -> dict[str, Any] | None:
    """The object of a reply's file list whose ``path`` names ``path``, slashes collapsed."""
    for item in items if isinstance(items, list) else []:
        named = isinstance(item, dict) and item.get("path")
        if named and collapse(json_text(item["path"])) == collapse(path):
            return cast("dict[str, Any]", item)
    return None


def flag(value: object) -> bool:
    """One JSON field as a boolean, whichever way the server spelt it.

    Implementations have written these as ``true``, as ``1`` and as ``"1"``,
    and all three mean yes; a client that only understood one would report a
    staged file as still on tape.
    """
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes")
    return bool(value)


def parse_document(payload: bytes, where: object = "the tape API") -> Any:
    """A reply body as JSON; an empty body is ``{}`` (a bare ``201``/``204``).

    Undecodable bytes are replaced rather than raised, so the
    :class:`~xrdcore.errors.ProtocolError` a garbled body produces names
    ``where`` it came from and shows the start of the body.
    """
    try:
        return json.loads(payload.decode("utf-8", "replace") or "{}")
    except ValueError as exc:
        raise ProtocolError(f"{where} did not answer with JSON: {payload[:120]!r}") from exc


def entries(document: Any) -> list[Any]:
    """The file list of a reply, whether it is the whole body or a member.

    The specification puts it under ``files``; some servers answer with the
    bare array, and one release of the standard called it ``responses``.
    """
    if isinstance(document, dict):
        for key in ("files", "responses"):
            found = document.get(key)
            if found is not None:
                return list(found)
        return []
    return list(document or [])


def api_path(*parts: str) -> str:
    """The server path of an API call: ``/api/v1/<parts>``."""
    return posixpath.join(API, *parts)


def stage_entries(paths: Sequence[str], lifetime: str = "") -> list[dict[str, str]]:
    """The ``files`` of a stage request for ``paths``, each with ``lifetime`` if given.

    ``lifetime`` is an ISO 8601 duration - ``"P1D"`` for a day - and asks the
    site to keep the files on disk that long once they arrive. Left empty,
    the site's own policy decides.
    """
    files: list[dict[str, str]] = [{"path": path} for path in paths]
    if lifetime:
        for entry in files:
            entry["diskLifetime"] = lifetime
    return files


def stage_body(files: Sequence[Mapping[str, Any]]) -> bytes:
    """The JSON body of ``POST stage``: ``{"files": [...]}``.

    Each entry is the specification's: a ``path``, and optionally its own
    ``diskLifetime`` and ``targetedMetadata`` (a JSON object keyed by the
    site's name for itself).
    """
    return json.dumps({"files": list(files)}).encode()


def paths_body(paths: Sequence[str]) -> bytes:
    """The JSON body of cancel, release and archiveinfo: ``{"paths": [...]}``."""
    return json.dumps({"paths": list(paths)}).encode()


def request_id(document: Any, location: str = "") -> str:
    """The id a ``POST stage`` answered with.

    The specification puts it in the body's ``requestId``; some servers put
    it only in the ``Location`` they redirect a poller to, whose last path
    segment it then is.
    """
    handle = str(document.get("requestId", "")) if isinstance(document, dict) else ""
    return handle or location.rstrip("/").rpartition("/")[2]


def _ordered(found: dict[str, FileStatus], paths: Sequence[str]) -> list[FileStatus]:
    """One status per path asked about, in that order - the ``kXR_QPrep`` shape.

    A file the reply says nothing about is reported as one the request never
    named, rather than quietly dropped: the caller asked about it, and silence
    is an answer it would have to guess at.
    """
    # No paths asked about means "every file of the request", in the
    # server's order.
    if not paths:
        return list(found.values())
    return [
        found.get(path, FileStatus(path=path, error="not part of this request")) for path in paths
    ]


def stage_statuses(document: Any, paths: Sequence[str] = ()) -> list[FileStatus]:
    """A ``GET stage/<id>`` document read into one :class:`FileStatus` per path.

    ``onDisk`` (however spelt, see :func:`flag`) or a ``COMPLETED`` state is
    online; a file neither online nor given up on is still on tape.
    """
    found = {}
    for entry in entries(document):
        state = str(entry.get("state", ""))
        online = flag(entry.get("onDisk")) or state == "COMPLETED"
        path = str(entry.get("path", ""))
        found[path] = FileStatus(
            path=path,
            exists=True,  # the request named it, and the server took the request
            # Not online yet and not given up on means the bytes are still
            # where staging fetches them from, which is the tape.
            on_tape=not online and state not in _GIVEN_UP,
            online=online,
            requested=True,
            has_request_id=True,
            requested_at=str(entry.get("startedAt", "") or ""),
            error=str(entry.get("error", "") or ""),
            state=state,
        )
    return _ordered(found, paths)


def archive_statuses(items: Sequence[Any], paths: Sequence[str] = ()) -> list[FileStatus]:
    """An ``archiveinfo`` reply's entries read into one :class:`FileStatus` per path."""
    found = {}
    for entry in items:
        path = str(entry.get("path", ""))
        found[path] = locality(path, str(entry.get("locality", "")), entry)
    return _ordered(found, paths)


def locality(path: str, word: str, entry: Mapping[str, Any]) -> FileStatus:
    """One ``archiveinfo`` entry, read from the locality word it answers with.

    Deployments differ over the vocabulary - ``DISK``/``TAPE`` in the
    specification, ``ONLINE``/``NEARLINE`` in the storage systems it describes
    - and both spell the third case as a compound, so this reads the two
    halves rather than matching whole words. Anything that names neither is a
    file the site cannot give you: lost, unavailable, or not there at all.
    """
    upper = word.upper()
    online = "DISK" in upper or "ONLINE" in upper
    on_tape = "TAPE" in upper or "NEARLINE" in upper
    return FileStatus(
        path=path,
        exists=online or on_tape,
        on_tape=on_tape,
        online=online,
        error=str(entry.get("error", "") or "") or ("" if online or on_tape else word.lower()),
        state=upper,
    )


# ---------------------------------------------------------------------------
# Verbs
# ---------------------------------------------------------------------------


class Reply(Protocol):
    """What :class:`TapeClient` reads of an answer: its body and one header."""

    @property
    def body(self) -> bytes:
        """The whole response body."""
        ...

    def header(self, name: str) -> str:
        """One response header's value; ``""`` when absent."""
        ...


#: ``send(method, path, body, headers, expect)``: one request to the server
#: the client is bound to, at server path ``path`` (``/api/v1/stage``). It
#: raises the client's own error for a status outside ``expect``, and for a
#: transport failure; credentials, retries and redirects are the client's.
Send = Callable[[str, str, "bytes | None", Mapping[str, str], "tuple[int, ...]"], Reply]


class TapeClient:
    """The API's verbs over one server, through the client's own ``send``.

    The client decides which server (and so which credentials) ``send``
    talks to; this class decides only what is asked and how the answer is
    read. It holds no connection and closes nothing.
    """

    def __init__(self, send: Send) -> None:
        """Make every request through ``send``; see :data:`Send`."""
        self._send = send

    def _json(self, method: str, path: str, body: bytes | None, expect: tuple[int, ...]) -> Any:
        """One call whose answer is a JSON document."""
        reply = self._send(method, path, body, _JSON if body is not None else {}, expect)
        return parse_document(reply.body, path)

    def stage(self, paths: Sequence[str], *, lifetime: str = "") -> str:
        """Ask for these files to be brought online. Returns the request id."""
        return self.stage_files(stage_entries(paths, lifetime))

    def stage_files(self, files: Sequence[Mapping[str, Any]]) -> str:
        """:meth:`stage` with each file's entry spelt out (see :func:`stage_body`)."""
        path = api_path("stage")
        reply = self._send("POST", path, stage_body(files), _JSON, (200, 201))
        return request_id(parse_document(reply.body, path), reply.header("Location"))

    def request_status(self, handle: str) -> Any:
        """The staging request ``handle``'s status document, as the site wrote it.

        The specification's shape is ``{"id", "createdAt", "startedAt",
        "completedAt", "files": [...]}``; :meth:`status` reads the files out of it.
        """
        return self._json("GET", api_path("stage", handle), None, (200,))

    def status(self, handle: str, paths: Sequence[str] = ()) -> list[FileStatus]:
        """How the staging request ``handle`` is going, one entry per path."""
        return stage_statuses(self.request_status(handle), paths)

    def cancel(self, handle: str) -> None:
        """Withdraw a staging request, files and all."""
        self._send("DELETE", api_path("stage", handle), None, {}, (200, 202, 204))

    def cancel_files(self, handle: str, paths: Sequence[str]) -> None:
        """Withdraw some of the files of staging request ``handle``, leaving the rest."""
        self._send(
            "POST", api_path("stage", handle, "cancel"), paths_body(paths), _JSON, (200, 202, 204)
        )

    def release(self, handle: str, paths: Sequence[str]) -> None:
        """Tell the site these files of request ``handle`` need not stay on disk for it."""
        self._send("POST", api_path("release", handle), paths_body(paths), _JSON, (200, 202, 204))

    def discover(self) -> TapeEndpoint:
        """The tape endpoint the site advertises (see :func:`choose_endpoint`)."""
        return choose_endpoint(self._json("GET", WELL_KNOWN, None, (200,)))

    def archive_entries(self, paths: Sequence[str]) -> list[Any]:
        """The ``archiveinfo`` reply's entries, as the site wrote them."""
        return entries(self._json("POST", api_path("archiveinfo"), paths_body(paths), (200,)))

    def archive_info(self, paths: Sequence[str]) -> list[FileStatus]:
        """Where each of these files lives, without asking for any of it to move."""
        return archive_statuses(self.archive_entries(paths), paths)
