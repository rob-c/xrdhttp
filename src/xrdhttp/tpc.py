"""HTTP third-party copy - the ``COPY`` dialect WLCG storage speaks.

The bytes never touch this process: one endpoint is told to fetch from (or
push to) the other, and the client only brokers the rendezvous and watches
the result. That is what FTS and Rucio do for every ``https://`` transfer on
the grid.

Two things about this protocol bite everyone who meets it for the first time,
and both are handled here:

* the transfer's *outcome* is in the response body, not the status line - a
  ``202 Accepted`` means the copy started, and a copy that then failed still
  arrived as a ``202``;
* the body is a stream of performance markers that only ends when the
  transfer does, so reading it is how you wait, and the last line says
  ``success:`` or ``failure:``.

The protocol is the WLCG HTTP-TPC one (the "HttpTpcTechnical" page of the
WLCG DOMA TPC working group, implemented by dCache, XRootD's XrdHttpTpc,
StoRM WebDAV and EOS): a WebDAV ``COPY`` (RFC 4918 section 9.8) whose
``Source:`` (pull) or ``Destination:`` (push) names a URL on *another*
server, with headers prefixed ``TransferHeader`` passed on - prefix
stripped - in the request the active side makes to the passive one.

What is here is what every client of the protocol shares; issuing the
request, choosing credentials and turning an outcome into an exception are
each client's own:

* :func:`follow_markers` reads the marker stream to its :class:`Outcome`,
  reporting each :class:`Marker` - xrdclient's ``COPY`` and gfal2's
  ``3rd pull``/``3rd push`` both read it;
* :func:`copy_headers` (and the ``add_*`` pieces it is made of) spells the
  request's headers the way gfal2's HTTP plug-in does, so an FTS job and a
  client present the same request:

  * ``Overwrite: T``/``F`` - RFC 4918 section 10.6, honoured for the target;
  * ``Credential: none``/``gridsite`` - whether the active side should use a
    delegated X.509 proxy (GridSite delegation) or only the bearer token;
  * ``RequireChecksumVerification`` and ``X-Number-Of-Streams`` - extensions
    (dCache's and XrdHttpTpc's) that a server without them ignores;

* :func:`remote_token`, :func:`strip_tokens`, :func:`token_minutes` and
  :data:`READ_ACTIVITIES`/:data:`WRITE_ACTIVITIES` are the far side's
  credential rules - where its token comes from, and what a macaroon minted
  for it is asked to allow and for how long;
* :func:`failure_detail` reads a ``failure:`` line for the reason and the
  status it quotes, so a client can raise what a direct request would have.

The markers themselves borrow GridFTP's ``Perf Marker`` block format; see
:func:`follow_markers`.
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Literal, TypeVar

from .redirects import TOKEN_FIELDS, query_token

__all__ = [
    "MAX_LINE",
    "READ_ACTIVITIES",
    "WRITE_ACTIVITIES",
    "CopyOptions",
    "Marker",
    "Mode",
    "Outcome",
    "OutcomeKind",
    "add_streams",
    "add_token",
    "add_transfer_headers",
    "add_verification",
    "copy_headers",
    "ends",
    "failure_detail",
    "follow_markers",
    "macaroon_caveats",
    "remote_token",
    "strip_tokens",
    "token_minutes",
]

#: Longest line we will believe is a performance marker. A server that sends
#: more than this is not speaking this protocol, and reading it unbounded is
#: how a client turns a confused endpoint into an out-of-memory kill.
MAX_LINE = 1 << 16

#: A ``failure:`` line usually quotes the status the far side got.
_STATUS = re.compile(r"\b([45]\d\d)\b")

#: What the far end is asked to allow, as gfal2 asks: reading needs a listing
#: and a download; writing also needs the name made, filled and - for a
#: failed copy's cleanup - removed.
READ_ACTIVITIES = ("LIST", "DOWNLOAD")
WRITE_ACTIVITIES = ("LIST", "DOWNLOAD", "MANAGE", "UPLOAD", "DELETE")

#: Which end the ``COPY`` goes to: the destination (``pull``) or the source.
Mode = Literal["pull", "push"]

#: How a ``COPY`` body ended: the far side's verdict, or the connection
#: closing before it gave one.
OutcomeKind = Literal["success", "failure", "aborted", "closed"]

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class Marker:
    """One performance marker: how far one stripe of the transfer has got.

    Servers send one block per stripe every few seconds, which is both the
    progress report and the keepalive that stops an idle-connection reaper
    from killing a long transfer.
    """

    #: Which stripe (parallel stream) the block is about; ``0`` when unsaid.
    index: int
    #: That stripe's running byte total - cumulative, not a delta.
    transferred: int
    #: How many stripes the server says there are (``Total Stripe Count``).
    stripes: int = 1
    #: The server's ``Timestamp`` line, Unix seconds; ``0`` when absent.
    timestamp: int = 0


@dataclass(frozen=True, slots=True)
class Outcome:
    """The end of a ``COPY`` body: its verdict, the line that said so, and the total.

    ``transferred`` is the sum of every stripe's last reported total - what
    the far side said had moved when it stopped reporting.
    """

    kind: OutcomeKind
    line: str
    transferred: int


# ---------------------------------------------------------------------------
# The request
# ---------------------------------------------------------------------------


def ends(mode: Mode, source: T, target: T) -> tuple[T, T]:
    """``(near, far)``: the end the ``COPY`` goes to, and the one only it contacts.

    In ``pull`` mode the destination fetches from the source; ``push`` sends
    the ``COPY`` to the source instead, for a destination that cannot make
    outbound connections. The far end's token is the one that travels in
    ``TransferHeaderAuthorization``.
    """
    return (target, source) if mode == "pull" else (source, target)


@dataclass(frozen=True, slots=True)
class CopyOptions:
    """What the caller chose, as the ``COPY`` headers need it.

    ``token`` is the far side's bearer token, already chosen (see
    :func:`remote_token`); ``None`` sends none. ``verify`` left ``None``
    sends ``RequireChecksumVerification: false`` (see :func:`add_verification`);
    ``streams`` left ``None`` leaves the number to the server.
    """

    mode: Mode = "pull"
    overwrite: bool = True
    token: str | None = None
    delegate: bool = False
    verify: bool | None = None
    streams: int | None = None
    transfer_headers: Mapping[str, str] | None = None


def copy_headers(far_url: str, options: CopyOptions) -> dict[str, str]:
    """Every header of the ``COPY`` request but the client's own credentials.

    ``far_url`` is the far endpoint as the near one must see it: absolute,
    ``http``/``https`` (never ``davs``, which a server will not resolve),
    path percent-encoded, no token in the query (see :func:`strip_tokens`).
    The near side's own ``Authorization`` is the client's to add, like any
    request's; everything here is about the far side.
    """
    headers = {
        "Source" if options.mode == "pull" else "Destination": far_url,
        "Overwrite": "T" if options.overwrite else "F",
        # Without this a server that supports delegation waits for one.
        "Credential": "gridsite" if options.delegate else "none",
    }
    add_token(headers, options.token)
    add_verification(headers, options.verify)
    add_streams(headers, options.streams)
    add_transfer_headers(headers, options.transfer_headers)
    return headers


def add_token(headers: dict[str, str], token: str | None) -> None:
    """Pass ``token`` to the far side, as the active side's ``Authorization``."""
    if token:
        headers["TransferHeaderAuthorization"] = f"Bearer {token}"


def add_verification(headers: dict[str, str], verify: bool | None) -> None:
    """Set ``RequireChecksumVerification``, defaulting it *off* as gfal2 does.

    ``true`` asks the destination to verify the source's checksum in band,
    which it does with a ``HEAD`` carrying ``Want-Digest``. Some sources
    answer a checksum *query* but put no digest in that ``HEAD`` - CNAF's
    StoRM is one - and the destination then fails the whole copy with "no
    checksum in HEAD response". Left absent, the destination applies its own
    default, which is to verify. So, like gfal2 (which never sends ``true``),
    ``None`` sends ``false``: the caller verifies the copy end to end
    afterwards by comparing each side's checksum query. ``verify=True`` still
    forces server-side verification for a caller who wants it and knows both
    ends can answer a ``HEAD`` digest. A client with a finer rule - gfal2's,
    which omits the header when only the source side is to be checked - sets
    the header itself instead of calling this.
    """
    headers["RequireChecksumVerification"] = "true" if verify else "false"


def add_streams(headers: dict[str, str], streams: int | None) -> None:
    """Suggest a number of parallel streams; ``None`` leaves it to the server."""
    if streams is not None:
        headers["X-Number-Of-Streams"] = str(streams)


def add_transfer_headers(
    headers: dict[str, str], transfer_headers: Mapping[str, str] | None
) -> None:
    """Add the caller's extra far-side headers, ``TransferHeader``-prefixed.

    Added last by :func:`copy_headers`, so a caller's ``Authorization`` here
    replaces the token chosen before it - deliberately: an explicit header is
    the most specific instruction there is.
    """
    for name, value in (transfer_headers or {}).items():
        headers[f"TransferHeader{name}"] = value


def remote_token(far_query: Mapping[str, str], explicit: str | None = None) -> str | None:
    """What authorises the far endpoint: its own URL's token first, then ``explicit``.

    ``far_query`` is the far URL's decoded query; a pre-signed pair of URLs
    (``?authz=...`` on each) therefore just works. ``explicit`` is the
    caller's choice - a ``remote_token`` argument, else the ambient token
    the client discovered.
    """
    return query_token(far_query) or explicit


def strip_tokens(url: str) -> str:
    """``url`` with its ``authz=``/``access_token=`` fields removed, the rest as written.

    A token moves into ``TransferHeaderAuthorization`` rather than being
    left in the URL handed to the far side. The other fields keep their
    exact spelling, since a CDN's signed URL covers it.
    """
    parts = urllib.parse.urlsplit(url)
    kept = [
        field
        for field in parts.query.split("&")
        if field and urllib.parse.unquote_plus(field.partition("=")[0]) not in TOKEN_FIELDS
    ]
    return urllib.parse.urlunsplit(parts._replace(query="&".join(kept)))


def token_minutes(timeout: float | None) -> int:
    """How long a macaroon minted for the far side lives, in minutes.

    gfal2's lifetime: twice the copy's timeout, plus ten minutes of slack for
    queueing at the active end - long enough to outlast a slow transfer,
    short enough that a leaked token is not a standing credential.
    """
    return 2 * int(timeout or 0) // 60 + 10


def macaroon_caveats(write: bool) -> list[str]:
    """The ``activity:`` caveat of a macaroon for the far side (it is written in a push)."""
    return [f"activity:{','.join(WRITE_ACTIVITIES if write else READ_ACTIVITIES)}"]


# ---------------------------------------------------------------------------
# The answer
# ---------------------------------------------------------------------------


def follow_markers(
    readline: Callable[[int], bytes],
    on_marker: Callable[[int, Marker | None], None] | None = None,
    *,
    limit: int = MAX_LINE,
) -> Outcome:
    """Read a ``COPY`` body's performance markers up to its outcome line.

    ``readline(limit)`` is the response's; whatever it raises (a read
    timeout) goes to the caller. ``on_marker(total, marker)`` is called at the
    ``End`` of every marker block with the transfer's running total - the
    sum over stripes, each stripe's latest total replacing its last - and the
    marker, or ``None`` for a block that reported no byte count (a keepalive,
    still a sign of life a caller may want to act on: check for a cancel, say).

    Lines are matched by prefix, case-insensitively, as davix matches them:
    ``Perf Marker`` opens a block, ``End`` closes it, ``Key: value`` lines
    fill it, and ``success``, ``aborted``, ``failure`` or ``failed`` is the
    outcome. A connection that closes first is the ``"closed"`` outcome.
    """
    # Each stripe's latest cumulative total; the transfer's total is their
    # sum. ``block`` is the Key: value lines of the marker being read.
    stripes: dict[int, int] = {}
    block: dict[str, str] = {}
    while True:
        line = readline(limit)
        if not line:
            return Outcome("closed", "", sum(stripes.values()))
        text = line.decode("utf-8", "replace").strip()
        kind = _verdict(text.lower())
        if kind is not None:
            return Outcome(kind, text, sum(stripes.values()))
        block = _absorb(text, block, stripes, on_marker)


def _verdict(lowered: str) -> OutcomeKind | None:
    """The outcome a line announces, if it is an outcome line."""
    if lowered.startswith("success"):
        return "success"
    if lowered.startswith("aborted"):
        return "aborted"
    if lowered.startswith(("failure", "failed")):
        return "failure"
    return None


def _absorb(
    text: str,
    block: dict[str, str],
    stripes: dict[int, int],
    on_marker: Callable[[int, Marker | None], None] | None,
) -> dict[str, str]:
    """Take one non-outcome line into the current block; returns the block now open."""
    lowered = text.lower()
    if lowered.startswith("perf marker"):
        return {}
    if lowered.startswith("end"):
        marker = _marker(block)
        if marker is not None:
            stripes[marker.index] = marker.transferred
        if on_marker is not None:
            on_marker(sum(stripes.values()), marker)
    elif ":" in text:
        name, _, value = text.partition(":")
        block[name.strip().lower()] = value.strip()
    return block


def _marker(block: dict[str, str]) -> Marker | None:
    """A finished ``Perf Marker`` block, or ``None`` if it said nothing useful."""
    moved = block.get("stripe bytes transferred", "")
    if not (moved.isascii() and moved.isdigit()):
        return None
    index = block.get("stripe index", "0")
    return Marker(
        index=int(index) if index.isascii() and index.isdigit() else 0,
        transferred=int(moved),
        stripes=_int(block.get("total stripe count"), 1),
        timestamp=_int(block.get("timestamp"), 0),
    )


def _int(value: str | None, default: int) -> int:
    """``value`` as an integer, or ``default`` when absent or not a number.

    A marker's optional fields are advisory; a malformed one must not cost
    the transfer its progress report.
    """
    try:
        return int(value) if value is not None else default
    except ValueError:
        return default


def failure_detail(line: str) -> tuple[str, int | None]:
    """A ``failure:`` line's reason, and the HTTP status it quotes, if it quotes one.

    The far side already classified the failure; raising what a direct
    request with that status would have raised - a 403 from the source is a
    permission error - beats flattening it to "the copy failed".
    """
    detail = line.partition(":")[2].strip() or line
    found = _STATUS.search(detail)
    return detail, int(found.group(1)) if found else None
