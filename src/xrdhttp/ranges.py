"""Several byte ranges in one ``GET``: RFC 9110 multi-range requests.

A vector read over HTTP asks for every range at once - ``Range:
bytes=0-99,4096-4195`` - and a server that can answers ``206`` with a
``multipart/byteranges`` body: each range as a part with its own
``Content-Range``, between boundary lines. This module owns the wire side of
that: which spans to ask for, how to read the parts back, and what to make of
an answer that is not quite what was asked.

The client trusts the server's framing no further than it has to:

* every part must lie inside the spans that were asked for, and together
  they may not deliver more than those spans hold - a hostile server cannot
  make the client buffer a file it did not want;
* boundary lines and part headers are read with a per-line and a total
  limit, so a body that never draws a boundary is an error, not a hang
  that fills memory;
* a part's bytes are copied straight into the buffers of the spans it
  covers, a megabyte at a time, so memory is what was asked for plus one
  chunk, however the server lays the parts out.

What a server does instead of a multipart answer is not an error. It may
coalesce ranges into one part (RFC 9110 allows it when the gaps are small),
serve only the first, or ignore ``Range`` and send the whole file; anything
left unfilled is fetched with ordinary single-range requests by the caller.

The order a caller runs it in: :func:`spans` merges the wanted ranges,
:func:`batches` cuts them into requests, :func:`range_header` spells each one;
on a ``206`` with :func:`boundary` set, :func:`read_multipart` feeds an
:class:`Assembly`; a single-part ``206`` goes through
:meth:`Assembly.accept` with :func:`content_range`; finally :func:`assemble`
cuts the caller's ranges back out of the filled spans. Spec references:
RFC 9110 section 14.1.2 (``bytes=first-last``, both ends inclusive), section
14.4 (``Content-Range``) and section 14.6 (``multipart/byteranges``, whose
framing is MIME's, RFC 2046 section 5.1.1).
"""

from __future__ import annotations

import bisect
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from email.message import Message
from typing import Protocol

from xrdcore.errors import ProtocolError, TransientError

__all__ = [
    "MAX_SPANS",
    "Assembly",
    "MultipartAnswer",
    "Span",
    "assemble",
    "batches",
    "boundary",
    "content_range",
    "range_header",
    "read_multipart",
    "spans",
]

#: Ranges asked for in one request. Servers cap this (Apache at 200, and a
#: ``Range`` header is one line that proxies also cap), and past a few dozen
#: one more request costs nothing next to the bytes.
MAX_SPANS = 64

#: The longest one line of multipart framing may be.
_LINE_LIMIT = 8 * 1024

#: The most framing - preamble, boundaries and part headers - one response
#: may carry in all. Generous for :data:`MAX_SPANS` parts' worth.
_FRAMING_LIMIT = 256 * 1024

#: How much of a part is read from the socket at a time.
_CHUNK = 1 << 20


@dataclass(slots=True)
class Span:
    """One contiguous run of bytes to fetch: ``[start, end)``.

    ``data`` is ``None`` until a response covered the whole span, and then
    holds its bytes - fewer than :attr:`length` only where the file ended.
    """

    start: int
    end: int
    data: bytearray | None = None

    @property
    def length(self) -> int:
        """How many bytes the span asks for (``end`` is exclusive)."""
        return self.end - self.start


def spans(ranges: Iterable[tuple[int, int]]) -> list[Span]:
    """The spans that cover ``(offset, length)`` ``ranges``, in file order.

    Overlapping and touching ranges become one span - one part to ask for,
    rather than the same bytes twice - and empty ranges ask for nothing.
    """
    merged: list[Span] = []
    for start, length in sorted(ranges):
        end = start + length
        if length <= 0:
            continue
        if merged and start <= merged[-1].end:
            merged[-1].end = max(merged[-1].end, end)
        else:
            merged.append(Span(start, end))
    return merged


def batches(merged: Sequence[Span]) -> Iterator[list[Span]]:
    """``merged`` in groups of at most :data:`MAX_SPANS`, one request each."""
    for index in range(0, len(merged), MAX_SPANS):
        yield list(merged[index : index + MAX_SPANS])


def range_header(batch: Sequence[Span]) -> str:
    """The ``Range`` value asking for every span of ``batch``."""
    # RFC 9110's last-byte-pos is inclusive, hence ``end - 1``.
    return "bytes=" + ",".join(f"{span.start}-{span.end - 1}" for span in batch)


def content_range(value: str) -> tuple[int, int] | None:
    """``bytes first-last/complete`` as ``(first, last + 1)``; ``None`` if not that."""
    # The complete length after ``/`` (possibly ``*``) is not needed: the
    # part's position is all that decides where its bytes go. The
    # unsatisfied form ``bytes */1234`` fails the digit test and is ``None``.
    unit, _, rest = value.strip().partition(" ")
    first, _, last = rest.partition("/")[0].partition("-")
    if unit.lower() != "bytes" or not first.isdigit() or not last.isdigit():
        return None
    if int(last) < int(first):
        return None
    return int(first), int(last) + 1


class MultipartAnswer(Protocol):
    """What :func:`boundary` and :func:`read_multipart` read: an answer's headers and body.

    An :class:`http.client.HTTPResponse` is one, and so is a
    :class:`xrdhttp.session.Response`: the multi-range reader does not care
    which client's connection the bytes come from.
    """

    @property
    def headers(self) -> Message:
        """The answer's header fields."""
        ...

    def readline(self, limit: int = ...) -> bytes:
        """One line of the body, at most ``limit`` bytes; empty at its end."""
        ...

    def read(self, amount: int | None = ..., /) -> bytes:
        """Up to ``amount`` bytes of the body."""
        ...


def boundary(response: MultipartAnswer) -> bytes | None:
    """The boundary of a ``multipart/byteranges`` body, or ``None`` if it is not one."""
    if response.headers.get_content_type() != "multipart/byteranges":
        return None
    value = response.headers.get_param("boundary")
    if not isinstance(value, str) or not value:
        raise ProtocolError("a multipart/byteranges response named no boundary")
    # Boundaries are 7-bit by RFC 2046; latin-1 maps any byte one-to-one so
    # a non-conforming one still compares exactly with the body's lines.
    return value.encode("latin-1")


def assemble(merged: Sequence[Span], wanted: Iterable[tuple[int, int]]) -> list[bytes]:
    """The bytes of each ``(offset, length)`` asked for, out of the filled spans."""
    # ``merged`` is sorted and non-overlapping (see :func:`spans`), so the
    # span holding ``offset`` is the last one starting at or before it.
    starts = [span.start for span in merged]
    out = []
    for offset, length in wanted:
        if length <= 0:
            out.append(b"")
            continue
        span = merged[bisect.bisect_right(starts, offset) - 1]
        assert span.data is not None  # every span is filled before assembly
        at = offset - span.start
        out.append(bytes(span.data[at : at + length]))
    return out


class Assembly:
    """Where the parts of one response land, and how much may still arrive."""

    def __init__(self, batch: Sequence[Span]) -> None:
        """Set the window and byte budget for one request's ``batch`` of spans.

        ``batch`` must be non-empty and in file order, as :func:`batches`
        yields it; its spans are filled in place as parts arrive.
        """
        self.batch = batch
        self.low = batch[0].start
        self.high = batch[-1].end
        #: Bytes the server may still send. What the spans hold, and as much
        #: again (and a chunk) for the gaps a server may coalesce across -
        #: RFC 9110 allows that for gaps cheaper to send than a new part -
        #: but not a whole file between two ranges at either end of it.
        wanted = sum(span.length for span in batch)
        self.budget = wanted + min(self.high - self.low - wanted, wanted + _CHUNK)

    def accept(self, first: int, end: int, read: Callable[[int], bytes]) -> None:
        """Take the part ``[first, end)``, pulling its bytes with ``read``.

        Spans it covers whole are filled; a span it covers only in part is
        left for the caller to fetch on its own, rather than stitched.
        """
        self._admit(first, end)
        covered = [span for span in self.batch if first <= span.start and span.end <= end]
        for span in covered:
            span.data = bytearray(span.length)
        _stream(covered, first, end, read)

    def _admit(self, first: int, end: int) -> None:
        """Refuse a part outside the spans asked for, or past the byte budget."""
        if first < self.low or end > self.high or end - first > self.budget:
            raise ProtocolError(
                f"the server sent bytes {first}-{end - 1}, which were not asked for"
            )
        self.budget -= end - first


def _stream(covered: list[Span], first: int, end: int, read: Callable[[int], bytes]) -> None:
    """Pull the part ``[first, end)`` a chunk at a time into the spans it covers."""
    position = first
    while position < end:
        chunk = read(min(_CHUNK, end - position))
        if not chunk:
            raise TransientError(f"the connection closed inside the part for {first}-{end - 1}")
        _copy(covered, position, chunk)
        position += len(chunk)


def _copy(covered: Iterable[Span], position: int, chunk: bytes) -> None:
    """Copy ``chunk``, which starts at ``position`` in the file, into ``covered``."""
    for span in covered:
        low = max(span.start, position)
        high = min(span.end, position + len(chunk))
        if low < high:
            assert span.data is not None  # allocated when the part was accepted
            span.data[low - span.start : high - span.start] = chunk[
                low - position : high - position
            ]


class _Framing:
    """The lines between parts, read within :data:`_LINE_LIMIT` and :data:`_FRAMING_LIMIT`."""

    def __init__(self, response: MultipartAnswer) -> None:
        """Start reading framing from ``response`` with the whole budget left."""
        self.response = response
        self.left = _FRAMING_LIMIT

    def line(self) -> bytes:
        """The next framing line without its line ending.

        Raises :class:`~xrdcore.errors.ProtocolError` past either limit
        (a boundary that never comes looks exactly like that), and
        :class:`~xrdcore.errors.TransientError` at an end of stream, which
        is a dropped connection rather than a malformed answer.
        """
        # One byte over the limit is read so that "exactly at the limit" and
        # "longer" can be told apart without a second read.
        raw = self.response.readline(_LINE_LIMIT + 1)
        self.left -= len(raw)
        if len(raw) > _LINE_LIMIT or self.left < 0:
            raise ProtocolError("multipart/byteranges framing is too long")
        if not raw:
            raise TransientError("the connection closed inside a multipart/byteranges body")
        return raw.rstrip(b"\r\n")

    def part_range(self) -> tuple[int, int]:
        """Read one part's headers; its ``Content-Range``, which it must have."""
        # Headers end at the empty line; ``Content-Type`` and the like are
        # read and ignored. A repeated Content-Range: the last one wins.
        found = None
        while line := self.line():
            name, _, value = line.decode("latin-1").partition(":")
            if name.strip().lower() == "content-range":
                found = content_range(value)
        if found is None:
            raise ProtocolError("a multipart/byteranges part has no usable Content-Range")
        return found


def read_multipart(response: MultipartAnswer, delimiter: bytes, assembly: Assembly) -> None:
    """Read a ``multipart/byteranges`` body into ``assembly``, part by part.

    ``delimiter`` is the boundary from :func:`boundary`. Returns at the
    closing delimiter, leaving any epilogue unread: the caller abandons or
    drains the response. Every failure is an exception; spans the server did
    not cover stay unfilled (``data is None``) for the caller to fetch.
    """
    framing = _Framing(response)
    opening, closing = b"--" + delimiter, b"--" + delimiter + b"--"
    while framing.line().rstrip() != opening:
        pass  # the preamble, which says nothing
    while True:
        assembly.accept(*framing.part_range(), response.read)
        line = framing.line()
        while not line.strip():
            line = framing.line()  # the CRLF that ends the data, and any padding
        line = line.rstrip()
        if line == closing:
            return
        if line != opening:
            raise ProtocolError("a multipart/byteranges part ran past its Content-Range")
