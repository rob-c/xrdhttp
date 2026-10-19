"""Multi-range ``GET``: spans, headers, ``multipart/byteranges`` framing and its limits."""

from __future__ import annotations

import functools

import pytest

from xrdcore.errors import ProtocolError, TransientError
from xrdhttp import ranges
from xrdhttp.testing import byteranges

from tests._sockets import canned_response

DATA = bytes(range(256)) * 40
BOUNDARY = "b0undary"


_multipart = functools.partial(
    byteranges, size=len(DATA), boundary=BOUNDARY, preamble=b"preamble\r\n", epilogue=b"epilogue"
)


def _response(body: bytes, content_type: str = f"multipart/byteranges; boundary={BOUNDARY}"):
    head = f"HTTP/1.1 206 Partial Content\r\nContent-Type: {content_type}\r\n"
    head += f"Content-Length: {len(body)}\r\n\r\n"
    return canned_response(head.encode() + body)


def _read(
    wanted: list[tuple[int, int]],
    body: bytes,
    content_type: str = f"multipart/byteranges; boundary={BOUNDARY}",
) -> list[ranges.Span]:
    merged = ranges.spans(wanted)
    response = _response(body, content_type)
    delimiter = ranges.boundary(response)
    assert delimiter is not None
    ranges.read_multipart(response, delimiter, ranges.Assembly(merged))
    return merged


def test_spans_merge_overlapping_and_touching_ranges_and_drop_empty_ones():
    merged = ranges.spans([(40, 5), (10, 5), (12, 10), (22, 3), (100, 0)])
    assert [(s.start, s.end) for s in merged] == [(10, 25), (40, 45)]
    assert merged[0].length == 15 and merged[0].data is None


def test_batches_and_the_range_header():
    merged = ranges.spans([(i * 10, 2) for i in range(ranges.MAX_SPANS + 3)])
    batches = list(ranges.batches(merged))
    assert [len(b) for b in batches] == [ranges.MAX_SPANS, 3]
    assert ranges.range_header(merged[:2]) == "bytes=0-1,10-11"


def test_a_multipart_answer_fills_every_span_and_assembles():
    wanted = [(40, 5), (10, 5)]
    merged = _read(wanted, _multipart((10, DATA[10:15]), (40, DATA[40:45])))
    assert ranges.assemble(merged, [*wanted, (0, 0)]) == [DATA[40:45], DATA[10:15], b""]


def test_padding_and_parts_in_any_order_are_fine():
    body = _multipart((40, DATA[40:45]), (10, DATA[10:15])).replace(b"\r\n--", b"\r\n  \r\n--")
    merged = _read([(10, 5), (40, 5)], body)
    assert all(span.data is not None for span in merged)


def test_a_coalesced_part_covers_several_spans():
    merged = _read([(10, 5), (20, 5)], _multipart((10, DATA[10:25])))
    assert ranges.assemble(merged, [(10, 5), (20, 5)]) == [DATA[10:15], DATA[20:25]]


def test_a_part_that_covers_a_span_partly_leaves_it_unfilled():
    merged = _read([(10, 5), (40, 5)], _multipart((10, DATA[10:15]), (40, DATA[40:42])))
    assert merged[0].data is not None and merged[1].data is None


def test_a_single_range_answer_goes_through_accept():
    merged = ranges.spans([(10, 5)])
    assembly = ranges.Assembly(merged)
    response = canned_response(b"HTTP/1.1 206 OK\r\nContent-Length: 5\r\n\r\n" + DATA[10:15])
    assert ranges.boundary(response) is None
    parsed = ranges.content_range("bytes 10-14/100")
    assert parsed is not None
    first, end = parsed
    assembly.accept(first, end, response.read)
    assert bytes(merged[0].data or b"") == DATA[10:15]


def test_a_single_range_answer_must_start_where_it_was_asked():
    assembly = ranges.Assembly(ranges.spans([(10, 5)]))
    with pytest.raises(ProtocolError, match="bytes 11-15"):
        assembly.accept(11, 16, lambda n: b"x" * n)


@pytest.mark.parametrize(
    ("body", "content_type", "error", "match"),
    [
        (_multipart((5000, DATA[5000:5005])), None, ProtocolError, "not asked for"),
        (_multipart((10, DATA[10:4000])), None, ProtocolError, "not asked for"),
        (
            b"--b0undary\r\nContent-Type: x\r\n\r\nhello\r\n--b0undary--\r\n",
            None,
            ProtocolError,
            "no usable Content-Range",
        ),
        (
            b"--b0undary\r\nContent-Range: bytes 15-10/100\r\n\r\n\r\n--b0undary--\r\n",
            None,
            ProtocolError,
            "no usable Content-Range",
        ),
        (b"x" * (10 * 1024), None, ProtocolError, "too long"),
        ((b"\r\n" * 200_000), None, ProtocolError, "too long"),
        (_multipart((10, DATA[10:15]), closing=False), None, TransientError, "closed"),
        (
            _multipart((10, DATA[10:15]))[: -len(b"\r\n--b0undary--\r\nepilogue")] + b"extra\r\n",
            None,
            ProtocolError,
            "ran past",
        ),
        (
            _multipart((10, DATA[10:15]), closing=False)[:-4],
            None,
            TransientError,
            "inside the part",
        ),
    ],
    ids=[
        "outside",
        "too-much",
        "no-content-range",
        "backwards",
        "endless-line",
        "endless-framing",
        "truncated",
        "overrun",
        "cut-mid-part",
    ],
)
def test_a_malformed_multipart_answer_is_refused(body, content_type, error, match):
    with pytest.raises(error, match=match):
        _read([(10, 5), (40, 5)], body)


def test_a_multipart_answer_without_a_boundary_is_refused():
    response = _response(b"", "multipart/byteranges")
    with pytest.raises(ProtocolError, match="no boundary"):
        ranges.boundary(response)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("bytes 0-9/100", (0, 10)),
        ("bytes 5-5/*", (5, 6)),
        ("BYTES 1-2/3", (1, 3)),
        ("bytes */100", None),
        ("bytes 9-0/100", None),
        ("items 0-9/100", None),
        ("", None),
    ],
)
def test_content_range_values(value, expected):
    assert ranges.content_range(value) == expected


def test_a_coalesced_part_read_in_small_chunks_lands_in_the_right_spans(monkeypatch):
    monkeypatch.setattr(ranges, "_CHUNK", 3)
    merged = _read([(10, 5), (20, 5)], _multipart((10, DATA[10:25])))
    assert ranges.assemble(merged, [(10, 5), (20, 5)]) == [DATA[10:15], DATA[20:25]]
