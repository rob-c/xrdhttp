"""HTTP third-party copy: the request headers, the far side's token, the marker stream."""

from __future__ import annotations

import io

import pytest

from xrdhttp import tpc
from xrdhttp.tpc import CopyOptions, Marker, Outcome

from tests._sockets import canned_response


def _stream(text: str) -> io.BytesIO:
    return io.BytesIO(text.encode())


MARKERS = """Perf Marker
Timestamp: 1700000000
Stripe Index: 0
Stripe Bytes Transferred: 100
Total Stripe Count: 2
End
Perf Marker
Stripe Index: 1
Stripe Bytes Transferred: 50
Total Stripe Count: 2
End
Perf Marker
Stripe Index: 0
Stripe Bytes Transferred: 300
Total Stripe Count: x
End
Perf Marker
Timestamp: soon
End
"""


def test_markers_are_summed_over_stripes_up_to_the_verdict():
    seen = []
    outcome = tpc.follow_markers(
        _stream(MARKERS + "success: Created\n").readline, lambda t, m: seen.append((t, m))
    )
    assert outcome == Outcome("success", "success: Created", 350)
    assert seen == [
        (100, Marker(0, 100, 2, 1700000000)),
        (150, Marker(1, 50, 2, 0)),
        (350, Marker(0, 300, 1, 0)),
        (350, None),  # a keepalive block: no byte count
    ]


@pytest.mark.parametrize(
    ("last", "kind"),
    [
        ("failure: HTTP 403 while reading", "failure"),
        ("Failed: oops", "failure"),
        ("aborted", "aborted"),
        ("", "closed"),
    ],
)
def test_every_ending(last, kind):
    outcome = tpc.follow_markers(_stream(MARKERS + last + ("\n" if last else "")).readline)
    assert outcome.kind == kind and outcome.transferred == 350


def test_a_bad_stripe_index_is_stripe_zero():
    text = "Perf Marker\nStripe Index: one\nStripe Bytes Transferred: 9\nEnd\nsuccess\n"
    assert tpc.follow_markers(_stream(text).readline).transferred == 9


def test_markers_read_from_a_real_response_with_the_line_limit():
    body = MARKERS + "success\n"
    response = canned_response(
        b"HTTP/1.1 202 Accepted\r\nContent-Length: %d\r\n\r\n" % len(body) + body.encode(),
        "COPY",
    )
    limits = []

    def readline(limit: int) -> bytes:
        limits.append(limit)
        return response.readline(limit)

    assert tpc.follow_markers(readline, limit=128).kind == "success"
    assert set(limits) == {128}


@pytest.mark.parametrize(
    ("line", "detail", "status"),
    [
        ("failure: source said HTTP 403 Forbidden", "source said HTTP 403 Forbidden", 403),
        ("failure: timeout", "timeout", None),
        ("failure", "failure", None),
        ("failed: 5000 bytes, 404", "5000 bytes, 404", 404),
    ],
)
def test_failure_detail(line, detail, status):
    assert tpc.failure_detail(line) == (detail, status)


def test_copy_headers_for_a_pull_with_everything():
    headers = tpc.copy_headers(
        "https://src.example/f",
        CopyOptions(
            mode="pull",
            overwrite=False,
            token="far-token",
            verify=True,
            streams=4,
            transfer_headers={"X-Extra": "1", "Authorization": "Bearer override"},
        ),
    )
    assert headers == {
        "Source": "https://src.example/f",
        "Overwrite": "F",
        "Credential": "none",
        "TransferHeaderAuthorization": "Bearer override",
        "RequireChecksumVerification": "true",
        "X-Number-Of-Streams": "4",
        "TransferHeaderX-Extra": "1",
    }


def test_copy_headers_for_a_delegated_push():
    headers = tpc.copy_headers(
        "https://dst.example/f", CopyOptions(mode="push", delegate=True, verify=False)
    )
    assert headers == {
        "Destination": "https://dst.example/f",
        "Overwrite": "T",
        "Credential": "gridsite",
        "RequireChecksumVerification": "false",
    }


def test_ends():
    assert tpc.ends("pull", "src", "dst") == ("dst", "src")
    assert tpc.ends("push", "src", "dst") == ("src", "dst")


def test_the_far_sides_token():
    assert tpc.remote_token({"authz": "Bearer from-url"}, "explicit") == "from-url"
    assert tpc.remote_token({}, "explicit") == "explicit"
    assert tpc.remote_token({}) is None


@pytest.mark.parametrize(
    ("url", "stripped"),
    [
        ("https://h/f?authz=tok&x=a%20b+c", "https://h/f?x=a%20b+c"),
        ("https://h/f?access_token=t", "https://h/f"),
        ("https://h/f?X-Amz-Signature=s&authz=t&", "https://h/f?X-Amz-Signature=s"),
        ("https://h/f", "https://h/f"),
    ],
)
def test_strip_tokens_keeps_the_rest_as_written(url, stripped):
    assert tpc.strip_tokens(url) == stripped


def test_minted_token_lifetime_and_caveats():
    assert tpc.token_minutes(None) == 10
    assert tpc.token_minutes(1800) == 70
    assert tpc.macaroon_caveats(False) == ["activity:LIST,DOWNLOAD"]
    assert tpc.macaroon_caveats(True) == ["activity:LIST,DOWNLOAD,MANAGE,UPLOAD,DELETE"]


def test_copy_headers_leave_streams_to_the_server_and_waive_verification_like_gfal2():
    assert tpc.copy_headers("https://src/f", CopyOptions()) == {
        "Source": "https://src/f",
        "Overwrite": "T",
        "Credential": "none",
        "RequireChecksumVerification": "false",
    }


def test_lines_that_are_neither_fields_nor_markers_are_ignored():
    text = "Perf Marker\nnoise without a colon\nStripe Bytes Transferred: 3\nEnd\nsuccess\n"
    assert tpc.follow_markers(_stream(text).readline).transferred == 3


def test_a_signed_byte_count_is_a_keepalive_and_the_verdict_is_read_in_any_case():
    """Ported from xrdclient's suite: ``-3`` is no count, so the block reports
    no marker and leaves the totals alone; ``FAILED`` is a failure however cased."""
    seen: list[tuple[int, Marker | None]] = []
    text = "Perf Marker\nStripe Bytes Transferred: 10\nEnd\n"
    text += "Perf Marker\nStripe Bytes Transferred: -3\nEnd\nFAILED: 403\n"
    outcome = tpc.follow_markers(_stream(text).readline, lambda t, m: seen.append((t, m)))
    assert seen == [(10, Marker(0, 10)), (10, None)]
    assert outcome == Outcome("failure", "FAILED: 403", 10)
