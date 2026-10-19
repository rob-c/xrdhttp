"""The pooled session: requests, pooling, retries, redirects, TLS, errors and the session's life.

Every case runs against an in-process scripted server (``tests/_http.py``,
``tests/_sockets.py``), so what is checked is the bytes the session puts on
a socket and what it makes of the bytes it gets back. Uploads and the
response object have their own modules.
"""

from __future__ import annotations

import errno
import http.client
import pickle
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from xrdcore import errors as core_errors
from xrdcore import retry
from xrdhttp import connection, session
from xrdhttp.session import (
    Answer,
    Auth,
    Errors,
    Failure,
    FileBody,
    Hop,
    Policy,
    RedirectPolicy,
    RetryPolicy,
    Route,
    Session,
)

from tests._http import Seen, answer, serve
from tests._sockets import Scripted, context_pair, read_request

Start = Callable[[Callable[[socket.socket], None]], Scripted]


class Ceiling:
    """A jitter source answering the top of every window, so backoff pauses are exact."""

    def uniform(self, a: float, b: float) -> float:
        return b


@pytest.fixture
def ceiling() -> Iterator[None]:
    previous = retry.use_rng(Ceiling())
    yield
    retry.use_rng(previous)


@pytest.fixture
def sleeps() -> list[float]:
    return []


def _session(sleeps: list[float], **retry_settings: Any) -> Session:
    """A session retrying as ``retry_settings`` say, its pauses recorded in ``sleeps``."""
    return Session(policy=Policy(retry=RetryPolicy(sleep=sleeps.append, **retry_settings)))


def _status(client: Session, method: str, url: str, **options: Any) -> int:
    """The status of one request's answer, its response closed."""
    with client.request(method, url, **options) as response:
        return response.status


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


def _url(server: Scripted, path: str = "/f", host: str = "127.0.0.1") -> str:
    return f"http://{host}:{server.port}{path}"


def _queue(*answers: bytes | None) -> Callable[[Seen], bytes | None]:
    """A handler giving ``answers`` in turn, then ``200`` with an empty body."""
    pending = list(answers)

    def handler(request: Seen) -> bytes | None:
        return pending.pop(0) if pending else answer()

    return handler


# ---------------------------------------------------------------------------
# Plain requests and pooling
# ---------------------------------------------------------------------------


def test_a_request_is_read_whole_and_its_connection_pooled(scripted: Start) -> None:
    seen: list[Seen] = []
    server = scripted(serve(lambda r: answer(200, b"hello " + r.target.encode()), seen))
    with Session() as client:
        for _ in range(3):
            response = client.request("GET", _url(server, "/a?x=1"))
            assert (response.status, response.reason) == (200, "OK")
            assert response.body() == b"hello /a?x=1"
        assert server.connections == 1
        assert client.idle_count() == 1
        assert repr(client) == "Session(1 idle connection(s))"
    assert client.idle_count() == 0


def test_headers_are_standing_then_credentials_then_the_callers(scripted: Start) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(), seen))
    policy = Policy(headers={"User-Agent": "test/1", "X-Both": "standing"})
    with Session(policy=policy) as client:
        auth = Auth(headers={"Authorization": "Bearer t", "X-Both": "auth"})
        client.request("GET", _url(server), auth=auth, headers={"X-Mine": "1"}).close()
        client.request("GET", _url(server), headers={"Host": "door.example:1"}).close()
    first, second = seen
    assert first.headers["user-agent"] == "test/1"
    assert first.headers["authorization"] == "Bearer t"
    assert first.headers["x-both"] == "auth"
    assert first.headers["x-mine"] == "1"
    assert first.headers["host"] == f"127.0.0.1:{server.port}"
    assert "accept-encoding" not in first.headers  # exactly the headers built here
    assert second.headers["host"] == "door.example:1"  # the caller's own, not a second one


def test_a_grid_scheme_goes_as_http_and_a_bare_authority_as_slash(scripted: Start) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(), seen))
    with Session() as client:
        client.request("GET", f"dav://127.0.0.1:{server.port}").close()
    assert seen[0].target == "/"


def test_routes() -> None:
    assert Route.of("davs://Host.Example/a%20b?x=1#frag") == Route(
        "https", "host.example", 443, "/a%20b?x=1"
    )
    with pytest.raises(ValueError, match="not an HTTP scheme"):
        Route.of("ftp://host/x")
    with pytest.raises(ValueError, match="names no host"):
        Route.of("http:///x")


def test_body_lengths(tmp_path: Path) -> None:
    assert session.body_length(None) is None
    assert session.body_length(b"abc") == 3
    assert session.body_length(memoryview(bytearray(8)).cast("I")) == 8
    with open(tmp_path / "f", "wb+") as handle:
        assert session.body_length(FileBody(handle, 0, 5)) == 5


def test_a_file_body_is_sent_from_its_offset(scripted: Start, tmp_path: Path) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(), seen))
    source = tmp_path / "data"
    source.write_bytes(b"0123456789")
    progress: list[int] = []
    with Session() as client, open(source, "rb") as handle:
        body = FileBody(handle, 2, 5, progress=progress.append)
        client.request("PUT", _url(server), body=body).close()
    assert seen[0].body == b"23456"
    assert seen[0].headers["content-length"] == "5"
    assert progress == [5]


def test_keep_alive_off_closes_every_connection(scripted: Start) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(), seen))
    switch = [False]
    with Session(policy=Policy(keep_alive=lambda: switch[0])) as client:
        client.request("GET", _url(server)).close()
        assert client.idle_count() == 0
        switch[0] = True
        client.request("GET", _url(server)).close()
        assert client.idle_count() == 1
    with Session(policy=Policy(keep_alive=False)) as client:
        client.request("GET", _url(server)).close()
        assert client.idle_count() == 0
    assert server.connections == 3


def test_no_connect_timeout_takes_the_requests(scripted: Start) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(), seen))
    with Session(policy=Policy(connect_timeout=None)) as client:
        response = client.request("GET", _url(server), timeout=7.0)
        assert response._exchange.conn.timeout == 7.0
        response.close()


def test_a_read_timeout_of_zero_or_less_is_no_limit(scripted: Start) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(), seen))
    with Session() as client:
        response = client.request("GET", _url(server), timeout=0)
        sock = response._exchange.conn.sock
        assert sock is not None and sock.gettimeout() is None
        response.close()
        response = client.request("GET", _url(server), timeout=4.5)
        sock = response._exchange.conn.sock
        assert sock is not None and sock.gettimeout() == 4.5
        response.close()


# ---------------------------------------------------------------------------
# Status errors
# ---------------------------------------------------------------------------


def test_an_unwanted_status_is_raised_with_its_body(scripted: Start) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(answer(404, b"no such file", "Not Found")), seen))
    with Session() as client:
        with pytest.raises(session.HTTPStatusError) as caught:
            client.request("GET", _url(server), expect=(200,))
        # The error body was read, so the connection went back to the pool.
        assert client.idle_count() == 1
    error = caught.value
    assert (error.status, error.reason, error.body) == (404, "Not Found", "no such file")
    assert error.url == _url(server)
    assert isinstance(error, core_errors.ProtocolError)
    copy = pickle.loads(pickle.dumps(error))
    assert (copy.status, copy.reason, copy.url, copy.body) == (
        404,
        "Not Found",
        error.url,
        "no such file",
    )


def test_no_expect_returns_every_answer(scripted: Start) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(answer(500)), seen))
    with Session() as client:
        assert _status(client, "GET", _url(server)) == 500


class _Mine(Errors):
    """A client's vocabulary: its own exception for an unwanted status."""

    def status(self, answer: Answer) -> Exception:
        return FileExistsError(errno.EEXIST, f"{answer.method} {answer.status} {answer.text}")


def test_a_clients_errors_word_the_status(scripted: Start) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(answer(409, b"\xffthere")), seen))
    with Session() as client, pytest.raises(FileExistsError, match="PUT 409 �there"):
        client.request("PUT", _url(server), body=b"x", expect=(201,), errors=_Mine())


def test_an_error_body_lost_mid_read_still_reports_the_status(
    scripted: Start, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(answer(403, b"why")), seen))

    def broken(self: http.client.HTTPResponse, amount: int | None = None) -> bytes:
        raise ConnectionResetError("reset")

    with Session() as client:
        monkeypatch.setattr(http.client.HTTPResponse, "read", broken)
        with pytest.raises(session.HTTPStatusError) as caught:
            client.request("GET", _url(server), expect=(200,))
        assert client.idle_count() == 0  # a connection that failed mid-body is not pooled
    assert (caught.value.status, caught.value.body) == (403, "")


def test_default_errors() -> None:
    errors = Errors()
    timeout = errors.transport(Failure("GET", "http://h/x?authz=secret", TimeoutError("slow")))
    assert isinstance(timeout, core_errors.TimeoutError)
    assert "secret" not in str(timeout)
    failed = errors.transport(Failure("GET", "http://h/x", ConnectionRefusedError("no")))
    assert type(failed) is core_errors.ConnectionError
    assert "failed: no" in str(failed)
    assert isinstance(errors.redirect("GET", "http://h/", "loop"), session.RedirectError)
    closed = errors.closed(False)
    assert isinstance(closed, session.SessionClosedError) and isinstance(closed, ValueError)
    assert "aborted" in str(errors.closed(True))


# ---------------------------------------------------------------------------
# Retries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("header", "expected"), [("7", [7.0]), ("3600", [30.0]), ("0", [])])
def test_retry_after_is_honoured_up_to_the_cap(
    scripted: Start, sleeps: list[float], header: str, expected: list[float]
) -> None:
    seen: list[Seen] = []
    busy = answer(503, b"busy", "Busy", {"Retry-After": header})
    server = scripted(serve(_queue(busy), seen))
    with _session(sleeps, retries=2) as client:
        assert _status(client, "GET", _url(server), expect=(200,)) == 200
    assert sleeps == expected
    assert len(seen) == 2


def test_backoff_doubles_without_retry_after(
    scripted: Start, sleeps: list[float], ceiling: None
) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(answer(429), answer(503)), seen))
    with _session(sleeps, retries=3, backoff=0.1) as client:
        assert _status(client, "GET", _url(server)) == 200
    assert sleeps == pytest.approx([0.1, 0.2])


def test_the_pause_is_slept_by_default(scripted: Start, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(answer(503, headers={"Retry-After": "2"})), seen))
    slept: list[float] = []
    monkeypatch.setattr(time, "sleep", slept.append)
    with Session(policy=Policy(retry=RetryPolicy(retries=1))) as client:
        assert _status(client, "GET", _url(server)) == 200
    assert slept == [2.0]


def test_exhausted_retries_raise_the_last_answer(scripted: Start, sleeps: list[float]) -> None:
    seen: list[Seen] = []
    server = scripted(serve(lambda r: answer(503, reason="Overloaded"), seen))
    with _session(sleeps, retries=2, backoff=0) as client:
        with pytest.raises(session.HTTPStatusError) as caught:
            client.request("GET", _url(server), expect=(200,))
        assert _status(client, "GET", _url(server)) == 503
    assert caught.value.reason == "Overloaded"
    assert len(seen) == 6
    assert sleeps == []  # a zero backoff does not even sleep


def test_an_expected_retry_status_is_the_answer(scripted: Start, sleeps: list[float]) -> None:
    seen: list[Seen] = []
    server = scripted(serve(lambda r: answer(503), seen))
    with _session(sleeps, retries=2) as client:
        assert _status(client, "GET", _url(server), expect=(200, 503)) == 503
    assert len(seen) == 1


@pytest.mark.parametrize(
    ("method", "options", "attempts"),
    [
        ("POST", {}, 1),
        ("POST", {"idempotent": True}, 2),
        ("PUT", {"headers": {"If-None-Match": "*"}}, 1),
        ("PUT", {}, 2),
        ("GET", {"idempotent": False}, 1),
    ],
)
def test_only_a_replayable_request_is_retried(
    scripted: Start, sleeps: list[float], method: str, options: dict[str, Any], attempts: int
) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(answer(503)), seen))
    with _session(sleeps, retries=2, backoff=0) as client:
        client.request(method, _url(server), body=b"x", **options).close()
    assert len(seen) == attempts


def test_a_dropped_connection_is_retried_with_backoff(
    scripted: Start, sleeps: list[float], ceiling: None
) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(None, None), seen))
    with _session(sleeps, retries=2, transport=True) as client:
        assert _status(client, "GET", _url(server)) == 200
    assert sleeps == [0.5, 1.0]
    assert server.connections == 3


def test_a_drop_is_raised_without_transport_retries(scripted: Start, sleeps: list[float]) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(None), seen))
    with (
        _session(sleeps, retries=2) as client,
        pytest.raises(core_errors.ConnectionError, match="GET http"),
    ):
        client.request("GET", _url(server))
    assert sleeps == []


def test_a_refused_connection_is_retried_then_reported(sleeps: list[float], ceiling: None) -> None:
    url = f"http://127.0.0.1:{_free_port()}/x"
    with (
        _session(sleeps, retries=2, transport=True, backoff=0.01) as client,
        pytest.raises(core_errors.ConnectionError) as caught,
    ):
        client.request("GET", url)
    assert isinstance(caught.value.__cause__, ConnectionRefusedError)
    assert len(sleeps) == 2


def test_a_timeout_is_never_retried(scripted: Start, sleeps: list[float]) -> None:
    release = threading.Event()

    def silent(sock: socket.socket) -> None:
        read_request(sock)
        release.wait(10)

    server = scripted(silent)
    try:
        with (
            _session(sleeps, retries=2, transport=True) as client,
            pytest.raises(core_errors.TimeoutError),
        ):
            client.request("GET", _url(server), timeout=0.2)
    finally:
        release.set()
    assert sleeps == []


def test_transient_failures() -> None:
    assert session._transient(ConnectionResetError())
    assert session._transient(ssl.SSLEOFError())
    assert not session._transient(TimeoutError())
    assert not session._transient(connection_short_file())
    assert not session._transient(ssl.SSLCertVerificationError())


def connection_short_file() -> OSError:
    """The error a local file that ran out of bytes mid-upload raises."""
    from xrdhttp.wire import ShortFileError

    return ShortFileError(3)


@pytest.fixture
def trusting(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pooled connections pass the liveness poll, so a stale one reaches a request."""
    monkeypatch.setattr(
        connection._Liveness, "is_connected", property(lambda self: self.sock is not None)
    )


def _answer_once(sock: socket.socket) -> None:
    """Answer one request, then hang up without saying so: a server's idle timeout."""
    read_request(sock)
    sock.sendall(answer(200, b"ok"))


def test_a_stale_pooled_connection_is_replaced_at_once(scripted: Start, trusting: None) -> None:
    server = scripted(_answer_once)
    with Session() as client:
        assert client.request("GET", _url(server)).body() == b"ok"
        time.sleep(0.1)  # the server's hang-up has arrived
        assert client.request("GET", _url(server)).body() == b"ok"
    assert server.connections == 2


def test_with_transport_retries_a_stale_connection_is_one_more_failure(
    scripted: Start, trusting: None, sleeps: list[float], ceiling: None
) -> None:
    server = scripted(_answer_once)
    with _session(sleeps, retries=1, transport=True) as client:
        assert client.request("GET", _url(server)).body() == b"ok"
        time.sleep(0.1)
        assert client.request("GET", _url(server)).body() == b"ok"
    assert sleeps == [0.5]  # counted and paused for, not replayed at once


def test_a_stale_connection_replays_a_post_only_by_davix_rule(
    scripted: Start, trusting: None
) -> None:
    server = scripted(_answer_once)
    with Session() as client:
        client.request("GET", _url(server)).body()
        time.sleep(0.1)
        with pytest.raises(core_errors.ConnectionError):
            client.request("POST", _url(server), body=b"x")
    unanswered = Policy(retry=RetryPolicy(replay_unanswered=True))
    with Session(policy=unanswered) as client:
        client.request("GET", _url(server)).body()
        time.sleep(0.1)
        assert client.request("POST", _url(server), body=b"x").body() == b"ok"


# ---------------------------------------------------------------------------
# Redirects
# ---------------------------------------------------------------------------


def test_a_redirect_within_the_origin_keeps_the_credentials(scripted: Start) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(answer(302, headers={"Location": "/elsewhere"})), seen))
    auth = Auth(headers={"Authorization": "Bearer t"})
    with Session() as client:
        response = client.request("PUT", _url(server), auth=auth, body=b"data")
        assert response.url == _url(server, "/elsewhere")
        response.close()
        assert server.connections == 1  # the redirect's connection carried the next hop
    assert [(r.method, r.target, r.body) for r in seen] == [
        ("PUT", "/f", b"data"),
        ("PUT", "/elsewhere", b"data"),
    ]
    assert seen[1].headers["authorization"] == "Bearer t"


def test_a_redirect_to_another_origin_drops_the_credentials(scripted: Start) -> None:
    seen: list[Seen] = []
    target = scripted(serve(_queue(), seen))
    elsewhere = _url(target, "/d", host="localhost")
    door = scripted(serve(_queue(answer(307, headers={"Location": elsewhere})), seen))
    headers = {"TransferHeaderAuthorization": "far", "Cookie": "c", "X-Plain": "p"}
    auth = Auth(headers={"Authorization": "Bearer t"})
    with Session() as client:
        client.request("COPY", _url(door), auth=auth, headers=headers).close()
    hop = seen[1].headers
    assert "authorization" not in hop and "cookie" not in hop
    assert hop["x-plain"] == "p"
    # An address is no site: a TransferHeader stays with its host.
    assert "transferheaderauthorization" not in hop


def test_a_relay_policy_may_keep_the_transfer_headers(scripted: Start) -> None:
    seen: list[Seen] = []
    target = scripted(serve(_queue(), seen))
    elsewhere = _url(target, host="localhost")
    door = scripted(serve(_queue(answer(307, headers={"Location": elsewhere})), seen))
    policy = Policy(redirects=RedirectPolicy(relays=lambda origin, target: True))
    headers = {"TransferHeaderAuthorization": "far", "Authorization": "mine"}
    with Session(policy=policy) as client:
        client.request("COPY", _url(door), headers=headers).close()
    assert seen[1].headers["transferheaderauthorization"] == "far"
    assert "authorization" not in seen[1].headers


def test_a_303_becomes_a_get_and_follow_false_hands_back_the_redirect(scripted: Start) -> None:
    seen: list[Seen] = []
    see_other = answer(303, headers={"Location": "/result"})
    server = scripted(serve(_queue(see_other, answer(), see_other), seen))
    with Session() as client:
        client.request("POST", _url(server), body=b"form").close()
        response = client.request("POST", _url(server), body=b"form", follow=False)
        assert (response.status, response.header("Location")) == (303, "/result")
        response.close()
    assert [(r.method, r.target) for r in seen] == [
        ("POST", "/f"),
        ("GET", "/result"),
        ("POST", "/f"),
    ]


def test_too_many_redirects(scripted: Start) -> None:
    seen: list[Seen] = []
    server = scripted(serve(lambda r: answer(302, headers={"Location": "/again"}), seen))
    policy = Policy(redirects=RedirectPolicy(limit=2))
    with (
        Session(policy=policy) as client,
        pytest.raises(session.RedirectError, match="more than 2"),
    ):
        client.request("GET", _url(server))
    assert len(seen) == 3


def test_a_redirect_to_a_url_that_is_not_http(scripted: Start) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(answer(302, headers={"Location": "ftp://h/x"})), seen))
    with Session() as client, pytest.raises(session.RedirectError, match="unusable Location"):
        client.request("GET", _url(server))


def test_a_first_401_may_be_answered_with_new_credentials(scripted: Start) -> None:
    seen: list[Seen] = []
    challenge = answer(401, headers={"WWW-Authenticate": "Bearer"})
    server = scripted(serve(_queue(challenge, challenge, challenge), seen))
    asked: list[str] = []

    def reauth(url: str, response: session.Response) -> Auth | None:
        asked.append(response.header("WWW-Authenticate"))
        return Auth(headers={"Authorization": "Bearer fresh"}) if len(asked) == 1 else None

    with Session() as client:
        # Answered once; the second 401 of the same request is the answer.
        assert _status(client, "GET", _url(server), reauth=reauth) == 401
        # A hook with nothing to offer hands the 401 back at once.
        assert _status(client, "GET", _url(server), reauth=reauth) == 401
        assert _status(client, "GET", _url(server)) == 200
    assert seen[1].headers["authorization"] == "Bearer fresh"
    assert asked == ["Bearer", "Bearer"]


def test_the_prepare_hook_sees_the_final_headers_and_may_move_the_hop(scripted: Start) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(), seen))
    hops: list[Hop] = []

    def sign(hop: Hop) -> None:
        hops.append(hop)
        hop.url = hop.url.replace("/f", "/bucket/f")
        hop.headers["Signature"] = ",".join(sorted(hop.headers))

    with Session() as client:
        client.request("PUT", _url(server), body=b"abc", auth=Auth(prepare=sign)).close()
    assert seen[0].target == "/bucket/f"
    assert seen[0].headers["signature"] == "Content-Length"
    assert hops[0].origin == _url(server) and hops[0].credentials


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------


@pytest.fixture
def tls_server(scripted: Start, tmp_path: Path) -> tuple[Scripted, ssl.SSLContext, list[Seen]]:
    server_context, client_context = context_pair(tmp_path)
    seen: list[Seen] = []
    plain = serve(_queue(), seen)

    def script(sock: socket.socket) -> None:
        try:
            wrapped = server_context.wrap_socket(sock, server_side=True)
        except (ssl.SSLError, OSError):
            return  # a client that refused the certificate
        with wrapped:
            plain(wrapped)

    return scripted(script), client_context, seen


def test_https_uses_the_factorys_context(
    tls_server: tuple[Scripted, ssl.SSLContext, list[Seen]],
) -> None:
    server, context, seen = tls_server
    asked: list[str] = []

    def factory(url: str) -> ssl.SSLContext:
        asked.append(url)
        return context

    url = f"https://localhost:{server.port}/secure"
    with Session(tls=factory) as client:
        client.request("GET", url).close()
        client.request("GET", url, auth=Auth(tls=context)).close()
        assert client.idle_count() == 1  # one context, one pool
    assert asked == [url]
    assert seen[0].target == "/secure"


def test_a_server_that_cannot_be_verified_is_not_retried(
    tls_server: tuple[Scripted, ssl.SSLContext, list[Seen]], sleeps: list[float]
) -> None:
    server, _, _ = tls_server
    with (
        _session(sleeps, retries=2, transport=True) as client,
        pytest.raises(core_errors.ConnectionError) as caught,
    ):
        client.request("GET", f"https://localhost:{server.port}/")
    assert isinstance(caught.value.__cause__, ssl.SSLCertVerificationError)
    assert sleeps == []


def _unverified() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def test_an_unverified_connection_warns(
    tls_server: tuple[Scripted, ssl.SSLContext, list[Seen]],
) -> None:
    server, _, _ = tls_server
    url = f"https://localhost:{server.port}/"
    with (
        Session(tls=lambda url: _unverified()) as client,
        pytest.warns(session.UnverifiedTLSWarning, match="localhost"),
    ):
        client.request("GET", url).close()
    with Session(tls=lambda url: _unverified(), policy=Policy(warn_unverified=False)) as client:
        client.request("GET", url).close()


# ---------------------------------------------------------------------------
# The session's life
# ---------------------------------------------------------------------------


def test_clear_keeps_the_session_and_close_ends_it(scripted: Start) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(), seen))
    client = Session()
    client.request("GET", _url(server)).close()
    client.clear()
    assert client.idle_count() == 0
    response = client.request("GET", _url(server))
    client.clear()
    response.close()  # its pool is gone: the connection is closed, not pooled
    assert client.idle_count() == 0
    client.close()
    with pytest.raises(session.SessionClosedError, match="closed"):
        client.request("GET", _url(server))


def test_abort_wakes_a_request_in_flight(scripted: Start) -> None:
    arrived, release = threading.Event(), threading.Event()

    def stall(sock: socket.socket) -> None:
        read_request(sock)
        arrived.set()
        release.wait(10)

    server = scripted(stall)
    client = Session()
    outcome: list[BaseException] = []

    def run() -> None:
        try:
            client.request("GET", _url(server))
        except BaseException as exc:
            outcome.append(exc)

    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert arrived.wait(5)
        client.abort()
        worker.join(5)
    finally:
        release.set()
    assert isinstance(outcome[0], session.SessionClosedError)
    with pytest.raises(session.SessionClosedError, match="aborted"):
        client.request("GET", _url(server))


def test_watch_hears_of_every_checked_out_connection(scripted: Start) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(), seen))
    registered: list[Callable[[], None]] = []
    released: list[int] = []

    def watch(abort: Callable[[], None]) -> Callable[[], None]:
        registered.append(abort)
        return lambda: released.append(len(registered))

    with Session(watch=watch) as client:
        client.request("GET", _url(server)).close()
    assert len(registered) == 1 and released == [1]


def test_a_refusing_watch_stops_the_request_before_a_byte(scripted: Start) -> None:
    seen: list[Seen] = []
    server = scripted(serve(_queue(), seen))

    def refuse(abort: Callable[[], None]) -> Callable[[], None]:
        raise InterruptedError("cancelled")

    with Session(watch=refuse) as client:
        with pytest.raises(InterruptedError):
            client.request("GET", _url(server))
        assert client.idle_count() == 1  # the unused connection went back
    assert seen == []


def test_an_exchange_abort_is_harmless_without_a_socket() -> None:
    conn = connection.HTTPConnection("127.0.0.1", 1)
    exchange = session._Exchange(("http", "127.0.0.1", 1, None), conn, False)
    exchange.abort()  # never connected
    conn.sock = socket.socket()
    conn.sock.close()
    exchange.abort()  # already closed: nothing to wake
    exchange.close()
