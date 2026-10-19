"""The fake storage element's front: lifecycle, records, faults, hooks, auth, redirects, Expect."""

from __future__ import annotations

import base64
import contextlib
import json
import socket
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from xrdhttp.testing import STYLES, MemoryStore, StorageServer

from tests._storage import ask, identities, raw


@pytest.fixture
def server() -> Iterator[StorageServer]:
    """An XrdCl-style fake holding ``/d/a.root``."""
    with StorageServer(MemoryStore({"/d/a.root": b"hello world"})) as srv:
        yield srv


@pytest.fixture
def davix() -> Iterator[StorageServer]:
    """A davix-style fake holding ``/d/a.root``."""
    with StorageServer(MemoryStore({"/d/a.root": b"hello world"}), style="davix") as srv:
        yield srv


# -- lifecycle and records -------------------------------------------------------------------


def test_a_server_binds_on_first_use_and_remembers_where_it_was():
    srv = StorageServer()
    assert repr(srv) == "StorageServer(unbound, requests=0)"
    srv.stop()  # never bound: nothing to release
    address = srv.address  # binds, without serving
    assert repr(srv).startswith("StorageServer(127.0.0.1:")
    srv.stop()
    assert srv.address == address and srv.port == address[1] and srv.host == "127.0.0.1"
    assert repr(srv) == f"StorageServer(127.0.0.1:{address[1]}, requests=0)"
    assert srv.base == f"http://127.0.0.1:{address[1]}" and srv.scheme == "http"
    with srv:
        assert srv.start() is srv  # already serving: no second thread
        assert ask(srv, "GET", "/nothing").status == 404


def test_stop_hangs_up_on_a_kept_alive_connection_and_need_not_wait(server):
    sock = socket.create_connection(server.address)
    sock.sendall(b"GET /d/a.root HTTP/1.1\r\nHost: h\r\n\r\n")
    answer = b""
    while not answer.endswith(b"hello world"):
        answer += sock.recv(4096)
    server.join_timeout = None
    server.stop()
    assert sock.recv(4096) == b""  # hung up on, as a dead server would
    sock.close()


def test_every_connection_is_counted(server):
    for _ in range(3):
        ask(server, "GET", "/d/a.root")
    assert server.connections == 3 and server.peer_certificates == []


def test_contents_seeding_and_records(server):
    server.add_file("/e/f", b"x")
    server.add_dir("/g/h")
    assert server.contents("e/f") == b"x"
    with pytest.raises(KeyError):
        server.contents("/g")
    with pytest.raises(KeyError):
        server.contents("/missing")
    ask(server, "GET", "/e/f?q=1")
    request = server.requests[-1]
    assert (request.method, request.target, request.path) == ("GET", "/e/f?q=1", "/e/f")
    assert request.param("q") == "1" and request.param("r", "-") == "-"
    assert request.header("HOST") and request.header("X-None") is None
    assert server.methods() == ["GET"]
    server.clear()
    assert server.requests == []


def test_the_styles_set_their_switches():
    davix = StorageServer(style="davix")
    for name, value in STYLES["davix"].items():
        assert getattr(davix, name) == value
    assert davix.digests is not STYLES["davix"]["digests"]  # a copy each


# -- faults ----------------------------------------------------------------------------------


def test_a_status_fault_answers_instead_and_is_used_up(server):
    fault = server.fault(
        "GET", "/d/a", status=503, body=b"busy", headers={"Retry-After": "1"}, times=2
    )
    assert ask(server, "GET", "/d/a.root").status == 503
    assert fault.times == 1 and server.faults == [fault]
    assert ask(server, "GET", "/d/a.root").header("Retry-After") == "1"
    assert server.faults == []
    assert ask(server, "GET", "/d/a.root").body == b"hello world"


def test_a_fault_on_another_method_or_path_is_left_alone(server):
    server.fault("PUT", status=500)
    server.fault(path="/other", status=500)
    assert ask(server, "GET", "/d/a.root").status == 200


def test_a_stalled_or_truncated_real_answer(server):
    server.fault("GET", stall=0.05)
    started = time.monotonic()
    assert ask(server, "GET", "/d/a.root").body == b"hello world"
    assert time.monotonic() - started >= 0.05
    server.fault("GET", truncate=5)
    answer = raw(server, b"GET /d/a.root HTTP/1.1\r\nHost: h\r\n\r\n")
    assert b"Content-Length: 11" in answer and answer.endswith(b"\r\n\r\nhello")
    server.fault("GET", truncate=5, hold=0.05)
    assert raw(server, b"GET /d/a.root HTTP/1.1\r\nHost: h\r\n\r\n").endswith(b"hello")
    server.fault("GET", status=503, reason="Busy\r\nnow")
    assert raw(server, b"GET /d/a.root HTTP/1.1\r\nHost: h\r\n\r\n").startswith(
        b"HTTP/1.1 503 Busy  now"
    )


def test_a_delay_alone_lets_the_request_through(server):
    server.fault("GET", delay=0.01)
    assert ask(server, "GET", "/d/a.root").status == 200


def test_a_dropped_connection_gets_no_answer(server):
    server.fault("GET", drop=True)
    assert raw(server, b"GET /d/a.root HTTP/1.1\r\nHost: h\r\n\r\n") == b""


def test_a_truncated_answer_promises_more_than_it_sends(server):
    server.fault("GET", status=200, body=b"0123456789", truncate=4)
    answer = raw(server, b"GET /d/a.root HTTP/1.1\r\nHost: h\r\n\r\n")
    assert b"Content-Length: 10" in answer and answer.endswith(b"\r\n\r\n0123")


def test_a_held_fault_goes_silent_until_its_time_is_up(server):
    server.fault("GET", hold=0.05)
    assert raw(server, b"GET /d/a.root HTTP/1.1\r\nHost: h\r\n\r\n", shut=False) == b""
    server.fault("GET", hold=0.05, status=206, body=b"abc", truncate=1)
    answer = raw(server, b"GET /d/a.root HTTP/1.1\r\nHost: h\r\n\r\n", shut=False)
    assert answer.startswith(b"HTTP/1.1 206") and answer.endswith(b"\r\n\r\na")


# -- the canned hook -----------------------------------------------------------------------------


def test_a_handler_answers_for_the_server_or_lets_it(server):
    calls: list[tuple[str, str]] = []

    def hook(
        method: str, path: str, headers: dict[str, str]
    ) -> tuple[int, bytes, dict[str, str]] | None:
        calls.append((method, path))
        return (418, b"teapot", {"X-Canned": "1"}) if path == "/d/a.root" else None

    server.handlers["GET"] = hook
    answer = ask(server, "GET", "/d/a.root")
    assert (answer.status, answer.body, answer.header("X-Canned")) == (418, b"teapot", "1")
    assert ask(server, "GET", "/missing").status == 404
    assert calls == [("GET", "/d/a.root"), ("GET", "/missing")]


def test_a_canned_refusal_of_a_streamed_upload_reads_the_body_first(server):
    server.handlers["PUT"] = lambda *_: (507, b"full", {})
    body = b"5\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\n"
    head = b"PUT /d/b HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
    answer = raw(server, head + body + b"GET /d/a.root HTTP/1.1\r\nHost: h\r\n\r\n")
    assert answer.startswith(b"HTTP/1.1 507") and answer.endswith(b"hello world")
    assert server.requests[0].body == b"hello"


# -- authorisation ---------------------------------------------------------------------------


def test_bearer_tokens_issued_or_configured(server):
    server.tokens = {"T"}
    refused = ask(server, "GET", "/d/a.root")
    assert (refused.status, refused.header("WWW-Authenticate")) == (401, "Bearer")
    assert ask(server, "GET", "/d/a.root", headers={"Authorization": "Bearer T"}).status == 200
    asking = {"Content-Type": "application/macaroon-request", "Authorization": "Bearer T"}
    token = json.loads(ask(server, "POST", "/d", b"{}", asking).body)["macaroon"]
    assert (
        ask(server, "GET", "/d/a.root", headers={"Authorization": f"Bearer {token}"}).status == 200
    )


def test_basic_authentication(server):
    server.basic = ("user", "pass")
    assert ask(server, "GET", "/d/a.root").status == 401
    login = base64.b64encode(b"user:pass").decode()
    assert (
        ask(server, "GET", "/d/a.root", headers={"Authorization": f"Basic {login}"}).status == 200
    )


def test_a_client_certificate_stands_in_for_a_token(tmp_path: Path):
    tls = identities(tmp_path)
    with StorageServer(MemoryStore({"/f": b"x"}), tls=tls.server) as srv:
        srv.tokens = {"T"}
        assert srv.base.startswith("https://") and srv.scheme == "https"
        assert ask(srv, "GET", "/f", context=tls.anonymous).status == 401
        assert ask(srv, "GET", "/f", context=tls.user).status == 200
        peer = srv.requests[-1].peer
        assert peer is not None and peer.subject == "/CN=Test User"
        assert srv.requests[0].peer is None
        assert srv.peer_certificates[0] == b"" and srv.peer_certificates[1]


def test_a_failed_handshake_is_quietly_dropped(tmp_path: Path):
    tls = identities(tmp_path)
    with StorageServer(tls=tls.server) as srv:
        with contextlib.suppress(OSError):  # cleartext at a TLS port: reset, or an alert
            raw(srv, b"GET / HTTP/1.1\r\n\r\n")
        assert ask(srv, "GET", "/", context=tls.anonymous).status == 200


# -- redirects -----------------------------------------------------------------------------------


def test_a_one_shot_redirect_is_used_up(server):
    server.redirects["/d/a.root"] = "http://elsewhere/d/a.root"
    moved = ask(server, "GET", "/d/a.root")
    assert (moved.status, moved.header("Location")) == (307, "http://elsewhere/d/a.root")
    assert ask(server, "GET", "/d/a.root").status == 200


def test_a_prefix_redirect_stays(server):
    server.redirect_prefixes["/x"] = "http://other:1"
    server.redirect_prefixes["/d"] = "http://pool:2"
    for _ in range(2):
        moved = ask(server, "GET", "/d/a.root?q=1")
        assert (moved.status, moved.header("Location")) == (307, "http://pool:2/d/a.root?q=1")


def test_an_early_redirect_hangs_up_without_reading_the_body(server):
    server.early_redirects = True
    server.redirects["/d/up"] = "http://pool/d/up"
    answer = raw(server, b"PUT /d/up HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n", shut=False)
    assert answer.startswith(b"HTTP/1.1 307") and b"Connection: close" in answer
    assert server.requests[-1].body == b""


# -- Expect: 100-continue and bodies -------------------------------------------------------------


def _expecting(path: str, length: int = 5) -> bytes:
    """The head of a ``PUT`` that waits for ``100 Continue``."""
    return (
        f"PUT {path} HTTP/1.1\r\nHost: h\r\nContent-Length: {length}\r\n"
        "Expect: 100-continue\r\n\r\n"
    ).encode()


def _first_answer(server: StorageServer, data: bytes) -> bytes:
    """What the server says first to ``data``, the connection held open."""
    with socket.create_connection(server.address, timeout=10) as sock:
        sock.sendall(data)
        return sock.recv(4096)


def test_continue_is_sent_with_a_header(server):
    assert _first_answer(server, _expecting("/d/b")).startswith(b"HTTP/1.1 100 Continue\r\nServer:")


def test_a_server_that_ignores_the_expectation_just_reads(server):
    server.expect_continue = False
    with socket.create_connection(server.address, timeout=10) as sock:
        sock.sendall(_expecting("/d/b"))
        sock.settimeout(0.2)
        with pytest.raises(TimeoutError):
            sock.recv(4096)
        sock.settimeout(10)
        sock.sendall(b"hello")
        assert sock.recv(4096).startswith(b"HTTP/1.1 201")


def test_an_early_redirect_answers_instead_of_continue(server):
    server.early_redirects = True
    server.redirects["/d/b"] = "http://pool/d/b"
    assert _first_answer(server, _expecting("/d/b")).startswith(b"HTTP/1.1 307")


def test_davix_style_refuses_before_continue(davix):
    davix.tokens = {"T"}
    assert _first_answer(davix, _expecting("/d/b")).startswith(b"HTTP/1.1 401")
    davix.tokens = set()
    assert _first_answer(davix, _expecting("/d/b")).startswith(b"HTTP/1.1 100")


def test_davix_style_closes_rather_than_drains_a_large_refused_body(davix):
    davix.fault("PUT", status=403)
    head = b"PUT /d/big HTTP/1.1\r\nHost: h\r\nContent-Length: 2000000\r\n\r\n"
    assert raw(davix, head, shut=False).startswith(b"HTTP/1.1 403")


def test_a_small_body_is_read_before_an_early_answer(davix):
    davix.fault("PUT", status=403)
    request = b"PUT /d/b HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\nhi"
    answer = raw(davix, request + b"GET /d/a.root HTTP/1.1\r\nHost: h\r\n\r\n")
    assert answer.startswith(b"HTTP/1.1 403") and answer.endswith(b"hello world")
    assert davix.requests[0].body == b"hi"


def test_a_body_cut_short_closes_the_connection(server):
    answer = raw(server, b"PUT /d/cut HTTP/1.1\r\nHost: h\r\nContent-Length: 2000000\r\n\r\nabc")
    assert answer.startswith(b"HTTP/1.1 201")
    assert server.contents("/d/cut") == b"abc"


def test_a_large_upload_is_not_kept_in_the_record(server):
    server.body_record_limit = 4
    assert ask(server, "PUT", "/d/big", b"0123456789").status == 201
    assert server.requests[-1].body == b"" and server.contents("/d/big") == b"0123456789"


def test_an_unread_body_closes_the_connection(server):
    head = b"GET /d/a.root HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
    answer = raw(server, head + b"2\r\nab\r\n0\r\n\r\nGET /d/a.root HTTP/1.1\r\nHost: h\r\n\r\n")
    assert answer.count(b"HTTP/1.1 200") == 1
