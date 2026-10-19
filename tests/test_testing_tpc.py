"""The fake storage element's HTTP third-party copy: pull, push, markers, failures, delegation."""

from __future__ import annotations

import http.client
from collections.abc import Iterator
from pathlib import Path

import pytest

from xrdhttp.testing import MemoryStore, StorageServer

from tests._sockets import context_pair
from tests._storage import ask

BODY = b"x" * 3000


@pytest.fixture
def source() -> Iterator[StorageServer]:
    """The far side, holding ``/d/f``."""
    with StorageServer(MemoryStore({"/d/f": BODY})) as srv:
        yield srv


@pytest.fixture
def target() -> Iterator[StorageServer]:
    """The active side, with an empty ``/d``."""
    with StorageServer(MemoryStore(dirs=["/d"])) as srv:
        yield srv


def copy(server: StorageServer, path: str, **headers: str) -> tuple[int, str]:
    """A ``COPY`` of ``path``: the status and the whole marker stream."""
    answer = ask(server, "COPY", path, headers=headers)
    return answer.status, answer.body.decode()


def test_a_pull_streams_markers_then_succeeds(source, target):
    target.tpc_markers = 3
    status, body = copy(target, "/d/pulled?x=1", Source=f"{source.base}/d/f?q=1")
    assert status == 202 and body.endswith("success: Created\n")
    assert body.count("Perf Marker") == 3 and "\tStripe Bytes Transferred: 3000\n" in body
    assert target.contents("/d/pulled") == BODY
    assert target.copies[-1]["Source"].endswith("/d/f?q=1")
    assert source.requests[-1].target == "/d/f?q=1"


def test_markers_can_follow_the_bytes_as_they_move(source, target):
    target.marker_every = 1000
    _, body = copy(target, "/d/pulled", Source=f"{source.base}/d/f")
    moved = [line for line in body.splitlines() if "Bytes Transferred" in line]
    assert moved == [f"\tStripe Bytes Transferred: {n}" for n in (1000, 2000, 3000)]


def test_a_push_puts_the_file_on_the_far_side(source, target):
    source.tpc_marker_gap = 0.001
    target.tokens = {"far"}
    status, body = copy(
        source,
        "/d/f",
        Destination=f"{target.base}/d/pushed?x=1",
        TransferHeaderAuthorization="Bearer far",
    )
    assert (status, body.splitlines()[-1]) == (202, "success: Created")
    assert target.contents("/d/pushed") == BODY
    assert target.requests[-1].header("Authorization") == "Bearer far"


def test_refusals_come_before_the_202(source, target):
    assert copy(target, "/d/x")[0] == 400  # neither Source nor Destination
    both = {"Source": "http://a/x", "Destination": "http://b/x"}
    assert copy(target, "/d/x", **both)[0] == 400
    assert copy(source, "/d/f", Source=f"{target.base}/d/x", Overwrite="F")[0] == 412
    status, _ = copy(target, "/d/new", Source=f"{source.base}/d/f", Overwrite="F")
    assert status == 202
    target.no_tpc = True
    assert copy(target, "/d/x", Source="http://a/x")[0] == 501


def test_xrootd_without_tpc_says_ok_and_hangs_up(target):
    target.tpc = "xrootd"
    assert copy(target, "/d/x", Source="http://a/x") == (200, "OK")


def test_a_copy_that_never_says_how_it_went(source, target):
    target.tpc = "eof"
    _, body = copy(target, "/d/x", Source=f"{source.base}/d/f")
    assert "Perf Marker" in body and "success" not in body and "failure" not in body


@pytest.mark.parametrize(
    ("path", "headers", "words"),
    [
        ("/d/x", {"Source": "file:///etc/passwd"}, "failure: HTTP 400 cannot speak file"),
        ("/d/x", {"Source": "SOURCE/d/missing"}, "failure: source answered HTTP 404"),
        ("/d/x", {"Source": "http://127.0.0.1:1/f"}, "failure: could not reach the source"),
        ("/d/none", {"Destination": "SOURCE/d/x"}, "is not here to push"),
        ("/d", {"Destination": "SOURCE/d/x"}, "failure: HTTP 404 : the source does not exist"),
        ("/d/y", {"Destination": "http://127.0.0.1:1/f"}, "could not reach the destination"),
        ("/d/y", {"Destination": "SOURCE/nowhere/f"}, "failure: destination answered HTTP 409"),
    ],
)
def test_transfer_failures_are_reported_in_the_body(source, target, path, headers, words):
    target.add_file("/d/y", b"y")
    sent = {name: value.replace("SOURCE", source.base) for name, value in headers.items()}
    status, body = copy(target, path, **sent)
    assert status == 202 and words in body


def test_a_failure_the_test_asks_for(source, target):
    target.tpc_failure = "HTTP 500 : the remote side refused"
    _, body = copy(target, "/d/x", Source=f"{source.base}/d/f")
    assert body.endswith("failure: HTTP 500 : the remote side refused\n")
    assert "Stripe Bytes Transferred: 0" in body and target.store.entry("/d/x") is None


def test_a_pull_over_https_uses_the_servers_client_context(tmp_path: Path, target):
    server_tls, client_tls = context_pair(tmp_path)
    with StorageServer(MemoryStore({"/f": b"secret"}), tls=server_tls) as far:
        target.client_tls = client_tls
        _, body = copy(target, "/d/x", Source=f"https://localhost:{far.port}/f")
    assert body.endswith("success: Created\n") and target.contents("/d/x") == b"secret"


# -- delegation ----------------------------------------------------------------------------------


def test_a_copy_waits_for_a_delegated_proxy(source, target):
    def service(server: StorageServer, body: bytes) -> tuple[int, bytes, dict[str, str]]:
        server.accept_delegation("d1", body.decode())
        return 200, b"ok", {}

    target.delegation = True
    target.delegation_service = service
    host, port = target.address
    connection = http.client.HTTPConnection(host, port, timeout=10)
    connection.request("COPY", "/d/x", headers={"Source": f"{source.base}/d/f"})
    response = connection.getresponse()
    endpoint = response.getheader("X-Delegate-To")
    assert endpoint == f"{target.base}/gridsite-delegation"
    assert ask(target, "POST", "/gridsite-delegation", b"proxy").body == b"ok"
    assert response.read().decode().endswith("success: Created\n")
    connection.close()
    assert target.delegated == {"d1": "proxy"}


def test_a_proxy_that_never_arrives_fails_the_copy(source, target):
    target.delegation = True
    target.delegation_timeout = 0.05
    _, body = copy(target, "/d/x", Source=f"{source.base}/d/f")
    assert body == "failure: no delegated credential arrived\n"
    _, body = copy(target, "/d/x", Source=f"{source.base}/d/f", Credential="none")
    assert body.endswith("success: Created\n")  # a token-authorised copy delegates nothing


def test_there_is_no_delegation_without_a_service(target):
    assert ask(target, "POST", "/gridsite-delegation", b"x").status == 404
