"""The fake storage element's tape REST API, CDMI QoS and token issuance."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest

from xrdhttp.testing import MemoryStore, StorageServer, Tape

from tests._storage import ask

WELL_KNOWN = "/.well-known/wlcg-tape-rest-api"


@pytest.fixture
def server() -> Iterator[StorageServer]:
    """A fake with tape, holding ``/t/a`` and ``/t/b``."""
    with StorageServer(MemoryStore({"/t/a": b"a", "/t/b": b"b"}, ["/t/sub"])) as srv:
        srv.tape = Tape()
        yield srv


def call(server: StorageServer, method: str, path: str, document: Any = None) -> tuple[int, Any]:
    """One tape API call: the status and the decoded JSON answer (``None`` for no body)."""
    body = None if document is None else json.dumps(document).encode()
    answer = ask(server, method, path, body)
    return answer.status, json.loads(answer.body) if answer.body else None


def stage(server: StorageServer, *paths: str) -> str:
    """Stage ``paths``; the request id."""
    status, document = call(
        server, "POST", "/api/v1/stage", {"files": [{"path": p} for p in paths]}
    )
    assert status == 201
    return str(document["requestId"])


def states(server: StorageServer, handle: str) -> dict[str, str]:
    """Path -> state of one poll of ``handle``."""
    status, document = call(server, "GET", f"/api/v1/stage/{handle}")
    assert status == 200
    return {entry["path"]: entry["state"] for entry in document["files"]}


def test_discovery_names_the_endpoint(server):
    status, document = call(server, "GET", WELL_KNOWN)
    assert status == 200 and document["sitename"] == "fake-site"
    assert document["endpoints"][0]["uri"] == f"{server.base}/api/v1"
    server.tape_endpoint = "/api/v1/"
    assert call(server, "GET", WELL_KNOWN)[1]["endpoints"][0]["uri"].endswith("/api/v1/")
    server.tape.discovery = {"sitename": "X"}
    assert call(server, "GET", WELL_KNOWN) == (200, {"sitename": "X"})
    server.tape.discovery = b"not json"
    assert ask(server, "GET", WELL_KNOWN).body == b"not json"


def test_a_site_without_tape(server):
    server.tape = None
    assert call(server, "GET", WELL_KNOWN)[0] == 404
    server.tape_absent_status = 403
    assert call(server, "POST", "/api/v1/stage", {"files": []})[0] == 403


def test_staging_follows_the_namespace_and_the_tests_state(server):
    server.tape.nearline.add("/t/a")
    server.tape.locality["/t/lost"] = "LOST"
    handle = stage(server, "/t/a", "/t/b", "/t/missing", "/t/lost")
    assert server.tape.staged() == {handle: ["/t/a", "/t/b", "/t/missing", "/t/lost"]}
    assert states(server, handle) == {
        "/t/a": "SUBMITTED",
        "/t/b": "COMPLETED",
        "/t/missing": "FAILED",
        "/t/lost": "FAILED",
    }
    server.tape.nearline.clear()
    server.tape.stage_polls = 2
    assert states(server, handle)["/t/a"] == "STARTED"
    assert states(server, handle)["/t/a"] == "COMPLETED"  # the third poll
    assert call(server, "GET", "/api/v1/stage/none")[0] == 404


def test_requests_are_cancelled_released_and_withdrawn(server):
    handle = stage(server, "/t/a", "/t/b")
    assert call(server, "POST", f"/api/v1/stage/{handle}/cancel", {"paths": ["/t/a"]})[0] == 200
    assert states(server, handle) == {"/t/a": "CANCELLED", "/t/b": "COMPLETED"}
    assert server.tape.cancelled == [(handle, ["/t/a"])]
    assert call(server, "POST", "/api/v1/stage/none/cancel", {"paths": []})[0] == 404
    assert call(server, "POST", f"/api/v1/release/{handle}", {"paths": ["/t/b"]})[0] == 200
    assert call(server, "POST", "/api/v1/release/none", {"paths": ["/t/b"]})[0] == 404
    server.release_unknown = True
    assert call(server, "POST", "/api/v1/release/none", {"paths": ["/t/b"]})[0] == 200
    assert server.tape.released == [(handle, ["/t/b"]), ("none", ["/t/b"])]
    assert call(server, "DELETE", f"/api/v1/stage/{handle}")[0] == 204
    assert call(server, "DELETE", f"/api/v1/stage/{handle}")[0] == 404


def test_an_id_is_never_issued_twice(server):
    first, second = stage(server, "/t/a"), stage(server, "/t/b")
    assert call(server, "DELETE", f"/api/v1/stage/{first}")[0] == 204
    third = stage(server, "/t/a")
    assert len({first, second, third}) == 3


def test_archive_info(server):
    server.tape.nearline.add("/t/a")
    server.tape.locality["/t/c"] = "DISK_AND_TAPE"
    paths = ["/t/a", "/t/b", "/t/c", "/t/sub", "/t/none"]
    status, document = call(server, "POST", "/api/v1/archiveinfo", {"paths": paths})
    assert status == 200
    localities = [entry.get("locality") for entry in document]
    assert localities == ["TAPE", "DISK", "DISK_AND_TAPE", "LOST", "LOST"]
    server.missing_archive_entry = {"error": "USER ERROR: file not found"}
    status, document = call(server, "POST", "/api/v1/archiveinfo", {"paths": ["/t/none"]})
    assert document == [{"path": "/t/none", "error": "USER ERROR: file not found"}]


def test_what_the_api_does_not_define(server):
    assert call(server, "POST", "/api/v1/stage", {"files": []})[0] == 400
    assert ask(server, "POST", "/api/v1/stage", b"not json").status == 400
    for method, path in [
        ("GET", "/api/v1/stage"),
        ("POST", "/api/v1/stage/x"),
        ("GET", "/api/v1/stage/x/cancel"),
        ("POST", "/api/v1/stage/x/other"),
        ("POST", "/api/v1/release"),
        ("GET", "/api/v1/archiveinfo"),
        ("GET", "/api/v1"),
    ]:
        assert call(server, method, path)[0] == 404, (method, path)


# -- CDMI ----------------------------------------------------------------------------------------


def test_cdmi_quality_of_service(server):
    disk = "/cdmi_capabilities/dataobject/disk"
    server.qos[disk] = {"cdmi_data_redundancy": "1"}
    server.qos["/cdmi_capabilities/container/c"] = {}
    server.qos["/t/a"] = {"capabilitiesURI": disk, "metadata": {}}
    assert call(server, "GET", "/cdmi_capabilities/dataobject/") == (200, {"children": ["disk/"]})
    assert call(server, "GET", disk) == (
        200,
        {"objectName": "dataobject/disk", "metadata": {"cdmi_data_redundancy": "1"}},
    )
    assert ask(server, "GET", "/cdmi_capabilities/other").status == 404
    assert call(server, "GET", "/t/a")[1]["capabilitiesURI"] == disk
    assert call(server, "PUT", "/t/a", {"capabilitiesURI": "/tape"})[0] == 204
    assert server.qos["/t/a"]["metadata"]["cdmi_capabilities_target"] == "/tape"


# -- tokens --------------------------------------------------------------------------------------


def test_macaroons_are_minted_and_recorded(server):
    asking = {"Content-Type": "application/macaroon-request"}
    document = json.loads(ask(server, "POST", "/t/a", b'{"validity": "PT1H"}', asking).body)
    assert document["macaroon"].startswith("mac-")
    assert document["uri"] == {"targetWithMacaroon": "/t/a"}
    server.macaroon = "fixed"
    assert json.loads(ask(server, "POST", "/t/b", None, asking).body)["macaroon"] == "fixed"
    assert server.macaroons[0]["validity"] == "PT1H" and server.macaroons[1]["path"] == "/t/b"


def test_oauth_issuance(server):
    discovery = "/.well-known/oauth-authorization-server"
    assert ask(server, "GET", discovery).status == 404
    server.oauth = True
    assert call(server, "GET", discovery)[1]["token_endpoint"] == f"{server.base}/token"
    server.oauth_endpoint = "https://issuer/token"
    assert call(server, "GET", discovery + "/realm")[1]["token_endpoint"] == "https://issuer/token"
    answer = ask(server, "POST", "/token", b"grant_type=client_credentials&scope=storage.read")
    token = json.loads(answer.body)["access_token"]
    assert server.macaroons[-1] == {
        "macaroon": token,
        "form": {"grant_type": ["client_credentials"], "scope": ["storage.read"]},
    }
    assert ask(server, "GET", "/token").status == 404  # the endpoint only takes POST
