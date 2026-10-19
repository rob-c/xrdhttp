"""The WLCG Tape REST API: vocabulary, answer reading, and the verbs over a ``send``."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import pytest

from xrdcore.errors import ProtocolError
from xrdhttp import tape
from xrdhttp.tape import FileStatus, TapeEndpoint

DOCUMENT = {
    "sitename": "EXAMPLE-TAPE",
    "endpoints": [
        {"uri": "https://tape.example/api/v0", "version": "v0"},
        {"uri": "https://tape.example/api/v1", "version": "V1"},
        {"uri": "https://tape.example/api/v2", "version": "v2"},
        {"uri": "https://partial.example/api"},
        "not an object",
    ],
}


@pytest.mark.parametrize(
    ("version", "number"),
    [("v1", 1), ("V1", 1), ("1", 1), ("v1.2", 1), ("v0", 0), ("vX", -1), ("", 0), ("v", 0)],
)
def test_api_version(version, number):
    assert tape.api_version(version) == number


def test_listed_endpoints_complete_and_lenient():
    strict = tape.listed_endpoints(DOCUMENT)
    assert [e.version for e in strict] == ["v0", "V1", "v2"]
    lenient = tape.listed_endpoints(DOCUMENT, complete=False)
    assert lenient[-1] == TapeEndpoint("https://partial.example/api", "", "EXAMPLE-TAPE")
    assert tape.listed_endpoints([]) == []
    assert tape.listed_endpoints({"endpoints": "nope"}) == []
    assert tape.listed_endpoints({"endpoints": [{"uri": 1, "version": 1}]})[0].uri == "1"


def test_newest_endpoint_takes_the_highest_known_version_and_the_later_of_equals():
    found = tape.newest_endpoint(tape.listed_endpoints(DOCUMENT))
    assert found == TapeEndpoint("https://tape.example/api/v1", "V1", "EXAMPLE-TAPE")
    twins = [TapeEndpoint("a", "v1", ""), TapeEndpoint("b", "v1", "")]
    assert tape.newest_endpoint(twins) == twins[1]
    assert tape.newest_endpoint([TapeEndpoint("", "v1", "")]) is None
    assert tape.newest_endpoint([TapeEndpoint("x", "v9", "")]) is None


def test_choose_endpoint_falls_back_to_the_first_and_refuses_an_empty_list():
    assert tape.choose_endpoint(DOCUMENT).uri.endswith("/v1")
    only_new = {"endpoints": [{"uri": "u", "version": "v7"}]}
    assert tape.choose_endpoint(only_new).uri == "u"
    with pytest.raises(ProtocolError, match="lists no tape endpoints"):
        tape.choose_endpoint({}, "https://h/.well-known")


def test_json_text_flag_collapse_and_entry_for():
    assert tape.json_text("s") == "s" and tape.json_text(True) == "true"
    assert all(tape.flag(v) for v in (True, 1, "1", "TRUE ", "yes"))
    assert not any(tape.flag(v) for v in (False, 0, "0", "no", None))
    assert tape.collapse("//a///b/") == "/a/b/"
    items = [{"path": "/x"}, {"path": "//a//b"}, "junk", {}]
    assert tape.entry_for(items, "/a/b") == {"path": "//a//b"}
    assert tape.entry_for(items, "/none") is None
    assert tape.entry_for("not a list", "/a") is None


def test_documents_and_entries():
    assert tape.parse_document(b"") == {}
    with pytest.raises(ProtocolError, match="did not answer with JSON"):
        tape.parse_document(b"<html>", "https://h/api/v1/stage")
    assert tape.entries({"files": [1]}) == [1]
    assert tape.entries({"responses": [2]}) == [2]
    assert tape.entries({"other": []}) == []
    assert tape.entries([3]) == [3]
    assert tape.entries(None) == []


def test_bodies_and_paths():
    files = tape.stage_entries(["/a", "/b"], "P1D")
    assert files == [{"path": "/a", "diskLifetime": "P1D"}, {"path": "/b", "diskLifetime": "P1D"}]
    assert tape.stage_entries(["/a"]) == [{"path": "/a"}]
    assert json.loads(tape.stage_body(files)) == {"files": files}
    assert json.loads(tape.paths_body(["/a"])) == {"paths": ["/a"]}
    assert tape.api_path("stage", "id", "cancel") == "/api/v1/stage/id/cancel"


def test_request_id_from_the_body_or_the_location():
    assert tape.request_id({"requestId": "abc"}) == "abc"
    assert tape.request_id({}, "https://h/api/v1/stage/xyz/") == "xyz"
    assert tape.request_id([], "") == ""


def test_stage_statuses():
    document = {
        "files": [
            {"path": "/on", "onDisk": "true", "state": "STARTED", "startedAt": 7},
            {"path": "/done", "state": "COMPLETED"},
            {"path": "/wait", "state": "SUBMITTED"},
            {"path": "/bad", "state": "FAILED", "error": "tape broke"},
        ]
    }
    on, done, wait, bad, missing = tape.stage_statuses(
        document, ["/on", "/done", "/wait", "/bad", "/missing"]
    )
    assert on.online and not on.on_tape and on.requested_at == "7" and bool(on)
    assert done.online and done.state == "COMPLETED"
    assert wait.on_tape and not wait.online and not bool(wait)
    assert not bad.on_tape and bad.error == "tape broke"
    assert missing == FileStatus(path="/missing", error="not part of this request")
    assert [s.path for s in tape.stage_statuses(document)] == ["/on", "/done", "/wait", "/bad"]


@pytest.mark.parametrize(
    ("word", "online", "on_tape", "error"),
    [
        ("DISK", True, False, ""),
        ("TAPE", False, True, ""),
        ("DISK_AND_TAPE", True, True, ""),
        ("ONLINE_AND_NEARLINE", True, True, ""),
        ("LOST", False, False, "lost"),
        ("", False, False, ""),
    ],
)
def test_locality(word, online, on_tape, error):
    status = tape.locality("/f", word, {})
    assert (status.online, status.on_tape, status.error) == (online, on_tape, error)
    assert status.exists is (online or on_tape) and status.state == word.upper()


def test_archive_statuses_and_the_server_error_wins():
    items = [{"path": "/f", "locality": "NONE", "error": "no such file"}]
    (status,) = tape.archive_statuses(items, ["/f"])
    assert status.error == "no such file" and not status.exists


def test_file_status_strings():
    assert str(FileStatus("/a", online=True)) == "/a: online"
    assert str(FileStatus("/a", on_tape=True)) == "/a: on tape"
    assert str(FileStatus("/a", error="gone")) == "/a: nowhere (gone)"


@dataclass
class _Reply:
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)

    def header(self, name: str) -> str:
        return self.headers.get(name, "")


class _Server:
    """A ``send`` that records each call and answers from a table."""

    def __init__(self, answers: dict[tuple[str, str], _Reply]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, str, object, dict[str, str], tuple[int, ...]]] = []

    def __call__(self, method, path, body, headers, expect):
        self.calls.append((method, path, body and json.loads(body), dict(headers), expect))
        return self.answers.get((method, path), _Reply())


def test_the_verbs_make_the_specified_requests():
    server = _Server(
        {
            ("POST", "/api/v1/stage"): _Reply(b"", {"Location": "/api/v1/stage/r1"}),
            ("GET", "/api/v1/stage/r1"): _Reply(
                json.dumps({"id": "r1", "files": [{"path": "/a", "onDisk": True}]}).encode()
            ),
            ("GET", tape.WELL_KNOWN): _Reply(json.dumps(DOCUMENT).encode()),
            ("POST", "/api/v1/archiveinfo"): _Reply(b'[{"path": "/a", "locality": "TAPE"}]'),
        }
    )
    client = tape.TapeClient(server)
    assert client.stage(["/a"], lifetime="PT1H") == "r1"
    assert client.status("r1", ["/a"])[0].online
    client.cancel("r1")
    client.cancel_files("r1", ["/a"])
    client.release("r1", ["/a"])
    assert client.discover().version == "V1"
    assert client.archive_info(["/a"])[0].on_tape
    json_header = {"Content-Type": "application/json"}
    assert server.calls == [
        (
            "POST",
            "/api/v1/stage",
            {"files": [{"path": "/a", "diskLifetime": "PT1H"}]},
            json_header,
            (200, 201),
        ),
        ("GET", "/api/v1/stage/r1", None, {}, (200,)),
        ("DELETE", "/api/v1/stage/r1", None, {}, (200, 202, 204)),
        ("POST", "/api/v1/stage/r1/cancel", {"paths": ["/a"]}, json_header, (200, 202, 204)),
        ("POST", "/api/v1/release/r1", {"paths": ["/a"]}, json_header, (200, 202, 204)),
        ("GET", tape.WELL_KNOWN, None, {}, (200,)),
        ("POST", "/api/v1/archiveinfo", {"paths": ["/a"]}, json_header, (200,)),
    ]
