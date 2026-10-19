"""The fake storage element's stores and records, driven directly."""

from __future__ import annotations

from pathlib import Path

import pytest

from xrdhttp.testing import DirectoryStore, MemoryStore, Store, Tape
from xrdhttp.testing._model import clean, decoded


@pytest.fixture(params=["memory", "directory"])
def store(request: pytest.FixtureRequest, tmp_path: Path) -> Store:
    """Each store, with bucket ``b`` holding ``k``."""
    found: Store = MemoryStore() if request.param == "memory" else DirectoryStore(tmp_path)
    found.make_bucket("b")
    found.put_object("b", "k", b"v")
    return found


def test_the_object_model(store):
    assert store.has_bucket("b") and not store.has_bucket("nope")
    store.put_object("b", "m/", b"")
    assert store.keys("b") == ["k", "m/"]
    entry = store.object_entry("b", "m/")
    assert entry is not None and entry.size == 0
    assert store.get_object("b", "k") == b"v" and store.get_object("b", "m/") == b""
    store.delete_object("b", "m/")
    store.delete_object("b", "k")
    store.delete_object("b", "absent")  # deleting nothing is no error
    assert store.keys("b") == [] and store.object_entry("b", "k") is None


def test_a_marker_with_keys_beneath_it_is_no_object(tmp_path: Path):
    store = DirectoryStore(tmp_path)
    store.put_object("b", "d/f", b"x")
    assert store.object_entry("b", "d/") is None
    store.delete_object("b", "d/")  # not an (empty) marker: left alone
    assert store.keys("b") == ["d/f"]
    assert store.keys("") == ["b/d/f"]  # the bucket "" is the whole root


def test_the_namespace(store):
    store.write("/a/b/f", [b"1", b"2"])
    assert store.children("/a") == ["b"]
    with store.open("/a/b/f") as handle:
        assert handle.read() == b"12"
    store.move("/a/b/f", "/c/g")
    store.move("/a", "/e")
    assert store.entry("/c/g") is not None and store.entry("/e/b") is not None
    store.mkdir("/e/b/deep")
    store.remove("/c/g")
    store.remove("/e")
    assert store.entry("/e") is None and store.entry("/c/g") is None


def test_a_memory_store_keeps_its_containers_in_place():
    store = MemoryStore({"/d/f": b"x"}, ["/e"])
    files, dirs = store.files, store.dirs
    store.remove("/d")
    assert store.files is files and store.dirs is dirs and dirs == {"/", "/e"}


def test_paths_and_records():
    assert clean("") == "/" and clean("a//b/") == "/a/b"
    assert decoded("http://h/a%20b?x=1") == "/a b"
    tape = Tape()
    tape.requests["r"] = {"files": [{"path": "/f"}], "polls": 0}
    assert tape.staged() == {"r": ["/f"]}
