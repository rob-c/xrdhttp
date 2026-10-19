"""What every suite shares: the fakes, the client, and how a failure is checked.

A client runs a suite by subclassing it in one of its own test modules
under a name pytest collects (``class TestNamespace(Mine, NamespaceSuite)``)
and supplying two hooks: :meth:`Conformance.make_adapter` (always) and
:meth:`Conformance.make_server` (to run against the client's own preset of
the fake - its style, its store, its delegation service). The suites'
names do not start with ``Test``, so importing one into a test module does
not run it a second time with no client behind it.

The fixtures are methods, so a subclass may also override one outright -
an S3 suite's ``server`` holds a bucket, for example. Each test gets fresh
fakes and a fresh adapter; the adapter is closed afterwards.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import ClassVar

import pytest

from .._server import StorageServer
from ._adapter import Adapter, Kind


class Conformance:
    """The base of every suite: ``server`` and ``peer`` (two fakes) and ``client``.

    ``style`` picks the :data:`~xrdhttp.testing.STYLES` column the default
    :meth:`make_server` uses; a client whose own preset sets the style
    overrides :meth:`make_server` instead. A test that needs a behaviour the
    two styles differ on sets that switch itself, so every test passes in
    either style.
    """

    #: The style of the fake :meth:`make_server` builds.
    style: ClassVar[str] = "xrdcl"

    def make_server(self, root: Path) -> StorageServer:
        """A fresh, unstarted fake; ``root`` is an empty directory it may keep files in."""
        return StorageServer(style=self.style)

    def make_adapter(self, server: StorageServer) -> Adapter:
        """The client under test, set up to talk to ``server`` (and to any other fake)."""
        raise NotImplementedError

    @pytest.fixture
    def server(self, tmp_path: Path) -> Iterator[StorageServer]:
        """The fake the test talks to, started, stopped afterwards."""
        root = tmp_path / "server"
        root.mkdir()
        with self.make_server(root) as started:
            yield started

    @pytest.fixture
    def peer(self, tmp_path: Path) -> Iterator[StorageServer]:
        """A second fake: the other end of a copy, the target of a redirect."""
        root = tmp_path / "peer"
        root.mkdir()
        with self.make_server(root) as started:
            yield started

    @pytest.fixture
    def client(self, server: StorageServer) -> Iterator[Adapter]:
        """The client, made for ``server`` and closed after the test."""
        adapter = self.make_adapter(server)
        yield adapter
        adapter.close()


def failure(client: Adapter, call: Callable[[], object]) -> Kind:
    """Run ``call``, which must fail, and say what its failure means to ``client``.

    A call that succeeds fails the test: every use of this is a check that
    the client refused something.
    """
    try:
        call()
    except Exception as error:  # every client error, whatever it derives from
        return client.kind(error)
    pytest.fail(f"{call!r} succeeded where a failure was expected")
