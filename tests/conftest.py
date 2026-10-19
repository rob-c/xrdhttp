"""Fixtures: a scripted socket server per test, closed and checked afterwards.

The helpers themselves are in ``tests/_sockets.py``, which test modules import.
"""

from __future__ import annotations

import socket
from collections.abc import Callable, Iterator

import pytest

from tests._sockets import Scripted


@pytest.fixture
def scripted() -> Iterator[Callable[[Callable[[socket.socket], None]], Scripted]]:
    """``scripted(script)`` starts a :class:`Scripted` server, closed after the test."""
    servers: list[Scripted] = []

    def start(script: Callable[[socket.socket], None]) -> Scripted:
        servers.append(Scripted(script))
        return servers[-1]

    yield start
    for server in servers:
        server.close()
    for server in servers:
        server.check()
