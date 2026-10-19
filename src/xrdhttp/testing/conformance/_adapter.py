"""The neutral face of a client: what the conformance suites call, and what they get back.

A suite never imports a client. It drives one through an :class:`Adapter`
that the client's own test module writes - a page of code mapping each
neutral operation onto the client's API (``FileSystem.stat`` in one,
``Gfal2Context.stat`` in the other) and each failure onto a :class:`Kind`.
What comes back is neutral too: a :class:`Stat` rather than a
``StatInfo`` or a ``gfal2`` stat, bytes rather than a text-mode file,
``True``/``False`` rather than an XrdCl ``PrepareStatus``.

Every operation raises :class:`NotImplementedError` here. An adapter
implements the ones the suites it runs call (a client with no tape support
runs no :class:`~xrdhttp.testing.conformance.TapeSuite`), so a missing
method is a loud failure in the one test that needed it, never a skip.

What a maintainer must not break: the meaning of each operation is the
contract both clients are held to. Change one and every client's adapter
changes with it; add one rather than widen one.
"""

from __future__ import annotations

import enum
import errno
import urllib.parse
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._server import StorageServer


class Kind(enum.Enum):
    """What went wrong, in the words every client's errors can be translated into.

    POSIX's vocabulary where it has a word (a client raises ``ENOENT`` or
    :class:`FileNotFoundError`, both are :attr:`NOT_FOUND`), and a few
    words for what is HTTP's own: a redirect chain that never ends, an
    answer that is not what the protocol promises.
    """

    #: Nothing is at that path (``ENOENT``, HTTP 404, a 409 for a missing parent).
    NOT_FOUND = "not found"
    #: Something already is (``EEXIST``, a 405 from ``MKCOL``, a 412 from ``If-None-Match``).
    EXISTS = "exists"
    #: A collection still holds something (``ENOTEMPTY``; POSIX lets ``rmdir`` say ``EEXIST``).
    NOT_EMPTY = "not empty"
    #: The caller may not (``EACCES``/``EPERM``, HTTP 401 and 403).
    PERMISSION = "permission"
    #: A file where a collection was needed (``ENOTDIR``).
    NOT_A_DIRECTORY = "not a directory"
    #: A collection where a file was needed (``EISDIR``).
    IS_A_DIRECTORY = "is a directory"
    #: The endpoint cannot do that at all (``ENOTSUP``/``ENOSYS``, HTTP 501, no digest offered).
    UNSUPPORTED = "unsupported"
    #: The network failed: refused, reset, dropped (``ECONNREFUSED``, ``ECONNRESET``).
    CONNECTION = "connection"
    #: Nothing arrived in the time allowed (``ETIMEDOUT``).
    TIMEOUT = "timeout"
    #: Redirected more times than the client allows (``ELOOP``).
    REDIRECTS = "too many redirects"
    #: An answer that breaks the protocol: malformed XML, JSON, markers.
    PROTOCOL = "protocol"
    #: Anything else: a 500, a 507 - the server failed and said only that.
    OTHER = "other"


#: How errno values read as a :class:`Kind`; anything else is :attr:`Kind.OTHER`.
ERRNO_KINDS: dict[int, Kind] = {
    errno.ENOENT: Kind.NOT_FOUND,
    errno.EEXIST: Kind.EXISTS,
    errno.ENOTEMPTY: Kind.NOT_EMPTY,
    errno.EACCES: Kind.PERMISSION,
    errno.EPERM: Kind.PERMISSION,
    errno.ENOTDIR: Kind.NOT_A_DIRECTORY,
    errno.EISDIR: Kind.IS_A_DIRECTORY,
    errno.ENOTSUP: Kind.UNSUPPORTED,
    errno.ENOSYS: Kind.UNSUPPORTED,
    errno.EPROTONOSUPPORT: Kind.UNSUPPORTED,
    errno.ECONNREFUSED: Kind.CONNECTION,
    errno.ECONNRESET: Kind.CONNECTION,
    errno.EHOSTUNREACH: Kind.CONNECTION,
    errno.ETIMEDOUT: Kind.TIMEOUT,
    errno.ELOOP: Kind.REDIRECTS,
    errno.EPROTO: Kind.PROTOCOL,
}

#: The built-in exception classes a client's errors commonly derive from, in the
#: order they are tried (most specific first, so a timeout is not a mere ``OSError``).
_CLASS_KINDS: tuple[tuple[type[BaseException], Kind], ...] = (
    (FileNotFoundError, Kind.NOT_FOUND),
    (FileExistsError, Kind.EXISTS),
    (PermissionError, Kind.PERMISSION),
    (NotADirectoryError, Kind.NOT_A_DIRECTORY),
    (IsADirectoryError, Kind.IS_A_DIRECTORY),
    (TimeoutError, Kind.TIMEOUT),
    (ConnectionError, Kind.CONNECTION),
)


def kind_of_errno(code: int | None) -> Kind:
    """The :class:`Kind` an ``errno`` value names; :attr:`Kind.OTHER` for any other."""
    return ERRNO_KINDS.get(code or 0, Kind.OTHER)


@dataclass(frozen=True, slots=True)
class Stat:
    """What a stat says that every client reports the same way.

    ``modified`` is whole seconds since the epoch, ``0`` where the server
    gave no time a client could read - which both clients report as zero
    rather than fail on.
    """

    size: int
    directory: bool = False
    modified: int = 0


#: A progress report: the bytes the transfer has moved so far.
Progress = Callable[[int], None]


class Adapter:
    """One client, driven through neutral operations; subclass it in the client's suite.

    Paths reach the adapter as URLs it built itself with :meth:`url`, so a
    client with its own spelling (``dav://``, ``s3://``) chooses it there.
    Results are neutral (:class:`Stat`, ``bytes``, ``list[str]``); errors are
    left to propagate, and the suites read them through :meth:`kind`.
    """

    def url(self, server: StorageServer, path: str) -> str:
        """The URL this client is given for ``path`` on ``server``.

        ``path`` is a plain name (a space is a space); the default encodes it
        once onto ``server.base`` - ``http``/``https`` as the server speaks.
        """
        return server.base + urllib.parse.quote(path)

    def kind(self, error: BaseException) -> Kind:
        """What ``error`` means; the default reads built-in classes, then ``errno``.

        A client whose errors carry their errno elsewhere (gfal2's ``code``)
        or whose classes say more than ``errno`` does (a redirect-limit error)
        overrides this, usually falling back to it.
        """
        for cls, kind in _CLASS_KINDS:
            if isinstance(error, cls):
                return kind
        return kind_of_errno(getattr(error, "errno", None))

    def close(self) -> None:
        """Release whatever the client holds (pooled connections); called after each test."""

    # -- settings ------------------------------------------------------------------------

    def authorise(self, token: str) -> None:
        """Present ``token`` as a bearer token on every request from now on.

        As a user would configure it (``BEARER_TOKEN``, a credential set on a
        context), not written into the URL.
        """
        raise NotImplementedError

    def time_limit(self, seconds: float) -> None:
        """Give up on any answer that takes longer than ``seconds`` from now on."""
        raise NotImplementedError

    # -- the namespace -----------------------------------------------------------------

    def stat(self, url: str) -> Stat:
        """The size and type of what ``url`` names."""
        raise NotImplementedError

    def listdir(self, url: str) -> list[str]:
        """The names in the collection ``url`` names, in any order (never itself)."""
        raise NotImplementedError

    def mkdir(self, url: str) -> None:
        """Make one collection; its parent must exist and it must not."""
        raise NotImplementedError

    def makedirs(self, url: str) -> None:
        """Make a collection and every missing parent; one already there is success."""
        raise NotImplementedError

    def rmdir(self, url: str) -> None:
        """Remove an empty collection."""
        raise NotImplementedError

    def unlink(self, url: str) -> None:
        """Remove a file."""
        raise NotImplementedError

    def rename(self, source: str, destination: str) -> None:
        """Move ``source`` to ``destination`` on the same endpoint, replacing what is there."""
        raise NotImplementedError

    # -- data ----------------------------------------------------------------------------

    def read(self, url: str) -> bytes:
        """The whole of the file ``url`` names."""
        raise NotImplementedError

    def pread(self, url: str, offset: int, size: int) -> bytes:
        """Up to ``size`` bytes from ``offset`` (short at the end of the file, empty past it)."""
        raise NotImplementedError

    def write(self, url: str, data: bytes) -> None:
        """Store ``data`` as the file ``url`` names, its length known before it is sent."""
        raise NotImplementedError

    def stream(self, url: str, chunks: Sequence[bytes]) -> None:
        """Store the ``chunks`` as one file, each handed to the client as it would be written."""
        raise NotImplementedError

    def checksum(self, url: str, algorithm: str) -> str:
        """The server's checksum of the file in lower-case hex; ``algorithm`` as gfal2 names it."""
        raise NotImplementedError

    # -- third-party copy --------------------------------------------------------------

    def copy(
        self, source: str, destination: str, *, push: bool = False, progress: Progress | None = None
    ) -> None:
        """An HTTP third-party copy: the destination pulls (or, ``push``, the source pushes).

        Only the ``COPY`` mode asked for: no fallback to another mode or to
        streaming through the client, so what is tested is the server-to-server
        transfer. ``progress`` hears the byte count of every performance marker.
        """
        raise NotImplementedError

    # -- the WLCG tape REST API -----------------------------------------------------

    def stage(self, urls: Sequence[str]) -> str:
        """Ask for ``urls`` to be brought online; the request id the server gave."""
        raise NotImplementedError

    def poll(self, request: str, urls: Sequence[str]) -> list[bool]:
        """Whether each of ``urls`` is online yet, per request ``request``.

        A file the request failed for (lost, never there) raises rather than
        answering ``False``; when every file failed the client may say so for
        the request as a whole.
        """
        raise NotImplementedError

    def release(self, request: str, urls: Sequence[str]) -> None:
        """Let the staged ``urls`` of request ``request`` go."""
        raise NotImplementedError

    def abort(self, request: str, urls: Sequence[str]) -> None:
        """Withdraw ``urls`` from request ``request``."""
        raise NotImplementedError

    def on_tape(self, urls: Sequence[str]) -> list[bool]:
        """Whether each file has a copy on tape (``archiveinfo``), staging nothing."""
        raise NotImplementedError

    # -- tokens ---------------------------------------------------------------------------

    def macaroon(self, url: str, activities: Sequence[str]) -> str:
        """A macaroon for ``url`` allowing ``activities`` (``DOWNLOAD``, ``UPLOAD``, ...)."""
        raise NotImplementedError
