"""Where the fake keeps what it serves: in memory, or in a real directory.

The fake speaks two data models over one store. WebDAV (and tape, and
third-party copy) sees a *namespace*: absolute, normalised paths that are
files or collections. S3, GCS and Swift see *buckets* of flat keys, where
``a//b`` and the marker ``a/`` are keys like any other. A :class:`Store`
answers both, so one server can, for example, issue a macaroon over WebDAV
and serve the object it guards over S3.

* :class:`MemoryStore` keeps files and collections in two public
  containers (:attr:`~MemoryStore.files`, :attr:`~MemoryStore.dirs`) and
  buckets in a dict of dicts, so a test seeds and inspects them directly.
  The two models are separate here, as they are in a real object store.
* :class:`DirectoryStore` keeps everything under a real directory, so a
  multi-GiB test file costs a sparse file rather than memory, and a test
  seeds and inspects with plain file operations. Buckets are its top-level
  directories (the root itself for the bucket ``""``, which is how a
  virtual-host-style request names its keys); a key is the file at that
  relative path and a marker ``a/`` is an empty directory - which cannot
  model a key and a "directory" of the same name, and no test needs it to.

The handlers never touch either representation: everything goes through
the methods of :class:`Store`, whose arguments are already decoded
(namespace paths come through :func:`~xrdhttp.testing._model.clean`).
Neither store is locked: the handler threads mutate it directly, which is
safe for the GIL-atomic dict and file operations used, and a test reads it
only after the client call it is checking has returned.
"""

from __future__ import annotations

import io
import os
import posixpath
import shutil
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol

from ._model import clean

#: Files are read and bodies streamed in 4 MiB pieces: big enough to be quick,
#: small enough that a multi-GiB test file never sits in memory whole.
CHUNK = 4 << 20


@dataclass(frozen=True, slots=True)
class Entry:
    """What a stat reports of one file, collection or object.

    ``created`` is ``None`` where the store has no such time (memory), and
    then a ``PROPFIND`` leaves ``creationdate`` out.
    """

    collection: bool
    size: int
    modified: float
    created: float | None = None


class Store(Protocol):
    """The operations the handlers perform on what the fake holds.

    Namespace paths are :func:`~xrdhttp.testing._model.clean` absolute
    paths; the caller has checked what WebDAV requires (a parent exists, a
    collection is empty) before calling a mutator, so these only do.
    """

    def entry(self, path: str) -> Entry | None:
        """``path``'s stat, or ``None`` if nothing is there."""
        ...

    def children(self, path: str) -> list[str]:
        """The names directly in collection ``path``, sorted."""
        ...

    def open(self, path: str) -> BinaryIO:
        """File ``path`` opened for reading (seekable; the caller closes it)."""
        ...

    def write(self, path: str, chunks: Iterable[bytes]) -> None:
        """Create or replace file ``path`` from ``chunks``, creating its parent collections."""
        ...

    def mkdir(self, path: str) -> None:
        """Create collection ``path`` and any missing parent."""
        ...

    def remove(self, path: str) -> None:
        """Remove file ``path``, or collection ``path`` with everything under it."""
        ...

    def move(self, source: str, destination: str) -> None:
        """Rename a file or a whole collection, replacing a destination file."""
        ...

    def has_bucket(self, bucket: str) -> bool:
        """Whether ``bucket`` exists."""
        ...

    def make_bucket(self, bucket: str) -> None:
        """Create ``bucket`` if it is not there."""
        ...

    def keys(self, bucket: str) -> list[str]:
        """Every key in ``bucket``, sorted."""
        ...

    def object_entry(self, bucket: str, key: str) -> Entry | None:
        """Object ``key``'s stat, or ``None`` if there is no such key."""
        ...

    def get_object(self, bucket: str, key: str) -> bytes:
        """Object ``key``'s bytes (it exists: the caller checked)."""
        ...

    def put_object(self, bucket: str, key: str, data: bytes) -> None:
        """Create or replace object ``key`` (the bucket exists: the caller checked)."""
        ...

    def delete_object(self, bucket: str, key: str) -> None:
        """Remove object ``key`` if it is there; deleting nothing is not an error."""
        ...


class MemoryStore:
    """Files, collections and buckets held in plain public containers.

    :attr:`files` and :attr:`dirs` are the namespace and :attr:`buckets`
    the object stores; a test may read or mutate any of them directly
    between two client calls. Every parent of every file and collection is
    in :attr:`dirs`, as a real namespace has them. Every entry reports
    :attr:`mtime` as its modification time, so listings and stats are
    reproducible.
    """

    def __init__(
        self,
        files: dict[str, bytes] | None = None,
        dirs: Iterable[str] = (),
        buckets: dict[str, dict[str, bytes]] | None = None,
        *,
        mtime: float = 0.0,
    ) -> None:
        """Hold ``files`` (and the empty collections ``dirs``) and ``buckets``."""
        #: Path to contents.
        self.files: dict[str, bytes] = {}
        #: Collections that exist, including every parent of every file.
        self.dirs: set[str] = {"/"}
        #: Bucket name to its objects (key to contents).
        self.buckets: dict[str, dict[str, bytes]] = buckets if buckets is not None else {}
        #: The modification time every entry reports.
        self.mtime = mtime
        for path, data in (files or {}).items():
            self.add_file(path, data)
        for path in dirs:
            self.add_dir(path)

    # -- seeding -------------------------------------------------------------------------

    def add_dir(self, path: str) -> None:
        """Create a collection and every missing parent of it."""
        target = clean(path)
        while target not in self.dirs:
            self.dirs.add(target)
            target = posixpath.dirname(target)

    def add_file(self, path: str, data: bytes = b"") -> None:
        """Create or replace a file, creating its parent collections."""
        target = clean(path)
        self.files[target] = bytes(data)
        self.add_dir(posixpath.dirname(target))

    # -- the namespace -------------------------------------------------------------------

    def entry(self, path: str) -> Entry | None:
        """A file's size, or a collection's; ``None`` for neither."""
        data = self.files.get(path)
        if data is not None:
            return Entry(False, len(data), self.mtime)
        return Entry(True, 0, self.mtime) if path in self.dirs else None

    def children(self, path: str) -> list[str]:
        """Names of the files and collections whose parent is ``path``."""
        names = {
            posixpath.basename(name)
            for name in [*self.files, *self.dirs]
            if name != "/" and posixpath.dirname(name) == path
        }
        return sorted(names)

    def open(self, path: str) -> BinaryIO:
        """The file's bytes as a stream, so they are served as a real file's are."""
        return io.BytesIO(self.files[path])

    def write(self, path: str, chunks: Iterable[bytes]) -> None:
        """Gather ``chunks`` and store them under ``path``."""
        self.add_file(path, b"".join(chunks))

    def mkdir(self, path: str) -> None:
        """:meth:`add_dir`."""
        self.add_dir(path)

    def remove(self, path: str) -> None:
        """Drop a file, or a collection and everything beneath it."""
        if self.files.pop(path, None) is not None:
            return
        prefix = path.rstrip("/") + "/"
        # In place: a preset hands these very containers to its tests.
        self.dirs.difference_update({d for d in self.dirs if d == path or d.startswith(prefix)})
        for name in [f for f in self.files if f.startswith(prefix)]:
            del self.files[name]

    def move(self, source: str, destination: str) -> None:
        """Rename a file, or a collection with everything beneath it."""
        if source in self.files:
            self.add_file(destination, self.files.pop(source))
            return
        prefix = source.rstrip("/") + "/"
        moved = [d for d in self.dirs if d == source or d.startswith(prefix)]
        self.dirs.difference_update(moved)
        for name in moved:
            self.add_dir(destination + name[len(source) :])
        for name in [f for f in self.files if f.startswith(prefix)]:
            self.add_file(destination + name[len(source) :], self.files.pop(name))

    # -- the object stores ---------------------------------------------------------------

    def has_bucket(self, bucket: str) -> bool:
        """Whether :attr:`buckets` has ``bucket``."""
        return bucket in self.buckets

    def make_bucket(self, bucket: str) -> None:
        """Add an empty bucket, keeping one already there."""
        self.buckets.setdefault(bucket, {})

    def keys(self, bucket: str) -> list[str]:
        """The bucket's keys, sorted."""
        return sorted(self.buckets[bucket])

    def object_entry(self, bucket: str, key: str) -> Entry | None:
        """The object's size, or ``None``."""
        data = self.buckets[bucket].get(key)
        return None if data is None else Entry(False, len(data), self.mtime)

    def get_object(self, bucket: str, key: str) -> bytes:
        """The object's bytes."""
        return self.buckets[bucket][key]

    def put_object(self, bucket: str, key: str, data: bytes) -> None:
        """Store the object."""
        self.buckets[bucket][key] = data

    def delete_object(self, bucket: str, key: str) -> None:
        """Drop the object if it is there."""
        self.buckets[bucket].pop(key, None)


class DirectoryStore:
    """Everything kept under :attr:`root`, a real directory (created if missing)."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        """Serve ``root``, creating it if it is missing."""
        #: The directory the namespace's ``/`` is.
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def local(self, path: str) -> Path:
        """The file behind namespace ``path`` (cleaned here, so any spelling will do)."""
        return self.root / clean(path).lstrip("/")

    # -- the namespace -------------------------------------------------------------------

    def entry(self, path: str) -> Entry | None:
        """The file system's stat of ``path``; ``None`` if it is missing or neither kind."""
        target = self.local(path)
        if not (target.is_file() or target.is_dir()):
            return None
        info = target.stat()
        directory = target.is_dir()
        return Entry(directory, 0 if directory else info.st_size, info.st_mtime, info.st_ctime)

    def children(self, path: str) -> list[str]:
        """The directory's entries, sorted."""
        return sorted(os.listdir(self.local(path)))

    def open(self, path: str) -> BinaryIO:
        """The file, opened for reading."""
        return open(self.local(path), "rb")

    def write(self, path: str, chunks: Iterable[bytes]) -> None:
        """Stream ``chunks`` to the file, creating its parent directories."""
        target = self.local(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "wb") as handle:
            for chunk in chunks:
                handle.write(chunk)

    def mkdir(self, path: str) -> None:
        """Create the directory and its parents."""
        self.local(path).mkdir(parents=True, exist_ok=True)

    def remove(self, path: str) -> None:
        """Unlink a file, or remove a directory tree."""
        target = self.local(path)
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()

    def move(self, source: str, destination: str) -> None:
        """``os.replace``, creating the destination's parent first."""
        target = self.local(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        os.replace(self.local(source), target)

    # -- the object stores ---------------------------------------------------------------

    def _bucket(self, bucket: str) -> Path:
        """The directory holding ``bucket``'s keys: the root itself for ``""``."""
        return self.root / bucket if bucket else self.root

    def _object(self, bucket: str, key: str) -> Path:
        """The file (or, for a marker ``a/``, the directory) standing for ``key``."""
        return self._bucket(bucket) / key.rstrip("/")

    def has_bucket(self, bucket: str) -> bool:
        """Whether the bucket's directory exists."""
        return self._bucket(bucket).is_dir()

    def make_bucket(self, bucket: str) -> None:
        """Create the bucket's directory (and its parents)."""
        self._bucket(bucket).mkdir(parents=True, exist_ok=True)

    def keys(self, bucket: str) -> list[str]:
        """The bucket's files, and ``dir/`` for each empty directory in it."""
        root = self._bucket(bucket)
        found = []
        for item in root.rglob("*"):
            name = item.relative_to(root).as_posix()
            if item.is_file():
                found.append(name)
            elif _empty_dir(item):
                found.append(name + "/")
        return sorted(found)

    def object_entry(self, bucket: str, key: str) -> Entry | None:
        """A file's stat for a key; for a marker ``a/``, an empty directory's (as :meth:`keys`)."""
        target = self._object(bucket, key)
        marker = key.endswith("/")
        if not (_empty_dir(target) if marker else target.is_file()):
            return None
        info = target.stat()
        return Entry(False, 0 if marker else info.st_size, info.st_mtime, info.st_ctime)

    def get_object(self, bucket: str, key: str) -> bytes:
        """The file's bytes; a marker is empty."""
        return b"" if key.endswith("/") else self._object(bucket, key).read_bytes()

    def put_object(self, bucket: str, key: str, data: bytes) -> None:
        """Write the file (a marker makes the directory), creating parents on demand."""
        target = self._object(bucket, key)
        if key.endswith("/"):
            target.mkdir(parents=True, exist_ok=True)
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def delete_object(self, bucket: str, key: str) -> None:
        """Unlink the file, or remove an empty marker directory; anything else stays."""
        target = self._object(bucket, key)
        if key.endswith("/"):
            if _empty_dir(target):
                target.rmdir()
        elif target.is_file():
            target.unlink()


def _empty_dir(path: Path) -> bool:
    """Whether ``path`` is a directory with nothing in it: what stands for a marker key."""
    return path.is_dir() and not any(path.iterdir())
