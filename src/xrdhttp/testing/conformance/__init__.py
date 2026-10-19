"""One conformance suite for every client of an HTTP storage element.

xrdclient and xgfalclient each tested stat, listings, collections, renames,
ranged reads, uploads (sized, chunked, ``100-continue``), digests,
redirects, HTTP third-party copy with its markers, the WLCG Tape REST API,
macaroons and S3 against the same fake (:class:`~xrdhttp.testing.StorageServer`)
- each in its own words, so the same server behaviour was checked twice and
the two sets drifted. These are those checks once, as pytest classes a
client runs by subclassing, in the manner of fsspec's abstract test
classes::

    from xrdhttp.testing.conformance import Adapter, NamespaceSuite

    class Mine(Adapter):            # the client's operations, in neutral terms
        def stat(self, url): ...

    class TestNamespace(NamespaceSuite):
        def make_adapter(self, server):
            return Mine(server)

The suites (:class:`NamespaceSuite`, :class:`ReadSuite`,
:class:`UploadSuite`, :class:`ChecksumSuite`, :class:`RedirectSuite`,
:class:`ConnectionSuite`, :class:`CopySuite`, :class:`TapeSuite`,
:class:`TokenSuite`, :class:`S3Suite`) provide the fakes as fixtures
(``server``, ``peer``) and the client as ``client``; see
:class:`Conformance` for the hooks. An :class:`Adapter` answers in neutral
terms (:class:`Stat`, bytes, booleans) and reads errors as a :class:`Kind`,
so a check is the same whichever client runs it. What only one client
promises - gfal2's error wording and errno, XrdCl's status codes, either
one's options, events and API shape - stays in that client's own suite.

The suites are tested here against a reference adapter built on
:class:`xrdhttp.session.Session` (``tests/_reference.py``), so every check
is known to be passable by a correct client. This package imports pytest,
which the ``testing`` extra brings.
"""

from __future__ import annotations

from ._adapter import ERRNO_KINDS as ERRNO_KINDS
from ._adapter import Adapter as Adapter
from ._adapter import Kind as Kind
from ._adapter import Progress as Progress
from ._adapter import Stat as Stat
from ._adapter import kind_of_errno as kind_of_errno
from ._base import Conformance as Conformance
from ._base import failure as failure
from ._copy import CopySuite as CopySuite
from ._data import ChecksumSuite as ChecksumSuite
from ._data import ReadSuite as ReadSuite
from ._data import UploadSuite as UploadSuite
from ._namespace import NamespaceSuite as NamespaceSuite
from ._network import ConnectionSuite as ConnectionSuite
from ._network import RedirectSuite as RedirectSuite
from ._s3 import S3Suite as S3Suite
from ._staging import TapeSuite as TapeSuite
from ._staging import TokenSuite as TokenSuite

__all__ = [
    "ERRNO_KINDS",
    "Adapter",
    "ChecksumSuite",
    "Conformance",
    "ConnectionSuite",
    "CopySuite",
    "Kind",
    "NamespaceSuite",
    "Progress",
    "ReadSuite",
    "RedirectSuite",
    "S3Suite",
    "Stat",
    "TapeSuite",
    "TokenSuite",
    "UploadSuite",
    "failure",
    "kind_of_errno",
]
