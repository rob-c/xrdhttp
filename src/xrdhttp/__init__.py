"""xrdhttp: the HTTP pieces every grid storage client shares.

WebDAV, S3 and the WLCG HTTP extensions are spoken by xrdclient's
``HTTPClient`` and xgfalclient's HTTP plug-in alike. Each keeps its own
facade - its URL type, its errors, its configuration - and sits on these
protocol pieces, which take plain strings, callbacks and an
:class:`ssl.SSLContext` the caller built, and know nothing of either client:

* :mod:`.session` - one pooled, thread-safe session over the pieces below:
  per-endpoint and per-credential pooling, redirects under a credential
  policy, ``Expect: 100-continue``, retries with ``Retry-After``, and a
  client's own error vocabulary; where a client's HTTP facade starts;
* :mod:`.engine` - the request lifecycle: one retry on a stale connection,
  the redirect loop;
* :mod:`.connection` - :mod:`http.client` connections with the streaming
  contract the session needs;
* :mod:`.wire` - moving body bytes: direct socket reads, ``sendfile``
  uploads, an idle-connection pool;
* :mod:`.expect` - ``Expect: 100-continue`` before a large upload;
* :mod:`.redirects` - which credentials may follow a redirect;
* :mod:`.ranges` - several byte ranges in one ``GET`` (``multipart/byteranges``);
* :mod:`.webdav` - ``PROPFIND`` multistatus and ``Digest`` parsing;
* :mod:`.tape` - the WLCG Tape REST API;
* :mod:`.tpc` - WLCG HTTP third-party copy: headers and performance markers;
* :mod:`.metalink` - Metalink 3/4 replica descriptors;
* :mod:`.s3` - AWS Signature Version 4 and the S3 answer codec (needs
  ``botocore``, the ``xrdhttp[s3]`` extra, imported only when named).

:mod:`xrdhttp.testing` is test support, not part of the library: a fake
storage element both clients' suites run against, built on xrdsec's test
server - the one module that imports xrdsec (the ``xrdhttp[testing]`` extra).

Errors are :mod:`xrdcore.errors`', cancellation :mod:`xrdcore.cancel`'s, and
XML is parsed by :mod:`xrdcore.safexml`. Importing this package imports none
of its modules: each is loaded when first named.
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import TYPE_CHECKING

from ._version import __version__

if TYPE_CHECKING:
    from . import (
        connection,
        engine,
        expect,
        metalink,
        ranges,
        redirects,
        s3,
        session,
        tape,
        tpc,
        webdav,
        wire,
    )

__all__ = [
    "__version__",
    "connection",
    "engine",
    "expect",
    "metalink",
    "ranges",
    "redirects",
    "s3",
    "session",
    "tape",
    "tpc",
    "webdav",
    "wire",
]

_SUBMODULES = frozenset(__all__) - {"__version__"}


def __getattr__(name: str) -> ModuleType:
    """Import a submodule the first time it is named as an attribute."""
    if name in _SUBMODULES:
        return importlib.import_module(f"{__name__}.{name}")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    """The public names, including submodules not yet imported."""
    return sorted(__all__)
