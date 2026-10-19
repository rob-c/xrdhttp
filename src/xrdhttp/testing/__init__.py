"""A fake HTTP storage element for testing any client of this library.

One threaded HTTP(S) server speaking what grid storage speaks over HTTP::

    with StorageServer(MemoryStore({"/d/a.root": b"hello"})) as srv:
        ...                               # point a client at srv.base
        srv.requests[-1].method           # "PROPFIND"

What it answers:

* WebDAV: ``OPTIONS``, ``PROPFIND`` (depth 0 and 1), ``MKCOL``,
  ``DELETE``, ``MOVE``; ``GET`` with one or several ``Range``\\ s,
  ``HEAD``, ``PUT`` (``Expect: 100-continue``, ``Content-Length`` or
  chunked, ``If-None-Match: *``); RFC 3230 ``Want-Digest`` and RFC 9530
  ``Want-Repr-Digest``; Metalink advertised with ``Link``;
* HTTP third-party ``COPY`` in pull and push mode, streaming performance
  markers, with proxy delegation (``X-Delegate-To``) through a
  :class:`DelegationService` the caller supplies;
* the WLCG Tape REST API (:class:`Tape`), macaroon and OAuth token
  issuance, and CDMI QoS;
* S3 (:class:`S3`): SigV4 header-signed and pre-signed requests, GCS V4
  signed URLs, ``ListObjects`` v1 and v2, multipart upload, server-side
  copy; and Swift (:class:`Swift`);
* authorisation: bearer tokens, Basic, and client certificates over TLS;
* faults (:meth:`StorageServer.fault`): a status, a dropped connection, a
  delay, a truncated or stalled body, a server gone silent - for the next
  matching request - and :attr:`StorageServer.handlers` for an answer no
  server would give;
* the reply helpers any in-process HTTP fake answers with:
  :func:`ranged_reply`, :func:`byteranges`, :func:`propfind_reply`,
  :func:`multistatus`, :func:`dav_entries` and :class:`DAVEntry`.

What is served lives in a :class:`MemoryStore` (dicts a test seeds and
reads directly) or a :class:`DirectoryStore` (a real directory, so large
files are cheap). Every request is recorded in
:attr:`StorageServer.requests`.

xrdclient and xgfalclient were each tested against their own fake of
this; this is the one they now share. Their tests rely on different
behaviour in a dozen corners, because the servers they meet differ: the
``style`` argument picks XrdCl's (the default) or davix's, and every
difference is a switch on :class:`StorageServer` (:data:`STYLES` lists
them). Each client keeps a thin preset with its own names
(``xrdclient.testing.FakeDAVServer``/``FakeS3Server``,
``xgfalclient.testing.webdav.WebDAVServer``).

The wire plumbing is xrdsec's generic test server,
:class:`xrdsec.testing.https.FakeHTTPSServer`: TLS per connection from the
caller's server-side :class:`ssl.SSLContext`, the client's certificate chain
(:attr:`Request.peer <xrdsec.testing.https.Request.peer>`), the request
log, :class:`Fault` and :class:`Request` are its. That is why this package
is the ``xrdhttp[testing]`` extra, and the only xrdhttp module importing
xrdsec. Delegation needs X.509 work beyond it (certificate requests), so it
is a :class:`DelegationService` plugged in by the client's preset.

Where to start reading: :mod:`._server` (state and lifecycle), then
:mod:`._front` (what every request passes through), then the dialect
modules it routes to. Public test API, versioned with the package.
Nothing in the library imports it.
"""

from __future__ import annotations

from xrdsec.testing.https import Fault as Fault
from xrdsec.testing.https import Request as Request
from xrdsec.testing.https import Response as Response

from ._model import S3 as S3
from ._model import DelegationService as DelegationService
from ._model import Handler as Handler
from ._model import Reply as Reply
from ._model import Swift as Swift
from ._model import Tape as Tape
from ._replies import BOUNDARY as BOUNDARY
from ._replies import DAVEntry as DAVEntry
from ._replies import byteranges as byteranges
from ._replies import dav_entries as dav_entries
from ._replies import multistatus as multistatus
from ._replies import propfind_reply as propfind_reply
from ._replies import ranged_reply as ranged_reply
from ._server import ALL_DIGESTS as ALL_DIGESTS
from ._server import STYLES as STYLES
from ._server import StorageServer as StorageServer
from ._store import DirectoryStore as DirectoryStore
from ._store import Entry as Entry
from ._store import MemoryStore as MemoryStore
from ._store import Store as Store

__all__ = [
    "ALL_DIGESTS",
    "BOUNDARY",
    "S3",
    "STYLES",
    "DAVEntry",
    "DelegationService",
    "DirectoryStore",
    "Entry",
    "Fault",
    "Handler",
    "MemoryStore",
    "Reply",
    "Request",
    "Response",
    "StorageServer",
    "Store",
    "Swift",
    "Tape",
    "byteranges",
    "dav_entries",
    "multistatus",
    "propfind_reply",
    "ranged_reply",
]
