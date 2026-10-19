"""What a test configures on, or reads back from, the fake storage element.

Plain data with no behaviour beyond naming: the state of the optional
dialects - :class:`Tape` (WLCG Tape REST), :class:`S3` (and Google Cloud
Storage signed URLs) and :class:`Swift` - and the two callable shapes a
test plugs in, :data:`Handler` (answer one method yourself) and
:data:`DelegationService` (speak a proxy-delegation protocol the fake does
not know). The recorded :class:`~xrdsec.testing.https.Request` and the
injected :class:`~xrdsec.testing.https.Fault` are the generic server's, which
the fake is built on. Everything is re-exported by :mod:`xrdhttp.testing`;
nothing here imports the server, so the handler modules can import it freely.
"""

from __future__ import annotations

import posixpath
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from ._server import StorageServer

#: One canned answer: ``(status, body, headers)``, sent exactly as given
#: (``Content-Length`` is added).
Reply = tuple[int, bytes, dict[str, str]]

#: What :attr:`~xrdhttp.testing.StorageServer.handlers` holds, per method. It
#: is handed ``(method, path, headers)`` - ``path`` decoded and normalised as
#: :attr:`Request.path` is - and either answers the request itself or
#: returns ``None`` to let the fake have it. This is how a test serves an
#: answer no server would produce on its own: a hostile multistatus, a short
#: body, a digest in a shape nobody sensible would send.
Handler = Callable[[str, str, dict[str, str]], Reply | None]


class DelegationService(Protocol):
    """A proxy-delegation endpoint the fake mounts at ``/gridsite-delegation``.

    Delegation needs X.509 certificate requests and signature checks, which
    are a client's (xrdsec's test server knows identities, not requests); a
    client's preset supplies the service (xgfalclient plugs in gridsite
    delegation 1 and 2). It is called with the server and the ``POST`` body,
    answers with a :data:`Reply`, and reports a proxy received with
    :meth:`~xrdhttp.testing.StorageServer.accept_delegation`, which wakes a
    third-party ``COPY`` waiting for it.
    """

    def __call__(self, server: StorageServer, body: bytes) -> Reply:
        """Serve one delegation request."""
        ...


def clean(path: str) -> str:
    """The stored form of a plain path: absolute, normalised, no trailing slash.

    A plain path is a name, as a test or a tape request writes it, so a
    ``%`` or a ``#`` in it is part of the name and is not decoded here.
    """
    stripped = path.strip("/")
    return posixpath.normpath("/" + stripped) if stripped else "/"


def decoded(target: str) -> str:
    """The plain path a request target or an absolute URL names.

    Its escapes are decoded exactly once - the other half of a client
    encoding a name exactly once - and the query is dropped.
    """
    return clean(urllib.parse.unquote(urllib.parse.urlsplit(target).path))


@dataclass
class Tape:
    """WLCG Tape REST API state: where each file is, and the staging requests.

    A file's locality is :attr:`locality`'s word for it when there is one;
    otherwise it is worked out from the namespace - ``TAPE`` for a file in
    :attr:`nearline`, ``DISK`` for any other file, and missing files are
    reported lost. A staged file is ``CANCELLED`` once withdrawn, ``FAILED``
    if it is lost (``LOST``/``NONE``), ``SUBMITTED`` while it is in
    :attr:`nearline` (a test discards it there to watch it come online),
    ``STARTED`` for the first :attr:`stage_polls` polls, then ``COMPLETED``.
    """

    sitename: str = "fake-site"
    #: The discovery document's ``description``.
    description: str = "xrdhttp test tape"
    #: The ``version`` the discovery document advertises (the endpoint is
    #: ``/api/v1/`` whatever it says, so a client must not build paths from it).
    version: str = "v1"
    #: Replace the discovery document (a JSON-able value, or raw bytes sent as they are).
    discovery: Any = None
    #: Path -> locality (``DISK``, ``TAPE``, ``DISK_AND_TAPE``, ``LOST``...), overriding
    #: what the namespace says.
    locality: dict[str, str] = field(default_factory=dict)
    #: Files that live on tape only: a staging request for one stays
    #: ``SUBMITTED`` until the test discards it from this set.
    nearline: set[str] = field(default_factory=set)
    #: How many polls a staged file takes to come online.
    stage_polls: int = 0
    #: Stage request id -> the server's record of it: ``files`` (the request's
    #: entries as sent) and ``polls`` (how many times it was polled).
    requests: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: ``(request id, paths)`` for every ``release`` call, in order.
    released: list[tuple[str, list[str]]] = field(default_factory=list)
    #: ``(request id, paths)`` for every ``cancel`` call, in order.
    cancelled: list[tuple[str, list[str]]] = field(default_factory=list)

    def staged(self) -> dict[str, list[str]]:
        """Request id -> the paths it named, for the requests not yet withdrawn."""
        return {
            key: [str(e.get("path", "")) for e in r["files"]] for key, r in self.requests.items()
        }


@dataclass
class S3:
    """The S3 dialect: path-style buckets, AWS Signature Version 4 with these keys.

    Every request must carry a valid SigV4 signature - in the
    ``Authorization`` header or as ``X-Amz-*`` query parameters - for
    ``access_key``/``secret_key``; anything else gets 403
    ``SignatureDoesNotMatch``. ``access_key=""`` turns the check off for
    tests that are not about authentication. Buckets are the store's
    buckets (see :class:`~xrdhttp.testing.MemoryStore` and
    :class:`~xrdhttp.testing.DirectoryStore`).
    """

    access_key: str = "AKIDTEST"
    secret_key: str = "SECRETTEST"
    #: The region a signature's scope must name; ``None`` accepts the one it names.
    region: str | None = "us-east-1"
    #: The session token (``x-amz-security-token``) a header-signed request must
    #: carry, as with temporary credentials; empty requires none.
    token: str = ""
    #: The default and the cap for ``max-keys`` in listings (v1 and v2); small values
    #: make the client follow ``NextMarker``/``NextContinuationToken``.
    page_size: int = 1000
    #: Multipart upload id -> part number -> part bytes, until completed or aborted.
    uploads: dict[str, dict[int, bytes]] = field(default_factory=dict)
    #: Uploads that were abandoned (``AbortMultipartUpload``), in order.
    aborted: list[str] = field(default_factory=list)
    #: ``bucket/key`` -> ``ETag`` for objects whose tag is not a plain MD5 - the
    #: ones that arrived as a multipart upload, whose tag is a digest of
    #: digests with the part count on the end.
    etags: dict[str, str] = field(default_factory=dict)
    #: Begin a multipart upload without naming it, as nothing sane does.
    nameless_uploads: bool = False
    #: Report a failure in the body of an otherwise successful completion,
    #: which is exactly how S3 reports one.
    complete_fails: bool = False
    #: Report a failure in the body of an otherwise successful copy, as S3
    #: does for ``CopyObject`` exactly as for completion.
    copy_fails: bool = False
    #: Part numbers to refuse with a 500, once each: a part lost on the way in.
    failing_parts: set[int] = field(default_factory=set)
    #: Refuse every request, whatever it is signed with (``AccessDenied``).
    forbidden: bool = False
    #: Speak GCS instead: V4 signed URLs checked against this service account's
    #: public key, any object with ``verify(data, signature, digest="sha256")``.
    gcs_key: Any = None
    gcs_email: str = ""


@dataclass
class Swift:
    """The Swift dialect: containers are buckets, reached as ``/v1/<account>/<container>``."""

    #: The ``X-Auth-Token`` required; empty accepts any request.
    token: str = ""
    #: The account the paths are under (``AUTH_<project>`` for a project); empty for none.
    account: str = ""
