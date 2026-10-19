"""AWS Signature Version 4, in the shape an S3 endpoint asks for.

Signing is the whole of what S3 adds to HTTP: every request carries an
``Authorization`` header holding an HMAC of the request itself, keyed by a
secret derived from the account's own. Nothing here touches the network, and
the secret never leaves the process - what goes on the wire is the signature,
not the key that made it.

    >>> creds = Credentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG")
    >>> headers = sign("GET", "/bucket/key", "s3.amazonaws.com", {},
    ...                hash_payload(b""), credentials=creds, region="us-east-1")
    >>> headers["Authorization"].split()[0]
    'AWS4-HMAC-SHA256'

How SigV4 works, so the code below reads in order. The *canonical request*
is the method, the URI path, the query (each name and value percent-encoded
per RFC 3986, sorted by name), the signed headers (names lower-cased, values
trimmed, sorted, one per line), the list of their names, and the payload's
SHA-256 - one per line. The *string to sign* is the algorithm, the
timestamp, the credential scope (``date/region/service/aws4_request``) and
the SHA-256 of the canonical request. The signing key is an HMAC chain -
secret, then date, region, service, ``aws4_request`` - so a leaked key is
only good for one day, region and service. The signature is HMAC-SHA256 of
the string to sign under that key.

The canonicalisation and the HMAC chain are botocore's (``S3SigV4Auth``),
because they are where a hand-rolled signer goes subtly wrong - S3, unlike
other services, does *not* double-encode the path. What this module owns
is everything around them: the URL is passed in already spelt as it goes
on the wire (:func:`_wire_url`), the moment is chosen by the caller so a
signature is reproducible, the payload hash is supplied rather than read
from a streamed body, and only ``host`` and ``x-amz-*`` headers are signed.
Tests check the result against AWS's published worked examples.
"""

from __future__ import annotations

import configparser
import hashlib
import os
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from botocore.auth import S3SigV4Auth, S3SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials as _AWSCredentials
from botocore.utils import percent_encode_sequence

__all__ = [
    "ALGORITHM",
    "DEFAULT_REGION",
    "EMPTY_SHA256",
    "UNSIGNED_PAYLOAD",
    "Credentials",
    "hash_payload",
    "presign",
    "sign",
]

#: The only algorithm S3 signs with, as it appears in the header.
ALGORITHM = "AWS4-HMAC-SHA256"
#: The hash of an empty body, which every request without one carries.
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
#: What a request whose body is not in hand up front signs instead. S3 accepts
#: it for a streamed upload, where the hash cannot be known before the bytes
#: have been sent.
UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD"
#: The region assumed when nothing names one; AWS's own default.
DEFAULT_REGION = "us-east-1"
#: How long a pre-signed URL stays valid when nothing says otherwise, in seconds.
DEFAULT_EXPIRES = 3600
#: The ``X-Amz-Date`` spelling of a moment.
_STAMP = "%Y%m%dT%H%M%SZ"

#: Where the shared credentials file lives when the environment is quiet.
DEFAULT_CREDENTIALS_FILE = "~/.aws/credentials"


@dataclass(frozen=True, repr=False, slots=True)
class Credentials:
    """An access key and the secret that signs with it.

    The secret is the credential; the key id merely names it. So the key id
    prints and the secret does not - a traceback, a log line or a ``repr`` in a
    notebook must not be a way to leak an account.
    """

    access_key: str
    secret_key: str
    #: The session token of a temporary credential, if this is one.
    session_token: str = ""

    def __repr__(self) -> str:
        """The key id, with the secret and any session token redacted."""
        token = ", session_token=<redacted>" if self.session_token else ""
        return f"Credentials({self.access_key!r}, secret_key=<redacted>{token})"

    @classmethod
    def from_env(cls) -> Credentials | None:
        """``AWS_ACCESS_KEY_ID`` and friends, or ``None`` if unset."""
        access = os.environ.get("AWS_ACCESS_KEY_ID", "")
        secret = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
        if not access or not secret:
            return None
        return cls(access, secret, os.environ.get("AWS_SESSION_TOKEN", ""))

    @classmethod
    def from_file(cls, path: str = "", profile: str = "") -> Credentials | None:
        """One profile of a shared credentials file, or ``None`` if it has none.

        The file is the one every S3 tool reads - ``~/.aws/credentials``, or
        whatever ``AWS_SHARED_CREDENTIALS_FILE`` points at - in the ini format
        they all write. An unreadable or malformed file is *no credentials*
        rather than an error: the caller may have meant to sign with the
        environment, or not to sign at all.
        """
        name = path or os.environ.get("AWS_SHARED_CREDENTIALS_FILE", DEFAULT_CREDENTIALS_FILE)
        section = profile or os.environ.get("AWS_PROFILE", "default")
        parser = configparser.ConfigParser()
        try:
            if not parser.read(os.path.expanduser(name)):
                return None
        except (OSError, configparser.Error):
            return None
        if not parser.has_section(section):
            return None
        values = parser[section]
        access = values.get("aws_access_key_id", "")
        secret = values.get("aws_secret_access_key", "")
        if not access or not secret:
            return None
        return cls(access, secret, values.get("aws_session_token", ""))

    @classmethod
    def discover(cls) -> Credentials | None:
        """The environment first, then the shared file - AWS's own order."""
        return cls.from_env() or cls.from_file()


def hash_payload(body: bytes | bytearray | memoryview | None) -> str:
    """The ``x-amz-content-sha256`` value for ``body``.

    ``None`` is a body that has not been assembled - a streamed upload - and
    signs as :data:`UNSIGNED_PAYLOAD`, which is what S3 offers for exactly
    that case.
    """
    if body is None:
        return UNSIGNED_PAYLOAD
    return hashlib.sha256(body).hexdigest()


def sign(
    method: str,
    target: str,
    host: str,
    headers: Mapping[str, str],
    payload_hash: str,
    *,
    credentials: Credentials,
    region: str,
    service: str = "s3",
    when: datetime | None = None,
) -> dict[str, str]:
    """Sign one request; the result is the headers to send with it.

    ``target`` is the origin-form request target - the percent-encoded path
    and query exactly as they go on the wire - and ``host`` the ``Host``
    header the connection will carry. Both are signed, so both must be what
    is actually sent, which is why this takes them rather than a URL.

    Of the headers, ``host`` and everything beginning ``x-amz-`` are signed,
    as S3 requires; the rest (``Range``, ``Content-Length``, ``User-Agent``)
    travel unsigned, so a proxy that adds one does not break the request.
    """
    request = _Request(
        method, _wire_url(target, host), host, _botocore_credentials(credentials), region, service
    )
    return _signed_request(request, headers, payload_hash, when)


def _wire_url(target: str, host: str) -> str:
    """The ``https`` URL botocore signs, spelt exactly as ``target`` goes on the wire."""
    path, separator, query = target.partition("?")
    # Encode literal spaces without decoding escaped slashes/object names.
    path = urllib.parse.quote(path or "/", safe="/%")
    return f"https://{host}{path}{separator}{query}"


def _botocore_credentials(credentials: Credentials) -> _AWSCredentials:
    """``credentials`` as botocore's signers take them."""
    return _AWSCredentials(
        credentials.access_key, credentials.secret_key, credentials.session_token or None
    )


@dataclass(frozen=True, slots=True)
class _Request:
    """One request to sign, as the private signing helpers take it.

    ``url`` is already the wire spelling (see :func:`_wire_url`) and
    ``credentials`` already botocore's type, so the helpers below can be
    driven directly - as the golden-value tests do -
    without going through the public argument conversion again. Grouping
    them is what keeps :func:`sign` and :func:`presign` (whose long
    signatures are public and stay) from being re-listed one level down.
    """

    method: str
    url: str
    host: str
    credentials: _AWSCredentials
    region: str
    service: str = "s3"


def _signed_request(
    request: _Request,
    headers: Mapping[str, str],
    payload_hash: str,
    when: datetime | None = None,
) -> dict[str, str]:
    """Sign an already encoded wire URL without changing its spelling.

    Only ``host`` and ``x-amz-*`` headers are taken from the caller (see
    :func:`_selected_headers`); the date, token and payload hash are set by
    the signer itself so a stale caller-supplied value can never be signed.
    ``request.params`` is filled from the URL because botocore canonicalises
    the query from there, not from the URL string. Header names come back
    lower-cased for ``x-amz-*`` - the spelling S3's own SDKs send - and as
    botocore spelt them otherwise (``Authorization``).
    """
    signed = _selected_headers(headers)
    signed["host"] = request.host
    signed["x-amz-content-sha256"] = payload_hash
    wire = AWSRequest(method=request.method.upper(), url=request.url, headers=signed)
    # Pairs, not a dict, so a repeated key is signed as sent. botocore's
    # canonicaliser takes either; botocore-stubs declares only the dict.
    pairs = urllib.parse.parse_qsl(request.url.partition("?")[2], keep_blank_values=True)
    wire.params = pairs  # type: ignore[assignment]  # stubs narrower than botocore
    signer = _PayloadSigner(request.credentials, request.service, request.region, payload_hash)
    _authorize(signer, wire, when)
    return {k.lower() if k.lower().startswith("x-amz-") else k: v for k, v in wire.headers.items()}


def presign(
    method: str,
    target: str,
    host: str,
    *,
    credentials: Credentials,
    region: str,
    expires: int = DEFAULT_EXPIRES,
    service: str = "s3",
    when: datetime | None = None,
) -> str:
    """A pre-signed ``https`` URL for one request: the signature in the query.

    Whoever holds the URL may make that request, with no credentials of
    their own, for ``expires`` seconds from ``when``. ``target`` and ``host``
    are as for :func:`sign`.
    """
    request = _Request(
        method, _wire_url(target, host), host, _botocore_credentials(credentials), region, service
    )
    return _presigned_url(request, expires, when)


def _presigned_url(
    request: _Request, expires: int = DEFAULT_EXPIRES, when: datetime | None = None
) -> str:
    """Pre-sign an already encoded wire URL, as :func:`presign` describes.

    A pre-signed URL signs only ``host``: the request it authorises may be
    made by any client, with whatever other headers that client sends, so
    nothing else can be pinned.
    """
    wire = AWSRequest(
        method=request.method.upper(), url=request.url, headers={"host": request.host}
    )
    auth = S3SigV4QueryAuth(request.credentials, request.service, request.region, expires=expires)
    _sign_query(auth, wire, _stamp(when), expires)
    return str(wire.url)


def _stamp(when: datetime | None) -> str:
    """``when``, or now, as ``X-Amz-Date`` spells it. Signing an explicit
    moment is what makes a signature reproducible; botocore's own
    ``add_auth`` always signs "now", which is why it is not used."""
    return (when or datetime.now(UTC)).strftime(_STAMP)


def _authorize(
    auth: S3SigV4Auth | S3SigV4QueryAuth, request: AWSRequest, when: datetime | None
) -> None:
    """Sign ``request`` in place with ``auth``, at ``when``.

    For a caller that hands in a botocore signer of its own; new code
    wants :func:`sign` or :func:`presign`. A query signer's lifetime
    is not something botocore lets a caller read back, so its own default
    is assumed unless the signer says otherwise - pass the lifetime to
    :func:`presign` instead.
    """
    stamp = _stamp(when)
    if isinstance(auth, S3SigV4QueryAuth):
        _sign_query(auth, request, stamp, getattr(auth, "_expires", DEFAULT_EXPIRES))
        return
    _sign_headers(auth, request, stamp)


def _replace_header(request: AWSRequest, name: str, value: str) -> None:
    """Set one header, replacing any earlier value: botocore's header map
    appends on assignment, and a duplicate would be signed twice."""
    del request.headers[name]
    request.headers[name] = value


def _sign_headers(auth: S3SigV4Auth, request: AWSRequest, stamp: str) -> None:
    """``Authorization``-header signing, from botocore's public signing steps.

    What ``S3SigV4Auth.add_auth`` does, but at ``stamp`` rather than at
    whatever the clock says: the date, the session token and the payload hash
    go in as headers - all three are signed - then the canonical request,
    the string to sign and the signature are botocore's own.
    """
    request.context["timestamp"] = stamp
    del request.headers["Authorization"]
    _replace_header(request, "X-Amz-Date", stamp)
    token = auth.credentials.token
    if token:
        _replace_header(request, "X-Amz-Security-Token", token)
    _replace_header(request, "X-Amz-Content-SHA256", auth.payload(request))
    canonical = auth.canonical_request(request)
    signature = auth.signature(auth.string_to_sign(request, canonical), request)
    names = auth.signed_headers(auth.headers_to_sign(request))
    request.headers["Authorization"] = (
        f"{ALGORITHM} Credential={auth.scope(request)}, "
        f"SignedHeaders={names}, Signature={signature}"
    )


def _sign_query(auth: S3SigV4QueryAuth, request: AWSRequest, stamp: str, expires: int) -> None:
    """Query-string signing - a pre-signed URL - from botocore's public steps.

    The request's own query comes first and the signing parameters after
    it, as SigV4 requires; the signature is appended last, since it cannot
    sign itself.
    """
    request.context["timestamp"] = stamp
    parameters = {
        "X-Amz-Algorithm": ALGORITHM,
        "X-Amz-Credential": auth.scope(request),
        "X-Amz-Date": stamp,
        "X-Amz-Expires": expires,
        "X-Amz-SignedHeaders": auth.signed_headers(auth.headers_to_sign(request)),
    }
    token = auth.credentials.token
    if token is not None:
        parameters["X-Amz-Security-Token"] = token
    if request.url is None:
        raise ValueError("a request to pre-sign needs a URL")
    parts = urllib.parse.urlsplit(request.url)
    existing = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
    query = ""
    if existing:
        query = percent_encode_sequence({k: v[0] for k, v in existing.items()}) + "&"
    query += percent_encode_sequence(parameters)
    request.url = urllib.parse.urlunsplit(parts._replace(query=query))
    canonical = auth.canonical_request(request)
    signature = auth.signature(auth.string_to_sign(request, canonical), request)
    request.url += f"&X-Amz-Signature={signature}"


class _PayloadSigner(S3SigV4Auth):
    """Use the caller's precomputed hash without reading a streamed body.

    botocore's signer hashes ``request.body`` itself; for an upload that body
    is a generator still being produced, and reading it here would consume
    it. The HTTP client already knows the hash (or ``UNSIGNED-PAYLOAD``), so
    that is what is signed.
    """

    def __init__(
        self, credentials: _AWSCredentials, service: str, region: str, digest: str
    ) -> None:
        """A botocore signer for ``service`` in ``region`` that signs ``digest``."""
        super().__init__(credentials, service, region)
        self._digest = digest

    def payload(self, request: AWSRequest) -> str:
        """The precomputed ``x-amz-content-sha256``; ``request`` is not read."""
        return self._digest


def _is_signed(name: str) -> bool:
    """``host`` and the ``x-amz-*`` family: the headers S3 requires to be signed."""
    lowered = name.lower()
    return lowered == "host" or lowered.startswith("x-amz-")


def _selected_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """The caller's headers that will be signed, less those the signer sets itself.

    ``host``, the date, the payload hash and the session token are written by
    the signing step from its own inputs; a caller's copy of any of them
    (left over from a retry, say) would otherwise be signed alongside the
    fresh one and the request rejected.
    """
    reserved = {"host", "x-amz-date", "x-amz-content-sha256", "x-amz-security-token"}
    return {k: v for k, v in headers.items() if _is_signed(k) and k.lower() not in reserved}
