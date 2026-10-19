"""Who may hear a credential when a server says "go elsewhere".

A redirect is a URL a server wrote, and following it with the caller's
``Authorization`` attached hands the caller's identity to whoever that URL
names. This module is the policy every client applies before following one,
on plain URL strings so that it does not care which client's URL type they
came from:

* :func:`carries_credentials` - the caller's own credentials follow only to
  the same origin (scheme, host, port), never down from HTTPS to HTTP, and
  to a configured trusted domain only when the operator opted it in;
* :func:`davix_carries_credentials` - gfal2's looser rule: any host, except
  from HTTPS down to HTTP on another host;
* :func:`relays_transfer_headers` - a ``COPY``'s ``TransferHeader*``
  headers (the *far* endpoint's credential) follow within the site that
  sent the redirect, never beyond it;
* :func:`without_credentials` - strips what a hop may not carry;
* :func:`resolve_location` and :func:`wire_path` - spell the next hop the
  way it goes on the wire.

``dav``/``davs``/``webdav`` are HTTP spelt by grid tools; they are read as
``http``/``https``/``http`` (see :func:`wire_scheme`). Anything else - an
``s3://`` URL, which different clients map differently - must be spelt as
the HTTP it is before it gets here.
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Collection, Mapping

__all__ = [
    "CREDENTIAL_HEADERS",
    "TOKEN_FIELDS",
    "TRANSFER_PREFIX",
    "carries_credentials",
    "davix_carries_credentials",
    "endpoint",
    "in_domain",
    "public_suffix",
    "query_token",
    "relays_transfer_headers",
    "resolve_location",
    "uses_tls",
    "wire_path",
    "wire_scheme",
    "without_credentials",
]

#: Request headers that are credentials, lower-cased.
CREDENTIAL_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie"})
#: ``TransferHeader*`` is a whole family: a ``COPY`` asks the server to pass
#: each one on to the far side, and the one that matters is the far side's token.
TRANSFER_PREFIX = "transferheader"
#: Query fields that are bearer tokens. They are presented in the
#: ``Authorization`` header and never sent in a request target.
TOKEN_FIELDS = ("authz", "access_token")

#: Grid spellings of HTTP, and what they are on the wire.
_WIRE = {
    "http": "http",
    "https": "https",
    "dav": "http",
    "davs": "https",
    "webdav": "http",
}
_DEFAULT_PORTS = {"http": 80, "https": 443}

#: An escaped slash, which :func:`wire_path` keeps as it is.
_ENCODED_SLASH = re.compile("%2F", re.IGNORECASE)


def wire_scheme(scheme: str) -> str:
    """``http`` or ``https``: what ``scheme`` is on the wire; ``ValueError`` if not HTTP."""
    try:
        return _WIRE[scheme.lower()]
    except KeyError:
        raise ValueError(f"{scheme!r} is not an HTTP scheme") from None


def uses_tls(url: str) -> bool:
    """Whether ``url`` is reached over TLS (``https``, ``davs``)."""
    return wire_scheme(urllib.parse.urlsplit(url).scheme) == "https"


def endpoint(url: str) -> tuple[str, str, int]:
    """The origin ``url`` is served by: ``(wire scheme, host, port)``.

    RFC 9110 section 4.3.1's origin: two URLs with the same key may share a
    connection, and a redirect within one key keeps its credentials. The
    host is lower-cased and an absent port is the scheme's default.
    """
    parts = urllib.parse.urlsplit(url)
    scheme = wire_scheme(parts.scheme)
    return (scheme, (parts.hostname or "").lower(), parts.port or _DEFAULT_PORTS[scheme])


def carries_credentials(origin: str, target: str, trusted: Collection[str] = ()) -> bool:
    """Whether a redirect from ``origin`` to ``target`` may carry credentials.

    The rule browsers, ``curl`` and ``requests`` follow: only to the same
    scheme, host and port, and never from HTTPS down to plain HTTP. A host
    in one of the ``trusted`` domains is let through whatever its port - that
    is how a site whose head node hands off to its data nodes is opted in -
    but still not over a downgrade.
    """
    if uses_tls(origin) and not uses_tls(target):
        return False
    if endpoint(origin) == endpoint(target):
        return True
    host = endpoint(target)[1]
    return any(in_domain(host, domain) for domain in trusted)


def davix_carries_credentials(origin: str, target: str) -> bool:
    """Whether a redirect may carry credentials by davix's rule, which gfal2 follows.

    davix forwards credentials across hosts because a storage element's door
    and its data servers are one service under different names, and the data
    server needs the same token. The one hop refused is from HTTPS down to
    plain HTTP on another host, where the token would cross the network in
    clear. Looser than :func:`carries_credentials` on purpose - a client
    emulating gfal2 must present what gfal2 presents - so it is a separate,
    named policy rather than an option of that one. An X.509 proxy is not
    affected by either: it travels in the TLS handshake, not in a header.
    """
    if endpoint(origin)[1] == endpoint(target)[1]:
        return True
    return not (uses_tls(origin) and not uses_tls(target))


def relays_transfer_headers(origin: str, target: str) -> bool:
    """Whether a redirect may carry a ``COPY``'s ``TransferHeader*`` headers.

    Those are not this client's credential for the host it is talking to:
    they are what the node that runs a third-party copy must present to the
    *far* endpoint - in practice a macaroon minted for this one transfer,
    scoped to one file and a few activities, for minutes. EOS's head node
    hands every ``COPY`` to a disk server of its own over plain ``http``
    (``st-*.cern.ch:8443``, authorised by a capability it signs), and a copy
    whose headers stayed behind fails there with ``401``. So they follow a
    redirect within the site that sent it - the origin's parent domain,
    which the origin proved it speaks for over TLS - even down to ``http``,
    and never anywhere else. The caller's own ``Authorization`` keeps the
    stricter rule of :func:`carries_credentials`. davix and gfal2 send
    everything everywhere.

    The parent domain must be a site's, not a registry's: ``se.ac.uk``'s
    parent is ``ac.uk``, which is every university in the country, so when
    the parent is a public suffix (:func:`public_suffix`) the headers stay
    with the origin host alone.
    """
    origin_host = endpoint(origin)[1]
    target_host = endpoint(target)[1]
    labels = origin_host.split(".")
    parent = ".".join(labels[1:])
    if len(labels) < 3 or labels[-1].isdigit() or public_suffix(parent):
        # a bare domain, an address, or a host directly under a registry
        return origin_host == target_host
    return in_domain(target_host, parent)


#: Multi-label public suffixes a research network's hosts sit under, where a
#: host one label below would otherwise call a whole country's universities
#: or companies its site. Not the Public Suffix List - this library carries
#: no data file and takes no dependency - but the second-level registries
#: of the countries whose sites run grid storage, beyond what the generic
#: rule in :func:`public_suffix` already catches.
_PUBLIC_SUFFIXES = frozenset(
    f"{label}.{country}"
    for country, labels in {
        "uk": "ac co gov org ltd plc me nhs sch police",
        "jp": "ac co go or ne ad ed gr lg",
        "kr": "ac co go or re",
        "cn": "ac edu com gov net org",
        "in": "ac co edu gov res ernet nic",
        "au": "edu com gov net org",
        "nz": "ac co govt cri org",
        "il": "ac co gov org muni",
        "at": "ac co gv or",
        "be": "ac",
        "pl": "edu com gov org",
        "es": "edu com gob org nom",
        "tr": "edu gov",
        "gr": "edu",
        "pt": "edu",
        "br": "edu com gov org",
        "mx": "edu com gob",
        "ar": "edu com",
        "co": "edu",
        "za": "ac co gov org",
    }.items()
    for label in labels.split()
)

#: Second-level labels that name a registry - academic, commercial, governmental -
#: in whatever country the top-level domain is, and so are treated as public
#: when they sit directly under a two-letter country code.
_REGISTRY_LABELS = frozenset(
    {"ac", "co", "com", "edu", "gov", "net", "org", "gob", "or", "ne", "go"}
)


def public_suffix(domain: str) -> bool:
    """Whether ``domain`` (two labels or more) is a registry, not a site.

    One of the curated suffixes is; so is any two-label name whose first
    label is a registry word - ``ac``, ``co``, ``edu``, ``gov``... - for the
    many countries not listed. ``cern.ch``, ``fnal.gov`` and ``desy.de`` are
    not.
    """
    labels = domain.split(".")
    return domain in _PUBLIC_SUFFIXES or (len(labels) == 2 and labels[0] in _REGISTRY_LABELS)


def in_domain(host: str, domain: str) -> bool:
    """Whether ``host`` is ``domain`` or under it; ``"*"`` matches anything.

    Matches on a label boundary - ``evilcern.ch`` is not under ``cern.ch`` -
    and ignores a leading or trailing dot in the configured entry.
    """
    host = host.lower()
    domain = domain.lower().strip(".")
    return domain == "*" or host == domain or host.endswith("." + domain)


def without_credentials(
    headers: Mapping[str, str], *, keep_transfer: bool = False
) -> dict[str, str]:
    """``headers`` less any that would authenticate the request.

    ``keep_transfer`` keeps the ``TransferHeader*`` family, which a
    same-site redirect of a ``COPY`` must carry to the node that runs it.
    """
    return {
        name: value
        for name, value in headers.items()
        if name.lower() not in CREDENTIAL_HEADERS
        and (keep_transfer or not name.lower().startswith(TRANSFER_PREFIX))
    }


def query_token(query: Mapping[str, str]) -> str | None:
    """The bearer token a URL's decoded query carries (``authz=``/``access_token=``), if any.

    A ``Bearer`` prefix, as XRootD's ``authz=Bearer%20...`` spells it, is
    dropped: the token is what follows it.
    """
    for name in TOKEN_FIELDS:
        value = query.get(name)
        if value:
            return value.removeprefix("Bearer ").strip()
    return None


def wire_path(path: str) -> str:
    """A plain path percent-encoded, exactly once, for an HTTP request.

    Every byte but ``/`` and RFC 3986's unreserved characters is escaped -
    a ``%`` included - except an escaped slash (``%2F``), which is kept: the
    path is a name, a name may hold a slash that is not a separator, and the
    decoding a client applies to a URL's path leaves ``%2F`` alone, so the
    two are inverses. Keeping an existing ``%41`` as an escape would send a
    file literally called ``a%41b`` to ``aAb``. The escaping is also exactly
    what S3 signs as its canonical URI, so the signature and the wire agree.
    """
    return "%2F".join(urllib.parse.quote(part, safe="/") for part in _ENCODED_SLASH.split(path))


def resolve_location(current: str, location: str) -> str:
    """A ``Location`` resolved against the URL that produced it, in ``current``'s scheme.

    An absolute ``Location`` is itself. A relative one (RFC 9110 section
    10.2.2 allows it) is resolved as RFC 3986 section 5 says: a path
    reference keeps ``current``'s whole authority, user name included, and a
    network-path reference (``//other/x``) replaces it - the user name was
    never meant for another server.

    The scheme is ``current``'s, whatever it is: a hop from ``davs://`` stays
    ``davs://`` and one from ``s3s://`` stays ``s3s://``, because a client
    attaches trust anchors, credentials and request signing to its scheme,
    and the next hop must get the same. :func:`urllib.parse.urljoin` resolves
    only the schemes it knows, so the join is made under ``http`` - whose
    resolution rules every hierarchical URL shares - and the scheme is put
    back. ``ValueError`` if ``current`` is not an absolute URL.
    """
    if urllib.parse.urlsplit(location).scheme:
        return location
    scheme, separator, rest = current.partition("://")
    if not separator or not scheme:
        raise ValueError(f"{current!r} is not an absolute URL")
    joined = urllib.parse.urljoin(f"http://{rest}", location)
    return f"{scheme}://{joined.removeprefix('http://')}"
