"""Metalink 3 and 4 download descriptions.

XrdCl treats a local or remote ``.meta4``/``.metalink`` file as a virtual
redirector.  The document must describe exactly one file; its URLs are tried
in priority order and its checksums describe the bytes every replica must
contain.  This module parses
that metadata.  Moving the bytes remains the copy engine's job.

Parsing is bounded before :mod:`xml.etree` sees the input.  Metalink files are
metadata, not datasets: accepting an unbounded document or XML entity
declarations would turn replica discovery into a memory-exhaustion surface.

A client picks its reading with a :class:`MetalinkPolicy`: XrdCl's is
:data:`XRDCL`, the default; a davix-style client builds its own for HTTP
failover (every ``<url>``, its own schemes).  The two readings differ on
purpose and only in two places: XrdCl insists on exactly one ``<file>`` and
takes any absolute URL, while davix takes every ``<url>`` in the document and
only the HTTP family of schemes.  Bounds, ranking (Metalink 3 ``preference``
high-first, Metalink 4 ``priority`` low-first, document order breaking ties),
deduplication and relative-URL resolution are the same for both.

Formats: Metalink 4 is RFC 5854 (namespace ``urn:ietf:params:xml:ns:metalink``,
``<url priority="1">`` with 1 the most preferred); Metalink 3 is the earlier
metalinker.org format (``<url preference="100">``, highest first, files under
``<files>``). Namespaces are ignored when matching element names, so both
read through the same code. Metalink/HTTP (RFC 6249, ``Link: rel=duplicate``
headers) is not parsed here - a client reads those headers itself,
resolving their targets with :func:`resolve`.

Where it is called from: a client's copy engine loads a descriptor (at most
:data:`MAX_DESCRIPTOR_SIZE` bytes of it) and calls :func:`parse_metalink`.
Start reading there; everything below it is private helpers, each enforcing
one rule. Checksums come back as :class:`xrdcore.checksum.ChecksumInfo`
(re-exported here), the one checksum type every client of xrdcore reports, so
a descriptor's checksums equal the ones a server's checksum query returns.
"""

from __future__ import annotations

import posixpath
import urllib.parse
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass, field

from xrdcore.checksum import ChecksumInfo, algorithms
from xrdcore.checksum import new as new_checksum
from xrdcore.errors import MetalinkError
from xrdcore.safexml import UnsafeXML, fromstring

__all__ = [
    "MAX_DESCRIPTOR_SIZE",
    "MAX_REPLICAS",
    "MAX_URL_SIZE",
    "XRDCL",
    "ChecksumInfo",
    "MetalinkError",
    "MetalinkFile",
    "MetalinkPolicy",
    "is_metalink",
    "parse_metalink",
    "resolve",
]

#: A descriptor is metadata.  Eight MiB leaves room for many thousands of
#: replicas while putting a hard ceiling on hostile input.
MAX_DESCRIPTOR_SIZE = 8 << 20
#: XrdCl limits one URL to 4096 bytes.  Bound the list as well, so a valid but
#: adversarial document cannot make failover run forever.
MAX_URL_SIZE = 4096
MAX_REPLICAS = 10_000

_HEX = frozenset("0123456789abcdefABCDEF")
#: Hash ``type`` spellings that are not our names even once dashes and
#: underscores are dropped: ``a32``, an adler32 abbreviation, and RFC 3230's
#: ``sha``. RFC 5854 takes its names from IANA's "Hash Function Textual
#: Names" registry, so ``sha-256`` normalises to ``sha256`` on its own.
_ALIASES = {"a32": "adler32", "sha": "sha1"}
#: Only algorithms the client can compute are kept: a checksum it could not
#: verify would be a promise the copy engine cannot keep.
_SUPPORTED = frozenset(algorithms())


@dataclass(frozen=True, slots=True)
class MetalinkFile:
    """The one file described by a Metalink document."""

    #: The ``<file name="...">``; empty under a policy that does not need it.
    name: str
    #: Absolute replica URLs, best first, without duplicates; never empty.
    replicas: tuple[str, ...]
    #: Every supported, well-formed ``<hash>``, one per algorithm, sorted by
    #: algorithm name; values are lower-case hex.
    checksums: tuple[ChecksumInfo, ...] = ()
    #: The ``<size>`` in bytes, or ``None`` when absent or not a number.
    size: int | None = None

    @property
    def checksum(self) -> ChecksumInfo | None:
        """XrdCl's default: the first supported checksum alphabetically."""
        return self.checksums[0] if self.checksums else None


def _has_scheme(url: str) -> bool:
    """XrdCl's test of a usable replica: absolute, with a host (or ``file:``)."""
    parsed = urllib.parse.urlsplit(url)
    return bool(parsed.scheme and (parsed.netloc or parsed.scheme == "file"))


@dataclass(frozen=True, slots=True)
class MetalinkPolicy:
    """How strictly one client reads a descriptor; see the module docstring.

    ``single_file`` is XrdCl's rule that a descriptor describes exactly one
    named ``<file>``; without it every ``<url>`` in the document is a replica
    of the one resource being read, and a file name is not required.
    ``accepts`` says whether a resolved replica URL is one this client can
    use - XrdCl takes any absolute URL, davix only ``http(s)``/``dav(s)``.
    """

    single_file: bool = True
    accepts: Callable[[str], bool] = field(default=_has_scheme)


#: XrdCl's reading, the default.
XRDCL = MetalinkPolicy()


def is_metalink(value: object) -> bool:
    """Whether ``value`` names a Metalink file, as XrdCl's ``URL`` decides."""
    if hasattr(value, "read") or hasattr(value, "write"):
        return False
    text = str(value)
    path = urllib.parse.urlsplit(text).path if "://" in text else text.partition("?")[0]
    lowered = path.lower()
    return lowered.endswith(".meta4") or lowered.endswith(".metalink")


def parse_metalink(
    document: bytes | bytearray | memoryview | str,
    *,
    base_url: str = "",
    policy: MetalinkPolicy = XRDCL,
) -> MetalinkFile:
    """Parse one bounded Metalink 3 or 4 document.

    ``base_url`` is used only for relative replica references.  RFC 5854 URLs
    are normally absolute, but resolving a relative one is both harmless and
    useful for hermetic catalogues.  ``policy`` is the reading to apply
    (:data:`XRDCL` unless a caller says otherwise).
    """
    # Bytes, so the size bound counts what was received and the XML parser
    # honours the document's own encoding declaration.
    data = document.encode() if isinstance(document, str) else bytes(document)
    root = _parse_document(data)
    scope = _one_file(root) if policy.single_file else root
    name = (scope.get("name") or "").strip()
    if policy.single_file and not name:
        raise MetalinkError("Metalink <file> has no name")
    # Metalink 3 carries ``version="3.0"`` on the root; RFC 5854 documents
    # have no version attribute, hence the default.
    version = (root.get("version") or "4").strip()
    replicas = _replicas(scope, base_url, version, policy.accepts)
    if not replicas:
        raise MetalinkError("Metalink file contains no usable replica URL")
    return MetalinkFile(name, replicas, _checksums(scope), _size(scope))


def _parse_document(data: bytes) -> ET.Element:
    """Parse XML only after enforcing the descriptor's resource bounds."""
    if len(data) > MAX_DESCRIPTOR_SIZE:
        raise MetalinkError(
            f"Metalink descriptor is {len(data)} bytes; limit is {MAX_DESCRIPTOR_SIZE}"
        )
    try:
        root = fromstring(data)
    except UnsafeXML as exc:
        raise MetalinkError(
            "Metalink descriptors may not declare a DOCTYPE or XML entities"
        ) from exc
    except ET.ParseError as exc:
        raise MetalinkError(f"Malformed or corrupted Metalink file: {exc}") from None
    if _local_name(root.tag) != "metalink":
        raise MetalinkError("Metalink document root must be <metalink>")
    return root


def _one_file(root: ET.Element) -> ET.Element:
    """Return the sole file XrdCl permits one descriptor to contain.

    Searched at any depth, so Metalink 3's ``<files><file>`` and RFC 5854's
    top-level ``<file>`` are found alike.
    """
    files = [element for element in root.iter() if _local_name(element.tag) == "file"]
    if len(files) != 1:
        raise MetalinkError(f"Expected exactly one file per Metalink, found {len(files)}")
    return files[0]


def _local_name(tag: str) -> str:
    """An element's name without its ``{namespace}``, lower-cased."""
    return tag.rpartition("}")[2].lower()


def _descendants(element: ET.Element, name: str) -> list[ET.Element]:
    """Every element named ``name`` (any namespace) below ``element``, in document order."""
    return [
        child for child in element.iter() if child is not element and _local_name(child.tag) == name
    ]


def _replicas(
    element: ET.Element, base_url: str, version: str, accepts: Callable[[str], bool]
) -> tuple[str, ...]:
    """The usable replica URLs under ``element``, best first, each once.

    Sorted by ``(rank, document order)``, so equal ranks keep the order the
    author wrote. The :data:`MAX_REPLICAS` bound counts usable URLs only:
    unusable ones cost nothing later.
    """
    ranked: list[tuple[int, int, str]] = []
    is_v3 = version.startswith("3")
    for order, node in enumerate(_descendants(element, "url")):
        candidate = _replica(node, base_url, is_v3, order, accepts)
        if candidate is None:
            continue
        ranked.append(candidate)
        if len(ranked) > MAX_REPLICAS:
            raise MetalinkError(f"Metalink contains more than {MAX_REPLICAS} replica URLs")
    ranked.sort()
    # Do not spend the retry budget twice on a duplicated URL.
    return tuple(dict.fromkeys(url for _, _, url in ranked))


def _replica(
    node: ET.Element, base_url: str, is_v3: bool, order: int, accepts: Callable[[str], bool]
) -> tuple[int, int, str] | None:
    """One usable URL and its version-specific sort key."""
    text = (node.text or "").strip()
    if not text or len(text.encode()) > MAX_URL_SIZE:
        return None
    url = resolve(base_url, text)
    if not accepts(url):
        return None
    # An unranked URL goes last: Metalink 3's lowest preference, and for
    # Metalink 4 a priority beyond RFC 5854's 1-999999 range.
    attribute, default = ("preference", 0) if is_v3 else ("priority", 999_999)
    rank = _integer(node.get(attribute), default)
    # Metalink 3 preference is high-first; Metalink 4 priority is low-first.
    return (-rank if is_v3 else rank, order, url)


def _checksums(element: ET.Element) -> tuple[ChecksumInfo, ...]:
    """The verifiable ``<hash>`` values; the first of each algorithm wins.

    Piece hashes (Metalink's ``<pieces><hash>``) have the right element
    name but cover chunks, not the file; their ``type`` sits on the parent,
    so they have none of their own and are skipped by :func:`_algorithm`.
    """
    found: dict[str, ChecksumInfo] = {}
    for node in _descendants(element, "hash"):
        algorithm = _algorithm(node.get("type") or "")
        # Whitespace inside a value is pretty-printing, not data.
        value = "".join((node.text or "").split())
        if algorithm is None or not _valid_digest(algorithm, value):
            continue
        found.setdefault(algorithm, ChecksumInfo(algorithm, value.lower()))
    return tuple(found[name] for name in sorted(found))


def _algorithm(name: str) -> str | None:
    """Our name for hash ``type`` ``name``, or ``None`` if we cannot compute it."""
    normal = name.strip().lower().replace("-", "").replace("_", "")
    normal = _ALIASES.get(normal, normal)
    return normal if normal in _SUPPORTED else None


def _valid_digest(algorithm: str, value: str) -> bool:
    """Whether ``value`` is hex of exactly ``algorithm``'s digest width.

    The width is taken from the implementation, not a table, so it cannot
    drift from what the copy engine will compute and compare.
    """
    width = len(new_checksum(algorithm).hexdigest())
    return len(value) == width and all(char in _HEX for char in value)


def _size(element: ET.Element) -> int | None:
    """The first ``<size>`` as bytes; ``None`` if absent, negative or not a number."""
    nodes = _descendants(element, "size")
    text = (nodes[0].text or "").strip() if nodes else ""
    return int(text) if text.isdigit() else None


def _integer(value: str | None, default: int) -> int:
    """A rank attribute as an integer; a missing or malformed one is ``default``."""
    try:
        return int(value) if value is not None else default
    except ValueError:
        return default


def resolve(base: str, reference: str) -> str:
    """Resolve ``reference`` against ``base``, whatever the scheme.

    ``urljoin`` leaves a relative reference alone under ``root://`` or
    ``davs://``; this resolves it the RFC 3986 way for any scheme, keeping
    the base's scheme and authority. A client resolves Metalink/HTTP ``Link``
    targets with it too.
    """
    if urllib.parse.urlsplit(reference).scheme or not base:
        return reference
    parsed = urllib.parse.urlsplit(base)
    if reference.startswith("//"):
        return f"{parsed.scheme}:{reference}"
    path = (
        reference
        if reference.startswith("/")
        else posixpath.join(posixpath.dirname(parsed.path), reference)
    )
    path = posixpath.normpath(path)
    # XRootD URLs spell an absolute path with a double slash
    # (``root://host//store/f``); normpath folds it, so it is put back.
    if parsed.path.startswith("//") and not path.startswith("//"):
        path = "/" + path
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
