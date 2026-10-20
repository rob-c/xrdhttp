# Changelog

Notable user-visible changes are recorded here. This project follows
[Semantic Versioning](https://semver.org/).

## [0.4.1] - Unreleased

No changes of its own: released with the 0.4.1 chain (xrdsec, xrdclient and xgfalclient fixes, xrdarc's production fixes), whose packages share one version. Requires xrdcore and xrdsec 0.4.1.

## [0.4.0] - 2026-10-19

The first release: the HTTP protocol pieces xrdclient and xgfalclient each
carried, as one library that knows nothing of either client.

### Added

- The HTTP protocol pieces previously private to xrdclient (`http._engine`,
  `http._wire`, `http._connection`, `http.expect`, `http._ranges`,
  `http._webdav`, `s3.sigv4`, `s3._codec`, `metalink`), as the public
  modules `engine`, `wire`, `connection`, `expect`, `ranges`, `webdav`,
  `s3.sigv4`, `s3.codec` and `metalink`, with no client dependency.
- `xrdhttp.redirects`: the redirect credential policy (`carries_credentials`,
  `relays_transfer_headers`, `without_credentials`) on plain URL strings, and
  `davix_carries_credentials`, gfal2/davix's looser cross-host rule (from
  xgfalclient's `plugins/http/_target._may_forward`).
- `xrdhttp.tape`: the WLCG Tape REST vocabulary shared by both clients, a
  neutral `FileStatus`, and `TapeClient` verbs over a caller-supplied `send`.
- `xrdhttp.tpc`: HTTP-TPC `COPY` header construction, far-side token rules
  and the performance-marker reader, without a request driver.
- `xrdhttp.metalink.ChecksumInfo` re-exports `xrdcore.checksum.ChecksumInfo`,
  so a descriptor's checksums are the same type the clients report.
- `xrdhttp.testing`: one fake HTTP(S) storage element, `StorageServer`, built
  from xrdclient's `testing/http.py` (`FakeDAVServer`) and `testing/s3.py`
  (`FakeS3Server`) and xgfalclient's `testing/webdav.py` + `testing/_webdav/*`
  (`WebDAVServer`), which each client now keeps only as a thin preset. It
  speaks WebDAV (ranges incl. `multipart/byteranges`, RFC 3230 and RFC 9530
  digests, `If-None-Match: *`), HTTP-TPC pull/push with performance markers
  and a pluggable `DelegationService` (gridsite delegation needs X.509, so
  the caller supplies it), WLCG Tape REST, CDMI QoS, macaroon and OAuth
  issuance, S3 (header-signed and pre-signed SigV4 checked independently of
  `s3.sigv4`, ListObjects v1/v2, multipart, copy), GCS V4 signed URLs,
  Swift, Metalink `Link` advertisement, bearer/Basic/certificate
  authorisation, faults and canned per-method `handlers`. Content lives in a
  `MemoryStore` or a `DirectoryStore`; where the two clients' fakes
  disagreed, a switch says which (`style="xrdcl"` or `"davix"`, see
  `STYLES`). It is built on xrdsec's generic test server
  (`xrdsec.testing.https.FakeHTTPSServer`: TLS per connection from the
  caller's `ssl.SSLContext`, client certificate identities, the request log
  and `Fault`s - `Request` and `Fault` are xrdsec's), because a client's
  identity is an X.509 chain and xrdsec's own and xrdarc's fakes share that
  server; so `xrdhttp.testing` needs the new `testing` extra
  (`xrdhttp[testing]` = `xrdsec>=0.4.0,<0.5`, also in `dev`). It is the only
  xrdhttp module that imports xrdsec; `tests/test_package.py` proves no
  runtime module does. The range and WebDAV reply helpers every HTTP fake
  answers with - `ranged_reply`, `propfind_reply`, `multistatus`,
  `dav_entries`, `DAVEntry`, `BOUNDARY` - moved here from
  `xrdsec.testing.https` (they are HTTP); `DAVEntry(length=)` reports a
  collection's `getcontentlength`.
- `xrdhttp.session`: one pooled, thread-safe HTTP/1.1 `Session` over the
  engine, connections, wire, expect and redirect pieces - the machinery
  xrdclient's `http/client.py`, xgfalclient's `plugins/http/_client.py` and
  xrdarc's `transport.py` each carried. Connections are pooled per endpoint
  and TLS context (a context factory, or `Auth.tls` per request); a stale
  pooled connection is replaced once; redirects are followed under a
  `RedirectPolicy` (credential headers same-origin by default, the
  `TransferHeader*` family within the site, `davix_carries_credentials`
  pluggable); a first `401` may be answered once (`reauth`); bodies of
  bytes or `FileBody` (sent with `sendfile`), `Expect: 100-continue` before
  large ones; idempotent requests retried on `429`/`503` (configurable) with
  `Retry-After` or jittered backoff, and on dropped connections when asked
  (`RetryPolicy`); statuses and failures spelt by a client's `Errors`
  subclass (`HTTPStatusError`, `RedirectError`, `SessionClosedError` and
  `xrdcore.errors` by default); streamed `Response` reads straight off the
  socket; `Session.upload` for a body the caller writes (declared length or
  chunked); `abort()` and a `watch` hook for cancellation;
  `UnverifiedTLSWarning` for a connection that verifies nothing. xrdarc's
  transport, xrdclient's `HTTPClient` and xgfalclient's HTTP plug-in are
  built on it, each a policy over one session.
- `xrdhttp.testing.conformance`: the client conformance suites. xrdclient
  and xgfalclient each tested the same behaviour of the shared fake - 77
  behaviours, in 96 xrdclient and 68 xgfalclient test functions - in their
  own words. It is now one set of pytest classes a client subclasses
  (fsspec-style): `NamespaceSuite` (stat, listings, `MKCOL`, `DELETE`,
  `MOVE`, awkward names, hostile multistatus), `ReadSuite` (whole, ranged,
  past the end, range-ignoring servers, resumed after a cut), `UploadSuite`
  (sized, in pieces, empty, `Expect: 100-continue` honoured or ignored,
  refused before the body, redirected before the body), `ChecksumSuite`
  (`Want-Digest` as hex, `Content-MD5`, none offered), `RedirectSuite`,
  `ConnectionSuite` (keep-alive, stale pooled connections, no server,
  timeouts, bearer tokens), `CopySuite` (HTTP-TPC pull and push, markers,
  failures after the `202`, the far side's token), `TapeSuite` (stage, poll,
  recall, release, abort, `archiveinfo`), `TokenSuite` (macaroons) and
  `S3Suite` (signed stat and listings with pages, single and multipart
  uploads and their failures, rename as copy-and-delete, ETag MD5, bad
  signatures). The suites provide the fakes (`server`, `peer`) and the
  client (`client`) as fixtures; a client supplies `make_adapter` (and
  `make_server` for its own preset) and an `Adapter` that performs each
  operation through its own API and reads its errors as a neutral `Kind`.
  Every check passes in both of the fake's styles. The `testing` extra now
  brings `pytest>=8` too.
- `xrdhttp.connection` re-exports the `http.client` names a client still
  has to spell - `BadStatusLine`, `HTTPException`, `HTTPMessage`,
  `HTTPResponse`, `IncompleteRead`, `RemoteDisconnected` - as the stdlib's
  own classes, so the clients' lint can ban `http.client` outright.
- `xrdhttp.testing.byteranges(*parts, size, boundary, part_type, preamble,
  epilogue, closing)`: a hand-made `multipart/byteranges` body of
  `(first byte, payload)` parts - parts never asked for, text around the
  delimiters, a missing close - for tests of a range parser. The fake's
  own `multipart` renderer is built on it (byte-identical answers), and it
  replaces the `_multipart` builders of xrdhttp's `test_ranges.py` and
  xrdclient's `test_http_readv.py`.

### Changed (relative to the xrdclient originals)

- Errors are `xrdcore.errors`' and cancellation `xrdcore.cancel`'s.
- `redirects.resolve_location` resolves on URL strings, keeps the caller's
  scheme for a relative `Location` (`davs://` stays `davs://`, `s3s://` stays
  `s3s://`, as xgfalclient's `_resolve` does, so the next hop keeps its trust
  anchors and signing), and does not carry a user name onto a network-path
  reference (`//other/x`).
- `tpc.add_verification` (and so `copy_headers`) sends
  `RequireChecksumVerification: false` when the caller does not choose, as
  xrdclient's `http/tpc.py` now does and gfal2 always has.
- `TapeClient.discover` returns a `TapeEndpoint` rather than a dict.
- `ranges.boundary` and `ranges.read_multipart` read any `MultipartAnswer`
  (headers, `readline`, `read`): an `http.client.HTTPResponse` or a
  `session.Response`.
- `connection`: the urllib3 connection-pool compatibility is gone - no
  client pools these classes with urllib3 any more (xrdarc's transport was
  the last urllib3 user, and is now `xrdhttp.session`). The constructors no
  longer take urllib3's TLS keywords (`cert_file`, `assert_hostname`, ...)
  or a pool's timeout sentinel, and `HTTPSConnection` takes its context as
  `ssl_context` only (the `context=` spelling is removed).

### Tests

- Cases xgfalclient's suite held for code that now lives here - the
  `request(headers=None)` contract of the connections, and `Expect:
  100-continue`'s LF-terminated and malformed interim answers - moved into
  `tests/test_connection.py` and `tests/test_expect.py`.
- `xrdhttp.testing` is tested on its own (`tests/test_testing_*.py`, every
  line and branch), driven with `http.client` and raw sockets; the cases the
  clients' suites held for their fakes' own corners (xrdclient's
  `tests/test_testing.py` WebDAV section and `tests/test_s3.py` "requests no
  client would send", xgfalclient's `test_server_*corners`) moved here.
- The conformance suites run here against a reference adapter made of this
  library alone (`tests/_reference.py` on `xrdhttp.session`,
  `tests/_reference_s3.py` with `xrdhttp.s3`), in both of the fake's styles
  (`tests/test_conformance.py`), so every check is known to be passable and
  `xrdhttp.testing.conformance` keeps its 100 % here.

### Packaging

- Typed (`py.typed`, checked with `mypy --strict`); Python 3.11 to 3.14 on
  Linux and macOS.
- Runtime dependencies: `xrdcore` only. `botocore` is the optional `s3`
  extra (`xrdhttp[s3]`), imported only by `xrdhttp.s3.sigv4` and
  `xrdhttp.s3.codec`; without it `xrdhttp.s3` refuses to import with a
  `ModuleNotFoundError` naming the extra. xrdclient and xgfalclient depend
  on `xrdhttp[s3]`; xrdarc on plain `xrdhttp`.
- The import-boundary tests (`tests/test_package.py`) start their
  `python -I` children with the installed xrdhttp and xrdcore (from the
  modules' own `__file__`) and the parent's `sys.path`, not a sibling
  `xrdcore/src` checkout, so they also run from a wheel install or a Nix
  build, where every dependency is on `PYTHONPATH`.
- The test suite covers every line and branch, and the package is held to the
  family's take-over scorecard (every measurement better than the median of 39
  widely used Python libraries).
- A security policy ([SECURITY.md](SECURITY.md)) and contributor guide
  ([CONTRIBUTING.md](CONTRIBUTING.md)).
- The chain's tooling moved to the new
  [xrd-devtools](https://github.com/rob-c/xrd-devtools) repository, used from
  a checkout (it is not on PyPI and cannot be a dependency):
  `tests/test_scorecard.py` is now a few lines loading its scorecard plugin
  (found through pytest's `pythonpath`: `../xrd-devtools/src` or CI's
  `.dependencies/xrd-devtools/src`; it skips, saying so, without one), in
  place of the copy that located xrdclient's `tools/scorecard.py` through
  `XRDCLIENT_CHECKOUT`/`SCORECARD_REQUIRED`. `.github/scripts/check_dist.py`,
  identical in the three libraries, is xrd-devtools' `check_dist.py`; ruff,
  mypy and complexipy no longer list `.github/scripts`.
- CI (`.github/workflows/ci.yml`) calls xrd-devtools' reusable workflows -
  `static.yml` (ruff, mypy, complexipy, the scorecard, made required, and
  `xrddevtools conformance`), `tests.yml`, `package.yml` and `chain.yml` (the
  duplicate and conformance gates over all seven repositories) - with the
  candidates from its one candidates action; `publish.yml` checks
  xrd-devtools out to run `check_dist.py`. CI therefore needs
  `rob-c/xrd-devtools` to exist.
- `publish.yml` installs the wheel with its `testing` extra before importing
  every public module: `xrdhttp.testing` is built on xrdsec, so the import
  check failed without it. xrdsec is therefore published before xrdhttp.

### Code health

- No grandfathered code: ruff's full rule set (`SIM` added) with nothing
  ignored, `mypy --strict` over the tests and release scripts as well as
  the package, complexipy at 15 with no snapshot, and every warning an
  error under pytest. Of 26 `type: ignore` and 3 `noqa`, one ignore remains,
  with its reason (`s3.sigv4` signs the query as pairs, which botocore takes
  and botocore-stubs does not declare). botocore is now type-checked against
  `botocore-stubs` (a development dependency) instead of being `Any`, and
  `expect`'s private socket helpers take protocols for what they use.
  A pre-signing request with no URL is refused with `ValueError`.
- The tests' shared helpers moved out of `conftest.py` into
  `tests/_sockets.py`.
- Banned APIs (ruff `TID251`; CONTRIBUTING.md explains the list): no
  third-party HTTP stack, no `gssapi`/pykrb5 (credentials come from the
  caller), no boto3, no bare `ThreadPoolExecutor` (`xrdcore.fanout`), no
  unguarded XML parser (`xrdcore.safexml`: the fake's multipart manifest and
  the reply tests now parse through it, so a manifest with a DOCTYPE names
  no parts), and no client. What xrdhttp owns stays allowed: `http.client`,
  hand-built TLS contexts in its own tests, botocore (`s3` only) and xrdsec
  (`testing` only) - the last two pinned by `tests/test_package.py`.
- Release metadata is xrd-devtools' release gate:
  `tests/test_release_metadata.py` is `release_gate(__file__)` from
  `xrddevtools.pytest_plugin` - one version source (`_version.py`, read by
  hatch), a CHANGELOG led by exactly that version's well-formed section,
  project metadata and README that name this repository, and a release
  workflow built through the shared publish action.
- The publish workflow's build job is xrd-devtools' shared `publish`
  composite action (build, `twine check --strict`, the artifact or
  pre-flight checks, a clean install whose tag, runtime version and dated
  changelog section agree, the artifact upload); only the trusted-publishing
  upload to PyPI stays in this workflow's own job.
- The standard's settings in `pyproject.toml` (ruff rules, the banned-API
  table, mypy's strictness and allowed overrides, complexipy, coverage,
  pytest's warnings filter) and CONTRIBUTING's *The code standard*, *Banned
  APIs* table and *xrd-devtools* sections are managed blocks, written by
  `xrddevtools sync` from the standard kept once in xrd-devtools;
  `xrddevtools conformance` fails a hand edit between the markers. The
  repository's own keys and notes sit beside the blocks.
