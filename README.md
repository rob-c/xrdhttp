# xrdhttp

The HTTP pieces every grid storage client shares. xrdclient's `HTTPClient`
and xgfalclient's HTTP plug-in each keep their own facade - URL type,
errors, configuration, credentials - and sit on these protocol pieces, which
take plain strings, callbacks and an `ssl.SSLContext` the caller built, and
know nothing of either client.

| Module | What it is |
|---|---|
| `xrdhttp.session` | One pooled, thread-safe HTTP/1.1 session: connections per endpoint and TLS context, the stale-connection retry, redirects under a pluggable credential policy, `Expect: 100-continue`, idempotent retries honouring `Retry-After`, statuses and failures spelt by the client's `Errors`, TLS from the caller's context factory, streamed uploads. |
| `xrdhttp.engine` | The request lifecycle: one retry on a stale pooled connection, the redirect loop (303 becomes a bodiless `GET`, 307/308 replay). |
| `xrdhttp.connection` | `http.client` connections with the streaming contract: every connect failure an `OSError`, TLS only through the caller's `ssl_context`, a liveness poll for pooling; honour `xrdcore.cancel` scopes. Re-exports the `http.client` types a client names (`IncompleteRead`, `HTTPMessage`, `HTTPResponse`, ...). |
| `xrdhttp.wire` | Moving body bytes: `DirectReader` (socket reads below `http.client`), `send_file` (`sendfile` or large TLS writes), `IdlePool`. |
| `xrdhttp.expect` | `Expect: 100-continue` before a large upload, and the early answer when a head node redirects first. |
| `xrdhttp.redirects` | Which credentials may follow a redirect (same origin, or gfal2/davix's cross-host rule; `TransferHeader*` within the site), and how the next hop is spelt. |
| `xrdhttp.ranges` | Several byte ranges in one `GET`: spans, `Range` headers, bounded `multipart/byteranges` reading. |
| `xrdhttp.webdav` | `PROPFIND` multistatus into a `Resource`, dates, `Digest` header values as hex. |
| `xrdhttp.tape` | WLCG Tape REST API: discovery-document vocabulary, request bodies, answer reading into `FileStatus`, and `TapeClient` verbs over a caller's `send`. |
| `xrdhttp.tpc` | WLCG HTTP third-party copy: `COPY` headers, the far side's token rules, the performance-marker stream. |
| `xrdhttp.metalink` | Metalink 3/4 descriptors: bounded, DTD-free, ranked replicas and verifiable checksums, under a client's `MetalinkPolicy`. |
| `xrdhttp.s3.sigv4` | AWS Signature Version 4 - headers and pre-signed URLs - over botocore's canonicalisation. |
| `xrdhttp.s3.codec` | S3's XML answers decoded with botocore's model, after `xrdcore.safexml` has parsed them. |
| `xrdhttp.testing` | Test support: `StorageServer`, a fake HTTP(S) storage element in the test process - WebDAV, HTTP-TPC with markers, WLCG Tape REST, CDMI, macaroon/OAuth issuance, S3 (SigV4, multipart), GCS signed URLs, Swift, Metalink `Link`s, faults - over a `MemoryStore` or `DirectoryStore`, with XrdCl- and davix-style switches (`STYLES`). Both clients' test fakes are presets of it. The reply helpers any fake answers with (`ranged_reply`, `propfind_reply`) and `byteranges`, a hand-made `multipart/byteranges` body for a range parser's tests. |
| `xrdhttp.testing.conformance` | The client conformance suites: pytest classes (`NamespaceSuite`, `ReadSuite`, `UploadSuite`, `ChecksumSuite`, `RedirectSuite`, `ConnectionSuite`, `CopySuite`, `TapeSuite`, `TokenSuite`, `S3Suite`) a client subclasses, supplying an `Adapter` that performs each operation through its own API and reads its errors as a neutral `Kind`. Both clients run them; here they run against a reference adapter on `xrdhttp.session`. |

Errors are `xrdcore.errors`' (`ProtocolError`, `TransientError`,
`MetalinkError`), cancellation is `xrdcore.cancel`'s, and XML goes through
`xrdcore.safexml`. Nothing here imports a client package, and no runtime
module imports xrdsec; TLS credentials reach a connection as the
`ssl.SSLContext` the caller hands in. The one exception is the test support,
`xrdhttp.testing`: its fake storage element is built on xrdsec's generic test
server (TLS per connection, client certificate identities, the request log,
faults), because a client's identity is an X.509 chain and every other fake
in the family shares that server - so it is the `testing` extra
(`pip install 'xrdhttp[testing]'`, which brings xrdsec, and pytest for the
conformance suites).

A client of a storage element runs `xrdhttp.testing.conformance` to prove it
behaves as every other one does against that fake: subclass a suite in a
test module, supply an adapter, and the suite's fixtures provide the servers.

```python
from xrdhttp.testing.conformance import Adapter, NamespaceSuite, Stat

class Mine(Adapter):
    def stat(self, url):
        info = my_client.stat(url)
        return Stat(info.size, info.is_dir, info.mtime)

class TestNamespace(NamespaceSuite):
    def make_adapter(self, server):
        return Mine()
```

`import xrdhttp` imports none of its modules, and `botocore` is imported
only when `xrdhttp.s3.sigv4` or `xrdhttp.s3.codec` is. botocore is the
optional `s3` extra (`pip install 'xrdhttp[s3]'`): without it every module
but `xrdhttp.s3` works, and `xrdhttp.s3` refuses to import with a message
naming the extra.

## The session

A client builds one `Session` with its policy and shares it between threads:

```python
from xrdhttp.session import Auth, Errors, Policy, RetryPolicy, Session

class MyErrors(Errors):              # the client's own exceptions
    def status(self, answer):
        return FileNotFoundError(answer.url) if answer.status == 404 else super().status(answer)

session = Session(
    tls=lambda url: context,         # an ssl.SSLContext the client built (xrdsec builds one)
    policy=Policy(headers={"User-Agent": "mytool/1.0"},
                  retry=RetryPolicy(retries=3, transport=True)),
    errors=MyErrors(),
)
with session.request("GET", "https://se.example.org/data/f", expect=(200,),
                     auth=Auth(headers={"Authorization": "Bearer ..."})) as response:
    data = response.body()
```

Every answer must be read or closed: only one read to its end gives its
connection back to the pool. Credential headers follow a redirect only where
`Policy.redirects` lets them (the same origin by default; gfal2's looser
rule is `xrdhttp.redirects.davix_carries_credentials`). `Session.upload`
streams a body the caller writes, after `Expect: 100-continue`.

## Installation

```sh
pip install xrdhttp          # everything but S3
pip install 'xrdhttp[s3]'    # with botocore, for xrdhttp.s3
```

Python 3.11 to 3.14, pure Python; the package is typed (`py.typed`).

## Development

Until xrdcore is published, the suite runs against the sibling checkout,
with the shared virtual environment's interpreter and nothing installed:

```sh
cd xrdhttp
../.venv/bin/python -m pytest -q -p no:cacheprovider -n auto  # pythonpath: ., src, ../xrdcore/src
../.venv/bin/ruff check src tests --no-cache
../.venv/bin/ruff format --check src tests --no-cache
../.venv/bin/mypy --no-incremental --cache-dir=/dev/null    # src and tests; mypy_path: src:../xrdcore/src
../.venv/bin/complexipy                                     # no function above 15, no snapshot
```

The tests speak to in-process scripted socket servers and canned
responses; the TLS cases make a throwaway certificate with `cryptography`
(a development dependency only). With `--cov` the suite must cover every
line and branch.

See [CONTRIBUTING.md](https://github.com/rob-c/xrdhttp/blob/main/CONTRIBUTING.md)
for a standalone setup and what a change needs, and
[SECURITY.md](https://github.com/rob-c/xrdhttp/blob/main/SECURITY.md) for what
the library guarantees about redirects, bounds and parsing, and how to report
a vulnerability. Changes are in
[CHANGELOG.md](https://github.com/rob-c/xrdhttp/blob/main/CHANGELOG.md).

## License

LGPL-3.0-or-later; see `LICENSE` and `COPYING`.
