# Security

## Reporting a vulnerability

Mail <robert.andrew.currie@gmail.com> with a description and, if you have one,
a reproducer. Please do not open a public issue for anything that could send a
credential somewhere it should not go, or let a server make a client spend
unbounded memory or time. Expect an acknowledgement within a few working days.
A fix is released as a patch version of the latest minor release, and the
clients built on xrdhttp (xrdclient, xgfalclient) are released against it at
the same time.

Supported versions: the latest `0.x` minor release. Until 1.0, fixes are not
back-ported to older minors.

## What this library is trusted with

xrdhttp is the protocol layer under two grid storage clients' HTTP, WebDAV,
S3, Tape REST and third-party-copy support. It does not find, read or hold
credentials of its own: TLS arrives as the `ssl.SSLContext` the caller built
(normally with `xrdsec.tls.client_context()`), and bearer tokens and S3 keys
as headers or arguments the caller passes. What it decides is what a server's
answer may make the client do: which headers follow a redirect, how much of a
response is read, and how a server-written document is parsed. Servers are
assumed to be the hosts that were named, but not to be well behaved.

## What the implementation guarantees

**TLS settings cannot bypass the context.** A connection wraps its socket with
the caller's context and the endpoint's name as `server_hostname`, so SNI is
sent and the context's `check_hostname` verifies the certificate. A connection
pool that asks for a setting outside the context (`cert_file`,
`assert_hostname`, ...) is refused rather than silently ignored.

**Credentials follow a redirect only within one origin.**
`redirects.carries_credentials()` lets `Authorization`, cookies and the other
`CREDENTIAL_HEADERS` follow only to the same scheme, host and port, never from
HTTPS down to HTTP, and to another host only inside a domain the operator
configured as trusted. `davix_carries_credentials()` is gfal2's looser rule
(any host, but still never HTTPS down to HTTP on another host), for the client
that must match gfal2. A third-party copy's `TransferHeader*` headers - the far
endpoint's credential - follow only within the site that sent the redirect.
`without_credentials()` strips what a hop may not carry, and a relative
`Location` keeps the caller's scheme, so `davs://` never quietly becomes
`http://`.

**Bounded work per response.** The redirect loop makes at most `limit + 1`
requests and retries a stale connection once. A `multipart/byteranges` answer
may only deliver the ranges that were asked for, and its boundary lines and
part headers are read under per-line and total limits, so a hostile server can
neither make a vector read buffer a whole file nor hang it with a body that
never draws a boundary. A third-party copy's performance-marker lines are read
at most 64 KiB at a time. A Metalink descriptor is at most 8 MiB, 10,000
replica URLs and 4,096 bytes per URL.

**Server-written XML is parsed safely.** `PROPFIND` multistatus, S3 answers
and Metalink documents go through `xrdcore.safexml`, which refuses any
`<!DOCTYPE` - the only place XML can declare an entity - while the tree is
built, so a billion-laughs document or an external entity can neither exhaust
memory nor read a local file. Tape REST answers are JSON, read with the
standard library.

**Cancellation is honoured before a byte is written.** A request made inside a
cancelled `xrdcore.cancel` scope is refused at the connection.

**Signing is botocore's.** AWS Signature Version 4 headers and pre-signed URLs
use botocore's canonicalisation and signer; xrdhttp only arranges the inputs.
botocore is imported only when `xrdhttp.s3` is.

**A small dependency set and no dynamic execution.** The runtime depends on
`xrdcore` (no dependencies of its own) and `botocore`. Nothing in the package
calls `eval`, `exec`, `pickle` or `subprocess`.

## Limits you should know about

- **Trust is the caller's.** xrdhttp verifies exactly what the context it is
  given verifies. A context built with verification off is used as it is.
- **A `?authz=` token in a redirect's own `Location` is kept.** The redirecting
  server chose to send it; `redirects.query_token()` reads it for the client.
- **A trusted redirect domain trusts everything under it.** Name the narrowest
  domain that covers a site's head and data nodes.
- **Checksums are integrity, not authentication.** A Metalink or `Digest`
  checksum catches corruption in transit and on disk; a server that serves the
  wrong bytes can serve the matching checksum too.
