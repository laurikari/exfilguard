# Design Decisions

This file explains choices that may otherwise look like missing work.

## Canonical request data for policy

ExfilGuard makes policy decisions from a normalized request view and keeps the
original request target for forwarding.

Policy rules should not depend on small syntax differences. ExfilGuard also
should not rewrite upstream-visible bytes in ways that change request meaning.
It rejects ambiguous or conflicting syntax first, then canonicalizes requests
that already have one clear meaning.

For policy matching, percent-encoded RFC-unreserved characters are decoded and
the hex digits of retained escapes are uppercased. Dot-segment processing runs
on that canonical policy path. IP-literal hosts in rules and requests are
parsed and serialized to one numeric spelling before comparison. The original
request target remains unchanged for forwarding, logging, cache keys, and
signature-sensitive traffic.

Policy path patterns must already be canonical: configurations containing dot
segments or repeated slash separators are rejected. Rewriting a pattern could
silently change operator intent, especially when the removed segment contains
a wildcard. Patterns accept the same literal RFC path characters and retained
uppercase percent escapes as the canonical request view. Because `*` is the
path wildcard, `\*` is the policy-only spelling for a literal raw asterisk;
request paths themselves reject backslashes. This keeps raw `*`, encoded `%2A`,
and literal `%2A` text exactly distinguishable in policy.

## Reject ambiguous syntax

ExfilGuard rejects malformed or ambiguous HTTP syntax on both sides of the
proxy.

That includes cases such as:

- both `Content-Length` and `Transfer-Encoding`
- malformed or ambiguously terminated chunk framing
- malformed CONNECT authorities
- encoded path separators
- encoded dot-segment tricks

Upstream HTTP/1 status lines must use exact CRLF framing and the standard
`HTTP/1.1 SP 3DIGIT SP [reason-phrase]` grammar. Valid reason-phrase bytes are
preserved exactly; nonstandard separators and control bytes are rejected before
the response is committed downstream.

This is a security choice. ExfilGuard should not quietly “fix” a request into
a different request or turn a malformed response into a different response.

## Close after a committed response fails

Once ExfilGuard has sent a final HTTP response head or `200 Connection
Established`, a later forwarding failure closes the downstream connection and
is recorded in logs and metrics. It does not append another HTTP error
response.

After commitment, downstream bytes already have a defined protocol meaning;
inside a CONNECT tunnel they may be arbitrary TLS or application data. A
second plaintext status line would corrupt that stream and cannot reliably
communicate the failure. Errors detected before commitment can still receive
the appropriate HTTP error response.

## Response-head limits include informational responses

For upstream HTTP/1, `response_header_timeout` is one absolute deadline from
the end of request transmission through the final response head.
`max_response_header_size` is one aggregate wire-byte budget across every
informational response and the final response head. Informational responses do
not receive fresh limits.

This bounds both slow header drips and fast informational-response floods using
the existing operator controls. A separate informational-response count would
add an arbitrary protocol limit without improving the byte or time bound.

## Cache only bodyless requests

Shared-cache lookup and storage are limited to requests proven to have no body.
Body-bearing `GET` and `HEAD` requests are forwarded normally without using the
cache. Cache keys do not include bodies, and serving a hit before consuming a
body would leave request bytes in the downstream connection. Chunked requests
also bypass the cache because their emptiness is unknown until framing is
consumed.

Fields named by `Vary` are matched using their complete ordered list of parsed
field-value bytes. ExfilGuard does not generically comma-combine repeated fields
because whether combination is valid depends on the field grammar. This
conservative comparison can produce a cache miss for semantically equivalent
spellings, but it cannot reuse a representation selected using a missing,
extra, or reordered value. Cache layout changes invalidate entries that lack
this complete key.

## Retry only replayable idempotent requests

When reuse of a pooled HTTP/1 upstream connection fails with an error that
indicates a stale socket, ExfilGuard retries once on a fresh connection only if
the request is bodyless and uses a standard idempotent method: `GET`, `HEAD`,
`OPTIONS`, `TRACE`, `PUT`, or `DELETE`.

The bodyless restriction makes the request locally replayable without buffering.
The method restriction follows HTTP idempotency semantics when delivery to the
origin is ambiguous. Non-idempotent methods and extension methods whose
semantics ExfilGuard cannot establish are not retried automatically.

## TLS leaf certificates are cached only in memory

ExfilGuard does not persist generated TLS leaf certificates or their private
keys. Leaf minting is cheap enough that reminting after a restart is preferable
to maintaining an on-disk private-key cache with its own capacity, expiry, and
filesystem-safety lifecycle.

The in-memory cache is capacity-bounded. Concurrent requests for the same leaf
are single-flighted, and globally limited mint jobs run on blocking workers so
certificate generation cannot stall asynchronous I/O workers.

## CA material is controlled by the process owner

ExfilGuard loads CA material only from a real owner-controlled directory. The
directory and all CA files must belong to the process UID; private keys must be
regular, non-symlink files with owner-only modes. Read-only owner modes are
supported, but shared ownership and permissive modes are rejected at startup
instead of being repaired automatically.

This intentionally excludes shared-volume and sidecar ownership models. A CA
signing key can impersonate every inspected origin, so deployment convenience
does not justify accepting material another local principal can replace or
read.

## CA lifecycle is selected explicitly

ExfilGuard has three CA sources with deliberately different ownership models.
`builtin` creates a long-lived root and intermediate once, persists only the
certificates and intermediate key through a recoverable filesystem transaction,
and does not renew them. `files` loads the same three artifacts but never creates
or changes them. `vault` generates each intermediate key in memory, has a
selected Vault PKI issuer sign it, and renews the complete issuer generation
before expiry.

The sources never silently fall back to one another. In particular, Vault
unavailability after a restart prevents inspected HTTPS from starting because
the previous in-memory issuer key is gone. During a running process, a failed
renewal retains the current valid generation; after it expires, inspection
fails closed instead of becoming a CONNECT tunnel. Replacing an issuer also
replaces its leaf cache atomically so new handshakes cannot receive a leaf from
the previous generation.

CA hierarchies must support arbitrary leaf names selected by policy. ExfilGuard
therefore rejects name constraints and any critical extension other than the
`basicConstraints` and `keyUsage` semantics it explicitly enforces, rather than
accepting an issuer whose additional constraints are ignored during leaf
minting.

ExfilGuard never loads or stores a root private key. File mode makes external
ownership explicit, while Vault mode keeps CA and leaf private keys off disk.
This separation is preferable to accepting partially managed directories or
guessing an operator's intended lifecycle from whichever files happen to be
present.

## HTTPS inspect and tunnel modes

In `inspect` mode, only a matching `ALLOW` rule may authorize the CONNECT host
and port preflight that lets ExfilGuard start a bumped TLS session. A matching
`DENY` rule does not authorize transport setup by itself, so deny-only
authorities fail at the outer CONNECT without opening an upstream connection.
Preflight does not allow arbitrary inner methods or paths. ExfilGuard checks
those only after decryption.

In `tunnel` mode, ExfilGuard may open a CONNECT tunnel and leave the payload
alone.

HTTP/1 clients may pipeline tunnel bytes immediately after the CONNECT header
section. The HTTP parser can prefetch some of those bytes while finding the
header boundary, so ExfilGuard preserves that bounded prefix across the mode
switch. An allowed tunnel forwards it before later socket bytes; an inspected
connection feeds it into the TLS handshake. A denied or failed CONNECT drops
the prefix and never forwards it.

This split makes the operator’s intent clear. It also keeps logs and metrics
tied to the decision that actually mattered.

## Ordered policy evaluation

ExfilGuard evaluates policies in order. Inside each policy, it evaluates rules
in order. The first match wins. If nothing matches, ExfilGuard denies the
request.

This keeps policy behavior readable. Operators can put specific rules before
general rules and know what will happen.

## Client identity from source IP and CIDR

ExfilGuard identifies a client from the downstream source address. It uses
exact IP matches, CIDR ranges, and one fallback client.

IPv4-mapped IPv6 peer addresses are treated as their underlying IPv4 address.
Configuration must therefore use the ordinary IPv4 address or CIDR; mapped-only
selectors are rejected rather than accepted as rules that can never match.

The fallback client has no address selector and is considered only after exact
IP and CIDR matching finds nothing. Configurations that set `ip` or `cidr` on
the fallback are rejected.

By default, it trusts the immediate peer address. If you enable PROXY protocol
and trust the sender, it may use the address from that header instead. It does
not use `X-Forwarded-For` or similar HTTP headers for client identity.

Allowlisted PROXY peers are trusted infrastructure and must send their complete
header promptly as the first bytes on the backend connection. A timeout and a
separate pending-connection limit bound resource retention if that
infrastructure stalls or malfunctions before ExfilGuard learns the logical
client identity.

Other auth or identity methods may come later.

## Block non-public upstreams by default

By default, ExfilGuard blocks upstream addresses that are not globally routable
on the public Internet.

This reduces SSRF risk. If a client is compromised or misconfigured,
ExfilGuard should not let it reach internal or special-purpose network space
unless an operator makes an explicit exception.

## One policy path for all front-ends

HTTP/1, HTTP/2, and CONNECT all go through the same policy code.

This keeps policy meaning consistent across front-ends. A request should not
get a different result just because it came in through a different HTTP stack.

## Explicit proxy traffic

Clients are expected to know they are talking to a proxy.

This keeps request meaning, client intent, and logging straightforward.
Transparent proxying may come later.

## Availability isolation combines client budgets with deployment controls

ExfilGuard assumes its proxy and metrics listeners are reachable only by the
authorized clients and monitoring systems an operator intends to serve. It is
not a complete denial-of-service isolation or multi-tenant fairness boundary,
but an authorized or compromised client must not retain unbounded downstream
connections.

Each configured client therefore has a default budget of 1,024 simultaneous
downstream TCP connections, with an explicit per-client override. The count
includes ordinary HTTP keep-alive connections, raw CONNECT tunnels, and
inspected CONNECT sessions. A CIDR identity deliberately shares one budget
across all matching machines. Admission uses the client identity after trusted
PROXY protocol processing; excess new connections are closed without evicting
established ones. Before that identity is available, connections from
allowlisted PROXY peers use a separate, configurable pending budget; the permit
is released as soon as ordinary per-client admission succeeds.

There is no separate global lifetime, per-IP, or per-rule ceiling. Client
limits remain stable across policy reloads and are observable through bounded
per-client metrics. Deployments that need broader availability isolation should
still use firewall, load-balancer, or equivalent network-edge controls. A
future adaptive overload controller would require real resource-pressure
signals and hysteresis; it is separate from deterministic client budgets.

## Request body limits are opt-in

By default, ExfilGuard does not cap inspected request body size.

It streams request bodies incrementally and relies on backpressure plus timeout
controls for transport safety. Body size alone does not make a request invalid
for policy purposes. Operators can still opt into a global request-body cap
with `max_request_body_size` when that tradeoff fits their environment.

When that cap is enabled, a request whose declared `Content-Length` already
exceeds it is rejected before ExfilGuard opens an upstream request. Bodies
without a declared length are still streamed and enforced incrementally.

## Real trust store for outbound TLS

If the system trust store is empty, startup fails.

That rule is strict on purpose. If a host has no trust anchors, the fix is to
install them.

## Debian package provisioning is root-aware and declarative

The Debian package provisions the `exfilguard` system account with
`systemd-sysusers` and its owned directories with `systemd-tmpfiles`. Both tools
operate against `DPKG_ROOT` when dpkg explicitly runs maintainer scripts without
a chroot, so image construction cannot mutate the build host.

Purge removes ExfilGuard's state directory but retains the system account. This
avoids reassigning its numeric UID to unrelated files that might remain outside
the package-owned state tree.

## Caching is opt-in

Response caching works only when global cache storage is configured and the
allow rule enables caching.

ExfilGuard does not cache allowed traffic by default. That keeps response
storage and freshness changes under explicit operator control.

## Response cache entries are protocol-neutral

Inspected HTTP/1.1 and HTTP/2 traffic uses one shared response cache. Entries
store canonical response headers and decoded payload bytes, not HTTP/1 chunk
framing or HTTP/2 frames. A hit is framed for the downstream protocol.

This keeps cache policy independent of ALPN and allows an entry populated over
one HTTP version to serve the other. Responses with trailers are forwarded but
not stored, and HTTP/1 responses with transfer-coding chains other than a sole
`chunked` coding are not representable and therefore skip storage.

## Cache disk limits do not throttle forwarding

`cache_total_capacity` bounds completed response bodies, while all in-progress
cache fills share one additional `cache_max_entry_size` staging allowance.
These are advisory cache-storage bounds rather than a filesystem quota; normal
metadata and filesystem overhead still require headroom.

When the staging allowance is exhausted, ExfilGuard abandons only the cache
copy and continues forwarding the response. It does not slow or reject client
traffic to protect cache population. HTTP/2 cache file operations on the
response path are likewise bounded by the response-body idle timeout; a storage
error or timeout abandons caching without failing the forwarded response.
Same-key fills are not coalesced: that is an upstream-load optimization with
response-variant complexity, not necessary for bounding temporary disk use.

## `SIGHUP` reloads policy data only

`SIGHUP` reloads clients and policies. It does not reload listener settings,
TLS material, cache settings, metrics settings, or timeout settings.

That keeps reload simple. Policy data changes decisions. The other settings
change long-lived runtime state. Restart handles those cases more clearly than
live reload does.

The configured client and policy files are one operator-managed generation.
Deployment tooling must finish replacing the complete generation before it
sends `SIGHUP`, and must leave those files unchanged while ExfilGuard reads
them. ExfilGuard does not attempt to infer filesystem transactions, coordinate
independent file updates, or defend against signals sent during an incomplete
deployment.

Each completed reload is still validated as a whole and published atomically
in memory. A failed reload leaves the previous snapshot active. Filesystem I/O,
TOML parsing, validation, and policy compilation run on Tokio's blocking pool
so a legitimate reload does not stall proxy I/O or timers.

## One semantic config validator

The loader reads files, parses TOML, and builds config structs. One validator
decides whether the config is valid.

This keeps the rules the same across startup, reloads, and any code that builds
config in memory. The validator runs on the full in-memory config.

## `Settings` stays close to `exfilguard.toml`

`Settings` is a plain Rust model of `exfilguard.toml`.

This keeps tests simple. Test code can build settings directly without builders
or helper layers. The config is still checked strictly. Deserialization checks
basic structure and types. Validation checks cross-field rules. Startup checks
settings again before we start serving traffic.

Startup layers the main file, lexically ordered `config.d/*.toml` fragments,
and environment overrides in that order. Fragments are partial global settings;
all relative paths retain the main file's directory as their base. Global
settings remain restart-only, while SIGHUP reload stays limited to client and
policy data.

## Client limits use connection-time accounting

Per-client `max_connections` is an operational resource guard, not a strict
tenant quota. A connection acquires its permit using the client identity
resolved when it is accepted, and that permit is not transferred if a later
reload maps the peer address to another client. New connections use the new
mapping and limits immediately.

Requests on established HTTP and inspected HTTPS connections still use the
latest policy snapshot, including any new client mapping. Reconciling their
connection permits retroactively would add disruptive cross-generation
accounting for an administrator-controlled transition without improving the
normal steady-state resource bound. Established opaque CONNECT tunnels retain
their setup-time decision until they close or reach their configured lifetime.

## Some protocol features stay out of scope

ExfilGuard does not currently support some protocol features, including
HTTP/1.0 and upgrade-style flows such as WebSocket over HTTP/1.1.

We leave them out because that keeps the code easier to reason about.

Inspected live forwarding also preserves the HTTP version across the client
and upstream legs instead of translating between HTTP/1.1 and HTTP/2. The
upstream ALPN preflight prevents ExfilGuard from advertising H2 unless the
origin selected H2. Each live request uses the downstream-selected version
upstream and fails rather than translating if that version is unavailable.
This limits semantic changes and protocol-conversion attack surface. The opt-in
response cache remains protocol-neutral because a cache hit has no live
upstream leg to translate.

## HTTP/2 uses request-idle connection timeouts

The downstream HTTP/2 connection preface must arrive within
`request_header_timeout`. After setup, `client_keepalive_idle_timeout` applies
only while there are no active request streams. A client must produce its next
complete request within that window; control traffic such as PING does not
keep a request-idle connection alive. Active streams continue to use their
phase-specific body, response, and optional total-request timeouts.

The `h2` library does not expose when an individual HEADERS/CONTINUATION block
starts. ExfilGuard therefore bounds an incomplete header block on an otherwise
idle connection with the connection-idle timeout instead of maintaining a
second partial HTTP/2 frame parser solely to apply a shorter header deadline.
This keeps setup and idle retention bounded without imposing a lifetime on
legitimate active or multiplexed sessions.

## HTTP/2 stream admission follows the origin's limit

Each upstream HTTP/2 connection keeps one authoritative request sender.
ExfilGuard waits for that sender to become ready and opens the stream while
holding the same admission lock, so concurrent downstream requests cannot
bypass the origin's advertised `MAX_CONCURRENT_STREAMS` state by using cloned
senders. Only readiness and stream creation are serialized; request bodies and
responses remain multiplexed independently after their streams are open.

Waiting for upstream stream capacity is part of the optional end-to-end
`request_total_timeout`. Without that timeout, downstream HTTP/2 stream
admission still bounds the number of waiting requests on the connection.

## HTTP/2 request and response bodies remain full duplex

After opening an upstream HTTP/2 stream, ExfilGuard polls request upload and
the origin response concurrently. An origin may send a final response before
the request body is complete, so ExfilGuard forwards that response immediately
and continues driving both directions while they remain active. If the
response completes first, the unfinished upload is canceled on that stream;
other streams and the shared HTTP/2 connection remain usable.

The response-header phase timeout starts after request upload completes, as it
does for ordinary request/response exchanges, but an early response is still
observed during upload. The optional total-request deadline continues to cover
both directions throughout. A standards-defined `RST_STREAM(NO_ERROR)` after a
complete early response terminates only the unused request side and does not
discard the response.

## The total request timeout is an end-to-end inner-request budget

When enabled, `request_total_timeout` starts after ExfilGuard accepts a complete
inner HTTP request head. One absolute deadline covers policy and cache work,
upstream resolution and connection setup, retries, request upload, and complete
response delivery. Phase-specific timeouts remain nested within that budget.

If the deadline expires before a final response starts, ExfilGuard returns a
504. Once a final response has started, it closes or resets the request rather
than writing a second response. Outer CONNECT setup and tunnel lifetime have
separate controls, and cleanup after response delivery does not consume the
request budget.

## Upstream TCP connection setup has one multi-address budget

`upstream_connect_timeout` bounds one complete TCP connection operation across
all resolved addresses, rather than granting a fresh timeout to each address.
ExfilGuard preserves resolver preference within each address family, alternates
IPv6 and IPv4 candidates, and starts attempts 250 milliseconds apart. The first
success wins and cancels the remaining attempts.

There is no fixed address-count cutoff. The total deadline and stagger bound the
work naturally; candidates whose turn falls beyond the deadline remain
unattempted. DNS resolution and TLS handshakes retain their own phase-specific
timeouts.

## Raw CONNECT tunnel idleness is bidirectional

A raw CONNECT tunnel is idle only when no bytes have been successfully relayed
in either direction for `connect_tunnel_idle_timeout`. Continuous upload or
download traffic therefore keeps the tunnel active even when the reverse
direction is silent. Successful half-close propagation refreshes the shared
activity deadline so the surviving direction receives a full idle interval.

Individual tunnel writes remain bounded by the same timeout, preventing a peer
that stops reading from blocking one relay half indefinitely. The optional
`connect_tunnel_max_lifetime` remains an independent absolute lifetime limit,
including for continuously active tunnels.
