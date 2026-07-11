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
a wildcard.

## Reject ambiguous syntax

ExfilGuard rejects malformed or ambiguous request syntax.

That includes cases such as:

- both `Content-Length` and `Transfer-Encoding`
- malformed or ambiguously terminated chunk framing
- malformed CONNECT authorities
- encoded path separators
- encoded dot-segment tricks

This is a security choice. ExfilGuard should not quietly “fix” a request into
a different request.

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
certificates and intermediate key, and does not renew them. `files` loads the
same three artifacts but never creates or changes them. `vault` generates each
intermediate key in memory, has a selected Vault PKI issuer sign it, and renews
the complete issuer generation before expiry.

The sources never silently fall back to one another. In particular, Vault
unavailability after a restart prevents inspected HTTPS from starting because
the previous in-memory issuer key is gone. During a running process, a failed
renewal retains the current valid generation; after it expires, inspection
fails closed instead of becoming a CONNECT tunnel. Replacing an issuer also
replaces its leaf cache atomically so new handshakes cannot receive a leaf from
the previous generation.

ExfilGuard never loads or stores a root private key. File mode makes external
ownership explicit, while Vault mode keeps CA and leaf private keys off disk.
This separation is preferable to accepting partially managed directories or
guessing an operator's intended lifecycle from whichever files happen to be
present.

## HTTPS inspect and tunnel modes

In `inspect` mode, ExfilGuard may do the CONNECT host and port preflight that
lets it start a bumped TLS session. That does not allow arbitrary inner
methods or paths. It checks those only after decryption.

In `tunnel` mode, ExfilGuard may open a CONNECT tunnel and leave the payload
alone.

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

## Availability isolation belongs at the deployment boundary

ExfilGuard assumes its proxy and metrics listeners are reachable only by the
authorized clients and monitoring systems an operator intends to serve. It
enforces egress policy, but it is not a denial-of-service isolation or
multi-tenant fairness boundary.

The process therefore does not impose a default global or per-IP connection
ceiling. Connection cost varies substantially between idle HTTP, TLS
handshakes, multiplexed HTTP/2, and long-lived tunnels, while node capacity
varies by orders of magnitude. A generic ceiling can strand most of a capable
node and indiscriminately reject healthy clients without identifying the
source of pressure.

Deployments that need availability isolation should restrict listener access
and apply coarse connection or rate controls at the firewall, load balancer,
or equivalent network edge. ExfilGuard's client metrics and policy reload help
identify and deny abusive traffic after attribution. A future in-process
overload controller would need real resource-pressure signals, client-aware
accounting, and hysteresis; it is a separate feature rather than a fixed
connection-count safeguard.

## Request body limits are opt-in

By default, ExfilGuard does not cap inspected request body size.

It streams request bodies incrementally and relies on backpressure plus timeout
controls for transport safety. Body size alone does not make a request invalid
for policy purposes. Operators can still opt into a global request-body cap
with `max_request_body_size` when that tradeoff fits their environment.

## Real trust store for outbound TLS

If the system trust store is empty, startup fails.

That rule is strict on purpose. If a host has no trust anchors, the fix is to
install them.

## Caching is opt-in

Response caching works only when global cache storage is configured and the
allow rule enables caching.

ExfilGuard does not cache allowed traffic by default. That keeps response
storage and freshness changes under explicit operator control.

## Cache disk limits do not throttle forwarding

`cache_total_capacity` bounds completed response bodies, while all in-progress
cache fills share one additional `cache_max_entry_size` staging allowance.
These are advisory cache-storage bounds rather than a filesystem quota; normal
metadata and filesystem overhead still require headroom.

When the staging allowance is exhausted, ExfilGuard abandons only the cache
copy and continues forwarding the response. It does not slow or reject client
traffic to protect cache population. Same-key fills are not coalesced: that is
an upstream-load optimization with response-variant complexity, not necessary
for bounding temporary disk use.

## `SIGHUP` reloads policy data only

`SIGHUP` reloads clients and policies. It does not reload listener settings,
TLS material, cache settings, metrics settings, or timeout settings.

That keeps reload simple. Policy data changes decisions. The other settings
change long-lived runtime state. Restart handles those cases more clearly than
live reload does.

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

## Some protocol features stay out of scope

ExfilGuard does not currently support some protocol features, including
HTTP/1.0 and upgrade-style flows such as WebSocket over HTTP/1.1.

We leave them out because that keeps the code easier to reason about.

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
