# Design Decisions

This file explains choices that may otherwise look like missing work.

## Canonical request data for policy

ExfilGuard makes policy decisions from a normalized request view and keeps the
original request target for forwarding.

Policy rules should not depend on small syntax differences. ExfilGuard also
should not rewrite upstream-visible bytes in ways that change request meaning.
It rejects ambiguous or conflicting syntax first, then canonicalizes requests
that already have one clear meaning.

## Reject ambiguous syntax

ExfilGuard rejects malformed or ambiguous request syntax.

That includes cases such as:

- both `Content-Length` and `Transfer-Encoding`
- malformed CONNECT authorities
- encoded path separators
- encoded dot-segment tricks

This is a security choice. ExfilGuard should not quietly “fix” a request into
a different request.

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

## Real trust store for outbound TLS

If the system trust store is empty, startup fails.

That rule is strict on purpose. If a host has no trust anchors, the fix is to
install them.

## Caching is opt-in

Response caching works only when global cache storage is configured and the
allow rule enables caching.

ExfilGuard does not cache allowed traffic by default. That keeps response
storage and freshness changes under explicit operator control.

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

## Some protocol features stay out of scope

ExfilGuard does not currently support some protocol features, including
HTTP/1.0 and upgrade-style flows such as WebSocket over HTTP/1.1.

We leave them out because that keeps the code easier to reason about.
