# Configuration Reference

These are the global settings in `exfilguard.toml` and optional
`config.d/*.toml` fragments. ExfilGuard reads them at startup.

---

## Core Settings

These settings are required.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `listen` | String | Yes | Listen address and port (e.g., `"127.0.0.1:3128"`) |
| `proxy_protocol` | String | `"off"` | PROXY protocol mode: `"off"`, `"optional"`, or `"required"` |
| `proxy_protocol_allowed_cidrs` | Array | None | CIDR allowlist for peers allowed to send PROXY headers (required when `proxy_protocol` is `"optional"` or `"required"`) |
| `ca` | Table | Yes | Explicit TLS interception CA source: `builtin`, `files`, or `vault` |
| `clients` | Path | Yes | Path to clients configuration file |
| `policies` | Path | Yes | Path to policies configuration file |
| `clients_dir` | Path | No | Directory containing additional client config files (*.toml) |
| `policies_dir` | Path | No | Directory containing additional policy config files (*.toml) |

!!! note
    Relative paths are resolved from the directory containing the main config file.

!!! note
    Use ExfilGuard as an explicit proxy. Clients should know they are talking
    to one.

!!! note
    When `proxy_protocol` is `"optional"` or `"required"`, ExfilGuard
    auto-detects PROXY protocol v1 or v2 headers for peers in
    `proxy_protocol_allowed_cidrs`.

    In `"optional"` mode, peers outside that allowlist are treated as normal
    client connections.

    In `"required"` mode, peers outside that allowlist are rejected before
    HTTP parsing, and allowlisted peers must send a valid PROXY header.

!!! note
    Set `proxy_protocol_allowed_cidrs` when PROXY protocol is enabled.

!!! note
    ExfilGuard reads `exfilguard.toml` and `config.d/*.toml` only at startup.
    `SIGHUP` reloads only the client and policy data read from the configured `clients`,
    `clients_dir`, `policies`, and `policies_dir` paths. If you change fields
    in `exfilguard.toml` itself, including `listen`, metrics, cache, TLS,
    logging, and timeout settings, restart the server.

---

## Global Configuration Fragments

ExfilGuard reads regular `*.toml` files from a `config.d` directory beside the
selected main configuration file. Fragments load in lexicographic filename
order after the main file and before `EXFILGUARD__*` environment overrides.
Later values replace earlier values, and fragments may contain only the fields
they override.

For the default `/etc/exfilguard/exfilguard.toml`, a long-polling override could
be written as `/etc/exfilguard/config.d/50-long-polls.toml`:

```toml
response_header_timeout = 90
```

All relative paths, including paths set by fragments, are resolved from the
directory containing the main configuration file. Changing a fragment requires
restarting ExfilGuard.

---

## TLS / Certificate Settings

These settings control TLS interception and leaf certificate generation.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `leaf_ttl` | u64 | 86400 | TLS certificate leaf TTL in seconds (must be > 0) |
| `leaf_cache_capacity` | usize | 4096 | Maximum number of generated TLS leaves retained in memory (must be > 0) |
| `leaf_mint_concurrency` | usize | 4 | Maximum concurrent blocking TLS leaf mint jobs (must be > 0) |

### CA Sources

ExfilGuard uses a root CA and a path-length-zero intermediate CA. The
intermediate signs generated leaves, ExfilGuard sends `Leaf -> Intermediate ->
Root`, and clients trust the root. Choose the component that owns this
lifecycle explicitly; ExfilGuard never guesses from the files it finds and
never falls back to another source. In every mode, leaf validity is capped by
the active intermediate's remaining validity, with a safety margin; issuance
stops when too little safe lifetime remains.

#### `builtin`

```toml
ca = { source = "builtin", dir = "/var/lib/exfilguard/ca" }
```

On the first start with an empty directory, ExfilGuard generates certificates
valid for approximately ten years and persists exactly:

```text
ca/
├── root.crt
├── intermediate.crt
└── intermediate.key
```

The root key exists only while the hierarchy is generated and is never written
to disk. Consequently, `builtin` cannot renew or replace its intermediate
under the same root. An incomplete directory fails startup rather than
silently creating a new trust anchor. Before the hierarchy expires, or after a
key compromise, generate a new hierarchy and distribute its new root to
clients.

The Debian package selects `builtin`, creates `/var/lib/exfilguard/ca` as
`exfilguard:exfilguard` mode `0700`, and runs the service with `UMask=0077`.
It therefore works on a clean installation without an operator permission
step.

#### `files`

```toml
ca = { source = "files", dir = "/var/lib/exfilguard/ca" }
```

`files` treats all three artifacts above as externally managed. ExfilGuard
neither creates nor renews them. Provision a new intermediate certificate and
matching key as one generation, replace the directory contents safely, and
restart ExfilGuard. The new process starts with an empty in-memory leaf cache.

Startup validates that the intermediate key matches its certificate, the
intermediate chains to the root, both certificates are currently valid, and
CA basic constraints, path length, key usage, and issuer validity allow safe
leaf issuance. `root.key` is always rejected: neither file-backed source uses
it, and leaving a root signing key beside the online intermediate needlessly
increases exposure.

#### File permissions

For `builtin` and `files`, ExfilGuard enforces owner-only control at every
startup:

- The directory must be real, not a symlink, owned by the process UID, and
  mode `0700` or read-only mode `0500`.
- Every CA file must be a regular, non-symlink file owned by the process UID.
- `intermediate.key` must have mode `0600` or read-only mode `0400`.
- Certificates must be owner-readable and non-executable, and must not be
  writable by group or other users. Modes `0600`, `0644`, and read-only
  equivalents are suitable.

Startup reports a remediation command instead of changing provisioned files.
For the packaged service, a typical repair is:

```bash
sudo chown -R exfilguard:exfilguard /var/lib/exfilguard/ca
sudo chmod 0700 /var/lib/exfilguard/ca
sudo chmod 0600 /var/lib/exfilguard/ca/intermediate.key
sudo chmod 0644 /var/lib/exfilguard/ca/root.crt \
  /var/lib/exfilguard/ca/intermediate.crt
```

Package upgrades restore the CA directory ownership and mode but deliberately
do not rewrite operator-provisioned files.

#### `vault`

This integration is for HashiCorp Vault's PKI secrets engine, including Vault
Enterprise namespaces. HCP Vault Secrets is a different product and API.

Vault mode generates a fresh intermediate key in process memory and submits
its CSR to the configured selected Vault PKI issuer. The intermediate key and
all generated leaf keys remain in memory. ExfilGuard authenticates only when
it needs a signing operation, discards direct-auth tokens after that request,
and renews the whole issuer generation before expiry. The immutable issuer and
its empty leaf cache become active in one atomic switch.

```toml
[ca]
source = "vault"
address = "https://vault.internal.example:8200"
tls_ca_cert = "/etc/exfilguard/vault-tls-ca.crt"
# namespace = "team-a"
pki_mount = "pki"
issuer = "exfilguard-parent"
expected_root_certs = "/etc/exfilguard/exfilguard-roots.pem"
intermediate_ttl = 2592000       # 30 days
renewal_threshold = 1296000      # renew with 15 days remaining
request_timeout = 10
# tls_client_cert = "/etc/exfilguard/vault-client.crt"
# tls_client_key = "/etc/exfilguard/vault-client.key"

[ca.auth]
method = "approle"
mount = "approle"
role_id = "00000000-0000-0000-0000-000000000000"
secret_id_file = "/etc/exfilguard/vault-secret-id"
```

`pki_mount` defaults to `pki`, `intermediate_ttl` to 30 days,
`renewal_threshold` to 15 days, and `request_timeout` to 10 seconds. The
threshold must be shorter than the requested lifetime. Set it early enough to
cover a realistic Vault outage and operator response window.

Set `tls_server_name` when `address` uses an IP literal but the Vault server
certificate names a DNS host. It controls certificate verification while the
client still connects to the configured IP.

ExfilGuard calls only:

```text
POST /v1/<pki_mount>/issuer/<issuer>/sign-intermediate
```

Vault must support selected issuers. ExfilGuard does not fall back to the
older default-issuer endpoint because that could select a different trust
hierarchy. Give the AppRole or token `update` permission only on that exact
path. If possible, use a selected signing issuer constrained to `pathlen:1` so
the ExfilGuard intermediate is cryptographically limited to `pathlen:0`.

`expected_root_certs` is a PEM bundle independent of the TLS CA used to reach
Vault. ExfilGuard accepts the returned issuer only when it chains to one of
these explicitly pinned roots and passes the same key, constraint, usage, and
validity checks as file mode. Put old and new roots in the bundle during a
planned root rotation, switch the Vault issuer, then remove the old root after
the overlap period. Changing the bundle requires restarting ExfilGuard.

Vault supports three authentication transports:

- `approle` performs a just-in-time login at
  `/v1/auth/<mount>/login`. Keep `role_id` in TOML and the durable SecretID in
  the dedicated owner-only `secret_id_file`. Prefer a narrowly scoped AppRole,
  CIDR bindings where addresses are stable, no default policy, and a one-use
  token for the signing request. The reusable SecretID remains durable signing
  authority: keeping CA keys in memory does not make a compromised host or
  credential harmless.
- `token_file` reads a token supplied and renewed by another component:

  ```toml
  [ca.auth]
  method = "token_file"
  token_file = "/run/exfilguard/vault-token"
  ```

- `proxy` sends the request without a token so a local Vault Proxy can attach
  its auto-auth token. Point `ca.address` at its restricted listener:

  ```toml
  [ca.auth]
  method = "proxy"
  ```

Credential files must be regular, non-symlink, owned by the ExfilGuard process
UID, and readable only by that owner. Literal SecretIDs and tokens are not
accepted in TOML or command-line arguments. Vault requests do not follow
redirects or inherit ambient HTTP proxy settings, preventing credentials from
being forwarded to another origin or back through ExfilGuard itself. Vault
connections must use HTTPS; plaintext HTTP is accepted only for a loopback IP
listener such as a local Vault Proxy.

Vault mode has a deliberate availability dependency: after every process
restart, Vault must be reachable because the old intermediate key was never
persisted. If a renewal fails while the active issuer is still valid,
ExfilGuard keeps serving with it, retries with bounded backoff, and exposes the
failure to Prometheus. An invalid Vault response never replaces the issuer. If
no usable issuer exists, inspected HTTPS fails closed; it never falls back to
`builtin`, `files`, direct forwarding, or CONNECT tunneling. Renewal failures
do not crash a process that still has a valid issuer.

### Migrating from `ca_dir`

The old top-level `ca_dir` setting is not accepted. Replace it with one of the
explicit configurations above. Existing installations must also remove
`root.key` from the active CA directory before starting this version. If it is
a real root key that must be retained, move it to appropriately protected
offline storage; ExfilGuard never reads it. Remove the older compatibility
workaround that copied `intermediate.key` to `root.key`.

For an existing locally generated directory, the direct migration is:

```toml
ca = { source = "builtin", dir = "/var/lib/exfilguard/ca" }
```

Retain `root.crt`, `intermediate.crt`, and `intermediate.key`, remove
`root.key`, restore the documented ownership and modes, then restart.

---

## Logging Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `log` | String | `"json"` | Log format: `"json"` or `"text"` |
| `log_queries` | Boolean | false | Whether to log each request query |

---

## Timeout Settings

All timeout values are in seconds. Use `0` to disable `request_total_timeout` and
`connect_tunnel_max_lifetime`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `dns_resolve_timeout` | u64 | 2 | Maximum time to resolve DNS for upstream hosts |
| `upstream_connect_timeout` | u64 | 5 | Maximum time to establish upstream TCP connections |
| `tls_handshake_timeout` | u64 | 10 | Maximum time for TLS handshakes (client or upstream) |
| `request_header_timeout` | u64 | 10 | Maximum time to read an HTTP/1 request line + headers or the downstream HTTP/2 connection preface |
| `request_body_idle_timeout` | u64 | 30 | Maximum idle time between request body reads/writes |
| `response_header_timeout` | u64 | 60 | Maximum time to receive upstream response headers |
| `response_body_idle_timeout` | u64 | 60 | Maximum idle time between response body reads/writes |
| `request_total_timeout` | u64 | 0 | Maximum total time from request start until the response has been fully forwarded (0 disables) |
| `client_keepalive_idle_timeout` | u64 | 30 | Idle time before closing an HTTP/1 keep-alive connection or an HTTP/2 connection with no active request streams |
| `connect_tunnel_idle_timeout` | u64 | 60 | Maximum idle time for CONNECT tunnels |
| `connect_tunnel_max_lifetime` | u64 | 0 | Maximum lifetime for CONNECT tunnels (0 disables) |

For downstream HTTP/2, the connection is request-idle whenever it has no
active stream task. The client must produce its next complete request within
`client_keepalive_idle_timeout`; PING and other control traffic do not extend
that period. This also bounds an incomplete HTTP/2 header block while no other
stream is active. Active streams remain governed by the request-body,
response, and optional total-request timeouts rather than the connection-idle
timer.

---

## Request Size Limits

All size values are in bytes. Header limits must be greater than 0.
Set `max_request_body_size = 0` to disable the global request-body cap.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_request_header_size` | usize | 32768 (32 KiB) | Maximum HTTP request header size, including bumped HTTP/2 header lists |
| `max_response_header_size` | usize | 32768 (32 KiB) | Maximum HTTP response header size, including upstream HTTP/2 header lists |
| `max_request_body_size` | usize | 0 (unlimited) | Maximum HTTP request body size during forwarding (0 disables the limit) |

---

## Connection Pool

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `upstream_pool_capacity` | usize | 32 | Maximum number of upstream connections to pool (must be >= 1) |

---

## HTTP/2

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `http2_max_concurrent_streams` | u32 | 100 | Maximum concurrent bumped downstream HTTP/2 streams per connection (must be >= 1) |

---

## Metrics

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `metrics_listen` | String | None | Optional listen address (e.g., `"127.0.0.1:9090"`) to serve Prometheus metrics at `/metrics` |
| `metrics_tls_cert` | Path | None | PEM certificate chain to enable HTTPS for `/metrics` |
| `metrics_tls_key` | Path | None | PEM private key matching `metrics_tls_cert` |

ExfilGuard exports counters and histograms for per-client and per-policy
decisions, latency, cache activity, and upstream reuse, plus gauges for current
downstream connections, in-flight requests, CONNECT tunnels, bumped TLS
sessions, active HTTP/2 streams, upstream connections, cache usage, and the
last successful policy reload time.

CA lifecycle metrics are intentionally low-cardinality:

| Metric | Description |
|--------|-------------|
| `ca_source_info{source}` | Selected `builtin`, `files`, or `vault` source |
| `ca_certificate_not_after_timestamp_seconds{certificate}` | Root or active intermediate expiry as a Unix timestamp |
| `ca_issuer_usable` | `1` while the active issuer can safely mint a leaf, otherwise `0` |
| `ca_issuer_generation` | In-process issuer generation; increments on a successful Vault replacement |
| `ca_vault_renewal_attempts_total{result,reason}` | Vault renewal outcomes with bounded reason labels |
| `ca_vault_last_renewal_attempt_timestamp_seconds` | Last Vault renewal attempt time |
| `ca_vault_last_renewal_success_timestamp_seconds` | Last successful Vault renewal time |

Scrape these metrics in every CA mode: certificate expiry matters for
`builtin` and `files` even though ExfilGuard does not renew those sources. See
[`prometheus-alerts.yml`](prometheus-alerts.yml) for example expiry, usability,
and Vault failure alerts. Adjust the warning windows to your certificate TTL
and incident-response policy.

---

## Cache Settings

Response caching is opt-in per rule. The settings here configure the shared
cache storage.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cache_dir` | Path | None | Directory for response cache storage |
| `cache_max_entry_size` | u64 | 104857600 (100 MiB) | Maximum size of individual cache entries |
| `cache_max_entries` | usize | 10000 | Maximum number of cached responses (LRU) |
| `cache_total_capacity` | u64 | 1073741824 (1 GiB) | Total cache capacity |
| `cache_sweeper_interval` | u64 | 300 | Interval in seconds between cache sweeper runs |
| `cache_sweeper_batch_size` | usize | 1000 | Maximum metadata entries inspected per sweep |

### Cache Behavior

The cache follows standard HTTP cache headers from upstream servers.

#### Scope

The cache is shared across all clients. Responses are keyed by method and
absolute URI. `Vary` headers decide which request headers are part of the cache
key. Enable caching only if cross-client sharing is acceptable in your
environment.

#### Supported Headers

- **Cache-Control**: `max-age`, `s-maxage`, `public`, `private`, `no-cache`, `no-store`
- **Expires**: HTTP date for cache expiration
- **Vary**: Cache keys include request headers specified by Vary

#### TTL Priority

Cache lifetime is chosen in this order:

1. `s-maxage` (shared cache max-age) - highest priority
2. `max-age`
3. `Expires` header
4. `force_cache_duration` from policy rule (fallback only)

#### What Gets Cached

- **Methods**: Only `GET` and `HEAD` requests
- **Status codes**: 200, 203, 204, 205, 301, 302
- **Bypass**: Requests with `Authorization` or `Cookie` headers are never
  served from cache and are not stored. Requests with fixed-length or chunked
  bodies, or with `Range`, are also bypassed.
- **Not cached**: Responses with `no-store`, `no-cache`, or `private`
  directives, or any `Set-Cookie` header

#### Request Cache Directives

Request-side cache controls can force a bypass. If a request includes
`Cache-Control: no-cache`, `Cache-Control: no-store`, `Cache-Control: max-age=0`,
`Pragma: no-cache`, or `Range`, the cache will not be used and the response will
not be stored. Otherwise, caching follows the upstream response headers plus
`force_cache_duration` from policy rules.

For fields named by `Vary`, ExfilGuard stores and compares the complete ordered
list of request field values. Requests with missing, extra, or reordered values
do not share a representation.

#### Eviction

The cache uses LRU eviction when capacity is reached. Expired entries are
removed on lookup.

#### Layout and Sweeping

Cache entries live under a versioned subdirectory (`v3` under the cache root).
Metadata is keyed by request URI and points to an immutable body generation.
When the layout changes, old version directories are deleted asynchronously. A
background sweeper runs every `cache_sweeper_interval` seconds and inspects up
to `cache_sweeper_batch_size` entries, removing expired entries and pruning
empty shard directories.

!!! note
    The cache does not support conditional revalidation (ETag/If-None-Match, Last-Modified/If-Modified-Since). Stale entries are discarded and fetched fresh from upstream.

---

## Environment Variables

You can override any setting with environment variables. Use the
`EXFILGUARD__` prefix and double underscores for nesting.

```bash
# Override listen address
EXFILGUARD__LISTEN="0.0.0.0:3128"

# Override log format
EXFILGUARD__LOG="text"

# Override timeouts
EXFILGUARD__CLIENT_KEEPALIVE_IDLE_TIMEOUT=60
EXFILGUARD__UPSTREAM_CONNECT_TIMEOUT=120
```

---

## Complete Example

```toml
# Core settings
listen = "127.0.0.1:3128"
ca = { source = "builtin", dir = "./ca" }
clients = "clients.toml"
policies = "policies.toml"
clients_dir = "clients.d"
policies_dir = "policies.d"

# Logging
log = "text"
log_queries = false

# TLS
leaf_ttl = 86400
leaf_cache_capacity = 4096
leaf_mint_concurrency = 4

# Timeouts (seconds)
dns_resolve_timeout = 2
upstream_connect_timeout = 5
tls_handshake_timeout = 10
request_header_timeout = 10
request_body_idle_timeout = 30
response_header_timeout = 60
response_body_idle_timeout = 60
request_total_timeout = 0
client_keepalive_idle_timeout = 30
connect_tunnel_idle_timeout = 60
connect_tunnel_max_lifetime = 0

# Connection pool
upstream_pool_capacity = 32

# HTTP/2
http2_max_concurrent_streams = 100

# Size limits (bytes)
max_request_header_size = 32768
max_response_header_size = 32768
max_request_body_size = 0

# Cache (optional)
cache_dir = "./cache"
cache_max_entry_size = 104857600
cache_max_entries = 10000
cache_total_capacity = 1073741824
cache_sweeper_interval = 300
cache_sweeper_batch_size = 1000
```
