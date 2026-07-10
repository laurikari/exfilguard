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
| `ca_dir` | Path | Yes | Directory containing CA certificate and private key for TLS interception |
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

### CA Directory Structure

ExfilGuard uses a root CA plus an intermediate CA. `ca_dir` must contain:

```
ca_dir/
├── root.crt           # Root CA certificate
├── root.key           # Root CA private key (optional when using external CA)
├── intermediate.crt   # Intermediate CA certificate (signed by root)
└── intermediate.key   # Intermediate CA private key
```

- The intermediate CA signs leaf certificates.
- ExfilGuard sends the chain `Leaf -> Intermediate -> Root` to clients.
- Clients only need to trust the root CA.
- If you use an externally signed intermediate, `root.key` may be omitted.

If `ca_dir` is empty, ExfilGuard generates all four files automatically on first startup.

ExfilGuard enforces owner-only control of this material at every startup:

- `ca_dir` must be a real directory, not a symlink, owned by the process UID,
  with mode `0700` or read-only mode `0500`.
- Every CA file must be a regular, non-symlink file owned by the process UID.
- `root.key` and `intermediate.key` must have mode `0600` or read-only mode
  `0400`.
- Certificates must be owner-readable, non-executable, and not writable by
  group or other users. Generated certificates request mode `0644`; the Debian
  service's `UMask=0077` reduces that to `0600`. Read-only modes such as `0444`
  are also suitable.

Startup fails with a remediation command when these requirements are not met;
ExfilGuard does not change the ownership or permissions of provisioned files.
For the packaged service, a typical repair is:

```bash
sudo chown -R exfilguard:exfilguard /var/lib/exfilguard/ca
sudo chmod 0700 /var/lib/exfilguard/ca
sudo chmod 0600 /var/lib/exfilguard/ca/root.key \
  /var/lib/exfilguard/ca/intermediate.key
sudo chmod 0644 /var/lib/exfilguard/ca/root.crt \
  /var/lib/exfilguard/ca/intermediate.crt
```

If `root.key` is intentionally absent, omit it from the command.

The Debian package creates `/var/lib/exfilguard/ca` as
`exfilguard:exfilguard` mode `0700` and runs the service with `UMask=0077`, so
a clean installation satisfies these rules on its first start. Package
upgrades restore the directory ownership and mode but deliberately do not
change existing CA files; operator-provisioned material must already satisfy
the file rules above.

!!! note
    If you change files under `ca_dir`, restart the server. Generated leaf
    certificates are cached only in process memory and disappear on restart.

### Using Your Corporate CA

Use this flow if you want clients to trust ExfilGuard through your existing
PKI:

1. **Let ExfilGuard generate its keys**:
   ```bash
   # Creates root.crt, root.key, intermediate.crt, intermediate.key
   exfilguard --config exfilguard.toml
   ```
   Start with an empty `ca_dir`, then stop the process after it creates the
   files.

2. **Create a CSR from the generated intermediate key**:
   ```bash
   openssl req -new -key ca_dir/intermediate.key \
     -out intermediate.csr \
     -subj "/CN=ExfilGuard Intermediate CA"
   ```

3. **Get your corporate CA to sign the CSR**:
   ```bash
   # Example using openssl (adjust to your CA's process)
   openssl x509 -req -in intermediate.csr \
     -CA corporate-ca.crt -CAkey corporate-ca.key \
     -CAcreateserial -out intermediate-signed.crt \
     -days 365 -sha256 \
     -extfile <(echo "basicConstraints=CA:TRUE,pathlen:0
   keyUsage=keyCertSign,cRLSign")
   ```

4. **Replace the certificates**:
   ```bash
   cp corporate-ca.crt ca_dir/root.crt
   cp intermediate-signed.crt ca_dir/intermediate.crt
   # Keep the original intermediate.key - it matches the CSR
   # root.key is no longer needed (can be removed or kept)
   ```

   Ensure the copied files are owned by the same UID that runs ExfilGuard and
   restore the directory, key, and certificate modes documented above.

5. **Restart ExfilGuard**.
   Clients that trust your corporate CA will then trust intercepted
   connections.

!!! note
    The private key (`intermediate.key`) stays the same. Only the certificate
    changes.

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
| `request_header_timeout` | u64 | 10 | Maximum time to read an HTTP request line + headers |
| `request_body_idle_timeout` | u64 | 30 | Maximum idle time between request body reads/writes |
| `response_header_timeout` | u64 | 60 | Maximum time to receive upstream response headers |
| `response_body_idle_timeout` | u64 | 60 | Maximum idle time between response body reads/writes |
| `request_total_timeout` | u64 | 0 | Maximum total time from request start until the response has been fully forwarded (0 disables) |
| `client_keepalive_idle_timeout` | u64 | 30 | Idle time before closing an idle client keep-alive connection |
| `connect_tunnel_idle_timeout` | u64 | 60 | Maximum idle time for CONNECT tunnels |
| `connect_tunnel_max_lifetime` | u64 | 0 | Maximum lifetime for CONNECT tunnels (0 disables) |

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
ca_dir = "./ca"
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
