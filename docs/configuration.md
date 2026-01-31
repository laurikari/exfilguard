# Configuration Reference

Global settings for ExfilGuard defined in `exfilguard.toml`.

---

## Core Settings

Required settings to run ExfilGuard.

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
    When `proxy_protocol` is `"optional"` or `"required"`, ExfilGuard auto-detects PROXY
    protocol v1 or v2 headers. If the peer IP is not in `proxy_protocol_allowed_cidrs`,
    ExfilGuard ignores any PROXY headers and treats the connection as a plain client.

!!! note
    `proxy_protocol_allowed_cidrs` must be set when PROXY protocol is enabled.

---

## TLS / Certificate Settings

Settings for TLS interception and certificate generation.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cert_cache_dir` | Path | None | Directory to cache dynamically generated TLS certificates |
| `leaf_ttl` | u64 | 86400 | TLS certificate leaf TTL in seconds (must be > 0) |

### CA Directory Structure

ExfilGuard uses a two-tier CA hierarchy. The `ca_dir` must contain:

```
ca_dir/
├── root.crt           # Root CA certificate
├── root.key           # Root CA private key (optional when using external CA)
├── intermediate.crt   # Intermediate CA certificate (signed by root)
└── intermediate.key   # Intermediate CA private key
```

- **Leaf certificates** are signed by the intermediate CA
- **Certificate chain** sent to clients: Leaf → Intermediate → Root
- Clients only need to trust the root CA
- If using an externally signed intermediate, `root.key` may be omitted

If `ca_dir` is empty, ExfilGuard generates all four files automatically on first startup.

### Using Your Corporate CA

To integrate with an existing PKI so clients already trust ExfilGuard's certificates:

1. **Let ExfilGuard generate its keys** (start with empty `ca_dir`, then stop):
   ```bash
   # Creates root.crt, root.key, intermediate.crt, intermediate.key
   exfilguard --config exfilguard.toml
   ```

2. **Create a CSR from the generated intermediate key**:
   ```bash
   openssl req -new -key ca_dir/intermediate.key \
     -out intermediate.csr \
     -subj "/CN=ExfilGuard Intermediate CA"
   ```

3. **Get your corporate CA to sign the CSR** (produces a new certificate):
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

5. **Restart ExfilGuard** - clients that trust your corporate CA will now trust intercepted connections.

!!! note
    The private key (`intermediate.key`) stays the same. You're replacing the certificate with one signed by a different authority.

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
| `response_header_timeout` | u64 | 30 | Maximum time to receive upstream response headers |
| `response_body_idle_timeout` | u64 | 60 | Maximum idle time between response body reads/writes |
| `request_total_timeout` | u64 | 0 | Maximum time from request start to upstream response headers (0 disables) |
| `client_keepalive_idle_timeout` | u64 | 30 | Idle time before closing an idle client keep-alive connection |
| `connect_tunnel_idle_timeout` | u64 | 60 | Maximum idle time for CONNECT tunnels |
| `connect_tunnel_max_lifetime` | u64 | 0 | Maximum lifetime for CONNECT tunnels (0 disables) |

---

## Request Size Limits

All size values are in bytes and must be greater than 0.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_request_header_size` | usize | 32768 (32 KiB) | Maximum HTTP request header size |
| `max_response_header_size` | usize | 32768 (32 KiB) | Maximum HTTP response header size |
| `max_request_body_size` | usize | 67108864 (64 MiB) | Maximum HTTP request body size |

---

## Connection Pool

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `upstream_pool_capacity` | usize | 32 | Maximum number of upstream connections to pool (must be >= 1) |

---

## Metrics

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `metrics_listen` | String | None | Optional listen address (e.g., `"127.0.0.1:9090"`) to serve Prometheus metrics at `/metrics` |
| `metrics_tls_cert` | Path | None | PEM certificate chain to enable HTTPS for `/metrics` |
| `metrics_tls_key` | Path | None | PEM private key matching `metrics_tls_cert` |

Exports counters and histograms for per-client/policy decisions and latency, cache activity, and connection pool health.

---

## Cache Settings

Response caching is opt-in per rule. The cache settings here configure the shared cache storage.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cache_dir` | Path | None | Directory for response cache storage |
| `cache_max_entry_size` | u64 | 10485760 (10 MiB) | Maximum size of individual cache entries |
| `cache_max_entries` | usize | 10000 | Maximum number of cached responses (LRU) |
| `cache_total_capacity` | u64 | 1073741824 (1 GiB) | Total cache capacity |
| `cache_sweeper_interval` | u64 | 300 | Interval in seconds between cache sweeper runs |
| `cache_sweeper_batch_size` | usize | 1000 | Maximum metadata entries inspected per sweep |

### Cache Behavior

The cache respects standard HTTP caching semantics from upstream servers.

#### Scope

The cache is shared across all clients. Responses are keyed by method + absolute URI, with
`Vary` request headers used to decide cache hits. Enable caching only if cross-client sharing
is acceptable for your deployment.

#### Supported Headers

- **Cache-Control**: `max-age`, `s-maxage`, `public`, `private`, `no-cache`, `no-store`
- **Expires**: HTTP date for cache expiration
- **Vary**: Cache keys include request headers specified by Vary

#### TTL Priority

Cache lifetime is determined in this order:

1. `s-maxage` (shared cache max-age) - highest priority
2. `max-age`
3. `Expires` header
4. `force_cache_duration` from policy rule (fallback only)

#### What Gets Cached

- **Methods**: Only `GET` and `HEAD` requests
- **Status codes**: 200, 203, 204, 205, 206, 301, 302
- **Bypass**: Requests with `Authorization` or `Cookie` headers are never served from cache
  and are not stored
- **Not cached**: Responses with `no-store`, `no-cache`, or `private` directives, or any `Set-Cookie` header

#### Request Cache Directives

Request-side cache controls are honored for bypass. If a request includes `Cache-Control:
no-cache`, `Cache-Control: no-store`, `Cache-Control: max-age=0`, or `Pragma: no-cache`, the
cache will not be used and the response will not be stored. Caching decisions otherwise
follow upstream response headers plus `force_cache_duration` from policy rules.

#### Eviction

Uses LRU (Least Recently Used) eviction when capacity is reached. Expired entries are removed on lookup.

#### Layout and Sweeping

Cache entries live under a versioned subdirectory (`v1` under the cache root). When the layout
version changes, old version directories are deleted asynchronously. A background
sweeper runs every `cache_sweeper_interval` seconds and inspects up to
`cache_sweeper_batch_size` entries, removing expired entries and pruning empty shard
directories.

!!! note
    The cache does not support conditional revalidation (ETag/If-None-Match, Last-Modified/If-Modified-Since). Stale entries are discarded and fetched fresh from upstream.

---

## Environment Variables

All settings can be overridden via environment variables using the `EXFILGUARD__` prefix with double underscores for nesting.

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
cert_cache_dir = "./cert_cache"
clients = "clients.toml"
policies = "policies.toml"
clients_dir = "clients.d"
policies_dir = "policies.d"

# Logging
log = "text"
log_queries = false

# TLS
leaf_ttl = 86400

# Timeouts (seconds)
dns_resolve_timeout = 2
upstream_connect_timeout = 5
tls_handshake_timeout = 10
request_header_timeout = 10
request_body_idle_timeout = 30
response_header_timeout = 30
response_body_idle_timeout = 60
request_total_timeout = 0
client_keepalive_idle_timeout = 30
connect_tunnel_idle_timeout = 60
connect_tunnel_max_lifetime = 0

# Connection pool
upstream_pool_capacity = 32

# Size limits (bytes)
max_request_header_size = 32768
max_response_header_size = 32768
max_request_body_size = 67108864

# Cache (optional)
cache_dir = "./cache"
cache_max_entry_size = 10485760
cache_max_entries = 10000
cache_total_capacity = 1073741824
cache_sweeper_interval = 300
cache_sweeper_batch_size = 1000
```
