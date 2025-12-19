# Configuration Reference

Global settings for ExfilGuard defined in `exfilguard.toml`.

---

## Core Settings

Required settings to run ExfilGuard.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `listen` | String | Yes | Listen address and port (e.g., `"127.0.0.1:3128"`) |
| `ca_dir` | Path | Yes | Directory containing CA certificate and private key for TLS interception |
| `clients` | Path | Yes | Path to clients configuration file |
| `policies` | Path | Yes | Path to policies configuration file |
| `clients_dir` | Path | No | Directory containing additional client config files (*.toml) |
| `policies_dir` | Path | No | Directory containing additional policy config files (*.toml) |

!!! note
    Relative paths are resolved from the directory containing the main config file.

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
├── root.key           # Root CA private key
├── intermediate.crt   # Intermediate CA certificate (signed by root)
└── intermediate.key   # Intermediate CA private key
```

- **Leaf certificates** are signed by the intermediate CA
- **Certificate chain** sent to clients: Leaf → Intermediate → Root
- Clients only need to trust the root CA

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

All timeout values are in seconds and must be greater than 0.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `client_timeout` | u64 | 30 | Maximum time to wait for client responses |
| `upstream_connect_timeout` | u64 | 5 | Maximum time to establish upstream connections |
| `upstream_timeout` | u64 | 60 | Maximum time to wait for upstream responses |

---

## Request Size Limits

All size values are in bytes and must be greater than 0.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_header_size` | usize | 32768 (32 KiB) | Maximum HTTP request header size |
| `max_response_header_size` | usize | 32768 (32 KiB) | Maximum HTTP response header size |
| `max_body_size` | usize | 67108864 (64 MiB) | Maximum HTTP body size |

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

Response caching is disabled by default. Set `cache_dir` to enable.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cache_dir` | Path | None | Directory for response caching (enables caching when set) |
| `cache_max_entry_size` | u64 | 10485760 (10 MiB) | Maximum size of individual cache entries |
| `cache_max_entries` | usize | 10000 | Maximum number of cached responses (LRU) |
| `cache_total_capacity` | u64 | 1073741824 (1 GiB) | Total cache capacity |

### Cache Behavior

The cache respects standard HTTP caching semantics from upstream servers.

#### Scope

The cache is shared across all clients. Responses are keyed by method + absolute URI, with
`Vary` request headers used to decide cache hits. Enable caching only if cross-client sharing
is acceptable for your deployment.

#### Supported Headers

- **Cache-Control**: `max-age`, `s-maxage`, `private`, `no-store`, `public`
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
- **Not cached**: Responses with `no-store` or `private` directives

#### Request Cache Directives

Request-side cache controls are honored for bypass. If a request includes `Cache-Control:
no-cache`, `Cache-Control: no-store`, `Cache-Control: max-age=0`, or `Pragma: no-cache`, the
cache will not be used and the response will not be stored. Caching decisions otherwise
follow upstream response headers plus `force_cache_duration` from policy rules.

#### Eviction

Uses LRU (Least Recently Used) eviction when capacity is reached. Expired entries are removed on lookup.

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
EXFILGUARD__CLIENT_TIMEOUT=60
EXFILGUARD__UPSTREAM_TIMEOUT=120
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
client_timeout = 30
upstream_connect_timeout = 5
upstream_timeout = 60

# Connection pool
upstream_pool_capacity = 32

# Size limits (bytes)
max_header_size = 32768
max_response_header_size = 32768
max_body_size = 67108864

# Cache (optional)
cache_dir = "./cache"
cache_max_entry_size = 10485760
cache_max_entries = 10000
cache_total_capacity = 1073741824
```
