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
| `proxy_protocol_max_pending_connections` | usize | 1024 | Maximum connections from allowlisted peers concurrently awaiting PROXY header processing |
| `vault` | Table | When used | Shared Vault connection, PKI trust, and authentication settings |
| `ca` | Table | Yes | Explicit TLS interception CA source: `builtin`, `files`, or `vault` |
| `clients` | Path | Yes | Path to clients configuration file |
| `policies` | Path | Yes | Path to policies configuration file |
| `clients_dir` | Path | No | Directory containing additional client config files (*.toml) |
| `policies_dir` | Path | No | Directory containing additional policy config files (*.toml) |
| `authorization` | Table | No | Named services for delegated request policy and authentication |

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

    Allowlisted peers are trusted to send the complete PROXY header promptly as
    the first bytes of a backend connection. ExfilGuard bounds this setup with
    `request_header_timeout` and `proxy_protocol_max_pending_connections`.
    Excess pending connections are closed without spawning a handler task.

!!! note
    Set `proxy_protocol_allowed_cidrs` when PROXY protocol is enabled.

!!! note
    ExfilGuard reads `exfilguard.toml` and `config.d/*.toml` only at startup.
    `SIGHUP` reloads only the client and policy data read from the configured `clients`,
    `clients_dir`, `policies`, and `policies_dir` paths. If you change fields
    in `exfilguard.toml` itself, including `listen`, metrics, cache, TLS,
    logging, and timeout settings, restart the server.

    Treat all configured client and policy files as one generation: finish
    replacing every file before sending `SIGHUP`, and do not modify them during
    the reload. ExfilGuard validates and atomically publishes the resulting
    in-memory snapshot; if loading fails, the previous snapshot remains active.

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

## Client Connection Admission

Every configured client has a simultaneous downstream connection budget. The
default is 1,024 connections and can be overridden on an individual client:

```toml
[[client]]
name = "build-workers"
cidr = "10.42.16.0/27"
policies = ["build-egress"]
max_connections = 2048
```

The budget counts ordinary HTTP keep-alive connections, raw CONNECT tunnels,
and inspected CONNECT sessions. A CIDR client shares one budget across every
machine it matches. When the budget is full, ExfilGuard closes new connections
without evicting established ones. `max_connections` must be greater than zero.

Client and policy reloads apply a changed limit to new admission without
resetting active connection accounting. An existing connection's permit remains
charged to the client identity assigned when it was accepted, even if a reload
later maps its peer address to another client. Subsequent requests still use the
latest client mapping and policies. The limit is an operational resource guard,
not a retroactively reconciled tenant quota.

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

ExfilGuard enforces the CA semantics needed for arbitrary policy-selected leaf
names. It rejects name-constrained hierarchies and critical certificate
extensions other than `basicConstraints` and `keyUsage`; accepting either would
require applying additional constraints during every leaf issuance. Noncritical
informational extensions remain permitted.

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
to disk. First-run creation is a recoverable filesystem transaction: ExfilGuard
stages and validates the complete hierarchy, publishes it durably, and resumes
or discards only its own recognizable staging state after interruption.
Operator-created incomplete material still fails startup rather than silently
creating a new trust anchor. Consequently, `builtin` cannot renew or replace
its intermediate under the same root. Before the hierarchy expires, or after a
key compromise, generate a new hierarchy and distribute its new root to clients.

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

ExfilGuard has one shared HashiCorp Vault connection. The inspection CA and
authorization services can both use it. HCP Vault Secrets is a different
product and API.

Vault HTTPS uses the platform trust store. `tls_ca_cert` adds certificates to
that trust store for the Vault connection; it does not replace the platform
roots. This transport trust is separate from `vault.pki.expected_root_certs`,
which pins the roots accepted for certificates issued by Vault.

Configure the Vault connection, PKI trust, and authentication once:

```toml
[vault]
address = "https://vault.internal.example:8200"
tls_ca_cert = "/etc/exfilguard/vault-tls-ca.crt"
# namespace = "team-a"
# tls_server_name = "vault.internal.example"
# request_timeout = 10
# tls_client_cert = "/etc/exfilguard/vault-client.crt"
# tls_client_key = "/etc/exfilguard/vault-client.key"

[vault.pki]
mount = "pki"
expected_root_certs = "/etc/exfilguard/exfilguard-roots.pem"

[vault.auth]
method = "approle"
mount = "approle"
role_id = "00000000-0000-0000-0000-000000000000"
secret_id_file = "/etc/exfilguard/vault-secret-id"
```

Then select Vault for the inspection CA:

```toml
[ca]
source = "vault"
issuer = "exfilguard-parent"
# intermediate_ttl = 2592000
# renewal_threshold = 1296000
```

ExfilGuard generates the intermediate private key and CSR in memory. Vault
signs the CSR using the selected issuer. Before the intermediate expires,
ExfilGuard generates a new key, obtains a new certificate, and switches the
complete issuer generation atomically. Generated origin keys also remain in
memory.

`vault.pki.mount` defaults to `pki` and `vault.request_timeout` to 10 seconds.
`ca.intermediate_ttl` defaults to 30 days and `ca.renewal_threshold` to 15
days. The threshold must be shorter than the requested lifetime and should
leave enough time to recover from a Vault outage.

The renewal scheduler rechecks certificate expiry against wall-clock time at
least hourly rather than sleeping for the complete multi-day interval. This
keeps renewal responsive after host suspend or a wall-clock adjustment. Failed
renewals retry with jittered exponential backoff from 5 seconds to 15 minutes.

Set `tls_server_name` when `address` uses an IP literal but the Vault server
certificate names a DNS host. It controls certificate verification while the
client still connects to the configured IP.

For the inspection CA, ExfilGuard calls only:

```text
POST /v1/<mount>/issuer/<issuer>/sign-intermediate
```

Vault must support selected issuers. ExfilGuard does not fall back to the
older default-issuer endpoint because that could select a different trust
hierarchy. Give the AppRole or token `update` permission only on that exact
path. If possible, use a selected signing issuer constrained to `pathlen:1` so
the ExfilGuard intermediate is cryptographically limited to `pathlen:0`.

`vault.pki.expected_root_certs` is a PEM bundle independent of the TLS CA used
to reach Vault. ExfilGuard accepts the returned issuer only when it chains to
one of these explicitly pinned roots and passes the same key, constraint,
usage, and validity checks as file mode. Put old and new roots in the bundle
during a planned root rotation, switch the Vault issuer, then remove the old
root after the overlap period. Changing the bundle requires restarting
ExfilGuard.

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
  [vault.auth]
  method = "token_file"
  token_file = "/run/exfilguard/vault-token"
  ```

- `proxy` sends the request without a token so a local Vault Proxy can attach
  its auto-auth token. Point `vault.address` at its restricted listener:

  ```toml
  [vault.auth]
  method = "proxy"
  ```

Credential files must be regular, non-symlink, owned by the ExfilGuard process
UID, and readable only by that owner. Literal SecretIDs and tokens are not
accepted in TOML or command-line arguments. Vault requests do not follow
redirects or inherit ambient HTTP proxy settings, preventing credentials from
being forwarded to another origin or back through ExfilGuard itself. Vault
connections must use HTTPS; plaintext HTTP is accepted only for a loopback IP
listener such as a local Vault Proxy.

ExfilGuard generates Vault-backed private keys in memory and does not save
them. It must therefore reach Vault after each restart to obtain certificates
for the new keys. A failed renewal leaves the current valid certificate in
place and triggers bounded retries. An invalid Vault response never replaces
it. Once no valid certificate remains, the affected operation fails closed.
Inspection never falls back to another CA, direct forwarding, or CONNECT
tunneling.

### Configuration migration

The old top-level `ca_dir` setting is not accepted. Replace it with one of the
explicit configurations above. Existing installations must also remove
`root.key` from the active CA directory before starting this version. If it is
a real root key that must be retained, move it to appropriately protected
offline storage; ExfilGuard never reads it. Remove the older compatibility
workaround that copied `intermediate.key` to `root.key`.

Vault connection settings that were previously nested under `[ca]` now belong
under `[vault]`, `[vault.pki]`, and `[vault.auth]`. Keep only `source`, `issuer`,
`intermediate_ttl`, and `renewal_threshold` under `[ca]`. This makes the same
Vault connection available to authorization services without coupling them to
the inspection CA source.

For an existing locally generated directory, the direct migration is:

```toml
ca = { source = "builtin", dir = "/var/lib/exfilguard/ca" }
```

Retain `root.crt`, `intermediate.crt`, and `intermediate.key`, remove
`root.key`, restore the documented ownership and modes, then restart.

---

## Delegated authorization

ExfilGuard can ask an external authorization service whether a client may call an API. The client
sends an authorization token, which ExfilGuard passes to the service unchanged. ExfilGuard
does not interpret the token.

The service returns rules for the token, and ExfilGuard caches them briefly. Both the client's local
policy and the service's policy must allow a request.

The service can also provide authentication headers for an allowed request. A policy rule names the
credential with a reference that only the service understands. ExfilGuard sends the token, the
reference, and the exact outgoing request to the service, then adds the returned headers before
forwarding it. The client can therefore call the API without ever having the credential.

This is configured per client. A client with an `authorization_service` must send a token. Other
clients on the same listener continue to use ordinary static policy.

Define one or more named services in the main configuration:

```toml
[[authorization.service]]
name = "central"
audience = "deployment-prod"
policy_url = "https://authorization.example.net/v1/policy"
credential_url = "https://authorization.example.net/v1/credential"
server_ca_cert = "/etc/exfilguard/exfilguard-roots.pem"

[authorization.service.client_certificate]
source = "vault"
role = "exfilguard-authorization-client"
common_name = "exfilguard-production"
```

This uses the shared `[vault]` configuration described above. ExfilGuard generates the client
private key and CSR in memory, sends the CSR to
`POST /v1/<mount>/sign/<role>`, and accepts the result only if it is a client-only certificate for
the configured common name and chains to `vault.pki.expected_root_certs`. The Vault role chooses
the issuer and certificate lifetime. ExfilGuard renews the certificate halfway through its actual
lifetime and switches new service requests to it atomically. Requests already in flight may finish
using the previous certificate.

Give the AppRole `update` permission on the exact signing-role path. Configure the Vault PKI role
to permit only the intended common name, issue client certificates rather than CA or server
certificates, and impose an appropriate maximum lifetime. When Vault manages both the inspection
CA and these client certificates, the one AppRole policy contains both exact signing paths.

File-backed client certificates remain available as an explicit alternative:

```toml
[authorization.service.client_certificate]
source = "files"
cert = "/etc/exfilguard/authorization/client.pem"
key = "/etc/exfilguard/authorization/client.key"
```

ExfilGuard supplies secure defaults for all timeouts and resource limits. The following settings
are optional:

| Setting | Default | Meaning |
|---------|---------|---------|
| `max_token_header_size` | 1024 bytes | Largest accepted proxy authorization value |
| `policy_cache_capacity` | 4096 | Cached policy results per service |
| `max_policy_cache_duration` | 30 seconds | Longest ExfilGuard will reuse a service policy |
| `negative_cache_duration` | 1 second | How briefly to remember a denied policy lookup |
| `max_policy_response_size` | 256 KiB | Largest accepted policy response |
| `max_policy_rules` | 1024 | Most rules accepted in one policy response |
| `max_credential_response_size` | 32 KiB | Largest accepted authentication-header response |
| `max_protected_headers` | 16 | Most authentication headers allowed on one request |
| `max_buffered_body_size` | 1 MiB | Largest request body the service may receive |
| `max_buffered_body_capacity` | 16 MiB | Total memory available for bodies and their JSON copies |

These settings belong under `[authorization]`. Each `[[authorization.service]]` also accepts an
optional `timeout` (5 seconds by default) and `max_concurrency` (32 simultaneous calls by default).
Both policy and credential calls use these values.

Then assign the service in the client configuration:

```toml
[[client]]
name = "build-client"
cidr = "192.0.2.0/24"
policies = ["build-ceiling"]
authorization_service = "central"

[[client.credential_limit]]
credential_reference = "build-api"
origin_scope = "https://api.example.net/v1/**"
protected_headers = ["authorization"]
body_access = "bounded_payload"
```

A `credential_limit` is a local safety rule, not a credential. It says where the named reference may
be used, which headers the service may return, and whether the service may receive the request body.
A rule that does not ask for credentials does not need a matching limit. If a rule asks for
credentials outside the limit, ExfilGuard denies the request.

The first request from a client that uses delegated authorization must contain
`Proxy-Authorization: ExfilGuard <base64url-token>`. ExfilGuard keeps that token with the
connection. Later requests may omit it but cannot replace it. For inspected HTTPS, the outer
`CONNECT` carries the token and all decrypted requests use it. Raw CONNECT tunnels are denied
because ExfilGuard cannot check the requests inside them.

ExfilGuard calls the configured URLs directly over HTTPS with the service's client certificate. It
trusts only `server_ca_cert`, does not follow redirects, and ignores proxy settings from the
environment. Public CA files must be regular files, not symlinks, owned by root or the ExfilGuard
process, and not writable by group or other users. A file-backed client key must be owned by the
ExfilGuard process, must not be a symlink, and must have mode `0400` or `0600`. Relative paths are
resolved from the main configuration directory. Vault-backed client keys are never written to
disk.

Each named service has its own policy cache. Policy and credential calls to that service share its
`max_concurrency` limit.

`body_access = "none"` permits credentials only on requests without a body. `"bounded_payload"`
lets the service receive a size-limited body, for example to sign it. Requests that use credentials
cannot have trailers or `Expect: 100-continue`. If the service does not return valid headers,
ExfilGuard sends nothing to the API. The request is not retried or cached. All requests that use
delegated authorization bypass the shared response cache, even when no credential is needed.

`max_buffered_body_size` limits one body. `max_buffered_body_capacity` limits the total memory used
by all buffered bodies and their JSON copies. It must be at least
`5 * max_buffered_body_size + 2`; ExfilGuard rejects a smaller value.

Service definitions and limits are read at startup. `SIGHUP` reloads client assignments, credential
limits, and local policies together. A client that names an unknown service causes the reload to
fail, leaving the current configuration in place.

See [Authorization Service API](authorization-service.md) for the two JSON operations and the exact
request format.

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
| `upstream_connect_timeout` | u64 | 5 | Maximum total time for one upstream TCP connection across all resolved addresses |
| `tls_handshake_timeout` | u64 | 10 | Maximum time for TLS handshakes (client or upstream) |
| `request_header_timeout` | u64 | 10 | Maximum time to read an HTTP/1 request line + headers or the downstream HTTP/2 connection preface |
| `request_body_idle_timeout` | u64 | 30 | Maximum idle time between request body reads/writes |
| `response_header_timeout` | u64 | 60 | Maximum total time from waiting for the first upstream response head through receiving the final response head |
| `response_body_idle_timeout` | u64 | 60 | Maximum idle time between response body reads/writes |
| `request_total_timeout` | u64 | 0 | Maximum total time from accepting a complete request head through policy/cache work, upstream setup, and full response delivery (0 disables) |
| `client_keepalive_idle_timeout` | u64 | 30 | Idle time before closing an HTTP/1 keep-alive connection or an HTTP/2 connection with no active request streams |
| `connect_tunnel_idle_timeout` | u64 | 60 | Maximum time with no successful relay progress in either direction of a raw CONNECT tunnel; also bounds individual tunnel writes and setup/shutdown operations |
| `connect_tunnel_max_lifetime` | u64 | 0 | Maximum lifetime for CONNECT tunnels (0 disables) |

For downstream HTTP/2, the connection is request-idle whenever it has no
active stream task. The client must produce its next complete request within
`client_keepalive_idle_timeout`; PING and other control traffic do not extend
that period. This also bounds an incomplete HTTP/2 header block while no other
stream is active. Active streams remain governed by the request-body,
response, and optional total-request timeouts rather than the connection-idle
timer.

The total-request timeout begins after a complete inner HTTP request head has
been accepted. It caps cache lookup and delivery, DNS/TCP/TLS upstream setup,
request upload, retries, and response delivery. Phase-specific timeouts still
apply, so whichever deadline expires first wins. Before a final response has
started, expiry returns `504 Gateway Timeout`; after response delivery has
started, ExfilGuard closes or resets the request instead of appending another
response. Outer CONNECT setup, tunnel lifetime, and cleanup after response
delivery use their own limits.

For HTTP/2 cacheable responses, `response_body_idle_timeout` also bounds each
cache file operation on the response path. A storage error or timeout abandons
the cache copy while response forwarding continues.

---

## Request Size Limits

All size values are in bytes. Header limits must be greater than 0.
Set `max_request_body_size = 0` to disable the global request-body cap.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_request_header_size` | usize | 32768 (32 KiB) | Maximum HTTP request header size, including bumped HTTP/2 header lists |
| `max_response_header_size` | usize | 32768 (32 KiB) | Maximum HTTP response header size; for HTTP/1 this is shared by all informational and final heads, and for HTTP/2 it limits the upstream header list |
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
downstream connections globally and by client, in-flight requests, CONNECT
tunnels, bumped TLS sessions, active HTTP/2 streams, upstream connections,
cache usage, and the last successful policy reload time. Rejected downstream
connections are counted by configured client name.

`requests_method_total` uses a bounded `method` label: the standard HTTP
methods are reported by name and all extension methods are aggregated as
`OTHER`. Access logs retain the exact method.

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
| `authorization_service_client_certificate_not_after_timestamp_seconds{service}` | Expiry of a Vault-backed authorization-service client certificate |
| `authorization_service_vault_renewal_attempts_total{service,result,reason}` | Client-certificate renewal outcomes |
| `authorization_service_vault_last_renewal_attempt_timestamp_seconds{service}` | Last client-certificate renewal attempt |
| `authorization_service_vault_last_renewal_success_timestamp_seconds{service}` | Last successful client-certificate renewal |

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
| `cache_max_entry_size` | u64 | 104857600 (100 MiB) | Maximum size of an entry and aggregate in-progress response bodies |
| `cache_max_entries` | usize | 10000 | Maximum number of cached responses (LRU) |
| `cache_total_capacity` | u64 | 1073741824 (1 GiB) | Capacity of completed cache entries |
| `cache_sweeper_interval` | u64 | 300 | Interval in seconds between cache sweeper runs |
| `cache_sweeper_batch_size` | usize | 1000 | Maximum metadata entries inspected per sweep |

### Cache Behavior

The cache follows standard HTTP cache headers from upstream servers.

#### Scope

The cache is shared across all clients and across inspected HTTP/1.1 and
HTTP/2 traffic. Responses are keyed by method and absolute URI. `Vary` headers
decide which request headers are part of the cache key. Enable caching only if
cross-client sharing is acceptable in your environment.

#### Supported Headers

- **Cache-Control**: `max-age`, `s-maxage`, `public`, `private`, `no-cache`, `no-store`
- **Expires**: HTTP date for cache expiration
- **Date and Age**: Used to account for a response's age before and while it is cached
- **Vary**: Cache keys include request headers specified by Vary

#### TTL Priority

Cache lifetime is chosen in this order:

1. `s-maxage` (shared cache max-age) - highest priority
2. `max-age`
3. `Expires` header
4. `force_cache_duration` from policy rule (fallback only)

The response's corrected age is subtracted from that lifetime, including when
`force_cache_duration` supplies the lifetime. Time spent receiving the response
body also consumes freshness. Cache hits replace any upstream `Age` field with
the response's current age.

#### What Gets Cached

- **Methods**: Only `GET` and `HEAD` requests
- **Status codes**: 200, 203, 204, 205, 301, 302
- **Bypass**: Requests with `Authorization` or `Cookie` headers are never
  served from cache and are not stored. Requests with fixed-length or chunked
  bodies, or with `Range`, are also bypassed.
- **Not cached**: Responses with `no-store`, `no-cache`, or `private`
  directives, any `Set-Cookie` header, or response trailers. HTTP/1 responses
  with transfer codings other than a sole `chunked` coding are also forwarded
  without being stored.

#### Request Cache Directives

Request-side cache controls can force a bypass. If a request includes
`Cache-Control: no-cache`, `Cache-Control: no-store`, `Cache-Control: max-age=0`,
`Pragma: no-cache`, or `Range`, the cache will not be used and the response will
not be stored. ExfilGuard does not evaluate conditional validators locally;
requests with `If-None-Match` or `If-Modified-Since` are likewise forwarded
without cache lookup or storage. Otherwise, caching follows the upstream
response headers plus `force_cache_duration` from policy rules.

For fields named by `Vary`, ExfilGuard stores and compares the complete ordered
list of request field values. Requests with missing, extra, or reordered values
do not share a representation.

#### Eviction

The cache uses LRU eviction when capacity is reached. Expired entries are
removed on lookup.

#### Layout and Sweeping

Cache entries live under a versioned subdirectory (`v6` under the cache root).
Metadata is keyed by request URI and points to an immutable body generation.
When the layout changes, old version directories are deleted asynchronously. A
background sweeper runs every `cache_sweeper_interval` seconds and inspects up
to `cache_sweeper_batch_size` entries, removing expired entries and pruning
empty shard directories. It retains an in-memory offset so successive bounded
runs advance through the complete metadata set; restart resets the offset after
the startup scan has already examined every entry.

`cache_total_capacity` is an advisory bound for completed response bodies, not
a filesystem quota. In-progress cache fills share an additional
`cache_max_entry_size` staging allowance; when it is exhausted, those fills
skip caching without slowing or rejecting the forwarded responses. Operators
should therefore reserve at least the sum of both settings, plus space for
metadata and normal filesystem overhead. Partial staging files are removed as
soon as their fill is discarded.

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
