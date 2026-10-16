# ExfilGuard

ExfilGuard is a Rust egress proxy for outbound HTTP and HTTPS. Clients use it
as an explicit proxy. ExfilGuard checks each request against the client's
policy, logs the decision, and then either forwards or denies it.

ExfilGuard can ask an authorization service whether to allow a request. The
client supplies an authorization token, and the service can also provide
authentication headers for an allowed request. This lets the client call an
API without having its credential. See
[delegated authorization](docs/configuration.md#delegated-authorization).

For HTTPS, ExfilGuard can either inspect traffic by terminating TLS with its
built-in CA or tunnel the CONNECT stream untouched. Client and policy data can
be reloaded without restarting the process.

## Quickstart

1. Start the proxy with the minimal config:

   ```shell
   cargo run -- --config examples/quickstart/exfilguard.toml
   ```

   This config trusts only `127.0.0.1`. It allows bumped HTTPS requests to
   `https://www.searchkit.com/faq/**` and denies everything else. All
   generated material lives under `/tmp/exfilguard/quickstart`.

2. Send a test request through the proxy:

   ```shell
   SSL_CERT_FILE=/tmp/exfilguard/quickstart/ca/root.crt \
     curl --cacert /tmp/exfilguard/quickstart/ca/root.crt \
     -x http://127.0.0.1:3128 https://www.searchkit.com/faq/ --head
   ```

   The response should be `200 OK`. Any other host, path, or client IP is denied.

## Architecture Overview

ExfilGuard is split into a few small stages. The goal is simple: parse
requests once, apply the same policy rules everywhere, and keep forwarding
separate from policy matching.

### 1. The Listener Layer (`src/proxy/listener.rs`)

Accepts TCP connections, performs TLS when `proxy_tls` is configured, and hands
the stream to the dispatcher.

### 2. The Dispatcher Layer (`src/proxy/http/dispatch.rs`)

Figures out whether the connection is HTTP/1.1, HTTP/2, or CONNECT. If a
`CONNECT` request has matching HTTPS inspect `ALLOW` rules, it starts the TLS
bump flow.

### 3. The Policy Engine (`src/policy/`)

Takes a request view with scheme, host, port, path, and method, then returns
allow or deny.

- TOML is compiled up front into matcher structures.
- Client resolution happens from the source IP before policy checks.

### 4. The Request Pipeline (`src/proxy/request_pipeline.rs`)

Shares the same policy evaluation logic across:

- Plain HTTP requests.
- CONNECT tunnels.
- HTTPS requests inside a bumped tunnel.

### 5. Upstream Handling (`src/proxy/http/forward.rs`)

Maintains pooled outbound connections for HTTP/1.1 and HTTP/2.

### Full example lab

Use the richer sample layout when you need multiple clients, a mix of inspect
and tunnel rules, or a reload demo:

```shell
cp examples/full/exfilguard.toml exfilguard.toml
cargo run -- --config exfilguard.toml
```

Edit the copied files, or point `--config` at the originals, to try different
policies.

`SIGHUP` reloads client/policy data from the already configured
`clients`, `clients_dir`, `policies`, and `policies_dir` paths, plus proxy server
certificate files when configured. Changes to
`exfilguard.toml` or `config.d/*.toml`, including listener, metrics, cache, TLS,
logging, and timeout settings, require restarting the process.

Finish replacing the complete set of client and policy files before sending
`SIGHUP`, and leave them unchanged while the reload runs. A reload is validated
and published atomically in memory; failure keeps the previous snapshot active.

## Platform Support

- **Linux** — primary production target.
- **macOS** — supported for development and demos.
- **Windows** — not supported.

### Trust anchors

ExfilGuard requires a populated platform trust store for outbound TLS. The
server will not start if no native trust anchors are available. If you run in a stripped-down
environment, such as a minimal container, install the standard CA bundle
(`ca-certificates` or equivalent).

## Repository Map

- `src/cli.rs` — entry point and runtime flags.
- `src/config/` — config schema and loaders.
- `src/authorization/` — delegated policy and authentication for outgoing requests.
- `src/policy/` — policy compiler and matcher.
- `src/proxy/` — listeners, HTTP handlers, and upstream clients.
- `src/tls/` — CA lifecycle and the in-memory leaf cache.
- `examples/` — ready-to-run configs (`quickstart/`, `full/`).
- `docs/design-decisions.md` — why the code works this way.

## Request Flow

1. The listener accepts TCP connections on the configured address.
2. Protocol front-ends parse HTTP/1.1 requests or CONNECT tunnels (HTTP/2 support
   lives in `proxy::http2`).
3. The request pipeline derives a canonical policy view and evaluates the
   relevant client's policies in order until one matches.
4. Allowed requests are proxied upstream with pooled TCP/TLS clients; denied
   requests receive a 403 and a structured log entry.

### Forwarding vs. Policy Matching

ExfilGuard preserves the raw request target for upstream forwarding, logging,
cache keys, and signed requests. Policy evaluation uses a separate, normalized
path.

- Query strings are ignored for path matching.
- Percent-encoded RFC-unreserved characters are decoded. Other valid escapes
  remain encoded and use uppercase hex in the policy view, so `%2F` remains
  distinct from `/`.
- Literal `.` and `..` path segments are normalized before policy evaluation.
- Ambiguous path syntax is rejected with `400 Bad Request`. This includes
  characters outside RFC 3986 path syntax, invalid escapes, raw or encoded
  backslashes, and encoded dot-segments such as `%2e%2e`.

## Security

Use `[proxy_tls]` for encrypted proxy connections with file or Vault server
certificates. See
[HTTPS Proxy Listener](docs/configuration.md#https-proxy-listener) for
configuration and curl examples.

ExfilGuard enforces an outbound allow list and logs allowed and blocked requests.
Timeouts close slow or stalled connections.

### Scope

Policy rules control request destinations and methods. ExfilGuard forwards
request and response bodies without interpreting their application content.
Clients can send sensitive data to allowed destinations, so policies must
account for that risk.

When configured, delegated authorization can buffer a request body for signing.
Per-request and total memory limits apply to this buffering.

### Defense in depth

ExfilGuard rejects malformed requests and enforces configured size limits.
For inspected HTTPS, it establishes the upstream TLS connection during CONNECT
handling, then evaluates each HTTP request received inside the client's TLS
connection.

### Hardening tips

- Use the `.deb` package for production—it creates a dedicated user and sets
  sane defaults.
- Run as a non-root user and only listen on the interfaces you need. Put a
  firewall in front.
- Expose the proxy only to authorized clients. Use connection and rate controls
  at the network edge to protect availability and isolate clients sharing the
  proxy.
- Choose an explicit `builtin`, `files`, or `vault` CA source. For file-backed
  sources, startup enforces owner-only directory/key modes and rejects
  symlinks. Vault mode keeps inspection and authorization-service private keys
  in memory.
- Review timeout and size limits in [docs/configuration.md](docs/configuration.md).
- ExfilGuard blocks private upstream addresses by default. Use
  `allow_private_upstream_cidrs` to allow specific address ranges. Requests to
  those addresses must still pass the configured policies.
- Treat logs and metrics as sensitive—they contain internal hostnames and can
  reveal unusual traffic patterns.

## Limitations

- Use ExfilGuard as an explicit proxy. Transparent interception is not
  documented or supported for deployment.
- ExfilGuard rejects HTTP/1.1 Upgrade requests, including WebSocket handshakes,
  with `501 Not Implemented` and closes the connection. Access logs record
  `upgrade_unsupported`. It also rejects upstream `101 Switching Protocols`
  responses. CONNECT tunnels forward bytes unchanged.
- ExfilGuard rejects HTTP/1.0 requests and upstream HTTP/1.0 responses. It
  only supports HTTP/1.1 framing.

### TLS inspection vs. pass-through

Each HTTPS policy rule declares an explicit mode:

- `https_mode = "inspect"` (default) terminates TLS so the proxy can enforce
  scheme, host, path, and method checks on the inner HTTP request. Matching
  HTTPS `ALLOW` rules authorize a TLS bump preflight for the same host/port,
  but the real policy decision is attached to the inner request. Deny-only
  authorities fail at the outer CONNECT. Private upstream addresses are still
  blocked.
- `https_mode = "tunnel"` only enforces scheme/host/port on the outer CONNECT.
  These rules must use `methods = ["CONNECT"]` and a `url_pattern` ending in
  `/**`, making it clear that the intent is to tunnel the host untouched. Use
  this for pinned TLS or non-HTTP payloads that cannot tolerate TLS
  interception.

Inspected HTTP/1.1 requests may use origin-form (`/path?query`) or an absolute
HTTPS URI matching the CONNECT destination. ExfilGuard checks that destination
before policy evaluation and cache lookup, rejects conflicting Host headers,
and preserves the original path/query bytes when forwarding upstream.

Example from `examples/full/policies.toml`:

```toml
[[policy]]
name = "trusted-analytics-egress"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["GET", "POST"]
  url_pattern = "https://api.trusted-analytics.com/v1/exports/**"

[[policy]]
name = "pinned-payments-egress"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["CONNECT"]
  url_pattern = "https://secure.partner.com/**"
  https_mode = "tunnel"
```

Config loading fails if the HTTPS mode and method set are inconsistent.

### Policy evaluation

1. ExfilGuard maps the request's downstream address to a client. Non-fallback
   selectors must not overlap, so the match is unambiguous.
2. If no selector matches, the `fallback` client is used.
3. It evaluates that client's policies in order; the first matching rule wins.
4. Tunnel-mode CONNECT rules stream bytes once allowed; inspect-mode HTTPS
   `ALLOW` rules authorize TLS bump preflight and then evaluate the inner
   request normally. Deny-only authorities fail at the outer CONNECT.

## Configuration Basics

- When `--config` is omitted, ExfilGuard looks for
  `/etc/exfilguard/exfilguard.toml` before falling back to `./exfilguard.toml`.
- Relative paths in the config are resolved from the directory that contains the
  config file, which keeps packaged installs self-contained.
- Global overrides can be placed in `config.d/*.toml` beside the selected main
  config. Files load alphabetically after the main config and may contain only
  the settings they override.
- `clients_dir` and `policies_dir` can point at optional `*.d` directories. Every
  `.toml` file in those directories loads in alphabetical order after the base
  file. Names must be unique across all files.

### Fallback client

Exactly one client must set `fallback = true`. That client handles requests that
do not match any specific IP or CIDR. Config loading fails if zero or multiple
fallback clients exist. The fallback must not set `ip` or `cidr`.

Each client may have at most 1,024 simultaneous downstream connections by
default. Set `max_connections` on a client to override that budget. A CIDR
client shares its budget across every matching machine. The count includes
ordinary HTTP keep-alive, raw CONNECT, and inspected CONNECT connections.
Permits remain charged to the connection-time client identity across reloads;
new requests still use the latest client mapping and policies.

## Certificate storage and permissions

The required `ca` table chooses one explicit source: `builtin` generates a
long-lived local hierarchy, `files` loads an externally managed hierarchy, and
`vault` obtains and renews an in-memory intermediate from HashiCorp Vault. The
same global Vault connection can obtain the proxy server certificate and
in-memory client certificates for authorization services. The two file-backed
CA sources require owner-controlled directories and private keys; both reject `root.key` because
ExfilGuard never needs the root signing key.
See `docs/configuration.md` for lifecycle, permission, Vault, and migration
details. Anyone who can use the intermediate key or Vault signing credential
can mint certificates, so run ExfilGuard as an unprivileged user. Generated
leaf keys are cached only in process memory.

## Testing

- Primary integration test (spins up the proxy on loopback):

  ```shell
  cargo test --test bump_integration
  ```

- Full suite (integration + unit tests):

  ```shell
  cargo test
  ```

See [perf/h2/README.md](perf/h2/README.md) for HTTP/2 throughput and slow-reader
benchmarks.

### Fuzzing

ExfilGuard fuzzes the parsers and request-handling paths that process untrusted
input, including HTTP/1 request and response parsing, chunked bodies, HTTP/2
request sanitization, and CONNECT targets. Targets live under
`fuzz/fuzz_targets/`.

Run a target:

```shell
cargo fuzz run http1_request_head
```

Stable regression seeds live under `fuzz/seeds/`. For example, run the chunked
body target from its signed-extension and malformed-framing seeds with:

```shell
cargo fuzz run http1_chunked_body fuzz/seeds/http1_chunked_body
```

The `connect_target` seeds cover signed, empty, textual, and overflowing ports.
Their decoded first byte selects the split between the two candidate authorities.

The `http1_request_head` seeds include absolute HTTPS targets, signed object
requests, conflicting authorities, non-HTTPS schemes, Upgrade headers, and
mixed-case `Connection: upgrade` tokens. The target exercises ordinary proxy
parsing and inspected-request validation against `example.com:443`.

The HTTP/1 response target also checks final-response framing normalization.
Its seeds cover zero-length 204 compatibility, signed-zero rejection,
conflicting transfer encoding, and a forged response appended after a 204:

```shell
cargo fuzz run http1_response_head fuzz/seeds/http1_response_head
```

Parallel workers example:

```shell
cargo fuzz run http1_request_head -- -jobs=8 -workers=8
```

### Developer ergonomics

- Install the pre-commit hook to enforce formatting locally:

  ```shell
  ln -sf ../../hooks/pre-commit .git/hooks/pre-commit
  ```

## Debian packaging

1. Build a release binary: `cargo build --release`.
2. Install the helper (once): `cargo install cargo-deb`.
3. Produce the package: `cargo deb` (outputs to
   `target/debian/exfilguard_<version>_<arch>.deb`).
4. Install with `sudo dpkg -i exfilguard_<version>_<arch>.deb`, edit
   `/etc/exfilguard/*.toml`, and enable the service with
   `sudo systemctl enable --now exfilguard`.

Need an isolated build environment? `packaging/deb-container/` provides a
Docker-based workflow that installs Rust, `cargo-deb`, and all system
dependencies inside Ubuntu 22.04. See that directory's README for usage.

The package installs `/usr/sbin/exfilguard`, sample configs in `/etc/exfilguard/`,
a writable CA/cache directory under `/var/lib/exfilguard/`, and a
`systemd` unit (`exfilguard.service`). The binary reads
`/etc/exfilguard/exfilguard.toml` by default, and logs go to journald unless you
override the config or set `EXFILGUARD__*` environment variables. Package
upgrades restart the service when it was already active; they do not start a
service that an administrator left stopped. During the one-time upgrade from a
pre-0.9 package whose removal script already stopped the process, an enabled
service is started because its previous active state cannot be recovered.
The package provisions its service account and directories through
`systemd-sysusers` and `systemd-tmpfiles`, including when dpkg runs maintainer
scripts chrootless against `DPKG_ROOT`. Purging removes ExfilGuard state under
`/var/lib/exfilguard` but retains the system account to avoid unsafe UID reuse.

## Metrics

Set `metrics_listen = "127.0.0.1:9090"` in your config to expose Prometheus
metrics at `/metrics`. Provide `metrics_tls_cert` and `metrics_tls_key` to serve
the endpoint over HTTPS. Use this listener for internal access only. Keep it
firewalled to Prometheus, or put an authenticating reverse proxy in front of
it, because the metrics include internal hosts and policy decisions. Request
series are labeled with `effective_mode=direct|bump|tunnel`, so inspected HTTPS
and explicit CONNECT tunnels stay distinct. Current-state gauges cover
downstream connections globally and by client, in-flight requests, CONNECT
tunnels, bumped TLS sessions, active HTTP/2 streams, upstream connections,
cache usage, and the last successful policy reload time. Rejected connections
are counted by client. Certificate metrics report inspection-CA state, proxy
server certificate expiry and renewal, and Vault-backed authorization-service
client certificate expiry and renewal.
Example alert rules are in `docs/prometheus-alerts.yml`.

## Learn more

- `examples/full/` shows both inspect and pass-through rules plus a multi-client
  layout.

## License

ExfilGuard is available under the terms of the Apache License, Version 2.0. See
`LICENSE` for the full text.
