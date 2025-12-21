# ExfilGuard

ExfilGuard is a Rust egress proxy that enforces per-client policies on outbound
HTTP and HTTPS traffic. It accepts explicit proxy connections, evaluates each
request against the client's policy, logs the decision, and either forwards or
denies the request. When a rule enables inspection, ExfilGuard terminates TLS
and mints leaf certificates on the fly using its built-in CA; otherwise it can
tunnel the CONNECT stream without touching the payload. Configuration can be
reloaded without restarting the process.

## Quickstart

1. Start the proxy with the minimal config:

   ```shell
   cargo run -- --config examples/quickstart/exfilguard.toml
   ```

   This config trusts only `127.0.0.1`, intercepts `CONNECT` requests to
   `https://www.searchkit.com/`, and only allows paths that start with `/faq/`.
   All generated material lives under `/tmp/exfilguard/quickstart`.

2. Send a test request through the proxy:

   ```shell
   SSL_CERT_FILE=/tmp/exfilguard/quickstart/ca/root.crt \
     curl --cacert /tmp/exfilguard/quickstart/ca/root.crt \
     -x http://127.0.0.1:3128 https://www.searchkit.com/faq/ --head
   ```

   The response should be `200 OK`. Any other host, path, or client IP is denied.

## Architecture Overview

ExfilGuard is designed as a modular pipeline to ensure security policies are
enforced consistently across different protocols.

### 1. The Listener Layer (`src/proxy/listener.rs`)
The entry point that accepts raw TCP connections. It hands off the stream to
the **Dispatcher**.

### 2. The Dispatcher Layer (`src/proxy/http/dispatch.rs`)
Determines the protocol (HTTP/1.1, HTTP/2, or CONNECT). If a `CONNECT`
request is received and the policy requires `inspect_payload = true`, it
triggers the **TLS Bumping** flow.

### 3. The Policy Engine (`src/policy/`)
A decoupled module that takes a "Request" (Scheme, Host, Port, Path, Method)
and returns a **Decision** (Allow/Deny).
- **Compilation**: TOML is compiled into a CIDR Trie and Regex-based Matchers.
- **Evaluation**: Client resolution happens via Source IP before policy iteration.

### 4. The Request Pipeline (`src/proxy/request_pipeline.rs`)
An abstraction layer using the `RequestHandler` trait. This allows the same
policy evaluation logic to be shared by:
- Plain HTTP requests.
- CONNECT tunnels (Splicing).
- "Unwrapped" HTTPS requests inside a bumped tunnel.

### 5. Upstream Handling (`src/proxy/http/forward.rs`)
Manages a connection pool (`UpstreamPool`) to reduce latency for outbound
requests, supporting both HTTP/1.1 and H2 multiplexing.

### Full example lab

Use the richer sample layout when you need multiple clients, a mix of inspection
settings, or hot reload demonstrations:

```shell
cp examples/full/exfilguard.toml exfilguard.toml
cargo run -- --config exfilguard.toml
```

Edit the copied files—or point `--config` at the originals—to try different
policies.

## Platform Support

- **Linux** — primary production target.
- **macOS** — supported for development and demos.
- **Windows** — not supported.

### Trust anchors

ExfilGuard’s outbound TLS client configuration **requires** a populated
platform trust store. The process aborts startup when no native anchors are
present rather than silently continuing without any trust material. This is
intentional; if you’re operating in a stripped-down environment, install system
certificates instead of providing a custom trust store.

## Repository Map

- `src/cli.rs` — entry point and runtime flags.
- `src/config/` — config schema and loaders.
- `src/policy/` — policy compiler and matcher.
- `src/proxy/` — listeners, HTTP handlers, and upstream clients.
- `src/tls/` — CA lifecycle plus the on-disk leaf cache.
- `examples/` — ready-to-run configs (`quickstart/`, `full/`).

## Request Flow

1. The listener accepts TCP connections on the configured address.
2. Protocol front-ends parse HTTP/1.1 requests or CONNECT tunnels (HTTP/2 support
   lives in `proxy::http2`).
3. The request pipeline normalizes the request and evaluates the relevant
   client's policies in order until one matches.
4. Allowed requests are proxied upstream with pooled TCP/TLS clients; denied
   requests receive a 403 and a structured log entry.

## Limitations

- WebSocket and HTTP/1.1 Upgrade flows are not supported; upstream `101 Switching Protocols`
  responses are rejected rather than tunneled.
- HTTP/1.0 requests and upstream HTTP/1.0 responses are rejected; ExfilGuard only supports
  HTTP/1.1 framing.

### TLS inspection vs. pass-through

Each policy rule declares whether ExfilGuard bumps TLS:

- `inspect_payload = true` (default) terminates TLS so the proxy can enforce
  scheme, host, path, and method checks—and log bodies if needed.
- `inspect_payload = false` only enforces scheme/host/port. These rules must use
  `methods = ["CONNECT"]` and a `url_pattern` ending in `/**`, making it clear
  that the intent is to tunnel the host untouched. Use this for pinned TLS or
  non-HTTP payloads that cannot tolerate MITM.

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
  url_pattern = "https://secure.partner.com/payments/**"
  inspect_payload = false
  allow_private_upstream = true
```

The loader aborts if the inspection settings are inconsistent (for example:
`inspect_payload=false is not allowed for DENY action`).

### Policy evaluation

1. ExfilGuard maps the request's downstream address to a client. Non-fallback
   selectors must not overlap, so the match is unambiguous.
2. If no selector matches, the `fallback` client is used.
3. It evaluates that client's policies in-order; the first matching rule wins.
4. Rules that disable inspection still use the same logging path—they simply skip
   the TLS bump step and stream bytes once allowed.

## Configuration Basics

- When `--config` is omitted, ExfilGuard looks for
  `/etc/exfilguard/exfilguard.toml` before falling back to `./exfilguard.toml`.
- Relative paths in the config are resolved from the directory that contains the
  config file, which keeps packaged installs self-contained.
- `clients_dir` and `policies_dir` can point at optional `*.d` directories. Every
  `.toml` file in those directories loads in alphabetical order after the base
  file. Names must be unique across all files.

### Fallback client

Exactly one client must set `fallback = true`. That client handles requests that
do not match any specific IP or CIDR. Config loading fails if zero or multiple
fallback clients exist.

## Certificate storage and permissions

`--ca-dir` and `cert_cache_dir` hold the root, intermediate, and leaf
material. Files are written with `0o600`, but you must also secure the
directories (for example `chmod 700`). Anyone who can read them can mint
certificates or impersonate the proxy, so run ExfilGuard as an unprivileged user
and store the CA on trusted disks.

## Testing

- Primary integration test (spins up the proxy on loopback):

  ```shell
  cargo test --test bump_integration
  ```

- Full suite (integration + unit tests):

  ```shell
  cargo test
  ```

### Fuzzing

ExfilGuard fuzzes critical untrusted input paths (HTTP/1 request/response
parsing, chunked bodies, HTTP/2 request sanitization, CONNECT targets). Targets
live under `fuzz/fuzz_targets/`.

Run a target:

```shell
cargo fuzz run http1_request_head
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
override the config or set `EXFILGUARD__*` environment variables.

## Metrics

Set `metrics_listen = "127.0.0.1:9090"` in your config to expose Prometheus
metrics at `/metrics`. Provide `metrics_tls_cert` and `metrics_tls_key` to serve
the endpoint over HTTPS.

## Learn more

- `examples/full/` shows both inspect and pass-through rules plus a multi-client
  layout.

## License

ExfilGuard is available under the terms of the Apache License, Version 2.0. See
`LICENSE` for the full text.
