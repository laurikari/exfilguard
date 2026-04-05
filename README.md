# ExfilGuard

ExfilGuard is a Rust egress proxy for outbound HTTP and HTTPS. Clients use it
as an explicit proxy. ExfilGuard checks each request against the client's
policy, logs the decision, and then either forwards or denies it.

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
Accepts raw TCP connections and hands them to the dispatcher.

### 2. The Dispatcher Layer (`src/proxy/http/dispatch.rs`)
Figures out whether the connection is HTTP/1.1, HTTP/2, or CONNECT. If a
`CONNECT` request has matching HTTPS inspect rules, it starts the TLS bump
flow.

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

`SIGHUP` reloads only the client/policy data from the already configured
`clients`, `clients_dir`, `policies`, and `policies_dir` paths. Changes to
`exfilguard.toml` itself, including listener, metrics, cache, TLS, logging, and
timeout settings, require restarting the process.

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
- `src/policy/` — policy compiler and matcher.
- `src/proxy/` — listeners, HTTP handlers, and upstream clients.
- `src/tls/` — CA lifecycle plus the on-disk leaf cache.
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

ExfilGuard keeps the raw request target for upstream forwarding, logging, cache
keys, and signature-sensitive traffic. Policy evaluation uses a separate
canonical path view so rule matching does not depend on origin-specific path
normalization.

- Query strings are ignored for path matching.
- Literal `.` and `..` path segments are normalized before policy evaluation.
- Ambiguous path syntax is rejected with `400 Bad Request` instead of being
  silently rewritten. This includes invalid escapes, backslashes, encoded path
  separators, and encoded dot-segments such as `%2e%2e`.

## Security

ExfilGuard controls what outbound traffic is allowed and logs everything for
review. It blocks requests to destinations not on your allow list and records
any blocked attempts.

### What it does and doesn't do

**Does:**
- Block outbound requests to hosts/paths you haven't allowed
- Log all traffic (allowed and blocked)
- Drop slow or stalled connections via timeouts

**Doesn't:**
- Inspect request or response bodies
- Stop data from leaving through allowed destinations
- Detect compromised clients misusing allowed routes

### Defense in depth

ExfilGuard does not fully trust clients or upstreams. It rejects malformed
requests, slow connections, and oversized headers or bodies early. Parsing is
strict, and policy checks run before any upstream connection is made.

### Hardening tips

- Use the `.deb` package for production—it creates a dedicated user and sets
  sane defaults.
- Run as a non-root user and only listen on the interfaces you need. Put a
  firewall in front.
- Lock down `ca_dir` with strict file permissions. Back up and rotate the CA
  files regularly.
- Review timeout and size limits for your setup (see `docs/configuration.md`).
- Set `max_request_body_size`, `max_request_header_size`, and
  `max_response_header_size` to reasonable values.
- ExfilGuard blocks private upstreams by default, including loopback and
  RFC1918/RFC4193 space. This reduces SSRF risk and keeps clients from
  reaching internal address space through the proxy.
- Treat logs and metrics as sensitive—they contain internal hostnames and can
  reveal unusual traffic patterns.

## Limitations

- Use ExfilGuard as an explicit proxy. Transparent interception is not
  documented or supported for deployment.
- ExfilGuard does not support WebSocket or HTTP/1.1 Upgrade flows. It rejects
  upstream `101 Switching Protocols` responses instead of tunneling them.
- ExfilGuard rejects HTTP/1.0 requests and upstream HTTP/1.0 responses. It
  only supports HTTP/1.1 framing.

### TLS inspection vs. pass-through

Each HTTPS policy rule declares an explicit mode:

- `https_mode = "inspect"` (default) terminates TLS so the proxy can enforce
  scheme, host, path, and method checks on the inner HTTP request. Matching
  HTTPS rules authorize a TLS bump preflight for the same host/port, but the
  real policy decision is attached to the inner request. Private upstream
  addresses are still blocked.
- `https_mode = "tunnel"` only enforces scheme/host/port on the outer CONNECT.
  These rules must use `methods = ["CONNECT"]` and a `url_pattern` ending in
  `/**`, making it clear that the intent is to tunnel the host untouched. Use
  this for pinned TLS or non-HTTP payloads that cannot tolerate TLS
  interception.

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
4. Tunnel-mode CONNECT rules stream bytes once allowed; inspect-mode HTTPS rules
   authorize TLS bump preflight and then evaluate the inner request normally.

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
material. ExfilGuard writes files with `0o600`, but you must also secure the
directories, for example with `chmod 700`. Anyone who can read them can mint
certificates or impersonate the proxy, so run ExfilGuard as an unprivileged
user and store the CA on trusted disks.

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

ExfilGuard fuzzes the parsers and request-handling paths that process untrusted
input, including HTTP/1 request and response parsing, chunked bodies, HTTP/2
request sanitization, and CONNECT targets. Targets live under
`fuzz/fuzz_targets/`.

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
the endpoint over HTTPS. Use this listener for internal access only. Keep it
firewalled to Prometheus, or put an authenticating reverse proxy in front of
it, because the metrics include internal hosts and policy decisions. Request
series are labeled with `effective_mode=direct|bump|tunnel`, so inspected HTTPS
and explicit CONNECT tunnels stay distinct.

## Learn more

- `examples/full/` shows both inspect and pass-through rules plus a multi-client
  layout.

## License

ExfilGuard is available under the terms of the Apache License, Version 2.0. See
`LICENSE` for the full text.
