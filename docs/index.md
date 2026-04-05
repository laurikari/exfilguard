# ExfilGuard

**Egress proxy for outbound HTTP and HTTPS**

Control outbound HTTP and HTTPS traffic. Set per-client rules for which
external endpoints are reachable, and log what happened.

---

## What is ExfilGuard?

ExfilGuard is an explicit egress proxy written in Rust. Clients should know
they are talking to a proxy. Each request is checked against the client's
policy, then either forwarded or denied.

The main use case is simple: internal services should only reach approved
external endpoints. ExfilGuard helps enforce that and leaves an audit trail in
the logs.

ExfilGuard targets Unix-like systems only; Windows is not supported.

---

## Key Features

**Per-Client Policy Enforcement**
:   Map clients by exact IP address or CIDR ranges. Each client references ordered policies; the first matching rule wins.

**URL Matching**
:   Policies specify allowed destinations using wildcard patterns for hostnames and paths.

**TLS Inspection**
:   Terminates TLS and mints leaf certificates on the fly so ExfilGuard can apply normal HTTP rules to the decrypted request.

**Pass-Through Mode**
:   Tunnels CONNECT streams without decryption for services that use certificate pinning or do not allow TLS interception.

**Optional Response Caching**
:   Shared HTTP response cache that follows standard cache headers. Enable it globally and opt in per rule.

**Private Upstream Blocking**
:   Blocks upstream connections to non-public addresses to reduce SSRF risk.

**Runtime Policy Reload**
:   `SIGHUP` reloads client and policy data from the configured files without restarting the process. If you change listener, metrics, cache, TLS, logging, or timeout settings, restart the server.

**Structured Logging**
:   JSON or text logs with the allow or deny decision and related request metadata.

**Metrics Exporter**
:   Optional Prometheus endpoint (`/metrics`) with counters and histograms for traffic, decisions, effective mode (`direct`, `bump`, `tunnel`), cache, and pool health. Supports HTTPS when given a cert and key.

---

## Use Cases

### Data Exfiltration Prevention

Block attempts to send data to unapproved cloud storage, analytics, or
communication services.

### Compliance & Audit

Keep audit logs of outbound traffic. Show which destinations are allowed and
which requests were blocked.

### Multi-Tenant SaaS

Control which external APIs different backend services can reach. Stop one
service from talking to destinations meant for another.

### Integration Management

Control integrations with external partners. Restrict which hosts and paths
each service may use.

---

## Installation

### 1. Add the APT repository

```bash
# Download and install the signing key
curl -fsSL https://laurikari.github.io/exfilguard/apt/exfilguard.gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/exfilguard.gpg

# Add ExfilGuard repository
echo "deb [signed-by=/etc/apt/keyrings/exfilguard.gpg] https://laurikari.github.io/exfilguard/apt ./" | \
  sudo tee /etc/apt/sources.list.d/exfilguard.list
sudo apt update
```

### 2. Install ExfilGuard

```bash
sudo apt install exfilguard
```

### 3. Configure and start

```bash
# Edit configuration
sudo nano /etc/exfilguard/exfilguard.toml

# Start the service
sudo systemctl enable --now exfilguard
```

---

## Quick Examples

These examples assume ExfilGuard is being used as an explicit proxy.

### Allow specific API endpoint

```toml
# Allow analytics service to reach trusted endpoint
# HTTPS inspect rules authorize TLS bump preflight for the same host/port.
[[policy.rule]]
action = "ALLOW"
methods = ["GET", "POST"]
url_pattern = "https://api.trusted-analytics.com/v1/exports/**"
```

### Pass-through for certificate-pinned services

```toml
# Payment gateway with certificate pinning
[[policy.rule]]
action = "ALLOW"
methods = ["CONNECT"]
url_pattern = "https://secure.payment-gateway.com/**"
https_mode = "tunnel"
```

### Client mapping by CIDR

```toml
# Map internal subnet to specific policies
[[client]]
name = "analytics-workers"
cidr = "10.42.16.0/27"
policies = ["analytics-policy", "default-deny"]
```

---

## Further Reading

- [Configuration Reference](configuration.md) - Global settings and options
- [Policies Guide](policies.md) - Client mapping and policy rules
- [Design Decisions](design-decisions.md) - Why the code works this way
