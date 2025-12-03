# ExfilGuard

**Egress proxy for data exfiltration prevention**

Control and monitor outbound HTTP/HTTPS traffic from your organization. Enforce per-client policies that determine exactly which external endpoints are reachable.

---

## What is ExfilGuard?

ExfilGuard is a Rust-based egress proxy that acts as a gatekeeper for all outbound traffic. It solves the critical security problem of **data exfiltration prevention** by ensuring that internal services and applications can only send data to explicitly approved external endpoints.

Organizations face risks from malicious insiders, compromised services attempting to exfiltrate sensitive data, accidental data leakage through misconfigured integrations, and compliance violations when data leaves uncontrolled. ExfilGuard addresses all of these by enforcing fine-grained, per-client policies at the application layer.

---

## Key Features

**Per-Client Policy Enforcement**
:   Map clients by exact IP address or CIDR ranges. Each client references ordered policies; the first matching rule wins.

**Fine-Grained URL Matching**
:   Policies specify allowed destinations using glob patterns for hostnames and regex patterns for paths.

**TLS Inspection**
:   Terminates TLS and mints leaf certificates on-the-fly for full request/response inspection including headers and body.

**Pass-Through Mode**
:   Tunnel CONNECT streams without decryption for services that use certificate pinning or refuse MITM.

**Hot-Reload Configuration**
:   Supports SIGHUP signal to reload configuration without restarting the process. Zero downtime policy updates.

**Structured Logging**
:   JSON or text format logging with decision tracking. Logs each request's allow/deny decision with structured metadata.

**Metrics Exporter**
:   Optional Prometheus endpoint (`/metrics`) with counters/histograms per client/policy for traffic, decisions, cache, and pool health. Supports HTTPS when given a cert/key.

---

## Use Cases

### Data Exfiltration Prevention

Block unauthorized attempts to send data to cloud storage, analytics platforms, or communication services.

### Compliance & Audit

Generate audit logs showing all external data flows. Demonstrate to regulators what data can leave your organization.

### Multi-Tenant SaaS

Control what external APIs different backend services can reach. Prevent rogue services from connecting to unauthorized platforms.

### Integration Management

Control integrations with external partners. Enforce OAuth/API credentials usage policies by restricting host access.

---

## Installation

### 1. Add the APT repository

```bash
# Add ExfilGuard repository
echo "deb [trusted=yes] https://laurikari.github.io/exfilguard/apt ./" | \
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

### Allow specific API endpoint

```toml
# Allow analytics service to reach trusted endpoint
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
inspect_payload = false
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

## Next Steps

- [Configuration Reference](configuration.md) - Global settings and options
- [Policies Guide](policies.md) - Client mapping and policy rules
