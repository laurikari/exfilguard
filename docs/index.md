# ExfilGuard

**Control and audit outbound network access.**

Restrict workloads to approved destinations and let them use APIs without
receiving API keys. Sandbox AI agents and limit the damage from supply chain
attacks or operator mistakes.

---

## What is ExfilGuard?

ExfilGuard is an explicit HTTP and HTTPS egress proxy written in Rust for
Unix-like systems. Each request is checked against the client's policy, then
either forwarded or denied.

---

## Use Cases

### AI Agents and Other Untrusted Workloads

Let a coding agent fetch dependencies and call approved APIs while limiting the
hosts, paths, and HTTP methods it can use. Lease tokens give it API access while
the API credentials stay outside the agent. The agent cannot leak credentials
it does not have, including by sending them to an LLM.

### Compromised Dependencies

Limit the destinations a service or build job can reach if a dependency is
compromised. Attempts to upload data or contact an attacker at an unapproved
destination are blocked and logged.

### Operator Mistakes

Restrict development tools and maintenance scripts to their intended services.
A policy that permits only test endpoints blocks a command accidentally
pointed at a production API.

### Audit and Investigation

Trace outbound requests to a configured client and see which were allowed or
denied. Use the logs to investigate unexpected destinations and review whether
services still need the access they have.

---

## Key Features

**Per-Client Policy Enforcement**
:   Apply policies by source address and optional password or lease-token credentials.

**API Access Without API Keys**
:   Give workloads scoped API access through lease tokens while keeping the API credentials outside the workload. See [delegated authorization](configuration.md#delegated-authorization).

**URL Matching**
:   Policies specify allowed destinations using wildcard patterns for hostnames and paths.

**TLS Inspection**
:   Apply HTTP method and URL rules to HTTPS requests.

**Pass-Through Mode**
:   Tunnels CONNECT streams without decryption for services that use certificate pinning or do not allow TLS interception.

**Optional Response Caching**
:   Shared HTTP response cache that follows standard cache headers. Enable it globally and opt in per rule.

**Private Upstream Blocking**
:   Blocks non-public upstream addresses by default, with explicit CIDR exceptions for internal services.

**Runtime Policy Reload**
:   Reload client and policy data without restarting ExfilGuard.

**Structured Logging**
:   JSON or text logs with the allow or deny decision and related request metadata.

**Metrics Exporter**
:   Monitor traffic, policy decisions, connections, and cache usage with Prometheus.

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

### Allow specific API endpoint

```toml
# Allow analytics service to reach trusted endpoint
# HTTPS inspect ALLOW rules authorize TLS bump preflight for the same host/port.
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
- [Authorization Service API](authorization-service.md) - Policy decisions and
  authentication headers
- [Policies Guide](policies.md) - Client mapping and policy rules
- [Design Decisions](design-decisions.md) - Why the code works this way
