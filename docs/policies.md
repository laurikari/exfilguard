# Clients & Policies

Define who can access what with client mappings and policy rules.

---

## Client Configuration

Clients map source IP addresses to policies. Defined in `clients.toml` or files in `clients.d/`.

### Client Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | String | Yes | Unique identifier for the client |
| `ip` | String | One of ip/cidr | Single IP address (e.g., `"127.0.0.1"`, `"::1"`) |
| `cidr` | String | One of ip/cidr | CIDR block (e.g., `"10.0.0.0/8"`, `"2001:db8::/32"`) |
| `policies` | Array | Yes | List of policy names to apply in order |
| `catch_all` | Boolean | No | Mark as fallback client (exactly one required) |

### Matching Order

When a request arrives, ExfilGuard determines the client by source IP:

1. **Exact IP match** - Direct IP lookup (O(1))
2. **CIDR match** - Longest prefix match using prefix trie
3. **Catch-all** - Fallback client if no other match

### Validation Rules

- Client names must be unique
- Either `ip` or `cidr` must be specified, not both
- Non-catch-all CIDRs must not overlap
- Exactly one client must have `catch_all = true`
- All referenced policies must exist

### Example

```toml
# Analytics workers subnet
[[client]]
name = "analytics-workers"
cidr = "10.42.16.0/27"
policies = ["analytics-policy", "fallback-deny"]

# Payment gateway subnet
[[client]]
name = "payments-gateway"
cidr = "10.42.48.0/28"
policies = ["payments-policy", "fallback-deny"]

# Localhost for testing
[[client]]
name = "loopback"
ip = "127.0.0.1"
policies = ["local-allow"]

# Catch-all: deny everything else
[[client]]
name = "catch-all"
cidr = "0.0.0.0/0"
policies = ["default-deny"]
catch_all = true
```

---

## Policy Configuration

Policies contain ordered rules that determine whether requests are allowed or denied. Defined in `policies.toml` or files in `policies.d/`.

### Policy Structure

```toml
[[policy]]
name = "policy-name"
  [[policy.rule]]
  # rule fields...
```

Rules are evaluated in order. The first matching rule determines the action.

---

## Rule Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `action` | String | Required | `"ALLOW"` or `"DENY"` |
| `methods` | Array | `["ANY"]` | HTTP methods to match |
| `url_pattern` | String | None | URL pattern to match (see syntax below) |
| `inspect_payload` | Boolean | true | Whether to inspect request/response bodies |
| `allow_private_upstream` | Boolean | false | Allow upstream requests to private IPs (ALLOW only) |
| `cache` | Table | None | Cache configuration (see below) |
| `status` | u16 | Required for DENY | HTTP status code for denial response |
| `reason` | String | None | HTTP reason phrase (DENY only) |
| `body` | String | None | Response body (DENY only) |

### ALLOW vs DENY

#### ALLOW Rules

- Permit the request to proceed upstream
- Must not set `status`, `reason`, or `body`
- Can use `inspect_payload = false` for tunnel mode
- Can set `allow_private_upstream = true`

#### DENY Rules

- Block the request with specified response
- Must set `status` (HTTP status code)
- Optional: `reason` and `body`
- Cannot use `allow_private_upstream`

---

## HTTP Methods

Valid method values:

- `"ANY"` - Matches all methods (default)
- `"GET"`, `"POST"`, `"PUT"`, `"PATCH"`, `"DELETE"`
- `"HEAD"`, `"OPTIONS"`, `"TRACE"`, `"CONNECT"`

```toml
# Single method
methods = ["GET"]

# Multiple methods
methods = ["GET", "POST", "DELETE"]

# Any method (default)
methods = ["ANY"]
```

!!! note
    Cannot mix `"ANY"` with explicit methods in the same array.

---

## URL Pattern Syntax

URL patterns follow the format: `scheme://host[:port][/path]`

### Scheme

`http` or `https` (required)

### Host Matching

| Pattern | Matches |
|---------|---------|
| `example.com` | Exact domain |
| `*.example.com` | Exactly one subdomain label of example.com |
| `**.example.com` | Any depth of subdomains of example.com (one or more) |
| `example.**` | Any suffix depth under example |
| `*` | Any host |
| `192.0.2.1` | Exact IPv4 address |
| `[2001:db8::1]` | Exact IPv6 address (bracketed) |

!!! note
    Host matching is case-insensitive. Wildcards can only appear as entire labels: `*.example.com` and `**.example.com` are valid, `a*b.com` is not. `*` matches a single label and `**` matches one or more labels.

### Port

Optional. Defaults to 80 for HTTP, 443 for HTTPS.

```toml
url_pattern = "https://example.com:8443/api/**"
```

### Path Matching

| Pattern | Matches |
|---------|---------|
| `/api/v1/users` | Exact path |
| `/users/*` | Single segment: `/users/123`, `/users/abc` |
| `/api/**` | Any depth: `/api/v1`, `/api/v1/users/123` |
| `/users/*/profile` | `/users/123/profile`, `/users/abc/profile` |

!!! note
    Query strings are ignored when evaluating path patterns.

### Complete Examples

```toml
# HTTPS to specific API endpoint
"https://api.example.com/v1/exports/**"

# Any subdomain of partner.com on custom port
"https://*.partner.com:8443/payments/**"

# HTTP to any host, specific path
"http://*/health"

# IPv6 address
"https://[2001:db8::1]/api/**"
```

---

## Payload Inspection

The `inspect_payload` option controls whether ExfilGuard inspects request/response bodies.

### inspect_payload = true (default)

- Full HTTP inspection including headers and body
- TLS is terminated and re-encrypted (MITM)
- Required for non-CONNECT methods
- Enables response filtering and logging

### inspect_payload = false (tunnel mode)

- Traffic is tunneled without inspection
- Only valid with `methods = ["CONNECT"]`
- Only valid with URL pattern ending in `/**`
- Useful for certificate-pinned services that refuse MITM

!!! warning
    Tunnel mode bypasses content inspection. Use only when necessary (e.g., payment gateways with certificate pinning).

---

## Response Caching

Rules can enable caching for matched responses. Requires `cache_dir` in global config.

```toml
[[policy.rule]]
action = "ALLOW"
methods = ["GET"]
url_pattern = "https://cdn.example.com/**"
  [policy.rule.cache]
  force_cache_duration = 3600  # Fallback: cache for 1 hour
```

| Field | Type | Description |
|-------|------|-------------|
| `force_cache_duration` | u64 | Fallback cache lifetime in seconds (used only when upstream sends no cache headers) |

### How Caching Works

The cache respects standard HTTP caching headers from upstream:

- **Cache-Control**: `s-maxage`, `max-age`, `private`, `no-store`
- **Expires**: HTTP date for expiration
- **Vary**: Responses vary by specified request headers

`force_cache_duration` is a **fallback only** - it does not override upstream headers. It only applies when the upstream server sends no cache directives.

!!! note
    Only `GET` and `HEAD` responses with status 200, 203, 204, 205, 206, 301, or 302 are cached. See [Cache Settings](configuration.md#cache-settings) for full details.

---

## Complete Examples

### Deny-All Fallback

```toml
[[policy]]
name = "fallback-deny"
  [[policy.rule]]
  action = "DENY"
  status = 470
  reason = "Policy Blocked"
  body = "Blocked by ExfilGuard\n"
```

### Allow Specific API Endpoints

```toml
[[policy]]
name = "api-policy"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["GET", "POST"]
  url_pattern = "https://api.trusted.com/v1/exports/**"

  [[policy.rule]]
  action = "ALLOW"
  methods = ["ANY"]
  url_pattern = "https://reports.trusted.com/dashboards/**"
```

### Certificate-Pinned Service (Tunnel)

```toml
[[policy]]
name = "pinned-payments"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["CONNECT"]
  url_pattern = "https://secure.partner.com/**"
  inspect_payload = false
  allow_private_upstream = true
```

### Cached Static Content

```toml
[[policy]]
name = "cached-content"
  [[policy.rule]]
  action = "ALLOW"
  methods = ["GET"]
  url_pattern = "https://cdn.example.com/**"
    [policy.rule.cache]
    force_cache_duration = 3600
```
