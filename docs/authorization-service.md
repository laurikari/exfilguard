# Authorization Service API

An authorization service returns request rules for an authorization token over HTTPS.

ExfilGuard uses a client certificate, does not follow redirects or use proxy settings from the
environment, and sends JSON. Unknown fields in a response are rejected.

## Policy

ExfilGuard sends:

```json
{
  "authorization_token": "example-token",
  "audience": "deployment-prod",
  "source_ip": "192.0.2.10"
}
```

An active response has this shape:

```json
{
  "active": true,
  "audience": "deployment-prod",
  "client_constraints": { "source_ip": "192.0.2.10" },
  "expires_at": 1893456000,
  "cache_until": 1893455940,
  "policy_version": "immutable-version-42",
  "rules": [
    {
      "action": "ALLOW",
      "methods": ["GET", "POST"],
      "url_pattern": "https://api.example.net/v1/**"
    },
    {
      "action": "DENY",
      "url_pattern": "https://api.example.net/v1/admin/**"
    }
  ]
}
```

Times are Unix seconds. If `methods` is absent, the rule matches every method. `"ANY"` has the same
meaning and must be the only entry. `CONNECT` is not allowed. Rules are checked in order, and the
first match wins.

An inactive response needs only `{"active": false}`. This version supports only an exact
`source_ip` constraint; authenticated connection identities are not yet supported. `policy_version`
is an identifier containing 1 to 128 visible ASCII bytes.
