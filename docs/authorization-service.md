# Authorization Service API

An authorization service has two HTTPS JSON endpoints. The policy endpoint returns rules for an
authorization token. The credential endpoint returns authentication headers for one allowed request.

ExfilGuard uses the same client certificate and limit on simultaneous calls for both endpoints. It
does not follow redirects or use proxy settings from the environment. All bodies use
`application/json`. Unknown fields in a response are rejected.

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
      "url_pattern": "https://api.example.net/v1/**",
      "credential": {
        "credential_reference": "build-api",
        "protected_headers": ["authorization"],
        "body_access": "bounded_payload"
      }
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

Only an allow rule may contain `credential`. ExfilGuard treats `credential_reference` only as a
name. The reference, requested headers, body access, and request URL must fit a `credential_limit`
on the selected client.

An inactive response needs only `{"active": false}`. This version supports only an exact
`source_ip` constraint; authenticated connection identities are not yet supported. `policy_version`
is an identifier containing 1 to 128 visible ASCII bytes.

## Authentication headers

After both policies allow the request, ExfilGuard resolves and checks the destination and builds the
exact outgoing request. It then sends this JSON to the same authorization service:

```json
{
  "authorization_token": "example-token",
  "credential_reference": "build-api",
  "audience": "deployment-prod",
  "source_ip": "192.0.2.10",
  "request_nonce": "c0f515dd-6c97-4059-b2b8-4cc32abdf32f",
  "request_fingerprint": [148, 139, 21, 38, 21, 47, 137, 57, 194, 172, 55, 55, 203, 12, 63, 161, 6, 137, 2, 21, 28, 27, 171, 182, 35, 230, 249, 248, 166, 243, 28, 202],
  "finalized_request": {
    "version": 1,
    "scheme": "https",
    "origin_host": "api.example.net",
    "effective_port": 443,
    "authority": "api.example.net",
    "method": "POST",
    "raw_path_and_query": [47, 118, 49, 47, 105, 116, 101, 109, 115],
    "headers": [
      {"name": "host", "value": [97, 112, 105, 46, 101, 120, 97, 109, 112, 108, 101, 46, 110, 101, 116]},
      {"name": "content-length", "value": [51]},
      {"name": "authorization", "value": []}
    ],
    "protected_header_slots": ["authorization"],
    "body_kind": "buffered_payload",
    "body": [97, 98, 99],
    "payload_length": 3,
    "trailers": null
  }
}
```

Byte strings and the 32-byte fingerprint are JSON arrays of unsigned byte values. Header order and
duplicate headers matter. Headers that the service must fill have empty values at this stage.

The service returns:

```json
{
  "request_nonce": "c0f515dd-6c97-4059-b2b8-4cc32abdf32f",
  "request_fingerprint": [148, 139, 21, 38, 21, 47, 137, 57, 194, 172, 55, 55, 203, 12, 63, 161, 6, 137, 2, 21, 28, 27, 171, 182, 35, 230, 249, 248, 166, 243, 28, 202],
  "expires_at": 1893455910,
  "protected_headers": [
    {"name": "authorization", "value": [66, 101, 97, 114, 101, 114, 32, 46, 46, 46]}
  ]
}
```

The response must echo the full nonce and fingerprint, have an expiry in the future, and return
exactly one value for every approved header and no others.

ExfilGuard rejects malformed, duplicate, missing, hop-by-hop, framing, forwarding, proxy, cookie,
and unapproved headers. It checks the expiry when accepting the response. The request may finish
after that time because it is already in progress. The response is never cached, retried, or reused.
Before sending the request, ExfilGuard checks once more that its fingerprint has not changed.

The fingerprint is SHA-256 over the ASCII text `exfilguard:finalized-request:v1`, one NUL byte, and
one definite-length CBOR map. The map uses these integer keys in order. Every length must use the
shortest valid CBOR encoding.

| Key | Field | CBOR type |
| ---: | --- | --- |
| 0 | version | unsigned integer |
| 1 | scheme | text string |
| 2 | normalized origin host | text string |
| 3 | effective port | unsigned integer |
| 4 | generated authority | text string |
| 5 | method | text string |
| 6 | raw path and query | byte string |
| 7 | ordered headers | array of two-element `[text string, byte string]` arrays |
| 8 | protected header slots | array of text strings |
| 9 | body kind | text string |
| 10 | payload | byte string |
| 11 | payload length | unsigned integer |
| 12 | trailers | null |

Headers that the service must fill are encoded with empty byte-string values. For the request above,
the fingerprint is
`948b1526152f8939c2ac3737cb0c3fa1068902151c1babb623e6f9f8a6f31cca`.
