# ExfilGuard Roadmap

## Policy Language Extensions
- Conditional rules (office-hour windows, request header predicates, payload
  size/type hints) that let operators express more context without embedding Lua
  or external hooks.
- Client-scoped variables (e.g., `bucket_name`, `tenant_id`) that can be
  interpolated inside URL patterns such as
  `https://{bucket_name}-backups.s3.aws.com/**`, reducing duplicate policies.

## Identity & Secrets
- Let the authorization service receive an authenticated client identity.
  Today it receives only the source IP and configured audience.
- Support secret managers other than Vault for externally managed certificates
  and policy values.

## Body Inspection
- Inspect request and response bodies for sensitive patterns (credit card numbers,
  API keys, PII) and block or flag matches.
- Content-type aware scanning (JSON, form data, multipart uploads).
- Configurable pattern sets per policy.

## Nice-to-haves
- “Why was this blocked?” tooling that can replay a request through the matcher
  and produce a human-readable explanation before rollout.
