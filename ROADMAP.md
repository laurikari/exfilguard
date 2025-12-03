# ExfilGuard Roadmap

## Policy Language Extensions
- Conditional rules (office-hour windows, request header predicates, payload
  size/type hints) that let operators express more context without embedding Lua
  or external hooks.
- Client-scoped variables (e.g., `bucket_name`, `tenant_id`) that can be
  interpolated inside URL patterns such as
  `https://{bucket_name}-backups.s3.aws.com/**`, reducing duplicate policies.

## Identity & Secrets
- Support for authenticating clients via proxy auth credentials or mTLS instead
  of just source IPs, so multi-tenant deployments can bind policies to
  people/services directly.
- Optional integrations with secret managers (Vault, etc.) to fetch CA material
  or policy variables at runtime, minimizing long-lived secrets on disk.

## Nice-to-haves
- “Why was this blocked?” tooling that can replay a request through the matcher
  and produce a human-readable explanation before rollout.
