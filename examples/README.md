# ExfilGuard Examples

Two ready-to-run layouts live under this directory:

- `full/` mirrors a multi-tenant deployment with several CIDR-mapped clients and
  both “inspect” and “pass-through” policies. Use it when experimenting with the
  full feature set.
- `quickstart/` allows `127.0.0.1` to reach `https://www.searchkit.com/faq/**`
  with TLS inspection, plus a deny-all fallback. It’s ideal for smoke tests
  because it exercises the bumping path with the bundled CA.

Each subdirectory ships its own `exfilguard.toml`, `clients.toml`, and
`policies.toml`. Thanks to relative-path resolution, you can launch either
example directly:

```shell
cargo run -- --config examples/quickstart/exfilguard.toml
```
