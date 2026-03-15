# Repository Guidelines

## Project Structure & Module Organization
- `src/cli.rs` defines the binary entrypoint; `src/config/`, `src/policy/`, `src/proxy/`, and `src/tls/` hold config parsing, policy evaluation, proxy front-ends, and CA/leaf cache logic.
- `examples/` contains ready-to-run configs (`quickstart/`, `full/`); copy and tweak rather than editing in place.
- `tests/` hosts integration suites; unit tests live alongside modules. `fuzz/` contains AFL targets for untrusted inputs. `docs/` and `ROADMAP.md` track broader guidance; `packaging/` covers the Debian build.
- `hooks/pre-commit` enforces formatting; symlink it into `.git/hooks/` when developing locally.

## Build, Test, and Development Commands
- Run locally with sample config: `cargo run -- --config examples/quickstart/exfilguard.toml`.
- Required hygiene before push: `cargo fmt`, `cargo clippy --all-targets --all-features`, and the full test suite `cargo test` (it runs quickly).
- Targeted runs: `cargo test --test bump_integration` for the main proxy integration path; add specific modules with `cargo test module_name`.
- Fuzz specific parsers when changing request handling: `cargo fuzz run http1_request_head` (add `-- -jobs=8 -workers=8` for parallelism).
- Package release binary: `cargo build --release`; Debian artifact via `cargo deb` after installing `cargo-deb`.

## Coding Style & Naming Conventions
- Rustfmt defaults (4-space indent, 100-col wrap); no manual alignment. Keep imports grouped by std / third-party / crate and keep `cargo clippy --all-targets --all-features` clean.
- Types and enums use `PascalCase`; modules, functions, and locals use `snake_case`. Config keys mirror TOML schema; match existing naming in `examples/`.
- Logs should be structured and explicit about policy outcomes; avoid ad-hoc `println!`.

## Design Priorities
- Prefer the best end-state design for ExfilGuard's goals over the smallest or lowest-risk patch when those trade off.
- Preserve transparent forwarding semantics so upstream-visible request targets and signed requests keep working unless a change is explicitly intended to alter forwarding behavior.
- Keep policy evaluation based on a separate canonical request view so rules are not a syntax footgun.
- Reject ambiguous or unsafe request syntax rather than silently rewriting forwarded bytes into a different meaning.
- When a step change is clearly good, self-contained, and all standard checks pass (`cargo fmt`, `cargo clippy --all-targets --all-features`, and `cargo test` unless a narrower scope is explicitly justified), prefer committing it promptly instead of waiting for a larger batch.

## Testing Guidelines
- Always run `cargo test` (full suite) before merging; add focused cases but keep runtime short.
- Favor deterministic tests that avoid external networks; reuse fixtures from `examples/` or generate temp dirs under `/tmp/exfilguard/*`.
- Integration tests spin an in-process proxy; keep ports ephemeral and clean up temporary artifacts.
- Add fuzz seeds when fixing parser bugs; place new targets under `fuzz/fuzz_targets/` and document inputs.

## Commit & Pull Request Guidelines
- Commit messages are short, imperative summaries (e.g., “Require explicit CONNECT port”); avoid prefixes unless needed for release tags.
- Before committing, run `cargo clippy --all-targets --all-features` in addition to formatting and relevant tests.
- PRs should describe behavior changes, configs touched, and risk areas; link issues and include repro steps or sample commands.
- Update relevant docs (`README.md`, `docs/`, `examples/`) alongside code. Include test commands run; add screenshots only when UI/CLI output materially changes.

## Release Versioning
- Bump `version` in `Cargo.toml` and update `Cargo.lock` (see past release commit for the pattern).
- Commit as `Release vX.Y.Z`, then create an annotated tag `vX.Y.Z` with message `Release vX.Y.Z`.

## Security & Configuration Tips
- Default config search is `/etc/exfilguard/exfilguard.toml`, then `./exfilguard.toml`; keep CA material (`--ca-dir`, `cert_cache_dir`) on restricted storage (`chmod 700` directories, files 0o600).
- Run as a non-root user and bind only needed interfaces; leave `allow_private_upstream = false` unless required.
- Treat logs and metrics as sensitive; set `metrics_tls_cert`/`metrics_tls_key` when exposing Prometheus at `metrics_listen`.
