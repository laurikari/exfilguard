# Debian builder container

This directory contains a small `docker compose` stack that builds ExfilGuard's
Debian package inside an Ubuntu 22.04 container. It installs Rust with rustup,
the `cargo-deb` helper, and the minimal system build dependencies ExfilGuard
needs.

## Usage

```bash
cd packaging/deb-container
HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose build
HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose run --rm deb-builder
```

- The UID/GID exports make the container user match your local account so the
  generated files in `target/` stay writable.
- The repository root is bind-mounted at `/workspace` in the container, so the
  `.deb` lands in `target/debian/` inside your checkout.
- Cargo registry/git caches live in Docker volumes (`cargo-registry` and
  `cargo-git`) to speed up repeated builds.

You can override the command that runs inside the container if you need to drop
into an interactive shell:

```bash
HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose run --rm deb-builder bash
```

The compose file keeps everything scoped to this subdirectory so the project
root stays clean.

## Building different architectures

- `deb-builder` follows the Docker host architecture (arm64 on Apple Silicon,
  amd64 on Intel hosts).
- `deb-builder-amd64` forces an `linux/amd64` image so you can produce Intel
  packages even from arm64 hosts:

  ```bash
  cd packaging/deb-container
  HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose build deb-builder-amd64
  HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose run --rm deb-builder-amd64
  ```

Docker Desktop already ships the emulation needed for cross-platform containers.
On native Linux you may need binfmt/qemu support configured (for example via
`docker run --privileged tonistiigi/binfmt` once) before running amd64 builds
from an arm64 host.
