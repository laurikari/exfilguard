# Build container for creating ExfilGuard Debian packages
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        curl \
        git \
        libssl-dev \
        llvm \
        pkg-config \
        sudo \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

ARG UID=1000
ARG GID=1000
RUN if ! getent group "${GID}" >/dev/null; then groupadd --gid "${GID}" builder; fi \
    && useradd --uid "${UID}" --gid "${GID}" --home-dir /home/builder --create-home builder

USER builder
ENV PATH=/home/builder/.cargo/bin:${PATH}
ENV CARGO_HOME=/home/builder/.cargo
ENV RUSTUP_HOME=/home/builder/.rustup
WORKDIR /workspace

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
RUN cargo install cargo-deb

CMD ["bash"]
