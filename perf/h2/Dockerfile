FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iputils-ping ethtool procps ca-certificates \
    && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
