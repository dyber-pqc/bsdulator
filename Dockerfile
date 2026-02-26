# Stage 1: Build
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Makefile ./
COPY src/ src/
COPY include/ include/

RUN make && strip bsdulator lochs

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/bsdulator

# Copy binaries from builder
COPY --from=builder /build/bsdulator /usr/local/bin/
COPY --from=builder /build/lochs /usr/local/bin/

# Copy scripts
COPY scripts/ scripts/
RUN chmod +x scripts/*.sh

# FreeBSD root will be mounted or downloaded at runtime
VOLUME ["/opt/bsdulator/freebsd-root"]

ENTRYPOINT ["bsdulator"]
