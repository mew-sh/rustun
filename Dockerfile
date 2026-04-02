# ============================================================================
# Multi-stage build for rustun
# ============================================================================
# Stage 1: Build
# ============================================================================
FROM rust:1.86-bookworm AS builder

# Install build dependencies for OpenSSL (needed by native-tls)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config libssl-dev perl make && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/rustun

# Cache dependency build: copy manifests first, create dummy src, build deps
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && \
    echo 'fn main() {}' > src/main.rs && \
    echo '' > src/lib.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

# Copy actual source and build
COPY src/ src/
COPY tests/ tests/
RUN touch src/main.rs src/lib.rs && cargo build --release

# ============================================================================
# Stage 2: Runtime
# ============================================================================
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        iptables \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/rustun/target/release/rustun /usr/local/bin/rustun

# Default configuration directory
RUN mkdir -p /etc/rustun

EXPOSE 8080 1080 8338 8443

ENTRYPOINT ["rustun"]
CMD ["-L", ":8080"]
