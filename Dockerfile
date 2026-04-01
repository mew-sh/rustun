# ============================================================================
# Multi-stage build for rustun
# ============================================================================
# Stage 1: Build
# ============================================================================
FROM rust:1.82-bookworm AS builder

WORKDIR /usr/src/rustun

# Cache dependency build: copy manifests first, create dummy main, build deps
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && \
    echo 'fn main() { println!("placeholder"); }' > src/main.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

# Copy actual source and build
COPY src/ src/
RUN cargo build --release

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
