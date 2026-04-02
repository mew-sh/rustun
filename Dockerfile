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

# Copy all source files and build in one step.
# This is simpler and more reliable than a two-stage dependency cache,
# which breaks when lib.rs exports are needed by main.rs.
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY tests/ tests/
RUN cargo build --release

# ============================================================================
# Stage 2: Runtime (minimal image)
# ============================================================================
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        iptables \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/rustun/target/release/rustun /usr/local/bin/rustun

RUN mkdir -p /etc/rustun

EXPOSE 8080 1080 8338 8443

ENTRYPOINT ["rustun"]
CMD ["-L", ":8080"]
