# ============================================================================
# Multi-stage build for rustun
# ============================================================================
# Stage 1: Build -- use latest stable Rust to avoid edition2024 issues
# ============================================================================
FROM rust:latest AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/rustun

COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY tests/ tests/

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

RUN mkdir -p /etc/rustun

EXPOSE 8080 1080 8338 8443

ENTRYPOINT ["rustun"]
CMD ["-L", ":8080"]
