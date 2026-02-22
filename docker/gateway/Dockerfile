# syntax=docker/dockerfile:1
# TrackOne gateway image for local Kubernetes development.
#
# NOTE: crates/trackone-gateway is a PyO3 extension module (cdylib), not a Rust binary.
# This image builds the extension and runs a tiny Python HTTP server (FastAPI) exposing /health.

FROM rust:1.87-slim AS builder

WORKDIR /workspace

# Build deps: OpenSSL for Rust TLS stacks, plus Python headers/interpreter for pyo3 build scripts.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    pkg-config \
    libssl-dev \
    python3 \
    python3-dev \
 && rm -rf /var/lib/apt/lists/*

# Pre-copy manifests for better layer caching.
COPY Cargo.toml Cargo.lock ./
COPY crates/trackone-gateway/Cargo.toml crates/trackone-gateway/Cargo.toml
COPY crates ./crates

# Build the extension module in release mode.
RUN cargo build -p trackone-gateway --release

# The produced artifact is a shared library. Install it under the Python package
# layout so `import trackone_core` works (native module: trackone_core._native).
RUN ls -la /workspace/target/release/libtrackone.so \
 && EXT_SUFFIX="$(python3-config --extension-suffix)" \
 && mkdir -p /workspace/trackone_core \
 && cp /workspace/target/release/libtrackone.so "/workspace/trackone_core/_native${EXT_SUFFIX}"

FROM python:3.12-slim

WORKDIR /app

# Runtime deps for a small HTTP server.
COPY docker/gateway/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Install the extension module into Python's site-packages.
COPY trackone_core /usr/local/lib/python3.12/site-packages/trackone_core
COPY --from=builder /workspace/trackone_core/_native*.so /usr/local/lib/python3.12/site-packages/trackone_core/

COPY docker/gateway/server.py /app/server.py
COPY docker/gateway/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
