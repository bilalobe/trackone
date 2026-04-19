# syntax=docker/dockerfile:1
# trackone/pod-fw:local
#
# A lightweight container that builds the pod firmware crate.
# This isn't a long-running service; it's a reproducible build artifact check.

FROM rust:1.87-slim

WORKDIR /workspace

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates/trackone-pod-fw/Cargo.toml crates/trackone-pod-fw/Cargo.toml
COPY crates ./crates

# Build in release mode; keep default features (std) for now.
RUN cargo build -p trackone-pod-fw --release

# Convenience: verify the built crate exists in target; no runtime entrypoint needed.
CMD ["bash", "-lc", "echo 'pod-fw built successfully'; ls -la target/release | head"]
