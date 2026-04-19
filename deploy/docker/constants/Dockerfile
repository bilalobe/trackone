# syntax=docker/dockerfile:1
# trackone/constants:local
#
# Smoke-test image for trackone-constants.

FROM rust:1.87-slim

WORKDIR /workspace

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates/trackone-constants/Cargo.toml crates/trackone-constants/Cargo.toml
COPY crates ./crates

RUN cargo build -p trackone-constants

CMD ["bash", "-lc", "echo 'trackone-constants built successfully'" ]
