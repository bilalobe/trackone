# syntax=docker/dockerfile:1

FROM rust:1.93-slim AS builder
WORKDIR /workspace
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --locked --release --package trackone-gateway \
    --features v2-service --bin trackone-v2-gateway

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl openssl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /workspace/target/release/trackone-v2-gateway /usr/local/bin/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/trackone-v2-gateway"]
