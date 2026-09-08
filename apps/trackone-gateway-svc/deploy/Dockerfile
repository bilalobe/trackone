# syntax=docker/dockerfile:1

FROM rust:1.93-slim AS builder
WORKDIR /workspace
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY apps ./apps
RUN cargo build --locked --release --package trackone-gateway-svc \
    --bin trackone-vtl-gateway

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl openssl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /workspace/target/release/trackone-vtl-gateway /usr/local/bin/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/trackone-vtl-gateway"]
