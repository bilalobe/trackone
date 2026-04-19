# trackone/core:local
#
# Build-only image for trackone-core.
#
# This image is intended to be used by a Kubernetes Job. The Job can set:
# - TRACKONE_CORE_FEATURES="std,gateway"
# - TRACKONE_CORE_NO_DEFAULT_FEATURES="1"
# to validate a specific compile-time feature set.

FROM rust:1.87-slim

WORKDIR /workspace

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    bash \
 && rm -rf /var/lib/apt/lists/*

# The upstream image in this environment provides a toolchain under
# /usr/local/rustup/toolchains but may not have the `rustup` shim binary.
# Ensure we can execute cargo/rustc reliably.
RUN ln -sf /usr/local/rustup/toolchains/1.87.0-x86_64-unknown-linux-gnu/bin/cargo /usr/local/bin/cargo && \
    ln -sf /usr/local/rustup/toolchains/1.87.0-x86_64-unknown-linux-gnu/bin/rustc /usr/local/bin/rustc

COPY Cargo.toml Cargo.lock ./
COPY crates/trackone-core/Cargo.toml crates/trackone-core/Cargo.toml
COPY crates/trackone-constants/Cargo.toml crates/trackone-constants/Cargo.toml
COPY crates ./crates

# Vendor dependencies at image build time so the in-cluster Job can run fully offline.
RUN mkdir -p .cargo && \
    cargo vendor /workspace/vendor > /workspace/.cargo/config.toml

# Default to a normal dev build.
ENV TRACKONE_CORE_FEATURES=""
ENV TRACKONE_CORE_NO_DEFAULT_FEATURES="0"

CMD bash -lc 'set -euo pipefail; \
  FEATURES="${TRACKONE_CORE_FEATURES:-}"; \
  NODEFAULT="${TRACKONE_CORE_NO_DEFAULT_FEATURES:-0}"; \
  echo "Building trackone-core (features=${FEATURES}, no_default_features=${NODEFAULT})"; \
  EXTRA=" --offline"; \
  if [ "${NODEFAULT}" = "1" ]; then EXTRA="$EXTRA --no-default-features"; fi; \
  if [ -n "${FEATURES}" ]; then EXTRA="$EXTRA --features ${FEATURES}"; fi; \
  # shellcheck disable=SC2086 \
  cargo --version; rustc --version; \
  cargo build -p trackone-core ${EXTRA}; \
  echo "trackone-core built successfully"'
