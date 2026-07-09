# syntax=docker/dockerfile:1
# trackone/pod-fw:local
#
# A lightweight container that builds the pod firmware crate.
# This isn't a long-running service; it's a reproducible build artifact check.

FROM rust:1.88-slim

WORKDIR /workspace

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    bash \
 && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates/trackone-pod-fw/Cargo.toml crates/trackone-pod-fw/Cargo.toml
COPY crates ./crates

# Vendor dependencies at image build time so the in-cluster Job can run fully offline.
RUN mkdir -p .cargo && \
    cargo vendor /workspace/vendor > /workspace/.cargo/config.toml

ENV TRACKONE_POD_FW_FEATURES="production"
ENV TRACKONE_POD_FW_NO_DEFAULT_FEATURES="1"
ENV TRACKONE_POD_FW_RELEASE="1"

CMD bash -lc 'set -euo pipefail; \
  FEATURES="${TRACKONE_POD_FW_FEATURES:-production}"; \
  NODEFAULT="${TRACKONE_POD_FW_NO_DEFAULT_FEATURES:-1}"; \
  RELEASE="${TRACKONE_POD_FW_RELEASE:-1}"; \
  echo "Building trackone-pod-fw (features=${FEATURES}, no_default_features=${NODEFAULT}, release=${RELEASE})"; \
  EXTRA=" --offline"; \
  if [ "${NODEFAULT}" = "1" ]; then EXTRA="$EXTRA --no-default-features"; fi; \
  if [ -n "${FEATURES}" ]; then EXTRA="$EXTRA --features ${FEATURES}"; fi; \
  if [ "${RELEASE}" = "1" ]; then EXTRA="$EXTRA --release"; fi; \
  cargo --version; rustc --version; \
  cargo build -p trackone-pod-fw ${EXTRA}; \
  echo "trackone-pod-fw built successfully"'
