# TrackOne workspace tasks
# Run with: just <command>
# Install just: cargo install just

# Default recipe shows help
default:
    @just --list

# Re-run the v2 verifier against the checked-in signed Class-A fixture.
verify bundle_dir="toolset/vectors/verifiable-telemetry-canonical-cbor-v2/fixtures/corrected-epoch-class-a":
    cargo run --locked --package trackone-evidence -- verify --root {{bundle_dir}} --tsa-ca-file toolset/vectors/verifiable-telemetry-canonical-cbor-v2/trust/tsa-root.pem --tsa-crls-file toolset/vectors/verifiable-telemetry-canonical-cbor-v2/trust/tsa-crls.pem --tsa-policy 1.3.6.1.4.1.55555.1 --tsa-signer-cert-sha256 14ab98cafe09d9d1d01562af42d69a904b01023d9cd5b03bd07e5779710c8014

# Enforce reusable-library and application dependency direction.
boundaries:
    python3 toolset/ci/check_workspace_boundaries.py

# Run all tests with correct feature combinations
test:
    cargo test --workspace --locked
    cargo test --locked --package trackone-core --features std,postcard,dummy-aead
    cargo test --locked --package trackone-ingest --features std,xchacha
    cargo test --locked --package trackone-pod-fw --features std
    cargo test --locked --package trackone-ledger --test vector_corpus -- --ignored

# Run clippy with correct features (avoid --all-features due to production+dummy-aead conflict)
clippy:
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo clippy --locked --package trackone-core --all-targets --features std,postcard,dummy-aead -- -D warnings
    cargo clippy --locked --package trackone-ingest --all-targets --features std,xchacha -- -D warnings
    cargo clippy --locked --package trackone-pod-fw --all-targets --features std -- -D warnings

# Build all packages in release mode
build-release:
    cargo build --workspace --release --locked

# Build with production feature (ensures dummy-aead is disabled)
build-production:
    cargo build --locked --package trackone-core --no-default-features --features std,production
    cargo build --locked --package trackone-pod-fw --no-default-features --features production
    ! cargo check --locked --package trackone-pod-fw --no-default-features --features production,trackone-core/dummy-aead
    cargo build --locked --package trackone-gateway-svc --release --bin trackone-v2-gateway

# Run Rust-side serialization benchmarks
bench-rust:
    cargo test --package trackone-core --features std,postcard,dummy-aead summary_report -- --nocapture

# Check formatting
fmt-check:
    cargo fmt --all -- --check

# Format all code
fmt:
    cargo fmt --all

# Clean build artifacts
clean:
    cargo clean

# Full CI check (format, clippy, test, build)
ci: boundaries fmt-check clippy test build-release
    @echo "✅ All CI checks passed!"
