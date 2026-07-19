# TrackOne workspace tasks
# Run with: just <command>
# Install just: cargo install just

# Default recipe shows help
default:
    @just --list

# Re-run verifier checks against a pipeline output root
verify out_dir="out/site_demo":
    cargo run --package trackone-evidence -- verify --root {{out_dir}} --facts {{out_dir}}/facts

# Enforce reusable-library, application, and binding dependency direction.
boundaries:
    python3 toolset/ci/check_workspace_boundaries.py

# Run all tests with correct feature combinations
test:
    cargo test --workspace --locked
    cargo test --locked --package trackone-core --features std,postcard,dummy-aead
    cargo test --locked --package trackone-ingest --features std,xchacha
    cargo test --locked --package trackone-pod-fw --features std
    cargo test --locked --package trackone-python --features python
    cargo test --locked --package trackone-ledger --test vector_corpus -- --ignored

# Run clippy with correct features (avoid --all-features due to production+dummy-aead conflict)
clippy:
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo clippy --locked --package trackone-core --all-targets --features std,postcard,dummy-aead -- -D warnings
    cargo clippy --locked --package trackone-ingest --all-targets --features std,xchacha -- -D warnings
    cargo clippy --locked --package trackone-pod-fw --all-targets --features std -- -D warnings
    cargo clippy --locked --package trackone-python --all-targets --features python -- -D warnings

# Build all packages in release mode
build-release:
    cargo build --workspace --release --locked

# Build with production feature (ensures dummy-aead is disabled)
build-production:
    cargo build --locked --package trackone-core --no-default-features --features std,production
    cargo build --locked --package trackone-pod-fw --no-default-features --features production
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
