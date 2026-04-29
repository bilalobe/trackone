# TrackOne workspace tasks
# Run with: just <command>
# Install just: cargo install just

# Default recipe shows help
default:
    @just --list

# Sync the supported Python/dev environment for local work
setup-dev:
    uv sync --extra ci --extra test --extra security

# Build/install the native extension into the project environment
native-dev:
    uv run --locked maturin develop --manifest-path crates/trackone-gateway/Cargo.toml

# Run the supported deterministic local demo pipeline
demo out_dir="out/site_demo":
    uv run --locked python scripts/gateway/run_pipeline_demo.py --out-dir {{out_dir}}

# Re-run verifier checks against a pipeline output root
verify out_dir="out/site_demo":
    uv run --locked python scripts/gateway/verify_cli.py --root {{out_dir}} --facts {{out_dir}}/facts

# Run the pytest benchmark suite against the current corpus and gateway paths
bench: setup-dev
    uv run --locked tox -e bench

# Run all tests with correct feature combinations
test:
    cargo test --package trackone-core --features std,postcard,dummy-aead
    cargo test --package trackone-ingest --features std,xchacha
    cargo test --package trackone-sensorthings
    cargo test --package trackone-pod-fw --features std
    cargo test --package trackone-gateway

# Run clippy with correct features (avoid --all-features due to production+dummy-aead conflict)
clippy:
    cargo clippy --package trackone-core --features std,postcard,dummy-aead -- -D warnings
    cargo clippy --package trackone-ingest --features std,xchacha -- -D warnings
    cargo clippy --package trackone-sensorthings -- -D warnings
    cargo clippy --package trackone-pod-fw --features std -- -D warnings
    cargo clippy --package trackone-gateway -- -D warnings
    cargo clippy --package trackone-gateway --no-default-features -- -D warnings

# Build all packages in release mode
build-release:
    cargo build --workspace --release

# Build with production feature (ensures dummy-aead is disabled)
build-production:
    cargo build --package trackone-core --no-default-features --features std,production
    cargo build --package trackone-pod-fw --features production
    cargo build --package trackone-gateway --release

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
ci: fmt-check clippy test build-release
    @echo "✅ All CI checks passed!"
