# TrackOne workspace tasks
# Run with: just <command>
# Install just: cargo install just

# Default recipe shows help
default:
    @just --list

# Re-run verifier checks against a pipeline output root
verify out_dir="out/site_demo":
    cargo run --package trackone-evidence -- verify --root {{out_dir}} --facts {{out_dir}}/facts

# Run all tests with correct feature combinations
test:
    cargo test --package trackone-core --features std,postcard,dummy-aead
    cargo test --package trackone-evidence
    cargo test --package trackone-ingest --features std,xchacha
    cargo test --package trackone-sensorthings
    cargo test --package trackone-pod-fw --features std
    cargo test --package trackone-gateway

# Run clippy with correct features (avoid --all-features due to production+dummy-aead conflict)
clippy:
    cargo clippy --package trackone-core --features std,postcard,dummy-aead -- -D warnings
    cargo clippy --package trackone-evidence -- -D warnings
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
    cargo build --package trackone-pod-fw --no-default-features --features production
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
