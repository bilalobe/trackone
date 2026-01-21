# TrackOne workspace tasks
# Run with: just <command>
# Install just: cargo install just

# Default recipe shows help
default:
    @just --list

# Run all tests with correct feature combinations
test:
    cargo test --package trackone-core --features std,gateway,dummy-aead
    cargo test --package trackone-pod-fw
    cargo test --package trackone-gateway

# Run clippy with correct features (avoid --all-features due to production+dummy-aead conflict)
clippy:
    cargo clippy --package trackone-core --features std,gateway,dummy-aead -- -D warnings
    cargo clippy --package trackone-pod-fw -- -D warnings
    cargo clippy --package trackone-gateway -- -D warnings

# Build all packages in release mode
build-release:
    cargo build --workspace --release

# Build with production feature (ensures dummy-aead is disabled)
build-production:
    cargo build --package trackone-core --no-default-features --features std,gateway,production
    cargo build --package trackone-pod-fw --no-default-features
    cargo build --package trackone-gateway --release

# Run serialization benchmarks
bench:
    cargo test --package trackone-core --features std,gateway,dummy-aead summary_report -- --nocapture

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
