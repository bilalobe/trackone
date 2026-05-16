# TrackOne

TrackOne is a beta-boundary Rust workspace for low-power telemetry, framed
ingest, deterministic ledger artifacts, evidence verification/export, and pod
firmware helpers.

## Workspace

- `crates/trackone-core` — protocol types, crypto-facing traits, and shared invariants.
- `crates/trackone-constants` — versioned constants shared across crates.
- `crates/trackone-ingest` — framed Postcard ingest, replay checks, and fixture helpers.
- `crates/trackone-ledger` — canonical JSON/CBOR, Merkle, and digest helpers.
- `crates/trackone-gateway` — host-side Rust gateway helpers; legacy PyO3 bindings are opt-in with `--features python`.
- `crates/trackone-evidence` — Rust CLI/library for evidence verification and export.
- `crates/trackone-sensorthings` — deterministic read-only SensorThings projection semantics.
- `crates/trackone-pod-fw` — firmware-side pod helpers.

Machine-readable schemas, CDDL, vectors, and examples remain under `toolset/`.
Kubernetes and Helm manifests remain under `deploy/`.

## Rust Checks

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The local `just` recipes mirror the supported Rust path:

```bash
just test
just verify out/site_demo
```

## Evidence CLI

Verify a generated evidence root:

```bash
cargo run --package trackone-evidence -- verify \
  --root out/site_demo \
  --facts out/site_demo/facts
```

Export a curated day-scoped evidence bundle:

```bash
cargo run --package trackone-evidence -- export \
  --pipeline-dir out/site_demo \
  --evidence-repo /path/to/evidence \
  --site an-001 \
  --day 2025-10-07
```

`trackone-evidence` is the supported verifier and export surface for beta bar.
