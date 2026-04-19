# trackone-gateway

`trackone-gateway` is the Rust crate that exposes TrackOne’s native host-side
surface to Python through PyO3. It is the bridge between Python orchestration
and Rust-owned deterministic protocol/ledger behavior.

## Responsibilities

This crate is responsible for:

- exporting native modules under the `trackone_core` Python package
- exposing selected helpers from `trackone-core`, `trackone-ingest`, and
  `trackone-ledger`
- keeping Python-facing behavior aligned with Rust-owned commitment and digest
  contracts
- consuming external lifecycle/admission results only where they are needed to
  preserve deterministic gateway behavior

Current Python-facing modules include:

- `trackone_core.ledger`
  - canonical JSON-to-CBOR helpers
  - day/block artifact helpers
  - `sha256_hex`
  - `normalize_hex64`
- `trackone_core.merkle`
  - Merkle root and leaf-hash helpers
- `trackone_core.ots`
  - OTS proof hashing and verification helpers
- release/disclosure constants re-exported from workspace crates
- `trackone_core.crypto`
  - Rust Postcard framed fixture emission
  - framed payload validation/decrypt helpers
  - replay-window-backed framed admission

## What this crate is not

This crate does not own the full gateway workflow.

It should not absorb:

- Python pipeline orchestration
- manifest assembly
- export/publication policy
- general CLI behavior

Those remain in the Python scripts. This crate exists to keep the native
contract small, deterministic, and reusable.

## Boundary watchlist

Keep this crate clear of:

- inventory and ownership registry behavior
- onboarding and first-admission workflow
- policy engines for fleet allow/deny/quarantine state
- release/export choreography that is not needed for native deterministic
  helpers

This crate should expose reusable native helpers to Python, not become a host
control plane.

## Key dependencies

- [`trackone-core`](../trackone-core/README.md) for protocol and type surfaces
- [`trackone-ingest`](../trackone-ingest/README.md) for framed Postcard,
  replay, and gateway admission helpers
- [`trackone-ledger`](../trackone-ledger/README.md) for commitment, Merkle, and
  digest logic
- `pyo3` for Python bindings

## Local build

```bash
uv run maturin develop --manifest-path crates/trackone-gateway/Cargo.toml
```

## Check

```bash
cargo test -p trackone-gateway
```
