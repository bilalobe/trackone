# trackone-gateway

`trackone-gateway` is the Rust crate for TrackOne host-side gateway helpers.
The beta surface builds the Rust helper contract by default; legacy PyO3
bindings remain available only behind the explicit `python` feature.

## Responsibilities

This crate is responsible for:

- exposing selected helpers from `trackone-core`, `trackone-ingest`,
  `trackone-ledger`, and `trackone-sensorthings`
- keeping host-side behavior aligned with Rust-owned commitment and digest
  contracts
- consuming external lifecycle/admission results only where they are needed to
  preserve deterministic gateway behavior

Current Rust-owned helper areas include ledger, Merkle, OTS proof inspection,
framed fixture/admission helpers, and SensorThings projection helpers.

## What this crate is not

This crate does not own the full gateway workflow.

It should not absorb:

- manifest assembly
- export/publication policy
- general CLI behavior

Export/publication policy belongs in `trackone-evidence`. This crate exists to
keep the gateway helper contract small, deterministic, and reusable.

## Boundary watchlist

Keep this crate clear of:

- inventory and ownership registry behavior
- onboarding and first-admission workflow
- policy engines for fleet allow/deny/quarantine state
- release/export choreography that is not needed for native deterministic
  helpers

This crate should expose reusable gateway helpers, not become a host control
plane.

## Key dependencies

- [`trackone-core`](../trackone-core/README.md) for protocol and type surfaces
- [`trackone-ingest`](../trackone-ingest/README.md) for framed Postcard,
  replay, and gateway admission helpers
- [`trackone-ledger`](../trackone-ledger/README.md) for commitment, Merkle, and
  digest logic
- [`trackone-sensorthings`](../trackone-sensorthings/README.md) for
  deterministic read-only SensorThings projection semantics
- optional `pyo3` for legacy Python bindings

## Local build

Use `cargo test -p trackone-gateway` for the default Rust surface. Build legacy
bindings only when explicitly needed with `--features python`.

## Check

```bash
cargo test -p trackone-gateway
```
