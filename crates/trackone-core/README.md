# trackone-core

`trackone-core` is the shared protocol crate for TrackOne. It owns the bounded
types, frame model, AEAD-facing traits, provisioning records, and deterministic
encoding surfaces that both host and firmware code depend on.

## Responsibilities

This crate owns:

- core identifiers and bounded types such as `PodId`, `FrameCounter`, and fact
  payload shapes
- framed telemetry data structures and helpers
- AEAD traits and crypto-adjacent type contracts
- provisioning/admission input types used to carry external lifecycle state
  into the TrackOne evidence path
- deterministic CBOR encoding support used by the commitment path
- re-export of shared policy constants from
  [`trackone-constants`](../trackone-constants/README.md)

## Feature model

- `std`
  Host-side support. This enables the `std`-backed CBOR surface and other
  host-friendly helpers.
- `gateway`
  Host-specific helpers used by the gateway/native boundary.
- `dummy-aead`
  Test/development-only AEAD implementation. Do not use for production builds.
- `production`
  Stricter build profile that refuses `dummy-aead`.

The crate remains `no_std`-capable when `std` is disabled.

## Boundary with other crates

- [`trackone-ledger`](../trackone-ledger/README.md) owns commitment-specific
  artifact construction, Merkle policy, and digest helpers.
- [`trackone-gateway`](../trackone-gateway/README.md) exposes selected core and
  ledger functionality to Python via PyO3.
- [`trackone-pod-fw`](../trackone-pod-fw/README.md) builds firmware-side
  runtime helpers on top of the core protocol model.

`trackone-core` should stay focused on shared protocol semantics. If logic is
only about verifier/export commitment artifacts, it probably belongs in
`trackone-ledger` instead.

## Boundary watchlist

Keep this crate clear of:

- onboarding protocol logic
- PKI issuance, revocation, or registrar workflow
- fleet lifecycle state machines
- update orchestration policy

Provisioning-related types are acceptable here only as shared input shapes at
the admitted-telemetry boundary, not as ownership of the lifecycle plane
itself.

## Typical use

```bash
cargo test -p trackone-core
```
