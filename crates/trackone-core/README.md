# trackone-core

`trackone-core` is the shared protocol crate for TrackOne. It owns the bounded
types, AEAD-facing traits, imported identity-input records, and
deterministic encoding surfaces that both host and firmware code depend on.

## Responsibilities

This crate owns:

- core identifiers and bounded types such as `PodId`, `FrameCounter`, and fact
  payload shapes
- AEAD traits and crypto-adjacent type contracts
- identity/admission input types used to carry external lifecycle state into
  the TrackOne evidence path
- deterministic CBOR encoding support used by the commitment path
- re-export of shared policy constants from
  [`trackone-constants`](../trackone-constants/README.md)

## Feature model

- `std`
  Host-side support. This enables the `std`-backed CBOR surface and other
  host-friendly helpers.
- `dummy-aead`
  Test/development-only AEAD implementation. Do not use for production builds.
- `production`
  Stricter build profile that refuses `dummy-aead`.

The crate remains `no_std`-capable when `std` is disabled.

## Boundary with other crates

- [`trackone-ledger`](../trackone-ledger/README.md) owns commitment-specific
  artifact construction, Merkle policy, and digest helpers.
- [`trackone-ingest`](../trackone-ingest/README.md) owns framed Postcard wire
  profiles, nonce/AAD binding, fixture emission, replay, and framed admission.
- [`trackone-gateway`](../trackone-gateway/README.md) exposes selected core and
  ledger functionality to Python via PyO3.
- [`trackone-pod-fw`](../trackone-pod-fw/README.md) builds firmware-side
  runtime helpers on top of the core protocol model.

`trackone-core` should stay focused on shared protocol semantics. If logic is
about framed ingest admission it belongs in `trackone-ingest`; if it is only
about verifier/export commitment artifacts, it probably belongs in
`trackone-ledger`.

## Boundary watchlist

Keep this crate clear of:

- onboarding protocol logic
- PKI issuance, revocation, or registrar workflow
- fleet lifecycle state machines
- update orchestration policy

Identity-context types are acceptable here only as shared input shapes at the
admitted-telemetry boundary, not as ownership of the lifecycle plane itself.

## Typical use

```bash
cargo test -p trackone-core
```
