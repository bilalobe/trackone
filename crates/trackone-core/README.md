# trackone-core

`trackone-core` is the shared telemetry protocol crate for TrackOne. It owns
the bounded fact types, AEAD-facing traits, imported identity-input records,
and deterministic fact encoding used by host and firmware code. The active VTL
artifact profile is a separate authority in `trackone-ledger`.

## Responsibilities

This crate owns:

- core identifiers and bounded types such as `PodId`, `FrameCounter`, and fact
  payload shapes
- no-std semantic validation for fact kind/payload pairing, finite
  environmental values, time ranges, and raw-versus-summary shape
- AEAD traits and crypto-adjacent type contracts
- identity/admission input types used to carry external lifecycle state into
  the TrackOne evidence path
- deterministic CBOR encoding for the shared telemetry fact model; this older
  fact encoding is outside the active VTL conformance surface
- re-export of shared policy constants from
  [`trackone-constants`](../trackone-constants/README.md)

## Feature model

- `std`
  Host-side support for heap-backed helpers such as canonical CBOR encoding.
- `postcard`
  Opt-in postcard compatibility coverage for shared core types. Framed postcard
  transport ownership remains in `trackone-ingest`.
- `dummy-aead`
  Test/development-only AEAD implementation. Do not use for production builds.
- `production`
  Stricter build profile that refuses `dummy-aead`.

The crate remains `no_std`-capable when `std` is disabled.

`EnvFact::instant` and `EnvFact::summary` are fallible. Postcard-facing and
deterministic-encoding callers must propagate `FactValidationError`;
deterministic CBOR encoding returns `CoreResult<Vec<u8>>` and never encodes an
invalid fact.

## Boundary with other crates

- [`trackone-ledger`](../trackone-ledger/README.md) owns the active VTL profile,
  artifact construction, Merkle policy, and VTL profile UUID.
- [`trackone-ingest`](../trackone-ingest/README.md) owns framed Postcard wire
  profiles, nonce/AAD binding, fixture emission, replay, and framed admission.
- [`trackone-sensorthings`](../trackone-sensorthings/README.md) owns read-only
  SensorThings projection semantics over accepted facts.
- [`trackone-pod-fw`](../trackone-pod-fw/README.md) builds firmware-side
  runtime helpers on top of the core protocol model.

`trackone-core` should stay focused on shared protocol semantics. If logic is
about framed ingest admission it belongs in `trackone-ingest`; if it is about
VTL producer/verifier artifacts, it belongs in
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
cargo test --locked -p trackone-core --features std,postcard
```
