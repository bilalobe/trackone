# trackone-sensorthings

`trackone-sensorthings` is the Rust home for TrackOne's deterministic,
read-only OGC SensorThings projection semantics.

## Responsibilities

This crate owns:

- deterministic SensorThings entity ID derivation
- RFC3339 UTC validation and normalization used by projection outputs
- SensorThings projection types for Things, Datastreams, Observations, and IDs
- deterministic environmental observation projection from accepted facts
- provisioning/deployment-backed sensor identity selection for projection inputs

## Boundary with other crates

- [`trackone-core`](../trackone-core/README.md) owns canonical protocol facts,
  sample types, and payload shapes.
- [`trackone-ledger`](../trackone-ledger/README.md) owns commitment artifacts;
  SensorThings outputs are not Merkle leaves or CBOR commitment authorities.
- [`trackone-gateway`](../trackone-gateway/README.md) exposes this crate to
  Python through PyO3 but does not own projection semantics.

## Boundary watchlist

Keep this crate clear of:

- framed decrypt/admission and replay policy
- CBOR/day/Merkle commitment construction
- Python CLI/file orchestration
- publication/export policy
- fleet lifecycle or onboarding workflows

SensorThings remains a derived integration view over accepted TrackOne
evidence.

## Check

```bash
cargo test -p trackone-sensorthings
```
