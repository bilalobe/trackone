# trackone-constants

`trackone-constants` is the smallest crate in the TrackOne workspace: a
dependency-free `no_std` home for shared policy constants.

## What belongs here

This crate is for constants that need to stay aligned across:

- `trackone-core`
- `trackone-ingest`
- `trackone-ledger`
- `trackone-gateway`
- `trackone-pod-fw`

Current examples include:

- sizing and framing limits such as `MAX_FACT_LEN`
- AEAD layout constants such as `AEAD_NONCE_LEN` and `AEAD_TAG_LEN`
- framed ingest labels such as `INGEST_PROFILE_RUST_POSTCARD_V1` and
  `FRAMED_FACT_MSG_TYPE`
- verifier/runtime defaults such as `OTS_VERIFY_TIMEOUT_SECS`
- release/profile labels such as `COMMITMENT_PROFILE_ID_CANONICAL_CBOR_V1`
- disclosure-class identifiers and labels

## What does not belong here

Do not put logic, parsing, allocation-heavy helpers, or `std`-dependent
utilities in this crate. If a value needs behavior around it, that behavior
belongs in the crate that owns the domain.

Do not turn this crate into a dumping ground for lifecycle-plane enums,
inventory state labels, or workflow-only flags just because multiple crates can
see them.

## Why it is `no_std`

This crate is intentionally `no_std` so embedded consumers can reuse the same
workspace constants without accidentally pulling `std` into firmware-oriented
paths.

## Typical consumers

- [`trackone-core`](../trackone-core/README.md) re-exports the core protocol
  constants
- [`trackone-ingest`](../trackone-ingest/README.md) uses sizing, nonce, and tag
  constants for framed admission and fixture emission
- [`trackone-gateway`](../trackone-gateway/README.md) uses shared release and
  verifier constants at the Python/native boundary
- [`trackone-pod-fw`](../trackone-pod-fw/README.md) uses the same sizing and
  protocol policy as host-side code

## Check

```bash
cargo test -p trackone-constants
```
