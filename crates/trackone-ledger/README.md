# trackone-ledger

`trackone-ledger` is the Rust home for TrackOne’s deterministic commitment and
artifact rules.

This crate is the single-source implementation for the deterministic commitment
primitives that must not drift between batching, verification, vector
generation, and the Python/native boundary.

## Responsibilities

This crate owns:

- deterministic CBOR commitment encoding and JSON projection helpers
- Merkle leaf hashing and root construction
- block-header and day-record construction for the current commitment profile
- lowercase SHA-256 hex generation
- `hex64` normalization and validation used by the alpha.11 integrity/manifest
  path

It is the right place for reusable deterministic logic that belongs to the
commitment contract. Under
[`ADR-039`](../../adr/ADR-039-cbor-first-commitment-profile-and-artifact-authority.md),
CBOR artifacts are authoritative; JSON helpers in this crate support stable
projection and parity workflows.

## Boundary with other crates

- [`trackone-core`](../trackone-core/README.md) owns shared protocol types and
  crypto-facing traits
- [`trackone-ingest`](../trackone-ingest/README.md) owns framed Postcard wire
  profiles and admission helpers before facts enter commitment artifacts
- [`trackone-gateway`](../trackone-gateway/README.md) exposes selected ledger
  helpers to Python
- [`trackone-sensorthings`](../trackone-sensorthings/README.md) may use digest
  helpers for deterministic projection IDs, but those projections are not
  commitment artifacts
- Python scripts still own workflow concerns such as manifest assembly, export
  policy, and file choreography

This split is intentional and matches
[`ADR-046`](../../adr/ADR-046-sealed-trust-root-boundary-and-deferring-trackone-seal.md):
deterministic seal primitives live here, but the seal/publication workflow is
not a separate crate yet.

## Boundary watchlist

Keep this crate clear of:

- manifest assembly workflow
- publication/export policy
- fleet lifecycle semantics
- onboarding or credential-management logic

If a behavior depends on operator workflow or deployment policy rather than
deterministic artifact rules, it probably does not belong here.

## Conformance role

The published vector corpus under
[`toolset/vectors/trackone-canonical-cbor-v1/`](../../toolset/vectors/trackone-canonical-cbor-v1/)
is generated against this contract, and Rust/Python parity tests are expected
to reproduce it exactly.

## Check

```bash
cargo test -p trackone-ledger
```
