# trackone-ledger

`trackone-ledger` is the Rust home for TrackOne’s deterministic commitment and
artifact rules.

This crate is the single-source implementation for the deterministic commitment
primitives that must not drift between batching, verification, vector
generation, and Rust-native evidence surfaces.

## Responsibilities

This crate owns:

- deterministic CBOR commitment encoding and JSON projection helpers
- Merkle leaf hashing and root construction
- block-header and segment-artifact construction for the current commitment profile
- lowercase SHA-256 hex generation
- `hex64` normalization and validation used by the integrity/manifest path
- the VTL canonical-record and version-one segment-artifact encoder, strict
  decoder, validated epoch/successor constructors, stable invariant
  categories, hash-sorted Merkle calculation, aligned batch subtrees, and
  profile UUID binding

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
- [`trackone-gateway-svc`](../../apps/trackone-gateway-svc/README.md) composes
  VTL commitment rules into a durable deployable service
- [`trackone-sensorthings`](../trackone-sensorthings/README.md) may use digest
  helpers for deterministic projection IDs, but those projections are not
  commitment artifacts
- [`trackone-evidence`](../../apps/trackone-evidence/README.md) owns VTL
  verification and deterministic bundle compaction

This split is intentional and matches
[`ADR-046`](../../adr/ADR-046-sealed-trust-root-boundary-and-deferring-trackone-seal.md):
deterministic seal primitives live here, but the seal/publication workflow is
not a separate crate yet.

## Internal VTL layout

The active VTL profile is deliberately split by authority inside
`vtl`: `merkle` contains only the domain-separated commitment tree, while the
parent module owns the profile model plus canonical artifact encoding and
decoding. This keeps tree changes independent from the strict CBOR parser and
creates a stable seam for later extraction when another supported consumer
needs the profile as a standalone package.

## Boundary watchlist

Keep this crate clear of:

- manifest assembly workflow
- publication/export policy
- fleet lifecycle semantics
- onboarding or credential-management logic

If a behavior depends on operator workflow or deployment policy rather than
deterministic artifact rules, it probably does not belong here.

## Conformance role

The `vtl` module implements the profile identified by
`c08ade4e-1785-4eb6-9648-b7003d76288d` and the normative
[`vtl-known-answer`](../../toolset/vectors/vtl-known-answer/)
vector. It owns deterministic record/segment commitment primitives; elapsed-time
segment formation, durable publication, and timestamp-channel orchestration
remain outside this crate.

## Check

```bash
cargo test --locked -p trackone-ledger
```
