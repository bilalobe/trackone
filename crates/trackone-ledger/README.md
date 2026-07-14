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
- block-header and day-record construction for the current commitment profile
- lowercase SHA-256 hex generation
- `hex64` normalization and validation used by the alpha.11 integrity/manifest
  path
- the isolated draft-08 v2 canonical-record and segment-artifact encoder,
  strict decoder, validated epoch/successor constructors, stable invariant
  categories, hash-sorted Merkle calculation, and embedded-batch invariants

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
  helpers to host-side gateway code
- [`trackone-sensorthings`](../trackone-sensorthings/README.md) may use digest
  helpers for deterministic projection IDs, but those projections are not
  commitment artifacts
- [`trackone-evidence`](../trackone-evidence/README.md) owns verifier/export
  policy for evidence bundles

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
[`toolset/vectors/verifiable-telemetry-canonical-cbor-v1/`](../../toolset/vectors/verifiable-telemetry-canonical-cbor-v1/)
is generated against this contract, and Rust tests are expected to reproduce it
exactly.

The v2 surface is additive and does not reinterpret v1 day artifacts. It
implements deterministic record/segment commitment primitives; elapsed-time
segment formation, durable publication, and timestamp-channel orchestration
remain outside this crate.

The v2 corpus includes exact corrected epoch bytes and a preserved invalid
successor/zero-predecessor artifact. The corpus gate checks canonical
round-trip equality and artifact digests in addition to record and Merkle
values.

## Check

```bash
cargo test -p trackone-ledger
```
