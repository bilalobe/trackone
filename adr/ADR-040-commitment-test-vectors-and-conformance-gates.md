# ADR-040: Commitment Test Vectors and Cross-Implementation Conformance Gates

**Status**: Proposed
**Date**: 2026-02-23

## Related ADRs

- [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md): CBOR-first commitment authority
- [ADR-034](ADR-034-serialization-boundaries-transport-vs-commitments.md): Commitment boundary enforcement
- [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md): Deterministic Merkle/day behavior
- [ADR-017](ADR-017-rust-core-and-pyo3-integration.md): Rust/Python integration path

## Context

Current deterministic-encoding claims are difficult to independently verify
without a conformance corpus. Reviewers can challenge stability claims unless
there are fixed vectors and enforced parity checks.

TrackOne now needs machine-readable vectors and CI gates that prove both Rust
and Python paths produce identical commitment artifacts.

## Decision

### 1) Publish conformance vectors

TrackOne MUST publish versioned machine-readable commitment vectors.

Minimum vector set for initial adoption:

- at least 3 vectors for initial merge;
- target 10+ vectors before status moves to Accepted.

Each vector MUST include:

- input logical fact/day payload;
- canonical commitment bytes (hex);
- fact leaf hash;
- batch Merkle root;
- day root;
- profile version identifier.

### 2) Enforce Rust/Python parity

CI MUST run conformance checks across implementations:

- Rust (`trackone-core` / `trackone-ledger`) output vs vector expected bytes;
- Python gateway output vs same expected bytes;
- Rust vs Python byte-for-byte equality for commitment bytes and roots.

Any mismatch is a hard CI failure.

### 3) Versioned profile compatibility

- Vectors are tied to a profile version.
- Profile changes that alter bytes MUST increment profile version and add new
  vectors.
- Legacy vectors MUST remain in-repo for regression detection.

### 4) Scope of vectors

Vectors MUST include edge cases:

- key-order permutations;
- numeric boundaries and integer encoding thresholds;
- optional/missing fields;
- odd-leaf Merkle layers;
- empty-day behavior.

## Consequences

### Positive

- Converts determinism from a narrative claim into an executable contract.
- Prevents accidental serializer drift during refactors.
- Improves confidence in I-D interoperability claims.

### Negative

- Adds CI/runtime overhead.
- Requires maintenance when profile versions evolve.

## Alternatives Considered

- Rely only on unit tests without published vectors: rejected (insufficient for
  external interoperability claims).
- Keep vectors private/internal: rejected (limits third-party verification).

## Testing & Migration

1. Create `toolset/unified/commitment_vectors/` with schema and initial vectors.
1. Add CI job validating vectors in both Rust and Python paths.
1. Make vector check mandatory for changes touching commitment encoding,
   Merkle logic, or day artifact generation.
1. Document vector update process in contributor docs.
