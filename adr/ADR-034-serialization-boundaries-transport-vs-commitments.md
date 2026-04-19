# ADR-034: Serialization Boundaries – Transport vs Commitment Encodings

**Status**: Accepted
**Date**: 2026-01-10
**Updated**: 2026-04-18

## Related ADRs

- [ADR-032](ADR-032-informational-rfc-verifiable-telemetry-ledger.md): Verifiable telemetry ledger (interoperability and audit posture)
- `crates/trackone-core/src/cbor.rs` (canonical CBOR commitment encoder)

## Context

TrackOne needs two different serialization properties:

1. **Transport efficiency** for device uplinks/downlinks and internal Rust services:

   - low overhead
   - `no_std` friendly where needed
   - schema-coupled is acceptable

1. **Commitment stability** for hashing, Merkle leaves, and audit artifacts:

   - deterministic/canonical encoding rules
   - cross-implementation reproducibility (goal)
   - safe from accidental serde configuration drift

Historically, these concerns were conflated into a single “Postcard vs CBOR vs JSON” narrative. This ADR separates them into explicit boundaries.

The framed-ingest path now has one supported plaintext profile:
`rust-postcard-v1` for the Rust-native `Fact` path. That profile is still
transport/admission detail. It does not change the commitment boundary.

## Decision

### 1) Transport encoding: Postcard

For TrackOne device-facing wire formats and internal transport where both ends share the Rust schema:

- Use **Postcard** as the default transport encoding.
- Rationale: compact, fast, schema-driven, and already integrated in TrackOne.

This choice is **not** a cross-language canonicalization claim.

### 2) Commitment encoding: Canonical CBOR (TrackOne Canonical Profile)

For hashing, Merkle leaves, signed receipts, and any “commitment bytes” that must remain stable:

- Use **canonical CBOR bytes produced by the TrackOne canonical encoder** (not generic serde CBOR).
- The canonical encoder is the API in `crates/trackone-core/src/cbor.rs`:
  - `to_canonical_cbor_vec(T: CanonicalCbor)`
  - explicit field numbering
  - canonical integer encoding (shortest form)
  - deterministic float encoding policy (fixed width where specified)
  - deterministic map and key strategy (integer keys)

This boundary prevents accidentally treating `ciborium::into_writer` output as commitment bytes.

### 3) Prohibited for commitments

The following MUST NOT be used to generate commitment bytes:

- `to_cbor_vec(T: Serialize)` or any generic serde-CBOR serializer
- JSON encodings (compact, pretty, or canonical) unless explicitly selected as the commitment profile in a future ADR
- AEAD plaintext encodings such as Postcard. These are inputs to
  admission/projection, not verifier-facing commitment bytes.

### 4) Frame-to-canonical-record projection

Framed telemetry begins as transport-specific input, then passes through native
Rust admission:

- `rust-postcard-v1` decodes postcard `Fact` through the native Rust boundary.
- Accepted input MUST project into the same canonical fact contract before
  commitment.

The public interoperability surface is the projected canonical record plus the
deterministic CBOR commitment profile, not the internal plaintext encoding.

## Consequences

### Positive

- Commitment stability becomes enforceable via API boundaries (`CanonicalCbor` trait).
- Transport format can evolve independently of commitment artifacts.
- Reduces “benchmarks as decisions” confusion: size tests inform transport choice, not commitment correctness.
- Prevents Postcard transport details from becoming public commitment
  authority.

### Negative / Tradeoffs

- Multiple ingest plaintext profiles may need to be maintained and documented
  during migration.
- Canonical CBOR profile is TrackOne-specific unless standardized externally.
- Adding new commitment types requires extending `CanonicalCbor` implementations and tests.

## Enforcement

- Commitment paths MUST depend on `to_canonical_cbor_vec` (or a wrapper) and MUST NOT call `to_cbor_vec`.
- Tests MUST cover:
  - stability (same input == same bytes)
  - schema/field number invariants (bytes stable across versions unless schema version bump)

## Notes on “Canonical”

“Canonical” in this ADR refers to deterministic encoding rules for commitments. TrackOne’s canonical CBOR profile is consistent with RFC 8949 deterministic encoding goals, but it is also constrained by TrackOne’s explicit field numbering and float policy.

## Appendix A: Why size benchmarks do not decide commitment encodings

Size benchmarks are useful to justify Postcard for transport. Commitment encodings are selected for audit stability and interoperability posture, where determinism and specification clarity dominate raw size.
