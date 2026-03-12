# ADR-039: CBOR-First Commitment Profile and Artifact Authority

**Status**: Accepted
**Date**: 2026-02-23
**Updated**: 2026-03-12

## Related ADRs

- [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md): Existing deterministic Merkle/day pipeline
- [ADR-034](ADR-034-serialization-boundaries-transport-vs-commitments.md): Transport vs commitment boundary
- [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md): Ledger semantics and anti-replay
- [ADR-032](ADR-032-informational-rfc-verifiable-telemetry-ledger.md): Informational RFC track

## Context

TrackOne currently documents commitment determinism with JSON-focused language
in several places while newer decisions (ADR-034) move commitment bytes toward
deterministic CBOR for stability and constrained-system efficiency.

This has produced ambiguity in external docs and review:

- whether JSON or CBOR is authoritative for commitments;
- whether `facts/*.json` are canonical artifacts or projections;
- whether implementation APIs define the profile, or RFC-level rules do.

For an interoperable I-D and auditable implementation, artifact authority and
encoding profile must be explicit.

## Decision

### 1) Normative commitment basis

TrackOne commitment bytes are **CBOR-first**.

- Deterministic commitment encoding MUST follow RFC 8949 deterministic encoding
  rules (Section 4.2.1) as the normative baseline.
- TrackOne MAY add profile constraints (field ordering, field numbering, float
  policy, key-type rules), but these are layered constraints and MUST NOT
  violate RFC 8949 deterministic requirements.

### 2) Profile authority boundary

- The **specification** defines canonical commitment rules.
- Encoder APIs (e.g., `to_canonical_cbor_vec`) are implementations of the
  profile, not the normative source.
- Generic serializers (`serde` defaults, generic CBOR writers, pretty JSON)
  MUST NOT be used for commitment bytes.

TrackOne MAY publish CDDL for the authoritative CBOR commitment family as a
machine-readable structural description of the artifact family. That CDDL is
additive documentation for the CBOR-authoritative boundary; it MUST NOT be
treated as expanding authority to JSON projection artifacts.

### 3) Artifact authority and naming

Canonical commitment artifacts are CBOR:

- `facts/<fact-id>.cbor` is authoritative for fact commitments.
- `day/YYYY-MM-DD.cbor` is authoritative for day-level commitment hashing.
- OTS/TSA/peer attestations bind to authoritative artifact digests.

The first CDDL introduction for this family covers:

- the canonical `Fact` / `EnvFact` CBOR encodings;
- `BlockHeaderV1` as part of the day-record commitment family; and
- `DayRecordV1`.

JSON artifacts are projections:

- `facts/*.json` and `day/*.json` are optional human/audit views.
- JSON projection files MUST NOT be treated as commitment source of truth.

### 4) Compatibility window

During migration, a dual-artifact mode is allowed:

- both CBOR canonical artifacts and JSON projections may be emitted;
- verifiers MUST recompute roots from canonical CBOR bytes;
- any root mismatch between CBOR and JSON projections MUST fail CI.

## Consequences

### Positive

- Removes CBOR/JSON ambiguity in both code and I-D language.
- Aligns constrained-device performance goals with commitment determinism.
- Reduces canonicalization attack surface from serializer drift.
- Provides a machine-readable structural description for the CBOR-authoritative
  artifact family without promoting JSON projections to commitment authority.

### Negative

- Requires migration of pipeline tooling and tests currently centered on JSON
  fact files.
- Requires clear projection tooling for human operators used to JSON artifacts.

## Alternatives Considered

- Keep JSON as canonical and treat CBOR as optional: rejected due to mismatch
  with constrained-performance direction and ADR-034 intent.
- Permit both JSON and CBOR as canonical: rejected because dual authority
  creates non-deterministic interoperability behavior.

## Testing & Migration

1. Introduce CBOR canonical artifacts in batching output (`.cbor`) while
   keeping JSON projections for transition.
1. Add CI checks that Merkle roots are recomputed from CBOR authoritative
   artifacts only.
1. Fail CI if projection artifacts imply a different commitment root.
1. Update docs and I-D text to state CBOR authority and JSON projection scope.
1. Remove JSON-as-canonical code paths after one stable release cycle.
