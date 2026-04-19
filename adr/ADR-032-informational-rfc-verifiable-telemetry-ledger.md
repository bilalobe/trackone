# ADR-032: Proposing an Informational RFC for Verifiable Telemetry Ledgers

**Status**: Accepted
**Date**: 2026-01-04
**Updated**: 2026-04-19

## Related ADRs

- [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md): Canonicalization and OTS anchoring (core ledger mechanics)
- [ADR-015](ADR-015-parallel-anchoring-ots-rfc3161-tsa.md): Parallel anchoring with RFC 3161 (multi-trust model)
- [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md): Anti-replay and ledger semantics
- [ADR-028](ADR-028-sensorthings-projection-mapping.md) & [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md): SensorThings projections and envfact schemas
- [ADR-018](ADR-018-cryptographic-randomness-and-nonce-policy.md): Randomness and nonce policy (crypto foundations)
- [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md): Commitment profile authority
- [ADR-040](ADR-040-commitment-test-vectors-and-conformance-gates.md): Conformance vectors and CI gates
- [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md): Disclosure bundle semantics

## Context

TrackOne has developed novel approaches to publicly auditable, low-power telemetry, including deterministic Merkle batching, dual-anchoring (OTS + RFC 3161), and projections to standards like OGC SensorThings. These build on existing RFCs (e.g., RFC 8785 for canonicalization, RFC 3161 for timestamps) but address underserved niches like multi-decade heritage monitoring without vendor lock-in.

Standardizing these could benefit the IoT/blockchain community, but we must evaluate if self-proposing an RFC is reasonable and accurate given our contributions.

## Decision

We propose drafting and endorsing an informational RFC candidate titled "Verifiable Telemetry Ledgers for Resource-Constrained Environments." This would:

- Document TrackOne's ledger model (append-only facts, daily Merkle roots, anti-replay via monotonic counters).
- Specify extensions like dual-anchoring for resilience and canonical envfact schemas for environmental sensing.
- Reference our reference implementation as a non-normative example.
- Include explicit deltas vs adjacent standards so the contribution is scoped and falsifiable.

Endorsement steps:

1. Internal review via this ADR.
1. Draft submission to IETF as an Independent Stream document for community feedback.
1. Seek co-authors/endorsements from partners (e.g., Smartilab for IoT aspects).

This is reasonable as a humble contribution, not a binding standard, and accurate as it evolves existing RFCs without overreach.

### Concrete Standards Delta Section (Required in I-D)

The draft MUST include a concrete "delta vs existing work" section that names
what TrackOne adds beyond adjacent standards:

- **SCITT delta**: supports disconnected/offline operations with day-batched
  commitment publishing where always-on transparency service assumptions are not valid.
- **COSE Merkle delta**: specifies batching semantics, anti-replay ledger
  semantics, and day-chaining policy (not only proof encoding).
- **RFC 3161/OTS operational delta**: defines combined anchoring lifecycle,
  sidecar metadata binding, and verifier behavior in strict/warn modes.
- **Disclosure delta**: defines minimum verification bundle requirements and
  privacy-tier labeling for independent recomputation claims.

The section MUST avoid claims of novel cryptographic primitives and instead
frame novelty as an interoperability/operations profile for constrained telemetry.

## Consequences

### Positive

- Elevates TrackOne's visibility and attracts collaborators.
- Provides a formal spec for interoperability (e.g., with OGC).
- Aligns with open-source goals by sharing innovations.
- Reduces criticism that the draft is "reinventing SCITT/COSE" by naming explicit operational gaps.

### Negative

- Requires effort for drafting/revisions; potential for rejection if not novel enough.
- Risk of dilution if not differentiated from RFCs like 6962 or 3161.
- Forces tighter wording discipline; vague novelty statements become unacceptable.

## Alternatives Considered

- Internal "RFC-like" doc only: Safer but limits impact.
- OGC extension proposal: More focused on sensing but misses crypto/anchoring breadth.
- No action: Misses opportunity to standardize our contributions.

## Testing & Migration

- Validate draft against project tests (e.g., E2E pipeline in tests/e2e).
- No migration needed; treat as additive documentation.
