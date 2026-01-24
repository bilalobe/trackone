# ADR-032: Proposing an Informational RFC for Verifiable Telemetry Ledgers

**Status**: Proposed
**Date**: 2026-01-04

## Related ADRs

- [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md): Canonicalization and OTS anchoring (core ledger mechanics)
- [ADR-015](ADR-015-parallel-anchoring-ots-rfc3161-tsa.md): Parallel anchoring with RFC 3161 (multi-trust model)
- [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md): Anti-replay and ledger semantics
- [ADR-028](ADR-028-sensorthings-projection-mapping.md) & [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md): SensorThings projections and envfact schemas
- [ADR-018](ADR-018-cryptographic-randomness-and-nonce-policy.md): Randomness and nonce policy (crypto foundations)

## Context

TrackOne has developed novel approaches to publicly auditable, low-power telemetry, including deterministic Merkle batching, dual-anchoring (OTS + RFC 3161), and projections to standards like OGC SensorThings. These build on existing RFCs (e.g., RFC 8785 for canonicalization, RFC 3161 for timestamps) but address underserved niches like multi-decade heritage monitoring without vendor lock-in.

Standardizing these could benefit the IoT/blockchain community, but we must evaluate if self-proposing an RFC is reasonable and accurate given our contributions.

## Decision

We propose drafting and endorsing an informational RFC candidate titled "Verifiable Telemetry Ledgers for Resource-Constrained Environments." This would:

- Document TrackOne's ledger model (append-only facts, daily Merkle roots, anti-replay via monotonic counters).
- Specify extensions like dual-anchoring for resilience and canonical envfact schemas for environmental sensing.
- Reference our reference implementation as a non-normative example.

Endorsement steps:

1. Internal review via this ADR.
1. Draft submission to IETF as an Independent Stream document for community feedback.
1. Seek co-authors/endorsements from partners (e.g., Smartilab for IoT aspects).

This is reasonable as a humble contribution, not a binding standard, and accurate as it evolves existing RFCs without overreach.

## Consequences

### Positive

- Elevates TrackOne's visibility and attracts collaborators.
- Provides a formal spec for interoperability (e.g., with OGC).
- Aligns with open-source goals by sharing innovations.

### Negative

- Requires effort for drafting/revisions; potential for rejection if not novel enough.
- Risk of dilution if not differentiated from RFCs like 6962 or 3161.

## Alternatives Considered

- Internal "RFC-like" doc only: Safer but limits impact.
- OGC extension proposal: More focused on sensing but misses crypto/anchoring breadth.
- No action: Misses opportunity to standardize our contributions.

## Testing & Migration

- Validate draft against project tests (e.g., E2E pipeline in tests/e2e).
- No migration needed; treat as additive documentation.
