# ADR-056: OTS Proof-State Metadata and Verification Lanes

**Status**: Accepted
**Date**: 2026-05-05

## Related ADRs

- [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md): Merkle canonicalization and OTS anchoring
- [ADR-007](ADR-007-ots-ci-verification-and-bitcoin-headers.md): OTS CI verification and Bitcoin headers
- [ADR-014](ADR-014-stationary-ots-calendar.md): stationary OTS calendar
- [ADR-020](ADR-020-stationary-ots-calendar-followup.md): stationary OTS follow-up
- [ADR-021](ADR-021-safety-net-ots-pipeline-verification.md): OTS pipeline safety net
- [ADR-023](ADR-023-ots-vs-git-integrity.md): OTS over Git integrity
- [ADR-053](ADR-053-beta-public-contract-spine.md): beta public contract spine

## Context

TrackOne uses several OTS-related states during development, CI, and release:
placeholder proofs, stationary local proofs, pending calendar attestations,
native detached-proof parsing, and external `ots verify` with Bitcoin headers.

Those states are useful, but broad wording such as "OTS verified" can
overclaim what happened. Native parsing can bind artifact digests and extract
`PendingAttestation(...)` or `BitcoinBlockHeaderAttestation(<height>)` leaves,
but it is not the same as trustless Bitcoin-header verification.

## Decision

TrackOne will treat OTS proof handling as separate lanes:

- **Development placeholder**: `OTS_PROOF_PLACEHOLDER`; never a Bitcoin
  attestation.
- **Stationary local proof**: deterministic local proof material for tests and
  offline CI; never a real OTS calendar or Bitcoin attestation.
- **Calendar pending**: a real OTS proof with pending calendar attestations but
  no Bitcoin attestation leaf yet.
- **Bitcoin-attested structure**: a proof whose detached structure contains
  `BitcoinBlockHeaderAttestation(<height>)`; native parsing may report the
  height.
- **Trustless verified**: external `ots verify` succeeds after the relevant
  Bitcoin headers are available.
- **Failed**: artifact binding, native parsing, external verification, or
  metadata validation failed.

OTS metadata MUST NOT fabricate Bitcoin block facts. Placeholder, stationary,
and pending proofs must not carry fake block hashes, heights, or Bitcoin Merkle
roots. If real attestation heights are parsed, metadata may report those
heights without claiming trustless header verification.

Strict/release verification MUST continue to rely on the external `ots verify`
lane for trustless Bitcoin-header validation.

User-facing metadata, verifier summaries, and release evidence MUST report one
of these exact proof states rather than collapsing them into a generic "OTS
verified" label.

## Consequences

### Positive

- Verifier and release evidence reports can distinguish structural proof
  parsing from trustless timestamp verification.
- Sidecar metadata stays truthful for placeholder, stationary, pending, and
  attested states.
- Local deterministic tests remain useful without becoming public proof claims.

### Negative

- User-facing status wording needs more precision than a single
  "verified/pending" flag.
- Release evidence may fail later than local structural parsing if the Bitcoin
  header lane is unavailable or behind.

## Alternatives Considered

- Treat native parsing of Bitcoin attestation leaves as verification.
  This was rejected because it does not fetch headers or validate the proof
  against a Bitcoin node.
- Keep fake Bitcoin fields in metadata as placeholders.
  This was rejected because placeholder block data becomes misleading
  verifier-visible evidence.

## Testing & Migration

1. Keep unit tests for placeholder, stationary, pending, and Bitcoin-attested
   OTS proof states.
1. Keep strict/release lanes wired to external `ots verify` with Bitcoin-header
   availability checks.
1. Keep docs, metadata, and release evidence aligned to the exact proof-state
   vocabulary rather than broad "OTS verified" wording.
