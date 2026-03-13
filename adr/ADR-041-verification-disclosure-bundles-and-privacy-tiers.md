# ADR-041: Verification Disclosure Bundles and Privacy Tiers

**Status**: Accepted
**Date**: 2026-02-23
**Updated**: 2026-03-13

## Related ADRs

- [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md): Ledger vs audit semantics
- [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md): Canonical artifact authority
- [ADR-015](ADR-015-parallel-anchoring-ots-rfc3161-tsa.md): Optional parallel attestations
- [ADR-032](ADR-032-informational-rfc-verifiable-telemetry-ledger.md): RFC posture
- [ADR-043](ADR-043-phased-bundle-manifest-maturity-for-id.md): Phased manifest maturity for the I-D

## Context

The project currently mixes strong independent-verification claims with privacy
minimization language but does not define a normative minimum disclosure
bundle. Without a clear minimum, operators can over-redact and still claim
"verified," creating ambiguity and potential audit disputes.

## Decision

### 1) Define verification bundle tiers

TrackOne defines three disclosure tiers:

- **Tier A (Public Recompute)**: full independent recomputation.
- **Tier B (Partner Audit)**: controlled disclosure for contracted auditors.
- **Tier C (Anchor-Only Proof)**: existence/timestamp verification only.

### 2) Normative minimum for Tier A

At the current `0.1.0-alpha.10` implementation boundary, a Tier A bundle
MUST contain:

- canonical fact artifacts for the day, as defined by the active commitment profile;
- day artifact, as defined by the active commitment profile;
- authoritative block/day records;
- OTS proof and OTS metadata sidecar;
- a standalone verification manifest carrying:
  - `disclosure_class`;
  - `commitment_profile_id`;
  - artifact path plus digest entries; and
  - machine-readable executed/skipped-check metadata.

The current tooling now emits and validates that manifest on the main
pipeline/verifier path. Per ADR-043, the remaining transition question is not
whether the manifest contract exists, but when strict verification should make
manifest absence fatal across every supported tooling path.

If any required Tier A recomputation element is missing, output MUST be
labeled "not independently recomputable". If the standalone manifest is
absent on a manifest-capable tooling path, output SHOULD be labeled
"manifest-absent" or equivalent transitional wording until strict manifest
requirement is enabled consistently.

### 3) Normative minimum for Tier B

A Tier B bundle MUST contain:

- day artifact and authoritative block/day records;
- OTS proof + sidecar;
- cryptographic commitments to redacted fact-set partitions;
- policy statement describing withheld fields.

Tier B MAY support recomputation only for authorized auditors with supplemental
material, but MUST NOT be represented as publicly reproducible.

### 4) Tier C semantics

Tier C supports only anchor/timestamp and chain-consistency checks.

- Tier C MUST be labeled "existence/timestamp evidence only".
- Tier C MUST NOT claim full fact-level reproducibility.

### 5) Labeling and verifier output

Verifier outputs MUST include a disclosure-class label (`A`, `B`, or `C`) and
explicitly state which checks were possible vs skipped due to disclosure limits.

## Consequences

### Positive

- Eliminates ambiguity between privacy controls and verification guarantees.
- Prevents overstatement of auditability in partially disclosed datasets.
- Provides a clean contract for policy and legal review.

### Negative

- Requires packaging and labeling work in pipeline tooling.
- Forces operators to choose and publicly document a disclosure class.

## Alternatives Considered

- Keep the disclosure policy purely operational (no ADR contract): rejected
  (inconsistent claims across deployments).
- Single-tier bundle for all contexts: rejected (unrealistic for privacy and
  institutional constraints).

## Testing & Migration

1. Add the disclosure class field to the verification manifest where manifests are emitted.
1. Update verifier to emit disclosure-class aware results and manifest-absent transitional labeling.
1. Add tests proving Tier B/C cannot report full recomputation success.
1. Update documentation and I-D language to align claims with disclosure tier.
1. Revisit the Tier A manifest requirement once ADR-043 Phase B is implemented, and raise SHOULD to MUST only after tooling enforces the same contract.
