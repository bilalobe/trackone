# ADR-041: Verification Disclosure Bundles and Privacy Tiers

**Status**: Accepted
**Date**: 2026-02-23
**Updated**: 2026-03-08

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

At the current `0.1.0-alpha.7` maturity level, a Tier A bundle MUST contain:

- canonical fact artifacts for the day, as defined by the active commitment profile;
- day artifact, as defined by the active commitment profile;
- authoritative block/day records;
- OTS proof and OTS metadata sidecar;
- sufficient information to identify the active commitment profile.

A standalone verification manifest (paths + digests) is RECOMMENDED and
SHOULD be included when the producing tool emits one. Per ADR-043, this
manifest requirement MAY be raised to MUST only after manifest emission and
consumption are uniformly supported across the main tooling paths.

During the ADR-039 dual-artifact migration window, Tier A verification MUST
treat the following as equivalent only when the selected profile and artifact
digests are bound unambiguously by a verification manifest or equivalent
verifier input:

- CBOR-first artifacts: `facts/*.cbor` and `day/YYYY-MM-DD.cbor`;
- transitional artifacts: `facts/*.json` and `day/YYYY-MM-DD.bin` (canonical JSON bytes).

Bundles using transitional artifacts MUST be labeled as
"Tier A (transitional profile artifacts)" in verifier output. Once CBOR-first
artifacts are the sole authoritative profile output, this transitional
equivalence MUST be removed.

If any required Tier A recomputation element is missing, output MUST be
labeled "not independently recomputable". If the standalone manifest is
absent, output SHOULD be labeled "manifest-absent" or equivalent transitional
wording rather than treated as a Tier A failure by default.

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
