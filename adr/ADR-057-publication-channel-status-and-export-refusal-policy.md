# ADR-057: Publication Channel Status and Export Refusal Policy

**Status**: Accepted
**Date**: 2026-05-05

## Related ADRs

- [ADR-015](ADR-015-parallel-anchoring-ots-rfc3161-tsa.md): parallel OTS, TSA, and peer channels
- [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md): disclosure bundles and privacy tiers
- [ADR-048](ADR-048-separate-scitt-publication-profile.md): separate SCITT publication profile
- [ADR-053](ADR-053-beta-public-contract-spine.md): beta public contract spine
- [ADR-054](ADR-054-release-bound-evidence-artifacts.md): release-bound evidence artifacts

## Context

TrackOne reports publication and anchoring channels across local verification,
evidence export, release evidence, and optional publication profiles. Current
channels include OTS, TSA, peer signatures, and SCITT-shaped publication
outputs.

If each script reduces channel status differently, verifier manifests and
export gates can disagree about whether evidence is verified, pending, missing,
failed, or skipped.

## Decision

Publication-channel status vocabulary and export refusal policy belong behind
package-level verification helpers, with scripts acting as CLI and file-I/O
wrappers.

The shared channel status vocabulary is:

- `verified`
- `pending`
- `missing`
- `failed`
- `skipped`

Verifier summaries, evidence export, release evidence, and manifest shaping
MUST consume the shared package vocabulary rather than reimplementing
script-local status normalization.

Export refusal MUST be based on fresh local verification. A publishable bundle
must not be exported when required local checks did not execute, the verifier
manifest is missing or invalid, artifact validation fails, metadata binding
fails, or Class A fact-level recomputation is claimed but not performed.

The default gate semantics are:

- `warning` policy: base local verification and artifact/metadata binding MUST
  succeed; optional publication channels may remain `pending` or `skipped`
  without blocking export.
- `strict` policy: base local verification and artifact/metadata binding MUST
  succeed, and every enabled publication channel MUST end in `verified`; any
  enabled channel in `pending`, `missing`, `failed`, or `skipped` fails the
  verifier run.

Optional publication channels remain optional edges. In warning policy, a
pending or skipped optional edge may be reported without blocking local
evidence export. In strict policy, enabled channels must satisfy the configured
requirements or the verifier run fails.

SCITT remains a separate publication profile. SCITT status may be reported as a
channel, but SCITT state must not redefine base commitment, disclosure, or
verifier-manifest semantics.

## Consequences

### Positive

- `verify_cli.py`, evidence export, and release workflows share one status
  language.
- Export refusal reasons become stable enough for operators and release
  evidence to audit.
- Optional publication edges can be added without changing the base evidence
  contract.

### Negative

- Scripts lose freedom to invent local status names.
- Future channel additions must update the shared vocabulary and tests before
  use in manifests or export gates.

## Alternatives Considered

- Keep channel reduction local to each script.
  This was rejected because it lets verifier and export behavior drift.
- Make all publication channels mandatory for beta.
  This was rejected because OTS/TSA/peer/SCITT channels have different trust
  models and deployment requirements.

## Testing & Migration

1. Keep unit coverage for shared channel reduction and export refusal reasons.
1. Keep schema tests aligned with verifier-manifest channel vocabulary.
1. Keep release evidence export gated first by fresh local verification under
   the selected policy, then by carrier pull-back verification.
