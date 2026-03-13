# ADR-043: Phased Bundle-Manifest Maturity for the I-D

**Status**: Accepted
**Date**: 2026-03-01
**Updated**: 2026-03-13

## Related ADRs

- [ADR-032](ADR-032-informational-rfc-verifiable-telemetry-ledger.md): Informational RFC posture
- [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md): Commitment profile authority
- [ADR-040](ADR-040-commitment-test-vectors-and-conformance-gates.md): Conformance vectors
- [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md): Disclosure bundle semantics

## Context

The current Internet-Draft rewrite uses the stronger specification structure
defined during the `-00` review pass: explicit disclosure classes, verifier
ordering, bundle semantics, and a machine-readable verification manifest
concept.

That structure is correct in direction, but the current TrackOne
implementation snapshot has now crossed the original Phase B boundary on the
main demo/verifier path, but manifest enforcement is not yet universal across
every supported tooling path.

At the current `alpha.9` / `alpha.10` transition point, TrackOne does support:

- authoritative CBOR fact and day artifacts;
- OTS proof plus sidecar binding to the day artifact digest;
- verifier recomputation from disclosed canonical artifacts;
- disclosure-tier language and conformance vectors in the draft;
- emitted pipeline manifests carrying `disclosure_class`,
  `commitment_profile_id`, artifact path+digest entries, and
  `checks_executed` / `checks_skipped`; and
- verifier-side manifest validation when that manifest is present.

TrackOne does not yet uniformly guarantee:

- manifest emission for every possible bundle producer;
- strict rejection of manifest-absent bundles in every CLI verification flow; and
- universal contract parity across all non-demo packaging paths.

If the I-D uses unconditional MUST-level language for those manifest
capabilities now, it will overstate current implementation support and create
a credibility gap between the document and the codebase.

## Decision

TrackOne will keep the stronger `-00` document structure from the review plan,
but MUST phase bundle-manifest requirements according to actual implementation
maturity.

### 1) Keep the stronger specification structure now

The `-00` draft SHOULD retain:

- disclosure classes (`A`, `B`, `C`);
- explicit artifact and proof semantics;
- verifier check ordering;
- the concept of a machine-readable verification manifest; and
- `commitment_profile_id` as the identifier for commitment semantics.

This structure is kept now because it expresses the correct long-term
interoperability shape and avoids a weaker `-00` that would need avoidable
restructuring in `-01`.

### 2) Downtune manifest requirements until enforcement is universal

Until manifest emission and enforcement are universal, the following posture
applies:

- For disclosure bundles in the I-D, a standalone verification manifest is
  **RECOMMENDED** / **SHOULD**, not unconditional **MUST**.
- Bundle descriptions MAY refer to `commitment_profile_id`, but the draft
  MUST distinguish between manifest-capable tooling paths and older/manual
  paths that may still be manifest-absent.
- Verifiers MAY infer disclosure-class capability from the available artifact
  set when no explicit manifest is present, but SHOULD prefer the explicit
  manifest when available.
- Verifier output SHOULD state which checks were executed versus skipped, even
  if the bundle did not contain a standalone manifest.

One exception remains:

- Published conformance vectors and explicit conformance bundles SHOULD name
  the active `commitment_profile_id`, because that documentation is under
  direct project control.

### 3) Adopt a phased implementation roadmap

TrackOne adopts the following phases for bundle-manifest maturity.

#### Phase A: `0.1.0-alpha.7`

- Keep the I-D structure.
- Keep standalone manifests optional-but-recommended in the I-D.
- Avoid overclaiming "fully packaged" bundle support.
- Continue allowing verification from canonical artifacts plus sidecar even
  when no standalone manifest is present.

#### Phase B: first manifest-capable tooling release

This phase is now implemented on the main demo/verifier path:

- a generated verification manifest artifact emitted by pipeline tooling;
- explicit `disclosure_class`;
- explicit `commitment_profile_id`;
- artifact path plus digest entries;
- per-channel anchor status; and
- a machine-readable list of checks executed.

At this phase, CLI verification SHOULD accept both:

- legacy bundles without a manifest; and
- manifest-carrying bundles.

Legacy bundles SHOULD be labeled as manifest-absent or transitional in output.

#### Phase C: post-transition tightening

After manifest emission, verification, and tests are stable across the main
tooling paths, the project MAY tighten the contract:

- Tier A / Class A bundles MAY be upgraded from manifest-SHOULD to
  manifest-MUST.
- The I-D MAY raise the manifest requirement to MUST in a later draft
  revision.
- Verifiers MAY reject manifest-absent bundles in strict conformance mode.

This tightening MUST NOT happen before the implementation actually enforces
the same contract.

### 4) Use the I-D as a forward contract, not a false claim

The I-D is allowed to describe the intended verification-bundle model, but it
MUST distinguish between:

- the structure the project is converging on; and
- what the current shipped tooling guarantees at `alpha.7`.

Where there is a mismatch, the document MUST choose wording that is both
truthful and forward-compatible, rather than weakening the architecture or
overstating implementation status.

## Consequences

### Positive

- Preserves the stronger `-00` document architecture without misrepresenting
  current tooling.
- Aligns the I-D with the real `alpha.9` / `alpha.10` implementation boundary.
- Creates a clean migration path from optional manifests to required
  manifests.
- Reduces reviewer criticism that the draft overclaims packaging maturity.

### Negative

- The draft carries a phased posture rather than a fully locked final bundle
  contract.
- Reviewers may still ask why manifest semantics are not yet uniformly
  enforced in tooling.
- Tooling and documentation must remain synchronized across the transition.

## Alternatives Considered

- **Make manifests unconditional MUST now**: rejected because it overstates
  `alpha.7` support.
- **Remove bundle-manifest structure from the `-00` draft**: rejected because
  it weakens the draft and delays the correct interoperability shape.
- **Keep the requirements vague**: rejected because vague wording recreates
  the ambiguity that prompted the rewrite.

## Testing & Migration

1. Keep SHOULD-level wording for standalone manifests where tooling is not yet universal.
1. Keep manifest emission in the main pipeline as a dedicated artifact.
1. Keep verifier support for explicit manifest parsing plus legacy fallback.
1. Add tests for:
   - manifest-present Tier A bundles;
   - manifest-absent legacy bundles;
   - disclosure-class labeling; and
   - strict-mode handling once manifests become normative.
1. Revisit the I-D wording when manifest support is consistently shipped, then
   raise requirements from SHOULD to MUST only if the implementation already
   enforces the same contract.
