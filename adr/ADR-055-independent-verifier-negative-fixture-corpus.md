# ADR-055: Independent Verifier Negative Fixture Corpus

**Status**: Accepted
**Date**: 2026-05-05

## Related ADRs

- [ADR-040](ADR-040-commitment-test-vectors-and-conformance-gates.md): commitment vectors and conformance gates
- [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md): disclosure classes and verification bundles
- [ADR-043](ADR-043-phased-bundle-manifest-maturity-for-id.md): verifier-manifest maturity
- [ADR-053](ADR-053-beta-public-contract-spine.md): beta public contract spine
- [ADR-054](ADR-054-release-bound-evidence-artifacts.md): release-bound evidence artifacts

## Context

The detached independent verifier now checks the public commitment corpus,
portable vector paths, verifier-manifest semantics, and decoded bundle fact
shape without importing TrackOne runtime code. That is enough to prove the
happy-path public spine, but beta also needs negative fixtures that exercise
the admission/evidence boundary and verifier refusal behavior.

Without a named fixture policy, future verifier hardening can drift into
ad-hoc tests that are hard for external implementers to reproduce.

## Decision

TrackOne will maintain a beta negative fixture corpus for the detached
independent verifier.

The beta minimum fixture corpus MUST include at least one detached-verifier
fixture for each of the following classes:

- verifier-manifest errors such as missing required fields, non-portable paths,
  digest mismatches, and malformed verification-bundle shapes;
- disclosure-class behavior for Class A/B/C recomputation and skipped checks;
- replay/admission negatives including duplicate and out-of-window frames;
- malformed-frame rejects that produce rejection-audit records but no
  commitment leaves;
- empty-batch and multi-batch day cases;
- non-zero previous-day-root chaining cases; and
- canonical CBOR shortest-form and decoded bundle-fact contract failures.

Additional negative fixtures may be added beyond this floor, but beta-readiness
claims must continue to cover each required class above.

Negative fixtures MUST be detached-verifier friendly: they must not require
TrackOne imports, private CI context, or source-tree layout assumptions.

Fixtures exist to prove that the current public spine rejects bad evidence and
reports skipped/failed checks explicitly. The corpus does not create a second
commitment profile or a verifier-private contract.

## Consequences

### Positive

- External verifier authors can test both accepted and rejected public-contract
  behavior.
- Beta-readiness claims can cite concrete fixtures instead of prose-only
  refusal rules.
- Replay, disclosure, and manifest failures become regression-testable without
  relying on private pipeline state.

### Negative

- The vector corpus grows beyond the current positive commitment examples.
- Fixture generation needs discipline so test data does not become another
  hidden implementation dependency.

## Alternatives Considered

- Keep only positive commitment vectors.
  This was rejected because positive vectors do not prove verifier refusal
  behavior or admission/evidence boundary reliability.
- Put all negative coverage only in Python integration tests.
  This was rejected because beta requires repo-independent verification
  evidence, not only local test confidence.

## Testing & Migration

1. Add and maintain the required fixture floor under the public vector or
   evidence-bundle test surface.
1. Extend the detached verifier tests to assert expected failure reasons for
   each negative fixture class.
1. Keep CI running the detached verifier with TrackOne imports disabled.
