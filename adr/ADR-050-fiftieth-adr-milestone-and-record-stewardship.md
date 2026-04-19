# ADR-050: Fiftieth ADR Milestone and Record Stewardship

**Status**: Accepted
**Date**: 2026-04-19

## Related ADRs

- [ADR-016](ADR-016-changelog-policy-git-cliff.md): changelog policy and
  rejected automation
- [ADR-035](ADR-035-workspace-versioning-and-release-visibility.md): workspace
  versioning and release visibility
- [ADR-038](ADR-038-surface-tooling-and-abi3-wheel-strategy.md): surface tooling
  and wheel strategy
- [ADR-047](ADR-047-trackone-evidence-plane-within-device-lifecycle.md):
  TrackOne as an evidence plane
- [ADR-049](ADR-049-native-evidence-plane-crypto-boundary-and-pynacl-demotion.md):
  native evidence-plane crypto boundary

## Context

TrackOne has reached its fiftieth architecture decision record.

That is a small project milestone, but it is also a signal: the ADR corpus is no
longer just a scratchpad for early prototype choices. It has become part of the
project's release and review surface. The ADRs explain which boundaries are
stable, which implementation choices are historical, which surfaces are
provisional, and which follow-up migrations are intentionally deferred.

Recent decisions have sharpened that role:

- ADR-039 made CBOR the authoritative commitment profile.
- ADR-047 narrowed TrackOne to the evidence plane within a broader lifecycle
  system.
- ADR-049 made `trackone_core` the stable Python-facing authority boundary for
  evidence-plane crypto/admission and demoted PyNaCl to optional/tooling scope.

The fiftieth ADR should therefore celebrate the count by preserving discipline,
not by adding new runtime scope.

## Decision

### 1. Treat ADR-050 as a milestone marker

ADR-050 intentionally marks the fiftieth ADR in the repository.

The milestone is documentation-only. It does not change protocol behavior,
runtime dependencies, release versioning, artifact schemas, or verifier
semantics.

### 2. Treat the ADR corpus as an active release artifact

The ADR corpus should be reviewed as part of milestone and release PRs when the
change affects:

- supported wire/admission profiles;
- canonical commitment behavior;
- verifier-facing artifacts;
- disclosure/export semantics;
- native-versus-Python authority boundaries;
- runtime dependency posture; or
- project scope boundaries.

This does not mean every implementation PR needs a new ADR. It means boundary
changes should leave the architecture record in a coherent state before the PR is
used to close a milestone.

### 3. Preserve explicit supersession

When a newer ADR changes the authority or scope of an older accepted decision,
the older ADR should be marked as superseded or given a clear supersession note.

Historical ADRs remain valuable, but they should not leave future readers unsure
which decision currently governs implementation.

### 4. Keep milestone ADRs useful

Milestone ADRs are acceptable only when they record a useful project decision.

Acceptable milestone ADR content includes:

- release or review discipline;
- stewardship of the decision record itself;
- boundary clarification after a consolidation phase; or
- explicit risk posture for a milestone-closeout PR.

Milestone ADRs should not introduce a new technical surface merely to make the
count feel meaningful.

### 5. Keep celebration out of stable protocol semantics

The fiftieth-ADR marker is intentionally outside the protocol and evidence
contracts. It must not create:

- a new wire profile;
- a new commitment profile;
- a new artifact type;
- a new versioning scheme; or
- a new runtime dependency.

## Consequences

### Positive

- Makes the ADR milestone visible without inventing technical scope.
- Reinforces that architecture records are part of the reviewable release
  surface.
- Encourages future cleanup of stale accepted decisions through explicit
  supersession.
- Supports a centralized milestone PR by making the intended risk posture
  concrete: documentation discipline first, implementation churn only where
  needed.

### Neutral

- Adds one process-oriented ADR to the corpus.
- Does not require code, schema, dependency, or lockfile changes.
- Does not change the manual changelog policy recorded by ADR-016.

### Negative / Tradeoffs

- One more ADR means one more index entry to maintain.
- If used carelessly, milestone ADRs could become ceremony. This ADR explicitly
  rejects that pattern by requiring a useful decision payload.

## Risk Assessment

Risk is low.

This ADR is documentation-only and does not alter runtime behavior. The main
risk is process noise, mitigated by limiting milestone ADRs to decisions that
clarify stewardship, release posture, or architecture boundaries.

## Alternatives Considered

### Do nothing

Rejected.

Skipping the milestone would be fine technically, but it misses a useful moment
to clarify that the ADR corpus is now an active project artifact and should be
kept coherent during milestone closeout.

### Add a purely celebratory note outside ADRs

Rejected.

A note would mark the count but would not establish a reviewable decision about
record stewardship.

### Add a technical feature just to make ADR-050 substantive

Rejected.

The milestone should not distort protocol, artifact, dependency, or release
scope. The useful decision is stewardship of the architecture record itself.

## Status Rationale

Accepted because the project has reached a meaningful documentation maturity
point. ADR-050 records that milestone while keeping the technical system stable:
the celebration is the discipline, not a new surface.
