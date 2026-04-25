# ADR-048: Separate SCITT publication profile from the base telemetry-ledger draft

**Status**: Accepted
**Date**: 2026-04-10
**Updated**: 2026-04-25

## Related ADRs

- [ADR-032](ADR-032-informational-rfc-verifiable-telemetry-ledger.md): I-D scope and interoperability posture
- [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md): disclosure classes and verifier-facing bundle semantics
- [ADR-043](ADR-043-phased-bundle-manifest-maturity-for-id.md): verifier-manifest maturity and publication posture
- [ADR-045](ADR-045-git-signed-evidence-distribution-plane.md): publication/distribution boundary for evidence artifacts
- [ADR-047](ADR-047-trackone-evidence-plane-within-device-lifecycle.md): evidence-plane boundary within a broader lifecycle system
- [ADR-052](ADR-052-commitment-profile-identifier-binding-boundary.md): commitment profile identifier binding boundary

## Context

The current Internet-Draft defines:

- accepted-telemetry commitment semantics;
- authoritative canonical records and day artifacts;
- verifier-facing manifests and disclosure classes; and
- anchor and proof validation over disclosed artifacts.

That scope has become cleaner after ADR-047: TrackOne is the evidence plane,
not the full lifecycle or publication platform.

SCITT is adjacent to that evidence plane, but not identical to it.

If TrackOne later publishes evidence through a SCITT service, additional design
questions arise that are not part of the base commitment profile:

- what exactly is the publication unit;
- what statement payload is submitted;
- which fields are mandatory in the published claim;
- whether the statement is over an authoritative day artifact or an exported
  disclosure bundle;
- what a verifier should do with SCITT state; and
- whether SCITT publication affects local verification semantics at all.

Trying to answer those questions inside the base telemetry-ledger draft would
mix two different concerns:

- what the evidence means; and
- how that evidence is later published into a transparency service.

That would widen the draft at exactly the point where narrower evidence-plane
scope has become a strength.

## Decision

### SCITT publication semantics belong in a separate companion profile

TrackOne does **not** define SCITT publication behavior inside the base
telemetry-ledger draft.

If SCITT publication is standardized, it will be defined in a separate
companion profile or design note.

The base draft may mention SCITT only as an adjacent, later publication layer.

### The base verifier does not consume SCITT state

Verification defined by the base telemetry-ledger draft remains local to the
disclosed artifacts and proof channels described there.

SCITT state is not required to:

- identify the applicable `commitment_profile_id`;
- recompute canonical-record or day-artifact commitments;
- validate OTS, RFC 3161, or peer proof channels; or
- determine the disclosure class exercised by a bundle.

If a SCITT profile is later defined, it adds publication transparency and
statement discoverability. It does not replace artifact recomputation or proof
validation performed by the TrackOne verifier.

### A future SCITT profile publishes one explicit evidence object

Any future SCITT profile must choose a single primary publication unit for a
statement.

The preferred default is:

- the digest of the authoritative day artifact.

An alternative publication unit is:

- the digest of an exported disclosure bundle.

The profile must not blur those two units inside one statement type.

### A future SCITT profile must carry TrackOne evidence identifiers explicitly

If TrackOne later defines a SCITT statement profile, that profile should carry
at minimum:

- the published object's digest and digest algorithm;
- the applicable `commitment_profile_id`;
- the applicable disclosure class; and
- enough bundle or artifact identity to let a relying party relate the SCITT
  statement to the disclosed TrackOne evidence set.

Per ADR-052, including `commitment_profile_id` in the signed SCITT statement
payload is how SCITT publication binds the profile claim. SCITT publication
does not retroactively put the profile identifier into fact, day, Merkle, OTS,
TSA, or peer-signature preimages.

Additional metadata such as `day_root`, site/day labels, or anchor-channel
summary may be included, but local TrackOne verification remains authoritative
for commitment and proof semantics.

### The SCITT profile remains subordinate to the base evidence contract

Any future SCITT publication profile must treat the base telemetry-ledger
profile as the source of truth for:

- authoritative artifacts;
- commitment semantics;
- disclosure classes; and
- verifier-visible claim boundaries.

The SCITT profile may describe how those claims are published. It does not get
to redefine them.

## Consequences

### Positive

- Keeps the base Internet-Draft focused on evidence semantics rather than
  transparency-service procedure.
- Avoids forcing SCITT-specific design decisions into the current ISE review
  cycle.
- Preserves a clean layering:
  - base draft = evidence meaning;
  - SCITT profile = evidence publication.
- Makes future SCITT work easier to scope as a companion profile instead of a
  late add-on.

### Negative

- SCITT integration remains intentionally incomplete in the base draft.
- Future publication semantics will require a second document rather than a
  single umbrella specification.
- Some deployers may want stronger guidance sooner on how SCITT statements map
  to TrackOne artifacts.

### Neutral / clarified

- This ADR does not reject SCITT as a publication mechanism.
- This ADR does not prevent local or proprietary SCITT integrations.
- This ADR only rejects defining SCITT semantics inside the base
  telemetry-ledger draft at this stage.

## Alternatives considered

### Define SCITT publication inline in the base draft

Rejected.

That would require the base draft to specify statement structure, publication
unit, and verifier behavior beyond its current evidence-plane scope.

### Remove SCITT mention entirely

Rejected.

SCITT remains a plausible later publication mechanism, and it is useful to say
that such publication is adjacent rather than silently ignoring it.

### Make the verifier depend on SCITT state

Rejected.

That would invert the evidence-plane boundary and make external publication
state part of core local verification semantics.
