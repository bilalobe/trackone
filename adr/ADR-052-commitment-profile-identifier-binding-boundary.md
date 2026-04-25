# ADR-052: Commitment Profile Identifier Binding Boundary

**Status**: Accepted
**Date**: 2026-04-25

## Related ADRs

- [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md): CBOR-first commitment profile and artifact authority
- [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md): Verification disclosure bundles and privacy tiers
- [ADR-043](ADR-043-phased-bundle-manifest-maturity-for-id.md): Phased bundle-manifest maturity for the I-D
- [ADR-045](ADR-045-git-signed-evidence-distribution-plane.md): Git-signed evidence distribution plane
- [ADR-048](ADR-048-separate-scitt-publication-profile.md): Separate SCITT publication profile

## Context

TrackOne uses `trackone-canonical-cbor-v1` as the
`commitment_profile_id` for the current public commitment profile.

That identifier appears in verifier-facing manifests, conformance vectors,
pipeline summaries, and SCITT-style publication statement payloads. It does
not currently appear inside:

- fact CBOR commitment bytes;
- Merkle leaf preimages;
- Merkle internal-node preimages;
- day-record CBOR fields;
- OTS or TSA stamped bytes; or
- optional peer-signature messages over day roots.

This creates an important contract question: is the profile identifier itself
part of every cryptographic commitment, or is it a label/claim that selects how
the already-committed bytes are interpreted?

## Decision

`trackone-canonical-cbor-v1` is **claim-bound, not
commitment-preimage-bound**.

The profile identifier is the verifier-visible name for the semantic and
encoding rules used to interpret authoritative artifacts. It is not injected
into every lower-level commitment preimage.

### 1) Intrinsic commitments do not include the profile identifier

The following commitments bind only the artifact bytes and their normal
domain-specific context:

- `SHA-256(fact_cbor_bytes)` for Merkle leaves;
- ADR-003 Merkle roots over sorted leaf hashes;
- `day/YYYY-MM-DD.cbor` bytes and their SHA-256 digest;
- OTS and TSA proofs over the day artifact digest; and
- optional peer signatures over the day root, site, day, and peer-attestation
  context string.

Those objects are valid byte commitments. They do not, by themselves, assert
which TrackOne profile should be used to interpret the bytes.

### 2) Verifier and publication claims must carry the profile identifier

Any verifier-facing claim that states "these artifacts satisfy TrackOne profile
X" MUST carry `commitment_profile_id`.

Today that applies to:

- verification manifests;
- pipeline manifest summaries;
- exported evidence manifests;
- conformance vector manifests; and
- SCITT-style publication statement payloads.

When those objects are signed, timestamped, committed into a signed Git history,
or submitted as signed SCITT statements, the profile identifier is bound to
that claim by the enclosing signature or publication mechanism.

### 3) A verifier must not infer the profile from the root alone

A Merkle root or day-artifact digest is not self-describing. A verifier MUST
select an explicit supported commitment profile before interpreting disclosed
artifacts.

If a bundle has no explicit manifest or publication statement, transitional
tooling MAY fall back to a configured/default profile per ADR-043, but output
MUST report that the profile was inferred or defaulted rather than explicitly
claim-bound.

### 4) Future profile revisions must not silently reuse the same identifier

Any incompatible change to authoritative commitment bytes, Merkle policy,
field semantics, or deterministic encoding rules requires a new
`commitment_profile_id`.

Compatible clarifications may remain under the same identifier only when they
do not change artifact bytes or verification outcomes for valid inputs.

## Why the profile is not embedded into every preimage

Embedding `commitment_profile_id` into every fact/day/Merkle preimage was
rejected for the current profile for four reasons.

1. It would change all existing roots and anchored artifacts without improving
   byte-level integrity of the artifacts already being hashed.
1. The profile identifier describes how to interpret and verify the artifact
   family; it is metadata about the claim, not part of the telemetry record.
1. Recursive self-description creates avoidable migration friction: a profile
   label change would alter historical roots even when the underlying artifact
   bytes and verification algorithm are otherwise unchanged.
1. Existing publication and disclosure surfaces already have a natural place to
   bind the identifier: the verifier manifest, signed evidence repository,
   conformance manifest, or SCITT statement payload.

## Consequences

### Positive

- Keeps existing day roots, OTS/TSA proofs, and peer signatures stable.
- Makes the commitment-profile boundary explicit for reviewers and external
  verifier authors.
- Avoids treating a profile label as hidden telemetry data.
- Preserves a clean distinction between byte commitments and claims about how
  those bytes satisfy a TrackOne profile.

### Negative

- Raw roots and raw day-artifact digests are not self-describing.
- A relying party must retain or obtain the explicit profile claim alongside
  the artifacts.
- Manifest-absent transitional bundles remain weaker than manifest-carrying or
  signed-publication bundles.

## Alternatives Considered

### Bind the profile identifier into every Merkle leaf and day record

Rejected for `trackone-canonical-cbor-v1`.

This would provide self-describing roots at the cost of invalidating existing
vectors and proofs and making label-only clarifications cryptographically
disruptive.

### Treat the profile identifier as a non-security display label only

Rejected.

The identifier is not part of every commitment preimage, but it is security
relevant in verifier and publication claims. It must be carried and checked
where a bundle claims conformance to a specific TrackOne commitment profile.

### Require signed manifests immediately for every bundle

Rejected for the current alpha line because ADR-043 still permits transitional
manifest-absent verification paths. The desired tightening path is to require
explicit manifest/profile claims in stricter conformance lanes once tooling
enforces that uniformly.

## Testing & Migration

1. Keep verifier-manifest and pipeline-manifest schemas requiring
   `commitment_profile_id`.
1. Keep SCITT statement schemas requiring `trackone.commitment_profile_id`.
1. Ensure conformance-vector manifests name the active profile and the public
   CBOR/Merkle rules.
1. Keep verifier output explicit about manifest-present versus
   manifest-absent/defaulted profile behavior.
1. Revisit strict-mode behavior after ADR-043 Phase C: strict conformance
   verification should reject bundles whose profile claim is absent or
   inconsistent with the selected verifier profile.
