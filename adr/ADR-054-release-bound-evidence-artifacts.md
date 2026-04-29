# ADR-054: Release-Bound Evidence Artifacts

**Status**: Accepted
**Date**: 2026-04-29

## Related ADRs

- [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md): Merkle canonicalization and anchoring
- [ADR-023](ADR-023-ots-vs-git-integrity.md): OTS remains the time and integrity authority
- [ADR-035](ADR-035-workspace-versioning-and-release-visibility.md): workspace release visibility
- [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md): CBOR-first commitment profile and artifact authority
- [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md): disclosure bundle semantics
- [ADR-045](ADR-045-git-signed-evidence-distribution-plane.md): signed evidence distribution boundary
- [ADR-048](ADR-048-separate-scitt-publication-profile.md): separate publication profiles from base evidence semantics
- [ADR-053](ADR-053-beta-public-contract-spine.md): beta public contract spine

## Context

TrackOne already distinguishes software release artifacts from verifier-visible
evidence artifacts:

- crates, wheels, and Helm charts publish the software release;
- `day/<date>.verify.json`, canonical CBOR day artifacts, digests, and
  disclosure metadata define verifier-visible evidence;
- self-contained archive bundles prove that the evidence can be verified
  without the repository, CI scripts, or private operator context; and
- branch CI publishes commit-addressed evidence archives for continuous
  survivability checks.

That separation is useful, but it leaves an ambiguity at release time. A
successful release tag might publish the software while relying parties still
need to infer whether a formal release evidence artifact exists for the same
tag.

The release process now needs an explicit state: after the release software
artifacts publish, TrackOne should mint a tag-addressed evidence artifact and
verify the artifact after retrieval from its publication carrier.

## Decision

### Release evidence is a formal release artifact

For a version tag release, TrackOne MUST publish a release-bound evidence
archive when the release workflow succeeds.

The release-bound evidence archive is not a replacement for crates, wheels, or
Helm charts. It is the verifier-facing evidence artifact associated with the
release tag.

The current publication unit is:

```text
ghcr.io/<owner>/<repo>/evidence-archive:<release-tag>
```

For example:

```text
ghcr.io/bilalobe/trackone/evidence-archive:v0.1.0-alpha.17
```

### The release evidence state machine is explicit

The release workflow is modeled as a finite state machine:

```text
tag pushed
  -> reusable CI succeeds
  -> archive-evidence-bundle exists
  -> Helm chart publishes
  -> crates publish
  -> wheel publishes
  -> release evidence archive publishes
  -> release evidence archive is pulled back
  -> release evidence archive is independently verified
  -> release complete
```

The release evidence transition MUST NOT run before software publication has
succeeded. Publishing release evidence before crates, wheels, or Helm complete
would create a tag-addressed evidence artifact for a release that did not
actually finish.

### Release evidence reuses the CI-built self-contained bundle

The tag workflow SHOULD reuse the self-contained `archive-evidence-bundle`
artifact produced by the reusable CI gate rather than reconstructing a second
bundle with release-specific logic.

That bundle must contain enough material to verify outside the source checkout:

- the disclosed evidence bundle under `bundle/`;
- the detached verifier under `verifier/`;
- verifier documentation;
- `result.json` from the scenario that produced the bundle; and
- `SHA256SUMS` covering the files inside the archive root.

The release workflow may wrap, transport, or publish that bundle, but it must
not silently weaken the bundle's detached-verification properties.

### Pull-back verification is required

Release evidence publication is incomplete until the workflow verifies the
artifact retrieved from its publication carrier.

The workflow MUST:

- validate the local tarball against its declared SHA-256 before publication;
- push the archive to the release evidence carrier;
- pull the archive back from the carrier;
- compare the pulled tarball digest against the pre-publish digest;
- extract the pulled archive;
- check `SHA256SUMS`; and
- rerun the detached verifier with repository-specific import paths disabled.

The release evidence result is a publication claim only after the pulled
artifact verifies.

### OCI is the current release evidence carrier

GHCR OCI artifacts are the current release evidence carrier because the release
workflow already uses GHCR for Helm/chart and operational artifacts.

The OCI artifact MUST use a release-tag reference, not only a commit-SHA
reference, when it represents release-bound evidence.

The OCI artifact SHOULD include annotations for:

- source repository;
- commit revision;
- release tag/version; and
- artifact title.

The current artifact type is:

```text
application/vnd.trackone.evidence.archive.v1+tar
```

Changing the archive's verifier-visible contents, bundle semantics, or
artifact-family meaning may require a new artifact type or a new artifact
family review under ADR-053.

### Commit-addressed and release-addressed evidence remain distinct

TrackOne keeps two related publication states:

```text
main CI evidence archive
  -> commit-addressed evidence survivability check

release evidence archive
  -> tag-addressed formal release artifact
```

The commit-addressed archive proves that a specific commit's evidence bundle
survives archive packaging, OCI publication, retrieval, and detached
verification.

The release-addressed archive proves that the successful release tag has a
formal verifier-facing evidence artifact.

They may point to the same underlying commit and equivalent bundle contents,
but they have different lifecycle semantics.

### Weekly ratchet remains vitality evidence

The weekly ratchet workflow is not a release evidence producer.

Weekly ratchet artifacts prove scheduled OTS and slow-path vitality:

```text
scheduled/manual run
  -> dependency audit
  -> OTS calendar image build
  -> real OTS/slow lanes
  -> ratchet metadata
  -> optional ratchet tag on main
```

That workflow may push immutable image tags and a `latest` convenience tag on
`main`, but those artifacts are operational vitality signals, not formal
release evidence.

The release evidence workflow and weekly ratchet workflow should share
discipline:

- serialize mutation-prone runs;
- prefer immutable references for durable claims;
- pull back and verify pushed artifacts where practical; and
- label mutable convenience tags as convenience only.

They should not share release semantics.

## Consequences

### Positive

- A successful release has an explicit verifier-facing evidence artifact.
- Release evidence is not inferred from branch CI artifacts or short-lived
  Actions uploads.
- The publication carrier is tested after retrieval, not trusted because the
  local bundle existed before upload.
- The release workflow now has a clear final evidence state, making failures
  easier to classify.
- Commit-addressed archive checks remain useful without pretending to be
  release artifacts.

### Negative

- Release runs do more work and have another GHCR write dependency.
- A release can now fail after crates, wheel, and chart publication if
  release-bound evidence publication or pull-back verification fails.
- Retrying a release tag needs careful handling of already-published software
  artifacts and the release evidence OCI reference.

### Neutral / clarified

- This ADR does not change canonical CBOR, Merkle, OTS, disclosure-class, or
  verifier-manifest semantics.
- This ADR does not make GitHub Actions artifact retention an archive strategy.
- This ADR does not make weekly ratchet a release producer.
- This ADR does not replace future SCITT publication work; SCITT remains a
  separate publication profile under ADR-048.

## Testing & Migration

1. The release workflow must grant the reusable CI call enough permissions to
   produce its archive and OCI verification states.
1. The release workflow must wait for software publication before minting the
   tag-addressed evidence artifact.
1. The release workflow must publish release-bound evidence as an OCI artifact
   keyed by `github.ref_name`.
1. The workflow must pull the release evidence artifact back and verify the
   pulled copy before considering the release evidence state complete.
1. The workflow must upload the release evidence digest/result as Actions
   artifacts for operator inspection, but those Actions artifacts are handoff
   records rather than the archival carrier.
1. The weekly ratchet workflow should keep mutation discipline aligned with this
   ADR by serializing runs and treating `latest` as a main-branch convenience
   tag only.

## Alternatives considered

### Keep evidence archive publication on main only

Rejected.

Commit-addressed evidence archives are valuable, but they do not make evidence
a formal release artifact. A relying party should not have to infer release
evidence from nearby branch CI state.

### Rebuild the evidence archive from scratch in the release workflow

Rejected for now.

The reusable CI gate already builds the self-contained archive bundle. Reusing
that artifact keeps one bundle-construction path and reduces drift between CI
and release behavior.

### Publish release evidence before software artifacts

Rejected.

That ordering could leave a formal evidence artifact for a release whose
software publication failed. Release evidence is the final release state, not
an early pre-publish check.

### Treat weekly ratchet output as release evidence

Rejected.

Weekly ratchet is a vitality workflow for OTS and slow-path coverage. It can
support confidence in the system, but it is not tied to a release tag's
software artifacts or disclosure bundle.
