# ADR-045: Git-Signed Evidence Distribution Plane for Release and Small Authoritative Artifacts

**Status**: Accepted
**Date**: 2026-03-13
**Updated**: 2026-03-13

## Related ADRs

- [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md): Canonical day artifacts and OTS anchoring
- [ADR-023](ADR-023-ots-vs-git-integrity.md): OTS remains the time-anchoring authority; Git is not the trust root
- [ADR-035](ADR-035-workspace-versioning-and-release-visibility.md): Release visibility and versioned boundaries
- [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md): CBOR-authoritative artifact family
- [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md): Verification bundle semantics
- [ADR-043](ADR-043-phased-bundle-manifest-maturity-for-id.md): Manifest maturity and release packaging

## Context

TrackOne already has multiple provenance layers with different jobs:

- canonical CBOR artifacts and Merkle/day records define what is being attested;
- OTS proofs and sidecars provide external time anchoring;
- optional peer/TSA channels add parallel evidence;
- Buildx/GitHub build provenance attests how OCI images were built and published.

That provenance stack is correct, but it still leaves a practical gap for
resource-constrained and intermittently connected deployments:

- how to distribute small, high-value evidence and control artifacts cheaply;
- how to preserve operator signoff on curated release/evidence sets;
- how to move authoritative small artifacts across air-gapped or low-connectivity
  environments without introducing a new always-on service.

Git is already part of the operator workflow and provides properties that are
useful here:

- content-addressed storage;
- signed commits and tags;
- cheap replication and offline transport via fetch, clone, and bundle;
- append-only reviewable history when used with linear policy.

At the same time, [ADR-023](ADR-023-ots-vs-git-integrity.md) remains correct:

- Git commit/tag timestamps are not an external time authority;
- Git signatures do not replace OTS proofs;
- Git object IDs are not TrackOne's normative artifact digest contract; and
- Buildx release attestation already covers container build provenance better
  than Git history does.

The opportunity is therefore not to replace OTS or Buildx provenance with Git,
but to use Git as a signed distribution and curation plane for a narrow class of
small authoritative artifacts.

The first pilot implementation now exists in-tree:

- [scripts/evidence/export_release.py](../scripts/evidence/export_release.py)
  exports a curated evidence bundle from a completed pipeline run;
- exported bundles can be committed, tagged, and shipped as `git bundle`
  archives; and
- detached verification still runs from the exported files themselves via
  `verify_cli --root <bundle-root> --facts <bundle-root>/facts`.

That pilot is intentionally narrow. It proves that Git can improve distribution
and operator signoff without being admitted into the verifier's trust contract.

## Decision

### Git MAY be used as a signed evidence distribution plane

TrackOne MAY publish and replicate selected evidence/control artifacts through a
dedicated signed Git history, repository, namespace, or Git bundle.

This role is complementary to OTS and Buildx provenance:

- OTS/TSA/peer evidence remains the authority for time anchoring and
  independent artifact verification;
- Buildx/GitHub provenance remains the authority for OCI image build provenance;
- Git-signed history attests operator curation, publication, and distribution
  of a chosen artifact set.

### Suitable artifact classes are small, high-value, and low-rate

Git distribution is appropriate for artifacts such as:

- release-level verification manifests;
- OTS proof sidecars and metadata copies;
- signed provisioning inputs and policy/control-plane artifacts;
- SBOMs, release notes, and verifier/configuration snapshots;
- small conformance bundles and published test vectors.

Git distribution is not appropriate for:

- high-rate telemetry streams;
- hot runtime state such as replay windows and mutable device tables;
- large mutable datasets or fact-by-fact day ingest;
- any artifact whose normal operation would cause repository growth to become
  the primary scaling bottleneck.

### The preferred Git unit is a signed release/evidence set, not per-fact history

When Git is used for TrackOne evidence distribution, the preferred unit is a
signed commit or signed tag containing a coherent release/evidence set plus a
manifest of internal artifact digests.

TrackOne SHOULD prefer:

- a signed tag for a published release/evidence boundary; or
- a signed linear commit series for append-only low-rate evidence batches.

TrackOne SHOULD NOT treat one-commit-per-fact or other high-churn Git history as
the default operational model for telemetry evidence.

### The evidence repository is a curated subset, not a second runtime workspace

When TrackOne publishes an 'evidence set' into Git, it SHOULD publish a curated,
portable subset of pipeline outputs rather than mirroring a full working
directory such as `out/site_demo/`.

That means:

- publish canonical artifacts, manifests, proof sidecars, provisioning inputs,
  and other stable derived outputs;
- exclude hot runtime state, transient audit/debug residue, and other mutable
  local workspace files; and
- normalize published paths so the evidence bundle is portable across machines
  and import methods.

The practical implication is that a Git-published evidence set is not "the
pipeline output directory committed as-is." It is a publication boundary built
from a subset of the pipeline outputs.

### Git signatures attest publication and curation, not external time

The semantics of a signed Git commit/tag in this role are:

- a named operator or maintainer key approved or published this artifact set;
- the repository state containing that artifact set has integrity under Git's
  object model; and
- the manifest inside that state identifies the TrackOne artifacts being
  distributed.

Those signatures do not mean:

- Git itself externally time-anchored the evidence;
- the artifacts are valid without OTS/TSA/peer verification; or
- the relevant container images were reproducibly built.

### Buildx release attestation and Git-signed evidence solve different problems

TrackOne explicitly distinguishes:

- **Buildx/GitHub build provenance**:
  attests how an OCI image or build output was produced;
- **Git-signed evidence distribution**:
  attests that a maintainer/operator published or curated a particular artifact
  set;
- **OTS/TSA/peer proofs**:
  attest externally verifiable time-binding and integrity of the authoritative
  TrackOne artifacts.

None of these layers replaces the others.

### Verification logic MUST NOT depend on Git metadata

TrackOne verifiers and conformance checks MUST continue to verify released
artifacts from their canonical digests, manifests, and OTS/TSA/peer sidecars.

They MUST NOT require:

- repository access;
- commit timestamps;
- Git commit IDs as the primary artifact hash contract; or
- Git signatures as a substitute for artifact-level proof verification.

Git remains an optional transport and publication layer, not a required verifier
dependency.

### "Not Git-aware" is a deliberate verifier boundary

In this ADR, "the verifier contract did not become Git-aware" has a precise
meaning:

- verifiers do not inspect commit IDs, refs, tags, or repository topology when
  deciding artifact validity;
- verifiers do not rely on commit timestamps or Git signatures to satisfy the
  time/integrity checks owned by OTS/TSA/peer channels; and
- the same exported evidence set should verify equivalently whether it was
  obtained from a live clone, a `git bundle`, a tarball, removable media, or a
  plain directory copy.

Git may attest publication intent and curator identity. It does not become a
hidden proof oracle for validity.

### Git publication complements but does not replace existing provenance layers

This ADR does not weaken earlier provenance decisions:

- [ADR-023](ADR-023-ots-vs-git-integrity.md) still governs the time/integrity
  authority boundary;
- Buildx/GitHub release attestation still covers OCI build provenance more
  directly than Git history does; and
- manifests and sidecars remain the machine-readable binding layer for exported
  evidence bundles.

The operational gain is distribution effectiveness, not a new root of trust.

## Consequences

### Positive

- Gives TrackOne an inexpensive signed transport/distribution mechanism for small
  authoritative artifacts.
- Fits constrained and intermittently connected environments well, including
  Git bundle export/import workflows.
- Makes good use of the existing maintainer discipline around signed commits/tags.
- Lets TrackOne publish evidence in a form that remains verifier-independent
  after detached export/import.
- Preserves clean separation between:
  - operator publication intent;
  - build provenance; and
  - externally anchored artifact verification.

### Negative

- Adds another publication surface that must be documented so operators do not
  confuse Git signatures with OTS time anchoring.
- Creates some pressure to overuse Git for datasets it does not scale well for.
- Requires discipline to keep manifests and signed release/evidence sets
  coherent.
- Requires a curated keep/drop boundary so the runtime state does not leak into
  published evidence sets.

## Alternatives Considered

- **Keep Git limited to code history only**: rejected because it leaves a useful
  low-cost signed distribution primitive unused for small evidence/control
  artifacts.
- **Use Git signatures as the primary release attestation**: rejected because
  Buildx/GitHub provenance is a better fit for OCI build provenance.
- **Treat Git timestamps or signed tags as a replacement for OTS**: rejected per
  [ADR-023](ADR-023-ots-vs-git-integrity.md); Git is not an external time
  authority.
- **Publish all telemetry evidence directly into Git history**: rejected because
  it does not scale and would blur runtime data flow with curated evidence
  distribution.

## Testing & Migration

1. Keep verifier and conformance logic independent of repository access.
1. Prefer release/evidence manifests that carry artifact digests inside the
   signed Git-published set.
1. The current pilot path is:
   - export a curated day-scoped bundle with
     [scripts/evidence/export_release.py](../scripts/evidence/export_release.py);
   - optionally commit/tag it in an evidence repository;
   - optionally create a `git bundle`; and
   - verify the imported bundle contents with
     `verify_cli --root <bundle-root> --facts <bundle-root>/facts`.
1. Treat detached verification from exported bundles as the acceptance test for
   this ADR's boundary: Git may move the bundle, but verification must still be
   driven by the artifacts, manifest, and sidecars inside it.
1. Document which artifacts are eligible for Git-signed distribution and which
   remain runtime-only or OTS-only concerns.
