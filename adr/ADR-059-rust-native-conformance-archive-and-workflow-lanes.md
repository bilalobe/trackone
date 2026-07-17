# ADR-059: Rust-Native Conformance Archive and Workflow Lanes

**Status**: Superseded by [ADR-061](ADR-061-full-draft-08-v2-conformance-and-archive-v3.md)
**Date**: 2026-07-12

ADR-061 preserves the workflow split, offline verification, and archive-v2
history while moving current subjects to archive v3 and declaring scoped full
draft-08 v2 conformance.

## Related ADRs

- [ADR-040](ADR-040-commitment-test-vectors-and-conformance-gates.md): commitment vectors and gates
- [ADR-053](ADR-053-beta-public-contract-spine.md): artifact-family and schema migration rules
- [ADR-054](ADR-054-release-bound-evidence-artifacts.md): release-bound carrier and pull-back invariant
- [ADR-055](ADR-055-independent-verifier-negative-fixture-corpus.md): detached refusal floor
- [ADR-056](ADR-056-ots-proof-state-metadata-and-verification-lanes.md): exact OTS proof states
- [ADR-060](ADR-060-beta-anchor-evidence-advancement-and-verifier-sanity.md): beta anchor evidence and verifier sanity

## Context

The beta branch correctly retired the alpha Python, wheel, tox, stationary
calendar, and release plumbing. It also removed invariants that remain relevant
to the Rust-native product: offline contract validation, a self-contained
detached verifier, commit-addressed publication survivability, and a real OTS
vitality lane.

The interim release workflow reconstructed a different payload but continued
publishing it as `application/vnd.trackone.evidence.archive.v1+tar`. It used
placeholder `example.org` schema identifiers, built non-deterministic tarballs,
and verified pull-backs by copying vectors into the source checkout. That does
not preserve the v1 artifact meaning or prove repository-independent use.

## Decision

### A distinct conformance archive v2 family

The Rust-native contracts, vectors, packaged crates, Helm chart, and detached
verifier form a new artifact family:

```text
ghcr.io/<owner>/<repo>/conformance-archive:<subject>
application/vnd.trackone.conformance.archive.v2+tar
```

Release subjects use the release tag. Successful main-branch CI subjects use
`sha-<full-commit>`. Historical `evidence-archive` v1 objects remain untouched.

Every archive contains a schema-governed `conformance-manifest.json`, complete
`SHA256SUMS`, the unified schemas/CDDL and schema catalog, v1 vectors, v2 preview
vectors and detached bundles, the ADR-055 negative fixtures, exactly the eight
current workspace crate packages, exactly one current Helm chart, a Linux
x86-64 `trackone-evidence` binary, and a standard-library detached runner.

The archive claims v1 vector replay, v2 preview replay, the negative-fixture
floor, and offline schema resolution. It explicitly does not claim full v2
conformance.

### Public schema provider and offline resolution

HTTP schema identifiers use the real raw repository provider under:

```text
https://raw.githubusercontent.com/bilalobe/trackone/main/toolset/unified/schemas/
```

URN identifiers for the v2 draft contracts remain URNs. CI and detached
verification resolve all identifiers through the shipped catalog and fail on
dangling or network-only references. The provider is a discovery location; the
checksummed archive copy is the release-verification authority.

### Workflow responsibility split

- PR/push/reusable CI runs formatting, default and supported Rust feature
  matrices, production builds, schema/reference checks, corpus replay, package
  verification, deterministic assembly, and detached verification.
- After successful main-branch push CI, a separate workflow publishes the
  CI-built archive under its immutable commit tag, pulls it back, and executes
  only material from the extracted archive.
- Tag release first validates an annotated tag and version alignment. It reuses
  CI-built crates, chart, and release-subject archive; publishes crates and Helm;
  then publishes and pulls back the archive. A GitHub prerelease record is the
  final state and carries compact digest/verification records.
- A main-CI-triggered, six-hourly, and manual anchoring-vitality workflow uses
  the pinned stable OpenTimestamps client to stamp the exact independently
  verified conformance subject. Exact-commit candidate clients must pass a
  deterministic verifier sanity vector before receipts can advance through
  `calendar-pending`, `bitcoin-attested-structure`, or
  `bitcoin-header-quorum-verified`. ADR-060 forbids treating the header-quorum
  stage as full-node `trustless-verified`.

Actions artifacts are handoff and operator records, not archival carriers.
Commit/release OCI tags are immutable: a retry may reuse identical bytes but
must fail if the existing tag resolves to different archive bytes.

## Consequences

### Positive

- The beta workflows retain the current Rust-native product boundary without
  losing the alpha survivability and detached-verification invariants.
- The v1 media type is no longer overloaded with a different artifact meaning.
- Release and main publication share one assembly path and exact validated
  package inputs.
- Pull-back checks no longer depend on a repository checkout.
- Real OTS availability and Bitcoin validation remain visible without making
  external network vitality a release prerequisite.

### Negative

- CI builds a release-mode verifier and packages Helm/crates on every PR.
- Detached binaries are immediately runnable only on Linux x86-64; other
  platforms rebuild from the included crate sources.
- Public calendar or header-source outages can delay a receipt at its previous
  monotonic state. Full-node trustless verification requires a separate
  persistent verifier lane.
- Releases now require annotated tags; cryptographic tag-signature enforcement
  remains deferred until trusted signer identities are configured.

## Testing & Migration

1. Validate every schema under Draft 2020-12 with local-only reference
   resolution and reject placeholder providers.
1. Build the same archive twice and require byte-identical SHA-256 results.
1. Execute the v1 vectors, v2 preview records/bundles, and ADR-055 cases from an
   extracted archive without `PYTHONPATH` or source checkout access.
1. Require main and release OCI pull-back digests to match the CI handoff.
1. Keep `evidence-archive` v1 tags immutable and begin publication only under
   `conformance-archive` v2.
