# ADR-061: Full Draft-08 V2 Conformance and Conformance Archive V3

**Status**: Accepted
**Date**: 2026-07-14

## Related ADRs

- [ADR-040](ADR-040-commitment-test-vectors-and-conformance-gates.md): commitment vectors and gates
- [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md): disclosure classes
- [ADR-053](ADR-053-beta-public-contract-spine.md): artifact-family and schema migration rules
- [ADR-055](ADR-055-independent-verifier-negative-fixture-corpus.md): detached refusal floor
- [ADR-059](ADR-059-rust-native-conformance-archive-and-workflow-lanes.md): archive v2 and workflow split
- [ADR-060](ADR-060-beta-anchor-evidence-advancement-and-verifier-sanity.md): anchor evidence over verified archives

## Context

ADR-059 introduced `conformance-archive` v2 while the canonical-CBOR v2
profile was still a preview. It deliberately limited the archive claim to v2
vector replay and explicitly excluded full v2 conformance.

The draft-08 implementation now covers the complete repository conformance
boundary: exact canonical-record validation, deterministic segment and batch
commitments, durable interval production, predecessor chaining, portable
verification bundles, disclosure Classes A, B, and C, and RFC 3161 timestamp
verification. Positive and negative fixtures exercise those behaviors through
the Rust verifier, contract checker, and detached archive verifier.

Continuing to publish that larger claim set under the archive-v2 manifest
would either understate the artifact or change the meaning of an existing
versioned family. The archive therefore needs a new manifest and media type,
and the full-conformance claim needs an explicit scope.

## Decision

### Publish conformance archive v3

Current commit-addressed and release-addressed conformance artifacts use:

```text
trackone-conformance-archive-v3
application/vnd.trackone.conformance.archive.v3+tar
ghcr.io/<owner>/<repo>/conformance-archive:<subject>
```

The manifest is governed by
`toolset/unified/schemas/conformance_archive_manifest_v3.schema.json`. The
archive remains deterministic and checksummed, resolves its schemas offline,
contains its detached verifier, and is verified again after OCI retrieval.

Archive-v2 manifests and media types remain immutable historical contracts.
Consumers that need to anchor or inspect existing v2 subjects may continue to
accept them, but new CI and release subjects are produced as archive v3.

### Claim full draft-08 v2 conformance

An archive-v3 manifest MUST assert and the detached verifier MUST enforce this
claim set:

- canonical-CBOR v1 vector replay;
- canonical-CBOR v2 vector replay;
- full draft-08 v2 conformance;
- durable v2 producer behavior;
- disclosure Classes A, B, and C;
- the RFC 3161 timestamp channel;
- the negative-fixture refusal floor; and
- offline schema resolution.

`v2_full_conformance` means conformance to the TrackOne implementation profile
of `draft-elkhatabi-verifiable-telemetry-ledgers-08` documented in
`docs/conformance/draft-08.md` and evidenced by the checks shipped in the exact
archive. It does not claim:

- truth, completeness, or authenticity of telemetry before canonical-record
  admission;
- fitness for autonomous sanctions or actuation;
- availability or honesty of an external TSA;
- support for deployment profiles not represented by the conformance boundary;
  or
- full Bitcoin-consensus validation of OpenTimestamps receipts.

Verification results report the checks actually executed, skipped, or refused.
The words "full conformance" do not widen a result beyond those declared
artifacts, algorithms, disclosure classes, channels, and deployment profile.

### Keep protocol, detached, release, and vitality claims distinct

The v3 carrier packages several related but different assurances:

- protocol conformance comes from schemas, CDDL, vectors, implementations, and
  positive and negative replay;
- detached verification proves those checks run without a repository checkout;
- release integrity binds the exact crates, Helm chart, binary, manifest, and
  checksums to the commit or tag subject; and
- survivability and vitality workflows prove publication, retrieval, replay,
  and timestamp-state advancement.

Packaging these materials together does not make Helm or OCI publication part
of the telemetry commitment algorithm. Their presence proves that the released
operational artifacts correspond to the same verified subject.

## Consequences

### Positive

- The public archive claim matches the implemented draft-08 coverage.
- The archive-v2 meaning remains stable for archived consumers.
- Full-conformance scope and exclusions are machine-readable and documented.
- Release and main-branch subjects use the same detached verification path.

### Negative

- Consumers that require the current claim set must understand archive v3.
- CI and releases carry the cost of producer, disclosure, RFC 3161, packaging,
  and detached-verification gates.
- Any future expansion of the conformance boundary requires a new claim or
  artifact-family review rather than silently broadening
  `v2_full_conformance`.

## Testing and Migration

1. Require the v3 schema and builder to set every conformance claim to `true`.
1. Require the detached verifier to reject a missing, false, or additional
   claim and to replay the full archive corpus outside the source checkout.
1. Exercise canonical records, batching, segment chaining, durable producer
   transitions, Classes A/B/C, RFC 3161 validation, and negative fixtures in
   repository CI.
1. Publish new commit and release subjects with the v3 media type and verify
   their pulled bytes and manifest digests.
1. Retain v2 schemas and allow existing anchor subjects to identify either the
   v2 or v3 media type without rewriting historical evidence.
