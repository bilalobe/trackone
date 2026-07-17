# ADR-060: Beta Anchor-Evidence Advancement and Verifier Sanity

**Status**: Accepted
**Date**: 2026-07-13

## Related ADRs

- [ADR-054](ADR-054-release-bound-evidence-artifacts.md): durable release carriers
- [ADR-056](ADR-056-ots-proof-state-metadata-and-verification-lanes.md): OTS state vocabulary
- [ADR-059](ADR-059-rust-native-conformance-archive-and-workflow-lanes.md): conformance archive and workflow split
- [ADR-061](ADR-061-full-draft-08-v2-conformance-and-archive-v3.md): archive v3 and full draft-08 v2 conformance

## Context

A fresh GitHub-hosted runner cannot economically bootstrap Bitcoin Core for
every timestamp verification. The work is Bitcoin initial block download and
consensus validation, not calculation of the OpenTimestamps leaf. Reusing a
large mutable Core datadir through an Actions cache is slow, fragile, and does
not make a receipt independently reproducible.

Two open OpenTimestamps client changes are relevant:

- [opentimestamps-client#163](https://github.com/opentimestamps/opentimestamps-client/pull/163)
  adds JSON `info`/`verify` output and separates pending exit code 2 from hard
  failure exit code 1.
- [opentimestamps-client#164](https://github.com/opentimestamps/opentimestamps-client/pull/164)
  adds dense and sparse Bitcoin-header sidecars and offline verification.

Neither change is an upstream release. The header implementation checks a
header against its declared proof-of-work target and, for a dense archive,
previous-hash continuity. It does not validate expected `nBits` difficulty
transitions. Sparse sidecars also do not establish a best-work active chain.
Explorer quorum therefore provides useful independent attestation evidence,
but it is not full Bitcoin consensus validation and must not be reported as
`trustless-verified`.

At this ADR's review snapshot, all four inline remarks on #163 were resolved.
#164 had one [unresolved review remark](https://github.com/opentimestamps/opentimestamps-client/pull/164#discussion_r3570346261)
about using the already-open file descriptor, rather than a second path lookup,
when sizing a dense header archive. This workflow does not use that dense
archive/bootstrap path; it uses the sparse OTSV sidecar path and validates the
sidecar independently. The open remark nevertheless reinforces the exact-pin
and isolation policy.

The previous vitality workflow also timestamped a constant probe rather than
the verified conformance artifact for the current main commit.

## Decision

### Freeze the verified CI artifact

After successful main-branch CI, and every six hours for pending advancement,
the anchoring workflow downloads the exact conformance handoff, checks its
SHA-256 sidecar, compares the detached manifest with the archive copy, and runs
the bundled independent verifier outside the source checkout.

It then creates a canonical JSON `trackone-anchor-subject-v1` statement binding:

- the repository and full CI commit;
- the conformance archive filename, SHA-256, media type, and OCI carrier;
- the detached manifest digest;
- the successful independent-verification result digest; and
- the deterministic OTS verifier-sanity result and exact candidate commits;
- the standard-library detached anchor-receipt verifier digest.

The SHA-256 of those exact canonical UTF-8 bytes is the anchor identifier. The
stable `opentimestamps-client==0.7.2` release alone creates and upgrades the OTS
proof. Open candidate branches do not author proof state.

### Prove candidate behavior before advancing evidence

Each run installs the two candidate clients in separate virtual environments
at exact commits:

```text
JSON:    3fd9cc735b48e5103316adc53f587220315e18cb
headers: c0386ab1f1fe56e0d7742961e3e456e27c4f83a1
```

The workflow uses the official completed `hello-world.txt.ots` example and a
checked-in Bitcoin block 358391 header cross-checked through two public
sources. Sanity succeeds only if:

1. JSON info reports the known target digest and Bitcoin height;
2. JSON verify with Bitcoin disabled returns pending/manual status and exit 2;
3. a sparse sidecar verifies the completed proof offline;
4. both clients reject a modified target; and
5. the header client rejects a corrupted header.

This result proves compatibility and refusal behavior for a fixed known proof.
It does not upgrade the header client into a full consensus verifier.

### Monotonic evidence states

Receipts use a new `trackone-anchor-evidence-v1` contract and may advance only:

```text
stationary
  -> calendar-pending
  -> bitcoin-attested-structure
  -> bitcoin-header-quorum-verified
```

`failed` is reserved for malformed or contradictory evidence. Calendar and
public-header outages are liveness warnings: they retain the last valid state
and are retried. Proof revisions are retained in the continuity artifact, and
Bitcoin attestation heights may never disappear.

Continuity is recovered only from the newest non-expired state artifact of a
successful run of this workflow. Advancement snapshots its mutable files and
rolls them back if parsing, monotonicity, or publication preparation fails.
The v1 `bitcoin-header-quorum-verified` state is terminal: it is revalidated
locally but no longer upgraded or queried over the network. A pending anchor
may advance only with the exact verifier commits bound into its sanity result;
candidate-pin rotation therefore waits for pending anchors or requires an
explicit migration design.

`bitcoin-header-quorum-verified` means the pinned header client fetched every
attested height from a configured two-of-three public Esplora quorum, emitted a
sparse OTSV sidecar, and then verified the proof offline against that sidecar.
Every such receipt sets:

```json
"full_bitcoin_consensus_validated": false
```

A later full-node lane requires a persistent, independently operated Bitcoin
Core verifier and a new receipt contract. Header-only results cannot be
relabeled in place.

### Durable detached delivery

The conformance archive remains immutable and is never rewritten to contain
its own timestamp. Subject, OTS proof, normalized receipt, verifier-sanity
record, and optional sparse header sidecar are detached files.

Every materially new receipt is published to:

```text
ghcr.io/<owner>/<repo>/anchor-evidence:sha256-<receipt-sha256>
application/vnd.trackone.anchor-evidence.v1
```

The tag is content-addressed. A retry pulls back the existing object, checks the
receipt digest, and executes the verifier shipped and hashed inside that pulled
object from outside the repository checkout. Actions
artifacts retain the monotonic proof queue and operator diagnostics but are not
the durable carrier. A publication marker is committed to continuity state only
after that pull-back succeeds, avoiding repeated registry traffic for terminal
receipt revisions while preserving failed-run retry behavior.

## Consequences

### Positive

- The anchored subject is the independently verified artifact for the exact
  main commit, not a static vitality probe.
- Pending proofs advance within hours without repeated Bitcoin Core initial
  block download.
- Machine-readable state no longer depends on parsing human OTS output.
- Candidate-client regressions fail a deterministic positive/negative sanity
  gate before they can advance a real receipt.
- Public-header evidence is useful and portable without overclaiming its trust
  model.
- Receipt revisions and OCI delivery are immutable and pull-back verified.

### Negative

- Two open upstream commits are provisional build-time dependencies. Their
  exact revisions must be deliberately updated and re-qualified.
- Public calendars and Esplora sources remain liveness dependencies for state
  advancement.
- Header quorum is weaker than local full-node consensus validation.
- The continuity queue remains an Actions artifact and must be periodically
  exercised before its retention window expires; durable receipt revisions are
  preserved in GHCR.

## Testing

1. Run the standard-library anchoring unit tests in ordinary CI.
2. Validate all three new schemas through the offline schema catalog.
3. Require the deterministic OTS sanity vector on every vitality run.
4. Reject subject/proof digest drift and Bitcoin-height regression.
5. Publish receipts only under their SHA-256-derived tag, pull them back, and
   run `anchor_evidence.py verify-bundle` on the pulled directory.
