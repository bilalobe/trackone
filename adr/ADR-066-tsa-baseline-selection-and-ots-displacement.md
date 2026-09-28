# ADR-066: TSA Baseline Selection and the Displacement of OTS

**Status:** Accepted
**Date:** 2026-09-10

> **Profile source:** the active profile source is the
> [current VTL document on the IETF Datatracker](https://datatracker.ietf.org/doc/draft-elkhatabi-verifiable-telemetry-ledgers/).
> The repository does not track copies of the Internet-Draft (`.gitignore:20`
> ignores `docs/draft-*`). Section numbers below are read from the -12
> rendering and the proposed text targets -13.
>
> **Reproducing the revision counts.** The table in "What the revision history
> shows" is derived from local renderings of -00 through -12, which are not in
> the repository. It is reproducible from the published Datatracker revisions:
> fetch each `draft-elkhatabi-verifiable-telemetry-ledgers-NN.txt` and run
> `grep -c 'OpenTimestamps'`, `grep -cE '\bOTS\b'`, `grep -ci 'peer'`, and
> `grep -c 'separate specification'` against each. The `-i` flag must not be
> used for the OTS count: it matches `roots` and `batch_roots` and inflates
> every revision.

## Related ADRs

- [ADR-015](ADR-015-parallel-anchoring-ots-rfc3161-tsa.md): parallel OTS, RFC 3161, and peer channels
- [ADR-022](ADR-022-first-party-stationary-ots-calendar-service.md): first-party stationary OTS calendar
- [ADR-056](ADR-056-ots-proof-state-metadata-and-verification-lanes.md): OTS proof-state metadata and verification lanes
- [ADR-062](ADR-062-rfc5816-signer-certificate-binding.md): RFC 5816 signer-certificate binding
- [ADR-064](ADR-064-vtl-versioning-reset.md): current VTL profile and evidence slate
- [ADR-065](ADR-065-ers-relationship-and-commitment-determinism.md): relationship to RFC 4998 ERS

## Context

Two questions are outstanding and they share one answer.

First: why is the RFC 3161 TSA channel the baseline, when OpenTimestamps,
peer signatures, and RFC 4998 ERS each offer real properties it does not?
Second: OTS was the default anchoring channel for eight revisions and is
absent from -12. Was that a scope decision or an abandonment?

The draft answers neither. Section 6.1 requires the `tsa` channel key in
every baseline-conformant result, Section 6.3 states that "alternative
timestamping or attestation mechanisms require a separate specification",
and Section 12.3 analyses TSA trust limits — but nothing in -12 states the
criterion that selected RFC 3161 over the alternatives the document once
carried, and OTS is not named anywhere in the revision.

That silence is the same defect [ADR-065](ADR-065-ers-relationship-and-commitment-determinism.md)
records for ERS, in a more acute form: ERS at least survives as three
passing mentions, whereas OTS went from default channel to zero mentions
with no positioning statement anywhere in the document.

### What the revision history shows

Occurrences per revision, counted as described in the Profile source note:

| revision | `OpenTimestamps` | `OTS` | `peer` | `separate specification` | role of OTS |
|---|---|---|---|---|---|
| -00 … -07 | 3–7 | 21–43 | 5–22 | 0–3 | **default anchoring channel**; RFC 3161 and peers optional and parallel |
| -08 | 5 | 40 | 18 | 2 | inverted: RFC 3161 "mandatory-to-implement"; OTS and peers "optional parallel" |
| -09 | 4 | 39 | 32 | 3 | OTS selectable "only as an additive, deployment-specific timestamp profile" (§6.4) |
| -10 … -12 | 0 | 0 | 0 | 5–7 | removed; "alternative timestamping and attestation mechanisms are outside this profile" |

The -00 abstract reads "OpenTimestamps (OTS) is the default anchoring
mechanism; optional parallel attestation methods (RFC 3161 timestamp
responses, peer signatures)". The -10 abstract reads "a baseline producer
uses RFC 3161 timestamping, as updated by RFC 5816 [...] Alternative
timestamping and attestation mechanisms are outside this profile."

### The removal was scope, not abandonment

Four independent pieces of evidence, all from the documents themselves:

1. **OTS did not leave alone.** Peer signatures went from 32 mentions in -09
   to 0 in -10, in the same revision. A judgement against OTS on its merits
   would not have removed peer signatures with it. This is one coordinated
   narrowing to a single specifiable baseline. Verified against renaming:
   `witness`, `co-sign`, `countersign`, `cosign`, `quorum`, `notar`, and
   `attestor` are all 0 in -12, and the 6 occurrences of `threshold` are all
   record-count or byte-size limits.
2. **The replacement sentence is a forward reference.** "Alternative
   timestamping and attestation mechanisms are outside this profile and
   **require a separate specification**" is deferral language, not rejection
   language.
3. **The re-entry socket was retained and strengthened.** `extension`
   mentions went 20 → 23 → 25 across -09/-10/-12, and Section 6.1 states that
   "a separate specification can define an additional evidence mechanism **and
   its validation result**" — precisely the distinct-channel-result slot that
   -09 §6.4 had built for OTS (`com.example.ots-verification`).
4. **Appendix D.6 classifies the case explicitly.** Under "Separate evidence
   and disclosure specifications", -12 lists "**additional timestamp
   channels**" among the things that "can preserve the committed artifact",
   qualified only by "it cannot replace baseline TSA validation while claiming
   baseline success." The document therefore already classifies an additional
   timestamp channel as a legitimate separate specification. It simply never
   says which one it had in mind.

SCITT received the same mechanical treatment — out of baseline, re-enterable
by separate specification — and nobody reads SCITT as abandoned, because
Section 1.2 names it. ERS likewise, once ADR-065's text lands. OTS is the one
displaced mechanism that got the socket and no paragraph.

### Why RFC 3161 is the baseline

This is a reconstruction from the draft's structure and constraints. It is
not recorded in -12 and is not a quotation of prior intent; see "Author gap"
below.

The selection criterion is not which channel offers the strongest evidence.
It is which channel a verifier can be *required* to implement such that
independent verifiers reach the same verdict. Four properties follow, and
only RFC 3161 has all four.

1. **The complete validation algorithm is specifiable by reference.**
   RFC 3161, RFC 5816, RFC 5652, and RFC 5035 form a closed, referenceable
   stack, and every restriction in §6.4 narrows something already normatively
   defined. OTS cannot clear this bar, and -09 §6.4 concedes it directly: the
   document "does not define an OTS wire format, calendar trust model,
   accepted attestation set, upgrade procedure, or validation algorithm."
   Making OTS baseline would mean specifying all five inside a VTL draft, for
   an ecosystem the author does not operate. Peer quorum is further out still:
   membership and threshold are deployment-defined by nature, so there is no
   algorithm to specify.
2. **The verdict is reproducible offline from a closed set of named inputs.**
   §6.4's policy list — trust anchors, accepted policy OIDs, revocation policy
   including historical certificate status at `TSTInfo.genTime`, algorithm
   strengths, maximum future skew, and the verifier-local time source — is
   finite and enumerable. Given those inputs and the bytes, two independent
   verifiers reach the same answer years later with no network access. The
   OTS trustless lane requires Bitcoin headers, a live and growing chain;
   [ADR-056](ADR-056-ots-proof-state-metadata-and-verification-lanes.md) is
   already careful to separate "Bitcoin-attested structure" from "trustless
   verified" for exactly this reason.
3. **It is synchronous and bounded.** VTL seals on an elapsed-time interval
   and needs a per-segment attestation. A TSA answers in one round trip with
   `granted(0)`. OTS is structurally delayed: pending calendar attestation
   first, upgrade later. §6.1 requires successful timestamp validation for a
   baseline success result, so a channel that is normally pending at sealing
   time cannot be the one gating that result. -09 §6.4.1 attempted to carry
   both and the seams are visible in it.
4. **The trust is nameable and pinnable.** A TSA is pinned by signer
   certificate SHA-256 (per
   [ADR-062](ADR-062-rfc5816-signer-certificate-binding.md)), policy OID, and
   trust anchors, and §12.3 states plainly that "the TSA is the only signing
   authority in the baseline." When it misbehaves there is a named,
   accountable party whose policy a relying party accepted. Bitcoin's trust is
   diffuse, which is its virtue for durability and its problem for a policy
   statement.

**ERS is not a competitor on this axis at all.** The `-13-ers-playground`
profile requires that "the `timeStamp` field of the ArchiveTimeStamp MUST
contain an RFC 3161 TimeStampResp restricted as in the RFC 3161 profile."
ERS consumes RFC 3161 as its time source. Selecting ERS *instead of* RFC 3161
is not a coherent option; the 3161 profile is still required underneath. This
is the sharpest form of ADR-065's "wrong layer" finding.

**The baseline is deliberately the weakest of the four on trust.** §12.3
documents the cost without flinching: "a key holder can mint a well-formed
token over any digest and asserted genTime." A single trusted third party can
backdate if compromised, TSA certificates expire and require archived
revocation evidence to validate old tokens, and Bitcoin anchors have neither
problem. Choosing the weakest fully-specifiable trust model as the
interoperability floor is the deliberate trade, not an oversight. It is also
why a strong deployment still runs OTS alongside.

### Author gap

Not established by this ADR, and to be filled by the author or struck:

- Whether the -10 editing pass had a reason for removing OTS beyond
  reviewability and specifiability.
- Whether the existing legal recognition of RFC 3161 timestamps in evidentiary
  regimes (for example eIDAS qualified timestamps and the ETSI profiles) was
  part of the selection reasoning. This is plausible for environmental
  telemetry used as evidence and is currently invisible in the draft, but it
  is unverified and is deliberately excluded from the reconstruction above.

## Decision

- **Keep RFC 3161 as the sole baseline timestamp channel.** The four
  properties above are the criterion, and no other channel satisfies them.
- **Record OTS as displaced, not rejected.** Its removal at -10 was a scope
  narrowing with a re-entry path that -12 still carries in §6.1 and
  Appendix D.6.
- **State the relationship in Section 1.2 of -13**, so that the strongest
  prior anchoring channel is positioned by name rather than by absence.
- **Retain `trackone-ots` and ADR-056.** OTS remains a supported
  deployment-specific durability channel outside the baseline result path. It
  MUST NOT set or influence the `tsa` channel status or the overall outcome,
  per §6.1's extension-opacity rule.
- **This decision does not depend on the scope-versus-abandonment
  reconstruction.** A Section 1.2 paragraph naming OTS as an out-of-baseline
  composition is correct under either reading, which is why the status is
  Accepted while the author gap remains open. The alternative — writing an
  abandonment rationale — would commit the document to defending a technical
  judgement against OTS that the workspace contradicts by shipping
  `trackone-ots`.

## Proposed Section 1.2 text for -13

Insertion point: **immediately after the two `<t>` blocks introduced by
[ADR-065](ADR-065-ers-relationship-and-commitment-determinism.md)**, and last
in Section 1.2. ADR-065 places its blocks after the existing SCITT/COSE
paragraph; the resulting order is CT, SCITT/COSE, ERS, then this. XML-ready;
the repository does not hold the draft source, so this is paste-in text for
wherever -13 is edited.

```xml
<t>
  Earlier revisions of this document carried OpenTimestamps as an anchoring
  channel and, in later revisions, as an additive deployment-specific
  timestamp profile. It is not part of this baseline. OpenTimestamps is a
  deployed public timestamping ecosystem rather than an IETF-standardized
  proof format, and a baseline channel requires that this document specify a
  complete validation algorithm, a closed set of verifier policy inputs, and a
  verdict two independent verifiers reproduce offline from those inputs and
  the evidence bytes alone. This document does not define an OpenTimestamps
  wire format, calendar trust model, accepted attestation set, upgrade
  procedure, or validation algorithm, and does not adopt one by reference.
</t>
<t>
  A deployment can operate such a channel alongside the baseline, as a
  composition of the kind described in Appendix D.6 and Section 6.1: a
  separate specification defines the additional evidence mechanism and its
  validation result without altering the authoritative segment artifact or
  this commitment profile. Such a deployment identifies its own validation
  profile and verifier policy and reports the result under a distinct channel
  key; it is not an RFC 3161 TSA channel result. Under Section 6.1 the
  presence, absence, or contents of that evidence do not change a baseline
  channel status or overall outcome, and a baseline success result still
  requires successful validation on the RFC 3161 channel.
</t>
```

## Consequences

**Section references to reconcile in -13.** Appendix D.6's "additional
timestamp channels" phrase and Section 6.1's "additional evidence mechanism"
sentence should reference the new Section 1.2 statement, so the document
positions the channel once rather than gesturing at it from two appendix-level
locations.

**ADR status marking, per ADR-050 Section 3.** That policy requires a
supersession marker when a newer ADR changes the authority or scope of an older
*accepted* decision, while affirming that historical ADRs remain valuable as
records. Applying it, this decision changes the authority of exactly one ADR:

- **[ADR-015](ADR-015-parallel-anchoring-ots-rfc3161-tsa.md) — mark superseded
  by this ADR.** Its decision adopts parallel anchoring and treats "successful
  verification of either anchor as sufficient for timestamp obtained", which
  the single-baseline contract of Section 6.1 overrides. It also carries
  `peer_signatures_count` and the legacy `out/<site>/day/` and `verify_cli.py`
  surfaces that CLAUDE.md excludes from the supported slate. A status-line
  change is sufficient; the body is a valid record of a decision taken at the
  time and needs no edit.

No other ADR requires marking:

- **[ADR-022](ADR-022-first-party-stationary-ots-calendar-service.md)** is
  **Proposed**, not Accepted. Its line 233 claim that "removing OTS would
  conflict with core design" was an argument inside a proposal that was never
  accepted, so it never governed implementation and ADR-050 Section 3 does not
  reach it.
- **[ADR-056](ADR-056-ots-proof-state-metadata-and-verification-lanes.md)**
  remains current and is affirmed rather than superseded: its lane vocabulary
  is the deployment-specific validation profile that -09 Section 6.4 demanded
  and that the new Section 1.2 text permits.
- **[ADR-057](ADR-057-publication-channel-status-and-export-refusal-policy.md)**
  decides a channel-agnostic status vocabulary and export gate. OTS appears in
  its context and rejected-alternatives sections only, and its vocabulary
  aligns with the Section 6.2 TSA channel status values.
- **ADR-003, ADR-007, ADR-008, ADR-014, ADR-020, ADR-021, ADR-023, ADR-024, and
  ADR-030** describe the era in which OTS was the default channel. Their
  framing is dated, but this ADR does not change what they decided; their
  authority was already narrowed by the versioning reset in
  [ADR-064](ADR-064-vtl-versioning-reset.md) and by the removal of the legacy
  v1 surface. They stand as historical records, unedited.

**No implementation change follows from this ADR.** The commitment,
anchoring, and verification code is unaffected. The separate finding that
`trackone-rfc3161` still shells out to `openssl ts -verify` and
`openssl verify` (`crates/trackone-rfc3161/src/lib.rs:551`, `:743`, `:759`)
while the native ASN.1 stack is already pinned in `[workspace.dependencies]`
is an [ADR-062](ADR-062-rfc5816-signer-certificate-binding.md) follow-up on a
different axis and is tracked separately.

## Alternatives considered

- **Leave Section 1.2 as is.** Rejected. OTS was the default anchoring channel
  for eight revisions. Silence after that history reads to a returning
  reviewer as an unexplained reversal, which is a worse outcome than the ERS
  omission ADR-065 corrects.
- **Record the removal as an abandonment of OTS.** Rejected. The evidence
  points the other way — peer signatures were removed in the same pass, the
  replacement sentence defers rather than rejects, and Appendix D.6 still
  classifies additional timestamp channels as a legitimate separate
  specification. Writing an abandonment rationale would also contradict the
  workspace, which still ships `trackone-ots` and an Accepted ADR-056.
- **Restore OTS as an additive channel in the baseline document, as in -09.**
  Rejected. -09 §6.4 shows the cost: every substantive validation term is
  pushed onto the deployment, so the document carries a channel it cannot
  define. That is specification weight without interoperability gain. The
  separate-specification path preserves the option at lower cost.
- **Promote OTS to baseline and demote RFC 3161.** Rejected on properties 1
  through 3 above, decisively on 1.
- **Add a rationale section to the draft covering the selection criterion.**
  Deferred, not rejected. The reconstruction above is the natural source text
  if -13 or a later revision adds one; the Section 1.2 paragraphs carry the
  minimum needed in the meantime.
