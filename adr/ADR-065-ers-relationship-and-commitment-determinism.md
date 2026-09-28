# ADR-065: Relationship to RFC 4998 ERS and commitment determinism

**Status:** Accepted
**Date:** 2026-09-09

> **Profile source:** the active profile source is the
> [current VTL document on the IETF Datatracker](https://datatracker.ietf.org/doc/draft-elkhatabi-verifiable-telemetry-ledgers/).
> The repository does not track copies of the Internet-Draft (`docs/draft-*`
> is ignored). Section numbers below are read from the -12 rendering and the
> proposed text targets -13.

## Context

RFC 4998 Evidence Record Syntax is a Proposed Standard that already covers
hashing arbitrary data objects, combining many objects under one hash-tree
root, timestamping that root, reduced hash trees for proving selected objects,
verification, timestamp renewal, and hash-tree renewal when a hash algorithm
ages out. That is close enough to VTL's anchoring layer that a reviewer is
entitled to ask why VTL exists at all.

The draft does not currently answer. Section 1.2, "Relationship to Existing
Work", positions VTL against RFC 9162 Certificate Transparency and against
SCITT/COSE, and does not mention ERS. RFC 4998 appears only three times, all
outside that section: Section 10.1 and Section 12.3 each say a deployment
"can use an external renewal profile such as [RFC4998]", and Section 12.6
permits a separate specification to staple "a reduced-tree construction
inspired by [RFC4998], whose objects are not interchangeable with VTL batch
roots". Given the degree of overlap, silence in Section 1.2 plus three passing
mentions reads as evasion rather than as a considered boundary.

### What RFC 4998 actually says

Verified against RFC 4998 directly rather than from summary, because the
justification rests on it:

- **Within-group ordering is fixed.** Section 4.2 step 3: "For each data group
  containing more than one document, its respective document hashes are binary
  sorted in ascending order, concatenated, and hashed." Step 4 applies the same
  binary ascending sort at each level above. ERS is therefore *not*
  order-nondeterministic, and any argument that says so is wrong.
- **Grouping, arity, and padding are not fixed.** Step 4 says only to "place
  them in groups"; the partition of objects into groups and the arity of the
  tree are the generator's choice. Step 4 further permits padding outright:
  "If additional hash values are needed, e.g., so that all nodes have the same
  number of children, any data may be hashed using H and used."
- **Single-object evidence needs no tree.** Section 3.2: "In case of local
  generation, it might be easier to generate a simple Archive Timestamp
  without building hash trees. This can be accomplished by omitting the
  reducedHashtree field from the ArchiveTimestamp."
- **The root is what gets timestamped.** Section 4: "The root hash value,
  which represents unambiguously all data objects, is timestamped."
- **No retrieval protocol.** Section 1.1: "ERS does not specify a protocol for
  interacting with a long-term archive system."

The determinism distinction is therefore about tree *shape*, not ordering: the
same data objects under ERS admit several valid evidence trees, because
grouping, arity, and padding vary by generator. VTL requires that the same
admitted record multiset under the same policy produce exactly one commitment
structure and exactly one artifact byte string across independent
implementations.

### Three further mismatches

1. **VTL timestamps more than a record root.** The imprint is
   `SHA-256(exact segment artifact bytes)`, not `segment_root`. The artifact
   also commits ledger identity, serial number, closure policy and reason,
   predecessor digest, record count, batch roots, and the in-band
   `commitment_profile_id`. The timestamp therefore attests to those exact
   commitment semantics for that exact segment, which Section 6.3 relies on.
   ERS timestamps a root over data objects; recovering the VTL property means
   making the segment descriptor another ERS object and then specifying that
   exactly one descriptor belongs to the group, that its `record_count`
   corresponds to the archived objects, that those objects are exactly the
   segment membership, that duplicate occurrences count separately, and that
   no padding object can masquerade as a record.
2. **The chains are orthogonal.** `ArchiveTimeStampChain` and
   `ArchiveTimeStampSequence` exist for cryptographic renewal of the same
   evidence across time and algorithm migrations. VTL's chain is ledger
   evolution — serial continuity and the predecessor artifact hash across
   segments 17, 18, 19. Adopting ERS does not remove the need for the VTL
   chain.
3. **ERS starts after the hard part.** RFC 4998 begins from "select the data
   objects to archive". VTL specifies how those objects become a segment:
   the admission linearization point and which side of an elapsed-time
   boundary a concurrently arriving record falls on, crash recovery, atomic
   durable admission, exactly-once recovery, serial allocation, closure-state
   persistence, asynchronous sealing, and backpressure. ERS does not address
   any of it.

ERS also does not solve the retrieval and provenance problem in
`docs/diagrams/vtl-wire-sequence.md`. An evidence record proves an object
existed at T; it does not prove the object is the one a relying party was
meant to retrieve for a given ledger and segment. Section 6.3's independently
provisioned expected digest is still required.

## Decision

- **Keep the VTL commitment construction.** Do not replace the deterministic
  tree with an ERS profile. Reproducing the current guarantees through ERS
  requires pinning exact canonical records as data objects, duplicate
  occurrence semantics, deterministic topology, a padding prohibition, exact
  grouping, segment cardinality, descriptor binding, predecessor linkage,
  timestamp type, the SHA-256 profile, and verifier-result semantics — which
  is most of the VTL commitment algorithm specified a second time, in someone
  else's frame.
- **Do not require ERS on any producer.** Wrapping the existing artifact
  timestamp in an `EvidenceRecord` for a single data object adds an ASN.1
  wrapper around the timestamp already produced, since Section 3.2 permits
  omitting the reduced hash tree. The gain is standardized renewal, which is
  an archival concern, not a gateway concern.
- **Position ERS as the preservation layer above the artifact.** An ERS
  evidence record can preserve a VTL segment artifact and its timestamp
  evidence over a longer cryptographic lifetime. That is a supported
  composition, stated as such.
- **State the relationship in Section 1.2 of -13**, and stop carrying it only
  as three passing mentions.

## Proposed Section 1.2 text for -13

To be added after the existing SCITT/COSE paragraph. XML-ready; the repository
does not hold the draft source, so this is paste-in text for wherever -13 is
edited.

```xml
<t>
  The Evidence Record Syntax of <xref target="RFC4998"/> addresses long-term
  evidence for arbitrary data objects using hash trees, reduced hash trees,
  timestamps, and cryptographic renewal. VTL defines no alternative long-term
  archival evidence syntax and no renewal mechanism. It instead defines the
  deterministic production of a producer-local telemetry segment: byte-level
  admission, segment membership and lifecycle, durable recovery, a uniquely
  reproducible multiset commitment, ledger sequencing, and a timestamped
  authoritative segment artifact. An ERS evidence record can preserve a VTL
  segment artifact and its timestamp evidence over a longer cryptographic
  lifetime without altering the rules defined here.
</t>
<t>
  The two constructions are not interchangeable at the commitment layer.
  Section 4.2 of <xref target="RFC4998"/> fixes binary ascending ordering
  within each group but leaves the partition of objects into groups and the
  arity of the tree to the generator, and permits additional hashed values so
  that nodes have the same number of children. The same data objects therefore
  admit several valid evidence trees. VTL requires that the same admitted
  record multiset under the same closure policy yield exactly one commitment
  structure and exactly one authoritative artifact byte string across
  independent implementations. VTL also timestamps the digest of the complete
  segment artifact rather than a root over records alone, so the timestamp
  binds ledger identity, serial number, closure policy and reason, predecessor
  digest, and commitment profile together with the record multiset.
</t>
```

## Consequences

Three existing references need to point at the new Section 1.2 statement
rather than gesture past it, or -13 will contradict its own positioning:

- Section 10.1, "Long-lived deployments can use an external renewal profile
  such as [RFC4998]" — reference Section 1.2 for the relationship.
- Section 12.3, "An external renewal profile such as [RFC4998] can support
  long-term preservation but is not defined here" — same.
- Section 12.6, "a reduced-tree construction inspired by [RFC4998], whose
  objects are not interchangeable with VTL batch roots" — "inspired by" now
  reads as a hedge; the non-interchangeability is the substantive half and
  follows from the grouping and padding latitude recorded above.

No implementation change follows from this ADR. The commitment, anchoring, and
verification code is unaffected.

## Experiment result (2026-09-09)

The prototype was built and run: five canonical records (four are the
normative Appendix A vectors, the fifth a byte-identical duplicate of the
first) plus a `segment-metadata.cbor` descriptor, an RFC 4998 Section 4.2
hash tree implemented with its freedoms intact, and reduced proofs for two
records. The probe reproduces the normative `integer_1_leaf` value, so it is
measuring against the real construction. It is throwaway code, kept outside
the workspace, and is not part of the build.

### All four properties fail under literal Section 4.2

1. **Determinism.** Three legal generators over the *same* objects produced
   three different roots: groups 2/2/2 at arity 2 gave
   `3203a7c5...c463a550`, groups 3/3 at arity 3 gave `d2553dad...975d9a49`,
   and the first plan with one permitted padding value gave
   `5f49ebec...c5ed15b7`. This is the evidence behind the Section 1.2
   sentence; it no longer rests on reading alone.
2. **Occurrence count.** ERS carries no record count and no record/padding
   distinction, so a tree over five records and a tree over four records plus
   one padding value are both well-formed and a verifier holding the root
   cannot tell them apart by kind.
3. **Proof binding.** Both reduced proofs verified against the root, and
   neither included the segment descriptor. A reduced hash tree proves the
   object was covered by the timestamped root and says nothing about which
   ledger, serial number, predecessor, or closure policy that root
   represents.
4. **Descriptor binding.** Follows from 3; nothing ties two proofs to one
   segment.

Class B is also not expressible: a reduced hash tree discloses one object's
path, so disclosing exactly one complete aligned batch needs a separate
opening object.

### Measurement, by rendering rather than estimate

Twelve rules are required. Drafted as normative prose they measure 87 lines,
about 1.9 pages. That number alone was not trusted, so the draft itself was
forked and rendered with `xml2rfc 3.34.0`. The baseline render of -12
reproduces the committed text exactly — 58 pages, identical trailer — so the
toolchain is calibrated.

| Fork | Pages | Body lines | vs -12 |
| --- | --- | --- | --- |
| `-12` baseline | 58 | 2274 | — |
| `-13-candidate` (this ADR's Section 1.2 text plus the three touchpoints) | 58 | 2301 | +27 lines, +0 pages |
| `-13-ers-playground` (ERS installed as the cryptographic core) | 63 | 2445 | +171 lines, **+5 pages** |

The playground replaces Section 4.3 with an "ERS Commitment Core" carrying
the eleven rules as numbered subsections (40 lines becomes 147, net +107) and
adds a 25-line segment-descriptor CDDL appendix.

**The +5 pages is a lower bound, and the reason matters more than the
number.** The playground still passes the normative Appendix A vectors
unchanged — `61d6b5be...` and the empty-segment root both survive — because
the rules that pin ERS's freedoms (fixed grouping, arity two, RFC 9162 split,
`0x00`/`0x01` prefixes) restate VTL's existing construction exactly. The
commitment bytes do not move. What the fork actually buys is five pages of
divergence bookkeeping around cryptography that is unchanged.

A fork that used ERS's *own* tree — generator-chosen grouping, variable
arity, no domain separation — would change every commitment byte, invalidate
Appendix A, and require regenerated conformance vectors and a security
analysis for the seven extensions. None of that is in the +5.

### Verdict: the ADR stands

The page criterion is satisfied and it does not matter. The rendered cost is
+5 pages, inside the band where switching was worth considering. The deciding
fact is not the page count: **7 of the 12 rules are deviations, not
restrictions**, and the +5 pages buys a re-narration of cryptography that
stays byte-for-byte identical. A profile
that fixes ERS's grouping, arity, and padding is still ERS. One that also
changes its hash computation (leaf and inner domain separation, absent from
Section 4.2 and the reason RFC 6962 prefixes its inputs), adds an object
count ERS has no field for, distinguishes one archived object as a
descriptor, and requires that descriptor in every partial disclosure is a
different construction wearing ERS's ASN.1.

Adopting it would mean claiming RFC 4998 conformance for trees that a
conforming ERS verifier cannot validate and that a conforming ERS generator
would not produce. That is worse for interoperability than defining the
construction plainly, which is what VTL does. The commitment layer stays as
specified.

Domain separation is the single clearest instance: it is not a restriction of
Section 4.2 available to a profile, and without it an inner node value is a
valid leaf value.

## Alternatives considered

- **Profile ERS as the commitment tree.** Rejected for now on the grounds
  above, pending the experiment. It would remove VTLRoot, aligned batch roots,
  and some Class B machinery, which is a genuine reduction in bespoke
  specification and the reason the question stays open.
- **Require an ERS wrapper around every segment timestamp.** Rejected. For a
  single data object it adds a wrapper without changing what is proven, and it
  puts an archival concern in the producer.
- **Leave Section 1.2 as is.** Rejected. ERS is the closest prior art, and
  omitting it from the section whose purpose is positioning invites the
  conclusion that it was not considered.
