# Draft -08 v2 vectors

These repository vectors exercise `verifiable-telemetry-canonical-cbor-v2`.
They are release-bound TrackOne engineering inputs, not normative dependencies
of the Internet-Draft.

The corpus carries the complete corrected draft-08 compact epoch artifact,
its three exact canonical records, embedded batch expectations, artifact
digest, and CLI-runnable Class A, B, and C bundles. The positive bundles carry
real RFC 3161 timestamp responses over the authoritative segment artifact and
are verified against the test-only `trust/tsa-root.pem` and complete base CRL
archive `trust/tsa-crls.pem` with policy OID `1.3.6.1.4.1.55555.1`. Their RFC
5816 SigningCertificateV2 attribute and embedded TSA signer certificate both
resolve to SHA-256
`14ab98cafe09d9d1d01562af42d69a904b01023d9cd5b03bd07e5779710c8014`.
It also archives the pre-correction
segment-7/zero-predecessor artifact as a required negative case. The negative
bytes remain exactly hash-reproducible but must never decode as a valid v2
segment. A second Class-A bundle proves a valid segment-1 successor against
the exact corrected epoch artifact.

Layout:

```text
manifest.json
cases.json
fixtures/
  corrected-epoch-class-a/
    segment.verify.json
    expected-result.json
    records/record-{1,2,3}.cbor
    segments/segment-0.cbor
  successor-class-a/
    segment.verify.json
    expected-result.json
    records/record-{1,2,3}.cbor
    segments/segment-{0,1}.cbor
  segment-7-zero-predecessor/
    segment.verify.json
    expected-error.json
    segments/segment-7.cbor
```

Replay the ledger-owned exact-byte checks:

```bash
cargo test --locked -p trackone-ledger --test vector_corpus -- \
  --ignored rust_reproduces_draft_08_v2_segment_vectors
```

Replay all detached bundles through the real evidence CLI:

```bash
cargo test --locked -p trackone-evidence --test v2_vector_bundles
```

This corpus closes the record, Merkle, embedded-batch, segment-artifact,
epoch/successor construction, strict chain-position, disclosure-class, and
RFC 3161 verifier boundaries. The fixture root and CRL are not production
validation material.
