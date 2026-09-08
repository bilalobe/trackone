# VTL interoperability cases

`cases.json` is an informative, machine-readable supplement to the normative
known-answer vector. It does not change the commitment profile or replace its
fixed values.

The global-sort trap reuses Appendix A's three canonical records in admission
order. With `B = 2`, independently sorting the first two records as one input
chunk puts the globally smallest leaf in the second batch and produces the
forbidden roots recorded in the case. A conforming producer sorts the complete
three-leaf multiset before partitioning it.

The canonical-record acceptance cases distinguish profile validity from the
mandatory baseline resource envelope. The depth-16 recipe constructs an exact
4096-octet record from the fixed record prefix, sixteen single-element array
heads, and a 4062-octet byte string. The depth-17 record is still a conforming
canonical record but can be rejected under identified verifier policy. Payload
depth counts arrays and maps beginning at `payload`; the outer seven-element
record array is excluded.

The five-leaf composition case uses `B = 2` and therefore carries three batch
roots. Its left range combines the first two full batch roots before that range
is combined with the singleton final root. This exercises the recursive split
that a two-batch vector cannot reach.

The lifecycle cases cover routine empty suppression, mandatory empty shutdown
and recovery artifacts, emitted empty intervals, exact-deadline assignment,
post-admission size and record thresholds, and close-reason precedence. Counts
describe one logical transition; `closed_record_count` and `close_reason` are
null when a suppressed empty interval has no authoritative artifact.

The file validates against
`toolset/unified/schemas/vtl_interoperability_cases.schema.json`.

## Baseline TSA channel case

Files under `tsa/` encode one purpose-generated test case. The `.b64` files are
base64 encodings of the exact DER `TimeStampReq` and `TimeStampResp`; whitespace
is not part of either DER object. The request binds Appendix A's
`segment_sha256`, sets `certReq=TRUE`, and carries the nonce recorded in
`cases.json`. The response is `granted`, echoes that nonce, uses the listed test
policy, contains exactly one `SignerInfo`, includes a critical
`id-kp-timeStamping` EKU in the signer certificate, and carries the required
SHA-256 `SigningCertificateV2` binding. `test-root.pem` is the test-only trust
anchor, and `test-root.crl.pem` is a non-revoking CRL whose validity interval
covers the token's `genTime`. The corresponding private keys were not retained.

The negative cases are reproducible mutations of the valid response rather
than separately signed tokens:

- change the top-level `PKIStatus` from `granted (0)` to
  `grantedWithMods (1)`;
- DER-decode `SignedData`, duplicate its only `SignerInfo`, and DER-encode the
  result; or
- replace the `id-aa-signingCertificateV2` OID
  `1.2.840.113549.1.9.16.2.47` with the equal-length legacy
  `id-aa-signingCertificate` OID `1.2.840.113549.1.9.16.2.12`.

Each mutation is expected to produce TSA channel status `failed` and failure
reason `channel_failure`. These test artifacts are informative and are not a
public TSA trust configuration.
