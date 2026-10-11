# TrackOne companion SCITT publication profile v1

This profile publishes organizational statements about VTL evidence objects.
It implements [ADR-048](../adr/ADR-048-separate-scitt-publication-profile.md)
and stays subordinate to the base VTL commitment profile. The base VTL verifier
does not consume SCITT state. Publication adds an accountable organizational
signature and a transparency-service registration receipt.

**SCITT publication does not prove telemetry truth or collection completeness.**
It does not establish that a sensor observation is accurate, that all observations
were collected, or that all accepted segments were published. A publication
receipt also does not replace VTL record recomputation, segment chaining, or
RFC 3161 verification.

The key words MUST, MUST NOT, REQUIRED, SHOULD, and MAY are interpreted as
described in RFC 2119 and RFC 8174.

## Contracts and authoritative subjects

| Statement kind | Sole primary subject | Authoritative copied metadata |
| --- | --- | --- |
| `trackone.segment-artifact.v1` | SHA-256 of exact authoritative `segment.cbor` bytes | Ledger ID, segment number, commitment-profile UUID from that artifact |
| `trackone.disclosure-bundle.v1` | SHA-256 of exact serialized disclosure bundle bytes | Identity from its segment artifact; disclosure class from its producer manifest |

For segment publication, the JSON payload MUST contain:

```json
{
  "statement_kind": "trackone.segment-artifact.v1",
  "issuer": "did:x509:0:sha256:<root-certificate-fingerprint>::subject:CN:<publisher-CN>",
  "subject": "urn:trackone:segment-artifact:sha256:<artifact-digest>",
  "artifact": {"digest_algorithm": "sha-256", "digest": "<64-lowercase-hex>"},
  "ledger_id": "<32-lowercase-hex>",
  "segment_number": "0",
  "commitment_profile_id": "c08ade4e-1785-4eb6-9648-b7003d76288d"
}
```

The digest MUST be calculated over the exact artifact bytes, before decoding.
A digest of re-encoded CBOR, a producer manifest, record root, or an individual
record MUST NOT substitute for it. Segment number uses a canonical unsigned
decimal string, covering `0` through `18446744073709551615`, to preserve VTL's
uint64 range in JSON. Ledger ID and commitment-profile UUID use the existing
VTL representations. The UUID above is the current supported profile; future
UUIDs require an explicit verifier implementation and policy update.

The digest determines the `subject` URI exactly. That URI contains the object
kind, so segment and bundle statements cannot be confused even if their
digests coincide. It is an identifier, not a retrieval URL. Artifact locations
and access credentials are distributed separately and are not trusted claims.

Issuers MUST derive copied fields from the authoritative artifact. Relying
parties MUST independently check all copied fields for exact agreement after
checking the digest. A valid signature over mismatching fields is rejected.
The companion schema does not admit extra fields or additional evidence
subjects. Optional roots, verification verdicts, and channel summaries from
the legacy proposal are deliberately absent from this version.

Schemas and payload examples are under `toolset/unified/`; the formal
payload/envelope model is
[`scitt-publication-v1.cddl`](../toolset/unified/cddl/scitt-publication-v1.cddl).
JSON Schemas enforce field shapes and the complete uint64 range. CDDL describes
the payload/envelope structure; semantic checks additionally enforce digest,
subject, authorization, supported profile, and authoritative-field agreement.

## Future disclosure-bundle publication

`trackone.disclosure-bundle.v1` is a separate contract reserved for publication
of a single-segment exported disclosure. Its subject is
`urn:trackone:disclosure-bundle:sha256:<bundle-digest>`. It replaces `artifact`
with `bundle`, containing `digest_algorithm`, `digest`, and `media_type`, and
adds `disclosure_class` (`A`, `B`, or `C`). The other required fields are the
same organizational and segment identifiers.

The v1 fixture carrier is an uncompressed `application/x-tar` archive. The
digest covers its exact serialized bytes, including tar framing and padding.
The archive MUST contain `segment.verify.json` and `segment.cbor` at its root.
It MUST contain only regular files with unique portable relative paths; links,
duplicate names, path traversal, and sparse files are rejected. Its manifest
MUST identify that exact segment artifact by path and digest, and all copied
identifiers MUST agree with both the manifest and artifact. The claimed
disclosure class MUST equal the manifest's class. Full validation of disclosed
records and proof channels remains the separate VTL step.

Changing archive bytes creates a different publication subject even if the
enclosed segment is unchanged. Changing disclosure class creates a different
disclosure of the same segment; disclosure class is **not an immutable segment
property**. Segment statements never contain it. The A/B/C fixtures demonstrate
this distinction. Production bundle export and live bundle publication are
future work; the demonstration service currently accepts only segment statements.

## Organizational signature and authorization

The signed statement MUST be tagged COSE_Sign1 with an attached UTF-8 JSON
payload. This v1 implementation uses ES256 with a P-256 organizational signing
certificate. Its protected headers MUST contain:

| COSE label | Value |
| --- | --- |
| `1` (`alg`) | `-7` (ES256) |
| `3` (`content type`) | `application/vnd.trackone.scitt-publication.v1+json` |
| `15` (CWT claims) | `1` (`iss`) and `2` (`sub`) |
| `33` (`x5chain`) | DER certificates ordered from publisher leaf to organizational root |

The CWT issuer and subject MUST equal the JSON payload's `issuer` and `subject`.
The submitted statement's unprotected headers MUST be empty. Unknown protected
headers and unsupported critical headers are rejected. Duplicate JSON members,
duplicate CBOR map keys, detached payloads, and trailing CBOR bytes are rejected.
The payload media type is a profile identifier, not an asserted IANA registration.

The supported organizational identity form is
`did:x509:0:sha256:<base64url-root-DER-SHA256>::subject:CN:<publisher-CN>`.
The fingerprint has no base64 padding; the publisher CN is restricted to ASCII
letters, digits, `.`, `_`, and `-`. Other `did:x509` policy forms are outside this
implementation. The DID MUST match the root certificate and the leaf's sole CN.

Deployments MUST provision organizational trust anchors independently of the
statement. The leaf MUST be an end-entity certificate permitting digital
signatures. The complete chain MUST pass certificate validity, chain, and
complete base-CRL checks at the relying party's evaluation time. The verifier
uses explicit CA/CRL files and does not fall back to system trust.
The DID root MUST be present in the supplied trust anchors, and path validation
MUST use only that root as its trust anchor. A leaf chaining to another trusted
organizational root cannot obtain the claimed root's authorization grants.
Deployments MUST maintain those inputs as signing keys expire or are revoked;
a captured historical replay does not establish present-day authorization or
revocation status.

Authorization is distinct from signature validity. The deployment-owned
`authorization.json` maps each accepted issuer to permitted `ledger_ids` and
`statement_kinds`; absence of a grant denies publication. An organizational
certificate, the submitted identifiers, API access credentials, and a receipt
do not themselves grant authority for a ledger. Signing-key custody and grant
changes belong to the publishing organization.

The local demonstration service independently verifies signatures and enforces
the accepted issuer, ES256, payload content type, ledger, statement kind, and
header/payload agreement before registration. Its loopback test API allows
unauthenticated transport requests; organizational publication authority still
comes from the signed statement and service policy. Production API access
policy remains deployment-owned.

## Relying-party procedure

1. Obtain the submitted signed statement, transparent statement, evidence object,
   organizational trust/CRLs and grants, and transparency-service trust keys.
   Evidence and statement fields are untrusted inputs.
2. Verify the organizational COSE signature, organizational certificate identity,
   chain validity/revocation, protected-header agreement, and issuer authorization.
3. Require that the transparent statement preserves the submitted protected
   header bytes, payload bytes, and organizational signature. Require receipts
   in unprotected label `394`. Verify each supplied receipt using the explicitly
   trusted service key and its inclusion proof bound to the exact submitted
   signed-statement bytes. Reject missing, malformed, invalid, or untrusted
   receipts; unsupported receipt suites fail rather than degrading to a status
   check. This implementation uses the pinned CCF receipt verifier.
4. Recompute the evidence object's exact byte digest and derived subject. Check
   every copied identifier against the authoritative artifact, and bundle
   disclosure metadata against its manifest where applicable.
5. Perform separate VTL verification over the disclosed artifacts and proof
   channels, with independently supplied VTL/TSA policy. Correlate that evidence
   set with the exact segment whose digest the publication check accepted.

Report publication and VTL results separately. Publication success cannot
upgrade a failing or partial VTL result. A VTL success cannot compensate for an
invalid receipt or unauthorized organizational issuer. Class C remains anchor
verification without public record recomputation. A service receipt does not
imply that the service downloaded or recomputed the VTL evidence.

Receipt verification is offline once service keys and evidence are provisioned.
Service keys MUST be obtained through an authenticated provisioning process,
not implicitly trusted from a receipt's issuer URL. The local runner copies its
TLS root through the Docker control plane, then obtains the receipt keys over
verified TLS. The captured public keys are explicit test trust inputs. Key
rollover requires updated service trust material; replay does not silently
fetch or trust new keys.

## Reproducible interoperability exchange

The independent implementation is Microsoft's
[SCITT CCF ledger](https://github.com/microsoft/scitt-ccf-ledger), pinned with
its client to `c276f12328fde2907512ffb8c4fbe9adacd19788`. The envelope follows
[RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html), CWT claims follow
[RFC 9597](https://www.rfc-editor.org/rfc/rfc9597.html), X.509 headers follow
[RFC 9360](https://www.rfc-editor.org/rfc/rfc9360.html), and receipts follow
[RFC 9942](https://www.rfc-editor.org/rfc/rfc9942.html). The implementation-specific
HTTP flow and CCF receipt suite are recorded; this exchange does not assert
interoperability with every SCITT service or receipt suite.

Use Python 3.13, Docker on x86-64 Linux, OpenSSL, and the repository Rust toolchain:

```sh
python3 -m venv /tmp/trackone-scitt-env
/tmp/trackone-scitt-env/bin/pip install -r toolset/scitt/requirements.txt
git clone https://github.com/microsoft/scitt-ccf-ledger.git /tmp/trackone-scitt-service
git -C /tmp/trackone-scitt-service checkout c276f12328fde2907512ffb8c4fbe9adacd19788
/tmp/trackone-scitt-env/bin/python toolset/scitt/run_exchange.py \
  --service-source /tmp/trackone-scitt-service --output /tmp/trackone-scitt-exchange
/tmp/trackone-scitt-env/bin/python toolset/scitt/replay.py --capture /tmp/trackone-scitt-exchange
PYTHONPATH=toolset/scitt /tmp/trackone-scitt-env/bin/python \
  -m unittest discover -s toolset/scitt -p 'test_*.py'
```

The runner builds the pinned upstream Dockerfile, binds the service to loopback,
applies the restrictive registration policy, submits the organizational statement,
retrieves a transparent statement, and verifies the receipt. It then invokes
`trackone-evidence` independently with a fresh synthetic RFC 3161 channel.
It records an unauthorized-ledger service rejection and demonstrates successful
publication alongside a failed VTL verification of a corrupted disclosed record.
Containers and private governance/TSA material are cleaned up after the run.
Publisher private keys stay in memory. Only public trust material, exact HTTP
entity bodies/headers, policies, signatures, receipts, revisions, and reports
are retained. Missing prerequisites or failed exchanges cause an explicit failure.

[`toolset/vectors/scitt-publication`](../toolset/vectors/scitt-publication/README.md)
contains positive/negative payloads and an actual captured service exchange.
Offline replay uses its explicit capture evaluation time. It rechecks publication
cryptography and artifact agreement; the separate retained VTL reports document
the live VTL step and are not a substitute for fresh VTL verification.

The legacy day/verify-manifest and Git evidence-bundle schemas, examples, and
`scitt-statements-v1.cddl` remain available at their existing identifiers but
are superseded. The companion verifier does not accept those statement kinds.
The base VTL contract and its fixture corpus do not change.

## Issue #325 acceptance evidence

| Criterion | Evidence |
| --- | --- |
| Separate companion profile | This document; ADR-048; separate tooling and CI job |
| One primary subject per type | Two distinct digest subject URIs and schemas |
| Exact artifact digest and identifiers | Segment schema, byte hashing, authoritative-field checks |
| Organizational identity and authorization | Protected X.509/CWT identity, CA/CRL validation, issuer grants, service policy |
| Copied fields agree | Signed semantic mismatch fixtures and rejection tests |
| Signature/receipt checks before separate VTL | Publication checker and live runner with separate reports |
| Future disclosure-bundle statement | Dedicated schema/CDDL and A/B/C fixtures |
| Disclosure class is not immutable | Same segment bytes in A/B/C disclosures; absent from segment statement |
| Schemas, fixtures, independent exchange | Unified contracts, captured CCF exchange, offline replay and CI |
| No telemetry-truth/completeness claim | Explicit claim boundary in profile and capture metadata |
