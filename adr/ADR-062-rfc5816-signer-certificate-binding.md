# ADR-062: RFC 5816 Signer-Certificate Binding

**Status**: Accepted
**Date**: 2026-07-19

## Related ADRs

- [ADR-015](ADR-015-parallel-anchoring-ots-rfc3161-tsa.md): RFC 3161 parallel anchoring
- [ADR-061](ADR-061-library-application-and-binding-package-boundaries.md): package boundaries
- [ADR-061](ADR-061-full-draft-08-v2-conformance-and-archive-v3.md): draft-08 conformance

## Context

The gateway and evidence application verified RFC 3161 signatures, trust
paths, SHA-256 message imprints, and TSA policy OIDs through OpenSSL. They did
not independently pin the certificate selected by CMS SignerInfo or require
the SHA-256-capable SigningCertificateV2 update defined by RFC 5816.

## Decision

Add the reusable `trackone-rfc3161` crate and use it from both applications.
OpenSSL remains responsible for signature, timestamp-purpose, and certificate-
path cryptography. Structured DER parsing additionally defines a strict VTL
archived timestamp profile: `PKIStatus.granted`, exactly one CMS signer, an
embedded matching signer certificate, a SHA-256 message imprint, and a SHA-256
SigningCertificateV2 whose first ESSCertIDv2 equals SHA-256 over that complete
DER signer certificate. Producers set `certReq=TRUE`; legacy SigningCertificate
and ESSCertID do not satisfy the profile.

The configured external signer pin, computed over the complete DER signer
certificate, must equal the same digest. It is deployment/verifier policy and
must not be accepted from the evidence bundle being verified. Legacy
SigningCertificate may coexist but cannot replace SigningCertificateV2.

Historical CRL-based path validation is a separate stage. The implementation
extracts a candidate `genTime`, uses it as the OpenSSL `-attime`, and verifies
the exact certificate selected by CMS SignerIdentifier with deployment-retained
anchors, optional intermediates, and complete base CRLs. Every non-root path
certificate requires exactly one issuer-matched CRL whose `thisUpdate` and
`nextUpdate` cover `genTime`. Delta and indirect CRLs and network retrieval are
not supported.

The extracted time is untrusted until token-signature validation succeeds.
Even after success, it remains a signed TSA assertion: this process does not
prove when the token was first observed or prevent all post-compromise
backdating. This ADR therefore specifies historical CRL-based path validation,
not comprehensive long-term validation or evidence augmentation.

Gateway startup requires `TRACKONE_TSA_SIGNER_CERT_SHA256` and
`TRACKONE_TSA_CRLS_FILE`, with `TRACKONE_TSA_INTERMEDIATES_FILE` when needed.
The v2 evidence CLI requires the corresponding CA, CRL, policy, and signer-pin
options when a TSA response is present.
`--allow-missing-tsa` permits absence only, not an invalid present response.

The coordinated release now contains eight reusable libraries and two
publishable applications. This supersedes ADR-061's package-count statements,
but not its dependency-direction rules.

## Consequences

- Gateway production and detached evidence verification enforce one signer
  identity policy and cannot drift independently.
- A valid chain under the configured CA is insufficient when the signer pin
  or RFC 5816 certificate identifier differs.
- Successful evidence results expose the TSA-asserted generation time, serial
  number, and optional accuracy without treating them as a first-observation
  record.
- Deployment operators must retain applicable historical base CRLs and path
  material; missing or ambiguous revocation evidence fails closed.
- The workspace and release sequence gain one publishable package and
  structured CMS/DER dependencies.

## Testing & Migration

The test-only TSA corpus is regenerated with a retained root and complete base
CRL, and the crate owns compact non-skipping fixtures. Deployments must
calculate and configure the DER certificate digest and archive applicable path
and CRL material before upgrading. Positive vectors, wrong-pin and profile
rejection tests, contract checks, detached archive replay, package boundaries,
Helm lint, and application tests gate the change.
