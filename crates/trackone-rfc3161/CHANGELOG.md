# Changelog

## Unreleased

- Document and cover signer-only timestamp response certificate sets while
  retaining acceptance of archived responses that include additional chain
  certificates.
- Added OpenSSL-backed RFC 3161 verification with structured RFC 5816
  SigningCertificateV2 and SHA-256 signer-certificate pinning.
- Define the strict signer-identifiable VTL archived timestamp profile, return
  `genTime`, serial number, and accuracy, bound response/process resources, and
  evaluate the exact signer path at the TSA-asserted time using deployment-
  retained complete base CRLs.
