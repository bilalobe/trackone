# Changelog

## Unreleased

- Document and cover signer-only timestamp response certificate sets while
  retaining acceptance of archived responses that include additional chain
  certificates.
- Added OpenSSL-backed RFC 3161 verification with structured RFC 5816
  SigningCertificateV2 and SHA-256 signer-certificate pinning.
- Enforce one signer, unambiguous embedded signer-certificate selection, and
  the required SHA-256 `SigningCertificateV2` binding with structured errors
  for missing or ambiguous certificate sets. Keep path and revocation choices
  in deployment verification policy.
