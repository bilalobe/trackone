# Changelog

## Unreleased

- Migrate CMS parsing and certificate handling to `cms 0.3.0-pre.2`, DER
  0.8.1, and `x509-cert 0.3.0-rc.4`; update nested decoder error typing,
  tag-peeking, and public X.509 accessors for the supported APIs.
- Remove the unpublished `trackone-python` binding boundary; RFC 3161
  verification is now part of the Rust-native product surface.
- Drain OpenSSL stdout and stderr concurrently, retain at most 64 KiB per
  diagnostic stream, and kill/reap the isolated process group plus join reader
  threads on timeout.
- Document and cover signer-only timestamp response certificate sets while
  retaining acceptance of archived responses that include additional chain
  certificates.
- Added OpenSSL-backed RFC 3161 verification with structured RFC 5816
  SigningCertificateV2 and SHA-256 signer-certificate pinning.
- Enforce one signer, unambiguous embedded signer-certificate selection, and
  the required SHA-256 `SigningCertificateV2` binding with structured errors
  for missing or ambiguous certificate sets. Keep path and revocation choices
  in deployment verification policy.
