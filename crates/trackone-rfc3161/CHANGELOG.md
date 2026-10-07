# Changelog

## Unreleased

- Add `VerificationPolicy::try_with_limits` and `validate` to reject zero
  response-size limits and zero or platform-unrepresentable timeouts during
  configuration. Preserve `with_limits` and validate its limits before
  response parsing or OpenSSL execution.

- Propagate generation-time bound and UTF-8 conversion failures instead of
  panicking, match archived intermediate paths with their PEM material, and
  encode PEM lines without fallible ASCII assumptions.

- Validate disclosed RFC 3161 requests, including SHA-256 message imprint,
  `certReq`, and request/response nonce equality.

## [0.2.0-beta.1] - 2026-09-08

- Reject `genTime` values beyond a deployment-configured maximum future skew.

## [0.1.0-beta.5] - 2026-08-08

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
