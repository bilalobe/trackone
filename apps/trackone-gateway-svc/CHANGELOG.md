# Changelog

All notable changes to trackone-gateway-svc will be documented in this file.

## [Unreleased]

### Added

- Add atomic `POST /v2/record-batches`, gzip batch carriers, admission bounds,
  ordered run summaries, and minimal success responses.

### Changed

- Persist explicit transition deltas, move existing open rows during sealing,
  stamp newly sealed artifacts directly, and limit replay TSA reads to status.
- Require a SHA-256 TSA signer-certificate pin and validate RFC 5816
  SigningCertificateV2 through the shared `trackone-rfc3161` verifier before
  marking timestamp responses verified.

## [0.1.0-beta.4] - 2026-07-18

### Changed

- Established an application boundary for the v2 producer, PostgreSQL store,
  HTTP runtime, timestamp authority, migrations, and service binary.
