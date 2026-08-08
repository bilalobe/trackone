# Changelog

All notable changes to trackone-gateway-svc will be documented in this file.

## [Unreleased]

### Added

- Add atomic `POST /v2/record-batches`, gzip batch carriers, admission bounds,
  ordered run summaries, and minimal success responses.

### Changed

- Align the gateway application with the Rust-only workspace product boundary
  after removal of the unpublished `trackone-python` binding leaf.
- Require a bearer token for admission POST routes, accept one optional prior
  token for rotation, and keep health checks public.
- Default PostgreSQL to hostname-verified TLS with an optional private CA and
  require an explicit development-only plaintext mode.
- Enable TLS 1.2+, hostname-valid retained certificates, SCRAM-SHA-256, and
  TLS-only host authentication on chart-managed PostgreSQL; automatically
  mount its CA into the gateway and reject mismatched managed TLS modes.
- Persist explicit transition deltas, move existing open rows during sealing,
  stamp newly sealed artifacts directly, and limit replay TSA reads to status.
- Require a SHA-256 TSA signer-certificate pin and validate RFC 5816
  SigningCertificateV2 through the shared `trackone-rfc3161` verifier before
  marking timestamp responses verified.

### Security

- Decode gzip in one bounded pass with exact CRC/ISIZE and one-member checks,
  and require sealed-row insert/delete counts to match the producer
  transition before commit.
- Retire duplicate Kustomize runtime manifests so Helm is the sole Kubernetes
  runtime contract.

## [0.1.0-beta.4] - 2026-07-18

### Changed

- Established an application boundary for the v2 producer, PostgreSQL store,
  HTTP runtime, timestamp authority, migrations, and service binary.
