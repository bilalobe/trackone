# Changelog

All notable changes to trackone-gateway-svc will be documented in this file.

## [Unreleased]

### Added

- Add public `/readyz` reporting admission availability, producer recovery state,
  durable timestamp backlog and attachment times, configured capacity pressure,
  and process counters for admission rejection, recovery, sealing failure, and
  terminal timestamp failure. Sample the admission connection every five seconds
  and expire observations after fifteen seconds; TSA failures report degradation
  while local admission capacity remains.
- Add optional Clap `--max-pending-timestamps` and
  `--max-retained-evidence-bytes` settings with corresponding `TRACKONE_MAX_*`
  environment bindings. Limits default to unlimited and reject exhausted or
  oversized admissions atomically with explicit 503 errors, preserving accepted
  idempotency replays and evidence preservation operations at capacity.
- Backfill transactional evidence-byte accounting and add timestamp enqueue and
  attachment metadata without changing commitment artifacts. Legacy enqueue
  ages use migration time; historical attachment times remain unknown.

### Changed

- Default Helm readiness probes to `/readyz` and retain `/healthz` for cheap
  process liveness. Expose optional admission capacity settings in chart values
  and ConfigMap rendering.
- Centralize gateway and exporter runtime options with Clap, preserving existing
  environment bindings and defaults, with generated help and validation before
  database connection.
- Return contextual startup errors, propagate fallible response construction,
  and stop timestamp claims safely when the shutdown mutex is poisoned.

- Use shared ledger closure-policy validation for producer configuration
  while preserving existing configuration error messages.

- Submit RFC 3161 timestamps through bounded background workers after listener
  binding and acknowledge admissions at durable commit. Persist retry metadata,
  fenced claim leases, and terminal failures through an additive database
  migration; expose authenticated per-segment timestamp status.

- Produce current VTL segment artifacts with aligned batch roots, version-one
  closure policy, deterministic close-reason precedence, contiguous chaining,
  and mandatory empty shutdown/recovery artifacts.
- Rename the executable to `trackone-vtl-gateway` and expose the normative
  commitment-profile UUID from health responses.
- Report locally queued timestamp work as `queued`, reserving producer
  `pending` claims for submission attempts that have left the local queue.

### Fixed

- Seal overdue intervals independently of admission capacity so idle emit-mode
  ledgers and previously accepted records continue making timestamp progress.
- Service pending readiness samples between producer operations under sustained
  traffic, while retaining stale-observation failures for stuck operations.
- Detect read-only admission transactions in readiness, including session write
  freezes, and recover readiness when writes are enabled again.
- Acquire the ledger lock before starting serializable admissions so timestamp
  accounting commits cannot leave admission with a stale snapshot.
- Keep readiness unavailable after PostgreSQL disk-full write errors even when
  read probes succeed; clear the storage failure signal after a successful
  durable producer write, timestamp attachment, or process restart.
- Acquire migration locks in producer write order before altering schema to
  avoid lock inversion during concurrent writes.

## [0.2.0-beta.1] - 2026-09-08

### Added

- Export immutable VTL disclosure snapshots through a standalone command,
  staging output privately and publishing it atomically without replacing an
  existing snapshot.

### Changed

- Allow deployments to bound how far TSA `genTime` may be ahead of the gateway
  clock, and expose the setting through environment and Helm configuration.

## [0.1.0-beta.5] - 2026-08-08

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
