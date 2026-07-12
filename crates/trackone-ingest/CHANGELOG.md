# Changelog

All notable changes to `trackone-ingest` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-beta.2] - 2026-07-11

### Added
- Added versioned `ReplayWindowSnapshot` support for persisting the replay
  namespace, window size, high-water counter, and accepted live-window
  counters.

### Fixed
- Restored replay windows now reject the persisted high-water counter and
  previously accepted reordered counters rather than treating them as new.
- Added `continuity_break` and `resync_required` to the rejection taxonomy.

## [0.1.0-beta.1] - 2026-05-16

### Notes
- No crate-local API changes landed in this release; `trackone-ingest`
  remains aligned with the workspace `0.1.0-beta.1` release line.

## [0.1.0-alpha.19] - 2026-05-16

### Added
- Added std-gated ADR-058 rejection-audit helpers: `RejectionSource`,
  `RejectionRecord`, `AdmissionStateUpdate`, rejection source/reason
  allow-lists, `hash_rejected_line(...)`, and `validate_rejection_record(...)`.

## [0.1.0-alpha.18] - 2026-05-05

### Notes
- No crate-local API changes landed in this release; `trackone-ingest`
  remains aligned with the workspace `0.1.0-alpha.18` release line.

## [0.1.0-alpha.17] - 2026-04-29

### Notes
- No crate-local API changes landed in this release; `trackone-ingest`
  remains aligned with the workspace `0.1.0-alpha.17` release line.

## [0.1.0-alpha.16] - 2026-04-24

### Added
- Introduced `trackone-ingest` as the Rust-native framed telemetry crate.
- Added the `rust-postcard-v1` profile contract, nonce/AAD helpers, Postcard fact encode/decode, frame/fact binding validation, and `EncryptedFrame<N>`.
- Added generic AEAD fact encryption/decryption helpers for pod-side emission.
- Added XChaCha20-Poly1305 framed admission, deterministic fixture emission, and replay-window state for host/gateway builds.

### Changed
- `trackone-ingest` is now `no_std`-first by default; host/gateway builds opt into replay-window and XChaCha admission helpers with `--features std,xchacha`.
