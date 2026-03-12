# Changelog

All notable changes to `trackone-ledger` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.9] - 2026-03-12

### Added
- A parser-backed CDDL conformance test that parses `toolset/unified/cddl/commitment-artifacts-v1.cddl` and asserts the expected commitment-family top-level rules.

### Changed
- `trackone-ledger` dev/test tooling now depends on the published `cddl` crate, aligning the contract gate with the workspace Rust `1.88` baseline.

## [0.1.0-alpha.8] - 2026-03-11

### Notes
- No crate-specific API changes in this release; the crate remains aligned with the workspace `0.1.0-alpha.8` release line.

## [0.1.0-alpha.7] - 2026-03-07

### Notes
- No crate-specific changes in this release; the crate version is aligned with the workspace `0.1.0-alpha.7` release.

## [0.1.0-alpha.6] - 2026-03-01

### Notes
- No crate-specific changes in this release; the crate version is aligned with the workspace `0.1.0-alpha.6` release.

## [0.1.0-alpha.5] - 2026-02-27

### Notes
- No crate-specific changes; version bump keeps `trackone-ledger` aligned with the workspace `0.1.0-alpha.5` release.

## [0.1.0-alpha.4] - 2026-02-26

### Added
- Canonical JSON helpers in `src/c_json.rs` (sorted keys, compact separators) and deterministic CBOR encoding helpers in `src/c_cbor.rs`, exposing `canonical_cbor_bytes`, `canonicalize_json_bytes_to_cbor`, and `canonicalize_serialize_to_cbor` for deterministic commitment encoding.
- `BlockHeaderV1`/`DayRecordV1` now provide `canonical_json_bytes` and `canonical_cbor_bytes` helpers for ADR-039 commitments.
- `build_day_v1_single_batch` and `day_record_v1_single_batch` helpers produce canonical records consumed by ledger and gateway tooling.
- Unit-test coverage for deterministic CBOR behavior, including map key ordering and integer encoding.

### Changed
- Deterministic map-key ordering for JSON objects is tightened to RFC 8949 Section 4.2.1 (shortest encoded key first, then lexicographic).

### Fixed
- Added tests that verify canonical JSON/CBOR stability, key sorting, and integer encoding choices.

## [0.1.0-alpha.3] - 2026-02-07

### Added
- Initial crate with:
  - Canonical JSON encoding helpers (ADR-003)
  - ADR-003 Merkle policy implementation (root + leaf hashes)
  - `BlockHeaderV1` / `DayRecordV1` helpers and canonical JSON byte encoding
