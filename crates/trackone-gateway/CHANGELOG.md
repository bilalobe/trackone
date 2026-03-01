# Changelog

All notable changes to `trackone-gateway` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.6] - 2026-03-01

### Notes
- No gateway-specific changes in this release; the crate version is aligned with the workspace `0.1.0-alpha.6` release.

## [0.1.0-alpha.5] - 2026-02-27

### Added
- `ots` submodule now exposes `hash_for_ots(...)`, `verify_ots_proof(...)`, `validate_meta_sidecar(...)`, and the `OtsStatus` / `OtsVerifyResult` result types for native OTS boundary checks.
- Rust unit tests now cover placeholder proofs, stationary stubs, real proofs, and OTS metadata validation edge cases.

### Changed
- Added direct `sha2`, `serde_json`, and `trackone-constants` dependencies so OTS validation logic can hash artifacts, parse sidecars natively, and share the default verify timeout constant.

## [0.1.0-alpha.4] - 2026-02-26

### Added
- `ledger` submodule exposes `canonicalize_json_bytes`, `canonicalize_json_to_cbor_bytes`, `build_day_v1_single_batch`, and `build_day_v1_single_batch_cbor`, giving Python callers deterministic JSON and CBOR helpers backed by the workspace `trackone-ledger` helpers.

### Changed
- Ledger helpers now delegate to the workspace `trackone-ledger` canonicalization modules when producing deterministic CBOR commitments for the Python gateway surface.

## [0.1.0-alpha.3] - 2026-02-07

### Added
- High-level Python gateway API:
  - `Gateway` and `GatewayBatch` exposed from the `trackone_core` extension module
  - `PyRadio` adapter for Python-implemented `send_frame`/`receive_frame`
- Merkle helpers:
  - ADR-003 Merkle root policy (SHA-256, hash-sorted leaves), implemented in `trackone-ledger`
  - `trackone_core.merkle.merkle_root_bytes` and `trackone_core.merkle.merkle_root_hex`
  - `trackone_core.merkle.merkle_root_hex_and_leaf_hashes` (root + leaf hashes, Python pipeline parity)
- Ledger helpers:
  - `trackone_core.ledger.canonicalize_json_bytes` (ADR-003 canonical JSON)
  - `trackone_core.ledger.build_day_v1_single_batch` (canonical block header + `day.bin` bytes)

### Changed
- `__version__` now reports the crate version (`CARGO_PKG_VERSION`)
- `trackone_core.crypto.version()` now matches the crate version (was a placeholder string)
- Merkle policy logic moved out of `trackone-gateway` and is now single-sourced in `trackone-ledger`
- Removed the legacy `merkle_policy` module (now provided by `trackone-ledger`)

## [0.1.0-alpha.2] - 2026-01-22

### Changed
- Minor version alignment with `trackone-core` v0.1.0-alpha.2
- Updated dependency on `trackone-core` to benefit from new provisioning types and CBOR encoding

### Notes
- No API changes in this release
- Gateway functionality remains compatible with alpha.1

## [0.1.0-alpha.1] - 2025-01-20

### Added
- Initial PyO3-based Python extension for gateway integration
- Core gateway bindings for TrackOne protocol
