# Changelog

All notable changes to `trackone-gateway` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.3] - 2026-02-07

### Added
- High-level Python gateway API:
  - `Gateway` and `GatewayBatch` exposed from the `trackone_core` extension module
  - `PyRadio` adapter for Python-implemented `send_frame`/`receive_frame`
- Merkle helpers:
  - ADR-003 Merkle root policy (SHA-256, hash-sorted leaves)
  - `trackone_core.merkle.merkle_root_bytes` and `trackone_core.merkle.merkle_root_hex`

### Changed
- `__version__` now reports the crate version (`CARGO_PKG_VERSION`)
- `trackone_core.crypto.version()` now matches the crate version (was a placeholder string)

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
