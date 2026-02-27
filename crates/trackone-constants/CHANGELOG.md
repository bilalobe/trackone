# Changelog

All notable changes to `trackone-constants` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.4] - 2026-02-26

### Notes
- No crate-specific changes; version bump keeps `trackone-constants` aligned with the workspace `0.1.0-alpha.4` release.

## [0.1.0-alpha.3] - 2026-02-07

### Added
- Added AEAD sizing constants:
  - `AEAD_NONCE_LEN` (24 bytes, XChaCha20-Poly1305)
  - `AEAD_TAG_LEN` (16 bytes, Poly1305)

## [0.1.0-alpha.2] - 2026-01-22

### Changed
- Minor version alignment with workspace release (no functional changes)

## [0.1.0-alpha.1] - 2025-01-20

### Added
- Initial release with `MAX_FACT_LEN` constant for fact payload size limit
