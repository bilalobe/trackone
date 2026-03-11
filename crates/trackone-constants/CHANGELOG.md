# Changelog

All notable changes to `trackone-constants` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Notes
- No `alpha.9` shared-constant changes are queued yet; add entries here only if provisioning, manifest, or verification hardening introduces new workspace-wide policy constants.

## [0.1.0-alpha.8] - 2026-03-11

### Notes
- No crate-specific constant changes in this release; the crate remains aligned with the workspace `0.1.0-alpha.8` release line.

## [0.1.0-alpha.7] - 2026-03-07

### Notes
- No crate-specific changes in this release; the crate version is aligned with the workspace `0.1.0-alpha.7` release.

## [0.1.0-alpha.6] - 2026-03-01

### Added
- `DEFAULT_WATCHDOG_MS` as the shared default pod watchdog timeout (1 000 ms) for firmware-side liveness recovery.

## [0.1.0-alpha.5] - 2026-02-27

### Added
- `OTS_VERIFY_TIMEOUT_SECS` for the shared default `ots verify` timeout used by gateway-side OTS validation.

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
