# Changelog

All notable changes to `trackone-pod-fw` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.2] - 2026-01-21

### Changed
- Minor version alignment with `trackone-core` v0.1.0-alpha.2
- Updated dependency on `trackone-core` for enhanced type system (EnvFact, FactKind)
- Firmware now benefits from expanded PodId representation ([u8; 8] with From<u32> compatibility)

### Notes
- No breaking changes to firmware API
- Firmware can continue using `PodId::from(u32)` for backward compatibility
- `no_std` compatibility maintained

## [0.1.0-alpha.1] - 2025-01-20

### Added
- Initial `no_std` firmware crate for TrackOne pod devices
- Integration with `trackone-core` for protocol types and crypto
- Firmware version delegation to core
