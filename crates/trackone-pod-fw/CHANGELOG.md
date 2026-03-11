# Changelog

All notable changes to `trackone-pod-fw` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Notes
- No pod-firmware-specific `alpha.9` work is queued yet; current next-release hardening is centered on gateway, provisioning, and verification-bundle boundaries.

## [0.1.0-alpha.8] - 2026-03-11

### Changed
- Adjusted local/test code for Rust 2024 keyword compatibility (`gen` identifier rename), keeping the crate buildable under the workspace edition update.

## [0.1.0-alpha.7] - 2026-03-07

### Notes
- No pod-firmware-specific changes in this release; the crate version is aligned with the workspace `0.1.0-alpha.7` release.

## [0.1.0-alpha.6] - 2026-03-01

### Added
- Hardware watchdog support for pod firmware via the new `wdg` feature:
  - quorum-based liveness registry that feeds the watchdog only after all enabled tasks check in
  - local `reset_counter` persistence hook for watchdog-triggered resets
  - `MockWatchdog` and host-side tests for local/CI validation

### Changed
- Added a compile-time production guard so `production` builds refuse to compile if `mock-hal` is still enabled.
- Expanded the HAL surface with `ResetCause` and `ResetCauseSource` to normalize boot-reset handling across board support packages.

## [0.1.0-alpha.5] - 2026-02-27

### Notes
- No pod firmware changes in this release; the crate version is aligned with the workspace `0.1.0-alpha.5` umbrella release.

## [0.1.0-alpha.4] - 2026-02-26

### Notes
- No pod firmware changes in this release; the crate version is aligned with the workspace `0.1.0-alpha.4` umbrella release.

## [0.1.0-alpha.3] - 2026-02-07

### Added
- Pod-side helpers:
  - `Pod` helper for constructing + encrypting facts via `trackone-core::frame`
  - `CounterNonce24` counter-based nonce generator (24-byte, XChaCha20-Poly1305)
- Firmware utilities promoted from the legacy bench prototype:
  - `trackone_pod_fw::hal` hardware abstraction traits, plus optional mocks (`mock`, `mock-log`)
  - `trackone_pod_fw::power` low-power helpers (`idle_wait`, `EventWaiter`, `enter_low_power`)
  - `trackone_pod_fw::stress` stack-guard paint/scan helpers for HWM checks

## [0.1.0-alpha.2] - 2026-01-22

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
