# Changelog

All notable changes to trackone-ots will be documented in this file.

## [Unreleased]

### Added

- Add `OtsVerifyOptions`, `OtsConfigError`, and `verify_ots_proof_with_options`
  for grouped library configuration and explicit timeout validation. Preserve
  `verify_ots_proof_native` as a compatibility wrapper.

### Changed

- Reject zero and platform-unrepresentable timeouts before digest parsing or
  file access for every proof kind, returning `ots-timeout-zero` or
  `ots-timeout-out-of-range` with a failed verification result.

### Fixed

- Use elapsed-time comparisons for external verifier polling to remove the
  deadline overflow panic from oversized durations.

## [0.2.0-beta.1] - 2026-09-08

### Security

- Stage stable private copies of the expected artifact and proof for external
  verifier processes, preventing path replacement or mutation from changing
  the verified bytes.

## [0.1.0-beta.5] - 2026-08-08

### Changed

- Remove the unpublished Python binding boundary; OTS verification remains
  owned by the reusable Rust crate.

### Security

- When an expected digest is supplied, bind every proof path to the sibling
  artifact before interpreting the proof. External `ots` verification always
  uses private staged artifact/proof copies; malformed expected hashes fail
  before process execution.

## [0.1.0-beta.4] - 2026-07-18

### Added

- Extracted reusable native OTS proof and metadata verification from the former
  mixed-purpose trackone-gateway package.
