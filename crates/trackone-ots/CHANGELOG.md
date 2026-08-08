# Changelog

All notable changes to trackone-ots will be documented in this file.

## [Unreleased]

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
