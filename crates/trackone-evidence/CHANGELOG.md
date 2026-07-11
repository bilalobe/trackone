# Changelog

All notable changes to `trackone-evidence` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Added the `verify-v2` CLI command and native v2 bundle verifier. It decodes
  authoritative segment CBOR through `trackone-ledger`, compares manifest
  identity claims, and validates disclosed predecessor-artifact linkage.

## [0.1.0-beta.1] - 2026-05-16

### Notes
- No crate-local API changes landed in this release; `trackone-evidence`
  remains aligned with the workspace `0.1.0-beta.1` release line.

## [0.1.0-alpha.19] - 2026-05-16

### Added
- Introduced `trackone-evidence` as the Rust-native verifier/export runner for
  TrackOne evidence bundles, with `verify` and `export` CLI subcommands.
- Added manifest, artifact, fact-level recompute, batch metadata, and OTS
  verification checks backed by `trackone-ledger` canonical CBOR/Merkle helpers
  and `trackone-gateway` OTS helpers.
- Added evidence export support for release-day artifacts, optional frame
  inclusion, fresh verification, optional git commit/tag creation, and optional
  git bundle emission.
- Added crate-local Rust tests covering the native evidence contract.
