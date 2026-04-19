# Changelog

All notable changes to `trackone-ingest` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Introduced `trackone-ingest` as the Rust-native framed telemetry crate.
- Added the `rust-postcard-v1` profile contract, nonce/AAD helpers, Postcard
  fact encode/decode, frame/fact binding validation, and `EncryptedFrame<N>`.
- Added generic AEAD fact encryption/decryption helpers for pod-side emission.
- Added XChaCha20-Poly1305 framed admission, deterministic fixture emission,
  and replay-window state for host/gateway builds.
