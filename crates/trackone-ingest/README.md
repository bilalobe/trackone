# trackone-ingest

`trackone-ingest` owns TrackOne's Rust-native framed telemetry path. It is the
single source for the Postcard framed plaintext profile, frame nonce/AAD
binding, bounded encrypted frame envelopes, fixture emission, replay-window
admission, and gateway-side framed decrypt/validation helpers.

## Responsibilities

This crate owns:

- the `rust-postcard-v1` ingest profile identifier and compatibility rules
- framed nonce construction and validation (`salt8 || fc32_as_u64_be || tail8`)
- framed AEAD associated-data construction from `dev_id`, `msg_type`, and `flags`
- Postcard encode/decode for canonical `trackone-core::Fact` plaintexts
- `EncryptedFrame<N>` and pod-side fact encryption/decryption helpers
- gateway-side framed validation/decryption for the Rust-native profile
- deterministic Rust framed fixture emission for tests and demos
- replay-window state used by framed gateway admission

## Boundary With Other Crates

- [`trackone-core`](../trackone-core/README.md) owns canonical protocol types,
  crypto-facing traits, identity/admission input records, and deterministic CBOR
  commitment surfaces.
- [`trackone-gateway`](../trackone-gateway/README.md) exposes selected ingest,
  core, and ledger helpers to Python via PyO3.
- [`trackone-pod-fw`](../trackone-pod-fw/README.md) uses ingest helpers to emit
  framed facts from firmware-side runtime state.
- [`trackone-ledger`](../trackone-ledger/README.md) owns commitment artifacts;
  CBOR remains the only commitment authority.

## What This Crate Is Not

This crate does not own the commitment plane, SensorThings exports, fleet
lifecycle state, onboarding policy, or Python workflow orchestration. It owns
the framed ingest wire contract and the small native admission helpers needed
to keep pods, gateways, and fixtures aligned.

## Feature Model

- default
  Minimal `no_std` framing and generic AEAD helpers.
- `std`
  Host-side helpers such as replay windows.
- `xchacha`
  Concrete XChaCha20-Poly1305 framed admission and fixture helpers. Implies
  `std`.

Host/gateway builds should opt into `std,xchacha`. Firmware-oriented builds can
use the default `no_std` profile, nonce, Postcard, and generic AEAD helpers
without the host admission surface.

## Check

```bash
cargo test -p trackone-ingest --features std,xchacha
cargo check -p trackone-ingest --no-default-features
```
