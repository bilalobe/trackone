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

Postcard encode/decode validates the complete fact semantics before data leaves
or enters the framed plane. Admission rejects non-fact message types before
decryption. Durable replay restoration requires an explicit, non-empty
expected namespace and distinguishes empty from mismatched namespace state.

The implementation is organized into `profile`, `frame`, `aad`, `nonce`,
`fixture`, `replay`, and `admission` modules while preserving the
crate-root API.

## Device Identity Invariant

The 16-bit frame `dev_id` is a routing hint, not the canonical device
identity. Every provisioned key record must carry its authoritative 8-byte
`PodId`, and admission must enforce both checks:

1. Before decryption, the provisioned `PodId` suffix must match the frame
   `dev_id`, proving that the selected key record is consistent with the
   route.
2. After decryption, the fact's complete `PodId` must exactly equal the
   provisioned `PodId`.

Never construct the expected identity from an incoming header or payload.
Use `DeviceMaterial::new(...)` with identity loaded from the provisioning
trust root:

```rust
use trackone_core::PodId;
use trackone_ingest::DeviceMaterial;

let pod_id = PodId::from([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x12, 0x34]);
let salt8 = [0x11; 8];
let ck_up = [0x22; 32];
let device = DeviceMaterial::new(pod_id, &salt8, &ck_up);

assert_eq!(device.expected_pod_id(), pod_id);
```

The corresponding API documentation includes executable examples showing
that a different full identity is rejected even when its legacy suffix
collides.

## Boundary With Other Crates

- [`trackone-core`](../trackone-core/README.md) owns canonical protocol types,
  crypto-facing traits, identity/admission input records, and deterministic CBOR
  commitment surfaces.
- [`trackone-pod-fw`](../trackone-pod-fw/README.md) uses ingest helpers to emit
  framed facts from firmware-side runtime state.
- [`trackone-sensorthings`](../trackone-sensorthings/README.md) owns read-only
  projection of already accepted facts into SensorThings-shaped outputs.
- [`trackone-ledger`](../trackone-ledger/README.md) owns commitment artifacts;
  CBOR remains the only commitment authority.

## What This Crate Is Not

This crate does not own the commitment plane, SensorThings exports, fleet
lifecycle state, onboarding policy, or workflow orchestration. It owns
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
cargo test --locked -p trackone-ingest --features std,xchacha
cargo test --locked -p trackone-ingest --doc --features std,xchacha
cargo check --locked -p trackone-ingest --no-default-features
```
