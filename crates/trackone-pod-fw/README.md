# trackone-pod-fw

`trackone-pod-fw` is the firmware-oriented helper crate for TrackOne pods. It
provides small, `no_std`-friendly building blocks for constructing facts,
generating nonces, emitting encrypted frames, and handling basic runtime support
concerns such as low-power waiting and watchdog coordination.

## Responsibilities

This crate currently provides:

- `Pod` for constructing and emitting framed telemetry from payloads
- `CounterNonce24` for frame-counter-bound 24-byte nonce generation
- small HAL-facing traits and optional mock implementations
- low-power helpers such as `idle_wait` and `enter_low_power`
- stress utilities such as stack-guard paint/scan
- watchdog/liveness helpers behind the `wdg` feature

## Feature model

- `std`
  Enabled by default for host-side development and tests.
- `wdg`
  Enables watchdog/liveness-registry helpers.
- `mock-hal`
  Enables host-side mock HAL implementations.
- `mock-log`
  Adds `std`-backed logging to the mock HAL path.
- `production`
  Intended for embedded builds; implies `wdg` and rejects mock HAL usage.

For embedded builds, disable default features:

```bash
cargo build -p trackone-pod-fw --no-default-features --features production
```

## Boundary with other crates

- [`trackone-core`](../trackone-core/README.md) owns the shared protocol model,
  bounded types, and crypto-facing traits
- [`trackone-ingest`](../trackone-ingest/README.md) owns the framed Postcard
  profile, nonce/AAD helpers, and encrypted frame envelope used by pod emission
- this crate owns firmware-side runtime helpers built on that model
- board-specific integration belongs in board/application crates such as
  [`trackone-pod-esp32`](../trackone-pod-esp32/README.md)

## Notes

- Additional firmware notes live in [`docs/pod-fw.md`](../../docs/pod-fw.md).

## Boundary watchlist

Keep this crate clear of:

- fleet inventory and onboarding workflow
- gateway-side admission policy
- update orchestration services
- verifier or publication semantics

This crate should stay focused on pod-side runtime behavior and emission
discipline.

## Check

```bash
cargo test -p trackone-pod-fw
```
