# ADR-042: Hardware Watchdog & Liveness-Registry Policy

**Status**: Proposed
**Date**: 2026-03-01

## Related ADRs

- [ADR-021: safety-net thinking for fault-detection and fail-loud behavior](ADR-021-safety-net-ots-pipeline-verification.md)
- [ADR-024: anti-replay and ledger semantics that inform later health-fact wiring](ADR-024-anti-replay-and-ots-backed-ledger.md)

## Context

TrackOne-pod firmware currently has no hardware watchdog (WDG).
Alpha .6 introduces a WDG module that:

1. Enables the MCU’s independent watchdog after boot.
1. Requires every periodic task to “check in” via a liveness bitmap.
1. Establishes a local reset-counter hook so spontaneous watchdog resets can be surfaced later without redesigning the pod runtime.

Because this decision touches hardware (extra pull-ups, jumper, testpoint), task architecture, boot semantics, and future health telemetry, it must be codified.

## Decision

### Hardware

- Use the MCU’s Independent Watchdog (IWDG) with its own LSI clock.
- Timeout defaults to `DEFAULT_WATCHDOG_MS` (1 000 ms) in `trackone-pod-fw::watchdog`, with board/profile overrides allowed once measured WCET evidence exists.
- Configuration is locked after the first feed; cannot be disabled without a full reset.

### Firmware

- `trackone-pod-fw` adds a `wdg` feature; `production` implies `wdg`, and production builds must disable `mock-hal`.
- An atomic liveness bitmap tracks enabled periodic tasks only; tasks disabled by configuration are excluded from quorum.
- Idle/lowest-priority context feeds the watchdog only when all enabled task bits are set, then clears the bitmap.
- Firmware exposes `ResetCause::{Watchdog, PowerOn, Software, Other}` so board support packages can normalize boot reasons.
- On boot, firmware may increment a local `reset_counter` stored in retained RAM (or equivalent retained storage) when the reset cause is `Watchdog`.

### Gateway / Ledger

- Deferred for the alpha.6 pod-firmware slice: no `trackone-core` schema change or gateway wiring is required to land the watchdog policy.
- Future work may surface the local `reset_counter` as `HealthFact::ResetCounter(u32)` once the pod-fw behavior is proven stable.

## Consequences

### Positive

- Automatic recovery from hangs in field deployments.
- Local reset-accounting hook for later ops/audit telemetry without reopening the watchdog policy.
- Minimal code footprint; no cross-crate schema churn in the first slice.

### Negative / Trade-offs

- Adds ~2 % current overhead while IWDG is running.
- Incorrect timeout sizing could induce reset loops; must be tuned per board.
- `reset_counter` is monotonic across watchdog resets only; it is not guaranteed across full power loss unless a flash-backed retention mode is selected.

## Alternatives Considered

- **Software watchdog in the scheduler** - rejected: can fail if the scheduler itself crashes.
- **No watchdog** - relies on manual power-cycle; unacceptable for multi-month unattended pods.

## Testing & Migration

1. HIL test hangs `task_radio()`; expect WDG reset within 2 s and `reset_counter += 1`.
1. CI host build uses a `MockWatchdog` so unit tests are unaffected.
1. Compile-time guard rejects `production` builds that still enable `mock-hal`.

## Future Work

- TODO: wire the local watchdog `reset_counter` into `trackone-core` as `HealthFact::ResetCounter(u32)` once the pod-fw-only slice is stable.
