# Pod Firmware Notes (`trackone-pod-fw`)

This document captures a few firmware-side design patterns that originated in
the early bench prototypes and are now promoted into the supported Rust crates.

## Goals

- Keep pod-side logic `no_std`-friendly and allocation-bounded.
- Make HAL boundaries explicit so the same logic can run on real hardware and
  in host-side mocks.
- Support low-power, event-driven loops (`WFI` / interrupt wakeups).
- Provide tiny bring-up aids (e.g., stack high-water mark checks).

## HAL boundary

`trackone-pod-fw` ships a dependency-free set of traits in `trackone_pod_fw::hal`
for common hardware interfaces:

- GPIO (`OutputPin`, `InputPin`)
- time (`DelayMs`, `DelayUs`, `MonotonicClock`)
- buses (`SpiBus`, `I2cBus`, `Serial`)
- RNG (`Rng`)
- storage (`NvStorage`)
- power (`PowerControl`)
- watchdog (`Watchdog`)

For host-side testing, enable the `mock` feature to access simple mock
implementations in `trackone_pod_fw::hal::mock`.

## Low-power helpers

The `trackone_pod_fw::power` module provides:

- `idle_wait()` — emits a `WFI` instruction on ARM targets; no-op elsewhere.
- `EventWaiter` — a tiny helper for event-driven loops.

## Stack guard checks (HWM)

The `trackone_pod_fw::stress` module provides generic helpers to paint and scan
a “guard” buffer with a sentinel byte pattern (`0xAA`) to detect whether the
stack (or any other memory pressure) has overwritten it.

Typical embedded usage is to place a static buffer in a known linker section and
scan it periodically:

```rust
use trackone_pod_fw::stress::{paint_stack_guard, scan_stack_guard};

#[link_section = ".stack_guard"]
static mut STACK_GUARD: [u8; 256] = [0u8; 256];

fn init() {
    unsafe { paint_stack_guard(&mut STACK_GUARD) };
}

fn periodic_check() {
    let report = unsafe { scan_stack_guard(&STACK_GUARD) };
    if !report.ok() {
        // treat as overflow / memory corruption indicator
    }
}
```

The concrete placement and section naming is platform/linker-script specific;
these helpers are intentionally generic.

## Validation approach

TrackOne’s preferred validation layering (when firmware binaries exist) is:

1. Host-side unit tests for logic and invariants.
1. Cross-compiled builds (and optionally QEMU) for ABI/stack behavior.
1. Real hardware bring-up for clocks/peripherals/radio.

The current workspace focuses on the shared protocol (`trackone-core`) and
portable helpers (`trackone-pod-fw`); board-specific binaries live outside this
workspace.
