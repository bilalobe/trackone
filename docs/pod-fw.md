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

## Pod Bring-Up Checklist

Use this as the minimum "do not skip" checklist when bringing up a new pod
board, a major firmware refactor, or a hardware respin.

### 1. Pre-power checks

- Confirm board revision, schematic, and BOM match the firmware target.
- Inspect solder joints, polarity-sensitive parts, crystals, antenna path, and
  any bodge wires before applying power.
- Verify SWD/UART headers, reset line, and boot-selection strapping are
  reachable on the bench.
- Confirm expected power rails, brown-out threshold, and current-limit settings
  on the lab supply before first power-on.

### 2. First power-on

- Power the board from a current-limited bench supply first, not battery.
- Record idle current draw at reset and compare it to the expected envelope.
- Confirm the MCU stays out of a reset loop and is debuggable over SWD/JTAG.
- Verify a basic "alive" indicator (LED toggle, UART banner, or debug pulse).

### 3. Clock and reset sanity

- Confirm the selected clock source starts reliably (HSI/HSE/LSE/LSI as
  applicable).
- Verify the system tick or monotonic timer advances at the expected rate.
- Exercise manual reset, software reset, and power-cycle reset paths.
- Confirm reset-cause decoding is correct for at least `PowerOn`, `Software`,
  and `Watchdog`.

### 4. Watchdog (WDG / IWDG)

- Start the watchdog early enough that normal boot still completes with margin.
- Confirm the watchdog feed path is driven by the liveness quorum, not a timer
  ISR alone.
- Deliberately block one periodic task and verify the watchdog expires and
  resets the MCU.
- Verify the retained `reset_counter` path increments across watchdog resets.
- Confirm production builds keep the watchdog enabled and reject `mock-hal`.

### 5. Storage and retained state

- Verify flash/NVM reads, writes, and sector erase behavior on real hardware.
- Confirm retained RAM or alternate storage survives watchdog resets as
  expected.
- Validate that corrupted or blank retained state fails safe and does not wedge
  boot.

### 6. Radio and transport smoke test

- Confirm SPI/UART transport to the radio is functional on real pins.
- Execute one known-good TX/RX smoke test at short range before field-range
  tuning.
- Measure one representative frame airtime and compare it to the expected duty
  cycle budget.
- Confirm the pod can emit at least one encrypted frame end-to-end with the
  target nonce path.

### 7. Sensor and power-path checks

- Verify each required sensor bus enumerates and returns sane values.
- Confirm out-of-range sensor data is surfaced as an error or status flag, not
  silently treated as valid.
- Measure sleep current, wake current, and TX peak current on the real board.
- Confirm the reservoir capacitor / supply path keeps the MCU and radio inside
  safe voltage during TX peaks.

### 8. Fault-injection checks

- Force a bad config or missing device state and confirm boot fails safe.
- Corrupt one radio transaction and confirm the firmware recovers or surfaces a
  clear error.
- Trigger a low-battery or brown-out condition and confirm behavior is
  predictable.
- If stack-guard checks are enabled, verify the guard reports before silent
  corruption.

### 9. Sign-off before field use

- Capture the measured boot current, sleep current, and TX peak current for the
  board revision.
- Record the chosen watchdog timeout and why it has sufficient runtime margin.
- Record the tested radio preset (frequency, spreading factor, bandwidth, power
  level).
- Link the bring-up notes to the relevant ADRs (at minimum ADR-042 for the
  watchdog policy).
- Do not move to unattended deployment until the board passes the watchdog trip
  test, one radio smoke test, and one power-cycle recovery test.
