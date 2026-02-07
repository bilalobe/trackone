//! Low-power helpers for embedded pods.
//!
//! These utilities are intentionally minimal and avoid external dependencies.
//! Platform-specific HAL code is still responsible for configuring clocks,
//! peripheral wake sources, and deep-sleep behavior.

/// Pod-side low-power modes (informational).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LowPowerMode {
    Sleep,
    LowPowerSleep,
    Stop1,
    Stop2,
}

/// Enter a low-power mode.
///
/// Current implementation maps all modes to `idle_wait()`; MCUs typically need
/// additional register configuration to distinguish STOP vs SLEEP variants.
#[inline]
pub fn enter_low_power(_mode: LowPowerMode) {
    idle_wait();
}

/// Wait-for-interrupt (WFI) on ARM targets; no-op on other targets.
#[inline]
pub fn idle_wait() {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    unsafe {
        core::arch::asm!("wfi", options(nomem, nostack));
    }
}

/// Event-driven sleep helper.
pub struct EventWaiter {
    events_pending: u8,
}

impl EventWaiter {
    pub const fn new() -> Self {
        Self { events_pending: 0 }
    }

    #[inline]
    pub fn signal(&mut self) {
        self.events_pending = self.events_pending.saturating_add(1);
    }

    /// Wait until at least one event is pending, then return the number of
    /// pending events and reset the counter.
    ///
    /// This method spins on `idle_wait()` until `events_pending` becomes non-zero.
    /// The caller is expected to call `signal()` from an interrupt handler or
    /// another execution context to set `events_pending` and wake the CPU.
    #[inline]
    #[allow(clippy::while_immutable_condition)]
    pub fn wait(&mut self) -> u8 {
        while self.events_pending == 0 {
            idle_wait();
        }
        let pending = self.events_pending;
        self.events_pending = 0;
        pending
    }
}

impl Default for EventWaiter {
    fn default() -> Self {
        Self::new()
    }
}
