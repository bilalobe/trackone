//! Low-power helpers for embedded pods.
//!
//! These utilities are intentionally minimal and avoid external dependencies.
//! Platform-specific HAL code is still responsible for configuring clocks,
//! peripheral wake sources, and deep-sleep behavior.

use portable_atomic::{AtomicU8, Ordering};

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
    events_pending: AtomicU8,
}

impl EventWaiter {
    pub const fn new() -> Self {
        Self {
            events_pending: AtomicU8::new(0),
        }
    }

    #[inline]
    pub fn signal(&self) {
        let _ = self
            .events_pending
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                Some(pending.saturating_add(1))
            });
        signal_event();
    }

    /// Wait until at least one event is pending, then return the number of
    /// pending events and reset the counter.
    ///
    /// The caller may invoke `signal()` from an interrupt handler or another
    /// execution context. ARM targets use the SEV/WFE event protocol so a
    /// signal racing with the transition to sleep is not lost.
    #[inline]
    pub fn wait(&self) -> u8 {
        loop {
            let pending = self.events_pending.swap(0, Ordering::Acquire);
            if pending != 0 {
                return pending;
            }
            wait_for_event();
        }
    }
}

#[inline]
fn signal_event() {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    unsafe {
        core::arch::asm!("sev", options(nomem, nostack));
    }
}

#[inline]
fn wait_for_event() {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    unsafe {
        core::arch::asm!("wfe", options(nomem, nostack));
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    core::hint::spin_loop();
}

impl Default for EventWaiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn event_waiter_can_be_signaled_through_a_shared_reference() {
        let waiter = Arc::new(EventWaiter::new());
        let signaler = Arc::clone(&waiter);
        let thread = thread::spawn(move || {
            signaler.signal();
            signaler.signal();
        });

        thread.join().unwrap();
        assert_eq!(waiter.wait(), 2);
    }

    #[test]
    fn event_counter_saturates() {
        let waiter = EventWaiter::new();
        for _ in 0..=u8::MAX {
            waiter.signal();
        }
        assert_eq!(waiter.wait(), u8::MAX);
    }
}
