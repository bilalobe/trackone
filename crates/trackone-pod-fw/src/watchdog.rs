//! Watchdog helpers and liveness-registry policy for pod firmware.
//!
//! This module keeps the policy small: feed the hardware watchdog only after
//! all enabled periodic tasks report progress in the current interval.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::hal::{ResetCause, Watchdog};
pub use trackone_core::DEFAULT_WATCHDOG_MS;

/// Small storage contract for persisting the watchdog reset counter.
pub trait ResetCounterStore {
    type Error;

    fn load_reset_counter(&self) -> Result<u32, Self::Error>;
    fn store_reset_counter(&mut self, value: u32) -> Result<(), Self::Error>;
}

/// Tracks which enabled tasks have completed work during the current interval.
pub struct LivenessRegistry {
    enabled_mask: u32,
    heartbeat_mask: AtomicU32,
}

impl LivenessRegistry {
    /// Create a registry from the set of enabled task bits.
    pub const fn new(enabled_mask: u32) -> Self {
        Self {
            enabled_mask,
            heartbeat_mask: AtomicU32::new(0),
        }
    }

    /// Start the hardware watchdog with the crate default timeout.
    pub fn start<W: Watchdog>(&self, watchdog: &mut W) {
        watchdog.start(DEFAULT_WATCHDOG_MS);
        self.clear();
    }

    /// The task bitmask expected before a feed is allowed.
    pub const fn enabled_mask(&self) -> u32 {
        self.enabled_mask
    }

    /// Replace the enabled task set and clear any stale heartbeat state.
    pub fn set_enabled_mask(&mut self, enabled_mask: u32) {
        self.enabled_mask = enabled_mask;
        self.clear();
    }

    /// Record forward progress for a task bit in the current interval.
    pub fn check_in(&self, task_index: u8) {
        if task_index < u32::BITS as u8 {
            self.heartbeat_mask
                .fetch_or(1u32 << task_index, Ordering::Relaxed);
        }
    }

    /// True only when every enabled task has checked in at least once.
    ///
    /// When no tasks are enabled the condition is vacuously true.
    pub fn all_ready(&self) -> bool {
        let enabled = self.enabled_mask;
        if enabled == 0 {
            // With no enabled tasks, the readiness condition is vacuously true.
            return true;
        }
        (self.heartbeat_mask.load(Ordering::Relaxed) & enabled) == enabled
    }

    /// Return the subset of enabled tasks that still have not checked in.
    pub fn pending_mask(&self) -> u32 {
        self.enabled_mask & !self.heartbeat_mask.load(Ordering::Relaxed)
    }

    /// Clear the heartbeat state for the next watchdog interval.
    pub fn clear(&self) {
        self.heartbeat_mask.store(0, Ordering::Relaxed);
    }

    /// Feed the watchdog only when every enabled task has progressed.
    pub fn feed_if_ready<W: Watchdog>(&self, watchdog: &mut W) -> bool {
        if !self.all_ready() {
            return false;
        }

        watchdog.feed();
        self.clear();
        true
    }
}

/// Increment and persist the reset counter only for watchdog-triggered resets.
pub fn record_watchdog_reset<S>(
    reset_cause: ResetCause,
    store: &mut S,
) -> Result<Option<u32>, S::Error>
where
    S: ResetCounterStore,
{
    if reset_cause != ResetCause::Watchdog {
        return Ok(None);
    }

    let next = store.load_reset_counter()?.wrapping_add(1);
    store.store_reset_counter(next)?;
    Ok(Some(next))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hal::mock::MockWatchdog;

    struct MemoryCounter(u32);

    impl ResetCounterStore for MemoryCounter {
        type Error = ();

        fn load_reset_counter(&self) -> Result<u32, Self::Error> {
            Ok(self.0)
        }

        fn store_reset_counter(&mut self, value: u32) -> Result<(), Self::Error> {
            self.0 = value;
            Ok(())
        }
    }

    #[test]
    fn registry_starts_watchdog_with_default_timeout() {
        let registry = LivenessRegistry::new(0b0011);
        let mut watchdog = MockWatchdog::new();

        registry.start(&mut watchdog);

        assert!(watchdog.is_started());
        assert_eq!(watchdog.timeout_ms(), DEFAULT_WATCHDOG_MS);
        assert_eq!(registry.pending_mask(), 0b0011);
    }

    #[test]
    fn watchdog_is_not_fed_until_all_enabled_tasks_check_in() {
        let registry = LivenessRegistry::new(0b0111);
        let mut watchdog = MockWatchdog::new();

        registry.check_in(0);
        registry.check_in(1);

        assert!(!registry.all_ready());
        assert_eq!(registry.pending_mask(), 0b0100);
        assert!(!registry.feed_if_ready(&mut watchdog));
        assert_eq!(watchdog.feed_count(), 0);

        registry.check_in(2);

        assert!(registry.all_ready());
        assert!(registry.feed_if_ready(&mut watchdog));
        assert_eq!(watchdog.feed_count(), 1);
        assert_eq!(registry.pending_mask(), 0b0111);
    }

    #[test]
    fn empty_enabled_mask_is_vacuously_ready() {
        let registry = LivenessRegistry::new(0);
        let mut watchdog = MockWatchdog::new();

        assert!(registry.all_ready());
        assert!(registry.feed_if_ready(&mut watchdog));
        assert_eq!(watchdog.feed_count(), 1);
    }

    #[test]
    fn disabled_tasks_are_excluded_from_quorum() {
        let registry = LivenessRegistry::new(0b0101);
        let mut watchdog = MockWatchdog::new();

        registry.check_in(0);
        registry.check_in(2);

        assert!(registry.all_ready());
        assert!(registry.feed_if_ready(&mut watchdog));
        assert_eq!(watchdog.feed_count(), 1);
    }

    #[test]
    fn non_watchdog_resets_do_not_increment_counter() {
        let mut store = MemoryCounter(9);

        let count = record_watchdog_reset(ResetCause::PowerOn, &mut store).expect("record");

        assert_eq!(count, None);
        assert_eq!(store.0, 9);
    }

    #[test]
    fn watchdog_resets_increment_counter() {
        let mut store = MemoryCounter(9);

        let count = record_watchdog_reset(ResetCause::Watchdog, &mut store).expect("record");

        assert_eq!(count, Some(10));
        assert_eq!(store.0, 10);
    }
}
