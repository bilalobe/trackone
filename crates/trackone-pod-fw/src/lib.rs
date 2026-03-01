//! # trackone-pod-fw
//!
//! Firmware and embedded logic for TrackOne pod devices.
//!
//! This crate will contain:
//! - Sensor drivers and hardware abstraction
//! - Frame emission logic
//! - Power management
//! - Radio stack integration
//!
//! This crate depends on `trackone-core` for shared protocol logic and provides
//! pod/firmware-focused helpers and abstractions.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(debug_assertions), deny(warnings))]

#[cfg(all(feature = "production", feature = "mock-hal"))]
compile_error!("trackone-pod-fw production builds must disable the mock-hal feature");

use trackone_core as core;

pub mod hal;
pub mod nonce;
pub mod pod;
pub mod power;
pub mod stress;
#[cfg(feature = "wdg")]
pub mod watchdog;

pub use crate::nonce::{CounterNonce24, Nonce24};
pub use crate::pod::Pod;
pub use crate::power::{enter_low_power, idle_wait, EventWaiter, LowPowerMode};
#[cfg(feature = "wdg")]
pub use crate::watchdog::{
    record_watchdog_reset, LivenessRegistry, ResetCounterStore, DEFAULT_WATCHDOG_MS,
};

/// Firmware version, delegates to core version
pub fn version() -> &'static str {
    core::VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_version_matches_core() {
        assert_eq!(version(), trackone_core::VERSION);
    }
}
