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

use trackone_core as core;

pub mod hal;
pub mod nonce;
pub mod pod;
pub mod power;
pub mod stress;

pub use crate::nonce::{CounterNonce24, Nonce24};
pub use crate::pod::Pod;
pub use crate::power::{enter_low_power, idle_wait, EventWaiter, LowPowerMode};

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
