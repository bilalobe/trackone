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
//! Currently a placeholder; depends on trackone-core for shared protocol logic.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(debug_assertions), deny(warnings))]

use trackone_core as core;

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
