//! # trackone-core
//!
//! Core protocol, cryptographic primitives, and shared logic for the TrackOne
//! ultra-low-power verifiable telemetry system.
//!
//! This crate is platform-agnostic and can be used in both gateway (host)
//! and pod (embedded/firmware) contexts.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(debug_assertions), deny(warnings))]

/// Protocol version string
pub const VERSION: &str = "0.1.0-alpha.1";

/// Core shared types for frames, identifiers, and errors.
pub mod types;

/// Cryptographic abstractions and key/nonce types.
pub mod crypto;

/// Frame construction, encryption, and serialization helpers.
pub mod frame;

/// Gateway-only Merkle tree helpers, enabled via the `gateway` feature.
#[cfg(feature = "gateway")]
pub mod merkle;

pub use trackone_constants::MAX_FACT_LEN;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_sanity() {
        assert_eq!(VERSION, "0.1.0-alpha.1");
    }

    #[test]
    fn types_compile() {
        use crate::types::{FrameCounter, PodId};

        let pod = PodId(42);
        let fc: FrameCounter = 7;
        assert_eq!(pod.0, 42);
        assert_eq!(fc, 7);
    }
}
