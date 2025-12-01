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
pub const VERSION: &str = "0.0.1";

/// Core cryptographic primitives module
pub mod crypto {
    //! Cryptographic primitives: HKDF, X25519, XChaCha20-Poly1305, Ed25519
    //!
    //! This module will contain wrappers around crypto libraries that are
    //! compatible with both std and no_std environments.
}

/// Merkle tree and batching logic
pub mod merkle {
    //! Merkle tree construction, canonical JSON serialization,
    //! and proof generation/verification.
}

/// Protocol frame and ledger structures
pub mod protocol {
    //! Frame formats, ledger entries, and wire protocol definitions
    //! shared between gateway and pod.
}

/// OpenTimestamps structures and helpers
pub mod ots {
    //! OTS proof construction and verification primitives
    //! (calendar-agnostic).
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_sanity() {
        assert_eq!(VERSION, "0.0.1");
    }
}
