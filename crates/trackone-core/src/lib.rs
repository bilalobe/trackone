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
pub const VERSION: &str = "0.1.0-alpha.5";

/// Core shared types for frames, identifiers, and errors.
pub mod types;

/// Re-export common types for ergonomic access from other crates.
pub use crate::types::{
    CoreResult, DeviceId, EncryptedFrame, EnvFact, Error, Fact, FactKind, FactPayload,
    FrameCounter, PodId, SampleType, SensorCapability,
};

/// Cryptographic abstractions and key/nonce types.
pub mod crypto;

/// Frame construction, encryption, and serialization helpers.
pub mod frame;

/// Gateway-only Merkle tree helpers, enabled via the `gateway` feature.
#[cfg(feature = "gateway")]
pub mod merkle;

/// Provisioning records and CBOR serialization (ADR-019, ADR-034).
pub mod provisioning;

/// Canonical CBOR encoding for deterministic hashing/commitments (ADR-034).
///
/// Note: this is currently `std`-gated because it returns `Vec<u8>`.
#[cfg(feature = "std")]
pub mod cbor;

pub use trackone_constants::{AEAD_NONCE_LEN, AEAD_TAG_LEN, MAX_FACT_LEN};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_sanity() {
        assert_eq!(VERSION, "0.1.0-alpha.5");
    }

    #[test]
    fn types_compile() {
        use crate::types::{FrameCounter, PodId};

        let pod = PodId::from(42u32);
        let fc: FrameCounter = 7;
        assert_eq!(pod.0[4..8], 42u32.to_be_bytes());
        assert_eq!(fc, 7);
    }
}
