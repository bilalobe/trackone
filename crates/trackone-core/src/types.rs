//! Shared core types for TrackOne frames and identifiers.
//!
//! This module is `no_std`-friendly and avoids heap allocations by
//! using fixed-size buffers via `heapless` where needed.

use core::fmt;
use heapless::Vec;
use serde::{Deserialize, Serialize};

/// Monotonically increasing frame counter per pod.
pub type FrameCounter = u64;

/// Identifier for a pod/device.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PodId(pub u32);

/// Payload carried by a fact/measurement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FactPayload {
    SoilMoisture { value: u16 },
    Temperature { milli_celsius: i32 },
    Battery { millivolts: u16 },
}

/// A single telemetry fact produced by a pod.
///
/// Canonical wire format:
/// 1. Serialize `Fact` with postcard.
/// 2. Encrypt serialized bytes with AEAD into an `EncryptedFrame`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Fact {
    pub pod_id: PodId,
    pub fc: FrameCounter,
    pub payload: FactPayload,
}

/// Encrypted frame as seen on the wire.
///
/// The ciphertext is stored in a bounded `heapless::Vec` to keep this
/// usable in `no_std` environments without a heap.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptedFrame<const N: usize> {
    pub pod_id: PodId,
    pub fc: FrameCounter,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8, N>,
}

/// Core error type for trackone-core operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Underlying AEAD/crypto failure (seal/open).
    CryptoError,
    /// Not enough space in internal buffers for serialization.
    SerializeBufferTooSmall,
    /// Postcard serialization failure for `Fact`.
    SerializeError,
    /// Postcard deserialization failure for `Fact`.
    DeserializeError,
    /// Ciphertext does not fit into the configured `EncryptedFrame` capacity.
    CiphertextTooLarge,
}

pub type CoreResult<T> = Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            CryptoError => write!(f, "crypto error"),
            SerializeBufferTooSmall => write!(f, "serialize buffer too small"),
            SerializeError => write!(f, "serialize error"),
            DeserializeError => write!(f, "deserialize error"),
            CiphertextTooLarge => write!(f, "ciphertext too large for frame capacity"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pod_id_and_counter_basic() {
        let pod = PodId(1);
        let fc: FrameCounter = 10;
        assert_eq!(pod.0, 1);
        assert_eq!(fc, 10);
    }

    #[test]
    fn fact_roundtrip_serde() {
        let fact = Fact {
            pod_id: PodId(7),
            fc: 42,
            payload: FactPayload::Temperature {
                milli_celsius: 25_000,
            },
        };

        let mut buf = [0u8; 128];
        let used = postcard::to_slice(&fact, &mut buf).expect("serialize fact");

        let decoded: Fact = postcard::from_bytes(used).expect("deserialize fact");
        assert_eq!(fact, decoded);
    }

    #[test]
    fn error_display() {
        assert_eq!(Error::CryptoError.to_string(), "crypto error");
        assert_eq!(
            Error::SerializeBufferTooSmall.to_string(),
            "serialize buffer too small"
        );
        assert_eq!(Error::SerializeError.to_string(), "serialize error");
        assert_eq!(Error::DeserializeError.to_string(), "deserialize error");
        assert_eq!(
            Error::CiphertextTooLarge.to_string(),
            "ciphertext too large for frame capacity"
        );
    }
}
