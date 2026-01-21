//! Shared core types for TrackOne frames and identifiers.
//!
//! This module is `no_std`-friendly and avoids unbounded allocations by
//! using fixed-size buffers via `heapless` where needed.
//!
//! ## Core invariants
//! - The tuple `(pod_id, fc)` uniquely identifies a fact and enforces anti-replay.
//! - The schema is forward-only (see ADR-006 / ADR-030).
//! - `phenomenon_time_*` represent the measured time window (SensorThings phenomenonTime).
//! - `ingest_time` represents gateway arrival time (SensorThings resultTime).

use core::fmt;

use heapless::Vec;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

/// Monotonically increasing frame counter per pod.
pub type FrameCounter = u64;

/// Canonical device identifier.
///
/// Uses 8 bytes to leave room for future schemes (site prefix, manufacturing batch, etc.).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PodId(pub [u8; 8]);

impl From<[u8; 8]> for PodId {
    fn from(v: [u8; 8]) -> Self {
        Self(v)
    }
}

impl From<u32> for PodId {
    fn from(v: u32) -> Self {
        let mut id = [0u8; 8];
        id[4..8].copy_from_slice(&v.to_be_bytes());
        Self(id)
    }
}

/// Alias used by ADRs and gateway terminology.
pub type DeviceId = PodId;

/// Environmental sample channel/type.
///
/// This aligns with SensorThings ObservedProperty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum SampleType {
    AmbientAirTemperature = 1,
    AmbientRelativeHumidity = 2,
    InterfaceTemperature = 3,
    CoverageCapacitance = 4,
    BioImpedanceMagnitude = 5,
    BioImpedanceActivity = 6,
    SupplyVoltage = 7,
    BatterySoc = 8,
    FloodContact = 9,
    LinkQuality = 10,
    Custom = 250,
}

/// Out-of-band sensor capability metadata.
///
/// Not embedded into the wire-level Fact schema to avoid lifetime and
/// payload bloat; instead, used as static tables in firmware/gateway.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SensorCapability {
    pub sample_type: SampleType,
    /// Smallest meaningful step (engineering units).
    pub resolution: f32,
    /// Accuracy (engineering units), e.g. ±0.2°C.
    pub accuracy: f32,
    /// Human-facing unit symbol (e.g. "°C", "%", "V").
    pub unit_symbol: &'static str,
    /// Human-facing label.
    pub label: &'static str,
}

/// Payload for environmental sensing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvFact {
    pub sample_type: SampleType,

    /// Seconds since epoch (UTC). Inclusive.
    pub phenomenon_time_start: i64,
    /// Seconds since epoch (UTC). Inclusive.
    pub phenomenon_time_end: i64,

    /// Instantaneous value (if present). If this is set for a windowed summary,
    /// it should be interpreted as the window result (e.g., mean).
    pub value: Option<f32>,

    pub min: Option<f32>,
    pub max: Option<f32>,
    pub mean: Option<f32>,
    pub count: Option<u32>,

    /// Optional quality indicator (application-specific but stable).
    pub quality: Option<f32>,

    /// Optional channel index (ADC channel, bus index, etc.).
    pub sensor_channel: Option<u8>,
}

impl EnvFact {
    /// Convenience constructor for an instantaneous sample.
    pub fn instant(sample_type: SampleType, t: i64, value: f32) -> Self {
        Self {
            sample_type,
            phenomenon_time_start: t,
            phenomenon_time_end: t,
            value: Some(value),
            min: None,
            max: None,
            mean: None,
            count: Some(1),
            quality: None,
            sensor_channel: None,
        }
    }

    /// Convenience constructor for a window summary.
    pub fn summary(
        sample_type: SampleType,
        t0: i64,
        t1: i64,
        min: f32,
        max: f32,
        mean: f32,
        count: u32,
    ) -> Self {
        Self {
            sample_type,
            phenomenon_time_start: t0,
            phenomenon_time_end: t1,
            value: None,
            min: Some(min),
            max: Some(max),
            mean: Some(mean),
            count: Some(count),
            quality: None,
            sensor_channel: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum FactKind {
    Env = 1,
    Pipeline = 2,
    Health = 3,
    Custom = 250,
}

/// Payload carried by a Fact.
///
/// `Custom` is intentionally very small; large experimental payloads should be
/// handled as a separate design decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FactPayload {
    Env(EnvFact),
    Custom(Vec<u8, 64>),
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

    /// Gateway arrival time (seconds since epoch).
    pub ingest_time: i64,

    /// Optional pod-local time (seconds since epoch), if available.
    pub pod_time: Option<i64>,

    pub kind: FactKind,
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
    fn pod_id_from_u32_is_stable() {
        let pod = PodId::from(42u32);
        assert_eq!(pod.0[4..8], 42u32.to_be_bytes());
    }

    #[test]
    fn fact_roundtrip_postcard() {
        let fact = Fact {
            pod_id: PodId::from(7u32),
            fc: 42,
            ingest_time: 0,
            pod_time: None,
            kind: FactKind::Env,
            payload: FactPayload::Env(EnvFact::instant(
                SampleType::AmbientAirTemperature,
                1_700_000_000,
                25.0,
            )),
        };

        let mut buf = [0u8; 256];
        let used = postcard::to_slice(&fact, &mut buf).expect("serialize fact");

        let decoded: Fact = postcard::from_bytes(used).expect("deserialize fact");
        assert_eq!(fact, decoded);
    }
}
