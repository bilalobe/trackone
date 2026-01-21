//! TrackOne core types shared across pods, gateway, and verifiers.
//!
//! Goals:
//! - `no_std` friendly (bounded allocations via `heapless`)
//! - Forward-only schema (ADR-006 / ADR-030)
//! - Clear SensorThings alignment:
//!   - `phenomenon_time_*` => phenomenonTime
//!   - `ingest_time` => resultTime

use core::fmt;

use heapless::Vec;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

/// Monotonically increasing frame counter per pod.
pub type FrameCounter = u64;

/// Canonical device identifier.
///
/// 8 bytes keeps the door open for future strategies (site prefix, batch, etc.).
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PodId(pub [u8; 8]);

impl PodId {
    fn fmt_hex(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl fmt::Display for PodId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_hex(f)
    }
}

impl fmt::Debug for PodId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PodId(")?;
        self.fmt_hex(f)?;
        f.write_str(")")
    }
}

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

/// ADR-friendly alias for the same identifier.
pub type DeviceId = PodId;

/// Environmental sample channel/type (SensorThings ObservedProperty).
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

/// Out-of-band capability metadata (static tables in firmware/gateway).
///
/// Not part of the wire-level `Fact` schema to avoid lifetime constraints and payload bloat.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SensorCapability {
    pub sample_type: SampleType,
    pub resolution: f32,
    pub accuracy: f32,
    pub unit_symbol: &'static str,
    pub label: &'static str,
}

/// Environmental payload.
/// Times are seconds since epoch (UTC), inclusive.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvFact {
    pub sample_type: SampleType,
    pub phenomenon_time_start: i64,
    pub phenomenon_time_end: i64,

    /// Instant result; if used on a summary fact, treat as the window result (e.g., mean).
    pub value: Option<f32>,

    pub min: Option<f32>,
    pub max: Option<f32>,
    pub mean: Option<f32>,

    /// TrackOne count semantics:
    /// - Instant sample: `Some(1)`
    /// - Summary: `Some(n)` where `n >= 1`
    /// - `None`: unknown (avoid if possible)
    pub count: Option<u32>,

    pub quality: Option<f32>,
    pub sensor_channel: Option<u8>,
}

impl EnvFact {
    /// Instantaneous sample at time `t` with `value`.
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

    /// Window summary over `[t0, t1]`.
    pub fn summary(
        sample_type: SampleType,
        t0: i64,
        t1: i64,
        min: f32,
        max: f32,
        mean: f32,
        count: u32,
    ) -> Self {
        assert!(t0 <= t1, "phenomenon_time_start must be <= phenomenon_time_end");
        assert!(count >= 1, "count must be >= 1");

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

/// Fact payload.
///
/// `Custom` is intentionally small; big payloads should be a separate design decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FactPayload {
    Env(EnvFact),
    Custom(Vec<u8, 64>),
}

/// A single telemetry fact produced by a pod.
///
/// Wire format:
/// 1) postcard serialize `Fact`
/// 2) AEAD encrypt into `EncryptedFrame`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Fact {
    pub pod_id: PodId,
    pub fc: FrameCounter,
    pub ingest_time: i64,
    pub pod_time: Option<i64>,
    pub kind: FactKind,
    pub payload: FactPayload,
}

/// AEAD-wrapped fact as seen on the wire (bounded ciphertext).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptedFrame<const N: usize> {
    pub pod_id: PodId,
    pub fc: FrameCounter,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8, N>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    CryptoError,
    SerializeBufferTooSmall,
    SerializeError,
    DeserializeError,
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
    extern crate alloc;
    use alloc::{boxed::Box, vec::Vec};

    const SENSOR_CAPABILITY_EXAMPLE: SensorCapability = SensorCapability {
        sample_type: SampleType::AmbientAirTemperature,
        resolution: 0.1,
        accuracy: 0.2,
        unit_symbol: "°C",
        label: "Ambient temperature",
    };

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

    #[test]
    fn sensor_capability_roundtrip_postcard() {
        let mut buf = [0u8; 64];
        let used =
            postcard::to_slice(&SENSOR_CAPABILITY_EXAMPLE, &mut buf).expect("serialize sensor");

        // Ensure we can decode from a stable byte slice.
        let static_bytes: &'static [u8] = Box::leak(Vec::from(used).into_boxed_slice());
        let decoded: SensorCapability = postcard::from_bytes(static_bytes).expect("deserialize");
        assert_eq!(decoded, SENSOR_CAPABILITY_EXAMPLE);
    }

    #[test]
    fn sensor_capability_str_fields_are_static() {
        fn assert_static(_: &'static SensorCapability) {}
        assert_static(&SENSOR_CAPABILITY_EXAMPLE);

        let _: &'static str = SENSOR_CAPABILITY_EXAMPLE.unit_symbol;
        let _: &'static str = SENSOR_CAPABILITY_EXAMPLE.label;
    }

    #[test]
    #[should_panic(expected = "phenomenon_time_start must be <= phenomenon_time_end")]
    fn env_fact_summary_rejects_reversed_window() {
        let _ = EnvFact::summary(
            SampleType::AmbientAirTemperature,
            2,
            1,
            -10.0,
            50.0,
            20.0,
            10,
        );
    }

    #[test]
    #[should_panic(expected = "count must be >= 1")]
    fn env_fact_summary_rejects_zero_count() {
        let _ = EnvFact::summary(
            SampleType::AmbientAirTemperature,
            1,
            1,
            -10.0,
            50.0,
            20.0,
            0,
        );
    }
}
