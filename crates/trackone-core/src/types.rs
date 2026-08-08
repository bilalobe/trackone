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
    /// Constructs a `PodId` from a legacy 32-bit identifier.
    ///
    /// ## Wire layout (stable, forward-compatible)
    ///
    /// This maps the `u32` into the **last 4 bytes** (`[4..8]`) in **big-endian** order:
    ///
    /// - `self.0[0..4]`: reserved for a future prefix (site/fleet/issuer/batch/etc.).
    ///   Currently all zeros for `From<u32>`.
    /// - `self.0[4..8]`: the `u32` value encoded as `v.to_be_bytes()`.
    ///
    /// Rationale:
    /// - Keeping the high 4 bytes reserved allows introducing namespacing later without
    ///   changing the overall `PodId` width.
    /// - Big-endian provides a canonical encoding independent of host endianness.
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
    WaterLevel = 11,
    WaterFlowRate = 12,
    WaterVolume = 13,
    WaterPressure = 14,
    WaterTemperature = 15,
    WaterElectricalConductivity = 16,
    WaterPh = 17,
    WaterDissolvedOxygen = 18,
    WaterTurbidity = 19,
    WaterSalinity = 20,
    WaterTotalDissolvedSolids = 21,
    Rainfall = 22,
    RainIntensity = 23,
    WindSpeed = 24,
    WindDirection = 25,
    BarometricPressure = 26,
    SolarIrradiance = 27,
    SoilMoisture = 28,
    SoilTemperature = 29,
    SoilElectricalConductivity = 30,
    VibrationRms = 31,
    VibrationPeak = 32,
    ShockAcceleration = 33,
    InclinationAngle = 34,
    Displacement = 35,
    Strain = 36,
    CrackWidth = 37,
    AcousticNoise = 38,
    AirQualityPm25 = 39,
    AirQualityPm10 = 40,
    CarbonDioxide = 41,
    VolatileOrganicCompounds = 42,
    BatteryVoltage = 43,
    BatteryCurrent = 44,
    BatteryTemperature = 45,
    SolarChargeCurrent = 46,
    EnclosureHumidity = 47,
    EnclosureTemperature = 48,
    RadioRssi = 49,
    RadioSnr = 50,
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
    pub fn instant(
        sample_type: SampleType,
        t: i64,
        value: f32,
    ) -> Result<Self, FactValidationError> {
        let fact = Self {
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
        };
        fact.validate()?;
        Ok(fact)
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
    ) -> Result<Self, FactValidationError> {
        let fact = Self {
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
        };
        fact.validate()?;
        Ok(fact)
    }

    /// Validate the semantic shape shared by every wire and commitment surface.
    pub fn validate(&self) -> Result<(), FactValidationError> {
        if self.phenomenon_time_start > self.phenomenon_time_end {
            return Err(FactValidationError::PhenomenonTimeReversed);
        }
        if self.quality.is_some_and(|quality| !quality.is_finite()) {
            return Err(FactValidationError::NonFiniteQuality);
        }

        match self.value {
            Some(value) => {
                if self.phenomenon_time_start != self.phenomenon_time_end {
                    return Err(FactValidationError::InstantTimeRange);
                }
                if !value.is_finite() {
                    return Err(FactValidationError::NonFiniteInstantValue);
                }
                if self.min.is_some() || self.max.is_some() || self.mean.is_some() {
                    return Err(FactValidationError::InstantHasAggregates);
                }
                if !matches!(self.count, None | Some(1)) {
                    return Err(FactValidationError::InstantCount);
                }
            }
            None => {
                let (Some(min), Some(max), Some(mean), Some(count)) =
                    (self.min, self.max, self.mean, self.count)
                else {
                    return Err(FactValidationError::IncompleteSummary);
                };
                if count == 0 {
                    return Err(FactValidationError::SummaryCount);
                }
                if !min.is_finite() || !max.is_finite() || !mean.is_finite() {
                    return Err(FactValidationError::NonFiniteSummaryValue);
                }
                if min > mean || mean > max {
                    return Err(FactValidationError::SummaryOrder);
                }
            }
        }

        Ok(())
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
/// Rust-native framed transport profiles live in `trackone-ingest`; commitment
/// authority remains with the canonical CBOR surfaces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Fact {
    pub pod_id: PodId,
    pub fc: FrameCounter,
    pub ingest_time: i64,
    pub pod_time: Option<i64>,
    pub kind: FactKind,
    pub payload: FactPayload,
}

impl Fact {
    /// Validate the kind/payload pairing and all payload-level invariants.
    pub fn validate(&self) -> Result<(), FactValidationError> {
        match (&self.kind, &self.payload) {
            (FactKind::Env, FactPayload::Env(env)) => env.validate(),
            (FactKind::Pipeline | FactKind::Health | FactKind::Custom, FactPayload::Custom(_)) => {
                Ok(())
            }
            _ => Err(FactValidationError::KindPayloadMismatch),
        }
    }
}

/// Stable semantic validation failures for canonical telemetry facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactValidationError {
    KindPayloadMismatch,
    PhenomenonTimeReversed,
    InstantTimeRange,
    NonFiniteInstantValue,
    InstantHasAggregates,
    InstantCount,
    IncompleteSummary,
    SummaryCount,
    NonFiniteSummaryValue,
    SummaryOrder,
    NonFiniteQuality,
}

impl fmt::Display for FactValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::KindPayloadMismatch => "fact kind does not match its payload",
            Self::PhenomenonTimeReversed => "phenomenon_time_start must be <= phenomenon_time_end",
            Self::InstantTimeRange => "instant fact must use equal phenomenon times",
            Self::NonFiniteInstantValue => "instant value must be finite",
            Self::InstantHasAggregates => "instant fact must not contain aggregate values",
            Self::InstantCount => "instant count must be absent or equal to one",
            Self::IncompleteSummary => "summary fact requires min, max, mean, and count",
            Self::SummaryCount => "summary count must be positive",
            Self::NonFiniteSummaryValue => "summary values must be finite",
            Self::SummaryOrder => "summary values must satisfy min <= mean <= max",
            Self::NonFiniteQuality => "quality must be finite when present",
        };
        f.write_str(message)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    CryptoError,
    SerializeBufferTooSmall,
    SerializeError,
    DeserializeError,
    CiphertextTooLarge,
    InvalidFact(FactValidationError),
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
            InvalidFact(reason) => write!(f, "invalid fact: {reason}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    #[cfg(feature = "postcard")]
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

    #[cfg(feature = "postcard")]
    #[test]
    fn fact_roundtrip_postcard() {
        let fact = Fact {
            pod_id: PodId::from(7u32),
            fc: 42,
            ingest_time: 0,
            pod_time: None,
            kind: FactKind::Env,
            payload: FactPayload::Env(
                EnvFact::instant(SampleType::AmbientAirTemperature, 1_700_000_000, 25.0)
                    .expect("valid instant fact"),
            ),
        };

        let mut buf = [0u8; 256];
        let used = postcard::to_slice(&fact, &mut buf).expect("serialize fact");
        let decoded: Fact = postcard::from_bytes(used).expect("deserialize fact");
        assert_eq!(fact, decoded);
    }

    #[cfg(feature = "postcard")]
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
    fn env_fact_summary_rejects_reversed_window() {
        assert_eq!(
            EnvFact::summary(
                SampleType::AmbientAirTemperature,
                2,
                1,
                -10.0,
                50.0,
                20.0,
                10,
            ),
            Err(FactValidationError::PhenomenonTimeReversed)
        );
    }

    #[test]
    fn env_fact_summary_rejects_zero_count() {
        assert_eq!(
            EnvFact::summary(
                SampleType::AmbientAirTemperature,
                1,
                1,
                -10.0,
                50.0,
                20.0,
                0,
            ),
            Err(FactValidationError::SummaryCount)
        );
    }

    #[test]
    fn fact_validation_rejects_kind_payload_mismatch() {
        let fact = Fact {
            pod_id: PodId::from(7u32),
            fc: 1,
            ingest_time: 0,
            pod_time: None,
            kind: FactKind::Health,
            payload: FactPayload::Env(
                EnvFact::instant(SampleType::AmbientAirTemperature, 1_700_000_000, 25.0).unwrap(),
            ),
        };

        assert_eq!(
            fact.validate(),
            Err(FactValidationError::KindPayloadMismatch)
        );
    }

    #[test]
    fn env_fact_validation_rejects_non_finite_and_mixed_shapes() {
        assert_eq!(
            EnvFact::instant(SampleType::AmbientAirTemperature, 1_700_000_000, f32::NAN,),
            Err(FactValidationError::NonFiniteInstantValue)
        );
        assert_eq!(
            EnvFact::summary(SampleType::AmbientAirTemperature, 1, 2, 10.0, 20.0, 9.0, 2,),
            Err(FactValidationError::SummaryOrder)
        );

        let invalid = EnvFact {
            sample_type: SampleType::AmbientAirTemperature,
            phenomenon_time_start: 1,
            phenomenon_time_end: 1,
            value: Some(1.0),
            min: Some(1.0),
            max: None,
            mean: None,
            count: Some(1),
            quality: None,
            sensor_channel: None,
        };
        assert_eq!(
            invalid.validate(),
            Err(FactValidationError::InstantHasAggregates)
        );
    }
}
