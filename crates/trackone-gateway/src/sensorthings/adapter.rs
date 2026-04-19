use serde_json::json;
use trackone_core::{Fact, FactKind, FactPayload, SampleType};
use trackone_ledger::sha256_hex;

use super::mapping::{
    EnvObservationProjection, EnvObservationProjectionInput, ObservationResult,
    project_env_observation,
};
use super::timefmt::format_rfc3339_utc;
use super::validate::ValidationError;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EnvObservationAdapterContext {
    pub site_id: Option<String>,
    pub sensor_key_override: Option<String>,
    pub deployment_sensor_key: Option<String>,
    pub provisioning_sensor_key: Option<String>,
    pub provisioning_identity: Option<String>,
}

#[derive(Debug)]
pub enum AdapterError {
    NotEnvFact,
    MissingSensorIdentity {
        pod_id: String,
        observed_property_key: &'static str,
        sensor_channel: Option<u8>,
    },
    Validation(ValidationError),
}

impl core::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotEnvFact => f.write_str("fact is not an environmental observation"),
            Self::MissingSensorIdentity {
                pod_id,
                observed_property_key,
                sensor_channel,
            } => write!(
                f,
                "missing provisioning/deployment-backed sensor identity for {pod_id} \
observed_property={observed_property_key} sensor_channel={sensor_channel:?}"
            ),
            Self::Validation(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for AdapterError {}

impl From<ValidationError> for AdapterError {
    fn from(value: ValidationError) -> Self {
        Self::Validation(value)
    }
}

pub fn adapt_env_fact_input(
    fact: &Fact,
    ctx: &EnvObservationAdapterContext,
) -> Result<EnvObservationProjectionInput, AdapterError> {
    let env = match (&fact.kind, &fact.payload) {
        (FactKind::Env, FactPayload::Env(env)) => env,
        _ => return Err(AdapterError::NotEnvFact),
    };
    let observed_property_key = observed_property_key(env.sample_type);

    let sensor_key = ctx
        .sensor_key_override
        .clone()
        .or_else(|| ctx.deployment_sensor_key.clone())
        .or_else(|| ctx.provisioning_sensor_key.clone())
        .or_else(|| {
            ctx.provisioning_identity.as_deref().map(|identity| {
                derive_provisioned_sensor_key(identity, observed_property_key, env.sensor_channel)
            })
        })
        .ok_or_else(|| AdapterError::MissingSensorIdentity {
            pod_id: fact.pod_id.to_string(),
            observed_property_key,
            sensor_channel: env.sensor_channel,
        })?;

    Ok(EnvObservationProjectionInput {
        pod_id: fact.pod_id.to_string(),
        site_id: ctx.site_id.clone(),
        sensor_key,
        observed_property_key: observed_property_key.to_owned(),
        stream_key: if env.value.is_some() {
            "raw".to_owned()
        } else {
            "summary".to_owned()
        },
        phenomenon_time_start_rfc3339_utc: unix_to_rfc3339(env.phenomenon_time_start),
        phenomenon_time_end_rfc3339_utc: unix_to_rfc3339(env.phenomenon_time_end),
        result_time_rfc3339_utc: unix_to_rfc3339(fact.ingest_time),
        result: match env.value {
            Some(value) => ObservationResult::Scalar(f64::from(value)),
            None => ObservationResult::Structured(json!({
                "min": env.min,
                "max": env.max,
                "mean": env.mean,
                "count": env.count,
                "quality": env.quality,
                "sensor_channel": env.sensor_channel,
            })),
        },
    })
}

pub fn project_fact_env_observation(
    fact: &Fact,
    ctx: &EnvObservationAdapterContext,
) -> Result<EnvObservationProjection, AdapterError> {
    let input = adapt_env_fact_input(fact, ctx)?;
    Ok(project_env_observation(&input)?)
}

fn unix_to_rfc3339(value: i64) -> String {
    format_rfc3339_utc(value)
}

fn observed_property_key(sample_type: SampleType) -> &'static str {
    match sample_type {
        SampleType::AmbientAirTemperature => "temperature_air",
        SampleType::AmbientRelativeHumidity => "relative_humidity",
        SampleType::InterfaceTemperature => "temperature_interface",
        SampleType::CoverageCapacitance => "coverage_capacitance",
        SampleType::BioImpedanceMagnitude => "bioimpedance_magnitude",
        SampleType::BioImpedanceActivity => "bioimpedance_activity",
        SampleType::SupplyVoltage => "supply_voltage",
        SampleType::BatterySoc => "battery_soc",
        SampleType::FloodContact => "flood_contact",
        SampleType::LinkQuality => "link_quality",
        SampleType::Custom => "custom",
    }
}

fn derive_provisioned_sensor_key(
    identity: &str,
    observed_property_key: &str,
    sensor_channel: Option<u8>,
) -> String {
    let digest = sha256_hex(identity.as_bytes());
    let fingerprint = &digest[..16];
    let suffix = match sensor_channel {
        Some(channel) => format!("ch{channel}"),
        None => observed_property_key.replace('_', "-"),
    };
    format!("prov-{fingerprint}-{suffix}")
}

#[cfg(test)]
mod tests {
    use trackone_core::{EnvFact, Fact, FactKind, FactPayload, PodId, SampleType};

    use super::{
        EnvObservationAdapterContext, adapt_env_fact_input, derive_provisioned_sensor_key,
        project_fact_env_observation,
    };

    #[test]
    fn adapts_instant_fact() {
        let fact = Fact {
            pod_id: PodId::from(7u32),
            fc: 1,
            ingest_time: 1_709_251_501,
            pod_time: None,
            kind: FactKind::Env,
            payload: FactPayload::Env(EnvFact::instant(
                SampleType::AmbientAirTemperature,
                1_709_251_500,
                21.5,
            )),
        };

        let input = adapt_env_fact_input(
            &fact,
            &EnvObservationAdapterContext {
                site_id: Some("site-a".to_owned()),
                sensor_key_override: Some("shtc3-ambient".to_owned()),
                deployment_sensor_key: None,
                provisioning_sensor_key: None,
                provisioning_identity: None,
            },
        )
        .expect("adapter should succeed");

        assert_eq!(input.pod_id, "0000000000000007");
        assert_eq!(input.observed_property_key, "temperature_air");
        assert_eq!(input.stream_key, "raw");
        assert_eq!(
            input.phenomenon_time_start_rfc3339_utc,
            "2024-03-01T00:05:00Z"
        );
    }

    #[test]
    fn projects_summary_fact() {
        let fact = Fact {
            pod_id: PodId::from(9u32),
            fc: 2,
            ingest_time: 1_709_251_860,
            pod_time: None,
            kind: FactKind::Env,
            payload: FactPayload::Env(EnvFact::summary(
                SampleType::AmbientRelativeHumidity,
                1_709_251_500,
                1_709_251_800,
                40.0,
                45.0,
                42.0,
                4,
            )),
        };

        let projection = project_fact_env_observation(
            &fact,
            &EnvObservationAdapterContext {
                site_id: None,
                sensor_key_override: None,
                deployment_sensor_key: Some("shtc3-rh".to_owned()),
                provisioning_sensor_key: None,
                provisioning_identity: None,
            },
        )
        .expect("projection should succeed");

        assert_eq!(projection.thing.pod_id, "0000000000000009");
        assert_eq!(projection.datastream.stream_key, "summary");
    }

    #[test]
    fn prefers_provisioning_sensor_key_when_present() {
        let fact = Fact {
            pod_id: PodId::from(11u32),
            fc: 3,
            ingest_time: 1_709_251_860,
            pod_time: None,
            kind: FactKind::Env,
            payload: FactPayload::Env(EnvFact::instant(
                SampleType::AmbientAirTemperature,
                1_709_251_800,
                19.5,
            )),
        };

        let input = adapt_env_fact_input(
            &fact,
            &EnvObservationAdapterContext {
                site_id: None,
                sensor_key_override: None,
                deployment_sensor_key: None,
                provisioning_sensor_key: Some("shtc3-ambient".to_owned()),
                provisioning_identity: None,
            },
        )
        .expect("adapter should succeed");

        assert_eq!(input.sensor_key, "shtc3-ambient");
    }

    #[test]
    fn derives_sensor_key_from_provisioning_identity() {
        let fact = Fact {
            pod_id: PodId::from(12u32),
            fc: 4,
            ingest_time: 1_709_251_860,
            pod_time: None,
            kind: FactKind::Env,
            payload: FactPayload::Env(EnvFact::instant(
                SampleType::AmbientAirTemperature,
                1_709_251_800,
                20.0,
            )),
        };

        let input = adapt_env_fact_input(
            &fact,
            &EnvObservationAdapterContext {
                site_id: None,
                sensor_key_override: None,
                deployment_sensor_key: None,
                provisioning_sensor_key: None,
                provisioning_identity: Some("ed25519-pubkey-pod-012".to_owned()),
            },
        )
        .expect("adapter should succeed");

        assert_eq!(
            input.sensor_key,
            derive_provisioned_sensor_key("ed25519-pubkey-pod-012", "temperature_air", None)
        );
    }

    #[test]
    fn rejects_missing_sensor_identity() {
        let fact = Fact {
            pod_id: PodId::from(13u32),
            fc: 5,
            ingest_time: 1_709_251_860,
            pod_time: None,
            kind: FactKind::Env,
            payload: FactPayload::Env(EnvFact::instant(
                SampleType::AmbientAirTemperature,
                1_709_251_800,
                20.5,
            )),
        };

        let err = adapt_env_fact_input(&fact, &EnvObservationAdapterContext::default())
            .expect_err("missing identity should fail");

        match err {
            super::AdapterError::MissingSensorIdentity {
                pod_id,
                observed_property_key,
                sensor_channel,
            } => {
                assert_eq!(pod_id, "000000000000000d");
                assert_eq!(observed_property_key, "temperature_air");
                assert_eq!(sensor_channel, None);
            }
            other => panic!("unexpected error: {other}"),
        }
    }
}
