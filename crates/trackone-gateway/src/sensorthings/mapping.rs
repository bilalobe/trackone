use serde_json::Value;

use super::ids::{entity_id, SensorThingsEntityKind};
use super::timefmt::{format_rfc3339_utc, parse_rfc3339_timestamp};
use super::types::{
    ObservationPayload, SensorThingsDatastream, SensorThingsEntityIds, SensorThingsObservation,
    SensorThingsThing, TimeInterval,
};
use super::validate::{validate_env_observation_input, ValidationError};

#[derive(Clone, Debug, PartialEq)]
pub enum ObservationResult {
    Scalar(f64),
    Structured(Value),
}

#[derive(Clone, Debug, PartialEq)]
pub struct EnvObservationProjectionInput {
    pub pod_id: String,
    pub site_id: Option<String>,
    pub sensor_key: String,
    pub observed_property_key: String,
    pub stream_key: String,
    pub phenomenon_time_start_rfc3339_utc: String,
    pub phenomenon_time_end_rfc3339_utc: String,
    pub result_time_rfc3339_utc: String,
    pub result: ObservationResult,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EnvObservationProjection {
    pub ids: SensorThingsEntityIds,
    pub thing: SensorThingsThing,
    pub datastream: SensorThingsDatastream,
    pub observation: SensorThingsObservation,
}

pub fn project_env_observation(
    input: &EnvObservationProjectionInput,
) -> Result<EnvObservationProjection, ValidationError> {
    validate_env_observation_input(input)?;
    let phenomenon_time_start_rfc3339_utc = normalize_rfc3339_utc(
        "phenomenon_time_start_rfc3339_utc",
        &input.phenomenon_time_start_rfc3339_utc,
    )?;
    let phenomenon_time_end_rfc3339_utc = normalize_rfc3339_utc(
        "phenomenon_time_end_rfc3339_utc",
        &input.phenomenon_time_end_rfc3339_utc,
    )?;
    let result_time_rfc3339_utc =
        normalize_rfc3339_utc("result_time_rfc3339_utc", &input.result_time_rfc3339_utc)?;

    let thing_id = entity_id(SensorThingsEntityKind::Thing, &[&input.pod_id]);
    let sensor_id = entity_id(
        SensorThingsEntityKind::Sensor,
        &[&input.pod_id, &input.sensor_key],
    );
    let observed_property_id = entity_id(
        SensorThingsEntityKind::ObservedProperty,
        &[&input.observed_property_key],
    );
    let datastream_id = entity_id(
        SensorThingsEntityKind::Datastream,
        &[
            &input.pod_id,
            &input.sensor_key,
            &input.observed_property_key,
            &input.stream_key,
        ],
    );
    let observation_id = entity_id(
        SensorThingsEntityKind::Observation,
        &[
            &datastream_id,
            &phenomenon_time_start_rfc3339_utc,
            &phenomenon_time_end_rfc3339_utc,
            &result_time_rfc3339_utc,
        ],
    );

    let ids = SensorThingsEntityIds {
        thing_id: thing_id.clone(),
        sensor_id: sensor_id.clone(),
        observed_property_id: observed_property_id.clone(),
        datastream_id: datastream_id.clone(),
        observation_id: observation_id.clone(),
    };

    let thing = SensorThingsThing {
        id: thing_id.clone(),
        pod_id: input.pod_id.clone(),
        site_id: input.site_id.clone(),
    };

    let datastream = SensorThingsDatastream {
        id: datastream_id.clone(),
        thing_id: thing_id.clone(),
        sensor_id,
        observed_property_id,
        stream_key: input.stream_key.clone(),
    };

    let observation = SensorThingsObservation {
        id: observation_id,
        datastream_id,
        phenomenon_time: TimeInterval {
            start_rfc3339_utc: phenomenon_time_start_rfc3339_utc,
            end_rfc3339_utc: phenomenon_time_end_rfc3339_utc,
        },
        result_time_rfc3339_utc,
        result: match &input.result {
            ObservationResult::Scalar(value) => ObservationPayload::Scalar(*value),
            ObservationResult::Structured(value) => ObservationPayload::Structured(value.clone()),
        },
    };

    Ok(EnvObservationProjection {
        ids,
        thing,
        datastream,
        observation,
    })
}

fn normalize_rfc3339_utc(field: &'static str, value: &str) -> Result<String, ValidationError> {
    let timestamp =
        parse_rfc3339_timestamp(value).map_err(|_| ValidationError::InvalidRfc3339(field))?;
    Ok(format_rfc3339_utc(timestamp.unix_seconds))
}

#[cfg(test)]
mod tests {
    use super::{project_env_observation, EnvObservationProjectionInput, ObservationResult};

    #[test]
    fn projects_ids_and_observation() {
        let input = EnvObservationProjectionInput {
            pod_id: "pod-01".to_owned(),
            site_id: Some("site-a".to_owned()),
            sensor_key: "shtc3-0".to_owned(),
            observed_property_key: "temperature_air".to_owned(),
            stream_key: "raw".to_owned(),
            phenomenon_time_start_rfc3339_utc: "2026-03-06T00:00:00Z".to_owned(),
            phenomenon_time_end_rfc3339_utc: "2026-03-06T00:05:00Z".to_owned(),
            result_time_rfc3339_utc: "2026-03-06T00:05:01Z".to_owned(),
            result: ObservationResult::Scalar(21.5),
        };

        let projection = project_env_observation(&input).expect("projection should succeed");
        assert_eq!(projection.thing.pod_id, "pod-01");
        assert_eq!(projection.datastream.stream_key, "raw");
        assert_eq!(
            projection.observation.phenomenon_time.end_rfc3339_utc,
            "2026-03-06T00:05:00Z"
        );
    }
}
