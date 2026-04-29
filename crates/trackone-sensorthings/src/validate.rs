use std::error::Error;
use std::fmt::{Display, Formatter};

use super::mapping::EnvObservationProjectionInput;
use super::timefmt::{Timestamp, format_rfc3339_utc, parse_rfc3339_timestamp};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidationError {
    MissingField(&'static str),
    InvalidRfc3339(&'static str),
    InvalidTimeRange,
}

impl Display for ValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "missing required field: {field}"),
            Self::InvalidRfc3339(field) => write!(f, "invalid RFC3339 UTC timestamp: {field}"),
            Self::InvalidTimeRange => write!(f, "phenomenon time end must not be before start"),
        }
    }
}

impl Error for ValidationError {}

pub fn validate_env_observation_input(
    input: &EnvObservationProjectionInput,
) -> Result<(), ValidationError> {
    require_field("pod_id", &input.pod_id)?;
    require_field("sensor_key", &input.sensor_key)?;
    require_field("observed_property_key", &input.observed_property_key)?;
    require_field("stream_key", &input.stream_key)?;
    require_field(
        "phenomenon_time_start_rfc3339_utc",
        &input.phenomenon_time_start_rfc3339_utc,
    )?;
    require_field(
        "phenomenon_time_end_rfc3339_utc",
        &input.phenomenon_time_end_rfc3339_utc,
    )?;
    require_field("result_time_rfc3339_utc", &input.result_time_rfc3339_utc)?;

    let phenomenon_start = parse_rfc3339_utc(
        "phenomenon_time_start_rfc3339_utc",
        &input.phenomenon_time_start_rfc3339_utc,
    )?;
    let phenomenon_end = parse_rfc3339_utc(
        "phenomenon_time_end_rfc3339_utc",
        &input.phenomenon_time_end_rfc3339_utc,
    )?;
    let _result_time =
        parse_rfc3339_utc("result_time_rfc3339_utc", &input.result_time_rfc3339_utc)?;

    if phenomenon_end < phenomenon_start {
        return Err(ValidationError::InvalidTimeRange);
    }

    Ok(())
}

fn require_field(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        return Err(ValidationError::MissingField(field));
    }
    Ok(())
}

fn parse_rfc3339_utc(field: &'static str, value: &str) -> Result<Timestamp, ValidationError> {
    let timestamp =
        parse_rfc3339_timestamp(value).map_err(|_| ValidationError::InvalidRfc3339(field))?;
    if format_rfc3339_utc(timestamp.unix_seconds) != value {
        return Err(ValidationError::InvalidRfc3339(field));
    }
    Ok(timestamp)
}

#[cfg(test)]
mod tests {
    use super::{ValidationError, validate_env_observation_input};
    use crate::mapping::{EnvObservationProjectionInput, ObservationResult};

    #[test]
    fn rejects_empty_fields() {
        let input = EnvObservationProjectionInput {
            pod_id: String::new(),
            site_id: None,
            sensor_key: "shtc3".to_owned(),
            observed_property_key: "temperature_air".to_owned(),
            stream_key: "raw".to_owned(),
            phenomenon_time_start_rfc3339_utc: "2026-03-06T00:00:00Z".to_owned(),
            phenomenon_time_end_rfc3339_utc: "2026-03-06T00:05:00Z".to_owned(),
            result_time_rfc3339_utc: "2026-03-06T00:05:01Z".to_owned(),
            result: ObservationResult::Scalar(21.5),
        };
        assert_eq!(
            validate_env_observation_input(&input),
            Err(ValidationError::MissingField("pod_id"))
        );
    }

    #[test]
    fn rejects_invalid_rfc3339() {
        let input = EnvObservationProjectionInput {
            pod_id: "0000000000000007".to_owned(),
            site_id: None,
            sensor_key: "shtc3".to_owned(),
            observed_property_key: "temperature_air".to_owned(),
            stream_key: "raw".to_owned(),
            phenomenon_time_start_rfc3339_utc: "2026-03-06 00:00:00".to_owned(),
            phenomenon_time_end_rfc3339_utc: "2026-03-06T00:05:00Z".to_owned(),
            result_time_rfc3339_utc: "2026-03-06T00:05:01Z".to_owned(),
            result: ObservationResult::Scalar(21.5),
        };
        assert_eq!(
            validate_env_observation_input(&input),
            Err(ValidationError::InvalidRfc3339(
                "phenomenon_time_start_rfc3339_utc"
            ))
        );
    }

    #[test]
    fn rejects_non_canonical_utc_offset_timestamp() {
        let input = EnvObservationProjectionInput {
            pod_id: "0000000000000007".to_owned(),
            site_id: None,
            sensor_key: "shtc3".to_owned(),
            observed_property_key: "temperature_air".to_owned(),
            stream_key: "raw".to_owned(),
            phenomenon_time_start_rfc3339_utc: "2026-03-06T01:00:00+01:00".to_owned(),
            phenomenon_time_end_rfc3339_utc: "2026-03-06T00:05:00Z".to_owned(),
            result_time_rfc3339_utc: "2026-03-06T00:05:01Z".to_owned(),
            result: ObservationResult::Scalar(21.5),
        };
        assert_eq!(
            validate_env_observation_input(&input),
            Err(ValidationError::InvalidRfc3339(
                "phenomenon_time_start_rfc3339_utc"
            ))
        );
    }

    #[test]
    fn rejects_non_canonical_fractional_seconds() {
        let input = EnvObservationProjectionInput {
            pod_id: "0000000000000007".to_owned(),
            site_id: None,
            sensor_key: "shtc3".to_owned(),
            observed_property_key: "temperature_air".to_owned(),
            stream_key: "raw".to_owned(),
            phenomenon_time_start_rfc3339_utc: "2026-03-06T00:00:00.000Z".to_owned(),
            phenomenon_time_end_rfc3339_utc: "2026-03-06T00:05:00Z".to_owned(),
            result_time_rfc3339_utc: "2026-03-06T00:05:01Z".to_owned(),
            result: ObservationResult::Scalar(21.5),
        };
        assert_eq!(
            validate_env_observation_input(&input),
            Err(ValidationError::InvalidRfc3339(
                "phenomenon_time_start_rfc3339_utc"
            ))
        );
    }

    #[test]
    fn rejects_reverse_time_range_after_parsing() {
        let input = EnvObservationProjectionInput {
            pod_id: "0000000000000007".to_owned(),
            site_id: None,
            sensor_key: "shtc3".to_owned(),
            observed_property_key: "temperature_air".to_owned(),
            stream_key: "raw".to_owned(),
            phenomenon_time_start_rfc3339_utc: "2026-03-06T00:05:00Z".to_owned(),
            phenomenon_time_end_rfc3339_utc: "2026-03-06T00:00:00Z".to_owned(),
            result_time_rfc3339_utc: "2026-03-06T00:05:01Z".to_owned(),
            result: ObservationResult::Scalar(21.5),
        };
        assert_eq!(
            validate_env_observation_input(&input),
            Err(ValidationError::InvalidTimeRange)
        );
    }
}
