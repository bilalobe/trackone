use serde_json::Value;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeInterval {
    pub start_rfc3339_utc: String,
    pub end_rfc3339_utc: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorThingsThing {
    pub id: String,
    pub pod_id: String,
    pub site_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorThingsDatastream {
    pub id: String,
    pub thing_id: String,
    pub sensor_id: String,
    pub observed_property_id: String,
    pub stream_key: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ObservationPayload {
    Scalar(f64),
    Structured(Value),
}

#[derive(Clone, Debug, PartialEq)]
pub struct SensorThingsObservation {
    pub id: String,
    pub datastream_id: String,
    pub phenomenon_time: TimeInterval,
    pub result_time_rfc3339_utc: String,
    pub result: ObservationPayload,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorThingsEntityIds {
    pub thing_id: String,
    pub sensor_id: String,
    pub observed_property_id: String,
    pub datastream_id: String,
    pub observation_id: String,
}
