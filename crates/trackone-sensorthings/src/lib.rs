#![cfg_attr(not(debug_assertions), deny(warnings))]

pub mod adapter;
pub mod ids;
pub mod mapping;
mod timefmt;
pub mod types;
pub mod validate;

pub use adapter::{
    AdapterError, EnvObservationAdapterContext, adapt_env_fact_input, project_fact_env_observation,
};
pub use ids::{SensorThingsEntityKind, entity_id};
pub use mapping::{
    EnvObservationProjection, EnvObservationProjectionInput, ObservationResult,
    project_env_observation,
};
pub use types::{
    ObservationPayload, SensorThingsDatastream, SensorThingsEntityIds, SensorThingsObservation,
    SensorThingsThing, TimeInterval,
};
pub use validate::{ValidationError, validate_env_observation_input};
