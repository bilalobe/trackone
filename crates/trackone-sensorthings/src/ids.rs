use trackone_ledger::sha256_hex;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensorThingsEntityKind {
    Thing,
    Sensor,
    ObservedProperty,
    Datastream,
    Observation,
    Location,
}

impl SensorThingsEntityKind {
    fn prefix(self) -> &'static str {
        match self {
            Self::Thing => "thing",
            Self::Sensor => "sensor",
            Self::ObservedProperty => "observed-property",
            Self::Datastream => "datastream",
            Self::Observation => "observation",
            Self::Location => "location",
        }
    }
}

pub fn entity_id(kind: SensorThingsEntityKind, components: &[&str]) -> String {
    let mut material = Vec::new();
    material.extend_from_slice(kind.prefix().as_bytes());
    for component in components {
        material.push(0x1f);
        material.extend_from_slice(component.as_bytes());
    }
    format!("trackone:{}:{}", kind.prefix(), sha256_hex(&material))
}

#[cfg(test)]
mod tests {
    use super::{SensorThingsEntityKind, entity_id};

    #[test]
    fn ids_are_stable() {
        let id = entity_id(
            SensorThingsEntityKind::Datastream,
            &["pod-01", "env", "temperature", "raw"],
        );
        assert_eq!(
            id,
            "trackone:datastream:470a3c146fd6adeec6cc507d6c778f17bee8023ceeb63dbc9520b950af219704"
        );
    }
}
