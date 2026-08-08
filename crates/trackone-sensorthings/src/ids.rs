use trackone_ledger::sha256_hex;

const ENTITY_ID_DOMAIN: &[u8] = b"trackone:sensorthings:entity-id:v2";

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
    append_length_prefixed(&mut material, ENTITY_ID_DOMAIN);
    append_length_prefixed(&mut material, kind.prefix().as_bytes());
    material.extend_from_slice(&(components.len() as u64).to_be_bytes());
    for component in components {
        append_length_prefixed(&mut material, component.as_bytes());
    }
    format!("trackone:{}:{}", kind.prefix(), sha256_hex(&material))
}

fn append_length_prefixed(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
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
            "trackone:datastream:b83c0189580700a4088ad0c101b7aa1978d7b3ddba0a2549307e7d40f89f3974"
        );
    }

    #[test]
    fn component_boundaries_cannot_collide() {
        let left = entity_id(
            SensorThingsEntityKind::Datastream,
            &["pod-01", "env\u{1f}temperature"],
        );
        let right = entity_id(
            SensorThingsEntityKind::Datastream,
            &["pod-01\u{1f}env", "temperature"],
        );
        assert_ne!(left, right);
    }

    #[test]
    fn entity_kind_is_domain_separated() {
        assert_ne!(
            entity_id(SensorThingsEntityKind::Thing, &["same"]),
            entity_id(SensorThingsEntityKind::Sensor, &["same"])
        );
    }
}
