use sha2::{Digest, Sha256};

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
    let mut hasher = Sha256::new();
    hasher.update(kind.prefix().as_bytes());
    for component in components {
        hasher.update([0x1f]);
        hasher.update(component.as_bytes());
    }
    format!(
        "trackone:{}:{}",
        kind.prefix(),
        hex_lower(&hasher.finalize())
    )
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
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
