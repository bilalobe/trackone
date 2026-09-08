//! Producer-manifest data model and duplicate-key-safe JSON decoding.

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArtifactRef {
    pub(super) path: String,
    pub(super) sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordBatchOpening {
    pub(super) batch_number: String,
    pub(super) records: Vec<ArtifactRef>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Artifacts {
    pub(super) segment_cbor: ArtifactRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) predecessor_segment_cbor: Option<ArtifactRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) record_batches: Option<Vec<RecordBatchOpening>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) tsa_req: Option<ArtifactRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) tsa_tsr: Option<ArtifactRef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) extensions: BTreeMap<String, ArtifactRef>,
}

impl Artifacts {
    pub(super) fn references(&self, include_extensions: bool) -> Vec<&ArtifactRef> {
        let mut references = vec![&self.segment_cbor];
        references.extend(self.predecessor_segment_cbor.iter());
        for opening in self.record_batches.iter().flatten() {
            references.extend(&opening.records);
        }
        references.extend(self.tsa_req.iter());
        references.extend(self.tsa_tsr.iter());
        if include_extensions {
            references.extend(self.extensions.values());
        }
        references
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProducerTsaState {
    pub(super) status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Anchoring {
    pub(super) tsa: ProducerTsaState,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub(super) version: u8,
    pub(super) ledger_id: String,
    pub(super) segment_number: String,
    pub(super) commitment_profile_id: String,
    pub(super) disclosure_class: String,
    pub(super) artifacts: Artifacts,
    pub(super) anchoring: Anchoring,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) extensions: Option<BTreeMap<String, Value>>,
}

pub(super) struct NoDuplicateJson(pub(super) Value);

impl<'de> Deserialize<'de> for NoDuplicateJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = NoDuplicateJson;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON value without duplicate object names")
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Self::Value, E> {
                Ok(NoDuplicateJson(Value::Bool(value)))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Self::Value, E> {
                Ok(NoDuplicateJson(value.into()))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Self::Value, E> {
                Ok(NoDuplicateJson(value.into()))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .map(NoDuplicateJson)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
                Ok(NoDuplicateJson(Value::String(value.to_string())))
            }
            fn visit_string<E: de::Error>(
                self,
                value: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(NoDuplicateJson(Value::String(value)))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(NoDuplicateJson(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(NoDuplicateJson(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<NoDuplicateJson>()? {
                    values.push(value.0);
                }
                Ok(NoDuplicateJson(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom(format!("duplicate JSON member {key:?}")));
                    }
                    values.insert(key, map.next_value::<NoDuplicateJson>()?.0);
                }
                Ok(NoDuplicateJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(JsonVisitor)
    }
}
