use serde::Serialize;
use serde_json::{Map, Value};

use crate::{Error, Result};

/// Canonicalize a JSON `Value` by sorting object keys recursively.
///
/// This is the JSON projection/helper surface for commitment artifacts.
/// Under ADR-039, authoritative commitment bytes are CBOR; these helpers keep
/// JSON projections deterministic and stable where JSON views are still needed.
///
/// JSON projection encoding:
/// - UTF-8 JSON bytes
/// - sorted keys at all nesting levels
/// - compact separators (no whitespace)
pub fn canonicalize_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();

            let mut out = Map::new();
            for k in keys {
                let v = map.get(k).expect("key exists");
                out.insert(k.clone(), canonicalize_value(v));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_value).collect()),
        other => other.clone(),
    }
}

/// Deterministic canonical JSON bytes for a projection/helper `Value`.
pub fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    let canonical = canonicalize_value(value);
    serde_json::to_vec(&canonical).expect("Value -> JSON is infallible")
}

/// Parse JSON bytes and return deterministic canonical JSON projection bytes.
pub fn canonicalize_json_bytes(input: &[u8]) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(input)?;
    Ok(canonical_json_bytes(&value))
}

/// Convert a serializable structure into deterministic canonical JSON projection bytes.
pub fn canonicalize_serialize<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let json = serde_json::to_value(value).map_err(Error::Json)?;
    Ok(canonical_json_bytes(&json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_recursively() {
        let v = json!({
            "b": 1,
            "a": { "d": 2, "c": 3 },
            "arr": [{ "z": 1, "y": 2 }]
        });

        let got = String::from_utf8(canonical_json_bytes(&v)).expect("utf-8");
        assert_eq!(got, r#"{"a":{"c":3,"d":2},"arr":[{"y":2,"z":1}],"b":1}"#);
    }

    #[test]
    fn canonicalize_json_bytes_roundtrip() {
        let input = br#"{ "b": 1, "a": 2 }"#;
        let got = canonicalize_json_bytes(input).expect("canonicalize");
        assert_eq!(got, br#"{"a":2,"b":1}"#);
    }
}
