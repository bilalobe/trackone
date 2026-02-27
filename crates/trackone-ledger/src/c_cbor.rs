use serde::Serialize;
use serde_json::Value;

use crate::{Error, Result};

fn major_u64(buf: &mut Vec<u8>, major: u8, n: u64) {
    if n < 24 {
        buf.push((major << 5) | (n as u8));
    } else if u8::try_from(n).is_ok() {
        buf.push((major << 5) | 24);
        buf.push(n as u8);
    } else if u16::try_from(n).is_ok() {
        buf.push((major << 5) | 25);
        buf.extend_from_slice(&(n as u16).to_be_bytes());
    } else if u32::try_from(n).is_ok() {
        buf.push((major << 5) | 26);
        buf.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        buf.push((major << 5) | 27);
        buf.extend_from_slice(&n.to_be_bytes());
    }
}

fn cbor_uint(buf: &mut Vec<u8>, n: u64) {
    major_u64(buf, 0, n);
}

fn cbor_nint(buf: &mut Vec<u8>, n: i64) {
    debug_assert!(n < 0);
    let m = (-1i128 - (n as i128)) as u64;
    major_u64(buf, 1, m);
}

fn cbor_i64(buf: &mut Vec<u8>, n: i64) {
    if n >= 0 {
        cbor_uint(buf, n as u64);
    } else {
        cbor_nint(buf, n);
    }
}

fn cbor_f64(buf: &mut Vec<u8>, n: f64) -> Result<()> {
    if !n.is_finite() {
        return Err(Error::NonFiniteFloat);
    }
    buf.push(0xFB); // float64
    buf.extend_from_slice(&n.to_bits().to_be_bytes());
    Ok(())
}

fn cbor_text(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    major_u64(buf, 3, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

fn cbor_array_len(buf: &mut Vec<u8>, n: usize) {
    major_u64(buf, 4, n as u64);
}

fn cbor_map_len(buf: &mut Vec<u8>, n: usize) {
    major_u64(buf, 5, n as u64);
}

fn encode_value(buf: &mut Vec<u8>, value: &Value) -> Result<()> {
    match value {
        Value::Null => {
            buf.push(0xF6);
            Ok(())
        }
        Value::Bool(false) => {
            buf.push(0xF4);
            Ok(())
        }
        Value::Bool(true) => {
            buf.push(0xF5);
            Ok(())
        }
        Value::Number(num) => {
            if let Some(u) = num.as_u64() {
                cbor_uint(buf, u);
                return Ok(());
            }
            if let Some(i) = num.as_i64() {
                cbor_i64(buf, i);
                return Ok(());
            }
            if let Some(f) = num.as_f64() {
                return cbor_f64(buf, f);
            }
            Err(Error::UnsupportedNumber)
        }
        Value::String(s) => {
            cbor_text(buf, s);
            Ok(())
        }
        Value::Array(items) => {
            cbor_array_len(buf, items.len());
            for item in items {
                encode_value(buf, item)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            // JSON objects restrict map keys to text strings.
            // For deterministic ordering (RFC 8949 Section 4.2.1), sort by:
            // 1) encoded key length, 2) lexicographic encoded key bytes.
            // For text-only keys this is equivalent to utf-8 length then bytes.
            keys.sort_by(|a, b| {
                let a_bytes = a.as_bytes();
                let b_bytes = b.as_bytes();
                a_bytes
                    .len()
                    .cmp(&b_bytes.len())
                    .then_with(|| a_bytes.cmp(b_bytes))
            });
            cbor_map_len(buf, keys.len());
            for key in keys {
                cbor_text(buf, key);
                let item = map.get(key).expect("key exists");
                encode_value(buf, item)?;
            }
            Ok(())
        }
    }
}

/// Deterministic CBOR bytes from a JSON `Value`.
pub fn canonical_cbor_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encode_value(&mut out, value)?;
    Ok(out)
}

/// Parse JSON bytes and return deterministic CBOR bytes.
pub fn canonicalize_json_bytes_to_cbor(input: &[u8]) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(input)?;
    canonical_cbor_bytes(&value)
}

/// Convert a serializable structure into deterministic CBOR bytes.
pub fn canonicalize_serialize_to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let json = serde_json::to_value(value).map_err(Error::Json)?;
    canonical_cbor_bytes(&json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cbor_encoding_is_stable_with_reordered_json_keys() {
        let a = json!({
            "b": 2,
            "a": {"y": 2, "x": 1},
            "arr": [3, 1, 2],
        });
        let b = json!({
            "arr": [3, 1, 2],
            "a": {"x": 1, "y": 2},
            "b": 2,
        });
        let ca = canonical_cbor_bytes(&a).expect("cbor");
        let cb = canonical_cbor_bytes(&b).expect("cbor");
        assert_eq!(ca, cb);
    }

    #[test]
    fn cbor_uses_small_int_for_json_integer() {
        let v = json!({"n": 10});
        let cbor = canonical_cbor_bytes(&v).expect("cbor");
        assert!(cbor.windows(2).any(|w| w == [0x61, b'n']));
        assert!(cbor.contains(&0x0A));
    }

    #[test]
    fn cbor_text_map_keys_are_sorted_by_len_then_bytes() {
        let v = json!({
            "aa": 1,
            "b": 2,
        });
        let cbor = canonical_cbor_bytes(&v).expect("cbor");
        // a2            # map(2)
        //   61 62       # "b"
        //   02          # 2
        //   62 61 61    # "aa"
        //   01          # 1
        assert_eq!(cbor, vec![0xA2, 0x61, b'b', 0x02, 0x62, b'a', b'a', 0x01]);
    }
}
