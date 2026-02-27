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

/// Returns the big-endian IEEE 754 binary16 (half-precision) encoding of `val`
/// if `val` is exactly representable as float16, otherwise `None`.
/// Precondition: `val` is finite (not NaN, not infinity).
fn try_encode_as_f16(val: f64) -> Option<[u8; 2]> {
    let bits64 = val.to_bits();
    let sign = (bits64 >> 63) as u16;
    if val == 0.0 {
        // Preserve sign of zero: +0.0 → 0x0000, -0.0 → 0x8000.
        return Some((sign << 15).to_be_bytes());
    }
    let exp64 = ((bits64 >> 52) & 0x7FF) as i32;
    let mant64 = bits64 & 0x000F_FFFF_FFFF_FFFF;
    let unbiased = exp64 - 1023; // f64 exponent bias is 1023

    // f16 normal range: unbiased in [-14, 15]; subnormal: [-24, -15].
    if !(-24..=15).contains(&unbiased) {
        return None;
    }
    let f16_bits = if unbiased >= -14 {
        // Normal f16 (biased exponent 1..=30).
        let f16_exp = (unbiased + 15) as u16;
        // f16 has 10 mantissa bits; f64 has 52.  Lower 42 bits must be zero.
        if mant64 & ((1u64 << 42) - 1) != 0 {
            return None;
        }
        let f16_mant = (mant64 >> 42) as u16;
        (sign << 15) | (f16_exp << 10) | f16_mant
    } else {
        // Subnormal f16 (biased exponent 0): unbiased in [-24, -15].
        // Include the implicit leading 1 bit.
        let full_sig = (1u64 << 52) | mant64;
        // total_shift = (f64_mant_bits - f16_mant_bits) + subnormal_shift
        //             = 42 + (-14 - unbiased) = 28 - unbiased  (in range [43, 52])
        let total_shift = (28 - unbiased) as u32;
        if full_sig & ((1u64 << total_shift) - 1) != 0 {
            return None;
        }
        let f16_mant = (full_sig >> total_shift) as u16;
        (sign << 15) | f16_mant
    };
    Some(f16_bits.to_be_bytes())
}

/// Encode a finite `f64` using the shortest CBOR float representation
/// (float16, float32, or float64) per RFC 8949 Section 4.2.1.
fn cbor_float(buf: &mut Vec<u8>, n: f64) -> Result<()> {
    if !n.is_finite() {
        return Err(Error::NonFiniteFloat);
    }
    if let Some(f16_bytes) = try_encode_as_f16(n) {
        buf.push(0xF9); // float16
        buf.extend_from_slice(&f16_bytes);
        return Ok(());
    }
    let f32_val = n as f32;
    if (f32_val as f64).to_bits() == n.to_bits() {
        buf.push(0xFA); // float32
        buf.extend_from_slice(&f32_val.to_bits().to_be_bytes());
        return Ok(());
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
                return cbor_float(buf, f);
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
    fn cbor_float_uses_shortest_representation() {
        // RFC 8949 Appendix A test vectors.

        // 1.0 fits in float16 → F9 3C 00
        assert_eq!(
            canonical_cbor_bytes(&json!(1.0_f64)).unwrap(),
            vec![0xF9, 0x3C, 0x00]
        );
        // 1.5 fits in float16 → F9 3E 00
        assert_eq!(
            canonical_cbor_bytes(&json!(1.5_f64)).unwrap(),
            vec![0xF9, 0x3E, 0x00]
        );
        // -4.0 fits in float16 → F9 C4 00
        assert_eq!(
            canonical_cbor_bytes(&json!(-4.0_f64)).unwrap(),
            vec![0xF9, 0xC4, 0x00]
        );
        // 0.00006103515625 (= 2^-14, smallest normal f16) → F9 04 00
        assert_eq!(
            canonical_cbor_bytes(&json!(0.00006103515625_f64)).unwrap(),
            vec![0xF9, 0x04, 0x00]
        );
        // 5.960464477539063e-8 (= 2^-24, smallest positive f16 subnormal) → F9 00 01
        assert_eq!(
            canonical_cbor_bytes(&json!(5.960464477539063e-8_f64)).unwrap(),
            vec![0xF9, 0x00, 0x01]
        );
        // 100000.0 fits in float32 → FA 47 C3 50 00
        assert_eq!(
            canonical_cbor_bytes(&json!(100000.0_f64)).unwrap(),
            vec![0xFA, 0x47, 0xC3, 0x50, 0x00]
        );
        // -4.1 is not exact in float32 → FB prefix (9 bytes total)
        let cbor = canonical_cbor_bytes(&json!(-4.1_f64)).unwrap();
        assert_eq!(cbor[0], 0xFB);
        assert_eq!(cbor.len(), 9);
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
