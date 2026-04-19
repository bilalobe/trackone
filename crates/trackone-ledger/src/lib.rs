#![cfg_attr(not(debug_assertions), deny(warnings))]

use sha2::{Digest, Sha256};

// Keep externally-stable module names while using shorter filenames.
#[path = "c_cbor.rs"]
pub mod canonical_cbor;
#[path = "c_json.rs"]
pub mod canonical_json;
pub mod merkle;
pub mod types;

/// Ledger-level errors.
#[derive(Debug)]
pub enum Error {
    Json(serde_json::Error),
    NonFiniteFloat,
    UnsupportedNumber,
    InvalidHexLength { expected: usize, actual: usize },
    InvalidHexCharacter { index: usize, byte: u8 },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Json(e) => write!(f, "json error: {e}"),
            Error::NonFiniteFloat => write!(f, "non-finite float not allowed"),
            Error::UnsupportedNumber => write!(f, "unsupported JSON number representation"),
            Error::InvalidHexLength { expected, actual } => {
                write!(f, "invalid hex length: expected {expected}, got {actual}")
            }
            Error::InvalidHexCharacter { index, byte } => {
                write!(f, "invalid hex character at index {index}: 0x{byte:02x}")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256_digest(data);
    hex_lower(&digest)
}

pub fn normalize_hex64(value: &str) -> Result<String> {
    if value.len() != 64 {
        return Err(Error::InvalidHexLength {
            expected: 64,
            actual: value.len(),
        });
    }

    let mut out = String::with_capacity(64);
    for (index, byte) in value.bytes().enumerate() {
        let normalized = match byte {
            b'0'..=b'9' | b'a'..=b'f' => byte,
            b'A'..=b'F' => byte.to_ascii_lowercase(),
            _ => return Err(Error::InvalidHexCharacter { index, byte }),
        };
        out.push(normalized as char);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{Error, normalize_hex64, sha256_hex};

    #[test]
    fn sha256_hex_matches_known_value() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn normalize_hex64_accepts_lowercase() {
        let value = "a".repeat(64);
        assert_eq!(normalize_hex64(&value).unwrap(), value);
    }

    #[test]
    fn normalize_hex64_canonicalizes_uppercase() {
        assert_eq!(normalize_hex64(&"A".repeat(64)).unwrap(), "a".repeat(64));
    }

    #[test]
    fn normalize_hex64_rejects_wrong_length() {
        let err = normalize_hex64("abcd").unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidHexLength {
                expected: 64,
                actual: 4
            }
        ));
    }

    #[test]
    fn normalize_hex64_rejects_invalid_character() {
        let err = normalize_hex64(&format!("{}z", "a".repeat(63))).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidHexCharacter {
                index: 63,
                byte: b'z'
            }
        ));
    }
}
