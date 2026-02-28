#![cfg_attr(not(debug_assertions), deny(warnings))]

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
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Json(e) => write!(f, "json error: {e}"),
            Error::NonFiniteFloat => write!(f, "non-finite float not allowed"),
            Error::UnsupportedNumber => write!(f, "unsupported JSON number representation"),
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
