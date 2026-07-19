//! Ingest profile identifiers and validation.

use crate::RejectReason;

/// Current Rust-native framed plaintext profile identifier.
pub const INGEST_PROFILE_RUST_POSTCARD_V1: &str =
    trackone_constants::INGEST_PROFILE_RUST_POSTCARD_V1;

/// Message type used by the current Rust-native framed fact path.
pub const FRAMED_FACT_MSG_TYPE: u8 = trackone_constants::FRAMED_FACT_MSG_TYPE;

/// Accept omitted profile for backward-compatible callers, or the explicit
/// Rust postcard profile. Any other profile name is unsupported.
pub fn is_supported_ingest_profile(raw: Option<&str>) -> bool {
    matches!(raw, None | Some(INGEST_PROFILE_RUST_POSTCARD_V1))
}

pub fn validate_ingest_profile(raw: Option<&str>) -> Result<(), RejectReason> {
    if is_supported_ingest_profile(raw) {
        Ok(())
    } else {
        Err(RejectReason::InvalidIngestProfile)
    }
}
