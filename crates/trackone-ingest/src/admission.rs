//! Gateway admission results, rejection audit, and framed decryption.

use core::fmt;

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::string::String;
#[cfg(feature = "std")]
use trackone_ledger::sha256_hex;

#[cfg(feature = "xchacha")]
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
#[cfg(feature = "xchacha")]
use std::vec::Vec;
#[cfg(feature = "xchacha")]
use trackone_core::AEAD_TAG_LEN;

#[cfg(feature = "xchacha")]
use crate::FramedNonceError;
#[cfg(feature = "xchacha")]
use crate::{
    AcceptedFrame, DeviceMaterial, FrameInput, FramedFactBindingError, MAX_FRAME_CIPHERTEXT_BYTES,
    decode_fact_postcard, framed_aad, validate_fact_binding, validate_nonce_prefix,
};

/// Rejection reasons produced by framed admission and replay checks.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RejectReason {
    Salt8Length,
    CkUpLength,
    NonceLength,
    TagLength,
    EmptyCiphertext,
    CiphertextTooLarge,
    NonceSaltMismatch,
    NonceFcMismatch,
    UnsupportedFlags,
    DecryptFailed,
    InvalidIngestProfile,
    PayloadDeviceIdMismatch,
    PayloadFcMismatch,
    Duplicate,
    OutOfWindow,
    ContinuityBreak,
    ResyncRequired,
}

impl RejectReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Salt8Length => "salt8_length",
            Self::CkUpLength => "ck_up_length",
            Self::NonceLength => "nonce_length",
            Self::TagLength => "tag_length",
            Self::EmptyCiphertext => "empty_ciphertext",
            Self::CiphertextTooLarge => "ciphertext_too_large",
            Self::NonceSaltMismatch => "nonce_salt_mismatch",
            Self::NonceFcMismatch => "nonce_fc_mismatch",
            Self::UnsupportedFlags => "unsupported_flags",
            Self::DecryptFailed => "decrypt_failed",
            Self::InvalidIngestProfile => "invalid_ingest_profile",
            Self::PayloadDeviceIdMismatch => "payload_device_id_mismatch",
            Self::PayloadFcMismatch => "payload_fc_mismatch",
            Self::Duplicate => "duplicate",
            Self::OutOfWindow => "out_of_window",
            Self::ContinuityBreak => "continuity_break",
            Self::ResyncRequired => "resync_required",
        }
    }
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Source bucket for rejected framed input in the operator-audit contract.
#[cfg(feature = "std")]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RejectionSource {
    Parse,
    Decrypt,
    Replay,
}

#[cfg(feature = "std")]
impl RejectionSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::Decrypt => "decrypt",
            Self::Replay => "replay",
        }
    }
}

#[cfg(feature = "std")]
impl fmt::Display for RejectionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Additive-only rejection-audit shape from ADR-058.
#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectionRecord {
    pub device_id: String,
    pub fc: Option<u64>,
    pub reason: String,
    pub observed_at_utc: String,
    pub frame_sha256: String,
    pub source: String,
}

#[cfg(feature = "std")]
impl RejectionRecord {
    pub fn new(
        device_id: impl Into<String>,
        fc: Option<u64>,
        reason: impl Into<String>,
        observed_at_utc: impl Into<String>,
        frame_sha256: impl Into<String>,
        source: RejectionSource,
    ) -> Result<Self, RejectionAuditError> {
        let record = Self {
            device_id: device_id.into(),
            fc,
            reason: reason.into(),
            observed_at_utc: observed_at_utc.into(),
            frame_sha256: frame_sha256.into(),
            source: source.as_str().to_string(),
        };
        validate_rejection_record(&record)?;
        Ok(record)
    }
}

/// Stable accepted-frame state update shape from ADR-058.
#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionStateUpdate {
    pub device_key: String,
    pub highest_fc_seen: u64,
    pub last_seen: String,
    pub msg_type: u8,
    pub flags: u8,
}

#[cfg(feature = "std")]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RejectionAuditError {
    UnknownSource,
    UnknownReason,
    InvalidFrameHash,
}

#[cfg(feature = "std")]
impl fmt::Display for RejectionAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSource => f.write_str("unknown rejection source"),
            Self::UnknownReason => f.write_str("unknown rejection reason"),
            Self::InvalidFrameHash => f.write_str("invalid rejection frame hash"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RejectionAuditError {}

#[cfg(feature = "std")]
pub const REJECTION_SOURCES: &[&str] = &["parse", "decrypt", "replay"];

#[cfg(feature = "std")]
pub const REJECTION_REASONS: &[&str] = &[
    "line_too_long",
    "invalid_json",
    "not_dict",
    "missing_frame_fields",
    "unexpected_frame_fields",
    "invalid_hdr",
    "invalid_frame_types",
    "missing_hdr_fields",
    "unexpected_hdr_fields",
    "invalid_hdr_types",
    "dev_id_range",
    "msg_type_range",
    "fc_range",
    "flags_range",
    "invalid_ingest_profile",
    "unsupported_flags",
    "unknown_device",
    "missing_salt8",
    "invalid_base64",
    "salt8_length",
    "ck_up_length",
    "nonce_length",
    "tag_length",
    "empty_ciphertext",
    "ciphertext_too_large",
    "nonce_salt_mismatch",
    "nonce_fc_mismatch",
    "decrypt_failed",
    "payload_device_id_mismatch",
    "payload_fc_mismatch",
    "duplicate",
    "out_of_window",
    "continuity_break",
    "resync_required",
];

#[cfg(feature = "std")]
pub fn hash_rejected_line(raw_line: &str) -> String {
    sha256_hex(raw_line.trim_end_matches(['\r', '\n']).as_bytes())
}

#[cfg(feature = "std")]
pub fn validate_rejection_record(record: &RejectionRecord) -> Result<(), RejectionAuditError> {
    if !REJECTION_SOURCES.contains(&record.source.as_str()) {
        return Err(RejectionAuditError::UnknownSource);
    }
    if !REJECTION_REASONS.contains(&record.reason.as_str()) {
        return Err(RejectionAuditError::UnknownReason);
    }
    if record.frame_sha256.len() != 64
        || !record
            .frame_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(RejectionAuditError::InvalidFrameHash);
    }
    Ok(())
}

#[cfg(feature = "xchacha")]
pub fn validate_and_decrypt(
    frame: FrameInput<'_>,
    device: DeviceMaterial<'_>,
) -> Result<AcceptedFrame, RejectReason> {
    if frame.tag.len() != AEAD_TAG_LEN {
        return Err(RejectReason::TagLength);
    }
    if device.ck_up.len() != 32 {
        return Err(RejectReason::CkUpLength);
    }
    if frame.ct.is_empty() {
        return Err(RejectReason::EmptyCiphertext);
    }
    if frame.ct.len() > MAX_FRAME_CIPHERTEXT_BYTES {
        return Err(RejectReason::CiphertextTooLarge);
    }
    if frame.header.flags != 0 {
        return Err(RejectReason::UnsupportedFlags);
    }
    validate_nonce_prefix(frame.nonce, device.salt8, frame.header.fc)
        .map_err(map_framed_nonce_error)?;

    let aad = framed_aad(
        frame.header.dev_id,
        frame.header.msg_type,
        frame.header.flags,
    );
    let mut combined = Vec::with_capacity(frame.ct.len() + frame.tag.len());
    combined.extend_from_slice(frame.ct);
    combined.extend_from_slice(frame.tag);

    let cipher =
        XChaCha20Poly1305::new_from_slice(device.ck_up).map_err(|_| RejectReason::CkUpLength)?;
    let nonce = frame
        .nonce
        .try_into()
        .map_err(|_| RejectReason::NonceLength)?;
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: combined.as_slice(),
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| RejectReason::DecryptFailed)?;

    let fact = decode_fact_postcard(&plaintext).map_err(|_| RejectReason::DecryptFailed)?;
    validate_fact_binding(&fact, frame.header.dev_id, frame.header.fc).map_err(|reason| {
        match reason {
            FramedFactBindingError::PodIdMismatch => RejectReason::PayloadDeviceIdMismatch,
            FramedFactBindingError::FrameCounterMismatch => RejectReason::PayloadFcMismatch,
        }
    })?;

    Ok(AcceptedFrame {
        header: frame.header,
        fact,
    })
}

#[cfg(feature = "xchacha")]
fn map_framed_nonce_error(reason: FramedNonceError) -> RejectReason {
    match reason {
        FramedNonceError::NonceLength => RejectReason::NonceLength,
        FramedNonceError::Salt8Length => RejectReason::Salt8Length,
        FramedNonceError::SaltMismatch => RejectReason::NonceSaltMismatch,
        FramedNonceError::FrameCounterMismatch => RejectReason::NonceFcMismatch,
    }
}
