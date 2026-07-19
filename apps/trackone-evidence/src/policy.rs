//! Verification and export policy inputs and stable check identifiers.

use std::path::PathBuf;

use crate::{EvidenceError, Result};

pub const STATUS_VERIFIED: &str = "verified";
pub const STATUS_FAILED: &str = "failed";
pub const STATUS_MISSING: &str = "missing";
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_SKIPPED: &str = "skipped";

pub const CHECK_DAY_ARTIFACT: &str = "day_artifact_validation";
pub const CHECK_FACT_RECOMPUTE: &str = "fact_level_recompute";
pub const CHECK_MANIFEST: &str = "verification_manifest_validation";
pub const CHECK_BATCH_METADATA: &str = "batch_metadata_validation";
pub const CHECK_REJECTION_AUDIT: &str = "rejection_audit_validation";
pub const CHECK_OTS: &str = "ots_verification";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyMode {
    Warn,
    Strict,
}

impl PolicyMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "warn" | "warning" => Ok(Self::Warn),
            "strict" => Ok(Self::Strict),
            _ => Err(EvidenceError::Invalid(format!(
                "invalid policy mode: {value}"
            ))),
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Warn => "warn",
            Self::Strict => "strict",
        }
    }
}

#[derive(Clone, Debug)]
pub struct VerifyOptions {
    pub root: PathBuf,
    pub facts: PathBuf,
    pub policy_mode: PolicyMode,
    pub disclosure_class: String,
    pub commitment_profile_id: String,
    pub require_ots: bool,
    pub allow_placeholder: bool,
}

#[derive(Clone, Debug)]
pub struct ExportOptions {
    pub pipeline_dir: PathBuf,
    pub evidence_repo: PathBuf,
    pub site: String,
    pub day: String,
    pub include_frames: bool,
    pub git_commit: bool,
    pub sign: bool,
    pub tag: bool,
    pub tag_name: Option<String>,
    pub bundle_out: Option<PathBuf>,
}
