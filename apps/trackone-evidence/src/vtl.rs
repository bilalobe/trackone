//! Verification and deterministic carriage for Verifiable Telemetry Ledgers bundles.

use super::{EvidenceError, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;
use trackone_ledger::vtl::{
    COMMITMENT_PROFILE_ID, SegmentDecodeError, decode_segment_profile_id, decode_segment_record,
};
use trackone_ledger::{sha256_digest, sha256_hex};
use trackone_rfc3161::{SignerCertificateSha256, verify_request};

mod archive;
mod chain;
mod disclosure;
mod manifest;
mod paths;
mod policy;
mod result;
mod timestamp;

use archive::write_archive;
use chain::validate_chain;
use disclosure::validate_disclosure;
use manifest::{Manifest, NoDuplicateJson};
use paths::{
    parse_uint64, read_file_bounded, referenced_artifact, safe_read, valid_hex,
    validate_portable_path,
};
use policy::validate_policy;
use result::{Conclusions, result_value};
use timestamp::verify_timestamp;

const MANIFEST_NAME: &str = "segment.verify.json";
pub const MANIFEST_MEDIA_TYPE: &str = "application/json";
pub const SPECIALIZED_MANIFEST_MEDIA_TYPE: &str = "application/vnd.vtl.manifest+json";
pub const RESULT_MEDIA_TYPE: &str = "application/json";
const MAX_ARCHIVE_MEMBERS: usize = 10_000;
const MAX_COMPRESSED_ARCHIVE: u64 = 64 * 1024 * 1024;
const MAX_EXPANDED_ARCHIVE: u64 = 256 * 1024 * 1024;
pub(super) const MAX_ARCHIVE_MEMBER: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct VerifyPolicy {
    pub tsa_ca_file: Option<PathBuf>,
    pub tsa_intermediates_file: Option<PathBuf>,
    pub tsa_crls_file: Option<PathBuf>,
    pub tsa_policy_oid: Option<String>,
    pub tsa_signer_cert_sha256: Option<SignerCertificateSha256>,
    pub openssl_binary: PathBuf,
    pub max_future_skew: Duration,
    /// Explicit identifier supplied by the policy owner. When omitted, the
    /// verifier derives a stable identifier from the complete configuration.
    pub verifier_policy_id: Option<String>,
    pub verifier_policy_artifact: Option<PathBuf>,
    pub selected_scope: Option<VerificationScope>,
    pub selected_batches: BTreeSet<u64>,
    pub require_claimed_scope: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationScope {
    PublicRecompute,
    DisclosedBatchRecompute,
    AnchorOnly,
}

impl VerificationScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PublicRecompute => "public_recompute",
            Self::DisclosedBatchRecompute => "disclosed_batch_recompute",
            Self::AnchorOnly => "anchor_only",
        }
    }

    const fn strength(self) -> u8 {
        match self {
            Self::PublicRecompute => 3,
            Self::DisclosedBatchRecompute => 2,
            Self::AnchorOnly => 1,
        }
    }

    fn for_disclosure_class(value: &str) -> Self {
        match value {
            "A" => Self::PublicRecompute,
            "B" => Self::DisclosedBatchRecompute,
            _ => Self::AnchorOnly,
        }
    }
}

impl Default for VerifyPolicy {
    fn default() -> Self {
        Self {
            tsa_ca_file: None,
            tsa_intermediates_file: None,
            tsa_crls_file: None,
            tsa_policy_oid: None,
            tsa_signer_cert_sha256: None,
            openssl_binary: PathBuf::from("openssl"),
            max_future_skew: Duration::ZERO,
            verifier_policy_id: None,
            verifier_policy_artifact: None,
            selected_scope: None,
            selected_batches: BTreeSet::new(),
            require_claimed_scope: false,
        }
    }
}

impl VerifyPolicy {
    pub fn baseline() -> Self {
        Self::default()
    }
}

fn bad(message: impl Into<String>) -> EvidenceError {
    EvidenceError::Invalid(message.into())
}

fn parse_manifest(bytes: &[u8]) -> Result<Manifest> {
    let value = serde_json::from_slice::<NoDuplicateJson>(bytes)?.0;
    let manifest: Manifest = serde_json::from_value(value)?;
    if manifest.version != 1 {
        return Err(bad("producer manifest version must be 1"));
    }
    if !valid_hex(&manifest.ledger_id, 32)
        || parse_uint64(&manifest.segment_number).is_none()
        || manifest.commitment_profile_id.is_empty()
        || !matches!(manifest.disclosure_class.as_str(), "A" | "B" | "C")
        || !matches!(
            manifest.anchoring.tsa.status.as_str(),
            "present" | "pending" | "unavailable"
        )
    {
        return Err(bad(
            "producer manifest violates its baseline lexical contract",
        ));
    }
    if let Some(openings) = &manifest.artifacts.record_batches
        && (openings.is_empty()
            || openings.iter().any(|opening| {
                opening.records.is_empty() || parse_uint64(&opening.batch_number).is_none()
            }))
    {
        return Err(bad(
            "record_batches and records must be non-empty and batch_number must be a uint64",
        ));
    }
    for reference in manifest.artifacts.references(true) {
        validate_portable_path(&reference.path)?;
        if !valid_hex(&reference.sha256, 64) {
            return Err(bad(
                "artifact reference SHA-256 is not lowercase hexadecimal",
            ));
        }
    }
    match manifest.anchoring.tsa.status.as_str() {
        "present" if manifest.artifacts.tsa_tsr.is_none() => {
            return Err(bad("present TSA state requires tsa_tsr"));
        }
        "pending" | "unavailable" if manifest.artifacts.tsa_tsr.is_some() => {
            return Err(bad("non-present TSA state must omit tsa_tsr"));
        }
        _ => {}
    }
    Ok(manifest)
}

fn evaluate_tsa(
    root: &Path,
    manifest: &Manifest,
    artifact_digest: [u8; 32],
    policy: &VerifyPolicy,
    conclusions: &mut Conclusions,
) {
    match manifest.anchoring.tsa.status.as_str() {
        "present" => {
            let Some(reference) = &manifest.artifacts.tsa_tsr else {
                conclusions.tsa_status = "missing";
                conclusions.tsa_reason = Some("timestamp response is absent".to_string());
                conclusions.fail("channel_failure");
                return;
            };
            let response = match referenced_artifact(root, reference) {
                Ok(response) => response,
                Err(EvidenceError::VerificationFailed(error)) => {
                    conclusions.tsa_status = "failed";
                    conclusions.tsa_reason = Some(error);
                    conclusions.fail("channel_failure");
                    conclusions.fail("commitment_mismatch");
                    return;
                }
                Err(error) => {
                    conclusions.tsa_status = "missing";
                    conclusions.tsa_reason = Some(error.to_string());
                    conclusions.fail("channel_failure");
                    return;
                }
            };
            if let Some(reason) = missing_timestamp_policy(policy) {
                conclusions.tsa_status = "failed";
                conclusions.tsa_reason = Some(reason.to_string());
                conclusions.fail("channel_failure");
                conclusions.fail("verifier_policy_rejection");
                return;
            }
            match verify_timestamp(&response, artifact_digest, policy) {
                Ok(verified) => {
                    let request_result = match &manifest.artifacts.tsa_req {
                        Some(reference) => {
                            referenced_artifact(root, reference).and_then(|request| {
                                verify_request(&request, artifact_digest, verified.nonce.as_deref())
                                    .map(|_| ())
                                    .map_err(|error| bad(error.to_string()))
                            })
                        }
                        None if verified.nonce.is_some() => {
                            Err(bad("nonce-bearing timestamp response requires tsa_req"))
                        }
                        None => Ok(()),
                    };
                    match request_result {
                        Ok(()) => conclusions.tsa_status = "verified",
                        Err(error) => {
                            conclusions.tsa_status = "failed";
                            conclusions.tsa_reason = Some(error.to_string());
                            conclusions.fail("channel_failure");
                        }
                    }
                }
                Err(error) => {
                    conclusions.tsa_status = "failed";
                    conclusions.tsa_reason = Some(error.to_string());
                    conclusions.fail("channel_failure");
                }
            }
        }
        "pending" => {
            conclusions.tsa_status = "pending_claim";
            conclusions.tsa_reason = Some("producer_pending_claim".to_string());
        }
        _ => {
            conclusions.tsa_status = "missing";
            conclusions.tsa_reason = Some("timestamp issuance is unavailable".to_string());
            conclusions.fail("channel_failure");
        }
    }
}

fn missing_timestamp_policy(policy: &VerifyPolicy) -> Option<&'static str> {
    if policy.tsa_ca_file.is_none() {
        Some("RFC 3161 trust anchor is not configured")
    } else if policy.tsa_crls_file.is_none() {
        Some("RFC 3161 historical CRL archive is not configured")
    } else if policy.tsa_policy_oid.is_none() {
        Some("RFC 3161 TSA policy OID is not configured")
    } else if policy.tsa_signer_cert_sha256.is_none() {
        Some("RFC 3161 signer certificate SHA-256 is not configured")
    } else {
        None
    }
}

pub fn verify_bundle(root: &Path) -> Result<Value> {
    verify_bundle_with_policy(root, &VerifyPolicy::baseline())
}

pub fn verify_bundle_with_policy(root: &Path, policy: &VerifyPolicy) -> Result<Value> {
    validate_policy(policy)?;
    let manifest_bytes = read_file_bounded(
        &root.join(MANIFEST_NAME),
        MAX_ARCHIVE_MEMBER,
        "producer manifest",
    )?;
    let manifest = parse_manifest(&manifest_bytes)?;
    for reference in manifest.artifacts.extensions.values() {
        referenced_artifact(root, reference)?;
    }
    let claimed_scope = VerificationScope::for_disclosure_class(&manifest.disclosure_class);
    let selected_scope = policy.selected_scope.unwrap_or(claimed_scope);
    let downscoped = selected_scope.strength() < claimed_scope.strength();
    let artifact_bytes = safe_read(root, &manifest.artifacts.segment_cbor.path)?;
    let artifact_digest = sha256_digest(&artifact_bytes);
    let profile = decode_segment_profile_id(&artifact_bytes).ok();
    let mut conclusions = Conclusions::new(selected_scope);
    let mut claimed_scope_supported = false;

    if sha256_hex(&artifact_bytes) != manifest.artifacts.segment_cbor.sha256 {
        conclusions.fail("commitment_mismatch");
    }
    if profile
        .as_deref()
        .is_some_and(|value| value != manifest.commitment_profile_id)
    {
        conclusions.fail("commitment_mismatch");
    }
    match decode_segment_record(&artifact_bytes) {
        Ok(segment) => {
            let segment_matches_manifest = segment.ledger_id == manifest.ledger_id
                && segment.segment_number.to_string() == manifest.segment_number
                && segment.commitment_profile_id == manifest.commitment_profile_id;
            if !segment_matches_manifest {
                conclusions.fail("commitment_mismatch");
            }
            validate_chain(root, &manifest, &segment, &mut conclusions);
            claimed_scope_supported = segment_matches_manifest
                && validate_disclosure(root, &manifest, &segment, policy, &mut conclusions);
        }
        Err(_)
            if profile.as_deref().is_some_and(|value| {
                is_lowercase_uuid(value) && value != COMMITMENT_PROFILE_ID
            }) =>
        {
            conclusions.fail("unsupported_commitment_profile")
        }
        Err(SegmentDecodeError::ResourceLimit(_)) => conclusions.fail("verifier_policy_rejection"),
        Err(_) => conclusions.fail("invalid_segment_artifact"),
    }
    if downscoped && policy.require_claimed_scope && claimed_scope_supported {
        conclusions.fail("scope_not_exercised");
    }
    evaluate_tsa(root, &manifest, artifact_digest, policy, &mut conclusions);
    result_value(
        &manifest_bytes,
        &manifest,
        &artifact_bytes,
        profile.as_deref(),
        policy,
        conclusions,
    )
}

fn is_lowercase_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => matches!(byte, b'0'..=b'9' | b'a'..=b'f'),
        })
}

pub fn compact_bundle(
    root: &Path,
    output: &Path,
    policy: &VerifyPolicy,
    include_extensions: bool,
) -> Result<()> {
    let result = verify_bundle_with_policy(root, policy)?;
    if result["overall"] != "success" {
        return Err(EvidenceError::VerificationFailed(
            "compact requires successful baseline verification".to_string(),
        ));
    }
    let manifest_bytes = read_file_bounded(
        &root.join(MANIFEST_NAME),
        MAX_ARCHIVE_MEMBER,
        "producer manifest",
    )?;
    let mut manifest = parse_manifest(&manifest_bytes)?;
    if !include_extensions {
        manifest.artifacts.extensions.clear();
        manifest.extensions = None;
    }
    let mut members = BTreeMap::new();
    for reference in manifest.artifacts.references(include_extensions) {
        members.insert(
            reference.path.clone(),
            referenced_artifact(root, reference)?,
        );
    }
    members.insert(MANIFEST_NAME.to_string(), serde_json::to_vec(&manifest)?);
    write_archive(output, &members)
}

pub use archive::verify_archive;
