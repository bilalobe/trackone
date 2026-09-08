//! Verifier-policy validation and deterministic policy identity derivation.

use super::paths::read_file_bounded;
use super::{MAX_ARCHIVE_MEMBER, Result, VerificationScope, VerifyPolicy, bad};
use serde::Serialize;
use std::path::PathBuf;
use trackone_ledger::sha256_hex;

pub(super) fn validate_policy(policy: &VerifyPolicy) -> Result<()> {
    if policy
        .verifier_policy_id
        .as_deref()
        .is_some_and(str::is_empty)
    {
        return Err(bad("verifier policy identifier must not be empty"));
    }
    if let Some(path) = &policy.verifier_policy_artifact
        && !path.is_file()
    {
        return Err(bad("verifier policy artifact is not available for hashing"));
    }
    if !policy.selected_batches.is_empty()
        && policy.selected_scope != Some(VerificationScope::DisclosedBatchRecompute)
    {
        return Err(bad(
            "selected batches are valid only for disclosed_batch_recompute",
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct PolicyFingerprint {
    version: u8,
    tsa_ca_sha256: Option<String>,
    tsa_intermediates_sha256: Option<String>,
    tsa_crls_sha256: Option<String>,
    tsa_policy_oid: Option<String>,
    tsa_signer_cert_sha256: Option<String>,
    openssl_binary: Vec<u8>,
    max_future_skew_seconds: u64,
    max_future_skew_nanoseconds: u32,
    verifier_policy_artifact_sha256: Option<String>,
    selected_scope: Option<&'static str>,
    selected_batches: Vec<u64>,
    require_claimed_scope: bool,
}

fn configured_file_sha256(path: Option<&PathBuf>, label: &str) -> Result<Option<String>> {
    path.map(|path| {
        read_file_bounded(path, MAX_ARCHIVE_MEMBER, label).map(|bytes| sha256_hex(&bytes))
    })
    .transpose()
}

pub(super) fn effective_verifier_policy_id(policy: &VerifyPolicy) -> Result<String> {
    if let Some(identifier) = &policy.verifier_policy_id {
        return Ok(identifier.clone());
    }
    let fingerprint = PolicyFingerprint {
        version: 1,
        tsa_ca_sha256: configured_file_sha256(
            policy.tsa_ca_file.as_ref(),
            "RFC 3161 trust anchors",
        )?,
        tsa_intermediates_sha256: configured_file_sha256(
            policy.tsa_intermediates_file.as_ref(),
            "RFC 3161 intermediates",
        )?,
        tsa_crls_sha256: configured_file_sha256(policy.tsa_crls_file.as_ref(), "RFC 3161 CRLs")?,
        tsa_policy_oid: policy.tsa_policy_oid.clone(),
        tsa_signer_cert_sha256: policy
            .tsa_signer_cert_sha256
            .as_ref()
            .map(ToString::to_string),
        openssl_binary: policy
            .openssl_binary
            .as_os_str()
            .as_encoded_bytes()
            .to_vec(),
        max_future_skew_seconds: policy.max_future_skew.as_secs(),
        max_future_skew_nanoseconds: policy.max_future_skew.subsec_nanos(),
        verifier_policy_artifact_sha256: configured_file_sha256(
            policy.verifier_policy_artifact.as_ref(),
            "verifier policy artifact",
        )?,
        selected_scope: policy.selected_scope.map(VerificationScope::as_str),
        selected_batches: policy.selected_batches.iter().copied().collect(),
        require_claimed_scope: policy.require_claimed_scope,
    };
    let encoded = serde_json::to_vec(&fingerprint)?;
    Ok(format!("vtl-policy-sha256-{}", sha256_hex(&encoded)))
}
