//! Verification conclusions and their stable JSON result projection.

use super::manifest::Manifest;
use super::paths::read_file_bounded;
use super::policy::effective_verifier_policy_id;
use super::{MAX_ARCHIVE_MEMBER, Result, VerificationScope, VerifyPolicy};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use trackone_ledger::sha256_hex;

pub(super) struct Conclusions {
    pub(super) failures: BTreeSet<&'static str>,
    pub(super) chain_status: Option<&'static str>,
    pub(super) tsa_status: &'static str,
    pub(super) tsa_reason: Option<String>,
    pub(super) scope: VerificationScope,
}

impl Conclusions {
    pub(super) fn new(scope: VerificationScope) -> Self {
        Self {
            failures: BTreeSet::new(),
            chain_status: None,
            tsa_status: "missing",
            tsa_reason: None,
            scope,
        }
    }

    pub(super) fn fail(&mut self, reason: &'static str) {
        self.failures.insert(reason);
    }

    fn overall(&self) -> &'static str {
        if !self.failures.is_empty() {
            "failure"
        } else if self.tsa_status == "pending_claim" {
            "incomplete"
        } else {
            "success"
        }
    }
}

pub(super) fn result_value(
    manifest_bytes: &[u8],
    manifest: &Manifest,
    artifact_bytes: &[u8],
    profile: Option<&str>,
    policy: &VerifyPolicy,
    conclusions: Conclusions,
) -> Result<Value> {
    let verifier_policy_id = effective_verifier_policy_id(policy)?;
    let mut result = serde_json::Map::from_iter([
        (
            "artifact_sha256".to_string(),
            json!(sha256_hex(artifact_bytes)),
        ),
        (
            "manifest_sha256".to_string(),
            json!(sha256_hex(manifest_bytes)),
        ),
        (
            "claimed_disclosure_class".to_string(),
            json!(manifest.disclosure_class),
        ),
        (
            "verification_scope".to_string(),
            json!(conclusions.scope.as_str()),
        ),
        (
            "channels".to_string(),
            json!({"tsa": {
                "status": conclusions.tsa_status,
                "reason": conclusions.tsa_reason,
            }}),
        ),
        ("verifier_policy_id".to_string(), json!(verifier_policy_id)),
        ("overall".to_string(), json!(conclusions.overall())),
    ]);
    if let Some(profile) = profile {
        result.insert("commitment_profile_id".to_string(), json!(profile));
    }
    if let Some(chain_status) = conclusions.chain_status {
        result.insert("chain_status".to_string(), json!(chain_status));
    }
    if !conclusions.failures.is_empty() {
        result.insert("failure_reasons".to_string(), json!(conclusions.failures));
    }
    if let Some(path) = &policy.verifier_policy_artifact {
        result.insert(
            "verifier_policy_sha256".to_string(),
            json!(sha256_hex(&read_file_bounded(
                path,
                MAX_ARCHIVE_MEMBER,
                "verifier policy artifact",
            )?)),
        );
    }
    if conclusions.tsa_status == "verified" {
        result
            .get_mut("channels")
            .and_then(Value::as_object_mut)
            .and_then(|channels| channels.get_mut("tsa"))
            .and_then(Value::as_object_mut)
            .expect("TSA result object is constructed above")
            .remove("reason");
    }
    Ok(Value::Object(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_deliberate_downscope_is_success_at_selected_scope() {
        assert_eq!(
            Conclusions::new(VerificationScope::AnchorOnly).overall(),
            "success"
        );
    }

    #[test]
    fn pending_claim_is_incomplete_and_failure_takes_precedence() {
        let mut conclusions = Conclusions::new(VerificationScope::AnchorOnly);
        conclusions.tsa_status = "pending_claim";
        assert_eq!(conclusions.overall(), "incomplete");
        conclusions.fail("channel_failure");
        assert_eq!(conclusions.overall(), "failure");
    }
}
