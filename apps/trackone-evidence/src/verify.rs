//! Evidence-bundle verification orchestration.

use serde_json::{Value, json};
use std::fs;
use trackone_ledger::{canonical_cbor, merkle};
use trackone_ots::{validate_meta_sidecar_native, verify_ots_proof_native};

use crate::bundle::{
    BlockHeader, find_block, validate_canonical_cbor_fact, validate_rejection_audit,
};
use crate::manifest::{
    VerificationBundle, VerifyManifest, manifest_artifact_path, read_json, resolve_bundle_path,
    verify_manifest_path,
};
use crate::policy::{
    CHECK_BATCH_METADATA, CHECK_DAY_ARTIFACT, CHECK_FACT_RECOMPUTE, CHECK_MANIFEST, CHECK_OTS,
    CHECK_REJECTION_AUDIT, PolicyMode, STATUS_FAILED, STATUS_MISSING, STATUS_PENDING,
    STATUS_SKIPPED, STATUS_VERIFIED, VerifyOptions,
};
use crate::{EvidenceError, Result};

fn channel(enabled: bool, status: &str, reason: &str) -> Value {
    json!({"enabled": enabled, "status": status, "reason": reason})
}

fn record_executed(summary: &mut Value, check: &str) {
    summary["checks_executed"]
        .as_array_mut()
        .unwrap()
        .push(json!(check));
    let scope = summary["verification_scope_exercised"]
        .as_array_mut()
        .unwrap();
    if !scope.iter().any(|value| value.as_str() == Some(check)) {
        scope.push(json!(check));
    }
}

fn record_skipped(summary: &mut Value, check: &str, reason: &str) {
    summary["checks_skipped"]
        .as_array_mut()
        .unwrap()
        .push(json!({"check": check, "reason": reason}));
}

fn set_channel(summary: &mut Value, name: &str, enabled: bool, status: &str, reason: &str) {
    summary["channels"][name] = channel(enabled, status, reason);
}

fn manifest_channel(manifest: &VerifyManifest, name: &str) -> (bool, String, String) {
    let item = &manifest.anchoring["channels"][name];
    let enabled = item
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let status = item
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or(if enabled {
            STATUS_PENDING
        } else {
            STATUS_SKIPPED
        })
        .to_string();
    let reason = item
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or(if enabled { "not-run" } else { "disabled" })
        .to_string();
    (enabled, status, reason)
}

fn compute_overall(policy: &PolicyMode, channels: &Value) -> &'static str {
    if policy == &PolicyMode::Strict {
        for item in channels.as_object().into_iter().flat_map(|m| m.values()) {
            if item.get("enabled").and_then(Value::as_bool) == Some(true)
                && item.get("status").and_then(Value::as_str) != Some(STATUS_VERIFIED)
            {
                return "failed";
            }
        }
        return "success";
    }
    let ots = &channels["ots"];
    if ots.get("enabled").and_then(Value::as_bool) == Some(true)
        && matches!(
            ots.get("status").and_then(Value::as_str),
            Some(STATUS_FAILED | STATUS_MISSING)
        )
    {
        return "failed";
    }
    "success"
}

fn refresh_public(summary: &mut Value) {
    let class_a = summary["verification"]["disclosure_class"].as_str() == Some("A");
    let artifact_valid = summary["checks"]["artifact_valid"].as_bool() == Some(true);
    let root_match = summary["checks"]["root_match"].as_bool() == Some(true);
    summary["verification"]["publicly_recomputable"] =
        json!(class_a && artifact_valid && root_match);
}

pub fn local_verification_failure(summary: &Value) -> Option<String> {
    if summary["manifest"]["status"].as_str() != Some("present") {
        return Some("manifest-missing".to_string());
    }
    let executed = summary["checks_executed"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_string))
        .collect::<std::collections::BTreeSet<_>>();
    for required in [CHECK_DAY_ARTIFACT, CHECK_MANIFEST, CHECK_BATCH_METADATA] {
        if !executed.contains(required) {
            return Some(format!("{required}-not-executed"));
        }
    }
    if summary["checks"]["artifact_valid"].as_bool() != Some(true) {
        return Some("artifact-invalid".to_string());
    }
    if summary["checks"]["meta_valid"].as_bool() != Some(true) {
        return Some("meta-invalid".to_string());
    }
    if summary["verification"]["disclosure_class"].as_str() == Some("A") {
        if !executed.contains(CHECK_FACT_RECOMPUTE) {
            return Some("fact_level_recompute-not-executed".to_string());
        }
        if summary["checks"]["root_match"].as_bool() != Some(true) {
            return Some("fact-root-mismatch".to_string());
        }
    }
    None
}

pub(crate) fn portable_summary(summary: &Value) -> Value {
    let mut out = serde_json::Map::new();
    for key in [
        "policy",
        "verification",
        "checks",
        "verification_scope_exercised",
        "checks_executed",
        "checks_skipped",
        "channels",
        "manifest",
        "operator_audit",
        "overall",
    ] {
        if !summary[key].is_null() {
            out.insert(key.to_string(), summary[key].clone());
        }
    }
    Value::Object(out)
}

pub(crate) fn verification_bundle_from_summary(
    summary: &Value,
    original: &VerificationBundle,
) -> Value {
    json!({
        "disclosure_class": summary["verification"]["disclosure_class"].as_str().unwrap_or(&original.disclosure_class),
        "commitment_profile_id": summary["verification"]["commitment_profile_id"].as_str().unwrap_or(&original.commitment_profile_id),
        "checks_executed": summary["checks_executed"].as_array().cloned().unwrap_or_default(),
        "checks_skipped": summary["checks_skipped"].as_array().cloned().unwrap_or_default(),
    })
}

pub fn verify_bundle(options: &VerifyOptions) -> Result<Value> {
    let root = &options.root;
    let block_path = find_block(root)?;
    let block: BlockHeader = read_json(&block_path)?;
    let day = block.day.clone();
    let day_artifact = root.join("day").join(format!("{day}.cbor"));
    let day_json_path = root.join("day").join(format!("{day}.json"));
    let ots_path = day_artifact.with_extension("cbor.ots");
    let manifest_path = verify_manifest_path(&root.join("day"), &day);
    let manifest: VerifyManifest = read_json(&manifest_path)?;

    let mut summary = json!({
        "policy": {"mode": options.policy_mode.as_str()},
        "verification": {
            "disclosure_class": options.disclosure_class,
            "disclosure_label": match options.disclosure_class.as_str() {
                "A" => trackone_constants::DISCLOSURE_CLASS_PUBLIC_RECOMPUTE_LABEL,
                "B" => trackone_constants::DISCLOSURE_CLASS_PARTNER_AUDIT_LABEL,
                "C" => trackone_constants::DISCLOSURE_CLASS_ANCHOR_ONLY_LABEL,
                _ => options.disclosure_class.as_str(),
            },
            "commitment_profile_id": options.commitment_profile_id,
            "publicly_recomputable": false,
        },
        "manifest": {"status": "missing", "source": Value::Null, "schema": "verify_manifest"},
        "artifacts": {
            "block": block_path.to_string_lossy(),
            "day_cbor": day_artifact.to_string_lossy(),
            "day_ots": ots_path.to_string_lossy(),
            "verification_manifest": manifest_path.to_string_lossy(),
        },
        "checks": {
            "root_match": Value::Null,
            "artifact_valid": false,
            "meta_valid": true,
            "rejection_audit_valid": Value::Null,
        },
        "operator_audit": {
            "rejection_records": 0,
            "commitment_material": false,
        },
        "verification_scope_exercised": [],
        "checks_executed": [],
        "checks_skipped": [],
        "channels": {
            "ots": channel(options.require_ots, if options.require_ots { STATUS_PENDING } else { STATUS_SKIPPED }, if options.require_ots { "not-run" } else { "disabled" }),
            "tsa": channel(false, STATUS_SKIPPED, "disabled"),
            "peers": channel(false, STATUS_SKIPPED, "disabled"),
        },
        "overall": "failed",
    });
    record_executed(&mut summary, CHECK_DAY_ARTIFACT);
    record_executed(&mut summary, CHECK_MANIFEST);
    record_executed(&mut summary, CHECK_BATCH_METADATA);

    if manifest.date != day || manifest.site != block.site_id {
        return Err(EvidenceError::Invalid(
            "manifest does not match block header".to_string(),
        ));
    }
    if manifest.verification_bundle.disclosure_class != options.disclosure_class {
        return Err(EvidenceError::Invalid(
            "manifest disclosure_class mismatch".to_string(),
        ));
    }
    if manifest.verification_bundle.commitment_profile_id != options.commitment_profile_id {
        return Err(EvidenceError::Invalid(
            "manifest commitment_profile_id mismatch".to_string(),
        ));
    }
    for required in ["block", "day_cbor"] {
        let _ = manifest_artifact_path(root, &manifest, required)?;
    }
    if manifest.artifacts.contains_key("rejection_audit") {
        let audit_path = manifest_artifact_path(root, &manifest, "rejection_audit")?;
        if audit_path
            .strip_prefix(root)
            .ok()
            .and_then(|rel| rel.components().next())
            .is_some_and(|component| component.as_os_str() == "facts")
        {
            return Err(EvidenceError::Invalid(
                "rejection audit must not be commitment material".to_string(),
            ));
        }
        record_executed(&mut summary, CHECK_REJECTION_AUDIT);
        let count = validate_rejection_audit(&audit_path)?;
        summary["checks"]["rejection_audit_valid"] = json!(true);
        summary["operator_audit"]["rejection_records"] = json!(count);
    }
    summary["manifest"] = json!({"status": "present", "source": manifest_path.file_name().and_then(|v| v.to_str()), "schema": "verify_manifest"});
    for name in ["tsa", "peers"] {
        let (enabled, status, reason) = manifest_channel(&manifest, name);
        set_channel(&mut summary, name, enabled, &status, &reason);
    }

    let day_bytes = fs::read(&day_artifact)?;
    let day_json_bytes = fs::read(&day_json_path)?;
    let canonical = canonical_cbor::canonicalize_json_bytes_to_cbor(&day_json_bytes)?;
    if canonical != day_bytes {
        return Err(EvidenceError::Invalid(
            "day artifact is not canonical commitment bytes".to_string(),
        ));
    }
    let day_record: Value = serde_json::from_slice(&day_json_bytes)?;
    if day_record["day_root"].as_str() != Some(&block.merkle_root)
        || day_record["date"].as_str() != Some(&day)
        || day_record["site_id"].as_str() != Some(&block.site_id)
    {
        return Err(EvidenceError::Invalid(
            "day projection does not match block header".to_string(),
        ));
    }
    let batches = day_record["batches"]
        .as_array()
        .ok_or_else(|| EvidenceError::Invalid("day projection batches missing".to_string()))?;
    if batches.len() != 1 {
        return Err(EvidenceError::Invalid(
            "day projection must contain exactly one batch for current manifest".to_string(),
        ));
    }
    summary["checks"]["artifact_valid"] = json!(true);

    if let Some(meta_ref) = manifest.artifacts.get("day_ots_meta") {
        let meta_path = resolve_bundle_path(root, &meta_ref.path)?;
        let meta_check = validate_meta_sidecar_native(&meta_path, root, &day_artifact, &ots_path);
        if !meta_check.ok {
            summary["checks"]["meta_valid"] = json!(false);
            return Err(EvidenceError::Invalid(format!(
                "OTS metadata validation failed: {}",
                meta_check.reason
            )));
        }
    }

    if options.disclosure_class == "A" {
        record_executed(&mut summary, CHECK_FACT_RECOMPUTE);
        let mut fact_files = match fs::read_dir(&options.facts) {
            Ok(entries) => entries
                .filter_map(|entry| entry.ok().map(|item| item.path()))
                .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("cbor"))
                .collect::<Vec<_>>(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(err) => return Err(err.into()),
        };
        fact_files.sort();
        if fact_files.is_empty() {
            return Err(EvidenceError::Invalid(
                "CBOR facts are required for Class A verification".to_string(),
            ));
        }
        let leaves = fact_files
            .iter()
            .map(|path| {
                let bytes = fs::read(path)?;
                validate_canonical_cbor_fact(&bytes).map_err(|err| {
                    EvidenceError::Invalid(format!(
                        "fact artifact is not canonical CBOR: {}: {err}",
                        path.display()
                    ))
                })?;
                Ok(bytes)
            })
            .collect::<Result<Vec<_>>>()?;
        let recomputed = merkle::merkle_root_from_leaves(&leaves).root_hex();
        summary["checks"]["root_match"] = json!(recomputed == block.merkle_root);
        if recomputed != block.merkle_root {
            return Err(EvidenceError::VerificationFailed(
                "fact-root-mismatch".to_string(),
            ));
        }
    } else {
        record_skipped(
            &mut summary,
            CHECK_FACT_RECOMPUTE,
            &format!(
                "disclosure-class-{}",
                options.disclosure_class.to_ascii_lowercase()
            ),
        );
    }

    let ots_enabled = options.require_ots
        || manifest
            .anchoring
            .pointer("/channels/ots/enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    if ots_enabled {
        record_executed(&mut summary, CHECK_OTS);
        let expected_sha = manifest
            .artifacts
            .get("day_cbor")
            .map(|artifact| artifact.sha256.as_str());
        let ots_result = verify_ots_proof_native(
            &ots_path,
            options.allow_placeholder,
            expected_sha,
            None,
            None,
        );
        let status = ots_result.status.as_str();
        set_channel(&mut summary, "ots", true, status, &ots_result.reason);
        if !ots_result.ok && (options.require_ots || options.policy_mode == PolicyMode::Strict) {
            summary["overall"] = json!("failed");
            refresh_public(&mut summary);
            return Err(EvidenceError::VerificationFailed(ots_result.reason));
        }
    }

    let overall = compute_overall(&options.policy_mode, &summary["channels"]);
    summary["overall"] = json!(overall);
    refresh_public(&mut summary);
    Ok(summary)
}
