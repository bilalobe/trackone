//! Verification manifest types, path confinement, and JSON persistence.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use trackone_ledger::{normalize_hex64, sha256_hex};

use crate::{EvidenceError, PolicyMode, Result};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ArtifactRef {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerificationBundle {
    pub disclosure_class: String,
    pub commitment_profile_id: String,
    #[serde(default)]
    pub checks_executed: Vec<String>,
    #[serde(default)]
    pub checks_skipped: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifyManifest {
    pub version: u64,
    pub date: String,
    pub site: String,
    pub device_id: String,
    pub frame_count: u64,
    pub facts_dir: String,
    pub frames_file: Option<String>,
    pub artifacts: BTreeMap<String, ArtifactRef>,
    pub anchoring: Value,
    #[serde(default)]
    pub verifier: Option<Value>,
    pub verification_bundle: VerificationBundle,
}

pub(crate) fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let text = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

pub(crate) fn write_json(path: &Path, data: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(data)?)?;
    append_newline(path)?;
    Ok(())
}

fn append_newline(path: &Path) -> Result<()> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new().append(true).open(path)?;
    file.write_all(b"\n")?;
    Ok(())
}

pub(crate) fn verify_manifest_path(day_dir: &Path, day: &str) -> PathBuf {
    day_dir.join(format!("{day}.verify.json"))
}

pub(crate) fn artifact_ref(path: &Path, root: &Path) -> Result<Value> {
    Ok(json!({
        "path": path.strip_prefix(root).map_err(|_| {
            EvidenceError::Invalid(format!("artifact path escapes root: {}", path.display()))
        })?.to_string_lossy(),
        "sha256": sha256_hex(&fs::read(path)?),
    }))
}

pub(crate) fn resolve_bundle_path(root: &Path, rel: &str) -> Result<PathBuf> {
    let rel_path = Path::new(rel);
    if rel_path.is_absolute()
        || rel_path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(EvidenceError::Invalid(format!(
            "manifest artifact path escapes root: {rel}"
        )));
    }
    Ok(root.join(rel_path))
}

pub(crate) fn manifest_policy_mode(manifest: &VerifyManifest) -> Result<PolicyMode> {
    let mode = manifest
        .anchoring
        .pointer("/policy/mode")
        .and_then(Value::as_str)
        .unwrap_or(PolicyMode::Warn.as_str());
    PolicyMode::parse(mode)
}

pub(crate) fn manifest_artifact_path(
    root: &Path,
    manifest: &VerifyManifest,
    name: &str,
) -> Result<PathBuf> {
    let artifact = manifest
        .artifacts
        .get(name)
        .ok_or_else(|| EvidenceError::Invalid(format!("manifest missing artifact: {name}")))?;
    let path = resolve_bundle_path(root, &artifact.path)?;
    let declared = normalize_hex64(&artifact.sha256)?;
    let actual = sha256_hex(&fs::read(&path)?);
    if actual != declared {
        return Err(EvidenceError::Invalid(format!(
            "manifest artifact sha256 mismatch for {name}: expected {declared}, got {actual}"
        )));
    }
    Ok(path)
}
