use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use trackone::ots::{validate_meta_sidecar_native, verify_ots_proof_native};
use trackone_ingest::{RejectionRecord, validate_rejection_record};
use trackone_ledger::{canonical_cbor, merkle, normalize_hex64, sha256_hex};

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

#[derive(Debug)]
pub enum EvidenceError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Ledger(trackone_ledger::Error),
    Invalid(String),
    VerificationFailed(String),
    Git(String),
}

impl core::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "io error: {err}"),
            Self::Json(err) => write!(f, "json error: {err}"),
            Self::Ledger(err) => write!(f, "ledger error: {err}"),
            Self::Invalid(msg) | Self::VerificationFailed(msg) | Self::Git(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for EvidenceError {}

impl From<std::io::Error> for EvidenceError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for EvidenceError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

impl From<trackone_ledger::Error> for EvidenceError {
    fn from(err: trackone_ledger::Error) -> Self {
        Self::Ledger(err)
    }
}

pub type Result<T> = core::result::Result<T, EvidenceError>;

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

#[derive(Clone, Debug, Deserialize)]
struct BlockHeader {
    site_id: String,
    day: String,
    merkle_root: String,
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let text = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, data: &Value) -> Result<()> {
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

fn verify_manifest_path(day_dir: &Path, day: &str) -> PathBuf {
    day_dir.join(format!("{day}.verify.json"))
}

fn artifact_ref(path: &Path, root: &Path) -> Result<Value> {
    Ok(json!({
        "path": path.strip_prefix(root).map_err(|_| {
            EvidenceError::Invalid(format!("artifact path escapes root: {}", path.display()))
        })?.to_string_lossy(),
        "sha256": sha256_hex(&fs::read(path)?),
    }))
}

fn resolve_bundle_path(root: &Path, rel: &str) -> Result<PathBuf> {
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

fn manifest_policy_mode(manifest: &VerifyManifest) -> Result<PolicyMode> {
    let mode = manifest
        .anchoring
        .pointer("/policy/mode")
        .and_then(Value::as_str)
        .unwrap_or(PolicyMode::Warn.as_str());
    PolicyMode::parse(mode)
}

fn manifest_artifact_path(root: &Path, manifest: &VerifyManifest, name: &str) -> Result<PathBuf> {
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

fn read_cbor_uint(data: &[u8], pos: &mut usize, ai: u8) -> Result<u64> {
    match ai {
        n @ 0..=23 => Ok(n as u64),
        24 => {
            let value = *data
                .get(*pos)
                .ok_or_else(|| EvidenceError::Invalid("truncated CBOR".to_string()))?
                as u64;
            *pos += 1;
            if value < 24 {
                return Err(EvidenceError::Invalid(
                    "CBOR integer is not shortest-form".to_string(),
                ));
            }
            Ok(value)
        }
        25 => {
            let bytes = data
                .get(*pos..*pos + 2)
                .ok_or_else(|| EvidenceError::Invalid("truncated CBOR".to_string()))?;
            *pos += 2;
            let value = u16::from_be_bytes([bytes[0], bytes[1]]) as u64;
            if value <= u8::MAX as u64 {
                return Err(EvidenceError::Invalid(
                    "CBOR integer is not shortest-form".to_string(),
                ));
            }
            Ok(value)
        }
        26 => {
            let bytes = data
                .get(*pos..*pos + 4)
                .ok_or_else(|| EvidenceError::Invalid("truncated CBOR".to_string()))?;
            *pos += 4;
            let value = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
            if value <= u16::MAX as u64 {
                return Err(EvidenceError::Invalid(
                    "CBOR integer is not shortest-form".to_string(),
                ));
            }
            Ok(value)
        }
        27 => {
            let bytes = data
                .get(*pos..*pos + 8)
                .ok_or_else(|| EvidenceError::Invalid("truncated CBOR".to_string()))?;
            *pos += 8;
            let value = u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            if value <= u32::MAX as u64 {
                return Err(EvidenceError::Invalid(
                    "CBOR integer is not shortest-form".to_string(),
                ));
            }
            Ok(value)
        }
        _ => Err(EvidenceError::Invalid(
            "indefinite or reserved CBOR additional information".to_string(),
        )),
    }
}

fn parse_canonical_cbor_value(data: &[u8], pos: &mut usize) -> Result<()> {
    let initial = *data
        .get(*pos)
        .ok_or_else(|| EvidenceError::Invalid("empty CBOR value".to_string()))?;
    *pos += 1;
    let major = initial >> 5;
    let ai = initial & 0x1f;

    match major {
        0 | 1 => {
            let _ = read_cbor_uint(data, pos, ai)?;
        }
        2 | 3 => {
            let len = read_cbor_uint(data, pos, ai)? as usize;
            let end = pos
                .checked_add(len)
                .filter(|end| *end <= data.len())
                .ok_or_else(|| EvidenceError::Invalid("truncated CBOR bytes/text".to_string()))?;
            if major == 3 {
                std::str::from_utf8(&data[*pos..end])
                    .map_err(|_| EvidenceError::Invalid("CBOR text is not UTF-8".to_string()))?;
            }
            *pos = end;
        }
        4 => {
            let len = read_cbor_uint(data, pos, ai)? as usize;
            for _ in 0..len {
                parse_canonical_cbor_value(data, pos)?;
            }
        }
        5 => {
            let len = read_cbor_uint(data, pos, ai)? as usize;
            let mut previous_key: Option<Vec<u8>> = None;
            for _ in 0..len {
                let key_start = *pos;
                parse_canonical_cbor_value(data, pos)?;
                let key = data[key_start..*pos].to_vec();
                if let Some(previous) = previous_key.as_ref()
                    && (previous.len() > key.len()
                        || (previous.len() == key.len() && previous.as_slice() >= key.as_slice()))
                {
                    return Err(EvidenceError::Invalid(
                        "CBOR map keys are not canonical-order".to_string(),
                    ));
                }
                previous_key = Some(key);
                parse_canonical_cbor_value(data, pos)?;
            }
        }
        6 => {
            return Err(EvidenceError::Invalid(
                "CBOR tags are outside the beta fact contract".to_string(),
            ));
        }
        7 => match ai {
            20..=23 => {}
            24 => {
                let simple = *data
                    .get(*pos)
                    .ok_or_else(|| EvidenceError::Invalid("truncated CBOR simple".to_string()))?;
                *pos += 1;
                if simple < 32 {
                    return Err(EvidenceError::Invalid(
                        "CBOR simple value is not shortest-form".to_string(),
                    ));
                }
            }
            _ => {
                return Err(EvidenceError::Invalid(
                    "CBOR simple/float value is outside the beta fact contract".to_string(),
                ));
            }
        },
        _ => unreachable!(),
    }
    Ok(())
}

fn validate_canonical_cbor_fact(bytes: &[u8]) -> Result<()> {
    let mut pos = 0;
    parse_canonical_cbor_value(bytes, &mut pos)?;
    if pos != bytes.len() {
        return Err(EvidenceError::Invalid(
            "CBOR fact has trailing bytes".to_string(),
        ));
    }
    Ok(())
}

fn validate_rejection_audit(path: &Path) -> Result<usize> {
    let text = fs::read_to_string(path)?;
    let mut count = 0usize;
    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: RejectionRecord = serde_json::from_str(line).map_err(|err| {
            EvidenceError::Invalid(format!(
                "rejection audit line {} invalid JSON: {err}",
                idx + 1
            ))
        })?;
        validate_rejection_record(&record).map_err(|err| {
            EvidenceError::Invalid(format!(
                "rejection audit line {} invalid record: {err}",
                idx + 1
            ))
        })?;
        count += 1;
    }
    Ok(count)
}

fn find_block(root: &Path) -> Result<PathBuf> {
    let mut entries = fs::read_dir(root.join("blocks"))?
        .filter_map(|entry| entry.ok().map(|item| item.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".block.json"))
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries
        .into_iter()
        .next()
        .ok_or_else(|| EvidenceError::Invalid("no block header found".to_string()))
}

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

fn portable_summary(summary: &Value) -> Value {
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

fn verification_bundle_from_summary(summary: &Value, original: &VerificationBundle) -> Value {
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

fn copy_file(src: &Path, dst: &Path) -> Result<()> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(src, dst)?;
    Ok(())
}

fn copy_dir(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir(&src_path, &dst_path)?;
        } else {
            copy_file(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn find_meta_sidecar(pipeline_dir: &Path, day: &str) -> Result<PathBuf> {
    let meta_name = format!("{day}.ots.meta.json");
    let mut candidates = vec![pipeline_dir.join("day").join(&meta_name)];
    for dir in pipeline_dir.ancestors() {
        candidates.push(dir.join("proofs").join(&meta_name));
    }

    for candidate in candidates {
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(EvidenceError::Invalid(format!(
        "OTS metadata sidecar not found for {day}"
    )))
}

pub fn export_bundle(options: &ExportOptions) -> Result<PathBuf> {
    let manifest_path = verify_manifest_path(&options.pipeline_dir.join("day"), &options.day);
    let manifest: VerifyManifest = read_json(&manifest_path)?;
    if manifest.site != options.site || manifest.date != options.day {
        return Err(EvidenceError::Invalid(
            "verification manifest site/day mismatch".to_string(),
        ));
    }
    let policy_mode = manifest_policy_mode(&manifest)?;
    let verify_options = VerifyOptions {
        root: options.pipeline_dir.clone(),
        facts: options.pipeline_dir.join(&manifest.facts_dir),
        policy_mode,
        disclosure_class: manifest.verification_bundle.disclosure_class.clone(),
        commitment_profile_id: manifest.verification_bundle.commitment_profile_id.clone(),
        require_ots: false,
        allow_placeholder: true,
    };
    let verifier_summary = verify_bundle(&verify_options).map_err(|err| {
        EvidenceError::VerificationFailed(format!(
            "fresh verification failed; refusing to export unverified evidence: {err}"
        ))
    })?;
    if let Some(reason) = local_verification_failure(&verifier_summary) {
        return Err(EvidenceError::VerificationFailed(format!(
            "fresh verification failed; refusing to export unverified evidence: {reason}"
        )));
    }
    if verifier_summary["overall"].as_str() != Some("success") {
        return Err(EvidenceError::VerificationFailed(format!(
            "fresh verification failed; refusing to export unverified evidence: overall-{}",
            verifier_summary["overall"].as_str().unwrap_or("failed")
        )));
    }

    let dest_root = options
        .evidence_repo
        .join("site")
        .join(&options.site)
        .join("day")
        .join(&options.day);
    if dest_root.exists() {
        fs::remove_dir_all(&dest_root)?;
    }
    fs::create_dir_all(&dest_root)?;

    copy_dir(
        &options.pipeline_dir.join(&manifest.facts_dir),
        &dest_root.join("facts"),
    )?;
    for artifact in manifest.artifacts.values() {
        let src = resolve_bundle_path(&options.pipeline_dir, &artifact.path)?;
        copy_file(&src, &dest_root.join(&artifact.path))?;
    }
    let exported_manifest = verify_manifest_path(&dest_root.join("day"), &options.day);
    copy_file(&manifest_path, &exported_manifest)?;

    if options.include_frames {
        let frames = manifest.frames_file.as_deref().ok_or_else(|| {
            EvidenceError::Invalid("verification manifest missing frames_file".to_string())
        })?;
        copy_file(
            &options.pipeline_dir.join(frames),
            &dest_root.join("frames.ndjson"),
        )?;
    }

    let source_meta = find_meta_sidecar(&options.pipeline_dir, &options.day)?;
    let mut meta: Value = read_json(&source_meta)?;
    if let Some(object) = meta.as_object_mut() {
        object.remove("milestone");
        object.insert(
            "artifact".to_string(),
            json!(format!("day/{}.cbor", options.day)),
        );
        object.insert(
            "ots_proof".to_string(),
            json!(format!("day/{}.cbor.ots", options.day)),
        );
    }
    let exported_meta = dest_root
        .join("day")
        .join(format!("{}.ots.meta.json", options.day));
    write_json(&exported_meta, &meta)?;

    let mut exported: Value = read_json(&exported_manifest)?;
    if !options.include_frames {
        exported.as_object_mut().unwrap().remove("frames_file");
    }
    exported["artifacts"]["day_ots_meta"] = artifact_ref(&exported_meta, &dest_root)?;
    exported["verifier"] = portable_summary(&verifier_summary);
    exported["verification_bundle"] =
        verification_bundle_from_summary(&verifier_summary, &manifest.verification_bundle);
    write_json(&exported_manifest, &exported)?;

    update_index(options, &dest_root, &exported_manifest)?;
    if options.git_commit || options.tag || options.bundle_out.is_some() {
        ensure_git_repo(&options.evidence_repo)?;
    }
    if options.git_commit || options.tag || options.bundle_out.is_some() {
        maybe_commit(options)?;
    }
    if options.tag {
        maybe_tag(options)?;
    }
    if let Some(bundle_out) = &options.bundle_out {
        if let Some(parent) = bundle_out.parent() {
            fs::create_dir_all(parent)?;
        }
        git(
            &options.evidence_repo,
            &["bundle", "create", &bundle_out.to_string_lossy(), "--all"],
        )?;
    }
    Ok(dest_root)
}

fn update_index(options: &ExportOptions, bundle_root: &Path, manifest_path: &Path) -> Result<()> {
    let index_path = options.evidence_repo.join("index.json");
    let mut index = if index_path.exists() {
        read_json::<Value>(&index_path)?
    } else {
        json!({"version": 1, "exports": []})
    };
    let exports = index["exports"]
        .as_array_mut()
        .ok_or_else(|| EvidenceError::Invalid("index.json exports must be an array".to_string()))?;
    exports.retain(|item| {
        item.get("site").and_then(Value::as_str) != Some(&options.site)
            || item.get("day").and_then(Value::as_str) != Some(&options.day)
    });
    let mut entry = json!({
        "site": options.site,
        "day": options.day,
        "bundle_root": bundle_root.strip_prefix(&options.evidence_repo).unwrap().to_string_lossy(),
        "manifest": manifest_path.strip_prefix(&options.evidence_repo).unwrap().to_string_lossy(),
        "frames_included": options.include_frames,
    });
    if options.tag {
        entry["tag"] = json!(tag_name(options));
    }
    exports.push(entry);
    exports.sort_by_key(|item| {
        format!(
            "{}:{}",
            item.get("site").and_then(Value::as_str).unwrap_or_default(),
            item.get("day").and_then(Value::as_str).unwrap_or_default()
        )
    });
    write_json(&index_path, &index)
}

fn tag_name(options: &ExportOptions) -> String {
    options
        .tag_name
        .clone()
        .unwrap_or_else(|| format!("evidence/{}/{}", options.site, options.day))
}

fn git(repo: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git").args(args).current_dir(repo).output()?;
    if !output.status.success() {
        return Err(EvidenceError::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn ensure_git_repo(repo: &Path) -> Result<()> {
    fs::create_dir_all(repo)?;
    if !repo.join(".git").exists() {
        git(repo, &["init"])?;
    }
    Ok(())
}

fn maybe_commit(options: &ExportOptions) -> Result<()> {
    if git(&options.evidence_repo, &["status", "--short"])?.is_empty() {
        return Ok(());
    }
    git(&options.evidence_repo, &["add", "."])?;
    let message = format!("evidence: {} {}", options.site, options.day);
    if options.sign {
        git(&options.evidence_repo, &["commit", "-S", "-m", &message])?;
    } else {
        git(
            &options.evidence_repo,
            &["-c", "commit.gpgsign=false", "commit", "-m", &message],
        )?;
    }
    Ok(())
}

fn maybe_tag(options: &ExportOptions) -> Result<()> {
    let tag = tag_name(options);
    if !git(&options.evidence_repo, &["tag", "--list", &tag])?.is_empty() {
        return Err(EvidenceError::Git(format!("tag already exists: {tag}")));
    }
    if options.sign {
        git(&options.evidence_repo, &["tag", "-s", &tag, "-m", &tag])?;
    } else {
        git(
            &options.evidence_repo,
            &["-c", "tag.gpgSign=false", "tag", "-a", &tag, "-m", &tag],
        )?;
    }
    Ok(())
}
