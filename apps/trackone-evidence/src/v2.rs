//! Verifier for draft-09 segment bundles owned by the evidence app.
use super::{EvidenceError, Result};
use flate2::{Compression, Crc, Decompress, FlushDecompress, GzBuilder, Status};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use trackone_ledger::{
    hex_lower, sha256_digest, sha256_hex,
    v2::{
        COMMITMENT_PROFILE_ID, ZERO_SHA256, decode_segment_record_v2, merkle_root_from_records,
        validate_canonical_record_v2,
    },
};
use trackone_rfc3161::{
    HistoricalValidationArchive, SignerCertificateSha256, VerificationPolicy, VerifiedTimestamp,
    verify_response,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactRef {
    path: String,
    sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    ledger_id: String,
    site_id: String,
    segment_number: String,
    commitment_profile_id: String,
    disclosure_class: String,
    artifacts: Artifacts,
    anchoring: Anchoring,
    // Legacy manifest-v2 field. Manifest v3 rejects it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operational_summary: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extensions: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Artifacts {
    segment_cbor: ArtifactRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    predecessor_segment_cbor: Option<ArtifactRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    records: Option<Vec<ArtifactRef>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    records_pack: Option<ArtifactRef>,
    // The following convenience projections are accepted only when reading
    // legacy manifest v2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    batches: Option<Vec<ArtifactRef>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    segment_json: Option<ArtifactRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    segment_sha256: Option<ArtifactRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    segment_ots: Option<ArtifactRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    segment_ots_meta: Option<ArtifactRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    peer_attest: Option<ArtifactRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tsa_info: Option<ArtifactRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tsa_tsr: Option<ArtifactRef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    extensions: BTreeMap<String, ArtifactRef>,
}

impl Artifacts {
    fn references(&self) -> Vec<&ArtifactRef> {
        let mut references = vec![&self.segment_cbor];
        references.extend(self.predecessor_segment_cbor.iter());
        references.extend(self.records.iter().flatten());
        references.extend(self.records_pack.iter());
        references.extend(self.batches.iter().flatten());
        references.extend(self.segment_json.iter());
        references.extend(self.segment_sha256.iter());
        references.extend(self.segment_ots.iter());
        references.extend(self.segment_ots_meta.iter());
        references.extend(self.peer_attest.iter());
        references.extend(self.tsa_info.iter());
        references.extend(self.tsa_tsr.iter());
        references.extend(self.extensions.values());
        references
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Anchoring {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tsa: Option<ChannelClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ots: Option<ChannelClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    peer: Option<ChannelClaim>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ChannelClaim {
    status: String,
}

#[derive(Clone, Debug)]
pub struct V2VerifyPolicy {
    pub enforce_disclosure_requirements: bool,
    pub require_tsa: bool,
    pub tsa_ca_file: Option<PathBuf>,
    pub tsa_intermediates_file: Option<PathBuf>,
    pub tsa_crls_file: Option<PathBuf>,
    pub tsa_policy_oid: Option<String>,
    pub tsa_signer_cert_sha256: Option<SignerCertificateSha256>,
    pub openssl_binary: PathBuf,
    pub verifier_policy_id: Option<String>,
    pub verifier_policy_artifact: Option<PathBuf>,
}

impl Default for V2VerifyPolicy {
    fn default() -> Self {
        Self {
            enforce_disclosure_requirements: false,
            require_tsa: false,
            tsa_ca_file: None,
            tsa_intermediates_file: None,
            tsa_crls_file: None,
            tsa_policy_oid: None,
            tsa_signer_cert_sha256: None,
            openssl_binary: PathBuf::from("openssl"),
            verifier_policy_id: Some("trackone-v2-permissive".to_string()),
            verifier_policy_artifact: None,
        }
    }
}

impl V2VerifyPolicy {
    pub fn baseline() -> Self {
        Self {
            enforce_disclosure_requirements: true,
            require_tsa: true,
            verifier_policy_id: Some("verifiable-telemetry-baseline-v2".to_string()),
            ..Self::default()
        }
    }
}

fn bad(message: impl Into<String>) -> EvidenceError {
    EvidenceError::Invalid(message.into())
}
fn valid_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
fn valid_uint64(value: &str) -> bool {
    !value.is_empty()
        && (value == "0" || (!value.starts_with('0') && value.bytes().all(|b| b.is_ascii_digit())))
        && value.parse::<u64>().is_ok()
}

fn validate_portable_path(rel: &str) -> Result<()> {
    if rel.is_empty()
        || rel.starts_with('/')
        || rel.starts_with('\\')
        || rel.contains('\\')
        || rel.contains(':')
        || rel.chars().any(|c| c.is_control())
    {
        return Err(bad("v2 manifest path is not portable"));
    }
    for component in Path::new(rel).components() {
        let Component::Normal(part) = component else {
            return Err(bad("v2 manifest path contains a dot or parent component"));
        };
        if part.is_empty() {
            return Err(bad("v2 manifest path contains an empty component"));
        }
    }
    Ok(())
}

fn read_file_bounded(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>> {
    read_handle_bounded(File::open(path)?, limit, label)
}

fn read_handle_bounded(file: File, limit: u64, label: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(bad(format!("{label} exceeds 64 MiB")));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn safe_read(root: &Path, rel: &str) -> Result<Vec<u8>> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};

    validate_portable_path(rel)?;
    let root = File::open(root)?;
    let descriptor = openat2(
        &root,
        rel,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::NOENT {
            EvidenceError::VerificationFailed(format!("referenced v2 artifact is missing: {rel}"))
        } else {
            bad(format!("cannot safely open v2 artifact {rel}: {error}"))
        }
    })?;
    read_handle_bounded(File::from(descriptor), MAX_ARCHIVE_MEMBER, "v2 artifact")
}

#[cfg(not(target_os = "linux"))]
fn safe_read(_root: &Path, rel: &str) -> Result<Vec<u8>> {
    validate_portable_path(rel)?;
    Err(bad(
        "race-resistant v2 manifest opening is unavailable on this platform",
    ))
}

fn artifact(root: &Path, reference: &ArtifactRef) -> Result<Vec<u8>> {
    if !valid_hex(&reference.sha256, 64) {
        return Err(bad("v2 artifact digest is not lowercase SHA-256"));
    }
    let bytes = safe_read(root, &reference.path)?;
    if sha256_hex(&bytes) != reference.sha256 {
        return Err(EvidenceError::VerificationFailed(
            "v2 artifact digest mismatch".to_string(),
        ));
    }
    Ok(bytes)
}

fn validate_manifest(manifest: &Manifest) -> Result<()> {
    if !matches!(manifest.version, 2 | 3)
        || manifest.commitment_profile_id != COMMITMENT_PROFILE_ID
        || !valid_hex(&manifest.ledger_id, 32)
        || manifest.site_id.is_empty()
        || !valid_uint64(&manifest.segment_number)
        || !matches!(manifest.disclosure_class.as_str(), "A" | "B" | "C")
    {
        return Err(bad("v2 manifest identity is invalid"));
    }
    if manifest.version == 2 && manifest.artifacts.records_pack.is_some() {
        return Err(bad("manifest v2 does not support records_pack"));
    }
    if manifest.version == 3
        && (manifest.operational_summary.is_some()
            || manifest.artifacts.batches.is_some()
            || manifest.artifacts.segment_json.is_some()
            || manifest.artifacts.segment_sha256.is_some()
            || manifest.artifacts.tsa_info.is_some())
    {
        return Err(bad(
            "manifest v3 contains a legacy convenience or operational field",
        ));
    }
    if manifest.version == 3
        && manifest.disclosure_class == "A"
        && manifest.artifacts.records.is_some()
        && manifest.artifacts.records_pack.is_some()
    {
        return Err(bad(
            "Class A manifest v3 cannot contain both records and records_pack",
        ));
    }
    for reference in manifest.artifacts.references() {
        validate_portable_path(&reference.path)?;
        if !valid_hex(&reference.sha256, 64) {
            return Err(bad("v2 artifact digest is not lowercase SHA-256"));
        }
    }
    for claim in [
        manifest.anchoring.tsa.as_ref(),
        manifest.anchoring.ots.as_ref(),
        manifest.anchoring.peer.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        let valid = if manifest.version == 3 {
            matches!(claim.status.as_str(), "present" | "pending")
        } else {
            matches!(
                claim.status.as_str(),
                "verified" | "pending" | "missing" | "failed" | "skipped" | "complete"
            )
        };
        if !valid {
            return Err(bad("v2 manifest anchoring status is unsupported"));
        }
    }
    if manifest.version == 3 {
        if manifest.artifacts.segment_ots.is_some() != manifest.artifacts.segment_ots_meta.is_some()
        {
            return Err(bad(
                "manifest v3 requires paired OTS proof and binding metadata",
            ));
        }
        validate_channel_artifact(
            "tsa",
            manifest.anchoring.tsa.as_ref(),
            manifest.artifacts.tsa_tsr.is_some(),
        )?;
        validate_channel_artifact(
            "ots",
            manifest.anchoring.ots.as_ref(),
            manifest.artifacts.segment_ots.is_some(),
        )?;
        validate_channel_artifact(
            "peer",
            manifest.anchoring.peer.as_ref(),
            manifest.artifacts.peer_attest.is_some(),
        )?;
    }
    Ok(())
}

fn validate_channel_artifact(
    name: &str,
    claim: Option<&ChannelClaim>,
    artifact_present: bool,
) -> Result<()> {
    match (claim.map(|claim| claim.status.as_str()), artifact_present) {
        (Some("present"), true) | (Some("pending"), false) | (None, false) => Ok(()),
        (Some("present"), false) => Err(bad(format!(
            "manifest v3 {name} channel claims present without evidence"
        ))),
        (Some("pending"), true) => Err(bad(format!(
            "manifest v3 {name} channel claims pending while evidence is present"
        ))),
        (None, true) => Err(bad(format!(
            "manifest v3 {name} evidence lacks a producer channel claim"
        ))),
        _ => Err(bad(format!(
            "manifest v3 {name} channel status is unsupported"
        ))),
    }
}

fn validate_verifier_policy(policy: &V2VerifyPolicy) -> Result<()> {
    let policy_id = policy
        .verifier_policy_id
        .as_deref()
        .ok_or_else(|| bad("verifier policy identifier is required"))?;
    if policy_id.is_empty() {
        return Err(bad("verifier policy identifier must not be empty"));
    }
    if !policy.require_tsa && policy_id == "verifiable-telemetry-baseline-v2" {
        return Err(bad(
            "a custom verifier policy identifier is required when TSA applicability changes",
        ));
    }
    if let Some(path) = &policy.verifier_policy_artifact
        && !path.is_file()
    {
        return Err(bad("verifier policy artifact is not available for hashing"));
    }
    Ok(())
}

fn verify_rfc3161(
    response: &[u8],
    artifact_sha256: [u8; 32],
    policy: &V2VerifyPolicy,
) -> Result<VerifiedTimestamp> {
    let ca_file = policy
        .tsa_ca_file
        .as_ref()
        .ok_or_else(|| bad("RFC 3161 trust anchor is not configured"))?;
    let policy_oid = policy
        .tsa_policy_oid
        .as_ref()
        .ok_or_else(|| bad("RFC 3161 TSA policy OID is not configured"))?;
    let crls_file = policy
        .tsa_crls_file
        .as_ref()
        .ok_or_else(|| bad("RFC 3161 historical CRL archive is not configured"))?;
    let signer_certificate_sha256 = policy
        .tsa_signer_cert_sha256
        .ok_or_else(|| bad("RFC 3161 signer certificate SHA-256 is not configured"))?;
    let verification_policy = VerificationPolicy::new(
        HistoricalValidationArchive {
            trust_anchors_file: ca_file.clone(),
            intermediates_file: policy.tsa_intermediates_file.clone(),
            crls_file: crls_file.clone(),
        },
        policy_oid,
        signer_certificate_sha256,
    )
    .map_err(|error| bad(error.to_string()))?
    .with_openssl_binary(policy.openssl_binary.clone());
    verify_response(response, artifact_sha256, &verification_policy)
        .map_err(|error| bad(error.to_string()))
}

/// Verify the portable v2 bundle envelope.  Segment CBOR and supplied record
/// artifacts are digest-bound here; the ledger crate owns the profile's exact
/// tree calculation used for Class A recomputation.
pub fn verify_v2_bundle(root: &Path) -> Result<Value> {
    verify_v2_bundle_with_policy(root, &V2VerifyPolicy::default())
}

pub fn verify_v2_bundle_with_policy(root: &Path, policy: &V2VerifyPolicy) -> Result<Value> {
    validate_verifier_policy(policy)?;
    let manifest_path = root.join("segment.verify.json");
    let manifest: Manifest = serde_json::from_slice(&read_file_bounded(
        &manifest_path,
        MAX_ARCHIVE_MEMBER,
        "v2 manifest",
    )?)?;
    validate_manifest(&manifest)?;
    let segment_bytes = safe_read(root, &manifest.artifacts.segment_cbor.path)?;
    let segment_digest_matches =
        sha256_hex(&segment_bytes) == manifest.artifacts.segment_cbor.sha256;
    let segment = decode_segment_record_v2(&segment_bytes)
        .map_err(|err| bad(format!("invalid v2 segment artifact: {err}")))?;
    let artifact_sha256 = sha256_hex(&segment_bytes);
    let scope = match manifest.disclosure_class.as_str() {
        "A" => "public_recompute",
        "B" => "partial_verification",
        _ => "anchor_only",
    };
    let result_context = VerificationResultContext {
        manifest: &manifest,
        policy,
        artifact_sha256: &artifact_sha256,
        scope,
    };
    let mut executed = vec![
        "bundle_disclosure_validation",
        "verification_manifest_validation",
        "segment_artifact_validation",
    ];
    let mut skipped = Vec::<Value>::new();
    let mut channels = serde_json::Map::new();
    if !segment_digest_matches {
        executed.push("segment_digest_binding");
        return verification_result(&result_context, executed, skipped, channels, "failure");
    }
    for reference in manifest.artifacts.references() {
        if reference.path == manifest.artifacts.segment_cbor.path {
            continue;
        }
        match artifact(root, reference) {
            Ok(_) => {}
            Err(EvidenceError::VerificationFailed(_)) => {
                executed.push("segment_digest_binding");
                return verification_result(
                    &result_context,
                    executed,
                    skipped,
                    channels,
                    "failure",
                );
            }
            Err(error) => return Err(error),
        }
    }
    if segment.ledger_id != manifest.ledger_id
        || segment.site_id != manifest.site_id
        || segment.segment_number.to_string() != manifest.segment_number
    {
        return verification_result(&result_context, executed, skipped, channels, "failure");
    }
    let has_tsa = manifest.artifacts.tsa_tsr.is_some();
    let has_ots =
        manifest.artifacts.segment_ots.is_some() && manifest.artifacts.segment_ots_meta.is_some();
    if policy.enforce_disclosure_requirements && !has_tsa && !has_ots {
        skipped.push(json!({
            "check": "segment_digest_binding",
            "reason": "missing_binding_metadata"
        }));
        return verification_result(&result_context, executed, skipped, channels, "failure");
    }
    if segment.segment_number == 0 {
        if segment.prev_segment_sha256 != ZERO_SHA256 {
            return verification_result(&result_context, executed, skipped, channels, "failure");
        }
        executed.push("segment_chain_validation");
    } else if let Some(predecessor) = &manifest.artifacts.predecessor_segment_cbor {
        let predecessor_bytes = artifact(root, predecessor)?;
        let previous = decode_segment_record_v2(&predecessor_bytes)
            .map_err(|err| bad(format!("invalid predecessor segment artifact: {err}")))?;
        if previous.ledger_id != segment.ledger_id
            || previous.site_id != segment.site_id
            || previous.segment_number.checked_add(1) != Some(segment.segment_number)
            || segment.prev_segment_sha256 != sha256_hex(&predecessor_bytes)
        {
            return verification_result(&result_context, executed, skipped, channels, "failure");
        }
        executed.push("segment_chain_validation");
    } else {
        skipped
            .push(json!({"check":"segment_chain_validation","reason":"predecessor_not_disclosed"}));
    }
    if manifest.disclosure_class == "A" {
        if manifest.artifacts.records.is_none() && manifest.artifacts.records_pack.is_none() {
            skipped
                .push(json!({"check":"record_level_recompute","reason":"records_not_disclosed"}));
            return verification_result(&result_context, executed, skipped, channels, "failure");
        }
        let bytes = disclosed_records(root, &manifest)?;
        let merkle = merkle_root_from_records(&bytes);
        let recomputed_root = merkle.root_hex();
        let recomputed_leaves = merkle
            .leaf_hashes
            .iter()
            .map(|hash| hex_lower(hash))
            .collect::<Vec<_>>();
        let embedded_leaves = segment
            .batches
            .iter()
            .flat_map(|batch| batch.leaf_hashes.iter().cloned())
            .collect::<Vec<_>>();
        if recomputed_leaves != embedded_leaves {
            executed.push("record_level_recompute");
            return verification_result(&result_context, executed, skipped, channels, "failure");
        }
        if recomputed_root != segment.segment_root {
            executed.push("record_level_recompute");
            return verification_result(&result_context, executed, skipped, channels, "failure");
        }
        executed.push("record_level_recompute");
        executed.push("batch_metadata_validation");
    } else {
        skipped.push(json!({
            "check":"record_level_recompute",
            "reason":format!("disclosure_class_{}", manifest.disclosure_class.to_ascii_lowercase())
        }));
        if manifest.disclosure_class == "C" {
            skipped.push(json!({"check":"batch_metadata_validation","reason":"out_of_scope"}));
        } else if let Some(batch_refs) = &manifest.artifacts.batches {
            validate_batch_projections(root, batch_refs, &segment)?;
            executed.push("batch_metadata_validation");
        } else {
            skipped.push(json!({"check":"batch_metadata_validation","reason":"not_disclosed"}));
        }
    }
    executed.push("segment_digest_binding");
    let channel_outcome = apply_timestamp_checks(
        root,
        &manifest,
        &segment_bytes,
        policy,
        &mut executed,
        &mut skipped,
        &mut channels,
    )?;
    let overall = if channel_outcome.failed {
        "failure"
    } else if channel_outcome.partial {
        "partial"
    } else {
        "success"
    };
    verification_result(&result_context, executed, skipped, channels, overall)
}

struct VerificationResultContext<'a> {
    manifest: &'a Manifest,
    policy: &'a V2VerifyPolicy,
    artifact_sha256: &'a str,
    scope: &'a str,
}

fn verification_result(
    context: &VerificationResultContext<'_>,
    executed: Vec<&'static str>,
    skipped: Vec<Value>,
    channels: serde_json::Map<String, Value>,
    overall: &str,
) -> Result<Value> {
    let mut result = serde_json::Map::from_iter([
        ("version".to_string(), json!(2)),
        (
            "artifact_sha256".to_string(),
            json!(context.artifact_sha256),
        ),
        (
            "commitment_profile_id".to_string(),
            json!(COMMITMENT_PROFILE_ID),
        ),
        (
            "disclosure_class".to_string(),
            json!(context.manifest.disclosure_class),
        ),
        ("verification_scope".to_string(), json!(context.scope)),
        ("checks_executed".to_string(), json!(executed)),
        ("checks_skipped".to_string(), Value::Array(skipped)),
        ("overall".to_string(), json!(overall)),
    ]);
    if !channels.is_empty() {
        result.insert("channels".to_string(), Value::Object(channels));
    }
    if let Some(policy_id) = &context.policy.verifier_policy_id {
        result.insert("verifier_policy_id".to_string(), json!(policy_id));
    }
    if let Some(path) = &context.policy.verifier_policy_artifact {
        result.insert(
            "verifier_policy_sha256".to_string(),
            json!(sha256_hex(&read_file_bounded(
                path,
                MAX_ARCHIVE_MEMBER,
                "verifier policy artifact"
            )?)),
        );
    }
    Ok(Value::Object(result))
}

fn disclosed_records(root: &Path, manifest: &Manifest) -> Result<Vec<Vec<u8>>> {
    let records = if let Some(references) = &manifest.artifacts.records {
        references
            .iter()
            .map(|reference| artifact(root, reference))
            .collect::<Result<Vec<_>>>()?
    } else if let Some(reference) = &manifest.artifacts.records_pack {
        decode_records_pack(&artifact(root, reference)?)?
    } else {
        return Err(bad("Class A requires disclosed records"));
    };
    for (index, record) in records.iter().enumerate() {
        validate_canonical_record_v2(record)
            .map_err(|err| bad(format!("invalid Class A canonical record {index}: {err}")))?;
    }
    Ok(records)
}

const MAX_PACKED_RECORDS: usize = 1_000_000;

fn record_leaf_hash(record: &[u8]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(record.len() + 1);
    bytes.push(0);
    bytes.extend_from_slice(record);
    sha256_digest(&bytes)
}

fn encode_records_pack(records: &mut [Vec<u8>]) -> Result<Vec<u8>> {
    records.sort_by_cached_key(|record| record_leaf_hash(record));
    let mut start = 0;
    while start < records.len() {
        let hash = record_leaf_hash(&records[start]);
        let mut end = start + 1;
        while end < records.len() && record_leaf_hash(&records[end]) == hash {
            end += 1;
        }
        records[start..end].sort_unstable();
        start = end;
    }
    let mut output = Vec::new();
    encode_cbor_head(
        4,
        u64::try_from(records.len()).map_err(|_| bad("record pack is too large"))?,
        &mut output,
    );
    for record in records {
        encode_cbor_head(
            2,
            u64::try_from(record.len()).map_err(|_| bad("record is too large"))?,
            &mut output,
        );
        output.extend_from_slice(record);
    }
    Ok(output)
}

fn decode_records_pack(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut offset = 0;
    let count = usize::try_from(decode_cbor_head(bytes, &mut offset, 4)?)
        .map_err(|_| bad("record pack count is too large"))?;
    if count > MAX_PACKED_RECORDS {
        return Err(bad("record pack count exceeds the supported limit"));
    }
    if count > bytes.len().saturating_sub(offset) {
        return Err(bad("record pack count exceeds remaining input"));
    }
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let length = usize::try_from(decode_cbor_head(bytes, &mut offset, 2)?)
            .map_err(|_| bad("packed record is too large"))?;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| bad("packed record length overflows"))?;
        records.push(
            bytes
                .get(offset..end)
                .ok_or_else(|| bad("record pack is truncated"))?
                .to_vec(),
        );
        offset = end;
    }
    if offset != bytes.len() {
        return Err(bad("record pack has trailing bytes"));
    }
    Ok(records)
}

fn encode_cbor_head(major: u8, value: u64, output: &mut Vec<u8>) {
    match value {
        0..=23 => output.push((major << 5) | value as u8),
        24..=0xff => output.extend_from_slice(&[(major << 5) | 24, value as u8]),
        0x100..=0xffff => {
            output.push((major << 5) | 25);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push((major << 5) | 26);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push((major << 5) | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn decode_cbor_head(bytes: &[u8], offset: &mut usize, major: u8) -> Result<u64> {
    let initial = *bytes
        .get(*offset)
        .ok_or_else(|| bad("record pack is truncated"))?;
    *offset += 1;
    if initial >> 5 != major {
        return Err(bad("record pack must be a definite array of byte strings"));
    }
    let info = initial & 31;
    let (value, width) = match info {
        value @ 0..=23 => (u64::from(value), 0),
        24 => (decode_uint(bytes, offset, 1)?, 1),
        25 => (decode_uint(bytes, offset, 2)?, 2),
        26 => (decode_uint(bytes, offset, 4)?, 4),
        27 => (decode_uint(bytes, offset, 8)?, 8),
        _ => return Err(bad("record pack uses an indefinite or reserved length")),
    };
    if (width == 1 && value < 24)
        || (width == 2 && value <= u64::from(u8::MAX))
        || (width == 4 && value <= u64::from(u16::MAX))
        || (width == 8 && value <= u64::from(u32::MAX))
    {
        return Err(bad("record pack length is not shortest-form"));
    }
    Ok(value)
}

fn decode_uint(bytes: &[u8], offset: &mut usize, width: usize) -> Result<u64> {
    let end = offset
        .checked_add(width)
        .ok_or_else(|| bad("record pack length overflows"))?;
    let slice = bytes
        .get(*offset..end)
        .ok_or_else(|| bad("record pack is truncated"))?;
    *offset = end;
    Ok(slice
        .iter()
        .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)))
}

fn validate_batch_projections(
    root: &Path,
    references: &[ArtifactRef],
    segment: &trackone_ledger::v2::SegmentRecordV2,
) -> Result<()> {
    if references.len() != segment.batches.len() {
        return Err(bad("standalone batch projection count mismatch"));
    }
    for (reference, batch) in references.iter().zip(&segment.batches) {
        let projection: Value = serde_json::from_slice(&artifact(root, reference)?)?;
        let expected = json!({
            "version": 2,
            "ledger_id": batch.ledger_id,
            "site_id": batch.site_id,
            "segment_number": batch.segment_number.to_string(),
            "batch_number": batch.batch_number.to_string(),
            "merkle_root": batch.merkle_root,
            "count": batch.count.to_string(),
            "leaf_hashes": batch.leaf_hashes,
        });
        if projection != expected {
            return Err(bad("standalone batch projection mismatch"));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
struct ChannelOutcome {
    failed: bool,
    partial: bool,
}

fn apply_timestamp_checks(
    root: &Path,
    manifest: &Manifest,
    segment_bytes: &[u8],
    policy: &V2VerifyPolicy,
    executed: &mut Vec<&'static str>,
    skipped: &mut Vec<Value>,
    channels: &mut serde_json::Map<String, Value>,
) -> Result<ChannelOutcome> {
    let mut outcome = ChannelOutcome::default();
    if let Some(reference) = &manifest.artifacts.tsa_tsr {
        validate_tsa_configuration(policy)?;
        let response = artifact(root, reference)?;
        executed.push("tsa_verification");
        match verify_rfc3161(&response, sha256_digest(segment_bytes), policy) {
            Ok(_) => {
                channels.insert(
                    "tsa".to_string(),
                    json!({"check":"tsa_verification","status":"verified"}),
                );
            }
            Err(error) => {
                channels.insert(
                    "tsa".to_string(),
                    json!({
                        "check":"tsa_verification",
                        "status":"failed",
                        "reason":error.to_string()
                    }),
                );
                outcome.failed = true;
            }
        }
    } else if manifest
        .anchoring
        .tsa
        .as_ref()
        .is_some_and(|claim| claim.status == "pending")
    {
        skipped.push(json!({"check":"tsa_verification","reason":"pending"}));
        channels.insert(
            "tsa".to_string(),
            json!({"check":"tsa_verification","status":"pending","reason":"producer_pending"}),
        );
        if policy.require_tsa {
            outcome.failed = true;
        } else {
            outcome.partial = true;
        }
    } else if policy.require_tsa {
        skipped.push(json!({"check":"tsa_verification","reason":"missing_proof"}));
        channels.insert(
            "tsa".to_string(),
            json!({"check":"tsa_verification","status":"missing","reason":"required_proof_missing"}),
        );
        outcome.failed = true;
    } else if manifest.anchoring.tsa.is_some() {
        skipped.push(json!({"check":"tsa_verification","reason":"missing_proof"}));
        channels.insert(
            "tsa".to_string(),
            json!({"check":"tsa_verification","status":"missing","reason":"selected_proof_missing"}),
        );
        outcome.partial = true;
    }

    if manifest.artifacts.segment_ots.is_some() || manifest.anchoring.ots.is_some() {
        let producer_status = manifest
            .anchoring
            .ots
            .as_ref()
            .map_or("missing", |claim| claim.status.as_str());
        let status = if producer_status == "pending" {
            "pending"
        } else if manifest.artifacts.segment_ots.is_some() {
            "skipped"
        } else {
            "missing"
        };
        skipped.push(json!({"check":"x-ots-verification","reason":status}));
        channels.insert(
            "ots".to_string(),
            json!({"check":"x-ots-verification","status":status,"reason":"optional_channel_not_verified"}),
        );
        outcome.partial = true;
    }
    if manifest.artifacts.peer_attest.is_some() || manifest.anchoring.peer.is_some() {
        let producer_status = manifest
            .anchoring
            .peer
            .as_ref()
            .map_or("missing", |claim| claim.status.as_str());
        let status = if producer_status == "pending" {
            "pending"
        } else if manifest.artifacts.peer_attest.is_some() {
            "skipped"
        } else {
            "missing"
        };
        skipped.push(json!({"check":"x-peer-quorum-verification","reason":status}));
        channels.insert(
            "peer".to_string(),
            json!({"check":"x-peer-quorum-verification","status":status,"reason":"optional_channel_not_verified"}),
        );
        outcome.partial = true;
    }
    Ok(outcome)
}

fn validate_tsa_configuration(policy: &V2VerifyPolicy) -> Result<()> {
    if policy.tsa_ca_file.is_none()
        || policy.tsa_crls_file.is_none()
        || policy.tsa_policy_oid.is_none()
        || policy.tsa_signer_cert_sha256.is_none()
    {
        return Err(bad(
            "RFC 3161 verifier policy is incomplete for the selected TSA channel",
        ));
    }
    Ok(())
}

const MAX_ARCHIVE_MEMBERS: usize = 10_000;
const MAX_COMPRESSED_ARCHIVE: u64 = 64 * 1024 * 1024;
const MAX_EXPANDED_ARCHIVE: u64 = 256 * 1024 * 1024;
const MAX_ARCHIVE_MEMBER: u64 = 64 * 1024 * 1024;

fn retain_artifact(
    root: &Path,
    members: &mut BTreeMap<String, Vec<u8>>,
    reference: &ArtifactRef,
) -> Result<ArtifactRef> {
    members.insert(reference.path.clone(), artifact(root, reference)?);
    Ok(reference.clone())
}

/// Verify a source bundle and emit its v2 commitments in a compact manifest-v3
/// deterministic gzip carrier.
pub fn compact_v2_bundle(
    root: &Path,
    output: &Path,
    policy: &V2VerifyPolicy,
    include_extensions: bool,
) -> Result<()> {
    let verification = verify_v2_bundle_with_policy(root, policy)?;
    if !matches!(
        verification["overall"].as_str(),
        Some("success" | "partial")
    ) {
        return Err(EvidenceError::VerificationFailed(format!(
            "compact requires non-failing source verification, got {}",
            verification["overall"]
        )));
    }
    let mut manifest: Manifest = serde_json::from_slice(&read_file_bounded(
        &root.join("segment.verify.json"),
        MAX_ARCHIVE_MEMBER,
        "v2 manifest",
    )?)?;
    validate_manifest(&manifest)?;
    let mut members = BTreeMap::<String, Vec<u8>>::new();
    let records_pack = if manifest.disclosure_class == "A" {
        let mut records = disclosed_records(root, &manifest)?;
        let pack = encode_records_pack(&mut records)?;
        let reference = ArtifactRef {
            path: "records.pack.cbor".to_string(),
            sha256: sha256_hex(&pack),
        };
        members.insert(reference.path.clone(), pack);
        Some(reference)
    } else {
        None
    };
    let mut extensions = BTreeMap::new();
    if include_extensions {
        for (name, reference) in &manifest.artifacts.extensions {
            extensions.insert(
                name.clone(),
                retain_artifact(root, &mut members, reference)?,
            );
        }
    }
    let compact_artifacts = Artifacts {
        segment_cbor: retain_artifact(root, &mut members, &manifest.artifacts.segment_cbor)?,
        predecessor_segment_cbor: manifest
            .artifacts
            .predecessor_segment_cbor
            .as_ref()
            .map(|reference| retain_artifact(root, &mut members, reference))
            .transpose()?,
        records: None,
        records_pack,
        batches: None,
        segment_json: None,
        segment_sha256: None,
        segment_ots: manifest
            .artifacts
            .segment_ots
            .as_ref()
            .map(|reference| retain_artifact(root, &mut members, reference))
            .transpose()?,
        segment_ots_meta: manifest
            .artifacts
            .segment_ots_meta
            .as_ref()
            .map(|reference| retain_artifact(root, &mut members, reference))
            .transpose()?,
        peer_attest: manifest
            .artifacts
            .peer_attest
            .as_ref()
            .map(|reference| retain_artifact(root, &mut members, reference))
            .transpose()?,
        tsa_info: None,
        tsa_tsr: manifest
            .artifacts
            .tsa_tsr
            .as_ref()
            .map(|reference| retain_artifact(root, &mut members, reference))
            .transpose()?,
        extensions,
    };
    manifest.version = 3;
    manifest.artifacts = compact_artifacts;
    manifest.operational_summary = None;
    manifest.anchoring = Anchoring {
        tsa: channel_claim_for_artifact(
            manifest.artifacts.tsa_tsr.is_some(),
            manifest.anchoring.tsa.as_ref(),
        ),
        ots: channel_claim_for_artifact(
            manifest.artifacts.segment_ots.is_some(),
            manifest.anchoring.ots.as_ref(),
        ),
        peer: channel_claim_for_artifact(
            manifest.artifacts.peer_attest.is_some(),
            manifest.anchoring.peer.as_ref(),
        ),
    };
    if !include_extensions {
        manifest.extensions = None;
    }
    validate_manifest(&manifest)?;
    members.insert(
        "segment.verify.json".to_string(),
        serde_json::to_vec(&manifest)?,
    );
    write_deterministic_archive(output, &members)
}

fn channel_claim_for_artifact(
    artifact_present: bool,
    previous: Option<&ChannelClaim>,
) -> Option<ChannelClaim> {
    if artifact_present {
        Some(ChannelClaim {
            status: "present".to_string(),
        })
    } else if previous.is_some_and(|claim| claim.status == "pending") {
        Some(ChannelClaim {
            status: "pending".to_string(),
        })
    } else {
        None
    }
}

fn write_deterministic_archive(output: &Path, members: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    let gzip = GzBuilder::new()
        .mtime(0)
        .write(File::create(output)?, Compression::best());
    let mut archive = tar::Builder::new(gzip);
    archive.mode(tar::HeaderMode::Deterministic);
    for (path, bytes) in members {
        validate_portable_path(path)?;
        let mut header = tar::Header::new_ustar();
        header.set_size(u64::try_from(bytes.len()).map_err(|_| bad("artifact is too large"))?);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        archive.append_data(&mut header, path, Cursor::new(bytes))?;
    }
    let gzip = archive.into_inner()?;
    gzip.finish()?;
    Ok(())
}

/// Safely extract and verify a compact v3 gzip carrier with fixed resource
/// bounds. Only regular files with portable, unique paths are accepted.
pub fn verify_v2_archive(archive_path: &Path, policy: &V2VerifyPolicy) -> Result<Value> {
    if fs::metadata(archive_path)?.len() > MAX_COMPRESSED_ARCHIVE {
        return Err(bad("compressed archive exceeds 64 MiB"));
    }
    let input = read_file_bounded(archive_path, MAX_COMPRESSED_ARCHIVE, "compressed archive")?;
    let expanded = expand_single_gzip_member(&input, MAX_EXPANDED_ARCHIVE)?;
    let temporary = tempfile::tempdir()?;
    let mut archive = tar::Archive::new(Cursor::new(expanded));
    let mut paths = BTreeSet::new();
    let mut count = 0_usize;
    for entry in archive.entries()? {
        let mut entry = entry?;
        count += 1;
        if count > MAX_ARCHIVE_MEMBERS {
            return Err(bad("archive contains more than 10000 members"));
        }
        if !entry.header().entry_type().is_file() {
            return Err(bad("archive contains a non-regular member"));
        }
        if entry.size() > MAX_ARCHIVE_MEMBER {
            return Err(bad("archive member exceeds 64 MiB"));
        }
        let path = entry
            .path()?
            .to_str()
            .ok_or_else(|| bad("archive path is not UTF-8"))?
            .to_string();
        validate_portable_path(&path)?;
        if !paths.insert(path.clone()) {
            return Err(bad("archive contains a duplicate path"));
        }
        let destination = temporary.path().join(path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = File::create(destination)?;
        std::io::copy(&mut entry, &mut file)?;
        file.flush()?;
    }
    verify_v2_bundle_with_policy(temporary.path(), policy)
}

fn expand_single_gzip_member(input: &[u8], limit: u64) -> Result<Vec<u8>> {
    let offset = gzip_deflate_offset(input)?;
    let limit =
        usize::try_from(limit).map_err(|_| bad("gzip expansion limit overflows platform"))?;
    let mut decompressor = Decompress::new(false);
    let mut expanded = Vec::new();
    let mut crc = Crc::new();
    let mut scratch = [0_u8; 8192];
    loop {
        let before_in = decompressor.total_in();
        let before_out = decompressor.total_out();
        let remaining = limit.saturating_sub(expanded.len()).saturating_add(1);
        let output_width = remaining.min(scratch.len());
        let consumed = usize::try_from(before_in).map_err(|_| bad("gzip stream is too large"))?;
        let input_offset = offset
            .checked_add(consumed)
            .ok_or_else(|| bad("gzip member length overflows"))?;
        let status = decompressor
            .decompress(
                input
                    .get(input_offset..)
                    .ok_or_else(|| bad("gzip deflate stream is truncated"))?,
                &mut scratch[..output_width],
                FlushDecompress::None,
            )
            .map_err(|_| bad("gzip deflate stream is malformed"))?;
        let produced = usize::try_from(decompressor.total_out() - before_out)
            .map_err(|_| bad("gzip output is too large"))?;
        crc.update(&scratch[..produced]);
        expanded.extend_from_slice(&scratch[..produced]);
        if expanded.len() > limit {
            return Err(bad("expanded archive exceeds 256 MiB"));
        }
        if status == Status::StreamEnd {
            break;
        }
        if decompressor.total_in() == before_in && decompressor.total_out() == before_out {
            return Err(bad("gzip deflate stream is truncated"));
        }
    }
    let consumed =
        usize::try_from(decompressor.total_in()).map_err(|_| bad("gzip stream is too large"))?;
    let trailer = offset
        .checked_add(consumed)
        .ok_or_else(|| bad("gzip member length overflows"))?;
    let expected_end = trailer
        .checked_add(8)
        .ok_or_else(|| bad("gzip member length overflows"))?;
    if expected_end != input.len() {
        return Err(bad("gzip carrier has trailing data or multiple members"));
    }
    let expected_crc = u32::from_le_bytes(
        input[trailer..trailer + 4]
            .try_into()
            .expect("checked gzip trailer"),
    );
    let expected_size = u32::from_le_bytes(
        input[trailer + 4..expected_end]
            .try_into()
            .expect("checked gzip trailer"),
    );
    if crc.sum() != expected_crc || crc.amount() != expected_size {
        return Err(bad("gzip data checksum or size is invalid"));
    }
    Ok(expanded)
}

fn gzip_deflate_offset(input: &[u8]) -> Result<usize> {
    if input.len() < 18 || input.get(0..3) != Some(&[0x1f, 0x8b, 8]) {
        return Err(bad("archive is not a gzip carrier"));
    }
    let flags = input[3];
    if flags & 0xe0 != 0 {
        return Err(bad("gzip carrier uses reserved flags"));
    }
    let mut offset = 10_usize;
    if flags & 0x04 != 0 {
        let length_bytes = input
            .get(offset..offset + 2)
            .ok_or_else(|| bad("gzip extra field is truncated"))?;
        offset += 2;
        let length = usize::from(u16::from_le_bytes([length_bytes[0], length_bytes[1]]));
        offset = offset
            .checked_add(length)
            .ok_or_else(|| bad("gzip extra field overflows"))?;
        if offset > input.len() {
            return Err(bad("gzip extra field is truncated"));
        }
    }
    for flag in [0x08, 0x10] {
        if flags & flag != 0 {
            let tail = input
                .get(offset..)
                .ok_or_else(|| bad("gzip header is truncated"))?;
            let end = tail
                .iter()
                .position(|byte| *byte == 0)
                .ok_or_else(|| bad("gzip string field is unterminated"))?;
            offset += end + 1;
        }
    }
    if flags & 0x02 != 0 {
        let expected = input
            .get(offset..offset + 2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
            .ok_or_else(|| bad("gzip header checksum is truncated"))?;
        let mut crc = Crc::new();
        crc.update(&input[..offset]);
        if crc.sum() as u16 != expected {
            return Err(bad("gzip header checksum is invalid"));
        }
        offset = offset
            .checked_add(2)
            .ok_or_else(|| bad("gzip header overflows"))?;
    }
    if offset + 8 > input.len() {
        return Err(bad("gzip carrier is truncated"));
    }
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trackone_ledger::v2::{
        ClosurePolicyV1, EmptyMode, SegmentBatchV2, SegmentRecordV2, merkle_root_from_records,
    };

    fn epoch_segment_bytes() -> Vec<u8> {
        let record = vec![vec![
            0x87, 0x01, 0x48, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0x00, 0xf6, 0x00, 0xf6,
        ]];
        let merkle = merkle_root_from_records(&record);
        let leaf = trackone_ledger::hex_lower(&merkle.leaf_hashes[0]);
        SegmentRecordV2::new_epoch(
            "b7a1d5e40c6f438e9a75db27c96f31aa",
            "an-001",
            ClosurePolicyV1 {
                interval_ms: 60_000,
                batch_record_limit: 1,
                record_limit: None,
                size_limit_bytes: None,
                empty_mode: EmptyMode::Suppress,
            },
            "interval",
            vec![SegmentBatchV2 {
                ledger_id: String::new(),
                site_id: String::new(),
                segment_number: u64::MAX,
                batch_number: u64::MAX,
                merkle_root: leaf.clone(),
                count: 1,
                leaf_hashes: vec![leaf],
            }],
            merkle.root_hex(),
        )
        .unwrap()
        .canonical_cbor_bytes()
        .unwrap()
    }

    fn successor_segment_bytes(predecessor: &[u8]) -> Vec<u8> {
        let record = vec![vec![
            0x87, 0x01, 0x48, 0, 0, 0, 0, 0, 0, 0, 2, 0x02, 0x00, 0xf6, 0x00, 0xf6,
        ]];
        let merkle = merkle_root_from_records(&record);
        let leaf = trackone_ledger::hex_lower(&merkle.leaf_hashes[0]);
        SegmentRecordV2::new_successor(
            predecessor,
            ClosurePolicyV1 {
                interval_ms: 60_000,
                batch_record_limit: 1,
                record_limit: None,
                size_limit_bytes: None,
                empty_mode: EmptyMode::Suppress,
            },
            "interval",
            vec![SegmentBatchV2 {
                ledger_id: String::new(),
                site_id: String::new(),
                segment_number: u64::MAX,
                batch_number: u64::MAX,
                merkle_root: leaf.clone(),
                count: 1,
                leaf_hashes: vec![leaf],
            }],
            merkle.root_hex(),
        )
        .unwrap()
        .canonical_cbor_bytes()
        .unwrap()
    }

    fn empty_epoch_segment_bytes() -> Vec<u8> {
        SegmentRecordV2::new_epoch(
            "b7a1d5e40c6f438e9a75db27c96f31aa",
            "an-001",
            ClosurePolicyV1 {
                interval_ms: 60_000,
                batch_record_limit: 1,
                record_limit: None,
                size_limit_bytes: None,
                empty_mode: EmptyMode::Emit,
            },
            "interval",
            Vec::new(),
            sha256_hex(b""),
        )
        .unwrap()
        .canonical_cbor_bytes()
        .unwrap()
    }

    #[test]
    fn record_pack_preserves_duplicates_and_rejects_noncanonical_lengths() {
        let duplicate = vec![
            0x87, 0x01, 0x48, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0xf6, 0, 0xf6,
        ];
        let other = vec![
            0x87, 0x01, 0x48, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0xf6, 0, 0xf6,
        ];
        let mut records = vec![duplicate.clone(), other, duplicate.clone()];
        let encoded = encode_records_pack(&mut records).unwrap();
        let decoded = decode_records_pack(&encoded).unwrap();
        assert_eq!(
            decoded
                .iter()
                .filter(|record| **record == duplicate)
                .count(),
            2
        );
        assert!(decode_records_pack(&[0x98, 0x01, 0x40]).is_err());
    }

    #[test]
    fn record_pack_uses_v2_leaf_order_and_bounds_declared_count() {
        let mut inversion = None;
        'outer: for left in 0_u8..=u8::MAX {
            for right in left.saturating_add(1)..=u8::MAX {
                let left = vec![left];
                let right = vec![right];
                if sha256_digest(&left).cmp(&sha256_digest(&right))
                    != record_leaf_hash(&left).cmp(&record_leaf_hash(&right))
                {
                    inversion = Some((left, right));
                    break 'outer;
                }
            }
        }
        let (left, right) = inversion.expect("test inputs contain a raw/leaf hash inversion");
        let mut records = if sha256_digest(&left) < sha256_digest(&right) {
            vec![left.clone(), right.clone()]
        } else {
            vec![right.clone(), left.clone()]
        };
        let expected = if record_leaf_hash(&left) < record_leaf_hash(&right) {
            vec![left, right]
        } else {
            vec![right, left]
        };
        assert_ne!(records, expected);
        let encoded = encode_records_pack(&mut records).unwrap();
        assert_eq!(decode_records_pack(&encoded).unwrap(), expected);

        let mut oversized = Vec::new();
        encode_cbor_head(4, MAX_PACKED_RECORDS as u64 + 1, &mut oversized);
        assert!(decode_records_pack(&oversized).is_err());
        assert!(decode_records_pack(&[0x82, 0x40]).is_err());
    }

    #[test]
    fn deterministic_archive_bytes_have_one_bounded_gzip_member() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first.gz");
        let second = root.path().join("second.gz");
        let members = BTreeMap::from([
            ("a".to_string(), b"one".to_vec()),
            ("z/path".to_string(), b"two".to_vec()),
        ]);
        write_deterministic_archive(&first, &members).unwrap();
        write_deterministic_archive(&second, &members).unwrap();
        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
        let compressed = fs::read(&first).unwrap();
        assert!(
            !expand_single_gzip_member(&compressed, MAX_EXPANDED_ARCHIVE)
                .unwrap()
                .is_empty()
        );
        let mut trailing = compressed.clone();
        trailing.push(0);
        assert!(expand_single_gzip_member(&trailing, MAX_EXPANDED_ARCHIVE).is_err());

        let mut corrupt = compressed.clone();
        let trailer = corrupt.len() - 8;
        corrupt[trailer] ^= 0x01;
        assert!(expand_single_gzip_member(&corrupt, MAX_EXPANDED_ARCHIVE).is_err());

        let mut multiple = compressed.clone();
        multiple.extend_from_slice(&compressed);
        assert!(expand_single_gzip_member(&multiple, MAX_EXPANDED_ARCHIVE).is_err());
        assert!(expand_single_gzip_member(&compressed, 1).is_err());
    }

    #[test]
    fn v2_bundle_rejects_nonportable_segment_path() {
        let root = std::env::temp_dir().join(format!("trackone-v2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let manifest = json!({
            "version": 2, "ledger_id": "a".repeat(32), "site_id": "test",
            "segment_number": "0", "commitment_profile_id": COMMITMENT_PROFILE_ID,
            "disclosure_class": "C", "anchoring": {},
            "artifacts": {"segment_cbor": {"path": "../segment.cbor", "sha256": "a".repeat(64)}}
        });
        fs::write(
            root.join("segment.verify.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(verify_v2_bundle(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn v2_bundle_decodes_authoritative_epoch_artifact() {
        let root = std::env::temp_dir().join(format!("trackone-v2-valid-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let segment = epoch_segment_bytes();
        fs::write(root.join("segment.cbor"), &segment).unwrap();
        let manifest = json!({
            "version": 2, "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa", "site_id": "an-001",
            "segment_number": "0", "commitment_profile_id": COMMITMENT_PROFILE_ID,
            "disclosure_class": "C", "anchoring": {},
            "artifacts": {"segment_cbor": {"path": "segment.cbor", "sha256": sha256_hex(&segment)}}
        });
        fs::write(
            root.join("segment.verify.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let result = verify_v2_bundle(&root).unwrap();
        assert_eq!(result["overall"], "success");
        assert!(result.get("channels").is_none());
        assert!(
            result["checks_executed"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "segment_chain_validation")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_v3_rejects_legacy_convenience_fields_and_mixed_record_forms() {
        let base = json!({
            "version": 3,
            "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
            "site_id": "an-001",
            "segment_number": "0",
            "commitment_profile_id": COMMITMENT_PROFILE_ID,
            "disclosure_class": "A",
            "anchoring": {},
            "artifacts": {
                "segment_cbor": {"path": "segment.cbor", "sha256": "0".repeat(64)},
                "records": [],
                "records_pack": {"path": "records.pack.cbor", "sha256": "0".repeat(64)}
            }
        });
        let manifest: Manifest = serde_json::from_value(base).unwrap();
        assert!(validate_manifest(&manifest).is_err());

        let legacy_projection = json!({
            "version": 3,
            "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
            "site_id": "an-001",
            "segment_number": "0",
            "commitment_profile_id": COMMITMENT_PROFILE_ID,
            "disclosure_class": "C",
            "anchoring": {},
            "artifacts": {
                "segment_cbor": {"path": "segment.cbor", "sha256": "0".repeat(64)},
                "segment_json": {"path": "segment.json", "sha256": "0".repeat(64)}
            }
        });
        let manifest: Manifest = serde_json::from_value(legacy_projection).unwrap();
        assert!(validate_manifest(&manifest).is_err());
    }

    #[test]
    fn applicability_change_requires_a_distinct_policy_identifier() {
        let mut policy = V2VerifyPolicy::baseline();
        policy.require_tsa = false;
        assert!(validate_verifier_policy(&policy).is_err());
        policy.verifier_policy_id = Some("local-no-tsa-policy".to_string());
        assert!(validate_verifier_policy(&policy).is_ok());
        policy.verifier_policy_artifact = Some(PathBuf::from("missing-policy.json"));
        assert!(validate_verifier_policy(&policy).is_err());
    }

    #[test]
    fn selected_pending_channel_is_partial_but_unselected_channels_are_ignored() {
        let root = std::env::temp_dir().join(format!(
            "trackone-v3-pending-channel-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let segment = epoch_segment_bytes();
        fs::write(root.join("segment.cbor"), &segment).unwrap();
        let manifest = json!({
            "version": 3,
            "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
            "site_id": "an-001",
            "segment_number": "0",
            "commitment_profile_id": COMMITMENT_PROFILE_ID,
            "disclosure_class": "C",
            "anchoring": {"tsa": {"status": "pending"}},
            "artifacts": {
                "segment_cbor": {"path": "segment.cbor", "sha256": sha256_hex(&segment)}
            }
        });
        fs::write(
            root.join("segment.verify.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let result = verify_v2_bundle(&root).unwrap();
        assert_eq!(result["overall"], "partial");
        assert_eq!(result["channels"]["tsa"]["status"], "pending");
        assert!(result["channels"].get("peer").is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn compaction_accepts_and_retains_partial_optional_channels() {
        let root = tempfile::tempdir().unwrap();
        let segment = epoch_segment_bytes();
        let ots = b"pending ots proof";
        let ots_meta = b"ots binding metadata";
        let peer = b"peer attestation";
        fs::write(root.path().join("segment.cbor"), &segment).unwrap();
        fs::write(root.path().join("segment.ots"), ots).unwrap();
        fs::write(root.path().join("segment.ots.json"), ots_meta).unwrap();
        fs::write(root.path().join("peer.attest"), peer).unwrap();
        let manifest = json!({
            "version": 2,
            "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
            "site_id": "an-001",
            "segment_number": "0",
            "commitment_profile_id": COMMITMENT_PROFILE_ID,
            "disclosure_class": "C",
            "anchoring": {},
            "artifacts": {
                "segment_cbor": {
                    "path": "segment.cbor",
                    "sha256": sha256_hex(&segment)
                },
                "segment_ots": {
                    "path": "segment.ots",
                    "sha256": sha256_hex(ots)
                },
                "segment_ots_meta": {
                    "path": "segment.ots.json",
                    "sha256": sha256_hex(ots_meta)
                },
                "peer_attest": {
                    "path": "peer.attest",
                    "sha256": sha256_hex(peer)
                }
            }
        });
        fs::write(
            root.path().join("segment.verify.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let output = root.path().join("compact.tar.gz");

        compact_v2_bundle(root.path(), &output, &V2VerifyPolicy::default(), false).unwrap();

        let result = verify_v2_archive(&output, &V2VerifyPolicy::default()).unwrap();
        assert_eq!(result["overall"], "partial");
        assert_eq!(result["channels"]["ots"]["status"], "skipped");
        assert_eq!(result["channels"]["peer"]["status"], "skipped");
    }

    #[test]
    fn compaction_accepts_and_retains_pending_channel_claims() {
        let root = tempfile::tempdir().unwrap();
        let segment = epoch_segment_bytes();
        fs::write(root.path().join("segment.cbor"), &segment).unwrap();
        let manifest = json!({
            "version": 2,
            "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
            "site_id": "an-001",
            "segment_number": "0",
            "commitment_profile_id": COMMITMENT_PROFILE_ID,
            "disclosure_class": "C",
            "anchoring": {
                "ots": {"status": "pending"},
                "peer": {"status": "pending"}
            },
            "artifacts": {
                "segment_cbor": {
                    "path": "segment.cbor",
                    "sha256": sha256_hex(&segment)
                }
            }
        });
        fs::write(
            root.path().join("segment.verify.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let output = root.path().join("compact.tar.gz");

        compact_v2_bundle(root.path(), &output, &V2VerifyPolicy::default(), false).unwrap();

        let result = verify_v2_archive(&output, &V2VerifyPolicy::default()).unwrap();
        assert_eq!(result["overall"], "partial");
        assert_eq!(result["channels"]["ots"]["status"], "pending");
        assert_eq!(result["channels"]["peer"]["status"], "pending");
    }

    #[test]
    fn class_a_missing_records_returns_a_structured_failure() {
        let root = std::env::temp_dir().join(format!(
            "trackone-v3-missing-records-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let segment = epoch_segment_bytes();
        fs::write(root.join("segment.cbor"), &segment).unwrap();
        let manifest = json!({
            "version": 3,
            "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
            "site_id": "an-001",
            "segment_number": "0",
            "commitment_profile_id": COMMITMENT_PROFILE_ID,
            "disclosure_class": "A",
            "anchoring": {},
            "artifacts": {
                "segment_cbor": {"path": "segment.cbor", "sha256": sha256_hex(&segment)}
            }
        });
        fs::write(
            root.join("segment.verify.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let result = verify_v2_bundle(&root).unwrap();
        assert_eq!(result["overall"], "failure");
        assert_eq!(
            result["checks_skipped"][0]["reason"],
            "records_not_disclosed"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn v2_bundle_rejects_profile_text_without_segment_cbor() {
        let root =
            std::env::temp_dir().join(format!("trackone-v2-profile-text-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let segment = COMMITMENT_PROFILE_ID.as_bytes();
        fs::write(root.join("segment.cbor"), segment).unwrap();
        let manifest = json!({
            "version": 2, "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa", "site_id": "an-001",
            "segment_number": "0", "commitment_profile_id": COMMITMENT_PROFILE_ID,
            "disclosure_class": "C", "anchoring": {},
            "artifacts": {"segment_cbor": {"path": "segment.cbor", "sha256": sha256_hex(segment)}}
        });
        fs::write(
            root.join("segment.verify.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(verify_v2_bundle(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn v2_bundle_validates_decoded_successor_linkage() {
        let root = std::env::temp_dir().join(format!("trackone-v2-chain-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let predecessor = epoch_segment_bytes();
        let successor = successor_segment_bytes(&predecessor);
        fs::write(root.join("segment-0.cbor"), &predecessor).unwrap();
        fs::write(root.join("segment-1.cbor"), &successor).unwrap();
        let manifest = json!({
            "version": 2, "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa", "site_id": "an-001",
            "segment_number": "1", "commitment_profile_id": COMMITMENT_PROFILE_ID,
            "disclosure_class": "C", "anchoring": {}, "artifacts": {
                "segment_cbor": {"path": "segment-1.cbor", "sha256": sha256_hex(&successor)},
                "predecessor_segment_cbor": {"path": "segment-0.cbor", "sha256": sha256_hex(&predecessor)}
            }
        });
        fs::write(
            root.join("segment.verify.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(verify_v2_bundle(&root).is_ok());
        fs::write(root.join("segment-0.cbor"), b"unrelated bytes").unwrap();
        assert_eq!(
            verify_v2_bundle(&root).unwrap()["overall"],
            Value::String("failure".to_string())
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn class_a_rejects_records_that_do_not_match_the_segment_root() {
        let root = std::env::temp_dir().join(format!(
            "trackone-v2-class-a-mismatch-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let segment = epoch_segment_bytes();
        let replacement = [0x80];
        fs::write(root.join("segment.cbor"), &segment).unwrap();
        fs::write(root.join("record.cbor"), replacement).unwrap();
        let manifest = json!({
            "version": 2, "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa", "site_id": "an-001",
            "segment_number": "0", "commitment_profile_id": COMMITMENT_PROFILE_ID,
            "disclosure_class": "A", "anchoring": {}, "artifacts": {
                "segment_cbor": {"path": "segment.cbor", "sha256": sha256_hex(&segment)},
                "records": [{"path": "record.cbor", "sha256": sha256_hex(&replacement)}]
            }
        });
        fs::write(
            root.join("segment.verify.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify_v2_bundle(&root),
            Err(EvidenceError::Invalid(message)) if message.contains("invalid Class A canonical record")
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn class_a_validates_records_against_embedded_batch_leaves() {
        let root =
            std::env::temp_dir().join(format!("trackone-v2-class-a-valid-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let segment = epoch_segment_bytes();
        let record = [
            0x87, 0x01, 0x48, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0x00, 0xf6, 0x00, 0xf6,
        ];
        fs::write(root.join("segment.cbor"), &segment).unwrap();
        fs::write(root.join("record.cbor"), record).unwrap();
        let manifest = json!({
            "version": 2, "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa", "site_id": "an-001",
            "segment_number": "0", "commitment_profile_id": COMMITMENT_PROFILE_ID,
            "disclosure_class": "A", "anchoring": {}, "artifacts": {
                "segment_cbor": {"path": "segment.cbor", "sha256": sha256_hex(&segment)},
                "records": [{"path": "record.cbor", "sha256": sha256_hex(&record)}]
            }
        });
        fs::write(
            root.join("segment.verify.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let result = verify_v2_bundle(&root).unwrap();
        assert!(
            result["checks_executed"]
                .as_array()
                .unwrap()
                .iter()
                .any(|check| check == "batch_metadata_validation")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn class_a_accepts_an_empty_emitted_segment_with_no_records() {
        let root =
            std::env::temp_dir().join(format!("trackone-v2-class-a-empty-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let segment = empty_epoch_segment_bytes();
        fs::write(root.join("segment.cbor"), &segment).unwrap();
        let manifest = json!({
            "version": 2, "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa", "site_id": "an-001",
            "segment_number": "0", "commitment_profile_id": COMMITMENT_PROFILE_ID,
            "disclosure_class": "A", "anchoring": {}, "artifacts": {
                "segment_cbor": {"path": "segment.cbor", "sha256": sha256_hex(&segment)},
                "records": []
            }
        });
        fs::write(
            root.join("segment.verify.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(verify_v2_bundle(&root).is_ok());
        fs::remove_dir_all(root).unwrap();
    }
}
