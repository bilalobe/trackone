//! Additive verifier for draft-08 segment bundles owned by the evidence app.
use super::{EvidenceError, Result};
use flate2::{Compression, Decompress, FlushDecompress, GzBuilder, Status, read::GzDecoder};
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
    HistoricalValidationArchive, SignerCertificateSha256, TimestampAccuracy, VerificationPolicy,
    VerifiedTimestamp, verify_response,
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
        }
    }
}

impl V2VerifyPolicy {
    pub fn baseline() -> Self {
        Self {
            enforce_disclosure_requirements: true,
            require_tsa: true,
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
    .map_err(|error| bad(format!("cannot safely open v2 artifact {rel}: {error}")))?;
    let mut file = File::from(descriptor);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
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
        return Err(bad("v2 artifact digest mismatch"));
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
        && manifest.disclosure_class == "A"
        && (manifest.artifacts.records.is_some() == manifest.artifacts.records_pack.is_some())
    {
        return Err(bad(
            "Class A manifest v3 requires exactly one of records or records_pack",
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
        if !matches!(
            claim.status.as_str(),
            "verified" | "pending" | "missing" | "failed" | "skipped" | "complete"
        ) {
            return Err(bad("v2 manifest anchoring status is unsupported"));
        }
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
    let manifest_path = root.join("segment.verify.json");
    let manifest: Manifest = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    validate_manifest(&manifest)?;
    let _ = (&manifest.operational_summary, &manifest.extensions);
    for reference in manifest.artifacts.references() {
        artifact(root, reference)?;
    }
    let segment_bytes = artifact(root, &manifest.artifacts.segment_cbor)?;
    let segment = decode_segment_record_v2(&segment_bytes)
        .map_err(|err| bad(format!("invalid v2 segment artifact: {err}")))?;
    if segment.ledger_id != manifest.ledger_id
        || segment.site_id != manifest.site_id
        || segment.segment_number.to_string() != manifest.segment_number
    {
        return Err(bad(
            "manifest identity does not match decoded segment artifact",
        ));
    }
    let has_tsa = manifest.artifacts.tsa_tsr.is_some();
    let has_ots =
        manifest.artifacts.segment_ots.is_some() && manifest.artifacts.segment_ots_meta.is_some();
    if policy.enforce_disclosure_requirements && !has_tsa && !has_ots {
        return Err(bad(
            "claimed disclosure class requires a timestamp proof and binding metadata",
        ));
    }
    let mut executed = vec![
        "bundle_disclosure_validation",
        "verification_manifest_validation",
        "segment_artifact_validation",
    ];
    let mut skipped = Vec::<Value>::new();
    let mut channels = serde_json::Map::new();
    if segment.segment_number == 0 {
        if segment.prev_segment_sha256 != ZERO_SHA256 {
            return Err(bad("epoch segment does not use the zero predecessor"));
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
            return Err(bad("segment predecessor linkage is invalid"));
        }
        executed.push("segment_chain_validation");
    } else {
        skipped
            .push(json!({"check":"segment_chain_validation","reason":"predecessor-not-disclosed"}));
    }
    if manifest.disclosure_class == "A" {
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
            return Err(EvidenceError::VerificationFailed(
                "Class A record leaves do not match authoritative batches".to_string(),
            ));
        }
        if recomputed_root != segment.segment_root {
            return Err(EvidenceError::VerificationFailed(
                "Class A record root does not match segment root".to_string(),
            ));
        }
        executed.push("record_level_recompute");
        executed.push("batch_metadata_validation");
        executed.push("segment_digest_binding");
        let mut tsa_fields = apply_timestamp_checks(
            root,
            &manifest,
            &segment_bytes,
            policy,
            &mut executed,
            &mut skipped,
            &mut channels,
        )?;
        let mut result = json!({"version":manifest.version,"artifact_sha256":sha256_hex(&segment_bytes),"commitment_profile_id":COMMITMENT_PROFILE_ID,"disclosure_class":"A","verification_scope":"public_recompute","channels":channels,"policy":{"require_tsa":policy.require_tsa},"checks_executed":executed,"checks_skipped":skipped,"record_multiset_root":recomputed_root,"overall":"success"});
        result
            .as_object_mut()
            .expect("verification result is an object")
            .append(&mut tsa_fields);
        return Ok(result);
    }
    skipped.push(json!({"check":"record_level_recompute","reason":format!("disclosure-class-{}",manifest.disclosure_class.to_ascii_lowercase())}));
    if manifest.disclosure_class == "C" {
        skipped.push(json!({"check":"batch_metadata_validation","reason":"out_of_scope"}));
    } else if let Some(batch_refs) = &manifest.artifacts.batches {
        validate_batch_projections(root, batch_refs, &segment)?;
        executed.push("batch_metadata_validation");
    } else {
        skipped.push(json!({"check":"batch_metadata_validation","reason":"not_disclosed"}));
    }
    executed.push("segment_digest_binding");
    let mut tsa_fields = apply_timestamp_checks(
        root,
        &manifest,
        &segment_bytes,
        policy,
        &mut executed,
        &mut skipped,
        &mut channels,
    )?;
    let scope = if manifest.disclosure_class == "B" {
        "partial_verification"
    } else {
        "anchor_only"
    };
    let mut result = json!({"version":manifest.version,"artifact_sha256":sha256_hex(&segment_bytes),"commitment_profile_id":COMMITMENT_PROFILE_ID,"disclosure_class":manifest.disclosure_class,"verification_scope":scope,"channels":channels,"policy":{"require_tsa":policy.require_tsa},"checks_executed":executed,"checks_skipped":skipped,"overall":"success"});
    result
        .as_object_mut()
        .expect("verification result is an object")
        .append(&mut tsa_fields);
    Ok(result)
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

fn encode_records_pack(records: &mut [Vec<u8>]) -> Result<Vec<u8>> {
    records.sort_by(|left, right| {
        sha256_digest(left)
            .cmp(&sha256_digest(right))
            .then_with(|| left.cmp(right))
    });
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

fn timestamp_accuracy_value(accuracy: TimestampAccuracy) -> Option<Value> {
    let mut value = serde_json::Map::new();
    if let Some(seconds) = accuracy.seconds {
        value.insert("seconds".to_string(), json!(seconds));
    }
    if let Some(millis) = accuracy.millis {
        value.insert("millis".to_string(), json!(millis));
    }
    if let Some(micros) = accuracy.micros {
        value.insert("micros".to_string(), json!(micros));
    }
    (!value.is_empty()).then_some(Value::Object(value))
}

fn apply_timestamp_checks(
    root: &Path,
    manifest: &Manifest,
    segment_bytes: &[u8],
    policy: &V2VerifyPolicy,
    executed: &mut Vec<&'static str>,
    skipped: &mut Vec<Value>,
    channels: &mut serde_json::Map<String, Value>,
) -> Result<serde_json::Map<String, Value>> {
    let mut tsa_fields = serde_json::Map::new();
    if let Some(reference) = &manifest.artifacts.tsa_tsr {
        let response = artifact(root, reference)?;
        match verify_rfc3161(&response, sha256_digest(segment_bytes), policy) {
            Ok(verified) => {
                executed.push("tsa_verification");
                channels.insert("tsa".to_string(), json!({"status":"verified"}));
                tsa_fields.insert(
                    "tsa_generation_time".to_string(),
                    json!(verified.generation_time.to_rfc3339()),
                );
                tsa_fields.insert(
                    "tsa_serial_number".to_string(),
                    json!(verified.serial_number.to_hex()),
                );
                if let Some(value) = verified.accuracy.and_then(timestamp_accuracy_value) {
                    tsa_fields.insert("tsa_accuracy".to_string(), value);
                }
            }
            Err(error) => {
                channels.insert(
                    "tsa".to_string(),
                    json!({"status":"failed","diagnostic":error.to_string()}),
                );
                return Err(error);
            }
        }
    } else if policy.require_tsa {
        skipped.push(json!({"check":"tsa_verification","reason":"missing_proof"}));
        return Err(bad("required RFC 3161 timestamp response is missing"));
    } else if manifest.anchoring.tsa.is_some() {
        skipped.push(json!({"check":"tsa_verification","reason":"missing_proof"}));
        channels.insert("tsa".to_string(), json!({"status":"missing"}));
    }

    if manifest.artifacts.segment_ots.is_some() || manifest.anchoring.ots.is_some() {
        let status = manifest
            .anchoring
            .ots
            .as_ref()
            .map_or("missing", |claim| claim.status.as_str());
        skipped.push(json!({"check":"x-ots-verification","reason":status}));
        channels.insert("ots".to_string(), json!({"status":status}));
    }
    if manifest.artifacts.peer_attest.is_some() || manifest.anchoring.peer.is_some() {
        let status = manifest
            .anchoring
            .peer
            .as_ref()
            .map_or("missing", |claim| claim.status.as_str());
        skipped.push(json!({"check":"x-peer-quorum-verification","reason":status}));
        channels.insert("peer".to_string(), json!({"status":status}));
    }
    Ok(tsa_fields)
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
    verify_v2_bundle_with_policy(root, policy)?;
    let mut manifest: Manifest =
        serde_json::from_slice(&fs::read(root.join("segment.verify.json"))?)?;
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
    if !include_extensions {
        manifest.extensions = None;
    }
    members.insert(
        "segment.verify.json".to_string(),
        serde_json::to_vec(&manifest)?,
    );
    write_deterministic_archive(output, &members)
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
    let input = fs::read(archive_path)?;
    validate_single_gzip_member(&input)?;
    let mut decoder = GzDecoder::new(input.as_slice());
    let mut expanded = Vec::new();
    decoder
        .by_ref()
        .take(MAX_EXPANDED_ARCHIVE + 1)
        .read_to_end(&mut expanded)?;
    if expanded.len() as u64 > MAX_EXPANDED_ARCHIVE {
        return Err(bad("expanded archive exceeds 256 MiB"));
    }
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

fn validate_single_gzip_member(input: &[u8]) -> Result<()> {
    if input.len() < 18 || input[0..3] != [0x1f, 0x8b, 8] {
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
        offset = offset
            .checked_add(2)
            .ok_or_else(|| bad("gzip header overflows"))?;
    }
    if offset + 8 > input.len() {
        return Err(bad("gzip carrier is truncated"));
    }
    let mut decompressor = Decompress::new(false);
    let mut consumed = 0_usize;
    let mut scratch = [0_u8; 8192];
    loop {
        let before = decompressor.total_in();
        let status = decompressor
            .decompress(
                &input[offset + consumed..],
                &mut scratch,
                FlushDecompress::None,
            )
            .map_err(|_| bad("gzip deflate stream is malformed"))?;
        consumed = usize::try_from(decompressor.total_in())
            .map_err(|_| bad("gzip stream is too large"))?;
        if status == Status::StreamEnd {
            break;
        }
        if decompressor.total_in() == before && status == Status::BufError {
            return Err(bad("gzip deflate stream is truncated"));
        }
    }
    let expected_end = offset
        .checked_add(consumed)
        .and_then(|value| value.checked_add(8))
        .ok_or_else(|| bad("gzip member length overflows"))?;
    if expected_end != input.len() {
        return Err(bad("gzip carrier has trailing data or multiple members"));
    }
    Ok(())
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
    fn empty_timestamp_accuracy_is_omitted() {
        assert_eq!(
            timestamp_accuracy_value(TimestampAccuracy {
                seconds: None,
                millis: None,
                micros: None,
            }),
            None
        );
    }

    #[test]
    fn timestamp_accuracy_components_are_projected() {
        assert_eq!(
            timestamp_accuracy_value(TimestampAccuracy {
                seconds: Some(0),
                millis: Some(12),
                micros: Some(34),
            }),
            Some(json!({"seconds": 0, "millis": 12, "micros": 34}))
        );
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
        validate_single_gzip_member(&fs::read(&first).unwrap()).unwrap();
        let mut trailing = fs::read(first).unwrap();
        trailing.push(0);
        assert!(validate_single_gzip_member(&trailing).is_err());
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
        assert!(verify_v2_bundle(&root).is_err());
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
