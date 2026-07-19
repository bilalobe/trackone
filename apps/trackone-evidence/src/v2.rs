//! Additive verifier for draft-08 segment bundles owned by the evidence app.
use super::{EvidenceError, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use trackone_ledger::{
    hex_lower, sha256_hex,
    v2::{
        COMMITMENT_PROFILE_ID, ZERO_SHA256, decode_segment_record_v2, merkle_root_from_records,
        validate_canonical_record_v2,
    },
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactRef {
    path: String,
    sha256: String,
}
#[derive(Clone, Debug, Deserialize)]
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
    #[serde(default)]
    operational_summary: Option<Value>,
    #[serde(default)]
    extensions: Option<Value>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifacts {
    segment_cbor: ArtifactRef,
    #[serde(default)]
    predecessor_segment_cbor: Option<ArtifactRef>,
    #[serde(default)]
    records: Option<Vec<ArtifactRef>>,
    #[serde(default)]
    batches: Option<Vec<ArtifactRef>>,
    #[serde(default)]
    segment_ots: Option<ArtifactRef>,
    #[serde(default)]
    segment_ots_meta: Option<ArtifactRef>,
    #[serde(default)]
    peer_attest: Option<ArtifactRef>,
    #[serde(default)]
    tsa_tsr: Option<ArtifactRef>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchoring {
    #[serde(default)]
    tsa: Option<ChannelClaim>,
    #[serde(default)]
    ots: Option<ChannelClaim>,
    #[serde(default)]
    peer: Option<ChannelClaim>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelClaim {
    status: String,
}

#[derive(Clone, Debug)]
pub struct V2VerifyPolicy {
    pub enforce_disclosure_requirements: bool,
    pub require_tsa: bool,
    pub tsa_ca_file: Option<PathBuf>,
    pub tsa_policy_oid: Option<String>,
    pub openssl_binary: PathBuf,
}

impl Default for V2VerifyPolicy {
    fn default() -> Self {
        Self {
            enforce_disclosure_requirements: false,
            require_tsa: false,
            tsa_ca_file: None,
            tsa_policy_oid: None,
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
    if manifest.version != 2
        || manifest.commitment_profile_id != COMMITMENT_PROFILE_ID
        || !valid_hex(&manifest.ledger_id, 32)
        || manifest.site_id.is_empty()
        || !valid_uint64(&manifest.segment_number)
        || !matches!(manifest.disclosure_class.as_str(), "A" | "B" | "C")
    {
        return Err(bad("v2 manifest identity is invalid"));
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

fn verify_rfc3161(response: &[u8], artifact_sha256: &str, policy: &V2VerifyPolicy) -> Result<()> {
    let ca_file = policy
        .tsa_ca_file
        .as_ref()
        .ok_or_else(|| bad("RFC 3161 trust anchor is not configured"))?;
    let unique = format!(
        "trackone-tsr-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| bad("system time is before the Unix epoch"))?
            .as_nanos()
    );
    let response_path = std::env::temp_dir().join(unique);
    fs::write(&response_path, response)?;
    let verification = Command::new(&policy.openssl_binary)
        .args(["ts", "-verify", "-in"])
        .arg(&response_path)
        .args(["-digest", artifact_sha256, "-CAfile"])
        .arg(ca_file)
        .output();
    let details = Command::new(&policy.openssl_binary)
        .args(["ts", "-reply", "-in"])
        .arg(&response_path)
        .arg("-text")
        .output();
    let _ = fs::remove_file(&response_path);
    let verification = verification
        .map_err(|error| bad(format!("cannot execute OpenSSL RFC 3161 verifier: {error}")))?;
    if !verification.status.success() {
        return Err(bad(format!(
            "RFC 3161 verification failed: {}{}",
            String::from_utf8_lossy(&verification.stdout),
            String::from_utf8_lossy(&verification.stderr)
        )));
    }
    let details =
        details.map_err(|error| bad(format!("cannot inspect RFC 3161 response: {error}")))?;
    if !details.status.success() {
        return Err(bad("OpenSSL could not decode the RFC 3161 response"));
    }
    let text = String::from_utf8_lossy(&details.stdout);
    if !text
        .lines()
        .any(|line| line.trim() == "Hash Algorithm: sha256")
    {
        return Err(bad("RFC 3161 message imprint is not SHA-256"));
    }
    if let Some(expected) = &policy.tsa_policy_oid {
        let expected = format!("Policy OID: {expected}");
        if !text.lines().any(|line| line.trim() == expected) {
            return Err(bad("RFC 3161 TSA policy OID mismatch"));
        }
    }
    Ok(())
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
        let records = manifest
            .artifacts
            .records
            .as_ref()
            .ok_or_else(|| bad("Class A requires disclosed records"))?;
        let bytes = records
            .iter()
            .enumerate()
            .map(|(index, record)| {
                let bytes = artifact(root, record)?;
                validate_canonical_record_v2(&bytes).map_err(|err| {
                    bad(format!(
                        "invalid Class A canonical record {index} at {}: {err}",
                        record.path
                    ))
                })?;
                Ok(bytes)
            })
            .collect::<Result<Vec<_>>>()?;
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
        apply_timestamp_checks(
            root,
            &manifest,
            &segment_bytes,
            policy,
            &mut executed,
            &mut skipped,
            &mut channels,
        )?;
        return Ok(
            json!({"version":2,"artifact_sha256":sha256_hex(&segment_bytes),"commitment_profile_id":COMMITMENT_PROFILE_ID,"disclosure_class":"A","verification_scope":"public_recompute","channels":channels,"policy":{"require_tsa":policy.require_tsa},"checks_executed":executed,"checks_skipped":skipped,"record_multiset_root":recomputed_root,"overall":"success"}),
        );
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
    apply_timestamp_checks(
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
    Ok(
        json!({"version":2,"artifact_sha256":sha256_hex(&segment_bytes),"commitment_profile_id":COMMITMENT_PROFILE_ID,"disclosure_class":manifest.disclosure_class,"verification_scope":scope,"channels":channels,"policy":{"require_tsa":policy.require_tsa},"checks_executed":executed,"checks_skipped":skipped,"overall":"success"}),
    )
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

fn apply_timestamp_checks(
    root: &Path,
    manifest: &Manifest,
    segment_bytes: &[u8],
    policy: &V2VerifyPolicy,
    executed: &mut Vec<&'static str>,
    skipped: &mut Vec<Value>,
    channels: &mut serde_json::Map<String, Value>,
) -> Result<()> {
    if let Some(reference) = &manifest.artifacts.tsa_tsr {
        let response = artifact(root, reference)?;
        match verify_rfc3161(&response, &sha256_hex(segment_bytes), policy) {
            Ok(()) => {
                executed.push("tsa_verification");
                channels.insert("tsa".to_string(), json!({"status":"verified"}));
            }
            Err(error) => {
                channels.insert(
                    "tsa".to_string(),
                    json!({"status":"failed","diagnostic":error.to_string()}),
                );
                if policy.require_tsa {
                    return Err(error);
                }
                skipped.push(json!({"check":"tsa_verification","reason":"validation_failed"}));
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
