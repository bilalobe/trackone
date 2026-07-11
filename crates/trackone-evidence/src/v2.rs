//! Additive verifier for draft-08 segment bundles.
use super::{EvidenceError, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs;
use std::path::{Component, Path, PathBuf};
use trackone_ledger::{
    sha256_hex,
    v2::{COMMITMENT_PROFILE_ID, ZERO_SHA256, decode_segment_record_v2, merkle_root_from_records},
};

#[derive(Clone, Debug, Deserialize)]
struct ArtifactRef {
    path: String,
    sha256: String,
}
#[derive(Clone, Debug, Deserialize)]
struct Manifest {
    version: u8,
    ledger_id: String,
    site_id: String,
    segment_number: String,
    commitment_profile_id: String,
    disclosure_class: String,
    artifacts: Artifacts,
    anchoring: Value,
}

#[derive(Clone, Debug, Deserialize)]
struct Artifacts {
    segment_cbor: ArtifactRef,
    #[serde(default)]
    predecessor_segment_cbor: Option<ArtifactRef>,
    #[serde(default)]
    records: Option<Vec<ArtifactRef>>,
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

/// Resolve and open a manifest path without accepting a platform-specific
/// spelling that can escape the evidence root.  Every existing component is
/// inspected before use; callers also receive digest validation below.
fn safe_path(root: &Path, rel: &str) -> Result<PathBuf> {
    if rel.is_empty()
        || rel.starts_with('/')
        || rel.starts_with('\\')
        || rel.contains('\\')
        || rel.contains(':')
        || rel.chars().any(|c| c.is_control())
    {
        return Err(bad("v2 manifest path is not portable"));
    }
    let mut path = root.to_path_buf();
    for component in Path::new(rel).components() {
        let Component::Normal(part) = component else {
            return Err(bad("v2 manifest path contains a dot or parent component"));
        };
        path.push(part);
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(bad("v2 manifest path traverses a symlink"));
        }
    }
    Ok(path)
}

fn artifact(root: &Path, reference: &ArtifactRef) -> Result<(PathBuf, Vec<u8>)> {
    if !valid_hex(&reference.sha256, 64) {
        return Err(bad("v2 artifact digest is not lowercase SHA-256"));
    }
    let path = safe_path(root, &reference.path)?;
    let bytes = fs::read(&path)?;
    if sha256_hex(&bytes) != reference.sha256 {
        return Err(bad("v2 artifact digest mismatch"));
    }
    Ok((path, bytes))
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
    if !manifest.anchoring.is_object() {
        return Err(bad("v2 manifest anchoring must be an object"));
    }
    Ok(())
}

/// Verify the portable v2 bundle envelope.  Segment CBOR and supplied record
/// artifacts are digest-bound here; the ledger crate owns the profile's exact
/// tree calculation used for Class A recomputation.
pub fn verify_v2_bundle(root: &Path) -> Result<Value> {
    let manifest_path = root.join("segment.verify.json");
    let manifest: Manifest = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    validate_manifest(&manifest)?;
    let (_, segment_bytes) = artifact(root, &manifest.artifacts.segment_cbor)?;
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
    let mut executed = vec![
        "bundle_disclosure_validation",
        "verification_manifest_validation",
        "segment_digest_binding",
        "segment_artifact_validation",
    ];
    let mut skipped = Vec::<Value>::new();
    if segment.segment_number == 0 {
        if segment.prev_segment_sha256 != ZERO_SHA256 {
            return Err(bad("epoch segment does not use the zero predecessor"));
        }
        executed.push("segment_chain_validation");
    } else if let Some(predecessor) = &manifest.artifacts.predecessor_segment_cbor {
        let (_, predecessor_bytes) = artifact(root, predecessor)?;
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
            .map(|record| artifact(root, record).map(|(_, bytes)| bytes))
            .collect::<Result<Vec<_>>>()?;
        let root = merkle_root_from_records(&bytes).root_hex();
        if root != segment.segment_root {
            return Err(EvidenceError::VerificationFailed(
                "Class A record root does not match segment root".to_string(),
            ));
        }
        executed.push("record_level_recompute");
        return Ok(
            json!({"version":1,"artifact_sha256":sha256_hex(&segment_bytes),"commitment_profile_id":COMMITMENT_PROFILE_ID,"disclosure_class":"A","checks_executed":executed,"checks_skipped":skipped,"record_multiset_root":root,"overall":"success"}),
        );
    }
    skipped.push(json!({"check":"record_level_recompute","reason":format!("disclosure-class-{}",manifest.disclosure_class.to_ascii_lowercase())}));
    Ok(
        json!({"version":1,"artifact_sha256":sha256_hex(&segment_bytes),"commitment_profile_id":COMMITMENT_PROFILE_ID,"disclosure_class":manifest.disclosure_class,"checks_executed":executed,"checks_skipped":skipped,"overall":"success"}),
    )
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
        SegmentRecordV2 {
            ledger_id: "b7a1d5e40c6f438e9a75db27c96f31aa".into(),
            site_id: "an-001".into(),
            segment_number: 0,
            closure_policy: ClosurePolicyV1 {
                interval_ms: 60_000,
                batch_record_limit: 1,
                record_limit: None,
                size_limit_bytes: None,
                empty_mode: EmptyMode::Suppress,
            },
            close_reason: "interval".into(),
            prev_segment_sha256: ZERO_SHA256.into(),
            batches: vec![SegmentBatchV2 {
                ledger_id: "b7a1d5e40c6f438e9a75db27c96f31aa".into(),
                site_id: "an-001".into(),
                segment_number: 0,
                batch_number: 0,
                merkle_root: leaf.clone(),
                count: 1,
                leaf_hashes: vec![leaf],
            }],
            segment_root: merkle.root_hex(),
        }
        .canonical_cbor_bytes()
        .unwrap()
    }

    fn successor_segment_bytes(predecessor: &[u8]) -> Vec<u8> {
        let record = vec![vec![
            0x87, 0x01, 0x48, 0, 0, 0, 0, 0, 0, 0, 2, 0x02, 0x00, 0xf6, 0x00, 0xf6,
        ]];
        let merkle = merkle_root_from_records(&record);
        let leaf = trackone_ledger::hex_lower(&merkle.leaf_hashes[0]);
        SegmentRecordV2 {
            ledger_id: "b7a1d5e40c6f438e9a75db27c96f31aa".into(),
            site_id: "an-001".into(),
            segment_number: 1,
            closure_policy: ClosurePolicyV1 {
                interval_ms: 60_000,
                batch_record_limit: 1,
                record_limit: None,
                size_limit_bytes: None,
                empty_mode: EmptyMode::Suppress,
            },
            close_reason: "interval".into(),
            prev_segment_sha256: sha256_hex(predecessor),
            batches: vec![SegmentBatchV2 {
                ledger_id: "b7a1d5e40c6f438e9a75db27c96f31aa".into(),
                site_id: "an-001".into(),
                segment_number: 1,
                batch_number: 0,
                merkle_root: leaf.clone(),
                count: 1,
                leaf_hashes: vec![leaf],
            }],
            segment_root: merkle.root_hex(),
        }
        .canonical_cbor_bytes()
        .unwrap()
    }

    fn empty_epoch_segment_bytes() -> Vec<u8> {
        SegmentRecordV2 {
            ledger_id: "b7a1d5e40c6f438e9a75db27c96f31aa".into(),
            site_id: "an-001".into(),
            segment_number: 0,
            closure_policy: ClosurePolicyV1 {
                interval_ms: 60_000,
                batch_record_limit: 1,
                record_limit: None,
                size_limit_bytes: None,
                empty_mode: EmptyMode::Emit,
            },
            close_reason: "interval".into(),
            prev_segment_sha256: ZERO_SHA256.into(),
            batches: Vec::new(),
            segment_root: sha256_hex(b""),
        }
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
            Err(EvidenceError::VerificationFailed(_))
        ));
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
