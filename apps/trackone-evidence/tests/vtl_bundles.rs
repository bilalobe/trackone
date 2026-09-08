use flate2::{Compression, write::GzEncoder};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::process::Command;
use trackone_evidence::vtl::{
    MANIFEST_MEDIA_TYPE, RESULT_MEDIA_TYPE, SPECIALIZED_MANIFEST_MEDIA_TYPE, VerificationScope,
    VerifyPolicy, verify_archive, verify_bundle_with_policy,
};
use trackone_ledger::sha256_hex;
use trackone_ledger::vtl::{
    COMMITMENT_PROFILE_ID, ClosurePolicy, EmptyMode, SegmentRecord, batch_roots_from_leaf_hashes,
    merkle_root_from_records,
};

fn empty_epoch() -> Vec<u8> {
    SegmentRecord::new_epoch(
        "b7a1d5e40c6f438e9a75db27c96f31aa",
        ClosurePolicy {
            interval_ms: 60_000,
            batch_record_limit: 2,
            record_limit: None,
            size_limit_bytes: None,
            empty_mode: EmptyMode::Emit,
        },
        "interval",
        0,
        Vec::new(),
        trackone_ledger::sha256_digest(b""),
    )
    .unwrap()
    .canonical_cbor_bytes()
    .unwrap()
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => unreachable!(),
            };
            digit(pair[0]) << 4 | digit(pair[1])
        })
        .collect()
}

fn three_record_epoch() -> (Vec<Vec<u8>>, Vec<u8>) {
    let records = [
        "87014800000000000000010100f600f6",
        "87014800000000000000020201f600f6",
        "87014800000000000000030302f600f6",
    ]
    .map(decode_hex)
    .to_vec();
    let merkle = merkle_root_from_records(&records);
    let segment = SegmentRecord::new_epoch(
        "b7a1d5e40c6f438e9a75db27c96f31aa",
        ClosurePolicy {
            interval_ms: 60_000,
            batch_record_limit: 2,
            record_limit: None,
            size_limit_bytes: None,
            empty_mode: EmptyMode::Suppress,
        },
        "interval",
        3,
        batch_roots_from_leaf_hashes(&merkle.leaf_hashes, 2).unwrap(),
        merkle.root,
    )
    .unwrap()
    .canonical_cbor_bytes()
    .unwrap();
    (records, segment)
}

fn class_a_manifest(records: &[Vec<u8>], segment: &[u8]) -> Value {
    json!({
        "version": 1,
        "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
        "segment_number": "0",
        "commitment_profile_id": COMMITMENT_PROFILE_ID,
        "disclosure_class": "A",
        "artifacts": {
            "segment_cbor": {"path": "segment.cbor", "sha256": sha256_hex(segment)},
            "record_batches": [
                {
                    "batch_number": "0",
                    "records": [
                        {"path": "records/record-3.cbor", "sha256": sha256_hex(&records[2])},
                        {"path": "records/record-2.cbor", "sha256": sha256_hex(&records[1])}
                    ]
                },
                {
                    "batch_number": "1",
                    "records": [
                        {"path": "records/record-1.cbor", "sha256": sha256_hex(&records[0])}
                    ]
                }
            ]
        },
        "anchoring": {"tsa": {"status": "unavailable"}}
    })
}

fn gzip_member(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn archive_rejects_concatenated_gzip_members() {
    let directory = tempfile::tempdir().unwrap();
    let archive = directory.path().join("concatenated.tar.gz");
    let mut bytes = gzip_member(b"first member");
    bytes.extend(gzip_member(b"second member"));
    fs::write(&archive, bytes).unwrap();

    let error = verify_archive(&archive, &VerifyPolicy::baseline()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("exactly one gzip member with no trailing bytes")
    );
}

#[test]
fn anchor_only_downscope_does_not_fetch_class_a_record_artifacts() {
    let directory = tempfile::tempdir().unwrap();
    let (records, segment) = three_record_epoch();
    fs::write(directory.path().join("segment.cbor"), &segment).unwrap();
    fs::write(
        directory.path().join("segment.verify.json"),
        serde_json::to_vec(&class_a_manifest(&records, &segment)).unwrap(),
    )
    .unwrap();
    let mut policy = VerifyPolicy::baseline();
    policy.selected_scope = Some(VerificationScope::AnchorOnly);

    let result = verify_bundle_with_policy(directory.path(), &policy).unwrap();
    assert_eq!(result["claimed_disclosure_class"], "A");
    assert_eq!(result["verification_scope"], "anchor_only");
    assert_eq!(result["failure_reasons"], json!(["channel_failure"]));
}

#[test]
fn anchor_only_downscope_rejects_unconsumed_opening_with_wrong_cardinality() {
    let directory = tempfile::tempdir().unwrap();
    let (records, segment) = three_record_epoch();
    fs::write(directory.path().join("segment.cbor"), &segment).unwrap();
    let mut manifest = class_a_manifest(&records, &segment);
    manifest["artifacts"]["record_batches"][0]["records"] = json!([
        {"path": "records/record-3.cbor", "sha256": sha256_hex(&records[2])}
    ]);
    fs::write(
        directory.path().join("segment.verify.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let mut policy = VerifyPolicy::baseline();
    policy.selected_scope = Some(VerificationScope::AnchorOnly);
    policy.require_claimed_scope = true;

    let result = verify_bundle_with_policy(directory.path(), &policy).unwrap();
    assert_eq!(
        result["failure_reasons"],
        json!(["channel_failure", "insufficient_disclosure"])
    );
}

#[test]
fn disclosed_batch_downscope_consumes_only_selected_complete_class_a_batches() {
    let directory = tempfile::tempdir().unwrap();
    let (records, segment) = three_record_epoch();
    fs::create_dir(directory.path().join("records")).unwrap();
    fs::write(directory.path().join("segment.cbor"), &segment).unwrap();
    fs::write(directory.path().join("records/record-2.cbor"), &records[1]).unwrap();
    fs::write(directory.path().join("records/record-3.cbor"), &records[2]).unwrap();
    fs::write(
        directory.path().join("segment.verify.json"),
        serde_json::to_vec(&class_a_manifest(&records, &segment)).unwrap(),
    )
    .unwrap();
    let mut policy = VerifyPolicy::baseline();
    policy.selected_scope = Some(VerificationScope::DisclosedBatchRecompute);
    policy.selected_batches.insert(0);

    let result = verify_bundle_with_policy(directory.path(), &policy).unwrap();
    assert_eq!(result["verification_scope"], "disclosed_batch_recompute");
    assert_eq!(result["failure_reasons"], json!(["channel_failure"]));
}

#[test]
fn policy_can_require_the_stronger_claimed_scope() {
    let directory = tempfile::tempdir().unwrap();
    let (records, segment) = three_record_epoch();
    fs::write(directory.path().join("segment.cbor"), &segment).unwrap();
    fs::write(
        directory.path().join("segment.verify.json"),
        serde_json::to_vec(&class_a_manifest(&records, &segment)).unwrap(),
    )
    .unwrap();
    let mut policy = VerifyPolicy::baseline();
    policy.selected_scope = Some(VerificationScope::AnchorOnly);
    policy.require_claimed_scope = true;

    let result = verify_bundle_with_policy(directory.path(), &policy).unwrap();
    assert_eq!(
        result["failure_reasons"],
        json!(["channel_failure", "scope_not_exercised"])
    );
}

#[test]
fn claimed_scope_is_not_reported_when_the_segment_is_invalid() {
    let directory = tempfile::tempdir().unwrap();
    let (records, mut segment) = three_record_epoch();
    let interval = segment
        .windows(b"interval_ms".len())
        .position(|window| window == b"interval_ms")
        .unwrap();
    let value_head = interval + b"interval_ms".len();
    segment[value_head] = match segment[value_head] {
        0x19 => 0x39,
        0x1a => 0x3a,
        other => panic!("unexpected interval_ms CBOR head {other:#x}"),
    };
    fs::write(directory.path().join("segment.cbor"), &segment).unwrap();
    fs::write(
        directory.path().join("segment.verify.json"),
        serde_json::to_vec(&class_a_manifest(&records, &segment)).unwrap(),
    )
    .unwrap();
    let mut policy = VerifyPolicy::baseline();
    policy.selected_scope = Some(VerificationScope::AnchorOnly);
    policy.require_claimed_scope = true;

    let result = verify_bundle_with_policy(directory.path(), &policy).unwrap();
    assert_eq!(result["commitment_profile_id"], COMMITMENT_PROFILE_ID);
    assert_eq!(
        result["failure_reasons"],
        json!(["channel_failure", "invalid_segment_artifact"])
    );
}

#[test]
fn present_but_unresolved_tsa_response_is_missing() {
    let directory = tempfile::tempdir().unwrap();
    let segment = empty_epoch();
    fs::write(directory.path().join("segment.cbor"), &segment).unwrap();
    let manifest = json!({
        "version": 1,
        "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
        "segment_number": "0",
        "commitment_profile_id": COMMITMENT_PROFILE_ID,
        "disclosure_class": "C",
        "artifacts": {
            "segment_cbor": {"path": "segment.cbor", "sha256": sha256_hex(&segment)},
            "tsa_tsr": {"path": "missing.tsr", "sha256": "00".repeat(32)}
        },
        "anchoring": {"tsa": {"status": "present"}}
    });
    fs::write(
        directory.path().join("segment.verify.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();

    let result = verify_bundle_with_policy(directory.path(), &VerifyPolicy::baseline()).unwrap();
    assert_eq!(result["channels"]["tsa"]["status"], "missing");
    assert_eq!(result["failure_reasons"], json!(["channel_failure"]));
}

#[test]
fn timestamp_response_digest_mismatch_preserves_commitment_mismatch() {
    let directory = tempfile::tempdir().unwrap();
    let segment = empty_epoch();
    let response = b"not the declared response";
    fs::write(directory.path().join("segment.cbor"), &segment).unwrap();
    fs::write(directory.path().join("timestamp.tsr"), response).unwrap();
    let manifest = json!({
        "version": 1,
        "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
        "segment_number": "0",
        "commitment_profile_id": COMMITMENT_PROFILE_ID,
        "disclosure_class": "C",
        "artifacts": {
            "segment_cbor": {"path": "segment.cbor", "sha256": sha256_hex(&segment)},
            "tsa_tsr": {"path": "timestamp.tsr", "sha256": sha256_hex(b"different response")}
        },
        "anchoring": {"tsa": {"status": "present"}}
    });
    fs::write(
        directory.path().join("segment.verify.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();

    let result = verify_bundle_with_policy(directory.path(), &VerifyPolicy::baseline()).unwrap();
    assert_eq!(result["channels"]["tsa"]["status"], "failed");
    assert_eq!(
        result["failure_reasons"],
        json!(["channel_failure", "commitment_mismatch"])
    );
}

#[test]
fn timestamp_policy_omission_is_a_policy_rejection() {
    let directory = tempfile::tempdir().unwrap();
    let segment = empty_epoch();
    let response = b"response whose policy cannot be evaluated";
    fs::write(directory.path().join("segment.cbor"), &segment).unwrap();
    fs::write(directory.path().join("timestamp.tsr"), response).unwrap();
    let manifest = json!({
        "version": 1,
        "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
        "segment_number": "0",
        "commitment_profile_id": COMMITMENT_PROFILE_ID,
        "disclosure_class": "C",
        "artifacts": {
            "segment_cbor": {"path": "segment.cbor", "sha256": sha256_hex(&segment)},
            "tsa_tsr": {"path": "timestamp.tsr", "sha256": sha256_hex(response)}
        },
        "anchoring": {"tsa": {"status": "present"}}
    });
    fs::write(
        directory.path().join("segment.verify.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();

    let result = verify_bundle_with_policy(directory.path(), &VerifyPolicy::baseline()).unwrap();
    assert_eq!(result["channels"]["tsa"]["status"], "failed");
    assert_eq!(
        result["failure_reasons"],
        json!(["channel_failure", "verifier_policy_rejection"])
    );
}

#[test]
fn producer_pending_claim_is_incomplete_without_failure_reasons() {
    let directory = tempfile::tempdir().unwrap();
    let segment = empty_epoch();
    fs::write(directory.path().join("segment.cbor"), &segment).unwrap();
    let manifest = json!({
        "version": 1,
        "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
        "segment_number": "0",
        "commitment_profile_id": COMMITMENT_PROFILE_ID,
        "disclosure_class": "C",
        "artifacts": {
            "segment_cbor": {"path": "segment.cbor", "sha256": sha256_hex(&segment)}
        },
        "anchoring": {"tsa": {"status": "pending"}}
    });
    fs::write(
        directory.path().join("segment.verify.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();

    let result = verify_bundle_with_policy(directory.path(), &VerifyPolicy::baseline()).unwrap();
    assert!(result.get("version").is_none());
    assert_eq!(result["channels"]["tsa"]["status"], "pending_claim");
    assert_eq!(
        result["channels"]["tsa"]["reason"],
        "producer_pending_claim"
    );
    assert_eq!(result["overall"], "incomplete");
    assert!(result.get("failure_reasons").is_none());
}

#[test]
fn extension_artifact_does_not_substitute_for_predecessor_member() {
    let directory = tempfile::tempdir().unwrap();
    let predecessor = empty_epoch();
    let successor = SegmentRecord::new_successor(
        &predecessor,
        ClosurePolicy {
            interval_ms: 60_000,
            batch_record_limit: 2,
            record_limit: None,
            size_limit_bytes: None,
            empty_mode: EmptyMode::Emit,
        },
        "interval",
        0,
        Vec::new(),
        trackone_ledger::sha256_digest(b""),
    )
    .unwrap()
    .canonical_cbor_bytes()
    .unwrap();
    fs::write(directory.path().join("segment.cbor"), &successor).unwrap();
    fs::write(directory.path().join("predecessor.cbor"), &predecessor).unwrap();
    let manifest = json!({
        "version": 1,
        "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
        "segment_number": "1",
        "commitment_profile_id": COMMITMENT_PROFILE_ID,
        "disclosure_class": "C",
        "artifacts": {
            "segment_cbor": {"path": "segment.cbor", "sha256": sha256_hex(&successor)},
            "extensions": {
                "predecessor": {
                    "path": "predecessor.cbor",
                    "sha256": sha256_hex(&predecessor)
                }
            }
        },
        "anchoring": {"tsa": {"status": "pending"}}
    });
    fs::write(
        directory.path().join("segment.verify.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();

    let result = verify_bundle_with_policy(directory.path(), &VerifyPolicy::baseline()).unwrap();
    assert_eq!(result["chain_status"], "predecessor_not_disclosed");
    assert_eq!(result["overall"], "incomplete");
}

#[test]
fn consumed_record_resource_limit_is_a_policy_rejection() {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join("records")).unwrap();
    let mut record = decode_hex("87014800000000000000010100f600");
    record.extend(std::iter::repeat_n(0x81, 34));
    record.push(0xf6);
    let merkle = merkle_root_from_records(std::slice::from_ref(&record));
    let segment = SegmentRecord::new_epoch(
        "b7a1d5e40c6f438e9a75db27c96f31aa",
        ClosurePolicy {
            interval_ms: 60_000,
            batch_record_limit: 2,
            record_limit: None,
            size_limit_bytes: None,
            empty_mode: EmptyMode::Suppress,
        },
        "interval",
        1,
        batch_roots_from_leaf_hashes(&merkle.leaf_hashes, 2).unwrap(),
        merkle.root,
    )
    .unwrap()
    .canonical_cbor_bytes()
    .unwrap();
    fs::write(directory.path().join("segment.cbor"), &segment).unwrap();
    fs::write(directory.path().join("records/record.cbor"), &record).unwrap();
    let manifest = json!({
        "version": 1,
        "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
        "segment_number": "0",
        "commitment_profile_id": COMMITMENT_PROFILE_ID,
        "disclosure_class": "A",
        "artifacts": {
            "segment_cbor": {"path": "segment.cbor", "sha256": sha256_hex(&segment)},
            "record_batches": [{
                "batch_number": "0",
                "records": [{"path": "records/record.cbor", "sha256": sha256_hex(&record)}]
            }]
        },
        "anchoring": {"tsa": {"status": "unavailable"}}
    });
    fs::write(
        directory.path().join("segment.verify.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();

    let result = verify_bundle_with_policy(directory.path(), &VerifyPolicy::baseline()).unwrap();
    assert_eq!(
        result["failure_reasons"],
        json!(["channel_failure", "verifier_policy_rejection"])
    );
}

#[test]
fn artifact_media_types_expose_generic_defaults_and_specialized_candidates() {
    assert_eq!(MANIFEST_MEDIA_TYPE, "application/json");
    assert_eq!(
        SPECIALIZED_MANIFEST_MEDIA_TYPE,
        "application/vnd.vtl.manifest+json"
    );
    assert_eq!(RESULT_MEDIA_TYPE, "application/json");
    assert_eq!(trackone_ledger::vtl::SEGMENT_MEDIA_TYPE, "application/cbor");
    assert_eq!(
        trackone_ledger::vtl::SPECIALIZED_SEGMENT_MEDIA_TYPE,
        "application/vnd.vtl.segment+cbor"
    );
}

#[test]
fn unknown_well_formed_profile_uuid_is_not_reinterpreted() {
    const UNKNOWN_PROFILE: &str = "00000000-0000-4000-8000-000000000000";
    let directory = tempfile::tempdir().unwrap();
    let mut segment = empty_epoch();
    let offset = segment
        .windows(COMMITMENT_PROFILE_ID.len())
        .position(|window| window == COMMITMENT_PROFILE_ID.as_bytes())
        .unwrap();
    segment[offset..offset + UNKNOWN_PROFILE.len()].copy_from_slice(UNKNOWN_PROFILE.as_bytes());
    fs::write(directory.path().join("segment.cbor"), &segment).unwrap();
    let manifest = json!({
        "version": 1,
        "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
        "segment_number": "0",
        "commitment_profile_id": UNKNOWN_PROFILE,
        "disclosure_class": "C",
        "artifacts": {
            "segment_cbor": {"path": "segment.cbor", "sha256": sha256_hex(&segment)}
        },
        "anchoring": {"tsa": {"status": "unavailable"}}
    });
    fs::write(
        directory.path().join("segment.verify.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();

    let result = verify_bundle_with_policy(directory.path(), &VerifyPolicy::baseline()).unwrap();
    assert_eq!(result["commitment_profile_id"], UNKNOWN_PROFILE);
    assert_eq!(
        result["failure_reasons"],
        json!(["channel_failure", "unsupported_commitment_profile"])
    );
}

#[test]
fn malformed_text_profile_uuid_is_an_invalid_segment_artifact() {
    const MALFORMED_PROFILE: &str = "00000000-0000-4000-8000-00000000000G";
    let directory = tempfile::tempdir().unwrap();
    let mut segment = empty_epoch();
    let offset = segment
        .windows(COMMITMENT_PROFILE_ID.len())
        .position(|window| window == COMMITMENT_PROFILE_ID.as_bytes())
        .unwrap();
    segment[offset..offset + MALFORMED_PROFILE.len()].copy_from_slice(MALFORMED_PROFILE.as_bytes());
    fs::write(directory.path().join("segment.cbor"), &segment).unwrap();
    let manifest = json!({
        "version": 1,
        "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
        "segment_number": "0",
        "commitment_profile_id": MALFORMED_PROFILE,
        "disclosure_class": "C",
        "artifacts": {
            "segment_cbor": {"path": "segment.cbor", "sha256": sha256_hex(&segment)}
        },
        "anchoring": {"tsa": {"status": "unavailable"}}
    });
    fs::write(
        directory.path().join("segment.verify.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();

    let result = verify_bundle_with_policy(directory.path(), &VerifyPolicy::baseline()).unwrap();
    assert_eq!(result["commitment_profile_id"], MALFORMED_PROFILE);
    assert_eq!(
        result["failure_reasons"],
        json!(["channel_failure", "invalid_segment_artifact"])
    );
}

#[test]
fn unsupported_artifact_profile_is_compared_with_the_manifest() {
    const UNKNOWN_PROFILE: &str = "00000000-0000-4000-8000-000000000000";
    let directory = tempfile::tempdir().unwrap();
    let mut segment = empty_epoch();
    let offset = segment
        .windows(COMMITMENT_PROFILE_ID.len())
        .position(|window| window == COMMITMENT_PROFILE_ID.as_bytes())
        .unwrap();
    segment[offset..offset + UNKNOWN_PROFILE.len()].copy_from_slice(UNKNOWN_PROFILE.as_bytes());
    fs::write(directory.path().join("segment.cbor"), &segment).unwrap();
    let manifest = json!({
        "version": 1,
        "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
        "segment_number": "0",
        "commitment_profile_id": COMMITMENT_PROFILE_ID,
        "disclosure_class": "C",
        "artifacts": {
            "segment_cbor": {"path": "segment.cbor", "sha256": sha256_hex(&segment)}
        },
        "anchoring": {"tsa": {"status": "unavailable"}}
    });
    fs::write(
        directory.path().join("segment.verify.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();

    let result = verify_bundle_with_policy(directory.path(), &VerifyPolicy::baseline()).unwrap();
    assert_eq!(result["commitment_profile_id"], UNKNOWN_PROFILE);
    assert_eq!(
        result["failure_reasons"],
        json!([
            "channel_failure",
            "commitment_mismatch",
            "unsupported_commitment_profile"
        ])
    );
}

#[test]
fn default_verifier_policy_id_covers_material_policy_inputs() {
    let directory = tempfile::tempdir().unwrap();
    let segment = empty_epoch();
    fs::write(directory.path().join("segment.cbor"), &segment).unwrap();
    let manifest = json!({
        "version": 1,
        "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
        "segment_number": "0",
        "commitment_profile_id": COMMITMENT_PROFILE_ID,
        "disclosure_class": "C",
        "artifacts": {
            "segment_cbor": {"path": "segment.cbor", "sha256": sha256_hex(&segment)}
        },
        "anchoring": {"tsa": {"status": "unavailable"}}
    });
    fs::write(
        directory.path().join("segment.verify.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let material = directory.path().join("policy-input.pem");
    fs::write(&material, b"policy input").unwrap();

    let policy_id = |policy: &VerifyPolicy| {
        verify_bundle_with_policy(directory.path(), policy).unwrap()["verifier_policy_id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let baseline_id = policy_id(&VerifyPolicy::baseline());
    assert!(baseline_id.starts_with("vtl-policy-sha256-"));

    let mut derived_ids = Vec::new();
    let mut policy = VerifyPolicy::baseline();
    policy.tsa_ca_file = Some(material.clone());
    derived_ids.push(policy_id(&policy));
    let mut policy = VerifyPolicy::baseline();
    policy.tsa_crls_file = Some(material.clone());
    derived_ids.push(policy_id(&policy));
    let mut policy = VerifyPolicy::baseline();
    policy.tsa_policy_oid = Some("1.3.6.1.4.1.55555.1".to_string());
    derived_ids.push(policy_id(&policy));
    let mut policy = VerifyPolicy::baseline();
    policy.tsa_signer_cert_sha256 = Some("11".repeat(32).parse().unwrap());
    derived_ids.push(policy_id(&policy));
    let mut policy = VerifyPolicy::baseline();
    policy.max_future_skew = std::time::Duration::from_secs(1);
    derived_ids.push(policy_id(&policy));

    assert!(
        derived_ids
            .iter()
            .all(|identifier| identifier != &baseline_id)
    );
    derived_ids.sort();
    derived_ids.dedup();
    assert_eq!(derived_ids.len(), 5);

    let mut explicit = VerifyPolicy::baseline();
    explicit.verifier_policy_id = Some("deployment-policy-v1".to_string());
    assert_eq!(policy_id(&explicit), "deployment-policy-v1");
}

#[test]
fn declared_extension_artifact_digest_is_verified() {
    let directory = tempfile::tempdir().unwrap();
    let segment = empty_epoch();
    fs::write(directory.path().join("segment.cbor"), &segment).unwrap();
    fs::write(
        directory.path().join("extension.bin"),
        b"tampered extension",
    )
    .unwrap();
    let manifest = json!({
        "version": 1,
        "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
        "segment_number": "0",
        "commitment_profile_id": COMMITMENT_PROFILE_ID,
        "disclosure_class": "C",
        "artifacts": {
            "segment_cbor": {"path": "segment.cbor", "sha256": sha256_hex(&segment)},
            "extensions": {
                "audit": {
                    "path": "extension.bin",
                    "sha256": sha256_hex(b"declared extension")
                }
            }
        },
        "anchoring": {"tsa": {"status": "unavailable"}}
    });
    fs::write(
        directory.path().join("segment.verify.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();

    let error = verify_bundle_with_policy(directory.path(), &VerifyPolicy::baseline()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("artifact reference digest mismatch")
    );
}

#[test]
fn cli_emits_the_unversioned_result_contract_for_missing_tsa() {
    let directory = tempfile::tempdir().unwrap();
    let segment = empty_epoch();
    fs::write(directory.path().join("segment.cbor"), &segment).unwrap();
    let manifest = json!({
        "version": 1,
        "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
        "segment_number": "0",
        "commitment_profile_id": COMMITMENT_PROFILE_ID,
        "disclosure_class": "A",
        "artifacts": {
            "segment_cbor": {
                "path": "segment.cbor",
                "sha256": sha256_hex(&segment),
            }
        },
        "anchoring": {"tsa": {"status": "unavailable"}}
    });
    fs::write(
        directory.path().join("segment.verify.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_trackone-evidence"))
        .args(["verify", "--root"])
        .arg(directory.path())
        .arg("--json")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result.get("version").is_none());
    assert_eq!(result["claimed_disclosure_class"], "A");
    assert_eq!(result["verification_scope"], "public_recompute");
    assert_eq!(result["chain_status"], "epoch");
    assert_eq!(result["channels"]["tsa"]["status"], "missing");
    assert_eq!(result["overall"], "failure");
    assert_eq!(result["failure_reasons"], json!(["channel_failure"]));
}

#[test]
fn cli_rejects_pre_slate_manifest_versions_without_a_result() {
    let directory = tempfile::tempdir().unwrap();
    let segment = empty_epoch();
    fs::write(directory.path().join("segment.cbor"), &segment).unwrap();
    let manifest = json!({
        "version": 3,
        "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
        "segment_number": "0",
        "commitment_profile_id": COMMITMENT_PROFILE_ID,
        "disclosure_class": "C",
        "artifacts": {
            "segment_cbor": {"path": "segment.cbor", "sha256": sha256_hex(&segment)}
        },
        "anchoring": {"tsa": {"status": "unavailable"}}
    });
    fs::write(
        directory.path().join("segment.verify.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_trackone-evidence"))
        .args(["verify", "--root"])
        .arg(directory.path())
        .arg("--json")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("version must be 1"));
}

#[test]
fn cli_rejects_the_removed_partial_verification_scope_token() {
    let output = Command::new(env!("CARGO_BIN_EXE_trackone-evidence"))
        .args([
            "verify",
            "--root",
            ".",
            "--scope",
            "partial_verification",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid --scope"));
}
