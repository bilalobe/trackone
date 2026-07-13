use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use trackone_evidence::{ExportOptions, PolicyMode, VerifyOptions, export_bundle, verify_bundle};
use trackone_ingest::{
    AdmissionStateUpdate, REJECTION_REASONS, REJECTION_SOURCES, RejectionRecord, RejectionSource,
    hash_rejected_line, validate_rejection_record,
};
use trackone_ledger::types::{
    BlockHeaderV1, block_header_v1_from_canonical_leaves, day_record_v1_single_batch,
};
use trackone_ledger::{canonical_cbor, sha256_hex};

fn temp_dir(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "trackone-evidence-test-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn write_json(path: &Path, value: &Value) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn copy_file_for_test(src: &Path, dst: &Path) {
    fs::create_dir_all(dst.parent().unwrap()).unwrap();
    fs::copy(src, dst).unwrap();
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn run_git(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn init_git_repo(repo: &Path) {
    fs::create_dir_all(repo).unwrap();
    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "TrackOne Tests"]);
    run_git(repo, &["config", "user.email", "tests@example.invalid"]);
}

fn trackone_evidence_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_trackone-evidence"))
}

fn artifact_ref(root: &Path, path: &Path) -> Value {
    json!({
        "path": path.strip_prefix(root).unwrap().to_string_lossy(),
        "sha256": sha256_hex(&fs::read(path).unwrap()),
    })
}

fn write_bundle(root: &Path) {
    let day = "2025-10-07";
    let site = "test-site";
    let facts_dir = root.join("facts");
    let blocks_dir = root.join("blocks");
    let day_dir = root.join("day");
    let prov_dir = root.join("provisioning");
    let st_dir = root.join("sensorthings");
    fs::create_dir_all(&facts_dir).unwrap();
    fs::create_dir_all(&blocks_dir).unwrap();
    fs::create_dir_all(&day_dir).unwrap();
    fs::create_dir_all(&prov_dir).unwrap();
    fs::create_dir_all(&st_dir).unwrap();

    let fact_a = canonical_cbor::canonicalize_json_bytes_to_cbor(
        br#"{"fc":1,"kind":"env.sample","pod_id":"pod-001"}"#,
    )
    .unwrap();
    let fact_b = canonical_cbor::canonicalize_json_bytes_to_cbor(
        br#"{"fc":2,"kind":"env.sample","pod_id":"pod-001"}"#,
    )
    .unwrap();
    fs::write(facts_dir.join("pod-001-00000001.cbor"), &fact_a).unwrap();
    fs::write(facts_dir.join("pod-001-00000002.cbor"), &fact_b).unwrap();
    let leaves = vec![fact_a, fact_b];

    let block =
        block_header_v1_from_canonical_leaves(site, day, format!("{site}-{day}-00"), &leaves);
    let day_record = day_record_v1_single_batch(site, day, "00".repeat(32), block.clone());
    let block_path = blocks_dir.join(format!("{day}-00.block.json"));
    let day_json_path = day_dir.join(format!("{day}.json"));
    let day_cbor_path = day_dir.join(format!("{day}.cbor"));
    fs::write(
        &block_path,
        [block.canonical_json_bytes().unwrap(), b"\n".to_vec()].concat(),
    )
    .unwrap();
    fs::write(
        &day_json_path,
        serde_json::to_vec_pretty(&day_record).unwrap(),
    )
    .unwrap();
    fs::write(&day_cbor_path, day_record.canonical_cbor_bytes().unwrap()).unwrap();
    fs::write(
        day_dir.join(format!("{day}.cbor.sha256")),
        format!("{}\n", sha256_hex(&fs::read(&day_cbor_path).unwrap())),
    )
    .unwrap();

    let ots_path = day_dir.join(format!("{day}.cbor.ots"));
    fs::write(
        &ots_path,
        format!(
            "STATIONARY-OTS:{}\n",
            sha256_hex(&fs::read(&day_cbor_path).unwrap())
        ),
    )
    .unwrap();
    let meta_path = day_dir.join(format!("{day}.ots.meta.json"));
    write_json(
        &meta_path,
        &json!({
            "day": day,
            "artifact": format!("day/{day}.cbor"),
            "artifact_sha256": sha256_hex(&fs::read(&day_cbor_path).unwrap()),
            "ots_proof": format!("day/{day}.cbor.ots"),
            "milestone": "test-only"
        }),
    );

    let provisioning_input = prov_dir.join("authoritative-input.json");
    let provisioning_records = prov_dir.join("records.json");
    let projection = st_dir.join(format!("{day}.observations.json"));
    write_json(
        &provisioning_input,
        &json!({"version": 1, "site_id": site, "records": []}),
    );
    write_json(
        &provisioning_records,
        &json!({"version": 1, "site_id": site, "records": []}),
    );
    write_json(
        &projection,
        &json!({"generated_at_utc": "2025-10-07T00:00:00Z", "site_id": site, "projection_mode": "read_only_canonical_fact_json", "things": [], "datastreams": [], "observed_properties": [], "observations": []}),
    );

    let manifest = json!({
        "version": 1,
        "date": day,
        "site": site,
        "device_id": "pod-001",
        "frame_count": 2,
        "frames_file": "frames.ndjson",
        "facts_dir": "facts",
        "artifacts": {
            "block": artifact_ref(root, &block_path),
            "day_cbor": artifact_ref(root, &day_cbor_path),
            "day_json": artifact_ref(root, &day_json_path),
            "day_sha256": artifact_ref(root, &day_dir.join(format!("{day}.cbor.sha256"))),
            "day_ots": artifact_ref(root, &ots_path),
            "day_ots_meta": artifact_ref(root, &meta_path),
            "provisioning_input": artifact_ref(root, &provisioning_input),
            "provisioning_records": artifact_ref(root, &provisioning_records),
            "sensorthings_projection": artifact_ref(root, &projection)
        },
        "anchoring": {
            "policy": {"mode": "warn"},
            "channels": {"ots": {"enabled": true, "status": "pending", "reason": "proof-created"}},
            "overall": "success"
        },
        "verification_bundle": {
            "disclosure_class": "A",
            "commitment_profile_id": "verifiable-telemetry-canonical-cbor-v1",
            "checks_executed": [],
            "checks_skipped": []
        }
    });
    write_json(&day_dir.join(format!("{day}.verify.json")), &manifest);
    fs::write(root.join("frames.ndjson"), "{}\n").unwrap();
}

#[test]
fn rust_verifier_accepts_bundle_without_python_runtime() {
    let root = temp_dir("verify");
    write_bundle(&root);
    let summary = verify_bundle(&VerifyOptions {
        root: root.clone(),
        facts: root.join("facts"),
        policy_mode: PolicyMode::Warn,
        disclosure_class: "A".to_string(),
        commitment_profile_id: "verifiable-telemetry-canonical-cbor-v1".to_string(),
        require_ots: false,
        allow_placeholder: true,
    })
    .unwrap();
    assert_eq!(summary["overall"], "success");
    assert_eq!(summary["checks"]["root_match"], true);
    assert_eq!(summary["verification"]["publicly_recomputable"], true);
}

#[test]
fn rust_export_writes_detached_bundle_and_reverifies() {
    let root = temp_dir("export-source");
    let evidence_repo = temp_dir("export-dest");
    write_bundle(&root);
    let exported = export_bundle(&ExportOptions {
        pipeline_dir: root,
        evidence_repo,
        site: "test-site".to_string(),
        day: "2025-10-07".to_string(),
        include_frames: false,
        git_commit: false,
        sign: false,
        tag: false,
        tag_name: None,
        bundle_out: None,
    })
    .unwrap();
    assert!(!exported.join("frames.ndjson").exists());
    let manifest: Value =
        serde_json::from_slice(&fs::read(exported.join("day/2025-10-07.verify.json")).unwrap())
            .unwrap();
    assert!(manifest.get("frames_file").is_none());
    assert_eq!(
        manifest["artifacts"]["day_ots_meta"]["path"],
        "day/2025-10-07.ots.meta.json"
    );
    let meta: Value =
        serde_json::from_slice(&fs::read(exported.join("day/2025-10-07.ots.meta.json")).unwrap())
            .unwrap();
    assert!(meta.get("milestone").is_none());

    let summary = verify_bundle(&VerifyOptions {
        root: exported.clone(),
        facts: exported.join("facts"),
        policy_mode: PolicyMode::Warn,
        disclosure_class: "A".to_string(),
        commitment_profile_id: "verifiable-telemetry-canonical-cbor-v1".to_string(),
        require_ots: false,
        allow_placeholder: true,
    })
    .unwrap();
    assert_eq!(summary["overall"], "success");
}

#[test]
fn rust_export_honors_manifest_strict_policy() {
    let root = temp_dir("export-strict-source");
    let evidence_repo = temp_dir("export-strict-dest");
    write_bundle(&root);

    let manifest_path = root.join("day/2025-10-07.verify.json");
    let mut manifest = read_json(&manifest_path);
    manifest["anchoring"]["policy"]["mode"] = json!("strict");
    write_json(&manifest_path, &manifest);
    fs::write(
        root.join("day/2025-10-07.cbor.ots"),
        b"OTS_PROOF_PLACEHOLDER\n",
    )
    .unwrap();

    let verifier_summary = verify_bundle(&VerifyOptions {
        root: root.clone(),
        facts: root.join("facts"),
        policy_mode: PolicyMode::Strict,
        disclosure_class: "A".to_string(),
        commitment_profile_id: "verifiable-telemetry-canonical-cbor-v1".to_string(),
        require_ots: false,
        allow_placeholder: true,
    })
    .unwrap();
    assert_eq!(verifier_summary["overall"], "failed");

    let err = export_bundle(&ExportOptions {
        pipeline_dir: root,
        evidence_repo,
        site: "test-site".to_string(),
        day: "2025-10-07".to_string(),
        include_frames: false,
        git_commit: false,
        sign: false,
        tag: false,
        tag_name: None,
        bundle_out: None,
    })
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("fresh verification failed; refusing to export unverified evidence")
    );
}

#[test]
fn rust_export_finds_parent_proofs_meta_sidecar() {
    let root = temp_dir("export-parent-proof-source");
    let pipeline_dir = root.join("runs/2025-10-07/output");
    let evidence_repo = temp_dir("export-parent-proof-dest");
    write_bundle(&pipeline_dir);

    let day = "2025-10-07";
    let day_meta = pipeline_dir.join(format!("day/{day}.ots.meta.json"));
    let parent_meta = root.join(format!("proofs/{day}.ots.meta.json"));
    copy_file_for_test(&day_meta, &parent_meta);
    fs::remove_file(&day_meta).unwrap();

    let manifest_path = pipeline_dir.join(format!("day/{day}.verify.json"));
    let mut manifest = read_json(&manifest_path);
    manifest["artifacts"]
        .as_object_mut()
        .unwrap()
        .remove("day_ots_meta");
    write_json(&manifest_path, &manifest);

    let exported = export_bundle(&ExportOptions {
        pipeline_dir,
        evidence_repo,
        site: "test-site".to_string(),
        day: day.to_string(),
        include_frames: false,
        git_commit: false,
        sign: false,
        tag: false,
        tag_name: None,
        bundle_out: None,
    })
    .unwrap();

    let exported_meta = exported.join(format!("day/{day}.ots.meta.json"));
    assert!(exported_meta.exists());
    let meta = read_json(&exported_meta);
    assert_eq!(meta["artifact"], format!("day/{day}.cbor"));
    assert_eq!(meta["ots_proof"], format!("day/{day}.cbor.ots"));
}

#[test]
fn rust_export_creates_bundle_output_parent_dirs() {
    let root = temp_dir("export-bundle-parent-source");
    let evidence_repo = temp_dir("export-bundle-parent-dest");
    let bundle_out = temp_dir("export-bundle-parent-out").join("fresh/artifacts/evidence.bundle");
    write_bundle(&root);
    init_git_repo(&evidence_repo);

    export_bundle(&ExportOptions {
        pipeline_dir: root,
        evidence_repo,
        site: "test-site".to_string(),
        day: "2025-10-07".to_string(),
        include_frames: false,
        git_commit: false,
        sign: false,
        tag: false,
        tag_name: None,
        bundle_out: Some(bundle_out.clone()),
    })
    .unwrap();

    assert!(bundle_out.exists());
}

#[test]
fn rust_cli_verify_exits_nonzero_for_failed_overall_summary() {
    let root = temp_dir("cli-strict-source");
    write_bundle(&root);
    fs::write(
        root.join("day/2025-10-07.cbor.ots"),
        b"OTS_PROOF_PLACEHOLDER\n",
    )
    .unwrap();

    let output = Command::new(trackone_evidence_bin())
        .args([
            "verify",
            "--root",
            root.to_str().unwrap(),
            "--facts",
            root.join("facts").to_str().unwrap(),
            "--policy-mode",
            "strict",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("\"overall\": \"failed\""));
}

#[test]
fn rust_verifier_rejects_tampered_fact_root() {
    let root = temp_dir("tamper");
    write_bundle(&root);
    fs::write(
        root.join("facts/pod-001-00000002.cbor"),
        canonical_cbor::canonicalize_json_bytes_to_cbor(
            br#"{"fc":999,"kind":"env.sample","pod_id":"pod-001"}"#,
        )
        .unwrap(),
    )
    .unwrap();
    let err = verify_bundle(&VerifyOptions {
        root: root.clone(),
        facts: root.join("facts"),
        policy_mode: PolicyMode::Warn,
        disclosure_class: "A".to_string(),
        commitment_profile_id: "verifiable-telemetry-canonical-cbor-v1".to_string(),
        require_ots: false,
        allow_placeholder: true,
    })
    .unwrap_err();
    assert!(err.to_string().contains("fact-root-mismatch"));
}

#[test]
fn rust_verifier_rejects_manifest_digest_mismatch() {
    let root = temp_dir("bad-manifest-digest");
    write_bundle(&root);
    let manifest_path = root.join("day/2025-10-07.verify.json");
    let mut manifest = read_json(&manifest_path);
    manifest["artifacts"]["day_cbor"]["sha256"] =
        json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    write_json(&manifest_path, &manifest);

    let err = verify_bundle(&VerifyOptions {
        root: root.clone(),
        facts: root.join("facts"),
        policy_mode: PolicyMode::Warn,
        disclosure_class: "A".to_string(),
        commitment_profile_id: "verifiable-telemetry-canonical-cbor-v1".to_string(),
        require_ots: false,
        allow_placeholder: true,
    })
    .unwrap_err();
    assert!(err.to_string().contains("artifact sha256 mismatch"));
}

#[test]
fn rust_verifier_rejects_nonportable_manifest_artifact_path() {
    let root = temp_dir("nonportable-path");
    write_bundle(&root);
    let manifest_path = root.join("day/2025-10-07.verify.json");
    let mut manifest = read_json(&manifest_path);
    manifest["artifacts"]["day_cbor"]["path"] = json!("../day/2025-10-07.cbor");
    write_json(&manifest_path, &manifest);

    let err = verify_bundle(&VerifyOptions {
        root: root.clone(),
        facts: root.join("facts"),
        policy_mode: PolicyMode::Warn,
        disclosure_class: "A".to_string(),
        commitment_profile_id: "verifiable-telemetry-canonical-cbor-v1".to_string(),
        require_ots: false,
        allow_placeholder: true,
    })
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("manifest artifact path escapes root")
    );
}

#[test]
fn rust_verifier_rejects_noncanonical_day_cbor() {
    let root = temp_dir("noncanonical-day-cbor");
    write_bundle(&root);
    fs::write(root.join("day/2025-10-07.cbor"), b"not-canonical-cbor").unwrap();
    let manifest_path = root.join("day/2025-10-07.verify.json");
    let mut manifest = read_json(&manifest_path);
    manifest["artifacts"]["day_cbor"] = artifact_ref(&root, &root.join("day/2025-10-07.cbor"));
    write_json(&manifest_path, &manifest);

    let err = verify_bundle(&VerifyOptions {
        root: root.clone(),
        facts: root.join("facts"),
        policy_mode: PolicyMode::Warn,
        disclosure_class: "A".to_string(),
        commitment_profile_id: "verifiable-telemetry-canonical-cbor-v1".to_string(),
        require_ots: false,
        allow_placeholder: true,
    })
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("day artifact is not canonical commitment bytes")
    );
}

#[test]
fn rust_verifier_rejects_empty_class_a_fact_disclosure() {
    let root = temp_dir("empty-class-a");
    write_bundle(&root);
    for entry in fs::read_dir(root.join("facts")).unwrap() {
        fs::remove_file(entry.unwrap().path()).unwrap();
    }

    let err = verify_bundle(&VerifyOptions {
        root: root.clone(),
        facts: root.join("facts"),
        policy_mode: PolicyMode::Warn,
        disclosure_class: "A".to_string(),
        commitment_profile_id: "verifiable-telemetry-canonical-cbor-v1".to_string(),
        require_ots: false,
        allow_placeholder: true,
    })
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("CBOR facts are required for Class A verification")
    );
}

#[test]
fn rust_verifier_rejects_missing_class_a_fact_dir_as_empty_disclosure() {
    let root = temp_dir("missing-class-a-facts");
    write_bundle(&root);
    fs::remove_dir_all(root.join("facts")).unwrap();

    let err = verify_bundle(&VerifyOptions {
        root: root.clone(),
        facts: root.join("facts"),
        policy_mode: PolicyMode::Warn,
        disclosure_class: "A".to_string(),
        commitment_profile_id: "verifiable-telemetry-canonical-cbor-v1".to_string(),
        require_ots: false,
        allow_placeholder: true,
    })
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("CBOR facts are required for Class A verification")
    );
}

#[test]
fn rust_verifier_reports_class_b_as_not_publicly_recomputable() {
    let root = temp_dir("class-b");
    write_bundle(&root);
    let manifest_path = root.join("day/2025-10-07.verify.json");
    let mut manifest = read_json(&manifest_path);
    manifest["verification_bundle"]["disclosure_class"] = json!("B");
    write_json(&manifest_path, &manifest);

    let summary = verify_bundle(&VerifyOptions {
        root: root.clone(),
        facts: root.join("facts"),
        policy_mode: PolicyMode::Warn,
        disclosure_class: "B".to_string(),
        commitment_profile_id: "verifiable-telemetry-canonical-cbor-v1".to_string(),
        require_ots: false,
        allow_placeholder: true,
    })
    .unwrap();
    assert_eq!(summary["overall"], "success");
    assert_eq!(summary["verification"]["publicly_recomputable"], false);
    assert!(
        summary["checks_skipped"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["check"] == "fact_level_recompute"
                && entry["reason"] == "disclosure-class-b")
    );
}

#[test]
fn rust_verifier_accepts_nonzero_previous_day_root_chain_input() {
    let root = temp_dir("nonzero-prev-day-root");
    write_bundle(&root);
    let day = "2025-10-07";
    let block: BlockHeaderV1 =
        serde_json::from_value(read_json(&root.join("blocks/2025-10-07-00.block.json"))).unwrap();
    let day_record = day_record_v1_single_batch("test-site", day, "11".repeat(32), block);
    let day_json_path = root.join(format!("day/{day}.json"));
    let day_cbor_path = root.join(format!("day/{day}.cbor"));
    let day_sha_path = root.join(format!("day/{day}.cbor.sha256"));
    let ots_path = root.join(format!("day/{day}.cbor.ots"));
    let meta_path = root.join(format!("day/{day}.ots.meta.json"));
    write_json(&day_json_path, &serde_json::to_value(&day_record).unwrap());
    fs::write(&day_cbor_path, day_record.canonical_cbor_bytes().unwrap()).unwrap();
    let day_sha = sha256_hex(&fs::read(&day_cbor_path).unwrap());
    fs::write(&day_sha_path, format!("{day_sha}\n")).unwrap();
    fs::write(&ots_path, format!("STATIONARY-OTS:{day_sha}\n")).unwrap();
    write_json(
        &meta_path,
        &json!({
            "day": day,
            "artifact": format!("day/{day}.cbor"),
            "artifact_sha256": day_sha,
            "ots_proof": format!("day/{day}.cbor.ots")
        }),
    );

    let manifest_path = root.join(format!("day/{day}.verify.json"));
    let mut manifest = read_json(&manifest_path);
    manifest["artifacts"]["day_json"] = artifact_ref(&root, &day_json_path);
    manifest["artifacts"]["day_cbor"] = artifact_ref(&root, &day_cbor_path);
    manifest["artifacts"]["day_sha256"] = artifact_ref(&root, &day_sha_path);
    manifest["artifacts"]["day_ots"] = artifact_ref(&root, &ots_path);
    manifest["artifacts"]["day_ots_meta"] = artifact_ref(&root, &meta_path);
    write_json(&manifest_path, &manifest);

    let summary = verify_bundle(&VerifyOptions {
        root: root.clone(),
        facts: root.join("facts"),
        policy_mode: PolicyMode::Warn,
        disclosure_class: "A".to_string(),
        commitment_profile_id: "verifiable-telemetry-canonical-cbor-v1".to_string(),
        require_ots: false,
        allow_placeholder: true,
    })
    .unwrap();
    assert_eq!(summary["overall"], "success");
}

#[test]
fn rust_verifier_rejects_multi_batch_day_projection_for_current_manifest() {
    let root = temp_dir("multi-batch-day");
    write_bundle(&root);
    let day_json_path = root.join("day/2025-10-07.json");
    let day_cbor_path = root.join("day/2025-10-07.cbor");
    let mut day_record = read_json(&day_json_path);
    let first_batch = day_record["batches"][0].clone();
    day_record["batches"]
        .as_array_mut()
        .unwrap()
        .push(first_batch);
    fs::write(
        &day_json_path,
        serde_json::to_vec_pretty(&day_record).unwrap(),
    )
    .unwrap();
    fs::write(
        &day_cbor_path,
        canonical_cbor::canonicalize_json_bytes_to_cbor(&fs::read(&day_json_path).unwrap())
            .unwrap(),
    )
    .unwrap();

    let manifest_path = root.join("day/2025-10-07.verify.json");
    let mut manifest = read_json(&manifest_path);
    manifest["artifacts"]["day_json"] = artifact_ref(&root, &day_json_path);
    manifest["artifacts"]["day_cbor"] = artifact_ref(&root, &day_cbor_path);
    write_json(&manifest_path, &manifest);

    let err = verify_bundle(&VerifyOptions {
        root: root.clone(),
        facts: root.join("facts"),
        policy_mode: PolicyMode::Warn,
        disclosure_class: "A".to_string(),
        commitment_profile_id: "verifiable-telemetry-canonical-cbor-v1".to_string(),
        require_ots: false,
        allow_placeholder: true,
    })
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("day projection must contain exactly one batch")
    );
}

#[test]
fn rust_rejection_audit_contract_matches_stable_shape() {
    let digest = hash_rejected_line("{bad}\n");
    let record = RejectionRecord::new(
        "pod-001",
        Some(7),
        "invalid_json",
        "2025-10-07T00:00:00+00:00",
        digest,
        RejectionSource::Parse,
    )
    .unwrap();
    validate_rejection_record(&record).unwrap();
    let update = AdmissionStateUpdate {
        device_key: "1".to_string(),
        highest_fc_seen: 7,
        last_seen: "2025-10-07T00:00:00+00:00".to_string(),
        msg_type: 1,
        flags: 0,
    };
    assert_eq!(update.highest_fc_seen, 7);

    let mut invalid = record.clone();
    invalid.reason = "new-unreviewed-reason".to_string();
    assert!(validate_rejection_record(&invalid).is_err());
}

#[test]
fn rust_rejection_audit_schema_matches_taxonomy() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap();
    let schema_path = repo_root.join("toolset/unified/schemas/rejection_audit.schema.json");
    if !schema_path.is_file() {
        eprintln!(
            "skipping: rejection audit schema is not present at {}",
            schema_path.display()
        );
        return;
    }
    let schema: Value = serde_json::from_slice(&fs::read(schema_path).unwrap()).unwrap();
    let reasons = schema["properties"]["reason"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()
        .unwrap();
    let sources = schema["properties"]["source"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()
        .unwrap();
    assert_eq!(reasons, REJECTION_REASONS);
    assert_eq!(sources, REJECTION_SOURCES);
}
