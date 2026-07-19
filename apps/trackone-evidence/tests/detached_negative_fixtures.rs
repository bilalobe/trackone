//! Detached negative-corpus integration coverage.

use serde::Deserialize;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use trackone_ledger::types::{block_header_v1_from_canonical_leaves, day_record_v1_single_batch};
use trackone_ledger::{canonical_cbor, sha256_hex};

const DAY: &str = "2025-10-07";
const SITE: &str = "test-site";

#[derive(Debug, Deserialize)]
struct FixtureCorpus {
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
struct FixtureCase {
    id: String,
    path: String,
    disclosure_class: String,
    policy_mode: String,
    expect_success: bool,
    expect_contains: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn temp_dir(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "trackone-evidence-detached-fixtures-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_trackone-evidence"))
}

fn write_json(path: &Path, value: &Value) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn artifact_ref(root: &Path, path: &Path) -> Value {
    json!({
        "path": path.strip_prefix(root).unwrap().to_string_lossy(),
        "sha256": sha256_hex(&fs::read(path).unwrap()),
    })
}

fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir(&src_path, &dst_path);
        } else {
            fs::create_dir_all(dst_path.parent().unwrap()).unwrap();
            fs::copy(&src_path, &dst_path).unwrap();
        }
    }
}

fn write_manifest(root: &Path, frame_count: u64) {
    let manifest = json!({
        "version": 1,
        "date": DAY,
        "site": SITE,
        "device_id": "pod-001",
        "frame_count": frame_count,
        "frames_file": "frames.ndjson",
        "facts_dir": "facts",
        "artifacts": {
            "block": artifact_ref(root, &root.join(format!("blocks/{DAY}-00.block.json"))),
            "day_cbor": artifact_ref(root, &root.join(format!("day/{DAY}.cbor"))),
            "day_json": artifact_ref(root, &root.join(format!("day/{DAY}.json"))),
            "day_sha256": artifact_ref(root, &root.join(format!("day/{DAY}.cbor.sha256"))),
            "day_ots": artifact_ref(root, &root.join(format!("day/{DAY}.cbor.ots"))),
            "day_ots_meta": artifact_ref(root, &root.join(format!("day/{DAY}.ots.meta.json")))
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
    write_json(&root.join(format!("day/{DAY}.verify.json")), &manifest);
}

fn refresh_commitment(root: &Path, prev_day_root: &str) {
    let mut fact_files = fs::read_dir(root.join("facts"))
        .unwrap()
        .filter_map(|entry| entry.ok().map(|item| item.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("cbor"))
        .collect::<Vec<_>>();
    fact_files.sort();
    let leaves = fact_files
        .iter()
        .map(fs::read)
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    let block =
        block_header_v1_from_canonical_leaves(SITE, DAY, format!("{SITE}-{DAY}-00"), &leaves);
    let day_record = day_record_v1_single_batch(SITE, DAY, prev_day_root, block.clone());

    let block_path = root.join(format!("blocks/{DAY}-00.block.json"));
    let day_json_path = root.join(format!("day/{DAY}.json"));
    let day_cbor_path = root.join(format!("day/{DAY}.cbor"));
    fs::create_dir_all(block_path.parent().unwrap()).unwrap();
    fs::create_dir_all(day_json_path.parent().unwrap()).unwrap();
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
    let day_sha = sha256_hex(&fs::read(&day_cbor_path).unwrap());
    fs::write(
        root.join(format!("day/{DAY}.cbor.sha256")),
        format!("{day_sha}\n"),
    )
    .unwrap();
    fs::write(
        root.join(format!("day/{DAY}.cbor.ots")),
        format!("STATIONARY-OTS:{day_sha}\n"),
    )
    .unwrap();
    write_json(
        &root.join(format!("day/{DAY}.ots.meta.json")),
        &json!({
            "day": DAY,
            "artifact": format!("day/{DAY}.cbor"),
            "artifact_sha256": day_sha,
            "ots_proof": format!("day/{DAY}.cbor.ots")
        }),
    );
    write_manifest(root, fact_files.len() as u64);
}

fn write_good_bundle(root: &Path) {
    fs::create_dir_all(root.join("facts")).unwrap();
    let fact_a = canonical_cbor::canonicalize_json_bytes_to_cbor(
        br#"{"fc":1,"kind":"env.sample","pod_id":"pod-001"}"#,
    )
    .unwrap();
    let fact_b = canonical_cbor::canonicalize_json_bytes_to_cbor(
        br#"{"fc":2,"kind":"env.sample","pod_id":"pod-001"}"#,
    )
    .unwrap();
    fs::write(root.join("facts/pod-001-00000001.cbor"), fact_a).unwrap();
    fs::write(root.join("facts/pod-001-00000002.cbor"), fact_b).unwrap();
    fs::write(root.join("frames.ndjson"), "{}\n").unwrap();
    refresh_commitment(root, &"00".repeat(32));
}

fn add_rejection_audit(root: &Path, name: &str, reason: &str, source: &str, fc: Option<u64>) {
    fs::create_dir_all(root.join("audit")).unwrap();
    let path = root.join(format!("audit/{name}.ndjson"));
    let device_id = if source == "parse" { "" } else { "pod-001" };
    let record = json!({
        "device_id": device_id,
        "fc": fc,
        "reason": reason,
        "observed_at_utc": "2025-10-07T00:00:00Z",
        "frame_sha256": sha256_hex(format!("{name}:{reason}").as_bytes()),
        "source": source
    });
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string(&record).unwrap()),
    )
    .unwrap();
    let manifest_path = root.join(format!("day/{DAY}.verify.json"));
    let mut manifest = read_json(&manifest_path);
    manifest["artifacts"]["rejection_audit"] = artifact_ref(root, &path);
    write_json(&manifest_path, &manifest);
}

fn with_bundle<F>(corpus: &Path, id: &str, mutate: F)
where
    F: FnOnce(&Path),
{
    let root = corpus.join("fixtures").join(id);
    let _ = fs::remove_dir_all(&root);
    write_good_bundle(&root);
    mutate(&root);
}

fn write_cases_manifest(corpus: &Path) {
    let cases = json!({
        "schema": "trackone-beta-negative-fixtures-v1",
        "cases": [
            {"id": "baseline-good-class-a", "path": "fixtures/baseline-good-class-a", "disclosure_class": "A", "policy_mode": "warn", "expect_success": true, "expect_contains": "\"overall\": \"success\""},
            {"id": "manifest-missing-required-field", "path": "fixtures/manifest-missing-required-field", "disclosure_class": "A", "policy_mode": "warn", "expect_success": false, "expect_contains": "missing field"},
            {"id": "manifest-nonportable-path", "path": "fixtures/manifest-nonportable-path", "disclosure_class": "A", "policy_mode": "warn", "expect_success": false, "expect_contains": "manifest artifact path escapes root"},
            {"id": "manifest-digest-mismatch", "path": "fixtures/manifest-digest-mismatch", "disclosure_class": "A", "policy_mode": "warn", "expect_success": false, "expect_contains": "manifest artifact sha256 mismatch"},
            {"id": "manifest-malformed-verification-bundle", "path": "fixtures/manifest-malformed-verification-bundle", "disclosure_class": "A", "policy_mode": "warn", "expect_success": false, "expect_contains": "commitment_profile_id"},
            {"id": "disclosure-class-a-empty-facts", "path": "fixtures/disclosure-class-a-empty-facts", "disclosure_class": "A", "policy_mode": "warn", "expect_success": false, "expect_contains": "CBOR facts are required"},
            {"id": "disclosure-class-b-skips-recompute", "path": "fixtures/disclosure-class-b-skips-recompute", "disclosure_class": "B", "policy_mode": "warn", "expect_success": true, "expect_contains": "disclosure-class-b"},
            {"id": "disclosure-class-c-skips-recompute", "path": "fixtures/disclosure-class-c-skips-recompute", "disclosure_class": "C", "policy_mode": "warn", "expect_success": true, "expect_contains": "disclosure-class-c"},
            {"id": "replay-duplicate-rejection-audit", "path": "fixtures/replay-duplicate-rejection-audit", "disclosure_class": "A", "policy_mode": "warn", "expect_success": true, "expect_contains": "\"rejection_records\": 1"},
            {"id": "replay-out-of-window-rejection-audit", "path": "fixtures/replay-out-of-window-rejection-audit", "disclosure_class": "A", "policy_mode": "warn", "expect_success": true, "expect_contains": "\"rejection_records\": 1"},
            {"id": "malformed-frame-rejection-audit", "path": "fixtures/malformed-frame-rejection-audit", "disclosure_class": "A", "policy_mode": "warn", "expect_success": true, "expect_contains": "\"commitment_material\": false"},
            {"id": "rejection-audit-as-commitment-material", "path": "fixtures/rejection-audit-as-commitment-material", "disclosure_class": "A", "policy_mode": "warn", "expect_success": false, "expect_contains": "rejection audit must not be commitment material"},
            {"id": "empty-batch-day", "path": "fixtures/empty-batch-day", "disclosure_class": "A", "policy_mode": "warn", "expect_success": false, "expect_contains": "exactly one batch"},
            {"id": "multi-batch-day", "path": "fixtures/multi-batch-day", "disclosure_class": "A", "policy_mode": "warn", "expect_success": false, "expect_contains": "exactly one batch"},
            {"id": "nonzero-previous-day-root-chain-input", "path": "fixtures/nonzero-previous-day-root-chain-input", "disclosure_class": "A", "policy_mode": "warn", "expect_success": true, "expect_contains": "\"overall\": \"success\""},
            {"id": "canonical-cbor-shortest-form-fact-failure", "path": "fixtures/canonical-cbor-shortest-form-fact-failure", "disclosure_class": "A", "policy_mode": "warn", "expect_success": false, "expect_contains": "not shortest-form"},
            {"id": "decoded-bundle-fact-contract-failure", "path": "fixtures/decoded-bundle-fact-contract-failure", "disclosure_class": "A", "policy_mode": "warn", "expect_success": false, "expect_contains": "fact artifact is not canonical CBOR"}
        ]
    });
    write_json(&corpus.join("cases.json"), &cases);
}

fn write_corpus_readme(corpus: &Path) {
    fs::write(
        corpus.join("README.md"),
        r#"# TrackOne Beta Negative Fixtures v1

This corpus is the ADR-055 beta floor for detached verifier refusal behavior.
Each fixture is a self-contained evidence bundle rooted under `fixtures/<id>/`
and is runnable through the public Rust verifier CLI:

```bash
cargo run --locked -p trackone-evidence -- verify \
  --root toolset/vectors/trackone-beta-negative-v1/fixtures/<id> \
  --facts toolset/vectors/trackone-beta-negative-v1/fixtures/<id>/facts \
  --json \
  --policy-mode <warn|strict> \
  --disclosure-class <A|B|C>
```

`cases.json` records the expected status and the diagnostic fragment that a
detached verifier must surface. The fixtures cover verifier-manifest errors,
disclosure-class recomputation behavior, replay/admission rejection audit
records, malformed-frame audit records, batch-shape failures, non-zero
previous-day-root chaining input, and canonical-CBOR/decoded fact refusal.

Rejected frames are represented only as operator-audit evidence under `audit/`.
They are not commitment leaves and must not be placed under `facts/`.
"#,
    )
    .unwrap();
}

#[test]
#[ignore = "regenerates public fixture files under toolset/vectors"]
fn regenerate_public_beta_negative_fixture_corpus() {
    let corpus = repo_root().join("toolset/vectors/trackone-beta-negative-v1");
    let _ = fs::remove_dir_all(&corpus);
    fs::create_dir_all(&corpus).unwrap();
    write_corpus_readme(&corpus);
    write_cases_manifest(&corpus);

    with_bundle(&corpus, "baseline-good-class-a", |_| {});
    with_bundle(&corpus, "manifest-missing-required-field", |root| {
        let manifest_path = root.join(format!("day/{DAY}.verify.json"));
        let mut manifest = read_json(&manifest_path);
        manifest.as_object_mut().unwrap().remove("device_id");
        write_json(&manifest_path, &manifest);
    });
    with_bundle(&corpus, "manifest-nonportable-path", |root| {
        let manifest_path = root.join(format!("day/{DAY}.verify.json"));
        let mut manifest = read_json(&manifest_path);
        manifest["artifacts"]["day_cbor"]["path"] = json!("../day/2025-10-07.cbor");
        write_json(&manifest_path, &manifest);
    });
    with_bundle(&corpus, "manifest-digest-mismatch", |root| {
        let manifest_path = root.join(format!("day/{DAY}.verify.json"));
        let mut manifest = read_json(&manifest_path);
        manifest["artifacts"]["day_cbor"]["sha256"] =
            json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        write_json(&manifest_path, &manifest);
    });
    with_bundle(&corpus, "manifest-malformed-verification-bundle", |root| {
        let manifest_path = root.join(format!("day/{DAY}.verify.json"));
        let mut manifest = read_json(&manifest_path);
        manifest["verification_bundle"] = json!({"disclosure_class": "A"});
        write_json(&manifest_path, &manifest);
    });
    with_bundle(&corpus, "disclosure-class-a-empty-facts", |root| {
        for entry in fs::read_dir(root.join("facts")).unwrap() {
            fs::remove_file(entry.unwrap().path()).unwrap();
        }
        refresh_commitment(root, &"00".repeat(32));
    });
    for class in ["B", "C"] {
        with_bundle(
            &corpus,
            &format!(
                "disclosure-class-{}-skips-recompute",
                class.to_ascii_lowercase()
            ),
            |root| {
                let manifest_path = root.join(format!("day/{DAY}.verify.json"));
                let mut manifest = read_json(&manifest_path);
                manifest["verification_bundle"]["disclosure_class"] = json!(class);
                write_json(&manifest_path, &manifest);
            },
        );
    }
    with_bundle(&corpus, "replay-duplicate-rejection-audit", |root| {
        add_rejection_audit(root, "duplicate", "duplicate", "replay", Some(1));
    });
    with_bundle(&corpus, "replay-out-of-window-rejection-audit", |root| {
        add_rejection_audit(root, "out-of-window", "out_of_window", "replay", Some(99));
    });
    with_bundle(&corpus, "malformed-frame-rejection-audit", |root| {
        add_rejection_audit(root, "invalid-json", "invalid_json", "parse", None);
    });
    with_bundle(&corpus, "rejection-audit-as-commitment-material", |root| {
        let path = root.join("facts/rejections.ndjson");
        fs::write(&path, "").unwrap();
        let manifest_path = root.join(format!("day/{DAY}.verify.json"));
        let mut manifest = read_json(&manifest_path);
        manifest["artifacts"]["rejection_audit"] = artifact_ref(root, &path);
        write_json(&manifest_path, &manifest);
    });
    with_bundle(&corpus, "empty-batch-day", |root| {
        let day_json_path = root.join(format!("day/{DAY}.json"));
        let mut day = read_json(&day_json_path);
        day["batches"] = json!([]);
        fs::write(&day_json_path, serde_json::to_vec_pretty(&day).unwrap()).unwrap();
        fs::write(
            root.join(format!("day/{DAY}.cbor")),
            canonical_cbor::canonicalize_json_bytes_to_cbor(&fs::read(&day_json_path).unwrap())
                .unwrap(),
        )
        .unwrap();
        write_manifest(root, 2);
    });
    with_bundle(&corpus, "multi-batch-day", |root| {
        let day_json_path = root.join(format!("day/{DAY}.json"));
        let mut day = read_json(&day_json_path);
        let batch = day["batches"][0].clone();
        day["batches"].as_array_mut().unwrap().push(batch);
        fs::write(&day_json_path, serde_json::to_vec_pretty(&day).unwrap()).unwrap();
        fs::write(
            root.join(format!("day/{DAY}.cbor")),
            canonical_cbor::canonicalize_json_bytes_to_cbor(&fs::read(&day_json_path).unwrap())
                .unwrap(),
        )
        .unwrap();
        write_manifest(root, 2);
    });
    with_bundle(&corpus, "nonzero-previous-day-root-chain-input", |root| {
        refresh_commitment(root, &"11".repeat(32));
    });
    with_bundle(
        &corpus,
        "canonical-cbor-shortest-form-fact-failure",
        |root| {
            fs::write(root.join("facts/pod-001-00000001.cbor"), [0x18, 0x01]).unwrap();
            refresh_commitment(root, &"00".repeat(32));
        },
    );
    with_bundle(&corpus, "decoded-bundle-fact-contract-failure", |root| {
        fs::write(root.join("facts/pod-001-00000001.cbor"), [0xff]).unwrap();
        refresh_commitment(root, &"00".repeat(32));
    });
}

#[test]
fn public_beta_negative_fixture_corpus_is_cli_runnable() {
    let corpus = repo_root().join("toolset/vectors/trackone-beta-negative-v1");
    if !corpus.join("cases.json").is_file() {
        eprintln!(
            "skipping: beta negative fixture corpus is not present at {}",
            corpus.display()
        );
        return;
    }
    let manifest: FixtureCorpus =
        serde_json::from_slice(&fs::read(corpus.join("cases.json")).unwrap()).unwrap();

    for case in manifest.cases {
        let work = temp_dir(&case.id);
        copy_dir(&corpus.join(&case.path), &work);
        let output = Command::new(bin())
            .args([
                "verify",
                "--root",
                work.to_str().unwrap(),
                "--facts",
                work.join("facts").to_str().unwrap(),
                "--json",
                "--policy-mode",
                &case.policy_mode,
                "--disclosure-class",
                &case.disclosure_class,
            ])
            .output()
            .unwrap();
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            output.status.success(),
            case.expect_success,
            "{} unexpected CLI status; output:\n{}",
            case.id,
            combined
        );
        assert!(
            combined.contains(&case.expect_contains),
            "{} missing expected fragment {:?}; output:\n{}",
            case.id,
            case.expect_contains,
            combined
        );
    }
}
