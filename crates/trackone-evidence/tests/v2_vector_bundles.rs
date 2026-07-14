use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Deserialize)]
struct Cases {
    schema: String,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    path: String,
    expect_success: bool,
    #[serde(default)]
    expected_result: Option<String>,
    #[serde(default)]
    expected_error: Option<String>,
    #[serde(default)]
    tsa_ca_file: Option<String>,
    #[serde(default)]
    tsa_policy_oid: Option<String>,
}

fn vector_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../toolset/vectors/verifiable-telemetry-canonical-cbor-v2")
}

#[test]
fn v2_vector_bundles_are_cli_runnable() {
    let root = vector_root();
    if !root.join("cases.json").is_file() {
        eprintln!(
            "skipping: v2 vector bundle corpus is not present at {}",
            root.display()
        );
        return;
    }
    let cases: Cases = serde_json::from_slice(&fs::read(root.join("cases.json")).unwrap()).unwrap();
    assert_eq!(cases.schema, "trackone-v2-bundle-cases-1");
    assert_eq!(cases.cases.len(), 3);

    for case in cases.cases {
        let bundle = root.join(&case.path);
        let mut command = Command::new(env!("CARGO_BIN_EXE_trackone-evidence"));
        command.args(["verify-v2", "--root"]).arg(&bundle).arg("--json");
        if let Some(ca_file) = &case.tsa_ca_file {
            command.arg("--tsa-ca-file").arg(root.join(ca_file));
        }
        if let Some(policy_oid) = &case.tsa_policy_oid {
            command.arg("--tsa-policy").arg(policy_oid);
        }
        let output = command.output().unwrap();

        if case.expect_success {
            assert!(
                output.status.success(),
                "{} failed: {}",
                case.id,
                String::from_utf8_lossy(&output.stderr)
            );
            let actual: Value = serde_json::from_slice(&output.stdout).unwrap();
            let expected_path = case
                .expected_result
                .as_deref()
                .expect("successful case needs expected_result");
            let expected: Value =
                serde_json::from_slice(&fs::read(bundle.join(expected_path)).unwrap()).unwrap();
            assert_eq!(actual, expected, "{} result drifted", case.id);
        } else {
            assert!(!output.status.success(), "{} unexpectedly passed", case.id);
            let expected_path = case
                .expected_error
                .as_deref()
                .expect("failing case needs expected_error");
            let expected: Value =
                serde_json::from_slice(&fs::read(bundle.join(expected_path)).unwrap()).unwrap();
            let expected_message = expected["error_contains"].as_str().unwrap();
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(expected_message),
                "{} did not report {expected_message:?}: {}",
                case.id,
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
