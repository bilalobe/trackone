//! Public command behavior and compatibility with the reusable verifier.

use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use trackone_evidence::vtl::{VerifyPolicy, verify_archive, verify_bundle_with_policy};
use trackone_ledger::sha256_hex;

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_trackone-evidence"))
}

fn stderr(output: &Output) -> String {
    let message = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(!message.contains("panicked"), "{message}");
    message
}

fn fixture_paths() -> (PathBuf, PathBuf) {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    (
        workspace.join("toolset/vectors/vtl-http-binding/class-c"),
        workspace.join("toolset/vectors/vtl-interoperability/tsa"),
    )
}

fn bundle_fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let (source, tsa) = fixture_paths();
    for name in ["segment.cbor", "timestamp.tsr"] {
        fs::copy(source.join(name), directory.path().join(name)).unwrap();
    }
    // The HTTP snapshot fixture omits the nonce-bearing token's request.
    // Complete it with the matching archived request for verifier replay.
    let encoded = fs::read_to_string(tsa.join("appendix-a-nonce.tsq.b64")).unwrap();
    let request = STANDARD
        .decode(encoded.split_whitespace().collect::<String>())
        .unwrap();
    fs::write(directory.path().join("timestamp.tsq"), &request).unwrap();
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(source.join("segment.verify.json")).unwrap()).unwrap();
    manifest["artifacts"]["tsa_req"] =
        json!({"path": "timestamp.tsq", "sha256": sha256_hex(&request)});
    fs::write(
        directory.path().join("segment.verify.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    directory
}

const TSA_POLICY: &str = "1.3.6.1.4.1.55555.12";
const TSA_SIGNER: &str = "d9605fad90502738f205d5742e93ba9985e6b4e69f09d7f6aa470a4783f894c5";

fn with_tsa_policy(command: &mut Command) -> &mut Command {
    let (_, tsa) = fixture_paths();
    command
        .arg("--tsa-ca-file")
        .arg(tsa.join("test-root.pem"))
        .arg("--tsa-crls-file")
        .arg(tsa.join("test-root.crl.pem"))
        .args([
            "--tsa-policy",
            TSA_POLICY,
            "--tsa-signer-cert-sha256",
            TSA_SIGNER,
        ]);
    command
}

fn fixture_policy() -> VerifyPolicy {
    let (_, tsa) = fixture_paths();
    VerifyPolicy {
        tsa_ca_file: Some(tsa.join("test-root.pem")),
        tsa_crls_file: Some(tsa.join("test-root.crl.pem")),
        tsa_policy_oid: Some(TSA_POLICY.into()),
        tsa_signer_cert_sha256: Some(TSA_SIGNER.parse().unwrap()),
        ..VerifyPolicy::baseline()
    }
}

#[test]
fn help_and_version_work_for_the_binary_and_both_subcommands() {
    for args in [
        vec!["--help"],
        vec!["verify", "--help"],
        vec!["compact", "--help"],
    ] {
        let output = command().args(&args).output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        let help = String::from_utf8(output.stdout).unwrap();
        if args.len() == 1 {
            assert!(help.contains("verify"));
            assert!(help.contains("compact"));
        } else {
            assert!(help.contains("--tsa-signer-cert-sha256"));
            assert!(help.contains("disclosed_batch_recompute"));
        }
    }
    for args in [
        vec!["--version"],
        vec!["verify", "--version"],
        vec!["compact", "--version"],
    ] {
        let output = command().args(args).output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains(env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn malformed_commands_exit_with_usage_errors_before_io() {
    let digest = "0".repeat(64);
    for args in [
        vec![],
        vec!["verify"],
        vec!["unknown-command"],
        vec![
            "verify",
            "--root",
            "/nonexistent",
            "--archive",
            "/nonexistent/archive",
        ],
        vec!["verify", "--root"],
        vec!["verify", "--bundle-url", "https://example.test/bundle/"],
        vec![
            "verify",
            "--bundle-url",
            "https://example.test/bundle/",
            "--expected-segment-sha256",
            &digest,
        ],
        vec![
            "verify",
            "--root",
            "/nonexistent",
            "--https-ca-file",
            "/nonexistent/ca.pem",
        ],
        vec!["compact", "--root", "/nonexistent"],
        vec!["compact", "--output", "/nonexistent/archive"],
        vec![
            "compact",
            "--root",
            "/nonexistent",
            "--output",
            "unused",
            "--batch",
            "-1",
        ],
    ] {
        let output = command().args(&args).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(output.stdout.is_empty(), "{args:?}");
        let error = stderr(&output);
        assert!(error.contains("--help"), "{error}");
        assert!(
            !error.contains("ERROR:"),
            "operation ran for {args:?}: {error}"
        );
    }
}

#[test]
fn operational_errors_keep_the_existing_exit_status_and_diagnostic_prefix() {
    let output = command()
        .args([
            "verify",
            "--root",
            "/nonexistent/trackone-cli-test",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(stderr(&output).starts_with("ERROR:"));
}

#[test]
fn successful_directory_verification_matches_the_library_and_output_modes() {
    let fixture = bundle_fixture();
    let root = fixture.path();
    let expected = verify_bundle_with_policy(root, &fixture_policy()).unwrap();
    assert_eq!(expected["overall"], "success", "{expected:#}");
    for flags in [vec!["--json"], vec!["--json", "--pretty"]] {
        let mut cli = command();
        cli.args(["verify", "--root"]).arg(root).args(&flags);
        let output = with_tsa_policy(&mut cli).output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(output.stderr.is_empty());
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            expected
        );
        assert!(output.stdout.ends_with(b"\n"));
        assert_eq!(
            output.stdout.windows(3).any(|bytes| bytes == b"\n  "),
            flags.contains(&"--pretty")
        );
    }
    let mut cli = command();
    cli.args(["verify", "--root"]).arg(root).arg("--pretty");
    let output = with_tsa_policy(&mut cli).output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(output.stdout, b"Disclosure=\"C\" Overall=\"success\"\n");
}

#[test]
fn compacted_archive_is_deterministic_and_preserves_verification_conclusions() {
    let directory = tempfile::tempdir().unwrap();
    let output_path = directory.path().join("bundle.tar.gz");
    let second_path = directory.path().join("repeat.tar.gz");
    let fixture = bundle_fixture();
    let root = fixture.path();
    for path in [&output_path, &second_path] {
        let mut cli = command();
        cli.args(["compact", "--root"])
            .arg(root)
            .arg("--output")
            .arg(path);
        let output = with_tsa_policy(&mut cli).output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(output.stdout.is_empty());
    }
    assert_eq!(
        std::fs::read(&output_path).unwrap(),
        std::fs::read(&second_path).unwrap()
    );
    let mut from_directory = command();
    from_directory
        .args(["verify", "--root"])
        .arg(root)
        .arg("--json");
    let expected = with_tsa_policy(&mut from_directory).output().unwrap();
    assert!(expected.status.success(), "{}", stderr(&expected));
    let mut from_archive = command();
    from_archive
        .args(["verify", "--archive"])
        .arg(&output_path)
        .arg("--json");
    let output = with_tsa_policy(&mut from_archive).output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let mut replayed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        replayed,
        verify_archive(&output_path, &fixture_policy()).unwrap()
    );
    let mut original: Value = serde_json::from_slice(&expected.stdout).unwrap();
    // Compaction serializes the manifest deterministically, so its byte digest
    // can change while the artifact, policy identity, and conclusions remain equal.
    original.as_object_mut().unwrap().remove("manifest_sha256");
    replayed.as_object_mut().unwrap().remove("manifest_sha256");
    assert_eq!(replayed, original);
}
