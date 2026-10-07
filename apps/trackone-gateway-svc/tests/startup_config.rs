//! Exercise environment parsing in child processes without changing global state.

use std::{
    fs,
    process::{Command, Output},
};

fn gateway() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_trackone-vtl-gateway"));
    command.env_clear().envs([
        ("TRACKONE_DATABASE_URL", "postgresql://localhost/trackone"),
        (
            "TRACKONE_INGEST_BEARER_TOKEN",
            "test-ingest-token-0123456789abcdef",
        ),
        ("TRACKONE_LEDGER_ID", "0123456789abcdef0123456789abcdef"),
        ("TRACKONE_SITE_ID", "test-site"),
        ("TRACKONE_TSA_URL", "https://tsa.example.test"),
        (
            "TRACKONE_TSA_CA_FILE",
            "/nonexistent/trackone-test-root.pem",
        ),
        (
            "TRACKONE_TSA_CRLS_FILE",
            "/nonexistent/trackone-test-crls.pem",
        ),
        ("TRACKONE_TSA_POLICY_OID", "1.2.3.4"),
        (
            "TRACKONE_TSA_SIGNER_CERT_SHA256",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
    ]);
    command
}

fn stderr(output: &Output) -> String {
    let error = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(!error.contains("panicked"), "{error}");
    error
}

#[test]
fn help_is_available_without_configuration_and_hides_credentials() {
    for binary in [
        env!("CARGO_BIN_EXE_trackone-vtl-gateway"),
        env!("CARGO_BIN_EXE_trackone-vtl-export"),
    ] {
        let output = Command::new(binary)
            .env_clear()
            .env(
                "TRACKONE_DATABASE_URL",
                "postgresql://user:private-password@host/db",
            )
            .env(
                "TRACKONE_INGEST_BEARER_TOKEN",
                "private-token-0123456789abcdef012345",
            )
            .arg("--help")
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains("--db-url"));
        assert!(help.contains("TRACKONE_DATABASE_URL"));
        assert!(!help.contains("private-password"));
        assert!(!help.contains("private-token"));
    }
}

#[test]
fn missing_required_configuration_is_a_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_trackone-vtl-gateway"))
        .env_clear()
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("--db-url"));
}

#[test]
fn malformed_environment_settings_are_rejected_before_io() {
    for (variable, value, flag) in [
        ("TRACKONE_BIND", "invalid", "--bind"),
        (
            "TRACKONE_POSTGRES_TLS_MODE",
            "prefer",
            "--postgres-tls-mode",
        ),
        ("TRACKONE_INTERVAL_MS", "invalid", "--interval-ms"),
        ("TRACKONE_BATCH_RECORD_LIMIT", "3", "--batch-record-limit"),
        ("TRACKONE_RECORD_LIMIT", "", "--record-limit"),
        (
            "TRACKONE_MAX_PENDING_TIMESTAMPS",
            "0",
            "--max-pending-timestamps",
        ),
        (
            "TRACKONE_MAX_RETAINED_EVIDENCE_BYTES",
            "invalid",
            "--max-retained-evidence-bytes",
        ),
        (
            "TRACKONE_TSA_WORKER_CONCURRENCY",
            "17",
            "--tsa-worker-concurrency",
        ),
        (
            "TRACKONE_TSA_MAX_FUTURE_SKEW_SECONDS",
            "3601",
            "--tsa-max-future-skew-seconds",
        ),
        (
            "TRACKONE_TSA_MAX_FUTURE_SKEW_SECONDS",
            "+1",
            "--tsa-max-future-skew-seconds",
        ),
    ] {
        let output = gateway().env(variable, value).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{variable}: {}",
            stderr(&output)
        );
        let message = stderr(&output);
        assert!(message.contains(flag), "{variable}: {message}");
        assert!(!message.contains("cannot connect"), "{message}");
    }
}

#[test]
fn command_line_values_override_environment_values() {
    let output = gateway()
        .env("TRACKONE_BIND", "invalid")
        .env("TRACKONE_MAX_PENDING_TIMESTAMPS", "invalid")
        .env("TRACKONE_MAX_RETAINED_EVIDENCE_BYTES", "0")
        .args([
            "--bind",
            "127.0.0.1:0",
            "--max-pending-timestamps",
            "2",
            "--max-retained-evidence-bytes",
            "10000",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    // Configuration parsed; the deliberately absent TSA archive is the first I/O failure.
    assert!(stderr(&output).contains("cannot initialize TSA verification policy"));
}

#[test]
fn malformed_grants_json_reports_the_file_and_parse_location() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grants.json");
    fs::write(&path, b"[broken JSON").unwrap();
    let output = gateway()
        .env("TRACKONE_DISCLOSURE_GRANTS_FILE", &path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let message = stderr(&output);
    assert!(message.contains("invalid disclosure grants file"));
    assert!(message.contains("grants.json"));
    assert!(message.contains("line 1 column"));
}

#[test]
fn invalid_retry_order_and_credentials_fail_before_database_connection() {
    let output = gateway()
        .env("TRACKONE_TSA_RETRY_INITIAL_MS", "300001")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("TRACKONE_TSA_RETRY_INITIAL_MS"));
    let output = gateway()
        .env("TRACKONE_INGEST_BEARER_TOKEN", "short-secret")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let message = stderr(&output);
    assert!(message.contains("TRACKONE_INGEST_BEARER_TOKEN"));
    assert!(!message.contains("short-secret"));
}

#[cfg(unix)]
#[test]
fn non_unicode_environment_setting_is_an_error_instead_of_a_default() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    let output = gateway()
        .env("TRACKONE_BIND", OsString::from_vec(vec![0xff]))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("invalid UTF-8"));
}

#[test]
fn exporter_rejects_duplicate_batch_selection_before_connecting() {
    let output = Command::new(env!("CARGO_BIN_EXE_trackone-vtl-export"))
        .env_clear()
        .env("TRACKONE_DATABASE_URL", "postgresql://localhost/trackone")
        .args([
            "--ledger-id",
            "0123456789abcdef0123456789abcdef",
            "--segment-number",
            "1",
            "--class",
            "B",
            "--batch",
            "0",
            "--batch",
            "0",
            "--output",
            "out",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("duplicate --batch"));
}
