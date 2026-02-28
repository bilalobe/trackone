use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use trackone_constants::OTS_VERIFY_TIMEOUT_SECS;
use trackone_ledger::hex_lower;

const PLACEHOLDER_BYTES: &[u8] = b"OTS_PROOF_PLACEHOLDER";
const STATIONARY_PREFIX: &[u8] = b"STATIONARY-OTS:";
const OTS_VERIFY_POLL_INTERVAL: Duration = Duration::from_millis(25);

fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha256_digest(bytes);
    hex_lower(&digest)
}

fn trim_ascii(input: &[u8]) -> &[u8] {
    let start = input
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(input.len());
    let end = input
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map(|idx| idx + 1)
        .unwrap_or(start);
    &input[start..end]
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn normalize_hex(value: &str) -> String {
    value.to_ascii_lowercase()
}

/// Derive the artifact path from an OTS proof path by stripping the trailing
/// `.ots` extension (for example, `2025-10-07.cbor.ots` -> `2025-10-07.cbor`).
fn artifact_path_for_ots(ots_path: &Path) -> PathBuf {
    debug_assert_eq!(
        ots_path.extension().and_then(|ext| ext.to_str()),
        Some("ots")
    );
    let mut artifact = ots_path.to_path_buf();
    artifact.set_extension("");
    artifact
}

fn parse_stationary_stub(raw: &[u8]) -> Option<String> {
    if !raw.starts_with(STATIONARY_PREFIX) {
        return None;
    }
    let line = raw[STATIONARY_PREFIX.len()..]
        .split(|byte| *byte == b'\n' || *byte == b'\r')
        .next()
        .unwrap_or_default();
    let text = core::str::from_utf8(line).ok()?.trim();
    if !is_sha256_hex(text) {
        return None;
    }
    Some(normalize_hex(text))
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    let is_absolute = path.is_absolute();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized.file_name().is_some() {
                    normalized.pop();
                } else if !is_absolute {
                    normalized.push(component.as_os_str());
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

fn resolve_from(root: &Path, rel: &Path) -> PathBuf {
    let mut combined = normalize_path(root);
    combined.push(rel);
    normalize_path(&combined)
}

fn default_verify_timeout() -> Duration {
    Duration::from_secs(OTS_VERIFY_TIMEOUT_SECS)
}

fn timeout_from_secs(timeout_secs: Option<f64>) -> Duration {
    match timeout_secs {
        Some(value) if value.is_finite() && value > 0.0 => Duration::from_secs_f64(value),
        _ => default_verify_timeout(),
    }
}

fn wait_for_exit(
    mut child: std::process::Child,
    timeout: Duration,
) -> core::result::Result<Option<std::process::ExitStatus>, std::io::Error> {
    let deadline = Instant::now() + timeout;

    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }

        let now = Instant::now();
        if now >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }

        let remaining = deadline.saturating_duration_since(now);
        thread::sleep(OTS_VERIFY_POLL_INTERVAL.min(remaining));
    }
}

fn is_executable(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::metadata(path)
            .map(|meta| meta.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }

    #[cfg(not(unix))]
    {
        true
    }
}

fn find_executable(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn required_str_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Option<&'a str> {
    object.get(key)?.as_str()
}

#[pyclass(eq, eq_int, skip_from_py_object)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OtsStatus {
    Verified,
    Pending,
    Failed,
    Missing,
    Skipped,
}

impl OtsStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Pending => "pending",
            Self::Failed => "failed",
            Self::Missing => "missing",
            Self::Skipped => "skipped",
        }
    }
}

#[pymethods]
impl OtsStatus {
    #[getter]
    fn value(&self) -> &'static str {
        self.as_str()
    }

    fn __str__(&self) -> &'static str {
        self.as_str()
    }

    fn __repr__(&self) -> String {
        format!("OtsStatus('{}')", self.as_str())
    }
}

#[pyclass(skip_from_py_object)]
#[derive(Clone, Debug)]
struct OtsVerifyResult {
    ok: bool,
    status: OtsStatus,
    reason: String,
}

impl OtsVerifyResult {
    fn new(ok: bool, status: OtsStatus, reason: impl Into<String>) -> Self {
        Self {
            ok,
            status,
            reason: reason.into(),
        }
    }

    fn success(status: OtsStatus, reason: impl Into<String>) -> Self {
        Self::new(true, status, reason)
    }

    fn failure(status: OtsStatus, reason: impl Into<String>) -> Self {
        Self::new(false, status, reason)
    }
}

#[pymethods]
impl OtsVerifyResult {
    #[getter]
    fn ok(&self) -> bool {
        self.ok
    }

    #[getter]
    fn status(&self) -> OtsStatus {
        self.status
    }

    #[getter]
    fn status_name(&self) -> &'static str {
        self.status.as_str()
    }

    #[getter]
    fn reason(&self) -> String {
        self.reason.clone()
    }

    fn __bool__(&self) -> bool {
        self.ok
    }

    fn __repr__(&self) -> String {
        format!(
            "OtsVerifyResult(ok={}, status='{}', reason='{}')",
            self.ok,
            self.status.as_str(),
            self.reason
        )
    }
}

fn verify_ots_proof_impl(
    ots_path: &Path,
    allow_placeholder: bool,
    expected_artifact_sha: Option<&str>,
    ots_binary: Option<&Path>,
    timeout: Duration,
) -> OtsVerifyResult {
    let raw = match fs::read(ots_path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return OtsVerifyResult::failure(OtsStatus::Missing, "ots-proof-not-found");
        }
        Err(_) => {
            return OtsVerifyResult::failure(OtsStatus::Failed, "ots-proof-read-failed");
        }
    };

    if let Some(stub_hex) = parse_stationary_stub(&raw) {
        if !allow_placeholder {
            return OtsVerifyResult::failure(OtsStatus::Failed, "placeholder-not-allowed");
        }

        let expected = if let Some(expected) = expected_artifact_sha {
            if !is_sha256_hex(expected) {
                return OtsVerifyResult::failure(
                    OtsStatus::Failed,
                    "stationary-stub-hash-mismatch",
                );
            }
            normalize_hex(expected)
        } else {
            let artifact_path = artifact_path_for_ots(ots_path);
            let artifact_bytes = match fs::read(&artifact_path) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return OtsVerifyResult::failure(
                        OtsStatus::Failed,
                        "stationary-stub-artifact-missing",
                    );
                }
            };
            sha256_hex(&artifact_bytes)
        };

        if stub_hex == expected {
            return OtsVerifyResult::success(OtsStatus::Verified, "stationary-stub-verified");
        }
        return OtsVerifyResult::failure(OtsStatus::Failed, "stationary-stub-hash-mismatch");
    }

    if trim_ascii(&raw) == PLACEHOLDER_BYTES {
        return if allow_placeholder {
            OtsVerifyResult::success(OtsStatus::Pending, "placeholder-accepted")
        } else {
            OtsVerifyResult::failure(OtsStatus::Failed, "placeholder-not-allowed")
        };
    }

    let binary = match ots_binary
        .map(PathBuf::from)
        .or_else(|| find_executable("ots"))
    {
        Some(path) => path,
        None => return OtsVerifyResult::failure(OtsStatus::Failed, "ots-binary-not-found"),
    };

    if !is_executable(&binary) {
        return OtsVerifyResult::failure(OtsStatus::Failed, "ots-binary-not-executable");
    }

    let child = match Command::new(&binary)
        .arg("verify")
        .arg(ots_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return OtsVerifyResult::failure(OtsStatus::Failed, "ots-exec-failed"),
    };

    match wait_for_exit(child, timeout) {
        Ok(Some(status)) if status.success() => {
            OtsVerifyResult::success(OtsStatus::Verified, "ots-verified")
        }
        Ok(Some(_)) => OtsVerifyResult::failure(OtsStatus::Failed, "ots-verification-failed"),
        Ok(None) => OtsVerifyResult::failure(OtsStatus::Failed, "ots-timeout"),
        Err(_) => OtsVerifyResult::failure(OtsStatus::Failed, "ots-exec-failed"),
    }
}

fn validate_meta_sidecar_impl(
    meta_path: &Path,
    repo_root: &Path,
    expected_artifact_path: &Path,
    expected_ots_path: &Path,
) -> OtsVerifyResult {
    let text = match fs::read_to_string(meta_path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return OtsVerifyResult::failure(OtsStatus::Missing, "meta-not-found");
        }
        Err(_) => {
            return OtsVerifyResult::failure(OtsStatus::Failed, "meta-read-failed");
        }
    };

    let value: Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(_) => return OtsVerifyResult::failure(OtsStatus::Failed, "meta-parse-failed"),
    };
    let object = match value.as_object() {
        Some(object) => object,
        None => return OtsVerifyResult::failure(OtsStatus::Failed, "meta-missing-fields"),
    };

    let artifact_rel = match required_str_field(object, "artifact") {
        Some(value) => value,
        None => return OtsVerifyResult::failure(OtsStatus::Failed, "meta-missing-fields"),
    };
    let day = match required_str_field(object, "day") {
        Some(value) if !value.is_empty() => value,
        _ => return OtsVerifyResult::failure(OtsStatus::Failed, "meta-missing-fields"),
    };
    let artifact_sha = match required_str_field(object, "artifact_sha256") {
        Some(value) if is_sha256_hex(value) => normalize_hex(value),
        _ => return OtsVerifyResult::failure(OtsStatus::Failed, "meta-missing-fields"),
    };
    let ots_rel = match required_str_field(object, "ots_proof") {
        Some(value) => value,
        None => return OtsVerifyResult::failure(OtsStatus::Failed, "meta-missing-fields"),
    };

    if resolve_from(repo_root, Path::new(artifact_rel)) != normalize_path(expected_artifact_path) {
        return OtsVerifyResult::failure(OtsStatus::Failed, "meta-artifact-path-mismatch");
    }

    let expected_day = expected_artifact_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    if day != expected_day {
        return OtsVerifyResult::failure(OtsStatus::Failed, "meta-day-mismatch");
    }

    let artifact_bytes = match fs::read(expected_artifact_path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return OtsVerifyResult::failure(OtsStatus::Missing, "meta-artifact-missing");
        }
        Err(_) => return OtsVerifyResult::failure(OtsStatus::Failed, "meta-read-failed"),
    };

    if sha256_hex(&artifact_bytes) != artifact_sha {
        return OtsVerifyResult::failure(OtsStatus::Failed, "meta-artifact-hash-mismatch");
    }

    if resolve_from(repo_root, Path::new(ots_rel)) != normalize_path(expected_ots_path) {
        return OtsVerifyResult::failure(OtsStatus::Failed, "meta-ots-path-mismatch");
    }

    if !expected_ots_path.exists() {
        return OtsVerifyResult::failure(OtsStatus::Missing, "ots-proof-not-found");
    }

    OtsVerifyResult::success(OtsStatus::Verified, "meta-valid")
}

#[pyfunction]
fn hash_for_ots<'py>(py: Python<'py>, artifact: &Bound<'py, PyBytes>) -> Bound<'py, PyBytes> {
    let digest = sha256_digest(artifact.as_bytes());
    PyBytes::new(py, &digest)
}

#[pyfunction(signature = (ots_path, allow_placeholder = true, expected_artifact_sha = None, ots_binary = None, timeout_secs = None))]
fn verify_ots_proof(
    ots_path: String,
    allow_placeholder: bool,
    expected_artifact_sha: Option<String>,
    ots_binary: Option<String>,
    timeout_secs: Option<f64>,
) -> OtsVerifyResult {
    verify_ots_proof_impl(
        Path::new(&ots_path),
        allow_placeholder,
        expected_artifact_sha.as_deref(),
        ots_binary.as_deref().map(Path::new),
        timeout_from_secs(timeout_secs),
    )
}

#[pyfunction]
fn validate_meta_sidecar(
    meta_path: String,
    repo_root: String,
    expected_artifact_path: String,
    expected_ots_path: String,
) -> OtsVerifyResult {
    validate_meta_sidecar_impl(
        Path::new(&meta_path),
        Path::new(&repo_root),
        Path::new(&expected_artifact_path),
        Path::new(&expected_ots_path),
    )
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(parent.py(), "ots")?;
    sub.add_class::<OtsStatus>()?;
    sub.add_class::<OtsVerifyResult>()?;
    sub.add_function(wrap_pyfunction!(hash_for_ots, &sub)?)?;
    sub.add_function(wrap_pyfunction!(verify_ots_proof, &sub)?)?;
    sub.add_function(wrap_pyfunction!(validate_meta_sidecar, &sub)?)?;
    parent.add_submodule(&sub)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "trackone-gateway-ots-{label}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[cfg(unix)]
    fn write_fake_ots_binary(dir: &Path, exit_code: i32) -> PathBuf {
        let path = dir.join("ots");
        fs::write(&path, format!("#!/bin/sh\nexit {exit_code}\n")).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    fn write_meta(path: &Path, day: &str, artifact: &str, artifact_sha256: &str, ots_proof: &str) {
        let meta = serde_json::json!({
            "day": day,
            "artifact": artifact,
            "artifact_sha256": artifact_sha256,
            "ots_proof": ots_proof,
        });
        fs::write(path, serde_json::to_vec(&meta).unwrap()).unwrap();
    }

    #[test]
    fn verify_ots_proof_accepts_placeholder() {
        let tmp = TestDir::new("placeholder");
        let ots_path = tmp.path().join("2025-10-07.cbor.ots");
        fs::write(&ots_path, b"OTS_PROOF_PLACEHOLDER\n").unwrap();

        let result = verify_ots_proof_impl(&ots_path, true, None, None, default_verify_timeout());

        assert!(result.ok);
        assert_eq!(result.status, OtsStatus::Pending);
        assert_eq!(result.reason, "placeholder-accepted");
    }

    #[test]
    fn verify_ots_proof_accepts_stationary_stub_when_hash_matches() {
        let tmp = TestDir::new("stationary");
        let artifact_path = tmp.path().join("2025-10-07.cbor");
        let ots_path = artifact_path.with_extension("cbor.ots");
        fs::write(&artifact_path, b"day-bytes").unwrap();
        let artifact_sha = sha256_hex(b"day-bytes");
        fs::write(&ots_path, format!("STATIONARY-OTS:{artifact_sha}\n")).unwrap();

        let result = verify_ots_proof_impl(
            &ots_path,
            true,
            Some(&artifact_sha),
            None,
            default_verify_timeout(),
        );

        assert!(result.ok);
        assert_eq!(result.status, OtsStatus::Verified);
        assert_eq!(result.reason, "stationary-stub-verified");
    }

    #[test]
    fn verify_ots_proof_rejects_stationary_stub_when_hash_mismatches() {
        let tmp = TestDir::new("stationary-mismatch");
        let artifact_path = tmp.path().join("2025-10-07.cbor");
        let ots_path = artifact_path.with_extension("cbor.ots");
        fs::write(&artifact_path, b"day-bytes").unwrap();
        fs::write(
            &ots_path,
            "STATIONARY-OTS:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();

        let result = verify_ots_proof_impl(
            &ots_path,
            true,
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            None,
            default_verify_timeout(),
        );

        assert!(!result.ok);
        assert_eq!(result.status, OtsStatus::Failed);
        assert_eq!(result.reason, "stationary-stub-hash-mismatch");
    }

    #[cfg(unix)]
    #[test]
    fn verify_ots_proof_accepts_real_proof_when_ots_binary_succeeds() {
        let tmp = TestDir::new("real-proof");
        let ots_path = tmp.path().join("2025-10-07.cbor.ots");
        let ots_binary = write_fake_ots_binary(tmp.path(), 0);
        fs::write(&ots_path, b"REAL_PROOF_BYTES\n").unwrap();

        let result = verify_ots_proof_impl(
            &ots_path,
            false,
            None,
            Some(&ots_binary),
            default_verify_timeout(),
        );

        assert!(result.ok);
        assert_eq!(result.status, OtsStatus::Verified);
        assert_eq!(result.reason, "ots-verified");
    }

    #[cfg(unix)]
    #[test]
    fn verify_ots_proof_times_out_when_binary_hangs() {
        let tmp = TestDir::new("real-proof-timeout");
        let ots_path = tmp.path().join("2025-10-07.cbor.ots");
        let ots_binary = tmp.path().join("ots");
        fs::write(&ots_binary, "#!/bin/sh\nsleep 1\n").unwrap();
        let mut permissions = fs::metadata(&ots_binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&ots_binary, permissions).unwrap();
        fs::write(&ots_path, b"REAL_PROOF_BYTES\n").unwrap();

        let result = verify_ots_proof_impl(
            &ots_path,
            false,
            None,
            Some(&ots_binary),
            Duration::from_millis(50),
        );

        assert!(!result.ok);
        assert_eq!(result.status, OtsStatus::Failed);
        assert_eq!(result.reason, "ots-timeout");
    }

    #[test]
    fn validate_meta_sidecar_accepts_valid_sidecar() {
        let tmp = TestDir::new("meta-valid");
        let repo_root = tmp.path();
        let artifact_path = repo_root.join("out/site_demo/day/2025-10-07.cbor");
        let ots_path = artifact_path.with_extension("cbor.ots");
        let meta_path = repo_root.join("proofs/2025-10-07.ots.meta.json");

        fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
        fs::create_dir_all(meta_path.parent().unwrap()).unwrap();
        fs::write(&artifact_path, b"day-bytes").unwrap();
        fs::write(&ots_path, b"OTS_PROOF_PLACEHOLDER\n").unwrap();

        let artifact_rel = artifact_path
            .strip_prefix(repo_root)
            .unwrap()
            .to_string_lossy();
        let ots_rel = ots_path.strip_prefix(repo_root).unwrap().to_string_lossy();
        write_meta(
            &meta_path,
            "2025-10-07",
            &artifact_rel,
            &sha256_hex(b"day-bytes"),
            &ots_rel,
        );

        let result = validate_meta_sidecar_impl(&meta_path, repo_root, &artifact_path, &ots_path);

        assert!(result.ok);
        assert_eq!(result.status, OtsStatus::Verified);
        assert_eq!(result.reason, "meta-valid");
    }

    #[test]
    fn validate_meta_sidecar_rejects_missing_required_fields() {
        let tmp = TestDir::new("meta-missing");
        let repo_root = tmp.path();
        let artifact_path = repo_root.join("out/site_demo/day/2025-10-07.cbor");
        let ots_path = artifact_path.with_extension("cbor.ots");
        let meta_path = repo_root.join("proofs/2025-10-07.ots.meta.json");

        fs::create_dir_all(meta_path.parent().unwrap()).unwrap();
        fs::write(
            &meta_path,
            br#"{"artifact":"out/site_demo/day/2025-10-07.cbor","artifact_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        )
        .unwrap();

        let result = validate_meta_sidecar_impl(&meta_path, repo_root, &artifact_path, &ots_path);

        assert!(!result.ok);
        assert_eq!(result.status, OtsStatus::Failed);
        assert_eq!(result.reason, "meta-missing-fields");
    }

    #[test]
    fn validate_meta_sidecar_rejects_hash_mismatch() {
        let tmp = TestDir::new("meta-mismatch");
        let repo_root = tmp.path();
        let artifact_path = repo_root.join("out/site_demo/day/2025-10-07.cbor");
        let ots_path = artifact_path.with_extension("cbor.ots");
        let meta_path = repo_root.join("proofs/2025-10-07.ots.meta.json");

        fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
        fs::create_dir_all(meta_path.parent().unwrap()).unwrap();
        fs::write(&artifact_path, b"day-bytes").unwrap();
        fs::write(&ots_path, b"OTS_PROOF_PLACEHOLDER\n").unwrap();

        let artifact_rel = artifact_path
            .strip_prefix(repo_root)
            .unwrap()
            .to_string_lossy();
        let ots_rel = ots_path.strip_prefix(repo_root).unwrap().to_string_lossy();
        write_meta(
            &meta_path,
            "2025-10-07",
            &artifact_rel,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &ots_rel,
        );

        let result = validate_meta_sidecar_impl(&meta_path, repo_root, &artifact_path, &ots_path);

        assert!(!result.ok);
        assert_eq!(result.status, OtsStatus::Failed);
        assert_eq!(result.reason, "meta-artifact-hash-mismatch");
    }

    #[test]
    fn validate_meta_sidecar_rejects_day_mismatch() {
        let tmp = TestDir::new("meta-day-mismatch");
        let repo_root = tmp.path();
        let artifact_path = repo_root.join("out/site_demo/day/2025-10-07.cbor");
        let ots_path = artifact_path.with_extension("cbor.ots");
        let meta_path = repo_root.join("proofs/2025-10-07.ots.meta.json");

        fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
        fs::create_dir_all(meta_path.parent().unwrap()).unwrap();
        fs::write(&artifact_path, b"day-bytes").unwrap();
        fs::write(&ots_path, b"OTS_PROOF_PLACEHOLDER\n").unwrap();

        let artifact_rel = artifact_path
            .strip_prefix(repo_root)
            .unwrap()
            .to_string_lossy();
        let ots_rel = ots_path.strip_prefix(repo_root).unwrap().to_string_lossy();
        write_meta(
            &meta_path,
            "2025-10-08",
            &artifact_rel,
            &sha256_hex(b"day-bytes"),
            &ots_rel,
        );

        let result = validate_meta_sidecar_impl(&meta_path, repo_root, &artifact_path, &ots_path);

        assert!(!result.ok);
        assert_eq!(result.status, OtsStatus::Failed);
        assert_eq!(result.reason, "meta-day-mismatch");
    }
}
