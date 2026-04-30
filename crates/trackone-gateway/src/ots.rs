#[cfg(feature = "python")]
use pyo3::exceptions::PyValueError;
#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use pyo3::types::PyBytes;
use serde_json::Value;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use trackone_constants::OTS_VERIFY_TIMEOUT_SECS;
use trackone_ledger::{hex_lower, sha256_digest, sha256_hex};

const PLACEHOLDER_BYTES: &[u8] = b"OTS_PROOF_PLACEHOLDER";
const STATIONARY_PREFIX: &[u8] = b"STATIONARY-OTS:";
const OTS_VERIFY_POLL_INTERVAL: Duration = Duration::from_millis(25);
const OTS_HEADER_MAGIC: &[u8] =
    b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
const OTS_MAJOR_VERSION: u64 = 1;
const OTS_OP_SHA256: u8 = 0x08;
const OTS_OP_APPEND: u8 = 0xf0;
const OTS_OP_PREPEND: u8 = 0xf1;
const OTS_TIMESTAMP_MORE: u8 = 0xff;
const OTS_TIMESTAMP_ATTESTATION: u8 = 0x00;
const OTS_PENDING_ATTESTATION_TAG: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const OTS_BITCOIN_BLOCK_HEADER_ATTESTATION_TAG: [u8; 8] =
    [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const OTS_MAX_OP_RESULT_LEN: usize = 4096;
const OTS_MAX_ATTESTATION_PAYLOAD_LEN: usize = 8192;
const OTS_MAX_URI_LEN: usize = 1000;
const OTS_MAX_RECURSION_DEPTH: u16 = 256;

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

fn hex_to_digest32(value: &str) -> Option<[u8; 32]> {
    if !is_sha256_hex(value) {
        return None;
    }

    let mut out = [0u8; 32];
    for (idx, byte) in out.iter_mut().enumerate() {
        let hi = value.as_bytes()[idx * 2];
        let lo = value.as_bytes()[idx * 2 + 1];
        *byte = (hex_nibble(hi)? << 4) | hex_nibble(lo)?;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Derive the artifact path from an OTS proof path by stripping the trailing
/// `.ots` extension (for example, `2025-10-07.cbor.ots` -> `2025-10-07.cbor`).
/// Returns `None` if the path does not have an `.ots` extension.
fn artifact_path_for_ots(ots_path: &Path) -> Option<PathBuf> {
    if ots_path.extension().and_then(|ext| ext.to_str()) != Some("ots") {
        return None;
    }
    let mut artifact = ots_path.to_path_buf();
    artifact.set_extension("");
    Some(artifact)
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
        Some(value) if value.is_finite() && value > 0.0 => {
            let max_secs = Duration::MAX.as_secs_f64();
            if value <= max_secs {
                Duration::from_secs_f64(value)
            } else {
                default_verify_timeout()
            }
        }
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct OtsProofSummary {
    file_digest: [u8; 32],
    pending_uris: Vec<String>,
    bitcoin_heights: Vec<u64>,
    steps: Vec<String>,
}

impl OtsProofSummary {
    fn new(file_digest: [u8; 32]) -> Self {
        Self {
            file_digest,
            pending_uris: Vec::new(),
            bitcoin_heights: Vec::new(),
            steps: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OtsInternalError {
    Fallback,
    Invalid(&'static str),
}

struct OtsCursor<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> OtsCursor<'a> {
    fn new(raw: &'a [u8]) -> Self {
        Self { raw, offset: 0 }
    }

    fn assert_magic(&mut self, magic: &[u8]) -> Result<(), OtsInternalError> {
        let actual = self.read_bytes(magic.len())?;
        if actual == magic {
            Ok(())
        } else {
            Err(OtsInternalError::Fallback)
        }
    }

    fn read_u8(&mut self) -> Result<u8, OtsInternalError> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], OtsInternalError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(OtsInternalError::Invalid("ots-proof-parse-failed"))?;
        if end > self.raw.len() {
            return Err(OtsInternalError::Invalid("ots-proof-parse-failed"));
        }
        let bytes = &self.raw[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn read_varuint(&mut self) -> Result<u64, OtsInternalError> {
        let mut value: u64 = 0;
        let mut shift = 0u32;

        loop {
            if shift >= 64 {
                return Err(OtsInternalError::Invalid("ots-proof-parse-failed"));
            }
            let byte = self.read_u8()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    fn read_varbytes(
        &mut self,
        max_len: usize,
        min_len: usize,
    ) -> Result<&'a [u8], OtsInternalError> {
        let len_u64 = self.read_varuint()?;
        let len = usize::try_from(len_u64)
            .map_err(|_| OtsInternalError::Invalid("ots-proof-parse-failed"))?;
        if len < min_len || len > max_len {
            return Err(OtsInternalError::Invalid("ots-proof-parse-failed"));
        }
        self.read_bytes(len)
    }

    fn assert_eof(&self) -> Result<(), OtsInternalError> {
        if self.offset == self.raw.len() {
            Ok(())
        } else {
            Err(OtsInternalError::Invalid("ots-proof-trailing-garbage"))
        }
    }
}

fn expected_digest_for_ots(
    ots_path: &Path,
    expected_artifact_sha: Option<&str>,
) -> Result<Option<[u8; 32]>, OtsInternalError> {
    if let Some(expected) = expected_artifact_sha {
        return hex_to_digest32(expected)
            .map(Some)
            .ok_or(OtsInternalError::Invalid("ots-expected-hash-invalid"));
    }

    let Some(artifact_path) = artifact_path_for_ots(ots_path) else {
        return Ok(None);
    };
    match fs::read(&artifact_path) {
        Ok(bytes) => Ok(Some(sha256_digest(&bytes))),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(OtsInternalError::Invalid("ots-artifact-read-failed")),
    }
}

fn parse_detached_ots(
    raw: &[u8],
    ots_path: &Path,
    expected_artifact_sha: Option<&str>,
) -> Result<OtsProofSummary, OtsInternalError> {
    if !raw.starts_with(OTS_HEADER_MAGIC) {
        return Err(OtsInternalError::Fallback);
    }

    let mut cursor = OtsCursor::new(raw);
    cursor.assert_magic(OTS_HEADER_MAGIC)?;

    let major = cursor.read_varuint()?;
    if major != OTS_MAJOR_VERSION {
        return Err(OtsInternalError::Invalid("ots-unsupported-version"));
    }

    let file_hash_op = cursor.read_u8()?;
    if file_hash_op != OTS_OP_SHA256 {
        return Err(OtsInternalError::Fallback);
    }

    let file_digest = cursor.read_bytes(32)?;
    let file_digest: [u8; 32] = file_digest
        .try_into()
        .map_err(|_| OtsInternalError::Invalid("ots-proof-parse-failed"))?;
    if let Some(expected_digest) = expected_digest_for_ots(ots_path, expected_artifact_sha)?
        && file_digest != expected_digest
    {
        return Err(OtsInternalError::Invalid(
            "ots-proof-artifact-hash-mismatch",
        ));
    }

    let mut summary = OtsProofSummary::new(file_digest);
    parse_timestamp(
        &mut cursor,
        file_digest.to_vec(),
        OTS_MAX_RECURSION_DEPTH,
        &mut summary,
    )?;
    cursor.assert_eof()?;
    Ok(summary)
}

fn parse_timestamp(
    cursor: &mut OtsCursor<'_>,
    msg: Vec<u8>,
    recursion_remaining: u16,
    summary: &mut OtsProofSummary,
) -> Result<(), OtsInternalError> {
    if recursion_remaining == 0 {
        return Err(OtsInternalError::Invalid("ots-proof-recursion-limit"));
    }

    let mut tag = cursor.read_u8()?;
    while tag == OTS_TIMESTAMP_MORE {
        let next = cursor.read_u8()?;
        parse_timestamp_tag(cursor, next, &msg, recursion_remaining, summary)?;
        tag = cursor.read_u8()?;
    }

    parse_timestamp_tag(cursor, tag, &msg, recursion_remaining, summary)
}

fn parse_timestamp_tag(
    cursor: &mut OtsCursor<'_>,
    tag: u8,
    msg: &[u8],
    recursion_remaining: u16,
    summary: &mut OtsProofSummary,
) -> Result<(), OtsInternalError> {
    if tag == OTS_TIMESTAMP_ATTESTATION {
        return parse_attestation(cursor, msg, summary);
    }

    let (step, result) = apply_ots_op(cursor, tag, msg)?;
    summary.steps.push(step);
    parse_timestamp(cursor, result, recursion_remaining - 1, summary)
}

fn apply_ots_op(
    cursor: &mut OtsCursor<'_>,
    tag: u8,
    msg: &[u8],
) -> Result<(String, Vec<u8>), OtsInternalError> {
    if msg.len() > OTS_MAX_OP_RESULT_LEN {
        return Err(OtsInternalError::Invalid("ots-proof-message-too-long"));
    }

    match tag {
        OTS_OP_APPEND => {
            let suffix = cursor.read_varbytes(OTS_MAX_OP_RESULT_LEN, 1)?;
            let mut result = Vec::with_capacity(msg.len() + suffix.len());
            result.extend_from_slice(msg);
            result.extend_from_slice(suffix);
            if result.len() > OTS_MAX_OP_RESULT_LEN {
                return Err(OtsInternalError::Invalid("ots-proof-message-too-long"));
            }
            Ok((format!("append {}", hex_lower(suffix)), result))
        }
        OTS_OP_PREPEND => {
            let prefix = cursor.read_varbytes(OTS_MAX_OP_RESULT_LEN, 1)?;
            let mut result = Vec::with_capacity(prefix.len() + msg.len());
            result.extend_from_slice(prefix);
            result.extend_from_slice(msg);
            if result.len() > OTS_MAX_OP_RESULT_LEN {
                return Err(OtsInternalError::Invalid("ots-proof-message-too-long"));
            }
            Ok((format!("prepend {}", hex_lower(prefix)), result))
        }
        OTS_OP_SHA256 => Ok(("sha256".to_string(), sha256_digest(msg).to_vec())),
        _ => Err(OtsInternalError::Fallback),
    }
}

fn parse_attestation(
    cursor: &mut OtsCursor<'_>,
    msg: &[u8],
    summary: &mut OtsProofSummary,
) -> Result<(), OtsInternalError> {
    let tag = cursor.read_bytes(8)?;
    let payload = cursor.read_varbytes(OTS_MAX_ATTESTATION_PAYLOAD_LEN, 0)?;

    if tag == OTS_PENDING_ATTESTATION_TAG {
        let uri = parse_pending_attestation_uri(payload)?;
        summary
            .steps
            .push(format!("verify PendingAttestation({uri})"));
        summary.pending_uris.push(uri);
        return Ok(());
    }

    if tag == OTS_BITCOIN_BLOCK_HEADER_ATTESTATION_TAG {
        if msg.len() != 32 {
            return Err(OtsInternalError::Invalid("ots-bitcoin-digest-invalid"));
        }
        let height = parse_bitcoin_block_header_attestation_height(payload)?;
        summary
            .steps
            .push(format!("verify BitcoinBlockHeaderAttestation({height})"));
        summary.bitcoin_heights.push(height);
        return Ok(());
    }

    Err(OtsInternalError::Fallback)
}

fn parse_pending_attestation_uri(payload: &[u8]) -> Result<String, OtsInternalError> {
    let mut payload_cursor = OtsCursor::new(payload);
    let uri = payload_cursor.read_varbytes(OTS_MAX_URI_LEN, 0)?;
    payload_cursor.assert_eof()?;
    if !uri.iter().all(|byte| {
        matches!(
            byte,
            b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b'-'
                | b'.'
                | b'_'
                | b'/'
                | b':'
        )
    }) {
        return Err(OtsInternalError::Invalid("ots-pending-uri-invalid"));
    }
    let uri = core::str::from_utf8(uri)
        .map_err(|_| OtsInternalError::Invalid("ots-pending-uri-invalid"))?;
    Ok(uri.to_string())
}

fn parse_bitcoin_block_header_attestation_height(payload: &[u8]) -> Result<u64, OtsInternalError> {
    let mut payload_cursor = OtsCursor::new(payload);
    let height = payload_cursor.read_varuint()?;
    payload_cursor.assert_eof()?;
    Ok(height)
}

fn verify_detached_ots_proof(
    raw: &[u8],
    ots_path: &Path,
    expected_artifact_sha: Option<&str>,
) -> Result<OtsVerifyResult, OtsInternalError> {
    let summary = parse_detached_ots(raw, ots_path, expected_artifact_sha)?;
    if !summary.bitcoin_heights.is_empty() {
        // Native parsing can confirm proof shape and artifact binding, but it
        // does not validate inclusion against the referenced Bitcoin header.
        return Err(OtsInternalError::Fallback);
    }
    if !summary.pending_uris.is_empty() {
        return Ok(OtsVerifyResult::success(
            OtsStatus::Pending,
            "ots-pending-attestation",
        ));
    }
    Err(OtsInternalError::Fallback)
}

fn describe_detached_ots_proof_impl(
    ots_path: &Path,
    expected_artifact_sha: Option<&str>,
) -> Result<Vec<String>, OtsInternalError> {
    let raw = fs::read(ots_path).map_err(|_| OtsInternalError::Invalid("ots-proof-read-failed"))?;
    let summary = parse_detached_ots(&raw, ots_path, expected_artifact_sha)?;
    let mut description = Vec::with_capacity(summary.steps.len() + 1);
    description.push(format!("file sha256 {}", hex_lower(&summary.file_digest)));
    description.extend(summary.steps);
    Ok(description)
}

#[cfg_attr(feature = "python", pyclass(eq, eq_int, skip_from_py_object))]
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

#[cfg(feature = "python")]
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

#[cfg_attr(feature = "python", pyclass(skip_from_py_object))]
#[derive(Clone, Debug)]
struct OtsVerifyResult {
    ok: bool,
    status: OtsStatus,
    reason: String,
    bitcoin_attestation_heights: Vec<u64>,
}

impl OtsVerifyResult {
    fn new(ok: bool, status: OtsStatus, reason: impl Into<String>) -> Self {
        Self {
            ok,
            status,
            reason: reason.into(),
            bitcoin_attestation_heights: Vec::new(),
        }
    }

    fn success(status: OtsStatus, reason: impl Into<String>) -> Self {
        Self::new(true, status, reason)
    }

    fn failure(status: OtsStatus, reason: impl Into<String>) -> Self {
        Self::new(false, status, reason)
    }
}

#[cfg(feature = "python")]
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

    #[getter]
    fn bitcoin_attestation_heights(&self) -> Vec<u64> {
        self.bitcoin_attestation_heights.clone()
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
                return OtsVerifyResult::failure(OtsStatus::Failed, "stationary-stub-invalid");
            }
            normalize_hex(expected)
        } else {
            let artifact_path = match artifact_path_for_ots(ots_path) {
                Some(path) => path,
                None => {
                    return OtsVerifyResult::failure(OtsStatus::Failed, "ots-invalid-path");
                }
            };
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

    match verify_detached_ots_proof(&raw, ots_path, expected_artifact_sha) {
        Ok(result) => return result,
        Err(OtsInternalError::Invalid(reason)) => {
            return OtsVerifyResult::failure(OtsStatus::Failed, reason);
        }
        Err(OtsInternalError::Fallback) => {}
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

    let meta_artifact_path = resolve_from(repo_root, Path::new(artifact_rel));
    let canonical_expected_artifact_path = match fs::canonicalize(expected_artifact_path) {
        Ok(path) => path,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return OtsVerifyResult::failure(OtsStatus::Missing, "meta-artifact-missing");
        }
        Err(_) => {
            return OtsVerifyResult::failure(
                OtsStatus::Failed,
                "meta-artifact-path-resolution-failed",
            );
        }
    };
    let canonical_meta_artifact_path = match fs::canonicalize(&meta_artifact_path) {
        Ok(path) => path,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return OtsVerifyResult::failure(OtsStatus::Missing, "meta-artifact-missing");
        }
        Err(_) => {
            return OtsVerifyResult::failure(
                OtsStatus::Failed,
                "meta-artifact-path-resolution-failed",
            );
        }
    };
    if canonical_meta_artifact_path != canonical_expected_artifact_path {
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

    let meta_ots_path = resolve_from(repo_root, Path::new(ots_rel));
    let canonical_expected_ots_path = match fs::canonicalize(expected_ots_path) {
        Ok(path) => path,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return OtsVerifyResult::failure(OtsStatus::Missing, "ots-proof-not-found");
        }
        Err(_) => {
            return OtsVerifyResult::failure(OtsStatus::Failed, "ots-proof-path-resolution-failed");
        }
    };
    let canonical_meta_ots_path = match fs::canonicalize(&meta_ots_path) {
        Ok(path) => path,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return OtsVerifyResult::failure(OtsStatus::Missing, "ots-proof-not-found");
        }
        Err(_) => {
            return OtsVerifyResult::failure(OtsStatus::Failed, "ots-proof-path-resolution-failed");
        }
    };
    if canonical_meta_ots_path != canonical_expected_ots_path {
        return OtsVerifyResult::failure(OtsStatus::Failed, "meta-ots-path-mismatch");
    }

    OtsVerifyResult::success(OtsStatus::Verified, "meta-valid")
}

#[cfg(feature = "python")]
#[pyfunction]
fn hash_for_ots<'py>(py: Python<'py>, artifact: &Bound<'py, PyBytes>) -> Bound<'py, PyBytes> {
    let digest = sha256_digest(artifact.as_bytes());
    PyBytes::new(py, &digest)
}

#[cfg(feature = "python")]
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

#[cfg(feature = "python")]
#[pyfunction(signature = (ots_path, expected_artifact_sha = None))]
fn describe_ots_proof(
    ots_path: String,
    expected_artifact_sha: Option<String>,
) -> PyResult<Vec<String>> {
    describe_detached_ots_proof_impl(Path::new(&ots_path), expected_artifact_sha.as_deref())
        .map_err(|err| {
            let reason = match err {
                OtsInternalError::Fallback => "ots-proof-unsupported",
                OtsInternalError::Invalid(reason) => reason,
            };
            PyValueError::new_err(reason)
        })
}

#[cfg(feature = "python")]
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

#[cfg(feature = "python")]
pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(parent.py(), "ots")?;
    sub.add_class::<OtsStatus>()?;
    sub.add_class::<OtsVerifyResult>()?;
    sub.add_function(wrap_pyfunction!(hash_for_ots, &sub)?)?;
    sub.add_function(wrap_pyfunction!(verify_ots_proof, &sub)?)?;
    sub.add_function(wrap_pyfunction!(describe_ots_proof, &sub)?)?;
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

    fn write_varuint(out: &mut Vec<u8>, mut value: u64) {
        if value == 0 {
            out.push(0);
            return;
        }

        while value != 0 {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
        }
    }

    fn write_varbytes(out: &mut Vec<u8>, bytes: &[u8]) {
        write_varuint(out, bytes.len() as u64);
        out.extend_from_slice(bytes);
    }

    fn write_attestation(out: &mut Vec<u8>, tag: &[u8; 8], payload: &[u8]) {
        out.push(OTS_TIMESTAMP_ATTESTATION);
        out.extend_from_slice(tag);
        write_varbytes(out, payload);
    }

    fn bitcoin_attestation_payload(height: u64) -> Vec<u8> {
        let mut payload = Vec::new();
        write_varuint(&mut payload, height);
        payload
    }

    fn pending_attestation_payload(uri: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        write_varbytes(&mut payload, uri.as_bytes());
        payload
    }

    fn detached_ots(file_digest: &[u8; 32], timestamp: &[u8]) -> Vec<u8> {
        let mut proof = Vec::new();
        proof.extend_from_slice(OTS_HEADER_MAGIC);
        write_varuint(&mut proof, OTS_MAJOR_VERSION);
        proof.push(OTS_OP_SHA256);
        proof.extend_from_slice(file_digest);
        proof.extend_from_slice(timestamp);
        proof
    }

    fn append_prepend_sha256_bitcoin_proof(file_digest: &[u8; 32], height: u64) -> Vec<u8> {
        let mut timestamp = Vec::new();
        timestamp.push(OTS_OP_APPEND);
        write_varbytes(&mut timestamp, &[0xaa, 0xbb]);
        timestamp.push(OTS_OP_PREPEND);
        write_varbytes(&mut timestamp, &[0x01, 0x02, 0x03]);
        timestamp.push(OTS_OP_SHA256);
        write_attestation(
            &mut timestamp,
            &OTS_BITCOIN_BLOCK_HEADER_ATTESTATION_TAG,
            &bitcoin_attestation_payload(height),
        );
        detached_ots(file_digest, &timestamp)
    }

    fn pending_proof(file_digest: &[u8; 32], uri: &str) -> Vec<u8> {
        let mut timestamp = Vec::new();
        write_attestation(
            &mut timestamp,
            &OTS_PENDING_ATTESTATION_TAG,
            &pending_attestation_payload(uri),
        );
        detached_ots(file_digest, &timestamp)
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
    fn verify_ots_proof_requires_external_verifier_for_bitcoin_attestation() {
        let tmp = TestDir::new("native-bitcoin");
        let artifact_path = tmp.path().join("2025-10-07.cbor");
        let ots_path = artifact_path.with_extension("cbor.ots");
        fs::write(&artifact_path, b"day-bytes").unwrap();
        let artifact_digest = sha256_digest(b"day-bytes");
        let proof = append_prepend_sha256_bitcoin_proof(&artifact_digest, 849_123);
        fs::write(&ots_path, &proof).unwrap();

        let result = verify_ots_proof_impl(
            &ots_path,
            false,
            Some(&hex_lower(&artifact_digest)),
            None,
            default_verify_timeout(),
        );

        assert!(!result.ok);
        assert_eq!(result.status, OtsStatus::Failed);
        assert_eq!(result.reason, "ots-binary-not-found");
        assert!(result.bitcoin_attestation_heights.is_empty());

        let summary = parse_detached_ots(&proof, &ots_path, Some(&hex_lower(&artifact_digest)))
            .expect("native OTS proof should parse");
        assert_eq!(summary.file_digest, artifact_digest);
        assert_eq!(summary.bitcoin_heights, vec![849_123]);
        assert_eq!(
            summary.steps,
            vec![
                "append aabb".to_string(),
                "prepend 010203".to_string(),
                "sha256".to_string(),
                "verify BitcoinBlockHeaderAttestation(849123)".to_string(),
            ]
        );
    }

    #[test]
    fn verify_ots_proof_reports_native_pending_attestation() {
        let tmp = TestDir::new("native-pending");
        let artifact_path = tmp.path().join("2025-10-07.cbor");
        let ots_path = artifact_path.with_extension("cbor.ots");
        fs::write(&artifact_path, b"day-bytes").unwrap();
        let artifact_digest = sha256_digest(b"day-bytes");
        fs::write(
            &ots_path,
            pending_proof(&artifact_digest, "https://calendar.example"),
        )
        .unwrap();

        let result = verify_ots_proof_impl(
            &ots_path,
            false,
            Some(&hex_lower(&artifact_digest)),
            None,
            default_verify_timeout(),
        );

        assert!(result.ok);
        assert_eq!(result.status, OtsStatus::Pending);
        assert_eq!(result.reason, "ots-pending-attestation");
    }

    #[test]
    fn verify_ots_proof_rejects_native_artifact_hash_mismatch() {
        let tmp = TestDir::new("native-mismatch");
        let artifact_path = tmp.path().join("2025-10-07.cbor");
        let ots_path = artifact_path.with_extension("cbor.ots");
        fs::write(&artifact_path, b"day-bytes").unwrap();
        let proof_digest = sha256_digest(b"different-day-bytes");
        fs::write(
            &ots_path,
            append_prepend_sha256_bitcoin_proof(&proof_digest, 849_123),
        )
        .unwrap();

        let result = verify_ots_proof_impl(
            &ots_path,
            false,
            Some(&sha256_hex(b"day-bytes")),
            None,
            default_verify_timeout(),
        );

        assert!(!result.ok);
        assert_eq!(result.status, OtsStatus::Failed);
        assert_eq!(result.reason, "ots-proof-artifact-hash-mismatch");
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
