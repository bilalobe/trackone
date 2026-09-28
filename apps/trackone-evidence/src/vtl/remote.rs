//! Optional HTTPS reference binding for immutable producer snapshots.

use super::manifest::{ArtifactRef, Manifest};
use super::paths::{valid_hex, validate_portable_path};
use super::{
    MANIFEST_NAME, MAX_ARCHIVE_MEMBER, Result, VerificationScope, VerifyPolicy, bad,
    parse_manifest, verify_bundle_with_policy,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use trackone_ledger::sha256_hex;

const MAX_REQUESTS: usize = 10_000;
const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_RETRIES: u8 = 2;
const MAX_DIAGNOSTIC_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug)]
pub struct RemoteOptions {
    pub bundle_url: String,
    pub expected_segment_sha256: String,
    pub https_ca_file: PathBuf,
    pub curl_binary: PathBuf,
    pub request_timeout: Duration,
    pub retries: u8,
    pub max_object_bytes: u64,
    pub max_total_bytes: u64,
    pub max_requests: usize,
}

impl RemoteOptions {
    pub fn new(
        bundle_url: impl Into<String>,
        expected_segment_sha256: impl Into<String>,
        https_ca_file: PathBuf,
    ) -> Self {
        Self {
            bundle_url: bundle_url.into(),
            expected_segment_sha256: expected_segment_sha256.into(),
            https_ca_file,
            curl_binary: PathBuf::from("curl"),
            request_timeout: DEFAULT_TIMEOUT,
            retries: DEFAULT_RETRIES,
            max_object_bytes: MAX_ARCHIVE_MEMBER,
            max_total_bytes: MAX_TOTAL_BYTES,
            max_requests: MAX_REQUESTS,
        }
    }
}

struct Retriever<'a> {
    options: &'a RemoteOptions,
    base: String,
    requests: usize,
    bytes: u64,
}

/// Retrieve only evidence consumed by the selected verification scope, stage
/// it privately, and apply the local baseline verifier to the exact bytes.
pub fn verify_remote_bundle(options: &RemoteOptions, policy: &VerifyPolicy) -> Result<Value> {
    validate_options(options)?;
    let temporary = tempfile::Builder::new()
        .prefix("trackone-remote-evidence-")
        .tempdir()?;
    let mut retriever = Retriever {
        options,
        base: validate_bundle_root(&options.bundle_url)?,
        requests: 0,
        bytes: 0,
    };
    let manifest_bytes = retriever.fetch(MANIFEST_NAME, "application/json")?;
    write_staged(temporary.path(), MANIFEST_NAME, &manifest_bytes)?;
    let manifest = parse_manifest(&manifest_bytes)?;

    // The primary artifact is acquired before any secondary evidence. Its
    // independently provisioned digest is deliberately not taken from the
    // unauthenticated manifest.
    let artifact = retriever.stage_reference(
        temporary.path(),
        &manifest.artifacts.segment_cbor,
        "application/cbor",
    )?;
    let expected_mismatch = sha256_hex(&artifact) != options.expected_segment_sha256;

    if let Some(reference) = &manifest.artifacts.predecessor_segment_cbor {
        retriever.stage_reference(temporary.path(), reference, "application/cbor")?;
    }
    for reference in manifest.artifacts.extensions.values() {
        retriever.stage_reference(temporary.path(), reference, "application/octet-stream")?;
    }
    if manifest.anchoring.tsa.status == "present" {
        if let Some(reference) = &manifest.artifacts.tsa_req {
            retriever.stage_reference(
                temporary.path(),
                reference,
                "application/timestamp-query",
            )?;
        }
        if let Some(reference) = &manifest.artifacts.tsa_tsr {
            retriever.stage_reference(
                temporary.path(),
                reference,
                "application/timestamp-reply",
            )?;
        }
    }

    let claimed_scope = VerificationScope::for_disclosure_class(&manifest.disclosure_class);
    let selected_scope = policy.selected_scope.unwrap_or(claimed_scope);
    let consumed_batches = consumed_batches(&manifest, policy, selected_scope);
    for opening in manifest.artifacts.record_batches.iter().flatten() {
        let Ok(batch_number) = opening.batch_number.parse::<u64>() else {
            continue;
        };
        if !consumed_batches.contains(&batch_number) {
            continue;
        }
        for reference in &opening.records {
            retriever.stage_reference(temporary.path(), reference, "application/cbor")?;
        }
    }

    let mut result = verify_bundle_with_policy(temporary.path(), policy)?;
    if expected_mismatch {
        add_integrity_failure(&mut result);
    }
    Ok(result)
}

fn consumed_batches(
    manifest: &Manifest,
    policy: &VerifyPolicy,
    scope: VerificationScope,
) -> BTreeSet<u64> {
    if scope == VerificationScope::AnchorOnly {
        return BTreeSet::new();
    }
    if scope == VerificationScope::DisclosedBatchRecompute && manifest.disclosure_class == "A" {
        return policy.selected_batches.clone();
    }
    manifest
        .artifacts
        .record_batches
        .iter()
        .flatten()
        .filter_map(|opening| opening.batch_number.parse().ok())
        .collect()
}

fn add_integrity_failure(result: &mut Value) {
    let object = result
        .as_object_mut()
        .expect("local verification always returns an object");
    let failures = object
        .entry("failure_reasons")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .expect("failure_reasons is an array");
    if !failures.iter().any(|value| value == "commitment_mismatch") {
        failures.push(json!("commitment_mismatch"));
        failures.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
    }
    object.insert("overall".into(), json!("failure"));
}

impl Retriever<'_> {
    fn stage_reference(
        &mut self,
        root: &Path,
        reference: &ArtifactRef,
        accept: &str,
    ) -> Result<Vec<u8>> {
        // Keep mismatching bytes: the baseline verifier must classify this as
        // commitment_mismatch, never as unavailable evidence.
        let bytes = self.fetch(&reference.path, accept)?;
        write_staged(root, &reference.path, &bytes)?;
        Ok(bytes)
    }

    fn fetch(&mut self, relative: &str, accept: &str) -> Result<Vec<u8>> {
        validate_portable_path(relative)?;
        self.requests = self
            .requests
            .checked_add(1)
            .ok_or_else(|| bad("remote request counter overflow"))?;
        if self.requests > self.options.max_requests {
            return Err(bad("remote evidence request limit exceeded"));
        }
        let url = format!("{}{}", self.base, encode_path(relative));
        if !url.starts_with(&self.base) {
            return Err(bad("constructed evidence URL escaped the bundle root"));
        }
        let scratch = tempfile::Builder::new()
            .prefix("trackone-http-object-")
            .tempdir()?;
        let body = scratch.path().join("body");
        let headers = scratch.path().join("headers");
        let timeout = self.options.request_timeout.as_secs().max(1).to_string();
        let retry_max = self
            .options
            .request_timeout
            .as_secs()
            .max(1)
            .saturating_mul(u64::from(self.options.retries) + 1)
            .to_string();
        let max_bytes = self.options.max_object_bytes.to_string();
        let output = Command::new(&self.options.curl_binary)
            .args([
                "--silent",
                "--show-error",
                "--path-as-is",
                "--proto",
                "=https",
                "--tlsv1.3",
                "--connect-timeout",
                &timeout,
                "--max-time",
                &timeout,
                "--retry",
                &self.options.retries.to_string(),
                "--retry-connrefused",
                "--retry-delay",
                "0",
                "--retry-max-time",
                &retry_max,
                "--max-filesize",
                &max_bytes,
                "--cacert",
            ])
            .arg(&self.options.https_ca_file)
            .args(["--header", "Accept-Encoding: identity", "--header"])
            .arg(format!("Accept: {accept}"))
            .arg("--dump-header")
            .arg(&headers)
            .arg("--output")
            .arg(&body)
            .args(["--write-out", "%{http_code} %{http_version}"])
            .arg(&url)
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .output()
            .map_err(|error| bad(format!("HTTPS retrieval could not execute: {error}")))?;
        if !output.status.success() {
            let diagnostic = String::from_utf8_lossy(
                &output.stderr[..output.stderr.len().min(MAX_DIAGNOSTIC_BYTES)],
            );
            return Err(bad(format!(
                "HTTPS retrieval failed after the finite retry budget: {}",
                diagnostic.trim()
            )));
        }
        let status =
            String::from_utf8(output.stdout).map_err(|_| bad("curl status output is not UTF-8"))?;
        let mut status_fields = status.split_whitespace();
        if status_fields.next() != Some("200") {
            return Err(bad(format!(
                "evidence retrieval requires a complete HTTP 200 response, got {status}"
            )));
        }
        if !matches!(status_fields.next(), Some("1.1" | "2")) {
            return Err(bad(format!(
                "unsupported negotiated HTTP version in {status}"
            )));
        }
        let declared_length = validate_headers(&fs::read(&headers)?)?;
        let bytes = fs::read(&body)?;
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if declared_length.is_some_and(|declared| declared != length) {
            return Err(bad(
                "HTTP Content-Length does not match the complete evidence body",
            ));
        }
        if length > self.options.max_object_bytes {
            return Err(bad(
                "remote evidence object exceeds the configured byte limit",
            ));
        }
        self.bytes = self
            .bytes
            .checked_add(length)
            .ok_or_else(|| bad("remote evidence byte counter overflow"))?;
        if self.bytes > self.options.max_total_bytes {
            return Err(bad(
                "remote evidence exceeds the configured aggregate byte limit",
            ));
        }
        Ok(bytes)
    }
}

fn validate_options(options: &RemoteOptions) -> Result<()> {
    if !valid_hex(&options.expected_segment_sha256, 64) {
        return Err(bad(
            "expected segment SHA-256 must be 64 lowercase hexadecimal characters",
        ));
    }
    if !options.https_ca_file.is_file() {
        return Err(bad("HTTPS CA file is not a regular file"));
    }
    if options.request_timeout.is_zero()
        || options.max_object_bytes == 0
        || options.max_total_bytes == 0
        || options.max_requests == 0
    {
        return Err(bad("remote retrieval limits must be finite and positive"));
    }
    Ok(())
}

fn validate_bundle_root(value: &str) -> Result<String> {
    let remainder = value
        .strip_prefix("https://")
        .ok_or_else(|| bad("bundle URL must use https"))?;
    let authority_end = remainder.find('/').unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty()
        || authority.contains('@')
        || value.contains('?')
        || value.contains('#')
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || !value.ends_with('/')
    {
        return Err(bad(
            "bundle URL must be an absolute HTTPS directory URL without userinfo, query, or fragment",
        ));
    }
    Ok(value.to_string())
}

fn encode_path(path: &str) -> String {
    let mut encoded = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    encoded
}

fn validate_headers(bytes: &[u8]) -> Result<Option<u64>> {
    let text = std::str::from_utf8(bytes).map_err(|_| bad("HTTP headers are not UTF-8"))?;
    let block = text
        .split("\r\n\r\n")
        .filter(|part| part.starts_with("HTTP/"))
        .last()
        .ok_or_else(|| bad("missing final HTTP response headers"))?;
    let mut content_length = None;
    let mut transfer_encoding = false;
    for line in block.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            return Err(bad("malformed HTTP response header"));
        };
        if name.eq_ignore_ascii_case("content-encoding")
            && !value.trim().eq_ignore_ascii_case("identity")
        {
            return Err(bad("unexpected Content-Encoding on evidence response"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value
                .trim()
                .parse::<u64>()
                .map_err(|_| bad("invalid Content-Length on evidence response"))?;
            if content_length.replace(parsed).is_some() {
                return Err(bad("multiple Content-Length fields on evidence response"));
            }
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            transfer_encoding = true;
        }
    }
    if transfer_encoding && content_length.is_some() {
        return Err(bad(
            "ambiguous HTTP framing: Transfer-Encoding with Content-Length",
        ));
    }
    // curl detects truncated framed bodies. Content-Length is retained here as
    // an additional syntax/ambiguity check; body length is bounded separately.
    Ok(content_length)
}

fn write_staged(root: &Path, relative: &str, bytes: &[u8]) -> Result<()> {
    validate_portable_path(relative)?;
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encoding_preserves_special_filename_octets_as_data() {
        assert_eq!(
            encode_path("records/literal%?#-é.cbor"),
            "records/literal%25%3F%23-%C3%A9.cbor"
        );
    }

    #[test]
    fn rejects_ambiguous_framing_without_rejecting_valid_chunked_responses() {
        assert!(
            validate_headers(
                b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
            .is_err()
        );
        assert_eq!(
            validate_headers(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap(),
            None
        );
        assert_eq!(
            validate_headers(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n").unwrap(),
            Some(12)
        );
    }

    #[test]
    fn bundle_root_rejects_ambiguous_or_insecure_urls() {
        assert!(validate_bundle_root("http://example.test/b/").is_err());
        assert!(validate_bundle_root("https://example.test/b").is_err());
        assert!(validate_bundle_root("https://example.test/b/?x").is_err());
        assert!(validate_bundle_root("https://user@example.test/b/").is_err());
        assert_eq!(
            validate_bundle_root("https://example.test/b/").unwrap(),
            "https://example.test/b/"
        );
    }
}
