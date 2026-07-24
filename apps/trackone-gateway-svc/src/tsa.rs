//! OpenSSL-backed RFC 3161 submission and strict archived-profile validation.
//!
//! The live path deliberately uses the archived-token verifier immediately
//! after submission. It does not reconstruct nonce-based transaction checks,
//! and historical validation at the signed `genTime` is not independent proof
//! of when the response was first observed.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use trackone_ledger::sha256_digest;
use trackone_rfc3161::{
    HistoricalValidationArchive, SignerCertificateSha256, VerificationPolicy, VerifiedTimestamp,
    verify_response,
};

use crate::producer::ProducerError;

const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StampedResponse {
    pub response_der: Vec<u8>,
    pub verified_timestamp: VerifiedTimestamp,
}

#[derive(Clone, Debug)]
pub struct Rfc3161TimestampAuthority {
    url: String,
    policy_oid: String,
    verification_policy: VerificationPolicy,
    openssl_binary: PathBuf,
    curl_binary: PathBuf,
    timeout: Duration,
}

impl Rfc3161TimestampAuthority {
    pub fn new(
        url: impl Into<String>,
        trust_anchors_file: PathBuf,
        intermediates_file: Option<PathBuf>,
        crls_file: PathBuf,
        policy_oid: impl Into<String>,
        signer_certificate_sha256: SignerCertificateSha256,
    ) -> Result<Self, ProducerError> {
        let policy_oid = policy_oid.into();
        let verification_policy = VerificationPolicy::new(
            HistoricalValidationArchive {
                trust_anchors_file,
                intermediates_file,
                crls_file,
            },
            &policy_oid,
            signer_certificate_sha256,
        )
        .map_err(|error| ProducerError::TimestampConfiguration(error.to_string()))?;
        let policy_oid = verification_policy.expected_policy_oid().to_string();
        Ok(Self {
            url: url.into(),
            policy_oid,
            verification_policy,
            openssl_binary: PathBuf::from("openssl"),
            curl_binary: PathBuf::from("curl"),
            timeout: DEFAULT_TIMEOUT,
        })
    }

    #[cfg(test)]
    fn with_binaries(mut self, openssl_binary: PathBuf, curl_binary: PathBuf) -> Self {
        self.verification_policy = self
            .verification_policy
            .with_openssl_binary(openssl_binary.clone());
        self.openssl_binary = openssl_binary;
        self.curl_binary = curl_binary;
        self
    }

    /// Submit, verify, and durably publish a timestamp response without
    /// replacing an existing destination.
    ///
    /// A successful return follows a staged-file `sync_all`, no-clobber
    /// publication, and containing-directory `sync_all`. As with any such
    /// guarantee, the backing filesystem must honor those synchronization
    /// operations.
    pub fn stamp(&self, artifact: &[u8]) -> Result<StampedResponse, ProducerError> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProducerError::Clock("system time precedes Unix epoch".to_string()))?
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("trackone-tsa-{}-{nonce}", std::process::id()));
        let query = base.with_extension("tsq");
        let response = base.with_extension("tsr");
        let result = self.stamp_paths(artifact, &query, &response);
        let _ = fs::remove_file(&query);
        let _ = fs::remove_file(&response);
        result
    }

    fn stamp_paths(
        &self,
        artifact: &[u8],
        query: &Path,
        response: &Path,
    ) -> Result<StampedResponse, ProducerError> {
        let artifact_digest = sha256_digest(artifact);
        let digest_hex = hex_lower(&artifact_digest);
        let staged_response = TemporaryResponse::new_next_to(response)?;
        let response_bytes = self.submit_paths(&digest_hex, query, staged_response.path())?;
        let verified_timestamp =
            verify_response(&response_bytes, artifact_digest, &self.verification_policy)
                .map_err(|error| ProducerError::TimestampVerification(error.to_string()))?;
        staged_response.persist(response)?;
        Ok(StampedResponse {
            response_der: response_bytes,
            verified_timestamp,
        })
    }

    fn submit_paths(
        &self,
        digest: &str,
        query: &Path,
        response: &Path,
    ) -> Result<Vec<u8>, ProducerError> {
        let mut query_command = Command::new(&self.openssl_binary);
        query_command
            .args([
                "ts",
                "-query",
                "-digest",
                digest,
                "-sha256",
                "-cert",
                "-tspolicy",
            ])
            .arg(&self.policy_oid)
            .arg("-no_nonce")
            .arg("-out")
            .arg(query);
        let query_status = run_command(query_command, "OpenSSL timestamp query", self.timeout)?;
        require_success("OpenSSL timestamp query", &query_status)?;

        let timeout = self.timeout.as_secs().max(1).to_string();
        let upload = format!("@{}", query.display());
        let mut curl_command = Command::new(&self.curl_binary);
        curl_command
            .args(["-fsS", "--max-time", &timeout])
            .args(["-H", "Content-Type: application/timestamp-query"])
            .args(["-H", "Accept: application/timestamp-reply"])
            .args(["--data-binary", &upload])
            .arg(&self.url)
            .arg("-o")
            .arg(response);
        let curl_status = run_command(curl_command, "RFC 3161 HTTP submission", self.timeout)?;
        require_success("RFC 3161 HTTP submission", &curl_status)?;

        let response_size = fs::metadata(response)
            .map_err(|error| ProducerError::TimestampSubmission(error.to_string()))?
            .len();
        if response_size > MAX_RESPONSE_BYTES {
            return Err(ProducerError::TimestampSubmission(format!(
                "TSA response is {response_size} bytes; maximum is {MAX_RESPONSE_BYTES}"
            )));
        }
        fs::read(response).map_err(|error| ProducerError::TimestampSubmission(error.to_string()))
    }
}

struct TemporaryResponse {
    path: PathBuf,
}

impl TemporaryResponse {
    fn new_next_to(final_path: &Path) -> Result<Self, ProducerError> {
        let parent = final_path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = final_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                ProducerError::TimestampPersistence(
                    "response path must have a UTF-8 file name".to_string(),
                )
            })?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                ProducerError::TimestampPersistence("system time precedes Unix epoch".to_string())
            })?
            .as_nanos();
        for attempt in 0..16_u8 {
            let path = parent.join(format!(
                ".{file_name}.{}-{nonce}-{attempt}.pending",
                std::process::id()
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(_) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(ProducerError::TimestampPersistence(error.to_string()));
                }
            }
        }
        Err(ProducerError::TimestampPersistence(
            "could not allocate a unique staged timestamp response".to_string(),
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn persist(self, final_path: &Path) -> Result<(), ProducerError> {
        let staged_file = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|error| ProducerError::TimestampPersistence(error.to_string()))?;
        staged_file
            .sync_all()
            .map_err(|error| ProducerError::TimestampPersistence(error.to_string()))?;
        fs::hard_link(&self.path, final_path)
            .map_err(|error| ProducerError::TimestampPersistence(error.to_string()))?;
        // The final hard link now owns publication. Remove the staging name
        // before syncing the directory so a successful return records both
        // the publication and its cleanup in the durable directory state.
        let _ = fs::remove_file(&self.path);
        let parent = final_path.parent().unwrap_or_else(|| Path::new("."));
        let directory = fs::File::open(parent)
            .map_err(|error| ProducerError::TimestampPersistence(error.to_string()))?;
        directory
            .sync_all()
            .map_err(|error| ProducerError::TimestampPersistence(error.to_string()))
    }
}

impl Drop for TemporaryResponse {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn run_command(
    mut command: Command,
    label: &'static str,
    timeout: Duration,
) -> Result<Output, ProducerError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|error| {
        ProducerError::TimestampSubmission(format!("{label} could not execute: {error}"))
    })?;
    let started = Instant::now();
    loop {
        if child
            .try_wait()
            .map_err(|error| ProducerError::TimestampSubmission(error.to_string()))?
            .is_some()
        {
            return child
                .wait_with_output()
                .map_err(|error| ProducerError::TimestampSubmission(error.to_string()));
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ProducerError::TimestampSubmission(format!(
                "{label} exceeded the {} second process timeout",
                timeout.as_secs()
            )));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn require_success(label: &str, output: &Output) -> Result<(), ProducerError> {
    if output.status.success() {
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let diagnostic = match (stdout.is_empty(), stderr.is_empty()) {
        (false, false) => format!("stdout: {stdout}; stderr: {stderr}"),
        (false, true) => format!("stdout: {stdout}"),
        (true, false) => format!("stderr: {stderr}"),
        (true, true) => "no diagnostic output".to_string(),
    };
    Err(ProducerError::TimestampSubmission(format!(
        "{label} failed: {diagnostic}"
    )))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const FIXTURE_SIGNER: &str = "14ab98cafe09d9d1d01562af42d69a904b01023d9cd5b03bd07e5779710c8014";

    fn fixture_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/trackone-rfc3161/tests/fixtures")
    }

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("trackone-tsa-test-{}-{name}", std::process::id()))
    }

    fn fake_curl(root: &Path, source: &Path) -> PathBuf {
        let curl = root.join("curl");
        fs::write(
            &curl,
            format!(
                "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; cp '{}' \"$1\"; exit $?; fi; shift; done\nexit 1\n",
                source.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&curl, fs::Permissions::from_mode(0o755)).unwrap();
        curl
    }

    fn fixture_authority(curl: PathBuf) -> Rfc3161TimestampAuthority {
        let fixtures = fixture_root();
        Rfc3161TimestampAuthority::new(
            "https://tsa.invalid",
            fixtures.join("tsa-root.pem"),
            None,
            fixtures.join("tsa-crls.pem"),
            "1.3.6.1.4.1.55555.1",
            FIXTURE_SIGNER.parse().unwrap(),
        )
        .unwrap()
        .with_binaries(PathBuf::from("openssl"), curl)
    }

    #[test]
    fn derives_one_digest_verifies_and_publishes_atomically() {
        let root = test_root("success");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let fixtures = fixture_root();
        let curl = fake_curl(&root, &fixtures.join("response.tsr"));
        let authority = fixture_authority(curl);
        let artifact = fs::read(fixtures.join("segment.cbor")).unwrap();
        let query = root.join("query.tsq");
        let response = root.join("response.tsr");

        let stamped = authority.stamp_paths(&artifact, &query, &response).unwrap();

        assert_eq!(stamped.response_der, fs::read(&response).unwrap());
        assert_eq!(
            stamped.verified_timestamp.generation_time.to_rfc3339(),
            "2026-07-22T23:04:12Z"
        );
        let query_text = Command::new("openssl")
            .args(["ts", "-query", "-in"])
            .arg(&query)
            .arg("-text")
            .output()
            .unwrap();
        assert!(query_text.status.success());
        let mut query_digest = Vec::new();
        for line in String::from_utf8_lossy(&query_text.stdout).lines() {
            let Some((_, values)) = line.split_once(" - ") else {
                continue;
            };
            for token in values.split_whitespace() {
                let components = token.split('-').collect::<Vec<_>>();
                if components.iter().all(|component| {
                    component.len() == 2 && u8::from_str_radix(component, 16).is_ok()
                }) {
                    query_digest.extend(
                        components
                            .into_iter()
                            .map(|component| u8::from_str_radix(component, 16).unwrap()),
                    );
                } else {
                    break;
                }
            }
        }
        assert_eq!(query_digest, sha256_digest(&artifact));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_response_never_occupies_the_final_path() {
        let root = test_root("invalid");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let invalid = root.join("invalid.tsr");
        fs::write(&invalid, b"not a timestamp response").unwrap();
        let curl = fake_curl(&root, &invalid);
        let authority = fixture_authority(curl);
        let query = root.join("query.tsq");
        let response = root.join("response.tsr");

        let error = authority
            .stamp_paths(b"artifact", &query, &response)
            .unwrap_err();

        assert!(matches!(error, ProducerError::TimestampVerification(_)));
        assert!(!response.exists());
        assert!(fs::read_dir(&root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".pending")
        }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn durable_publication_does_not_overwrite_an_existing_response() {
        let root = test_root("no-clobber");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let response = root.join("response.tsr");

        let staged = TemporaryResponse::new_next_to(&response).unwrap();
        fs::write(staged.path(), b"first").unwrap();
        staged.persist(&response).unwrap();
        assert_eq!(fs::read(&response).unwrap(), b"first");

        let staged = TemporaryResponse::new_next_to(&response).unwrap();
        fs::write(staged.path(), b"second").unwrap();
        let error = staged.persist(&response).unwrap_err();
        assert!(matches!(error, ProducerError::TimestampPersistence(_)));
        assert_eq!(fs::read(&response).unwrap(), b"first");
        assert!(fs::read_dir(&root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".pending")
        }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_archive_configuration_fails_at_construction() {
        let error = Rfc3161TimestampAuthority::new(
            "https://tsa.invalid",
            "missing-anchors.pem".into(),
            None,
            "missing-crls.pem".into(),
            "1.3.6.1.4.1.55555.1",
            FIXTURE_SIGNER.parse().unwrap(),
        )
        .unwrap_err();
        assert!(matches!(error, ProducerError::TimestampConfiguration(_)));
    }
}
