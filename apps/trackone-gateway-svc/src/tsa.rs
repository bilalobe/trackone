//! OpenSSL-backed RFC 3161 submission and strict archived-profile validation.
//!
//! The live path deliberately uses nonce-free requests, validates each returned
//! token immediately, and retains the response. Historical validation at the
//! signed `genTime` is not independent proof of when the response was observed.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
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
        max_future_skew: Duration,
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
        .map_err(|error| ProducerError::TimestampConfiguration(error.to_string()))?
        .with_max_future_skew(max_future_skew);
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
            // Must be first: ambient .curlrc output directives bypass stdout capture.
            .arg("--disable")
            .args(["-fsS", "--no-buffer", "--max-time", &timeout])
            .args(["-H", "Content-Type: application/timestamp-query"])
            .args(["-H", "Accept: application/timestamp-reply"])
            .args(["--data-binary", &upload])
            .arg(&self.url);
        let curl_status = run_submission(curl_command, self.timeout)?;
        require_success("RFC 3161 HTTP submission", &curl_status)?;

        // No response body reaches disk until the entire bounded transfer succeeds.
        let mut staged = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(response)
            .map_err(|error| ProducerError::TimestampPersistence(error.to_string()))?;
        staged
            .write_all(&curl_status.stdout)
            .map_err(|error| ProducerError::TimestampPersistence(error.to_string()))?;
        Ok(curl_status.stdout)
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

/// Capture the body with one overflow-detection byte, supervising the process
/// independently of reads so a stalled pipe cannot defeat the request deadline.
fn run_submission(mut command: Command, timeout: Duration) -> Result<Output, ProducerError> {
    const MAX_DIAGNOSTIC_BYTES: usize = 8192;
    let submission_error = |message: String| ProducerError::TimestampSubmission(message);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|error| {
        submission_error(format!(
            "RFC 3161 HTTP submission could not execute: {error}"
        ))
    })?;
    let started = Instant::now();
    let stdout = child.stdout.take().expect("piped submission stdout");
    let mut stderr = child.stderr.take().expect("piped submission stderr");

    thread::scope(|scope| {
        let body_reader = scope.spawn(move || {
            let mut body = Vec::new();
            stdout.take(MAX_RESPONSE_BYTES + 1).read_to_end(&mut body)?;
            Ok::<_, std::io::Error>(body)
        });
        let diagnostic_reader = scope.spawn(move || {
            let mut diagnostic = Vec::new();
            let mut buffer = [0; 4096];
            loop {
                let count = match stderr.read(&mut buffer) {
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    result => result?,
                };
                if count == 0 {
                    return Ok::<_, std::io::Error>(diagnostic);
                }
                let retained = count.min(MAX_DIAGNOSTIC_BYTES - diagnostic.len());
                diagnostic.extend_from_slice(&buffer[..retained]);
            }
        });
        let mut body_reader = Some(body_reader);
        let mut body = None;
        let result = (|| {
            loop {
                if body_reader
                    .as_ref()
                    .is_some_and(|reader| reader.is_finished())
                {
                    let bytes = body_reader
                        .take()
                        .unwrap()
                        .join()
                        .map_err(|_| submission_error("TSA response reader panicked".into()))?
                        .map_err(|error| {
                            submission_error(format!("TSA response read failed: {error}"))
                        })?;
                    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
                        return Err(submission_error(format!(
                            "TSA response exceeds maximum of {MAX_RESPONSE_BYTES} bytes"
                        )));
                    }
                    body = Some(bytes);
                }
                // Even when curl has exited, drain and check stdout before
                // accepting its status: buffered overflow or truncation matters.
                let status = child
                    .try_wait()
                    .map_err(|error| submission_error(error.to_string()))?;
                if let Some(status) = status
                    && body.is_some()
                    && diagnostic_reader.is_finished()
                {
                    return Ok(status);
                }
                if started.elapsed() >= timeout {
                    return Err(submission_error(format!(
                        "RFC 3161 HTTP submission exceeded the {} second process timeout",
                        timeout.as_secs()
                    )));
                }
                thread::sleep(Duration::from_millis(10));
            }
        })();
        if result.is_err() {
            let _ = child.kill();
        }
        // Always reap before joining readers or releasing the staged-file guard.
        let reaped = child.wait();
        if let Some(reader) = body_reader {
            let _ = reader.join();
        }
        let diagnostic = diagnostic_reader.join();
        let status = result?;
        reaped.map_err(|error| submission_error(error.to_string()))?;
        let stderr = diagnostic
            .map_err(|_| submission_error("TSA diagnostic reader panicked".into()))?
            .map_err(|error| submission_error(format!("TSA diagnostic read failed: {error}")))?;
        Ok(Output {
            status,
            stdout: body.unwrap(),
            stderr,
        })
    })
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
            format!("#!/bin/sh\nexec cat '{}'\n", source.display()),
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
            Duration::ZERO,
        )
        .unwrap()
        .with_binaries(PathBuf::from("openssl"), curl)
    }

    #[derive(Clone, Copy, Debug)]
    enum Framing {
        Declared,
        Chunked,
        CloseDelimited,
    }

    // Read the entire request, then either finish a response or wait for the
    // client to abort it. Socket deadlines keep fixture failures bounded.
    fn http_response(
        framing: Framing,
        size: usize,
        complete: bool,
        await_abort: bool,
    ) -> (String, thread::JoinHandle<bool>) {
        observed_http_response(framing, size, complete, await_abort, None)
    }

    fn observed_http_response(
        framing: Framing,
        size: usize,
        complete: bool,
        await_abort: bool,
        staging_directory: Option<PathBuf>,
    ) -> (String, thread::JoinHandle<bool>) {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "client never connected");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let length = String::from_utf8_lossy(&request)
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            stream.read_exact(&mut vec![0; length]).unwrap();
            let headers = match framing {
                Framing::Declared => format!(
                    "Content-Length: {}\r\n",
                    if await_abort {
                        size + 64 * 1024 * 1024
                    } else {
                        size + usize::from(!complete)
                    }
                ),
                Framing::Chunked => "Transfer-Encoding: chunked\r\n".into(),
                Framing::CloseDelimited => String::new(),
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nConnection: close\r\n{headers}\r\n"
            )
            .unwrap();
            if matches!(framing, Framing::Chunked) && size > 0 {
                write!(stream, "{size:x}\r\n").unwrap();
            }
            stream.write_all(&vec![b'x'; size]).unwrap();
            if matches!(framing, Framing::Chunked) && size > 0 {
                stream.write_all(b"\r\n").unwrap();
            }
            if let Some(directory) = staging_directory {
                // Observe disk usage while the transfer is still unfinished.
                for entry in fs::read_dir(directory).unwrap() {
                    let entry = entry.unwrap();
                    if entry.file_name().to_string_lossy().ends_with(".pending") {
                        match entry.metadata() {
                            Ok(metadata) => assert_eq!(metadata.len(), 0),
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                            Err(error) => panic!("staging metadata failed: {error}"),
                        }
                    }
                }
            }
            if await_abort {
                // Leave the response unfinished. Overflow must disconnect
                // before either the server's deadline or curl's max-time.
                match stream.read(&mut byte) {
                    Ok(0) => true,
                    Err(error) => matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                    ),
                    _ => false,
                }
            } else {
                if complete && matches!(framing, Framing::Chunked) {
                    stream.write_all(b"0\r\n\r\n").unwrap();
                }
                true
            }
        });
        (url, server)
    }

    fn download(url: &str, timeout: Duration) -> Result<Vec<u8>, ProducerError> {
        let mut command = Command::new("curl");
        command.args([
            "--disable",
            "-fsS",
            "--no-buffer",
            "--noproxy",
            "*",
            "--max-time",
            "15",
            url,
        ]);
        let output = run_submission(command, timeout)?;
        require_success("RFC 3161 HTTP submission", &output)?;
        Ok(output.stdout)
    }

    #[test]
    fn complete_transfers_enforce_the_inclusive_boundary() {
        for framing in [Framing::Declared, Framing::Chunked, Framing::CloseDelimited] {
            for size in [
                MAX_RESPONSE_BYTES as usize - 1,
                MAX_RESPONSE_BYTES as usize,
                MAX_RESPONSE_BYTES as usize + 1,
            ] {
                let (url, server) = http_response(framing, size, true, false);
                let result = download(&url, Duration::from_secs(3));
                assert!(server.join().unwrap());
                if size as u64 <= MAX_RESPONSE_BYTES {
                    assert_eq!(result.unwrap().len(), size, "{framing:?}");
                } else {
                    assert!(
                        matches!(result, Err(ProducerError::TimestampSubmission(_))),
                        "{framing:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn truncated_transfers_fail_immediately_around_the_boundary() {
        for framing in [Framing::Declared, Framing::Chunked] {
            for size in [
                MAX_RESPONSE_BYTES as usize - 1,
                MAX_RESPONSE_BYTES as usize,
                MAX_RESPONSE_BYTES as usize + 1,
            ] {
                let (url, server) = http_response(framing, size, false, false);
                let result = download(&url, Duration::from_secs(3));
                assert!(server.join().unwrap());
                assert!(
                    matches!(result, Err(ProducerError::TimestampSubmission(_))),
                    "{framing:?}, {size}"
                );
            }
        }
    }

    #[test]
    fn overflow_aborts_unfinished_transfers_without_writing_to_staging() {
        for framing in [Framing::Declared, Framing::Chunked, Framing::CloseDelimited] {
            for existing in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let response = root.path().join("response.tsr");
                if existing {
                    fs::write(&response, b"existing response").unwrap();
                }
                let (url, server) = observed_http_response(
                    framing,
                    MAX_RESPONSE_BYTES as usize + 1,
                    false,
                    true,
                    Some(root.path().to_path_buf()),
                );
                let mut authority = fixture_authority(PathBuf::from("curl"));
                authority.url = url;
                let started = Instant::now();
                let error = authority
                    .stamp_paths(b"artifact", &root.path().join("query.tsq"), &response)
                    .unwrap_err();
                assert!(matches!(error, ProducerError::TimestampSubmission(_)));
                assert!(error.to_string().contains("maximum"));
                assert!(started.elapsed() < Duration::from_secs(3));
                assert!(server.join().unwrap(), "client did not abort {framing:?}");
                assert_eq!(response.exists(), existing);
                if existing {
                    assert_eq!(fs::read(&response).unwrap(), b"existing response");
                }
                assert_no_pending(root.path());
            }
        }
    }

    fn assert_no_pending(root: &Path) {
        assert!(fs::read_dir(root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".pending")
        }));
    }

    #[test]
    fn stalled_and_interrupted_transfers_clean_up_without_publication() {
        for (size, stall) in [(17, false), (17, true), (MAX_RESPONSE_BYTES as usize, true)] {
            let root = tempfile::tempdir().unwrap();
            let response = root.path().join("response.tsr");
            let (url, server) = observed_http_response(
                Framing::Declared,
                size,
                false,
                stall,
                Some(root.path().to_path_buf()),
            );
            let mut authority = fixture_authority(PathBuf::from("curl"));
            authority.url = url;
            authority.timeout = Duration::from_millis(200);
            let started = Instant::now();
            let error = authority
                .stamp_paths(b"artifact", &root.path().join("query.tsq"), &response)
                .unwrap_err();
            assert!(matches!(error, ProducerError::TimestampSubmission(_)));
            if stall {
                assert!(error.to_string().contains("process timeout"));
            }
            assert!(started.elapsed() < Duration::from_secs(3));
            assert!(server.join().unwrap());
            assert!(!response.exists());
            assert_no_pending(root.path());
        }
    }

    #[test]
    fn public_stamp_removes_query_and_response_files_after_transfer_failures() {
        for (size, stall) in [
            (17, false),
            (17, true),
            (MAX_RESPONSE_BYTES as usize + 1, true),
        ] {
            let root = tempfile::tempdir().unwrap();
            let query_log = root.path().join("query-path");
            let openssl = root.path().join("openssl");
            // Record the allocated query path without changing query generation.
            fs::write(&openssl, format!(
                "#!/bin/sh\nfor arg do output=\"$arg\"; done\nprintf '%s' \"$output\" > '{}'\nexec openssl \"$@\"\n",
                query_log.display(),
            )).unwrap();
            fs::set_permissions(&openssl, fs::Permissions::from_mode(0o755)).unwrap();
            let (url, server) = http_response(Framing::Declared, size, false, stall);
            let mut authority = fixture_authority(PathBuf::from("curl"))
                .with_binaries(openssl, PathBuf::from("curl"));
            authority.url = url;
            authority.timeout = Duration::from_millis(200);
            assert!(matches!(
                authority.stamp(b"artifact"),
                Err(ProducerError::TimestampSubmission(_))
            ));
            assert!(server.join().unwrap());
            let query = PathBuf::from(fs::read_to_string(query_log).unwrap());
            let response = query.with_extension("tsr");
            assert!(!query.exists());
            assert!(!response.exists());
            let staging_prefix = format!(".{}.", response.file_name().unwrap().to_str().unwrap());
            assert!(
                fs::read_dir(response.parent().unwrap())
                    .unwrap()
                    .all(|entry| {
                        !entry
                            .unwrap()
                            .file_name()
                            .to_string_lossy()
                            .starts_with(&staging_prefix)
                    })
            );
        }
    }

    #[test]
    fn ambient_curl_output_configuration_cannot_bypass_the_response_limit() {
        let root = tempfile::tempdir().unwrap();
        let redirected = root.path().join("unbounded-output");
        fs::write(
            root.path().join(".curlrc"),
            format!("output = \"{}\"\n", redirected.display(),),
        )
        .unwrap();

        // Prove this curl reads the isolated config when --disable is absent.
        let (url, server) = http_response(Framing::Declared, 17, true, false);
        let mut command = Command::new("curl");
        command.env("CURL_HOME", root.path()).args([
            "-fsS",
            "--noproxy",
            "*",
            "--max-time",
            "3",
            &url,
        ]);
        let output = run_submission(command, Duration::from_secs(3)).unwrap();
        require_success("curl config control", &output).unwrap();
        assert!(server.join().unwrap());
        assert!(output.stdout.is_empty());
        assert_eq!(fs::read(&redirected).unwrap(), vec![b'x'; 17]);
        fs::remove_file(&redirected).unwrap();

        // Set CURL_HOME only in the child, keeping parallel tests independent.
        let curl = root.path().join("curl");
        fs::write(&curl, format!(
            "#!/bin/sh\n[ \"$1\" = --disable ] || exit 90\nexport CURL_HOME='{}'\nexec curl \"$@\"\n",
            root.path().display(),
        )).unwrap();
        fs::set_permissions(&curl, fs::Permissions::from_mode(0o755)).unwrap();
        for framing in [Framing::Declared, Framing::Chunked] {
            let (url, server) =
                http_response(framing, MAX_RESPONSE_BYTES as usize + 1, true, false);
            let mut authority = fixture_authority(curl.clone());
            authority.url = url;
            let response = root.path().join("response.tsr");
            let error = authority
                .stamp_paths(b"artifact", &root.path().join("query.tsq"), &response)
                .unwrap_err();
            assert!(server.join().unwrap());
            assert!(matches!(error, ProducerError::TimestampSubmission(_)));
            assert!(error.to_string().contains("maximum"));
            assert!(!redirected.exists());
            assert!(!response.exists());
            assert_no_pending(root.path());
        }
    }

    #[test]
    fn diagnostic_output_is_drained_but_retention_is_bounded() {
        let mut command = Command::new("sh");
        command.args(["-c", "head -c 65536 /dev/zero >&2; printf body"]);
        let output = run_submission(command, Duration::from_secs(3)).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"body");
        assert_eq!(output.stderr.len(), 8192);
    }

    #[test]
    fn authority_passes_future_skew_to_verification_policy() {
        let fixtures = fixture_root();
        let authority = Rfc3161TimestampAuthority::new(
            "https://tsa.invalid",
            fixtures.join("tsa-root.pem"),
            None,
            fixtures.join("tsa-crls.pem"),
            "1.3.6.1.4.1.55555.1",
            FIXTURE_SIGNER.parse().unwrap(),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(
            authority.verification_policy.max_future_skew(),
            Duration::from_secs(5)
        );
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
            Duration::ZERO,
        )
        .unwrap_err();
        assert!(matches!(error, ProducerError::TimestampConfiguration(_)));
    }
}
