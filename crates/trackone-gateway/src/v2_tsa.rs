//! OpenSSL-backed RFC 3161 submission and validation.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use trackone_ledger::sha256_hex;

use crate::v2_producer::ProducerError;

#[derive(Clone, Debug)]
pub struct Rfc3161TimestampAuthority {
    pub url: String,
    pub ca_file: PathBuf,
    pub policy_oid: String,
    pub openssl_binary: PathBuf,
    pub curl_binary: PathBuf,
    pub timeout: Duration,
}

impl Rfc3161TimestampAuthority {
    pub fn new(url: impl Into<String>, ca_file: PathBuf, policy_oid: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ca_file,
            policy_oid: policy_oid.into(),
            openssl_binary: PathBuf::from("openssl"),
            curl_binary: PathBuf::from("curl"),
            timeout: Duration::from_secs(15),
        }
    }

    pub fn stamp(&self, artifact: &[u8]) -> Result<Vec<u8>, ProducerError> {
        let digest = sha256_hex(artifact);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProducerError::Clock("system time precedes Unix epoch".to_string()))?
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("trackone-tsa-{}-{nonce}", std::process::id()));
        let query = base.with_extension("tsq");
        let response = base.with_extension("tsr");
        let result = self.stamp_paths(&digest, &query, &response);
        let _ = fs::remove_file(&query);
        let _ = fs::remove_file(&response);
        result
    }

    fn stamp_paths(
        &self,
        digest: &str,
        query: &std::path::Path,
        response: &std::path::Path,
    ) -> Result<Vec<u8>, ProducerError> {
        let query_status = Command::new(&self.openssl_binary)
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
            .arg(query)
            .output()
            .map_err(command_error("OpenSSL timestamp query"))?;
        require_success("OpenSSL timestamp query", &query_status)?;

        let timeout = self.timeout.as_secs().max(1).to_string();
        let upload = format!("@{}", query.display());
        let curl_status = Command::new(&self.curl_binary)
            .args(["-fsS", "--max-time", &timeout])
            .args(["-H", "Content-Type: application/timestamp-query"])
            .args(["-H", "Accept: application/timestamp-reply"])
            .args(["--data-binary", &upload])
            .arg(&self.url)
            .arg("-o")
            .arg(response)
            .output()
            .map_err(command_error("RFC 3161 HTTP submission"))?;
        require_success("RFC 3161 HTTP submission", &curl_status)?;

        let verification = Command::new(&self.openssl_binary)
            .args(["ts", "-verify", "-in"])
            .arg(response)
            .args(["-queryfile"])
            .arg(query)
            .arg("-CAfile")
            .arg(&self.ca_file)
            .output()
            .map_err(command_error("OpenSSL timestamp verification"))?;
        require_success("OpenSSL timestamp verification", &verification)?;
        fs::read(response).map_err(|error| ProducerError::Store(error.to_string()))
    }
}

fn command_error(label: &'static str) -> impl FnOnce(std::io::Error) -> ProducerError {
    move |error| ProducerError::Store(format!("{label} could not execute: {error}"))
}

fn require_success(label: &str, output: &std::process::Output) -> Result<(), ProducerError> {
    if output.status.success() {
        return Ok(());
    }
    Err(ProducerError::Store(format!(
        "{label} failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn submission_returns_the_verified_response_bytes() {
        let root = std::env::temp_dir().join(format!("trackone-tsa-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let openssl = root.join("openssl");
        let curl = root.join("curl");
        fs::write(
            &openssl,
            "#!/bin/sh\nif [ \"$2\" = \"-query\" ]; then while [ $# -gt 0 ]; do if [ \"$1\" = \"-out\" ]; then shift; printf query > \"$1\"; exit 0; fi; shift; done; fi\nexit 0\n",
        )
        .unwrap();
        fs::write(
            &curl,
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf response > \"$1\"; exit 0; fi; shift; done\nexit 1\n",
        )
        .unwrap();
        fs::set_permissions(&openssl, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&curl, fs::Permissions::from_mode(0o755)).unwrap();
        let mut authority = Rfc3161TimestampAuthority::new(
            "https://tsa.invalid",
            root.join("ca.pem"),
            "1.3.6.1.4.1.55555.1",
        );
        authority.openssl_binary = openssl;
        authority.curl_binary = curl;
        assert_eq!(authority.stamp(b"artifact").unwrap(), b"response");
        fs::remove_dir_all(root).unwrap();
    }
}
