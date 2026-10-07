//! Typed command-line and environment configuration, shared with the exporter.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use clap::{Args, Parser, builder::NonEmptyStringValueParser};
use trackone_ledger::vtl::{ClosurePolicy, EmptyMode};
use trackone_rfc3161::SignerCertificateSha256;

use crate::{
    error::{ResultContext, RuntimeError},
    observability::CapacityLimits,
    postgres_connection::PostgresTlsMode,
    service::{
        AdmissionAuth, DEFAULT_MAX_ADMISSION_BYTES, DEFAULT_MAX_BATCH_RECORDS,
        HARD_MAX_ADMISSION_BYTES, HARD_MAX_BATCH_RECORDS,
    },
    timestamp_worker::TimestampWorkerConfig,
};

#[derive(Args)]
pub struct DatabaseConfig {
    /// PostgreSQL connection string
    #[arg(long = "db-url", alias = "database-url", env = "TRACKONE_DATABASE_URL", hide_env_values = true, value_parser = NonEmptyStringValueParser::new())]
    pub url: String,

    /// PostgreSQL transport: verify-full, or disable for development
    #[arg(long, env = "TRACKONE_POSTGRES_TLS_MODE", default_value = "verify-full", value_parser = parse_postgres_tls_mode)]
    pub postgres_tls_mode: PostgresTlsMode,

    /// Additional PostgreSQL root CA in PEM format
    #[arg(long, env = "TRACKONE_POSTGRES_CA_FILE")]
    pub postgres_ca_file: Option<String>,
}

impl DatabaseConfig {
    pub fn ca_file(&self) -> Option<&str> {
        self.postgres_ca_file
            .as_deref()
            .filter(|path| !path.is_empty())
    }
}

#[derive(Parser)]
#[command(
    name = "trackone-vtl-gateway",
    version,
    about = "HTTP and PostgreSQL gateway for VTL admission"
)]
pub struct GatewayConfig {
    #[command(flatten)]
    pub database: DatabaseConfig,

    /// Ingest bearer credential, 32-256 visible ASCII characters
    #[arg(long, env = "TRACKONE_INGEST_BEARER_TOKEN", hide_env_values = true)]
    pub ingest_bearer_token: String,

    /// Previous ingest credential accepted during rotation
    #[arg(
        long,
        env = "TRACKONE_INGEST_BEARER_TOKEN_PREVIOUS",
        hide_env_values = true
    )]
    pub ingest_bearer_token_previous: Option<String>,

    /// Ledger identifier, 32 lowercase hexadecimal characters
    #[arg(long, env = "TRACKONE_LEDGER_ID", value_parser = parse_ledger_id)]
    pub ledger_id: String,

    /// Site identifier
    #[arg(long, env = "TRACKONE_SITE_ID", value_parser = NonEmptyStringValueParser::new())]
    pub site_id: String,

    /// RFC 3161 timestamp authority URL
    #[arg(long, env = "TRACKONE_TSA_URL", value_parser = NonEmptyStringValueParser::new())]
    pub tsa_url: String,

    /// Deployment TSA trust anchors in PEM format
    #[arg(long, env = "TRACKONE_TSA_CA_FILE", value_parser = parse_nonempty_path)]
    pub tsa_ca_file: PathBuf,

    /// Deployment TSA intermediate certificates in PEM format
    #[arg(long, env = "TRACKONE_TSA_INTERMEDIATES_FILE")]
    pub tsa_intermediates_file: Option<PathBuf>,

    /// Retained complete TSA base CRLs in PEM format
    #[arg(long, env = "TRACKONE_TSA_CRLS_FILE", value_parser = parse_nonempty_path)]
    pub tsa_crls_file: PathBuf,

    /// Expected TSA policy OID
    #[arg(long, env = "TRACKONE_TSA_POLICY_OID", value_parser = NonEmptyStringValueParser::new())]
    pub tsa_policy_oid: String,

    /// SHA-256 of the complete DER TSA signer certificate
    #[arg(long, env = "TRACKONE_TSA_SIGNER_CERT_SHA256")]
    pub tsa_signer_cert_sha256: SignerCertificateSha256,

    /// Maximum permitted lead of TSA genTime, in seconds (0-3600)
    #[arg(long, env = "TRACKONE_TSA_MAX_FUTURE_SKEW_SECONDS", default_value = "0", allow_negative_numbers = true, value_parser = parse_tsa_max_future_skew)]
    pub tsa_max_future_skew_seconds: Duration,

    /// HTTP listen address
    #[arg(long, env = "TRACKONE_BIND", default_value = "0.0.0.0:8080")]
    pub bind: SocketAddr,

    /// Empty segment policy: suppress or emit
    #[arg(long, env = "TRACKONE_EMPTY_MODE", default_value = "suppress", value_parser = parse_empty_mode)]
    pub empty_mode: EmptyMode,

    /// Segment interval in milliseconds
    #[arg(long, env = "TRACKONE_INTERVAL_MS", default_value = "60000", value_parser = clap::value_parser!(u64).range(1..))]
    pub interval_ms: u64,

    /// Maximum records per segment batch
    #[arg(long, env = "TRACKONE_BATCH_RECORD_LIMIT", default_value = "1024", value_parser = parse_batch_record_limit)]
    pub batch_record_limit: u64,

    /// Optional segment record limit
    #[arg(long, env = "TRACKONE_RECORD_LIMIT", value_parser = clap::value_parser!(u64).range(1..))]
    pub record_limit: Option<u64>,

    /// Optional segment byte limit
    #[arg(long, env = "TRACKONE_SIZE_LIMIT_BYTES", value_parser = clap::value_parser!(u64).range(1..))]
    pub size_limit_bytes: Option<u64>,

    /// Maximum records accepted in one HTTP batch (1-10000)
    #[arg(long, env = "TRACKONE_MAX_BATCH_RECORDS", default_value_t = DEFAULT_MAX_BATCH_RECORDS, value_parser = parse_max_batch_records)]
    pub max_batch_records: usize,

    /// Maximum expanded HTTP admission body size (1-16777216 bytes)
    #[arg(long, env = "TRACKONE_MAX_ADMISSION_BYTES", default_value_t = DEFAULT_MAX_ADMISSION_BYTES, value_parser = parse_max_admission_bytes)]
    pub max_admission_bytes: usize,

    /// Maximum pending timestamp segments per ledger; omitted means unlimited
    #[arg(long, env = "TRACKONE_MAX_PENDING_TIMESTAMPS", value_parser = clap::value_parser!(u64).range(1..))]
    pub max_pending_timestamps: Option<u64>,

    /// Maximum retained evidence payload bytes per ledger; omitted means unlimited
    #[arg(long, env = "TRACKONE_MAX_RETAINED_EVIDENCE_BYTES", value_parser = clap::value_parser!(u64).range(1..))]
    pub max_retained_evidence_bytes: Option<u64>,

    /// Concurrent TSA workers (1-16)
    #[arg(long, env = "TRACKONE_TSA_WORKER_CONCURRENCY", default_value = "2", value_parser = parse_worker_concurrency)]
    pub tsa_worker_concurrency: usize,

    /// Maximum TSA submission attempts (1-1000)
    #[arg(long, env = "TRACKONE_TSA_MAX_ATTEMPTS", default_value = "20", value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub tsa_max_attempts: u32,

    /// Initial TSA retry delay in milliseconds (1-86400000)
    #[arg(long, env = "TRACKONE_TSA_RETRY_INITIAL_MS", default_value = "5000", value_parser = clap::value_parser!(u64).range(1..=86_400_000))]
    pub tsa_retry_initial_ms: u64,

    /// Maximum TSA retry delay in milliseconds (1-86400000)
    #[arg(long, env = "TRACKONE_TSA_RETRY_MAX_MS", default_value = "300000", value_parser = clap::value_parser!(u64).range(1..=86_400_000))]
    pub tsa_retry_max_ms: u64,

    /// JSON file containing scoped disclosure credentials
    #[arg(long, env = "TRACKONE_DISCLOSURE_GRANTS_FILE", value_parser = parse_nonempty_path)]
    pub disclosure_grants_file: Option<PathBuf>,
}

impl GatewayConfig {
    pub fn capacity_limits(&self) -> CapacityLimits {
        CapacityLimits {
            max_pending_timestamps: self.max_pending_timestamps,
            max_retained_evidence_bytes: self.max_retained_evidence_bytes,
        }
    }

    pub fn admission_auth(&self) -> Result<AdmissionAuth, RuntimeError> {
        AdmissionAuth::new(
            &self.ingest_bearer_token,
            self.ingest_bearer_token_previous
                .as_deref()
                .filter(|token| !token.is_empty()),
        )
        .context("invalid TRACKONE_INGEST_BEARER_TOKEN or TRACKONE_INGEST_BEARER_TOKEN_PREVIOUS")
    }

    pub fn worker_config(&self) -> Result<TimestampWorkerConfig, RuntimeError> {
        let config = TimestampWorkerConfig {
            concurrency: self.tsa_worker_concurrency,
            max_attempts: self.tsa_max_attempts,
            retry_initial_ms: self.tsa_retry_initial_ms,
            retry_max_ms: self.tsa_retry_max_ms,
        };
        config.validate().context("invalid TRACKONE_TSA_RETRY_INITIAL_MS / TRACKONE_TSA_RETRY_MAX_MS: initial delay must not exceed maximum delay")?;
        Ok(config)
    }

    pub fn closure_policy(&self) -> ClosurePolicy {
        ClosurePolicy {
            interval_ms: self.interval_ms,
            batch_record_limit: self.batch_record_limit,
            record_limit: self.record_limit,
            size_limit_bytes: self.size_limit_bytes,
            empty_mode: self.empty_mode,
        }
    }
}

fn parse_postgres_tls_mode(raw: &str) -> Result<PostgresTlsMode, String> {
    PostgresTlsMode::parse(raw).map_err(|error| error.to_string())
}

fn parse_nonempty_path(raw: &str) -> Result<PathBuf, String> {
    if raw.is_empty() {
        Err("file path must not be empty".into())
    } else {
        Ok(PathBuf::from(raw))
    }
}

pub fn parse_ledger_id(raw: &str) -> Result<String, String> {
    if raw.len() == 32
        && raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(raw.to_string())
    } else {
        Err("ledger ID must contain 32 lowercase hexadecimal characters".into())
    }
}

fn parse_empty_mode(raw: &str) -> Result<EmptyMode, String> {
    match raw {
        "emit" => Ok(EmptyMode::Emit),
        "suppress" => Ok(EmptyMode::Suppress),
        _ => Err("empty mode must be emit or suppress".into()),
    }
}

fn parse_batch_record_limit(raw: &str) -> Result<u64, String> {
    let limit = raw
        .parse::<u64>()
        .map_err(|_| "must be a positive integer")?;
    ClosurePolicy::validate_batch_record_limit(limit)
        .map_err(|_| "batch record limit must be a power of two no greater than 2^63")?;
    Ok(limit)
}

fn parse_tsa_max_future_skew(raw: &str) -> Result<Duration, String> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("TRACKONE_TSA_MAX_FUTURE_SKEW_SECONDS must be a non-negative integer".into());
    }
    let seconds = raw
        .parse::<u64>()
        .map_err(|_| "TRACKONE_TSA_MAX_FUTURE_SKEW_SECONDS must be a non-negative integer")?;
    if seconds > 3600 {
        return Err("TRACKONE_TSA_MAX_FUTURE_SKEW_SECONDS must not exceed 3600".into());
    }
    Ok(Duration::from_secs(seconds))
}

fn parse_bounded_usize(raw: &str, maximum: usize) -> Result<usize, String> {
    let value = raw
        .parse::<usize>()
        .map_err(|_| "must be a positive integer")?;
    if (1..=maximum).contains(&value) {
        Ok(value)
    } else {
        Err(format!("must be between 1 and {maximum}"))
    }
}

fn parse_max_batch_records(raw: &str) -> Result<usize, String> {
    parse_bounded_usize(raw, HARD_MAX_BATCH_RECORDS)
}
fn parse_max_admission_bytes(raw: &str) -> Result<usize, String> {
    parse_bounded_usize(raw, HARD_MAX_ADMISSION_BYTES)
}
fn parse_worker_concurrency(raw: &str) -> Result<usize, String> {
    parse_bounded_usize(raw, 16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, FromArgMatches, error::ErrorKind};

    fn parse(extra: &[&str]) -> Result<GatewayConfig, clap::Error> {
        let mut args = vec![
            "trackone-vtl-gateway",
            "--db-url",
            "postgresql://localhost/trackone",
            "--ingest-bearer-token",
            "test-ingest-token-0123456789abcdef",
            "--ledger-id",
            "0123456789abcdef0123456789abcdef",
            "--site-id",
            "test-site",
            "--tsa-url",
            "https://tsa.example.test",
            "--tsa-ca-file",
            "root.pem",
            "--tsa-crls-file",
            "crls.pem",
            "--tsa-policy-oid",
            "1.2.3.4",
            "--tsa-signer-cert-sha256",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ];
        args.extend_from_slice(extra);
        // Tests neither mutate nor depend on the parent process environment.
        let matches = GatewayConfig::command()
            .mut_args(|arg| arg.env(None::<&str>))
            .try_get_matches_from(args)?;
        GatewayConfig::from_arg_matches(&matches)
    }

    #[test]
    fn command_schema_is_consistent() {
        GatewayConfig::command().debug_assert();
    }

    #[test]
    fn defaults_preserve_existing_gateway_behavior() {
        let config = parse(&[]).unwrap();
        assert_eq!(config.bind, "0.0.0.0:8080".parse::<SocketAddr>().unwrap());
        assert_eq!(
            config.database.postgres_tls_mode,
            PostgresTlsMode::VerifyFull
        );
        assert_eq!(config.interval_ms, 60_000);
        assert_eq!(config.batch_record_limit, 1024);
        assert_eq!(config.empty_mode, EmptyMode::Suppress);
        assert_eq!(config.max_batch_records, DEFAULT_MAX_BATCH_RECORDS);
        assert_eq!(config.max_admission_bytes, DEFAULT_MAX_ADMISSION_BYTES);
        assert_eq!(config.tsa_max_future_skew_seconds, Duration::ZERO);
        assert!(config.capacity_limits().max_pending_timestamps.is_none());
        assert!(
            config
                .capacity_limits()
                .max_retained_evidence_bytes
                .is_none()
        );
        assert!(config.record_limit.is_none());
        assert!(config.size_limit_bytes.is_none());
        assert!(config.disclosure_grants_file.is_none());
        config.admission_auth().unwrap();
        let worker = config.worker_config().unwrap();
        assert_eq!(worker.concurrency, 2);
        assert_eq!(worker.max_attempts, 20);
        assert_eq!(worker.retry_initial_ms, 5000);
        assert_eq!(worker.retry_max_ms, 300_000);
    }

    #[test]
    fn rejects_invalid_values_at_the_configuration_boundary() {
        for (flag, invalid) in [
            ("--bind", "localhost:bad"),
            ("--postgres-tls-mode", "prefer"),
            ("--empty-mode", "other"),
            ("--interval-ms", "0"),
            ("--interval-ms", "not-a-number"),
            ("--interval-ms", "18446744073709551616"),
            ("--batch-record-limit", "0"),
            ("--batch-record-limit", "3"),
            ("--record-limit", "0"),
            ("--size-limit-bytes", "0"),
            ("--max-pending-timestamps", "0"),
            ("--max-pending-timestamps", "18446744073709551616"),
            ("--max-retained-evidence-bytes", "0"),
            ("--max-retained-evidence-bytes", "invalid"),
            ("--max-batch-records", "0"),
            ("--max-batch-records", "10001"),
            ("--max-admission-bytes", "0"),
            ("--max-admission-bytes", "16777217"),
            ("--tsa-worker-concurrency", "0"),
            ("--tsa-worker-concurrency", "17"),
            ("--tsa-max-attempts", "1001"),
            ("--tsa-retry-initial-ms", "0"),
            ("--tsa-retry-max-ms", "86400001"),
            ("--tsa-max-future-skew-seconds", "3601"),
            ("--tsa-max-future-skew-seconds", "-1"),
            ("--tsa-max-future-skew-seconds", "+1"),
            ("--tsa-max-future-skew-seconds", "1.5"),
            ("--tsa-max-future-skew-seconds", ""),
        ] {
            let error = parse(&[flag, invalid])
                .err()
                .expect("invalid configuration accepted");
            assert!(error.to_string().contains(flag), "{flag}: {error}");
        }
        assert_eq!(
            parse(&["--typo"]).err().unwrap().kind(),
            ErrorKind::UnknownArgument
        );
    }

    #[test]
    fn accepts_limits_and_preserves_optional_empty_settings() {
        let config = parse(&[
            "--max-pending-timestamps",
            "2",
            "--max-retained-evidence-bytes",
            "18446744073709551615",
            "--max-batch-records",
            "10000",
            "--max-admission-bytes",
            "16777216",
            "--batch-record-limit",
            "9223372036854775808",
            "--empty-mode",
            "emit",
            "--record-limit",
            "1",
            "--size-limit-bytes",
            "1",
            "--tsa-worker-concurrency",
            "16",
            "--tsa-max-attempts",
            "1000",
            "--tsa-max-future-skew-seconds",
            "3600",
            "--postgres-ca-file",
            "",
            "--ingest-bearer-token-previous",
            "",
        ])
        .unwrap();
        assert_eq!(config.max_pending_timestamps, Some(2));
        assert_eq!(config.max_retained_evidence_bytes, Some(u64::MAX));
        assert_eq!(config.closure_policy().record_limit, Some(1));
        assert_eq!(config.closure_policy().empty_mode, EmptyMode::Emit);
        assert_eq!(
            config.tsa_max_future_skew_seconds,
            Duration::from_secs(3600)
        );
        assert!(config.database.ca_file().is_none());
        config.admission_auth().unwrap();
        config.worker_config().unwrap();
    }

    #[test]
    fn rejects_inconsistent_retry_delays_and_invalid_tokens_without_exposing_them() {
        let mut config = parse(&["--tsa-retry-initial-ms", "300001"]).unwrap();
        let message = config.worker_config().unwrap_err().to_string();
        assert!(message.contains("TRACKONE_TSA_RETRY_INITIAL_MS"));
        assert!(message.contains("TRACKONE_TSA_RETRY_MAX_MS"));
        config.ingest_bearer_token = "short-secret".into();
        let message = config.admission_auth().err().unwrap().to_string();
        assert!(message.contains("TRACKONE_INGEST_BEARER_TOKEN"));
        assert!(!message.contains("short-secret"));
    }
}
