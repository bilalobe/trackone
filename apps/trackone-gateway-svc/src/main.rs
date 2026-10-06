use std::env;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use std::sync::Arc;
use trackone_gateway_svc::postgres::PostgresLedgerStore;
use trackone_gateway_svc::postgres_connection::{PostgresTlsMode, connect_postgres};
use trackone_gateway_svc::producer::{ElapsedClock, LedgerProducer, ProducerError};
use trackone_gateway_svc::service::{AdmissionAuth, GatewayHttpState, router};
use trackone_gateway_svc::service::{
    DEFAULT_MAX_ADMISSION_BYTES, DEFAULT_MAX_BATCH_RECORDS, HARD_MAX_ADMISSION_BYTES,
    HARD_MAX_BATCH_RECORDS,
};
use trackone_gateway_svc::timestamp_worker::{TimestampWorkerConfig, TimestampWorkers};
use trackone_gateway_svc::tsa::Rfc3161TimestampAuthority;
use trackone_ledger::vtl::{ClosurePolicy, EmptyMode};
use trackone_rfc3161::SignerCertificateSha256;

struct SystemElapsedClock {
    origin: Instant,
    continuity_id: u128,
}

impl SystemElapsedClock {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        Ok(Self {
            origin: Instant::now(),
            continuity_id: epoch ^ u128::from(std::process::id()),
        })
    }
}

impl ElapsedClock for SystemElapsedClock {
    fn now_ms(&self) -> Result<u64, ProducerError> {
        u64::try_from(self.origin.elapsed().as_millis())
            .map_err(|_| ProducerError::Clock("elapsed milliseconds exceed uint64".to_string()))
    }

    fn continuity_id(&self) -> u128 {
        self.continuity_id
    }
}

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name).map_err(|_| format!("required environment variable {name} is missing").into())
}

fn optional_u64(name: &str) -> Result<Option<u64>, Box<dyn std::error::Error>> {
    env::var(name)
        .ok()
        .map(|value| value.parse().map_err(Into::into))
        .transpose()
}

const MAX_TSA_FUTURE_SKEW_SECONDS: u64 = 3_600;

fn parse_tsa_max_future_skew(value: &str) -> Result<Duration, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(
            "TRACKONE_TSA_MAX_FUTURE_SKEW_SECONDS must be a non-negative integer".to_string(),
        );
    }
    let seconds = value.parse::<u64>().map_err(|_| {
        "TRACKONE_TSA_MAX_FUTURE_SKEW_SECONDS must be a non-negative integer".to_string()
    })?;
    if seconds > MAX_TSA_FUTURE_SKEW_SECONDS {
        return Err(format!(
            "TRACKONE_TSA_MAX_FUTURE_SKEW_SECONDS must not exceed {MAX_TSA_FUTURE_SKEW_SECONDS}"
        ));
    }
    Ok(Duration::from_secs(seconds))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = required("TRACKONE_DATABASE_URL")?;
    let postgres_tls_mode = PostgresTlsMode::parse(
        &env::var("TRACKONE_POSTGRES_TLS_MODE").unwrap_or_else(|_| "verify-full".to_string()),
    )?;
    let postgres_ca_file = env::var("TRACKONE_POSTGRES_CA_FILE")
        .ok()
        .filter(|value| !value.is_empty());
    let bearer_token = required("TRACKONE_INGEST_BEARER_TOKEN")?;
    let previous_bearer_token = env::var("TRACKONE_INGEST_BEARER_TOKEN_PREVIOUS")
        .ok()
        .filter(|value| !value.is_empty());
    let admission_auth = AdmissionAuth::new(&bearer_token, previous_bearer_token.as_deref())?;
    let ledger_id = required("TRACKONE_LEDGER_ID")?;
    let site_id = required("TRACKONE_SITE_ID")?;
    let tsa_url = required("TRACKONE_TSA_URL")?;
    let tsa_ca_file = required("TRACKONE_TSA_CA_FILE")?.into();
    let tsa_intermediates_file = env::var("TRACKONE_TSA_INTERMEDIATES_FILE")
        .ok()
        .filter(|value| !value.is_empty())
        .map(Into::into);
    let tsa_crls_file = required("TRACKONE_TSA_CRLS_FILE")?.into();
    let tsa_policy_oid = required("TRACKONE_TSA_POLICY_OID")?;
    let tsa_signer_certificate_sha256: SignerCertificateSha256 =
        required("TRACKONE_TSA_SIGNER_CERT_SHA256")?.parse()?;
    let tsa_max_future_skew = match env::var("TRACKONE_TSA_MAX_FUTURE_SKEW_SECONDS") {
        Ok(value) => parse_tsa_max_future_skew(&value)?,
        Err(env::VarError::NotPresent) => Duration::ZERO,
        Err(env::VarError::NotUnicode(_)) => {
            return Err("TRACKONE_TSA_MAX_FUTURE_SKEW_SECONDS must be UTF-8".into());
        }
    };
    let bind: SocketAddr = env::var("TRACKONE_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()?;
    let empty_mode = match env::var("TRACKONE_EMPTY_MODE")
        .unwrap_or_else(|_| "suppress".to_string())
        .as_str()
    {
        "emit" => EmptyMode::Emit,
        "suppress" => EmptyMode::Suppress,
        _ => return Err("TRACKONE_EMPTY_MODE must be emit or suppress".into()),
    };
    let policy = ClosurePolicy {
        interval_ms: env::var("TRACKONE_INTERVAL_MS")
            .unwrap_or_else(|_| "60000".to_string())
            .parse()?,
        batch_record_limit: env::var("TRACKONE_BATCH_RECORD_LIMIT")
            .unwrap_or_else(|_| "1024".to_string())
            .parse()?,
        record_limit: optional_u64("TRACKONE_RECORD_LIMIT")?,
        size_limit_bytes: optional_u64("TRACKONE_SIZE_LIMIT_BYTES")?,
        empty_mode,
    };
    let max_batch_records = env::var("TRACKONE_MAX_BATCH_RECORDS")
        .unwrap_or_else(|_| DEFAULT_MAX_BATCH_RECORDS.to_string())
        .parse::<usize>()?;
    let max_admission_bytes = env::var("TRACKONE_MAX_ADMISSION_BYTES")
        .unwrap_or_else(|_| DEFAULT_MAX_ADMISSION_BYTES.to_string())
        .parse::<usize>()?;
    if max_batch_records == 0 || max_batch_records > HARD_MAX_BATCH_RECORDS {
        return Err("TRACKONE_MAX_BATCH_RECORDS must be between 1 and 10000".into());
    }
    if max_admission_bytes == 0 || max_admission_bytes > HARD_MAX_ADMISSION_BYTES {
        return Err("TRACKONE_MAX_ADMISSION_BYTES must be between 1 and 16777216".into());
    }

    let worker_config = TimestampWorkerConfig {
        concurrency: optional_u64("TRACKONE_TSA_WORKER_CONCURRENCY")?
            .unwrap_or(2)
            .try_into()?,
        max_attempts: optional_u64("TRACKONE_TSA_MAX_ATTEMPTS")?
            .unwrap_or(20)
            .try_into()?,
        retry_initial_ms: optional_u64("TRACKONE_TSA_RETRY_INITIAL_MS")?.unwrap_or(5_000),
        retry_max_ms: optional_u64("TRACKONE_TSA_RETRY_MAX_MS")?.unwrap_or(300_000),
    };
    worker_config.validate()?;

    let client = connect_postgres(
        &database_url,
        postgres_tls_mode,
        postgres_ca_file.as_deref(),
    )?;
    let mut store = PostgresLedgerStore::new(client, &ledger_id);
    store.migrate()?;
    let timestamp_authority = Rfc3161TimestampAuthority::new(
        tsa_url,
        tsa_ca_file,
        tsa_intermediates_file,
        tsa_crls_file,
        tsa_policy_oid,
        tsa_signer_certificate_sha256,
        tsa_max_future_skew,
    )?;
    let clock = SystemElapsedClock::new()?;
    let continuity_id = clock.continuity_id();
    let mut producer =
        LedgerProducer::open_or_create(store, clock, ledger_id.clone(), site_id, policy)?;
    if producer.state().open.clock_continuity_id != continuity_id {
        producer.recover()?;
    }

    // Keep the final synchronous PostgreSQL client owner outside the Tokio
    // runtime: its destructor closes the connection with its own block_on.
    let app = router(GatewayHttpState::new(
        producer,
        admission_auth,
        max_batch_records,
        max_admission_bytes,
    ));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(bind).await?;
        let workers = Arc::new(TimestampWorkers::start(
            worker_config,
            Arc::new(timestamp_authority),
            move || {
                connect_postgres(
                    &database_url,
                    postgres_tls_mode,
                    postgres_ca_file.as_deref(),
                )
                .map(|client| PostgresLedgerStore::new(client, &ledger_id))
                .map_err(|error| ProducerError::Store(error.to_string()))
            },
        )?);
        let shutdown_workers = Arc::clone(&workers);
        let result = axum::serve(listener, app.clone())
            .with_graceful_shutdown(async move {
                shutdown_signal().await;
                shutdown_workers.stop_claiming();
            })
            .await;
        drop(workers);
        result?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

async fn shutdown_signal() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => (),
        _ = terminate.recv() => (),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tsa_future_skew_configuration_has_bounded_integer_seconds() {
        assert_eq!(parse_tsa_max_future_skew("0").unwrap(), Duration::ZERO);
        assert_eq!(
            parse_tsa_max_future_skew("3600").unwrap(),
            Duration::from_secs(3600)
        );
        for invalid in ["", "-1", "+1", "1.5", "NaN", "3601", "18446744073709551616"] {
            assert!(parse_tsa_max_future_skew(invalid).is_err(), "{invalid}");
        }
    }
}
