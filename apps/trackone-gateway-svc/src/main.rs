use std::env;
use std::fs;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use native_tls::{Certificate, TlsConnector};
use postgres::config::SslMode;
use postgres::{Client, Config, NoTls};
use postgres_native_tls::MakeTlsConnector;
use trackone_gateway_svc::postgres::PostgresLedgerStore;
use trackone_gateway_svc::producer::{ElapsedClock, ProducerError, V2LedgerProducer};
use trackone_gateway_svc::service::{
    AdmissionAuth, GatewayHttpState, drain_pending_tsa_segments, router,
};
use trackone_gateway_svc::service::{
    DEFAULT_MAX_ADMISSION_BYTES, DEFAULT_MAX_BATCH_RECORDS, HARD_MAX_ADMISSION_BYTES,
    HARD_MAX_BATCH_RECORDS,
};
use trackone_gateway_svc::tsa::Rfc3161TimestampAuthority;
use trackone_ledger::v2::{ClosurePolicyV1, EmptyMode};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PostgresTlsMode {
    VerifyFull,
    Disable,
}

impl PostgresTlsMode {
    fn parse(raw: &str) -> Result<Self, Box<dyn std::error::Error>> {
        match raw {
            "verify-full" => Ok(Self::VerifyFull),
            "disable" => Ok(Self::Disable),
            _ => Err(
                "TRACKONE_POSTGRES_TLS_MODE must be verify-full or disable (development only)"
                    .into(),
            ),
        }
    }
}

fn connect_postgres(
    database_url: &str,
    mode: PostgresTlsMode,
    ca_file: Option<&str>,
) -> Result<Client, Box<dyn std::error::Error>> {
    let mut config = Config::from_str(database_url)?;
    match mode {
        PostgresTlsMode::VerifyFull => {
            config.ssl_mode(SslMode::Require);
            let mut builder = TlsConnector::builder();
            if let Some(path) = ca_file {
                builder.add_root_certificate(Certificate::from_pem(&fs::read(path)?)?);
            }
            Ok(config.connect(MakeTlsConnector::new(builder.build()?))?)
        }
        PostgresTlsMode::Disable => {
            config.ssl_mode(SslMode::Disable);
            Ok(config.connect(NoTls)?)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    let policy = ClosurePolicyV1 {
        interval_ms: env::var("TRACKONE_INTERVAL_MS")
            .unwrap_or_else(|_| "60000".to_string())
            .parse()?,
        batch_record_limit: env::var("TRACKONE_BATCH_RECORD_LIMIT")
            .unwrap_or_else(|_| "1000".to_string())
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
    )?;
    let clock = SystemElapsedClock::new()?;
    let continuity_id = clock.continuity_id();
    let mut producer = V2LedgerProducer::open_or_create(store, clock, ledger_id, site_id, policy)?;
    if producer.state().open.clock_continuity_id != continuity_id {
        producer.recover()?;
    }
    drain_pending_tsa_segments(&mut producer, &timestamp_authority)?;

    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(
        listener,
        router(GatewayHttpState::new(
            producer,
            timestamp_authority,
            admission_auth,
            max_batch_records,
            max_admission_bytes,
        )),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::PostgresTlsMode;

    #[test]
    fn postgres_tls_mode_accepts_only_explicit_supported_values() {
        assert_eq!(
            PostgresTlsMode::parse("verify-full").unwrap(),
            PostgresTlsMode::VerifyFull
        );
        assert_eq!(
            PostgresTlsMode::parse("disable").unwrap(),
            PostgresTlsMode::Disable
        );
        assert!(PostgresTlsMode::parse("prefer").is_err());
    }
}
