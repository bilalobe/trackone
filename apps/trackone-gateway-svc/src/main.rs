use std::env;
use std::net::SocketAddr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use postgres::{Client, NoTls};
use trackone_gateway_svc::postgres::PostgresLedgerStore;
use trackone_gateway_svc::producer::{ElapsedClock, ProducerError, V2LedgerProducer};
use trackone_gateway_svc::service::{GatewayHttpState, drain_pending_tsa_segments, router};
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = required("TRACKONE_DATABASE_URL")?;
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

    let client = Client::connect(&database_url, NoTls)?;
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
        router(GatewayHttpState::new(producer, timestamp_authority)),
    )
    .await?;
    Ok(())
}
