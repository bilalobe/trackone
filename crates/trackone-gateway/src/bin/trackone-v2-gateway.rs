use std::env;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use postgres::{Client, NoTls};
#[cfg(target_os = "linux")]
use rustix::time::{ClockId, Timespec, clock_gettime};
use trackone::v2_postgres::PostgresLedgerStore;
use trackone::v2_producer::{ElapsedClock, ProducerError, V2LedgerProducer};
use trackone::v2_service::{GatewayHttpState, router, submit_pending_timestamps};
use trackone::v2_tsa::Rfc3161TimestampAuthority;
use trackone_ledger::v2::{ClosurePolicyV1, EmptyMode};

struct SystemElapsedClock {
    continuity_id: u128,
}

impl SystemElapsedClock {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        Ok(Self {
            continuity_id: epoch ^ u128::from(std::process::id()),
        })
    }
}

impl ElapsedClock for SystemElapsedClock {
    fn now_ms(&self) -> Result<u64, ProducerError> {
        boottime_ms()
    }

    fn continuity_id(&self) -> u128 {
        self.continuity_id
    }
}

#[cfg(target_os = "linux")]
fn boottime_ms() -> Result<u64, ProducerError> {
    timespec_ms(clock_gettime(ClockId::Boottime))
}

#[cfg(target_os = "linux")]
fn timespec_ms(value: Timespec) -> Result<u64, ProducerError> {
    let seconds = u64::try_from(value.tv_sec).map_err(|_| {
        ProducerError::Clock("CLOCK_BOOTTIME returned negative seconds".to_string())
    })?;
    let nanoseconds = u64::try_from(value.tv_nsec).map_err(|_| {
        ProducerError::Clock("CLOCK_BOOTTIME returned negative nanoseconds".to_string())
    })?;
    if nanoseconds >= 1_000_000_000 {
        return Err(ProducerError::Clock(
            "CLOCK_BOOTTIME returned invalid nanoseconds".to_string(),
        ));
    }
    seconds
        .checked_mul(1_000)
        .and_then(|milliseconds| milliseconds.checked_add(nanoseconds / 1_000_000))
        .ok_or_else(|| {
            ProducerError::Clock("CLOCK_BOOTTIME exceeds uint64 milliseconds".to_string())
        })
}

#[cfg(not(target_os = "linux"))]
fn boottime_ms() -> Result<u64, ProducerError> {
    Err(ProducerError::Clock(
        "the v2 gateway requires Linux CLOCK_BOOTTIME".to_string(),
    ))
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
    let site_id = required("TRACKONE_SITE_ID")?;
    let tsa_url = required("TRACKONE_TSA_URL")?;
    let tsa_ca_file = required("TRACKONE_TSA_CA_FILE")?.into();
    let tsa_policy_oid = required("TRACKONE_TSA_POLICY_OID")?;
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
    let (store, ledger_id) = PostgresLedgerStore::open_active(client, &site_id)?;
    let clock = SystemElapsedClock::new()?;
    let continuity_id = clock.continuity_id();
    let mut producer = V2LedgerProducer::open_or_create(store, clock, ledger_id, site_id, policy)?;
    if producer.state().open.clock_continuity_id != continuity_id {
        producer.recover()?;
    }

    let timestamp_authority = Rfc3161TimestampAuthority::new(tsa_url, tsa_ca_file, tsa_policy_oid);
    submit_pending_timestamps(&mut producer, &timestamp_authority)?;

    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(
        listener,
        router(GatewayHttpState::new(producer, timestamp_authority)),
    )
    .await?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn boottime_conversion_is_checked_and_uses_milliseconds() {
        assert_eq!(
            timespec_ms(Timespec {
                tv_sec: 12,
                tv_nsec: 345_999_999,
            })
            .unwrap(),
            12_345
        );
        assert!(
            timespec_ms(Timespec {
                tv_sec: -1,
                tv_nsec: 0,
            })
            .is_err()
        );
        assert!(
            timespec_ms(Timespec {
                tv_sec: 0,
                tv_nsec: 1_000_000_000,
            })
            .is_err()
        );
    }
}
