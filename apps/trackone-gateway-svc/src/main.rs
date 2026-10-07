use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use trackone_gateway_svc::config::GatewayConfig;
use trackone_gateway_svc::error::{ResultContext, RuntimeError};
use trackone_gateway_svc::observability::PipelineEvents;
use trackone_gateway_svc::postgres::PostgresLedgerStore;
use trackone_gateway_svc::postgres_connection::connect_postgres;
use trackone_gateway_svc::producer::{ElapsedClock, LedgerProducer, ProducerError};
use trackone_gateway_svc::service::{GatewayHttpState, router};
use trackone_gateway_svc::timestamp_worker::TimestampWorkers;
use trackone_gateway_svc::tsa::Rfc3161TimestampAuthority;

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

fn main() -> Result<(), RuntimeError> {
    let config = GatewayConfig::parse();
    let events = Arc::new(PipelineEvents::default());
    let capacity_limits = config.capacity_limits();
    let admission_auth = config.admission_auth()?;
    let worker_config = config.worker_config()?;
    let policy = config.closure_policy();
    let disclosure_auth = match &config.disclosure_grants_file {
        Some(path) => {
            let bytes = std::fs::read(path).context(format!(
                "cannot read disclosure grants file {}",
                path.display()
            ))?;
            trackone_gateway_svc::evidence::DisclosureAuth::from_json(&bytes)
                .context(format!("invalid disclosure grants file {}", path.display()))?
        }
        None => trackone_gateway_svc::evidence::DisclosureAuth::default(),
    };
    let timestamp_authority = Rfc3161TimestampAuthority::new(
        config.tsa_url,
        config.tsa_ca_file,
        config
            .tsa_intermediates_file
            .filter(|path| !path.as_os_str().is_empty()),
        config.tsa_crls_file,
        config.tsa_policy_oid,
        config.tsa_signer_cert_sha256,
        config.tsa_max_future_skew_seconds,
    )
    .context("cannot initialize TSA verification policy")?;
    let postgres_tls_mode = config.database.postgres_tls_mode;
    let postgres_ca_file = config.database.ca_file().map(str::to_owned);
    let database_url = config.database.url;
    let ledger_id = config.ledger_id;
    let client = connect_postgres(
        &database_url,
        postgres_tls_mode,
        postgres_ca_file.as_deref(),
    )
    .context("cannot connect gateway to PostgreSQL")?;
    let mut store = PostgresLedgerStore::new(client, &ledger_id);
    store.set_events(Arc::clone(&events));
    store.set_capacity_limits(capacity_limits);
    store.migrate().context("cannot migrate gateway database")?;
    let clock = SystemElapsedClock::new().context("cannot initialize gateway clock")?;
    let continuity_id = clock.continuity_id();
    let mut producer =
        LedgerProducer::open_or_create(store, clock, ledger_id.clone(), config.site_id, policy)
            .context("cannot open or create ledger producer")?;
    producer.set_events(Arc::clone(&events));
    if producer.state().open.clock_continuity_id != continuity_id {
        producer
            .recover()
            .context("cannot recover ledger after clock continuity change")?;
    }

    // Keep the final synchronous PostgreSQL client owner outside the Tokio
    // runtime: its destructor closes the connection with its own block_on.
    let evidence_database = database_url.clone();
    let evidence_ca = postgres_ca_file.clone();
    let evidence =
        trackone_gateway_svc::evidence::router(trackone_gateway_svc::evidence::EvidenceState::new(
            ledger_id.clone(),
            disclosure_auth,
            move || {
                connect_postgres(
                    &evidence_database,
                    postgres_tls_mode,
                    evidence_ca.as_deref(),
                )
                .map_err(|error| error.to_string())
            },
        ));
    let state = GatewayHttpState::new(
        producer,
        admission_auth,
        config.max_batch_records,
        config.max_admission_bytes,
    );
    let app = router(state.clone()).merge(evidence);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot initialize gateway Tokio runtime")?;
    runtime.block_on(async {
        // Install both handlers before serving; an installation failure aborts startup.
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("cannot install SIGTERM handler")?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .context("cannot install SIGINT handler")?;
        let listener = tokio::net::TcpListener::bind(config.bind)
            .await
            .context(format!("cannot bind gateway listener to {}", config.bind))?;
        let readiness_sampler = state.start_readiness_sampler();
        let workers = Arc::new(
            TimestampWorkers::start(worker_config, Arc::new(timestamp_authority), move || {
                connect_postgres(
                    &database_url,
                    postgres_tls_mode,
                    postgres_ca_file.as_deref(),
                )
                .map(|client| {
                    let mut store = PostgresLedgerStore::new(client, &ledger_id);
                    store.set_events(Arc::clone(&events));
                    store
                })
                .map_err(|error| ProducerError::Store(error.to_string()))
            })
            .context("cannot start timestamp workers")?,
        );
        let shutdown_workers = Arc::clone(&workers);
        let result = axum::serve(listener, app.clone())
            .with_graceful_shutdown(async move {
                tokio::select! {
                    _ = interrupt.recv() => (),
                    _ = terminate.recv() => (),
                }
                state.readiness.shutdown();
                shutdown_workers.stop_claiming();
            })
            .await;
        readiness_sampler.abort();
        drop(workers);
        result.context("gateway HTTP server failed")?;
        Ok(())
    })
}
