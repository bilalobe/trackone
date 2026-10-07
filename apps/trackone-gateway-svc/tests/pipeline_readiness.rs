//! Readiness and transactional admission capacity exercised against real PostgreSQL.
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use postgres::{Client, NoTls};
use serde_json::Value;
use tower::ServiceExt;
use trackone_gateway_svc::{
    observability::CapacityLimits,
    postgres::PostgresLedgerStore,
    producer::{CloseReason, ElapsedClock, LedgerProducer, ProducerError},
    service::{AdmissionAuth, GatewayHttpState, router},
    timestamp_worker::TimestampWorkerConfig,
};
use trackone_ledger::vtl::{ClosurePolicy, EmptyMode};

const TOKEN: &str = "readiness-test-token-0123456789abcdef";
static NEXT: AtomicU64 = AtomicU64::new(0);
#[derive(Clone)]
struct Clock(Arc<AtomicU64>);
impl ElapsedClock for Clock {
    fn now_ms(&self) -> Result<u64, ProducerError> {
        Ok(0)
    }
    fn continuity_id(&self) -> u128 {
        u128::from(self.0.load(Ordering::Relaxed))
    }
}
fn record(counter: u8) -> Vec<u8> {
    vec![
        0x87, 1, 0x48, 0, 0, 0, 0, 0, 0, 0, counter, counter, 0, 0xf6, 0, 0xf6,
    ]
}
struct Database {
    url: String,
    schema: String,
    ledger: String,
}
impl Database {
    fn new() -> Option<Self> {
        let url = match std::env::var("TRACKONE_TEST_DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                assert!(
                    std::env::var_os("CI").is_none(),
                    "CI must supply PostgreSQL"
                );
                eprintln!("skipping readiness integration tests: TRACKONE_TEST_DATABASE_URL unset");
                return None;
            }
        };
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            + u128::from(NEXT.fetch_add(1, Ordering::Relaxed));
        let db = Self {
            url,
            schema: format!("readiness_{unique:x}"),
            ledger: format!("{unique:032x}"),
        };
        Client::connect(&db.url, NoTls)
            .unwrap()
            .batch_execute(&format!("CREATE SCHEMA {}", db.schema))
            .unwrap();
        db.store().migrate().unwrap();
        Some(db)
    }
    fn client(&self) -> Client {
        let mut config = self.url.parse::<postgres::Config>().unwrap();
        config.options(&format!("-c search_path={}", self.schema));
        config.connect(NoTls).unwrap()
    }
    fn store(&self) -> PostgresLedgerStore {
        PostgresLedgerStore::new(self.client(), &self.ledger)
    }
    fn producer(
        &self,
        limit: Option<u64>,
        clock: Clock,
    ) -> LedgerProducer<PostgresLedgerStore, Clock> {
        LedgerProducer::open_or_create(
            self.store(),
            clock,
            &self.ledger,
            "readiness",
            ClosurePolicy {
                interval_ms: u64::MAX,
                batch_record_limit: 1024,
                record_limit: limit,
                size_limit_bytes: None,
                empty_mode: EmptyMode::Suppress,
            },
        )
        .unwrap()
    }
    fn usage(&self) -> (u64, u64) {
        let row = self.client().query_one("SELECT pending_timestamps::text, retained_evidence_bytes::text FROM trackone_vtl_pipeline_usage WHERE ledger_id=$1", &[&self.ledger]).unwrap();
        (
            row.get::<_, String>(0).parse().unwrap(),
            row.get::<_, String>(1).parse().unwrap(),
        )
    }
    fn force_due(&self) {
        self.client().execute("UPDATE trackone_vtl_sealed_segment SET tsa_next_attempt=CURRENT_TIMESTAMP - INTERVAL '1 second', tsa_lease_until=NULL WHERE ledger_id=$1", &[&self.ledger]).unwrap();
    }
}
impl Drop for Database {
    fn drop(&mut self) {
        Client::connect(&self.url, NoTls)
            .unwrap()
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .unwrap();
    }
}
fn clock() -> Clock {
    Clock(Arc::new(AtomicU64::new(1)))
}
fn http_state(producer: LedgerProducer<PostgresLedgerStore, Clock>) -> GatewayHttpState<Clock> {
    GatewayHttpState::new(
        producer,
        AdmissionAuth::new(TOKEN, None).unwrap(),
        100,
        4096,
    )
}
fn request(
    app: &Router,
    method: &str,
    path: &str,
    key: Option<&str>,
    body: Vec<u8>,
    authorized: bool,
) -> (StatusCode, Value) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let mut builder = Request::builder().method(method).uri(path);
        if authorized {
            builder = builder.header("authorization", format!("Bearer {TOKEN}"));
        }
        if let Some(key) = key {
            builder = builder.header("idempotency-key", key);
        }
        if method == "POST" {
            builder = builder.header(
                "content-type",
                if path.ends_with("batches") {
                    "application/vnd.trackone.record-batch.v1+cbor"
                } else {
                    "application/cbor"
                },
            );
        }
        let response = app
            .clone()
            .oneshot(builder.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    })
}
fn ready(app: &Router) -> (StatusCode, Value) {
    request(app, "GET", "/readyz", None, vec![], false)
}
fn post(app: &Router, key: &str, counter: u8) -> (StatusCode, Value) {
    request(app, "POST", "/v2/records", Some(key), record(counter), true)
}

#[test]
fn queue_exhaustion_rolls_back_batch_and_preserves_replays_and_tsa_outage_admission() {
    let Some(db) = Database::new() else { return };
    let state = http_state(db.producer(Some(1), clock())).with_capacity_limits(CapacityLimits {
        max_pending_timestamps: Some(2),
        ..Default::default()
    });
    let app = router(state.clone());
    assert_eq!(ready(&app).0, StatusCode::SERVICE_UNAVAILABLE);
    state.sample_readiness();
    assert_eq!(ready(&app).0, StatusCode::OK);
    let mut batch = vec![0x83];
    for n in 1..=3 {
        let r = record(n);
        batch.push(0x40 + r.len() as u8);
        batch.extend(r);
    }
    let (status, value) = request(
        &app,
        "POST",
        "/v2/record-batches",
        Some("batch"),
        batch,
        true,
    );
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(value["error"], "queue_capacity_exhausted");
    assert_eq!(value["admission_available"], false);
    assert_eq!(db.usage(), (0, 0));
    assert_eq!(
        db.client()
            .query_one(
                "SELECT revision::text FROM trackone_vtl_ledger_state WHERE ledger_id=$1",
                &[&db.ledger]
            )
            .unwrap()
            .get::<_, String>(0),
        "0"
    );
    assert_eq!(post(&app, "one", 1).0, StatusCode::CREATED);
    let mut worker = db.store();
    let claim = worker.claim_timestamp(2).unwrap().unwrap();
    worker
        .finish_timestamp(
            &claim,
            &Err("TSA is offline".into()),
            &TimestampWorkerConfig {
                max_attempts: 2,
                ..Default::default()
            },
        )
        .unwrap();
    state.sample_readiness();
    let (status, value) = ready(&app);
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["pipeline_degraded"], true);
    assert_eq!(value["statistics"]["pending_timestamp_count"], 1);
    assert!(value["statistics"]["oldest_pending_timestamp_age_seconds"].is_number());
    assert_eq!(post(&app, "two", 2).0, StatusCode::CREATED);
    state.sample_readiness();
    assert_eq!(ready(&app).1["reasons"][0], "queue_capacity_exhausted");
    assert_eq!(
        post(&app, "three", 3).1["error"],
        "queue_capacity_exhausted"
    );
    assert_eq!(post(&app, "one", 1).0, StatusCode::OK);
    assert_eq!(post(&app, "one", 2).0, StatusCode::CONFLICT);
    assert_eq!(ready(&app).1["counters"]["admission_rejections"], 3);
    db.force_due();
    let claim = worker.claim_timestamp(2).unwrap().unwrap();
    worker
        .finish_timestamp(
            &claim,
            &Ok(vec![1, 2, 3]),
            &TimestampWorkerConfig::default(),
        )
        .unwrap();
    state.sample_readiness();
    assert_eq!(ready(&app).0, StatusCode::OK);
    assert!(ready(&app).1["statistics"]["last_successful_timestamp_attachment"].is_string());
    db.store().migrate().unwrap();
    assert_eq!(db.usage().0, 1);
    assert_eq!(post(&app, "three", 3).0, StatusCode::CREATED);
}

#[test]
fn byte_limit_counts_transferred_records_once_and_allows_preservation_above_limit() {
    let Some(db) = Database::new() else { return };
    let mut producer = db.producer(Some(2), clock());
    let bytes = record(1).len() as u64;
    producer.store_mut().set_capacity_limits(CapacityLimits {
        max_retained_evidence_bytes: Some(bytes * 2),
        ..Default::default()
    });
    producer.admit_idempotent("first", record(1)).unwrap();
    let revision = producer.state().revision;
    assert_eq!(
        producer.admit_idempotent("second", record(2)).unwrap_err(),
        ProducerError::StorageCapacityExhausted
    );
    assert_eq!(producer.state().revision, revision);
    assert_eq!(db.usage(), (0, bytes));
    let sealed = producer.recover().unwrap();
    assert_eq!(
        db.usage(),
        (1, bytes + sealed[0].artifact_cbor.len() as u64)
    );
    assert!(
        producer
            .admit_idempotent("first", record(1))
            .unwrap()
            .replayed
    );
    producer
        .store_mut()
        .attach_tsa_response(0, &sealed[0].artifact_sha256, &[1, 2, 3, 4])
        .unwrap();
    assert_eq!(
        db.usage(),
        (0, bytes + sealed[0].artifact_cbor.len() as u64 + 4)
    );
    let state = http_state(producer);
    state.sample_readiness();
    let app = router(state.clone());
    assert_eq!(ready(&app).1["reasons"][0], "storage_capacity_exhausted");
    assert_eq!(
        post(&app, "second", 2).1["error"],
        "storage_capacity_exhausted"
    );
    assert_eq!(ready(&app).1["counters"]["sealing_failures"], 0);
    assert_eq!(ready(&app).1["counters"]["recovery_events"], 1);
}

#[test]
fn exact_byte_boundary_and_atomic_byte_batch_rejection() {
    let Some(db) = Database::new() else { return };
    let mut producer = db.producer(None, clock());
    let bytes = record(1).len() as u64;
    producer.store_mut().set_capacity_limits(CapacityLimits {
        max_retained_evidence_bytes: Some(bytes * 2),
        ..Default::default()
    });
    assert_eq!(
        producer
            .admit_batch_idempotent("batch", vec![record(1), record(2), record(3)], b"batch")
            .unwrap_err(),
        ProducerError::StorageCapacityExhausted
    );
    assert_eq!(db.usage(), (0, 0));
    producer.admit_idempotent("one", record(1)).unwrap();
    producer.admit_idempotent("two", record(2)).unwrap();
    assert_eq!(db.usage(), (0, bytes * 2));
    assert_eq!(
        producer.admit_idempotent("three", record(3)).unwrap_err(),
        ProducerError::StorageCapacityExhausted
    );
    let state = http_state(producer);
    state.sample_readiness();
    let app = router(state.clone());
    assert_eq!(ready(&app).0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        ready(&app).1["capacity"]["retained_evidence_bytes"]["utilization"],
        1.0
    );
}

#[test]
fn terminal_events_are_committed_once_and_durable_statistics_survive_restart() {
    let Some(db) = Database::new() else { return };
    let producer = db.producer(Some(1), clock());
    let events = producer.events();
    let state = http_state(producer);
    let app = router(state.clone());
    post(&app, "one", 1);
    post(&app, "two", 2);
    let mut worker = db.store();
    worker.set_events(Arc::clone(&events));
    let config = TimestampWorkerConfig {
        max_attempts: 1,
        ..Default::default()
    };
    let claim = worker.claim_timestamp(1).unwrap().unwrap();
    assert!(
        worker
            .finish_timestamp(&claim, &Err("offline".into()), &config)
            .unwrap()
    );
    assert!(
        !worker
            .finish_timestamp(&claim, &Err("offline".into()), &config)
            .unwrap()
    );
    worker.claim_timestamp(1).unwrap().unwrap();
    db.force_due();
    assert!(worker.claim_timestamp(1).unwrap().is_none());
    assert!(worker.claim_timestamp(1).unwrap().is_none());
    state.sample_readiness();
    let (status, value) = ready(&app);
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["pipeline_degraded"], true);
    assert_eq!(value["counters"]["terminal_timestamp_failures"], 2);
    assert_eq!(value["statistics"]["terminal_failed_segment_count"], 2);
    assert!(value["statistics"]["oldest_pending_timestamp_age_seconds"].is_null());
    let restarted = http_state(db.producer(Some(1), clock()));
    restarted.sample_readiness();
    let value = ready(&router(restarted.clone())).1;
    assert_eq!(value["statistics"]["terminal_failed_segment_count"], 2);
    assert_eq!(value["counters"]["terminal_timestamp_failures"], 0);
}

#[test]
fn database_disconnect_keeps_liveness_and_returns_explicit_admission_failure() {
    let Some(db) = Database::new() else { return };
    let mut client = db.client();
    let pid: i32 = client
        .query_one("SELECT pg_backend_pid()", &[])
        .unwrap()
        .get(0);
    let producer = LedgerProducer::open_or_create(
        PostgresLedgerStore::new(client, &db.ledger),
        clock(),
        &db.ledger,
        "readiness",
        ClosurePolicy {
            interval_ms: u64::MAX,
            batch_record_limit: 1,
            record_limit: Some(1),
            size_limit_bytes: None,
            empty_mode: EmptyMode::Suppress,
        },
    )
    .unwrap();
    let state = http_state(producer);
    let app = router(state.clone());
    state.sample_readiness();
    assert_eq!(ready(&app).0, StatusCode::OK);
    db.client()
        .query_one("SELECT pg_terminate_backend($1)", &[&pid])
        .unwrap();
    state.sample_readiness();
    let (status, value) = ready(&app);
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(value["database_available"], false);
    assert!(value["statistics"].is_null());
    assert_eq!(
        request(&app, "GET", "/healthz", None, vec![], false).0,
        StatusCode::OK
    );
    let (status, value) = post(&app, "one", 1);
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(value["admission_available"], false);
    request(
        &app,
        "POST",
        "/v2/records",
        Some("unauth"),
        record(1),
        false,
    );
    request(&app, "POST", "/v2/records", Some("invalid"), vec![0], true);
    assert_eq!(ready(&app).1["counters"]["admission_rejections"], 3);
}

#[test]
fn recovery_state_sealing_failure_and_inactive_state_are_observable() {
    let Some(db) = Database::new() else { return };
    let clock = clock();
    let mut producer = db.producer(None, clock.clone());
    producer.admit(record(1)).unwrap();
    let state = http_state(producer);
    clock.0.store(2, Ordering::Relaxed);
    state.sample_readiness();
    assert_eq!(
        ready(&router(state.clone())).1["producer_state"],
        "recovery_required"
    );
    // A separate producer recovers the durable interval under the new clock.
    let mut recovered = db.producer(None, clock.clone());
    recovered.recover().unwrap();
    recovered.close(CloseReason::Shutdown).unwrap();
    let inactive = http_state(recovered);
    inactive.sample_readiness();
    assert_eq!(
        ready(&router(inactive.clone())).1["producer_state"],
        "inactive"
    );
    let mut failed = db.producer(None, clock);
    failed.admit(record(2)).unwrap();
    let events = failed.events();
    db.client().batch_execute("CREATE FUNCTION reject_segment() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test seal persistence failure'; END $$; CREATE TRIGGER reject_segment BEFORE INSERT ON trackone_vtl_sealed_segment FOR EACH ROW EXECUTE FUNCTION reject_segment()").unwrap();
    let revision = failed.state().revision;
    assert!(failed.recover().is_err());
    assert_eq!(failed.state().revision, revision);
    assert_eq!(events.sealing_failures.load(Ordering::Relaxed), 1);
    assert_eq!(events.recovery_events.load(Ordering::Relaxed), 0);
}

#[test]
fn concurrent_producers_cannot_bypass_capacity() {
    let Some(db) = Database::new() else { return };
    let mut first = db.producer(Some(1), clock());
    let mut second = db.producer(Some(1), clock());
    let limit = CapacityLimits {
        max_pending_timestamps: Some(1),
        ..Default::default()
    };
    first.store_mut().set_capacity_limits(limit);
    second.store_mut().set_capacity_limits(limit);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let barrier2 = Arc::clone(&barrier);
    let a = std::thread::spawn(move || {
        barrier.wait();
        first.admit(record(1))
    });
    let b = std::thread::spawn(move || {
        barrier2.wait();
        second.admit(record(2))
    });
    let results = [a.join().unwrap(), b.join().unwrap()];
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(db.usage().0, 1);
}

#[test]
fn legacy_migration_backfills_usage_without_inventing_attachment_times() {
    let Some(db) = Database::new() else { return };
    Client::connect(&db.url, NoTls)
        .unwrap()
        .batch_execute(&format!(
            "DROP SCHEMA {} CASCADE; CREATE SCHEMA {}",
            db.schema, db.schema
        ))
        .unwrap();
    let mut client = db.client();
    client
        .batch_execute(include_str!("../migrations/0001_vtl_ledger.sql"))
        .unwrap();
    client
        .batch_execute(include_str!("../migrations/0002_timestamp_queue.sql"))
        .unwrap();
    client.execute("INSERT INTO trackone_vtl_ledger_state (ledger_id, revision, site_id, next_segment_number, opened_at_ms, clock_continuity_id, open_interval_ms, open_batch_record_limit, open_empty_mode, byte_count, next_interval_ms, next_batch_record_limit, next_empty_mode) VALUES ($1,0,'legacy',2,0,1,60000,1024,'suppress',4,60000,1024,'suppress')", &[&db.ledger]).unwrap();
    client
        .execute(
            "INSERT INTO trackone_vtl_open_record VALUES ($1,0,$2)",
            &[&db.ledger, &vec![1u8; 4]],
        )
        .unwrap();
    client.execute("INSERT INTO trackone_vtl_sealed_segment (ledger_id, segment_number, close_reason, artifact_cbor, artifact_sha256) VALUES ($1,0,'manual',$2,repeat('0',64))", &[&db.ledger, &vec![2u8; 3]]).unwrap();
    client
        .execute(
            "INSERT INTO trackone_vtl_sealed_record VALUES ($1,0,0,$2)",
            &[&db.ledger, &vec![3u8; 6]],
        )
        .unwrap();
    client.execute("INSERT INTO trackone_vtl_sealed_segment (ledger_id, segment_number, close_reason, artifact_cbor, artifact_sha256, tsa_status, tsa_response) VALUES ($1,1,'manual',$2,repeat('0',64),'verified',$3)", &[&db.ledger, &vec![4u8; 3], &vec![5u8; 5]]).unwrap();
    let mut store = db.store();
    store.migrate().unwrap();
    store.migrate().unwrap();
    assert_eq!(db.usage(), (1, 21));
    let stats = store.pipeline_statistics(0).unwrap();
    assert_eq!(stats.pending_timestamp_count, 1);
    assert!(stats.oldest_pending_timestamp_age_seconds.unwrap() < 10.0);
    assert!(stats.last_successful_timestamp_attachment.is_none());
    client.execute("UPDATE trackone_vtl_sealed_segment SET tsa_status='failed' WHERE ledger_id=$1 AND segment_number=0", &[&db.ledger]).unwrap();
    assert_eq!(db.usage(), (0, 21));
}

#[test]
fn physical_storage_failure_is_not_cleared_by_a_successful_read_probe() {
    let Some(db) = Database::new() else { return };
    let state = http_state(db.producer(Some(1), clock()));
    let app = router(state.clone());
    state.sample_readiness();
    db.client().batch_execute("CREATE FUNCTION disk_full() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'simulated disk exhaustion' USING ERRCODE='53100'; END $$; CREATE TRIGGER disk_full BEFORE INSERT ON trackone_vtl_sealed_segment FOR EACH ROW EXECUTE FUNCTION disk_full()").unwrap();
    let (status, value) = post(&app, "one", 1);
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(value["error"], "storage_unavailable");
    assert_eq!(value["admission_available"], false);
    assert_eq!(db.usage(), (0, 0));
    state.sample_readiness();
    let (status, value) = ready(&app);
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(value["database_available"], true);
    assert_eq!(value["reasons"][0], "storage_unavailable");
    assert_eq!(
        request(&app, "GET", "/healthz", None, vec![], false).0,
        StatusCode::OK
    );
    db.client()
        .batch_execute("DROP TRIGGER disk_full ON trackone_vtl_sealed_segment")
        .unwrap();
    assert_eq!(post(&app, "one", 1).0, StatusCode::CREATED);
    state.sample_readiness();
    assert_eq!(ready(&app).0, StatusCode::OK);
}

#[test]
fn concurrent_timestamp_attachment_and_admission_keep_usage_consistent() {
    let Some(db) = Database::new() else { return };
    let mut producer = db.producer(Some(1), clock());
    producer.store_mut().set_capacity_limits(CapacityLimits {
        max_pending_timestamps: Some(1),
        ..Default::default()
    });
    producer.admit(record(1)).unwrap();
    let mut worker = db.store();
    let claim = worker.claim_timestamp(20).unwrap().unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let barrier2 = Arc::clone(&barrier);
    let a = std::thread::spawn(move || {
        barrier.wait();
        producer.admit(record(2))
    });
    let b = std::thread::spawn(move || {
        barrier2.wait();
        worker.finish_timestamp(&claim, &Ok(vec![9; 5]), &TimestampWorkerConfig::default())
    });
    let admitted = a.join().unwrap().is_ok();
    assert!(b.join().unwrap().unwrap());
    let mut client = db.client();
    let row = client.query_one("SELECT (SELECT count(*) FROM trackone_vtl_sealed_segment WHERE ledger_id=$1 AND tsa_status='queued'), (SELECT COALESCE(sum(octet_length(record_cbor)),0) FROM trackone_vtl_sealed_record WHERE ledger_id=$1) + (SELECT COALESCE(sum(octet_length(artifact_cbor) + COALESCE(octet_length(tsa_response),0)),0) FROM trackone_vtl_sealed_segment WHERE ledger_id=$1)", &[&db.ledger]).unwrap();
    assert_eq!(
        db.usage(),
        (row.get::<_, i64>(0) as u64, row.get::<_, i64>(1) as u64)
    );
    assert_eq!(db.usage().0, u64::from(admitted));
}

#[test]
fn background_sampler_populates_the_cache_and_stops_cleanly() {
    let Some(db) = Database::new() else { return };
    let state = http_state(db.producer(Some(1), clock()));
    let app = router(state.clone());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let sampler = state.start_readiness_sampler();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri("/readyz")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                if response.status() == StatusCode::OK {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        state.readiness.shutdown();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        sampler.abort();
        assert!(sampler.await.unwrap_err().is_cancelled());
    });
}

#[test]
fn cached_probes_and_sampler_do_not_wait_for_a_busy_producer() {
    use std::sync::{Condvar, Mutex};
    struct BlockingClock(Arc<(Mutex<(bool, bool)>, Condvar)>);
    impl ElapsedClock for BlockingClock {
        fn now_ms(&self) -> Result<u64, ProducerError> {
            let mut gate = self.0.0.lock().unwrap();
            while gate.0 {
                gate.1 = true;
                self.0.1.notify_all();
                gate = self.0.1.wait(gate).unwrap();
            }
            Ok(0)
        }
        fn continuity_id(&self) -> u128 {
            1
        }
    }
    let Some(db) = Database::new() else { return };
    let gate = Arc::new((Mutex::new((false, false)), Condvar::new()));
    let producer = LedgerProducer::open_or_create(
        db.store(),
        BlockingClock(Arc::clone(&gate)),
        &db.ledger,
        "readiness",
        ClosurePolicy {
            interval_ms: u64::MAX,
            batch_record_limit: 1024,
            record_limit: Some(1),
            size_limit_bytes: None,
            empty_mode: EmptyMode::Suppress,
        },
    )
    .unwrap();
    let state = GatewayHttpState::new(
        producer,
        AdmissionAuth::new(TOKEN, None).unwrap(),
        100,
        4096,
    );
    state.sample_readiness();
    let app = router(state.clone());
    gate.0.lock().unwrap().0 = true;
    let admission_app = app.clone();
    let admission = std::thread::spawn(move || post(&admission_app, "one", 1));
    let (entered, _) = gate
        .1
        .wait_timeout_while(
            gate.0.lock().unwrap(),
            std::time::Duration::from_secs(3),
            |g| !g.1,
        )
        .unwrap();
    let was_entered = entered.1;
    drop(entered);
    let (sender, receiver) = std::sync::mpsc::channel();
    let sample_state = state.clone();
    let sample = std::thread::spawn(move || {
        sample_state.sample_readiness();
        sender.send(()).unwrap();
    });
    let sampled_without_waiting = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .is_ok();
    let start = std::time::Instant::now();
    let readiness = ready(&app).0;
    let liveness = request(&app, "GET", "/healthz", None, vec![], false).0;
    let elapsed = start.elapsed();
    gate.0.lock().unwrap().0 = false;
    gate.1.notify_all();
    let admitted = admission.join().unwrap().0;
    sample.join().unwrap();
    assert!(was_entered);
    assert!(sampled_without_waiting);
    assert!(elapsed < std::time::Duration::from_secs(1));
    assert_eq!(readiness, StatusCode::OK);
    assert_eq!(liveness, StatusCode::OK);
    assert_eq!(admitted, StatusCode::CREATED);
}
