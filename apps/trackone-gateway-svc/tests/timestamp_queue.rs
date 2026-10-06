//! Real PostgreSQL lease/commit tests. CI supplies a mandatory database service.
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use postgres::{Client, NoTls};
use tower::ServiceExt;
use trackone_gateway_svc::{
    postgres::PostgresLedgerStore,
    producer::{ElapsedClock, LedgerProducer, ProducerError},
    service::{AdmissionAuth, GatewayHttpState, router},
    timestamp_worker::{
        TimestampClaim, TimestampSubmitter, TimestampWorkerConfig, TimestampWorkers, submit_claim,
    },
};
use trackone_ledger::vtl::{ClosurePolicy, EmptyMode};

const TOKEN: &str = "timestamp-test-token-0123456789abcdef0123456789";
static NEXT: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy)]
struct Clock;
impl ElapsedClock for Clock {
    fn now_ms(&self) -> Result<u64, ProducerError> {
        Ok(0)
    }
    fn continuity_id(&self) -> u128 {
        1
    }
}

fn record(counter: u8) -> Vec<u8> {
    vec![
        0x87, 0x01, 0x48, 0, 0, 0, 0, 0, 0, 0, counter, counter, 0, 0xf6, 0, 0xf6,
    ]
}

struct Database {
    url: String,
    ledger: String,
    schema: String,
}
impl Database {
    fn new() -> Option<Self> {
        let url = match std::env::var("TRACKONE_TEST_DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                assert!(
                    std::env::var_os("CI").is_none(),
                    "CI must configure TRACKONE_TEST_DATABASE_URL"
                );
                eprintln!("skipping PostgreSQL test: TRACKONE_TEST_DATABASE_URL is not configured");
                return None;
            }
        };
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            + NEXT.fetch_add(1, Ordering::SeqCst) as u128;
        let database = Self {
            url,
            ledger: format!("{unique:032x}"),
            schema: format!("timestamp_test_{unique:032x}"),
        };
        // Isolate serializable producer transactions and migrations across tests.
        Client::connect(&database.url, NoTls)
            .unwrap()
            .batch_execute(&format!("CREATE SCHEMA {}", database.schema))
            .unwrap();
        database.store().migrate().unwrap();
        Some(database)
    }
    fn store(&self) -> PostgresLedgerStore {
        PostgresLedgerStore::new(self.client(), &self.ledger)
    }
    fn client(&self) -> Client {
        let mut config = self.url.parse::<postgres::Config>().unwrap();
        config.options(&format!("-c search_path={}", self.schema));
        config.connect(NoTls).unwrap()
    }
    fn producer(&self) -> LedgerProducer<PostgresLedgerStore, Clock> {
        LedgerProducer::open_or_create(
            self.store(),
            Clock,
            &self.ledger,
            "timestamp-test",
            ClosurePolicy {
                interval_ms: u64::MAX,
                batch_record_limit: 1024,
                record_limit: Some(1),
                size_limit_bytes: None,
                empty_mode: EmptyMode::Suppress,
            },
        )
        .unwrap()
    }
    fn due(&self) {
        self.client().execute("UPDATE trackone_vtl_sealed_segment SET tsa_next_attempt=CURRENT_TIMESTAMP - INTERVAL '1 second', tsa_lease_until=NULL WHERE ledger_id=$1 AND tsa_status='queued'", &[&self.ledger]).unwrap();
    }
    fn expire(&self) {
        self.client().execute("UPDATE trackone_vtl_sealed_segment SET tsa_next_attempt=CURRENT_TIMESTAMP - INTERVAL '1 second', tsa_lease_until=CURRENT_TIMESTAMP - INTERVAL '1 second' WHERE ledger_id=$1 AND tsa_status='queued'", &[&self.ledger]).unwrap();
    }
    fn immutable(&self) -> (Vec<u8>, String, Vec<u8>, String) {
        let row = self.client().query_one("SELECT artifact_cbor, artifact_sha256, predecessor_cbor, revision::text FROM trackone_vtl_sealed_segment JOIN trackone_vtl_ledger_state USING (ledger_id) WHERE ledger_id=$1 AND segment_number=0", &[&self.ledger]).unwrap();
        (row.get(0), row.get(1), row.get(2), row.get(3))
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

#[test]
fn retries_are_durable_bounded_and_exhausted_claims_fail() {
    let Some(database) = Database::new() else {
        return;
    };
    database.producer().admit(record(1)).unwrap();
    let immutable = database.immutable();
    let config = TimestampWorkerConfig {
        max_attempts: 2,
        retry_initial_ms: 1000,
        retry_max_ms: 4000,
        ..Default::default()
    };
    let mut store = database.store();
    let first = store.claim_timestamp(config.max_attempts).unwrap().unwrap();
    assert!(database.store().claim_timestamp(2).unwrap().is_none());
    store
        .finish_timestamp(&first, &Err("outage\n".repeat(300)), &config)
        .unwrap();
    drop(store);
    let mut restarted = database.store();
    let status = restarted.timestamp_status(0).unwrap().unwrap();
    assert_eq!(status.state, "queued");
    assert_eq!(status.attempt_count, "1");
    assert_eq!(status.last_error.unwrap().len(), 512);
    assert!(status.next_attempt.unwrap().ends_with('Z'));
    let future: bool = database.client().query_one("SELECT tsa_next_attempt > CURRENT_TIMESTAMP FROM trackone_vtl_sealed_segment WHERE ledger_id=$1", &[&database.ledger]).unwrap().get(0);
    assert!(future);
    assert!(restarted.claim_timestamp(2).unwrap().is_none());
    database.due();
    let last = restarted.claim_timestamp(2).unwrap().unwrap();
    assert_eq!(last.attempt, 2);
    restarted
        .finish_timestamp(&last, &Err("still unavailable".into()), &config)
        .unwrap();
    let status = restarted.timestamp_status(0).unwrap().unwrap();
    assert_eq!(status.state, "failed");
    assert_eq!(status.last_error.as_deref(), Some("still unavailable"));
    assert!(status.next_attempt.is_none());
    assert!(restarted.claim_timestamp(2).unwrap().is_none());
    assert_eq!(database.immutable(), immutable);

    database.producer().admit(record(2)).unwrap();
    restarted.claim_timestamp(1).unwrap().unwrap(); // crash on final attempt
    database.expire();
    assert!(restarted.claim_timestamp(1).unwrap().is_none());
    let status = restarted.timestamp_status(1).unwrap().unwrap();
    assert_eq!(status.state, "failed");
    assert!(status.last_error.unwrap().contains("lease expired"));
}

struct Accepted;
impl TimestampSubmitter for Accepted {
    fn submit(&self, _: &[u8]) -> Result<Vec<u8>, ProducerError> {
        Ok(b"validated-test-token".to_vec())
    }
}

#[test]
fn crash_boundaries_fence_stale_workers_and_keep_first_attachment() {
    let Some(database) = Database::new() else {
        return;
    };
    database.producer().admit(record(1)).unwrap();
    let immutable = database.immutable();
    let config = TimestampWorkerConfig::default();
    let mut store = database.store();
    let submitted = store.claim_timestamp(20).unwrap().unwrap();
    let lost_response = submit_claim(&Accepted, &submitted).unwrap();
    drop(store); // submission succeeded; process died before attaching
    database.expire();
    let mut store = database.store();
    let received = store.claim_timestamp(20).unwrap().unwrap();
    let response = submit_claim(&Accepted, &received).unwrap();
    drop(store); // received and validated; process died immediately before attachment
    database.expire();
    let mut store = database.store();
    let current = store.claim_timestamp(20).unwrap().unwrap();
    assert_eq!(current.attempt, 3);
    assert!(
        !store
            .finish_timestamp(&received, &Ok(response), &config)
            .unwrap()
    );
    assert!(
        !store
            .finish_timestamp(&submitted, &Err("late failure".into()), &config)
            .unwrap()
    );
    assert!(
        store
            .finish_timestamp(&current, &Ok(b"first committed token".to_vec()), &config)
            .unwrap()
    );
    drop(store); // process died after attachment commit
    let mut store = database.store();
    assert!(store.claim_timestamp(20).unwrap().is_none());
    assert!(
        store
            .finish_timestamp(&submitted, &Ok(lost_response), &config)
            .unwrap()
    );
    store
        .attach_tsa_response(0, &current.artifact_sha256, b"different valid token")
        .unwrap();
    assert!(
        store
            .attach_tsa_response(0, &"0".repeat(64), b"wrong target")
            .is_err()
    );
    let retained: Vec<u8> = database
        .client()
        .query_one(
            "SELECT tsa_response FROM trackone_vtl_sealed_segment WHERE ledger_id=$1",
            &[&database.ledger],
        )
        .unwrap()
        .get(0);
    assert_eq!(retained, b"first committed token");
    assert_eq!(
        store.timestamp_status(0).unwrap().unwrap().state,
        "attached"
    );
    assert_eq!(database.immutable(), immutable);
}

struct Ambiguous {
    digests: Mutex<Vec<String>>,
}
impl TimestampSubmitter for Ambiguous {
    fn submit(&self, artifact: &[u8]) -> Result<Vec<u8>, ProducerError> {
        let mut digests = self.digests.lock().unwrap();
        digests.push(trackone_ledger::sha256_hex(artifact));
        if digests.len() == 1 {
            Err(ProducerError::TimestampSubmission(
                "remote accepted; connection lost".into(),
            ))
        } else {
            Ok(b"validated retry token".to_vec())
        }
    }
}
#[test]
fn ambiguous_remote_outcome_resubmits_the_exact_digest() {
    let Some(database) = Database::new() else {
        return;
    };
    database.producer().admit(record(1)).unwrap();
    let immutable = database.immutable();
    let submitter = Ambiguous {
        digests: Mutex::new(Vec::new()),
    };
    let config = TimestampWorkerConfig::default();
    let mut store = database.store();
    let first = store.claim_timestamp(20).unwrap().unwrap();
    store
        .finish_timestamp(&first, &submit_claim(&submitter, &first), &config)
        .unwrap();
    database.due();
    let second = store.claim_timestamp(20).unwrap().unwrap();
    store
        .finish_timestamp(&second, &submit_claim(&submitter, &second), &config)
        .unwrap();
    assert_eq!(
        *submitter.digests.lock().unwrap(),
        vec![first.artifact_sha256.clone(), first.artifact_sha256]
    );
    assert_eq!(
        store.timestamp_status(0).unwrap().unwrap().attempt_count,
        "2"
    );
    assert_eq!(database.immutable(), immutable);
}

#[test]
fn oversized_http_response_leaves_the_same_obligation_retryable() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use trackone_gateway_svc::tsa::Rfc3161TimestampAuthority;

    let Some(database) = Database::new() else {
        return;
    };
    database.producer().admit(record(1)).unwrap();
    let immutable = database.immutable();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "TSA client never connected");
                    std::thread::sleep(Duration::from_millis(5));
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
            .unwrap();
        stream.read_exact(&mut vec![0; length]).unwrap();
        let body = vec![b'x'; 1024 * 1024 + 1];
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(&body).unwrap();
    });
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/trackone-rfc3161/tests/fixtures");
    let authority = Rfc3161TimestampAuthority::new(
        url,
        fixtures.join("tsa-root.pem"),
        None,
        fixtures.join("tsa-crls.pem"),
        "1.3.6.1.4.1.55555.1",
        "14ab98cafe09d9d1d01562af42d69a904b01023d9cd5b03bd07e5779710c8014"
            .parse()
            .unwrap(),
        Duration::ZERO,
    )
    .unwrap();
    let config = TimestampWorkerConfig::default();
    let mut store = database.store();
    let first = store.claim_timestamp(config.max_attempts).unwrap().unwrap();
    let failure = submit_claim(&authority, &first);
    server.join().unwrap();
    assert!(failure.as_ref().unwrap_err().contains("maximum"));
    assert!(store.finish_timestamp(&first, &failure, &config).unwrap());
    let status = store.timestamp_status(0).unwrap().unwrap();
    assert_eq!(status.state, "queued");
    assert!(status.next_attempt.is_some());
    assert!(status.last_error.unwrap().contains("maximum"));
    let row = database.client().query_one(
        "SELECT tsa_response, tsa_lease_until IS NULL FROM trackone_vtl_sealed_segment WHERE ledger_id=$1 AND segment_number=0",
        &[&database.ledger],
    ).unwrap();
    assert!(row.get::<_, Option<Vec<u8>>>(0).is_none());
    assert!(row.get::<_, bool>(1));
    database.due();
    let retry = store.claim_timestamp(config.max_attempts).unwrap().unwrap();
    assert_eq!(retry.artifact_cbor, first.artifact_cbor);
    assert_eq!(retry.artifact_sha256, first.artifact_sha256);
    assert_eq!(retry.attempt, first.attempt + 1);
    assert!(
        store
            .finish_timestamp(&retry, &submit_claim(&Accepted, &retry), &config)
            .unwrap()
    );
    assert_eq!(
        store.timestamp_status(0).unwrap().unwrap().state,
        "attached"
    );
    assert_eq!(database.immutable(), immutable);
}

struct Blocked {
    started: AtomicUsize,
    release: (Mutex<bool>, Condvar),
}
impl TimestampSubmitter for Blocked {
    fn submit(&self, _: &[u8]) -> Result<Vec<u8>, ProducerError> {
        self.started.fetch_add(1, Ordering::SeqCst);
        let released = self
            .release
            .1
            .wait_timeout_while(
                self.release.0.lock().unwrap(),
                Duration::from_secs(10),
                |released| !*released,
            )
            .unwrap();
        assert!(*released.0, "test must release blocked submissions");
        Ok(b"validated-test-response".to_vec())
    }
}
impl Blocked {
    fn release(&self) {
        *self.release.0.lock().unwrap() = true;
        self.release.1.notify_all();
    }
}

async fn json_response(
    app: axum::Router,
    request: Request<Body>,
) -> (StatusCode, serde_json::Value) {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}
fn post(path: &str, key: &str, body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("Authorization", format!("Bearer {TOKEN}"))
        .header("Idempotency-Key", key)
        .header(
            "Content-Type",
            if path.ends_with("batches") {
                "application/vnd.trackone.record-batch.v1+cbor"
            } else {
                "application/cbor"
            },
        )
        .body(Body::from(body))
        .unwrap()
}
fn get(number: &str, authenticated: bool) -> Request<Body> {
    let mut builder = Request::builder().uri(format!("/v2/segments/{number}/timestamp"));
    if authenticated {
        builder = builder.header("Authorization", format!("Bearer {TOKEN}"));
    }
    builder.body(Body::empty()).unwrap()
}

#[test]
fn blocked_backlog_does_not_delay_listener_admission_or_status() {
    let Some(database) = Database::new() else {
        return;
    };
    let mut producer = database.producer();
    for counter in 0..6 {
        producer.admit(record(counter)).unwrap();
    }
    let app = router(GatewayHttpState::new(
        producer,
        AdmissionAuth::new(TOKEN, None).unwrap(),
        100,
        4096,
    ));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        // Match production ordering: bind before workers connect or process backlog.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_app = app.clone();
        let server = tokio::spawn(async move { axum::serve(listener, server_app).await.unwrap() });
        let submitter = Arc::new(Blocked {
            started: AtomicUsize::new(0),
            release: (Mutex::new(false), Condvar::new()),
        });
        let url = database.url.clone();
        let ledger = database.ledger.clone();
        let schema = database.schema.clone();
        let workers = TimestampWorkers::start(
            TimestampWorkerConfig::default(),
            submitter.clone(),
            move || {
                let mut config = url.parse::<postgres::Config>().unwrap();
                config.options(&format!("-c search_path={schema}"));
                config
                    .connect(NoTls)
                    .map(|client| PostgresLedgerStore::new(client, &ledger))
                    .map_err(|error| ProducerError::Store(error.to_string()))
            },
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(4);
        while submitter.started.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(submitter.started.load(Ordering::SeqCst), 2);
        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                tokio::net::TcpStream::connect(address)
            )
            .await
            .unwrap()
            .is_ok()
        );
        let (status, json) = tokio::time::timeout(
            Duration::from_secs(2),
            json_response(app.clone(), post("/v2/records", "single", record(7))),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED, "{json}");
        assert_eq!(json["tsa_status"], "queued");
        let (status, json) =
            json_response(app.clone(), post("/v2/records", "single", record(7))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["tsa_status"], "queued");
        let mut batch = vec![0x82];
        for counter in [8, 9] {
            let record = record(counter);
            batch.push(0x40 | record.len() as u8);
            batch.extend(record);
        }
        let (status, json) = tokio::time::timeout(
            Duration::from_secs(2),
            json_response(
                app.clone(),
                post("/v2/record-batches", "batch", batch.clone()),
            ),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED, "{json}");
        assert_eq!(json["tsa_status"], "queued");
        let replay = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v2/record-batches")
                    .header("Authorization", format!("Bearer {TOKEN}"))
                    .header("Idempotency-Key", "batch")
                    .header("Prefer", "return=minimal")
                    .header(
                        "Content-Type",
                        "application/vnd.trackone.record-batch.v1+cbor",
                    )
                    .body(Body::from(batch))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        assert_eq!(replay.headers()["preference-applied"], "return=minimal");
        assert!(to_bytes(replay.into_body(), 4096).await.unwrap().is_empty());
        for (number, authenticated, expected) in [
            ("0", false, StatusCode::UNAUTHORIZED),
            ("bad", true, StatusCode::BAD_REQUEST),
            ("18446744073709551616", true, StatusCode::BAD_REQUEST),
            ("999", true, StatusCode::NOT_FOUND),
            ("0", true, StatusCode::OK),
        ] {
            let (status, _) = json_response(app.clone(), get(number, authenticated)).await;
            assert_eq!(status, expected);
        }
        assert_eq!(submitter.started.load(Ordering::SeqCst), 2); // backlog stays bounded
        workers.stop_claiming();
        submitter.release();
        drop(workers);
        let (_, json) = json_response(app.clone(), get("0", true)).await;
        assert_eq!(json["state"], "attached");
        assert!(json["next_attempt"].is_null());
        server.abort();
    });
}

#[test]
fn digest_corruption_never_reaches_the_submitter() {
    let claim = TimestampClaim {
        segment_number: 0,
        artifact_cbor: b"corrupt".to_vec(),
        artifact_sha256: "0".repeat(64),
        attempt: 1,
    };
    assert!(
        submit_claim(&Accepted, &claim)
            .unwrap_err()
            .contains("SHA-256")
    );
}

#[test]
fn migration_upgrades_existing_backlog_without_changing_artifacts() {
    let Some(database) = Database::new() else {
        return;
    };
    let schema = format!("timestamp_upgrade_{}", database.ledger);
    let mut client = database.client();
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .unwrap();
    client
        .batch_execute(trackone_gateway_svc::postgres::MIGRATION)
        .unwrap();
    let store = PostgresLedgerStore::new(client, &database.ledger);
    let mut producer = LedgerProducer::open_or_create(
        store,
        Clock,
        &database.ledger,
        "migration-test",
        ClosurePolicy {
            interval_ms: u64::MAX,
            batch_record_limit: 1024,
            record_limit: Some(1),
            size_limit_bytes: None,
            empty_mode: EmptyMode::Suppress,
        },
    )
    .unwrap();
    producer.admit(record(1)).unwrap();
    producer.admit(record(2)).unwrap();
    let mut client = producer.into_store().into_client();
    client.execute("UPDATE trackone_vtl_sealed_segment SET tsa_status='verified', tsa_response=$2 WHERE ledger_id=$1 AND segment_number=0", &[&database.ledger, &b"retained response".as_slice()]).unwrap();
    let before: Vec<(Vec<u8>, String)> = client.query("SELECT artifact_cbor, artifact_sha256 FROM trackone_vtl_sealed_segment ORDER BY segment_number", &[]).unwrap().iter().map(|row| (row.get(0), row.get(1))).collect();
    let mut store = PostgresLedgerStore::new(client, &database.ledger);
    store.migrate().unwrap();
    store.migrate().unwrap();
    assert_eq!(
        store.timestamp_status(0).unwrap().unwrap().state,
        "attached"
    );
    assert!(
        store
            .timestamp_status(0)
            .unwrap()
            .unwrap()
            .next_attempt
            .is_none()
    );
    assert_eq!(store.timestamp_status(1).unwrap().unwrap().state, "queued");
    assert_eq!(
        store.claim_timestamp(20).unwrap().unwrap().segment_number,
        1
    );
    let mut client = store.into_client();
    let after: Vec<(Vec<u8>, String)> = client.query("SELECT artifact_cbor, artifact_sha256 FROM trackone_vtl_sealed_segment ORDER BY segment_number", &[]).unwrap().iter().map(|row| (row.get(0), row.get(1))).collect();
    assert_eq!(before, after);
    let response: Vec<u8> = client
        .query_one(
            "SELECT tsa_response FROM trackone_vtl_sealed_segment WHERE segment_number=0",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(response, b"retained response");
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .unwrap();
}

#[test]
fn terminal_failure_is_visible_on_status_and_replay_and_refuses_export() {
    use trackone_gateway_svc::snapshot::{DisclosureClass, export_snapshot};
    let Some(database) = Database::new() else {
        return;
    };
    let mut producer = database.producer();
    producer
        .admit_idempotent("failed-admission", record(1))
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let queued_error = export_snapshot(
        &mut database.client(),
        &database.ledger,
        0,
        DisclosureClass::C,
        &Default::default(),
        &temporary.path().join("queued"),
    )
    .unwrap_err();
    assert!(
        queued_error
            .to_string()
            .contains("queued export is refused")
    );
    let mut store = database.store();
    let claim = store.claim_timestamp(1).unwrap().unwrap();
    store
        .finish_timestamp(
            &claim,
            &Err("TSA unavailable".into()),
            &TimestampWorkerConfig {
                max_attempts: 1,
                ..Default::default()
            },
        )
        .unwrap();
    let failed_error = export_snapshot(
        &mut database.client(),
        &database.ledger,
        0,
        DisclosureClass::C,
        &Default::default(),
        &temporary.path().join("failed"),
    )
    .unwrap_err();
    assert!(
        failed_error
            .to_string()
            .contains("failed export is refused")
    );
    let app = router(GatewayHttpState::new(
        producer,
        AdmissionAuth::new(TOKEN, None).unwrap(),
        100,
        4096,
    ));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (status, json) = json_response(app.clone(), get("0", true)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["state"], "failed");
        assert_eq!(json["attempt_count"], "1");
        assert_eq!(json["last_error"], "TSA unavailable");
        assert!(json["next_attempt"].is_null());
        let (status, json) = json_response(
            app.clone(),
            post("/v2/records", "failed-admission", record(1)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["tsa_status"], "failed");
    });
}

struct DisconnectAfterSubmission {
    url: String,
    application: String,
    calls: AtomicUsize,
}
impl TimestampSubmitter for DisconnectAfterSubmission {
    fn submit(&self, _: &[u8]) -> Result<Vec<u8>, ProducerError> {
        assert_eq!(
            self.calls.fetch_add(1, Ordering::SeqCst),
            0,
            "a database reconnect must retain the received response"
        );
        Client::connect(&self.url, NoTls).unwrap().query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name=$1 AND pid <> pg_backend_pid()",
            &[&self.application],
        ).unwrap();
        Ok(b"validated response retained across reconnect".to_vec())
    }
}
#[test]
fn worker_reconnects_and_attaches_without_resubmitting_received_response() {
    let Some(database) = Database::new() else {
        return;
    };
    database.producer().admit(record(1)).unwrap();
    let application = format!("timestamp_reconnect_{}", database.ledger);
    let submitter = Arc::new(DisconnectAfterSubmission {
        url: database.url.clone(),
        application: application.clone(),
        calls: AtomicUsize::new(0),
    });
    let url = database.url.clone();
    let ledger = database.ledger.clone();
    let schema = database.schema.clone();
    let workers = TimestampWorkers::start(
        TimestampWorkerConfig {
            concurrency: 1,
            ..Default::default()
        },
        submitter.clone(),
        move || {
            let mut config = url.parse::<postgres::Config>().unwrap();
            config.application_name(&application);
            config.options(&format!("-c search_path={schema}"));
            config
                .connect(NoTls)
                .map(|client| PostgresLedgerStore::new(client, &ledger))
                .map_err(|error| ProducerError::Store(error.to_string()))
        },
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut store = database.store();
    while store.timestamp_status(0).unwrap().unwrap().state != "attached"
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    workers.stop_claiming();
    drop(workers);
    let status = store.timestamp_status(0).unwrap().unwrap();
    assert_eq!(status.state, "attached");
    assert_eq!(status.attempt_count, "1");
    assert_eq!(submitter.calls.load(Ordering::SeqCst), 1);
}
