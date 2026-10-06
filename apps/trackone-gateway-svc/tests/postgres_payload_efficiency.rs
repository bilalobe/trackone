use postgres::{Client, NoTls};
use std::time::{SystemTime, UNIX_EPOCH};
use trackone_gateway_svc::postgres::PostgresLedgerStore;
use trackone_gateway_svc::producer::{ElapsedClock, LedgerProducer, ProducerError};
use trackone_ledger::sha256_digest;
use trackone_ledger::vtl::{ClosurePolicy, EmptyMode};
use trackone_rfc3161::{HistoricalValidationArchive, VerificationPolicy, verify_response};

#[derive(Clone, Copy)]
struct FixedClock;

impl ElapsedClock for FixedClock {
    fn now_ms(&self) -> Result<u64, ProducerError> {
        Ok(0)
    }

    fn continuity_id(&self) -> u128 {
        1
    }
}

fn record(counter: u8) -> Vec<u8> {
    let mut encoded = vec![0x87, 0x01, 0x48, 0, 0, 0, 0, 0, 0, 0, counter];
    for _ in 0..2 {
        if counter < 24 {
            encoded.push(counter);
        } else {
            encoded.extend_from_slice(&[0x18, counter]);
        }
    }
    encoded.extend_from_slice(&[0xf6, 0, 0xf6]);
    encoded
}

#[test]
fn postgres_appends_moves_and_replays_batch_state_across_restart() {
    let Ok(database_url) = std::env::var("TRACKONE_TEST_DATABASE_URL") else {
        eprintln!("skipping: TRACKONE_TEST_DATABASE_URL is not configured");
        return;
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let ledger_id = format!("{unique:032x}");
    let mut store =
        PostgresLedgerStore::new(Client::connect(&database_url, NoTls).unwrap(), &ledger_id);
    store.migrate().unwrap();
    store.migrate().unwrap();
    let policy = ClosurePolicy {
        interval_ms: u64::MAX,
        batch_record_limit: 1_024,
        record_limit: Some(1_000),
        size_limit_bytes: None,
        empty_mode: EmptyMode::Suppress,
    };
    let mut producer = LedgerProducer::open_or_create(
        store,
        FixedClock,
        &ledger_id,
        "postgres-payload-test",
        policy.clone(),
    )
    .unwrap();

    for counter in 0..999 {
        producer.admit(record((counter % 251) as u8)).unwrap();
    }
    let store = producer.into_store();
    let rows = store
        .into_client()
        .query_one(
            "SELECT \
             (SELECT count(*) FROM trackone_vtl_open_record WHERE ledger_id=$1), \
             (SELECT count(*) FROM trackone_vtl_sealed_record WHERE ledger_id=$1), \
             predecessor_cbor IS NULL \
             FROM trackone_vtl_ledger_state WHERE ledger_id=$1",
            &[&ledger_id],
        )
        .unwrap();
    assert_eq!(rows.get::<_, i64>(0), 999);
    assert_eq!(rows.get::<_, i64>(1), 0);
    assert!(rows.get::<_, bool>(2));

    let store =
        PostgresLedgerStore::new(Client::connect(&database_url, NoTls).unwrap(), &ledger_id);
    let mut producer = LedgerProducer::open_or_create(
        store,
        FixedClock,
        &ledger_id,
        "postgres-payload-test",
        policy.clone(),
    )
    .unwrap();
    let final_record = record(252);
    let outcome = producer
        .admit_idempotent("sealing-request", final_record.clone())
        .unwrap();
    assert_eq!(outcome.sealed_segment_numbers, vec![0]);

    let mut client = producer.into_store().into_client();
    let rows = client
        .query_one(
            "SELECT \
             (SELECT count(*) FROM trackone_vtl_open_record WHERE ledger_id=$1), \
             (SELECT count(*) FROM trackone_vtl_sealed_record WHERE ledger_id=$1), \
             predecessor_cbor \
             FROM trackone_vtl_ledger_state WHERE ledger_id=$1",
            &[&ledger_id],
        )
        .unwrap();
    assert_eq!(rows.get::<_, i64>(0), 0);
    assert_eq!(rows.get::<_, i64>(1), 1_000);
    let predecessor: Vec<u8> = rows.get(2);

    let store =
        PostgresLedgerStore::new(Client::connect(&database_url, NoTls).unwrap(), &ledger_id);
    let mut restarted = LedgerProducer::open_or_create(
        store,
        FixedClock,
        &ledger_id,
        "postgres-payload-test",
        policy,
    )
    .unwrap();
    assert!(
        restarted
            .admit_idempotent("sealing-request", final_record)
            .unwrap()
            .replayed
    );
    restarted.admit(record(253)).unwrap();
    let queued = restarted.store_mut().load_queued_tsa_segments().unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].0, 0);
    assert_eq!(
        restarted.store_mut().tsa_statuses(&[0]).unwrap(),
        vec!["queued"]
    );
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/trackone-rfc3161/tests/fixtures");
    let verification_policy = VerificationPolicy::new(
        HistoricalValidationArchive {
            trust_anchors_file: fixtures.join("tsa-root.pem"),
            intermediates_file: None,
            crls_file: fixtures.join("tsa-crls.pem"),
        },
        "1.3.6.1.4.1.55555.1",
        "14ab98cafe09d9d1d01562af42d69a904b01023d9cd5b03bd07e5779710c8014"
            .parse()
            .unwrap(),
    )
    .unwrap();
    assert!(
        verify_response(
            &std::fs::read(fixtures.join("response.tsr")).unwrap(),
            sha256_digest(&queued[0].1),
            &verification_policy,
        )
        .is_err()
    );
    // A rejected response leaves the durable obligation available for retry.
    assert_eq!(
        restarted.store_mut().load_queued_tsa_segments().unwrap(),
        queued
    );
    restarted
        .store_mut()
        .attach_tsa_response(queued[0].0, &queued[0].2, b"test-response")
        .unwrap();
    assert_eq!(
        restarted.store_mut().tsa_statuses(&[0]).unwrap(),
        vec!["verified"]
    );
    let mut client = restarted.into_store().into_client();
    let retained: Vec<u8> = client
        .query_one(
            "SELECT predecessor_cbor FROM trackone_vtl_ledger_state WHERE ledger_id=$1",
            &[&ledger_id],
        )
        .unwrap()
        .get(0);
    assert_eq!(retained, predecessor);

    client
        .execute(
            "DELETE FROM trackone_vtl_sealed_segment WHERE ledger_id=$1",
            &[&ledger_id],
        )
        .unwrap();
    client
        .execute(
            "DELETE FROM trackone_vtl_ledger_state WHERE ledger_id=$1",
            &[&ledger_id],
        )
        .unwrap();
}
