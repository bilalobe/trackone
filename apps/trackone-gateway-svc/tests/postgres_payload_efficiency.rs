use postgres::{Client, NoTls};
use std::time::{SystemTime, UNIX_EPOCH};
use trackone_gateway_svc::postgres::PostgresLedgerStore;
use trackone_gateway_svc::producer::{ElapsedClock, ProducerError, V2LedgerProducer};
use trackone_ledger::v2::{ClosurePolicyV1, EmptyMode};

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
    vec![
        0x87, 0x01, 0x48, 0, 0, 0, 0, 0, 0, 0, counter, counter, 0, 0xf6, 0, 0xf6,
    ]
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
    let policy = ClosurePolicyV1 {
        interval_ms: u64::MAX,
        batch_record_limit: 1_000,
        record_limit: Some(1_000),
        size_limit_bytes: None,
        empty_mode: EmptyMode::Suppress,
    };
    let mut producer = V2LedgerProducer::open_or_create(
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
             (SELECT count(*) FROM trackone_v2_open_record WHERE ledger_id=$1), \
             (SELECT count(*) FROM trackone_v2_sealed_record WHERE ledger_id=$1), \
             predecessor_cbor IS NULL \
             FROM trackone_v2_ledger_state WHERE ledger_id=$1",
            &[&ledger_id],
        )
        .unwrap();
    assert_eq!(rows.get::<_, i64>(0), 999);
    assert_eq!(rows.get::<_, i64>(1), 0);
    assert!(rows.get::<_, bool>(2));

    let store =
        PostgresLedgerStore::new(Client::connect(&database_url, NoTls).unwrap(), &ledger_id);
    let mut producer = V2LedgerProducer::open_or_create(
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
             (SELECT count(*) FROM trackone_v2_open_record WHERE ledger_id=$1), \
             (SELECT count(*) FROM trackone_v2_sealed_record WHERE ledger_id=$1), \
             predecessor_cbor \
             FROM trackone_v2_ledger_state WHERE ledger_id=$1",
            &[&ledger_id],
        )
        .unwrap();
    assert_eq!(rows.get::<_, i64>(0), 0);
    assert_eq!(rows.get::<_, i64>(1), 1_000);
    let predecessor: Vec<u8> = rows.get(2);

    let store =
        PostgresLedgerStore::new(Client::connect(&database_url, NoTls).unwrap(), &ledger_id);
    let mut restarted = V2LedgerProducer::open_or_create(
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
    let mut client = restarted.into_store().into_client();
    let retained: Vec<u8> = client
        .query_one(
            "SELECT predecessor_cbor FROM trackone_v2_ledger_state WHERE ledger_id=$1",
            &[&ledger_id],
        )
        .unwrap()
        .get(0);
    assert_eq!(retained, predecessor);

    client
        .execute(
            "DELETE FROM trackone_v2_sealed_segment WHERE ledger_id=$1",
            &[&ledger_id],
        )
        .unwrap();
    client
        .execute(
            "DELETE FROM trackone_v2_ledger_state WHERE ledger_id=$1",
            &[&ledger_id],
        )
        .unwrap();
}
