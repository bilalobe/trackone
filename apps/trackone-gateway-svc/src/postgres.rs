//! PostgreSQL durable store for the draft-08 v2 producer.

use postgres::{Client, IsolationLevel};
use trackone_ledger::v2::{ClosurePolicyV1, EmptyMode};

use crate::producer::{
    IdempotencyRecord, LedgerStore, OpenInterval, ProducerError, ProducerState, SealedSegment,
};

pub const MIGRATION: &str = include_str!("../migrations/0001_v2_ledger.sql");

pub struct PostgresLedgerStore {
    client: Client,
    ledger_id: String,
}

impl PostgresLedgerStore {
    pub fn new(client: Client, ledger_id: impl Into<String>) -> Self {
        Self {
            client,
            ledger_id: ledger_id.into(),
        }
    }

    pub fn migrate(&mut self) -> Result<(), ProducerError> {
        self.client.batch_execute(MIGRATION).map_err(store_error)
    }

    pub fn into_client(self) -> Client {
        self.client
    }

    pub fn load_pending_tsa_segments(
        &mut self,
    ) -> Result<Vec<(u64, Vec<u8>, String)>, ProducerError> {
        let rows = self
            .client
            .query(
                "SELECT segment_number::text, artifact_cbor, artifact_sha256 \
                 FROM trackone_v2_sealed_segment \
                 WHERE ledger_id=$1 AND tsa_status='pending' ORDER BY segment_number",
                &[&self.ledger_id],
            )
            .map_err(store_error)?;
        rows.into_iter()
            .map(|row| {
                Ok((
                    parse_u64(row.get(0), "segment_number")?,
                    row.get(1),
                    row.get(2),
                ))
            })
            .collect()
    }

    pub fn attach_tsa_response(
        &mut self,
        segment_number: u64,
        artifact_sha256: &str,
        response: &[u8],
    ) -> Result<(), ProducerError> {
        let segment_number = numeric(segment_number);
        let changed = self
            .client
            .execute(
                "UPDATE trackone_v2_sealed_segment SET tsa_response=$4, tsa_status='verified' \
                 WHERE ledger_id=$1 AND segment_number=$2::numeric AND artifact_sha256=$3 \
                 AND tsa_status='pending'",
                &[
                    &self.ledger_id,
                    &segment_number,
                    &artifact_sha256,
                    &response,
                ],
            )
            .map_err(store_error)?;
        if changed != 1 {
            return Err(ProducerError::Store(
                "TSA response target is missing, changed, or already complete".to_string(),
            ));
        }
        Ok(())
    }
}

fn store_error(error: postgres::Error) -> ProducerError {
    ProducerError::Store(error.to_string())
}

fn parse_u64(value: String, field: &'static str) -> Result<u64, ProducerError> {
    value
        .parse()
        .map_err(|_| ProducerError::Store(format!("database {field} is outside uint64")))
}

fn parse_u128(value: String, field: &'static str) -> Result<u128, ProducerError> {
    value
        .parse()
        .map_err(|_| ProducerError::Store(format!("database {field} is outside uint128")))
}

fn parse_optional_u64(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<u64>, ProducerError> {
    value.map(|item| parse_u64(item, field)).transpose()
}

fn parse_empty_mode(value: &str) -> Result<EmptyMode, ProducerError> {
    match value {
        "emit" => Ok(EmptyMode::Emit),
        "suppress" => Ok(EmptyMode::Suppress),
        _ => Err(ProducerError::Store(
            "database empty_mode is unsupported".to_string(),
        )),
    }
}

fn numeric(value: u64) -> String {
    value.to_string()
}

fn optional_numeric(value: Option<u64>) -> Option<String> {
    value.map(|item| item.to_string())
}

impl LedgerStore for PostgresLedgerStore {
    fn load(&mut self) -> Result<Option<ProducerState>, ProducerError> {
        let row = self
            .client
            .query_opt(
                "SELECT revision::text, site_id, next_segment_number::text, predecessor_cbor, \
                 opened_at_ms::text, clock_continuity_id::text, open_interval_ms::text, \
                 open_batch_record_limit::text, open_record_limit::text, \
                 open_size_limit_bytes::text, open_empty_mode, byte_count::text, \
                 next_interval_ms::text, next_batch_record_limit::text, \
                 next_record_limit::text, next_size_limit_bytes::text, next_empty_mode \
                 FROM trackone_v2_ledger_state WHERE ledger_id = $1",
                &[&self.ledger_id],
            )
            .map_err(store_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let records = self
            .client
            .query(
                "SELECT record_cbor FROM trackone_v2_open_record \
                 WHERE ledger_id = $1 ORDER BY ordinal",
                &[&self.ledger_id],
            )
            .map_err(store_error)?
            .into_iter()
            .map(|row| row.get::<_, Vec<u8>>(0))
            .collect();
        let open_policy = ClosurePolicyV1 {
            interval_ms: parse_u64(row.get(6), "open_interval_ms")?,
            batch_record_limit: parse_u64(row.get(7), "open_batch_record_limit")?,
            record_limit: parse_optional_u64(row.get(8), "open_record_limit")?,
            size_limit_bytes: parse_optional_u64(row.get(9), "open_size_limit_bytes")?,
            empty_mode: parse_empty_mode(row.get(10))?,
        };
        let next_policy = ClosurePolicyV1 {
            interval_ms: parse_u64(row.get(12), "next_interval_ms")?,
            batch_record_limit: parse_u64(row.get(13), "next_batch_record_limit")?,
            record_limit: parse_optional_u64(row.get(14), "next_record_limit")?,
            size_limit_bytes: parse_optional_u64(row.get(15), "next_size_limit_bytes")?,
            empty_mode: parse_empty_mode(row.get(16))?,
        };
        Ok(Some(ProducerState {
            revision: parse_u64(row.get(0), "revision")?,
            ledger_id: self.ledger_id.clone(),
            site_id: row.get(1),
            next_segment_number: parse_u64(row.get(2), "next_segment_number")?,
            predecessor_cbor: row.get(3),
            open: OpenInterval {
                opened_at_ms: parse_u64(row.get(4), "opened_at_ms")?,
                clock_continuity_id: parse_u128(row.get(5), "clock_continuity_id")?,
                policy: open_policy,
                records,
                byte_count: parse_u64(row.get(11), "byte_count")?,
            },
            next_policy,
        }))
    }

    fn lookup_idempotency(
        &mut self,
        key: &str,
    ) -> Result<Option<IdempotencyRecord>, ProducerError> {
        let row = self
            .client
            .query_opt(
                "SELECT record_sha256, admitted_segment_number::text, state_revision::text, \
                 sealed_segment_numbers \
                 FROM trackone_v2_idempotency WHERE ledger_id=$1 AND idempotency_key=$2",
                &[&self.ledger_id, &key],
            )
            .map_err(store_error)?;
        row.map(|row| {
            let sealed: Vec<String> = row.get(3);
            Ok(IdempotencyRecord {
                key: key.to_string(),
                record_sha256: row.get(0),
                admitted_segment_number: parse_u64(row.get(1), "admitted_segment_number")?,
                state_revision: parse_u64(row.get(2), "state_revision")?,
                sealed_segment_numbers: sealed
                    .into_iter()
                    .map(|value| parse_u64(value, "sealed_segment_number"))
                    .collect::<Result<Vec<_>, _>>()?,
            })
        })
        .transpose()
    }

    fn compare_and_swap(
        &mut self,
        expected_revision: Option<u64>,
        state: &ProducerState,
        sealed: &[SealedSegment],
        admission: Option<&IdempotencyRecord>,
    ) -> Result<(), ProducerError> {
        if state.ledger_id != self.ledger_id {
            return Err(ProducerError::Store(
                "store ledger_id does not match producer state".to_string(),
            ));
        }
        let mut transaction = self
            .client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(store_error)?;
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&self.ledger_id],
            )
            .map_err(store_error)?;

        let revision = numeric(state.revision);
        let next_segment_number = numeric(state.next_segment_number);
        let opened_at_ms = numeric(state.open.opened_at_ms);
        let clock_continuity_id = state.open.clock_continuity_id.to_string();
        let open_interval_ms = numeric(state.open.policy.interval_ms);
        let open_batch_limit = numeric(state.open.policy.batch_record_limit);
        let open_record_limit = optional_numeric(state.open.policy.record_limit);
        let open_size_limit = optional_numeric(state.open.policy.size_limit_bytes);
        let byte_count = numeric(state.open.byte_count);
        let next_interval_ms = numeric(state.next_policy.interval_ms);
        let next_batch_limit = numeric(state.next_policy.batch_record_limit);
        let next_record_limit = optional_numeric(state.next_policy.record_limit);
        let next_size_limit = optional_numeric(state.next_policy.size_limit_bytes);

        let changed = if let Some(expected) = expected_revision {
            let expected = numeric(expected);
            transaction
                .execute(
                    "UPDATE trackone_v2_ledger_state SET revision=$2::numeric, site_id=$3, \
                     next_segment_number=$4::numeric, predecessor_cbor=$5, opened_at_ms=$6::numeric, \
                     clock_continuity_id=$7::numeric, open_interval_ms=$8::numeric, \
                     open_batch_record_limit=$9::numeric, open_record_limit=$10::numeric, \
                     open_size_limit_bytes=$11::numeric, open_empty_mode=$12, byte_count=$13::numeric, \
                     next_interval_ms=$14::numeric, next_batch_record_limit=$15::numeric, \
                     next_record_limit=$16::numeric, next_size_limit_bytes=$17::numeric, \
                     next_empty_mode=$18 WHERE ledger_id=$1 AND revision=$19::numeric",
                    &[&state.ledger_id, &revision, &state.site_id, &next_segment_number,
                      &state.predecessor_cbor, &opened_at_ms, &clock_continuity_id,
                      &open_interval_ms, &open_batch_limit, &open_record_limit,
                      &open_size_limit, &state.open.policy.empty_mode.as_str(), &byte_count,
                      &next_interval_ms, &next_batch_limit, &next_record_limit,
                      &next_size_limit, &state.next_policy.empty_mode.as_str(), &expected],
                )
                .map_err(store_error)?
        } else {
            transaction
                .execute(
                    "INSERT INTO trackone_v2_ledger_state \
                     (ledger_id, revision, site_id, next_segment_number, predecessor_cbor, \
                      opened_at_ms, clock_continuity_id, open_interval_ms, \
                      open_batch_record_limit, open_record_limit, open_size_limit_bytes, \
                      open_empty_mode, byte_count, next_interval_ms, next_batch_record_limit, \
                      next_record_limit, next_size_limit_bytes, next_empty_mode) VALUES \
                     ($1,$2::numeric,$3,$4::numeric,$5,$6::numeric,$7::numeric,$8::numeric, \
                      $9::numeric,$10::numeric,$11::numeric,$12,$13::numeric,$14::numeric, \
                      $15::numeric,$16::numeric,$17::numeric,$18) ON CONFLICT DO NOTHING",
                    &[
                        &state.ledger_id,
                        &revision,
                        &state.site_id,
                        &next_segment_number,
                        &state.predecessor_cbor,
                        &opened_at_ms,
                        &clock_continuity_id,
                        &open_interval_ms,
                        &open_batch_limit,
                        &open_record_limit,
                        &open_size_limit,
                        &state.open.policy.empty_mode.as_str(),
                        &byte_count,
                        &next_interval_ms,
                        &next_batch_limit,
                        &next_record_limit,
                        &next_size_limit,
                        &state.next_policy.empty_mode.as_str(),
                    ],
                )
                .map_err(store_error)?
        };
        if changed != 1 {
            return Err(ProducerError::ConcurrentWriter);
        }

        transaction
            .execute(
                "DELETE FROM trackone_v2_open_record WHERE ledger_id=$1",
                &[&state.ledger_id],
            )
            .map_err(store_error)?;
        for (ordinal, record) in state.open.records.iter().enumerate() {
            let ordinal = ordinal.to_string();
            transaction
                .execute(
                    "INSERT INTO trackone_v2_open_record (ledger_id, ordinal, record_cbor) \
                     VALUES ($1,$2::numeric,$3)",
                    &[&state.ledger_id, &ordinal, record],
                )
                .map_err(store_error)?;
        }
        for segment in sealed {
            let segment_number = numeric(segment.segment_number);
            transaction
                .execute(
                    "INSERT INTO trackone_v2_sealed_segment \
                     (ledger_id, segment_number, close_reason, artifact_cbor, artifact_sha256) \
                     VALUES ($1,$2::numeric,$3,$4,$5)",
                    &[
                        &state.ledger_id,
                        &segment_number,
                        &segment.close_reason.as_str(),
                        &segment.artifact_cbor,
                        &segment.artifact_sha256,
                    ],
                )
                .map_err(store_error)?;
            for (ordinal, record) in segment.records.iter().enumerate() {
                let ordinal = ordinal.to_string();
                transaction
                    .execute(
                        "INSERT INTO trackone_v2_sealed_record \
                         (ledger_id, segment_number, ordinal, record_cbor) \
                         VALUES ($1,$2::numeric,$3::numeric,$4)",
                        &[&state.ledger_id, &segment_number, &ordinal, record],
                    )
                    .map_err(store_error)?;
            }
        }
        if let Some(admission) = admission {
            let admitted_segment_number = numeric(admission.admitted_segment_number);
            let state_revision = numeric(admission.state_revision);
            let sealed_segment_numbers = admission
                .sealed_segment_numbers
                .iter()
                .map(|number| numeric(*number))
                .collect::<Vec<_>>();
            let inserted = transaction
                .execute(
                    "INSERT INTO trackone_v2_idempotency \
                     (ledger_id, idempotency_key, record_sha256, admitted_segment_number, \
                      state_revision, sealed_segment_numbers) \
                     VALUES ($1,$2,$3,$4::numeric,$5::numeric,$6) \
                     ON CONFLICT DO NOTHING",
                    &[
                        &state.ledger_id,
                        &admission.key,
                        &admission.record_sha256,
                        &admitted_segment_number,
                        &state_revision,
                        &sealed_segment_numbers,
                    ],
                )
                .map_err(store_error)?;
            if inserted != 1 {
                return Err(ProducerError::ConcurrentWriter);
            }
        }
        transaction.commit().map_err(store_error)
    }
}
