//! Durable, leased RFC 3161 jobs. Remote submission is at least once; attachment
//! retains the first verified response for the exact immutable artifact digest.

use std::sync::{Arc, Condvar, Mutex, atomic::Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::Serialize;
use trackone_ledger::sha256_hex;

use crate::postgres::{PostgresLedgerStore, store_error as db_error};
use crate::producer::ProducerError;
use crate::tsa::Rfc3161TimestampAuthority;

#[derive(Clone, Debug)]
pub struct TimestampWorkerConfig {
    pub concurrency: usize,
    pub max_attempts: u32,
    pub retry_initial_ms: u64,
    pub retry_max_ms: u64,
}

impl Default for TimestampWorkerConfig {
    fn default() -> Self {
        Self {
            concurrency: 2,
            max_attempts: 20,
            retry_initial_ms: 5_000,
            retry_max_ms: 300_000,
        }
    }
}

impl TimestampWorkerConfig {
    pub fn validate(&self) -> Result<(), ProducerError> {
        if !(1..=16).contains(&self.concurrency)
            || !(1..=1_000).contains(&self.max_attempts)
            || self.retry_initial_ms == 0
            || self.retry_max_ms < self.retry_initial_ms
            || self.retry_max_ms > 86_400_000
        {
            return Err(ProducerError::TimestampConfiguration(
                "TSA worker concurrency must be 1-16, attempts 1-1000, and retry delays positive, ordered, and at most one day".into(),
            ));
        }
        Ok(())
    }

    pub fn retry_delay_ms(&self, attempt: i64) -> u64 {
        let shift = u32::try_from(attempt.saturating_sub(1)).unwrap_or(u32::MAX);
        self.retry_initial_ms
            .saturating_mul(1_u64.checked_shl(shift).unwrap_or(u64::MAX))
            .min(self.retry_max_ms)
    }
}

#[derive(Debug)]
pub struct TimestampClaim {
    pub segment_number: u64,
    pub artifact_cbor: Vec<u8>,
    pub artifact_sha256: String,
    pub attempt: i64,
}

#[derive(Debug, Serialize)]
pub struct TimestampStatus {
    pub ledger_id: String,
    pub segment_number: String,
    pub artifact_sha256: String,
    pub state: String,
    pub attempt_count: String,
    pub next_attempt: Option<String>,
    pub last_error: Option<String>,
}

impl PostgresLedgerStore {
    /// Claims one artifact, never an unbounded backlog. Claim generation is the
    /// monotonically increasing attempt count and fences expired workers.
    pub fn claim_timestamp(
        &mut self,
        max_attempts: u32,
    ) -> Result<Option<TimestampClaim>, ProducerError> {
        let mut transaction = self.client.transaction().map_err(db_error)?;
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&self.ledger_id],
            )
            .map_err(db_error)?;
        let exhausted = transaction.execute(
            "WITH exhausted AS (SELECT ledger_id, segment_number FROM trackone_vtl_sealed_segment \
             WHERE ledger_id=$1 AND tsa_status='queued' AND tsa_attempt_count >= $2 \
             AND (tsa_lease_until IS NULL OR tsa_lease_until <= CURRENT_TIMESTAMP) \
             ORDER BY tsa_next_attempt, segment_number LIMIT 100 FOR UPDATE SKIP LOCKED) \
             UPDATE trackone_vtl_sealed_segment s SET tsa_status='failed', tsa_next_attempt=NULL, \
             tsa_lease_until=NULL, tsa_last_error=COALESCE(tsa_last_error, 'final attempt lease expired before completion') \
             FROM exhausted e WHERE s.ledger_id=e.ledger_id AND s.segment_number=e.segment_number",
            &[&self.ledger_id, &i64::from(max_attempts)],
        ).map_err(db_error)?;
        let row = transaction.query_opt(
            "WITH due AS (SELECT ledger_id, segment_number FROM trackone_vtl_sealed_segment \
             WHERE ledger_id=$1 AND tsa_status='queued' AND tsa_attempt_count < $2 \
             AND tsa_next_attempt <= CURRENT_TIMESTAMP \
             AND (tsa_lease_until IS NULL OR tsa_lease_until <= CURRENT_TIMESTAMP) \
             ORDER BY tsa_next_attempt, segment_number LIMIT 1 FOR UPDATE SKIP LOCKED) \
             UPDATE trackone_vtl_sealed_segment s SET tsa_attempt_count=tsa_attempt_count+1, \
             tsa_lease_until=CURRENT_TIMESTAMP + INTERVAL '5 minutes', \
             tsa_next_attempt=CURRENT_TIMESTAMP + INTERVAL '5 minutes' \
             FROM due d WHERE s.ledger_id=d.ledger_id AND s.segment_number=d.segment_number \
             RETURNING s.segment_number::text, s.artifact_cbor, s.artifact_sha256, s.tsa_attempt_count",
            &[&self.ledger_id, &i64::from(max_attempts)],
        ).map_err(db_error)?;
        let claim = row
            .map(|row| {
                let number: String = row.get(0);
                Ok(TimestampClaim {
                    segment_number: number.parse().map_err(|_| {
                        ProducerError::Store("segment number is outside uint64".into())
                    })?,
                    artifact_cbor: row.get(1),
                    artifact_sha256: row.get(2),
                    attempt: row.get(3),
                })
            })
            .transpose()?;
        transaction.commit().map_err(db_error)?;
        self.events
            .terminal_timestamp_failures
            .fetch_add(exhausted, Ordering::Relaxed);
        Ok(claim)
    }

    /// Returns false when another claim superseded this worker. A completed
    /// matching target is success even if this attempt received another token.
    pub fn finish_timestamp(
        &mut self,
        claim: &TimestampClaim,
        result: &Result<Vec<u8>, String>,
        config: &TimestampWorkerConfig,
    ) -> Result<bool, ProducerError> {
        self.finish_timestamp_target(
            claim.segment_number,
            &claim.artifact_sha256,
            Some(claim.attempt),
            result,
            config,
        )
    }

    pub(crate) fn attach_timestamp(
        &mut self,
        number: u64,
        digest: &str,
        response: &[u8],
        generation: Option<i64>,
    ) -> Result<(), ProducerError> {
        if self.finish_timestamp_target(
            number,
            digest,
            generation,
            &Ok(response.to_vec()),
            &TimestampWorkerConfig::default(),
        )? {
            Ok(())
        } else {
            Err(ProducerError::Store(
                "timestamp target has an active or superseding claim".into(),
            ))
        }
    }

    fn finish_timestamp_target(
        &mut self,
        number: u64,
        digest: &str,
        generation: Option<i64>,
        result: &Result<Vec<u8>, String>,
        config: &TimestampWorkerConfig,
    ) -> Result<bool, ProducerError> {
        let mut transaction = self.client.transaction().map_err(db_error)?;
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&self.ledger_id],
            )
            .map_err(db_error)?;
        let number = number.to_string();
        let row = transaction.query_opt(
            "SELECT artifact_sha256, tsa_status, tsa_attempt_count, tsa_lease_until IS NOT NULL \
             FROM trackone_vtl_sealed_segment WHERE ledger_id=$1 AND segment_number=$2::text::numeric FOR UPDATE",
            &[&self.ledger_id, &number],
        ).map_err(db_error)?.ok_or_else(|| ProducerError::Store("timestamp target is missing".into()))?;
        if row.get::<_, String>(0) != digest {
            return Err(ProducerError::Store(
                "timestamp target artifact digest changed".into(),
            ));
        }
        let status: String = row.get(1);
        let attempt: i64 = row.get(2);
        if status == "verified" {
            transaction.commit().map_err(db_error)?;
            return Ok(true);
        }
        if status != "queued"
            || generation.is_some_and(|value| value != attempt)
            || (generation.is_none() && row.get::<_, bool>(3))
        {
            return Ok(false);
        }
        match result {
            Ok(response) => {
                if response.is_empty() {
                    return Err(ProducerError::Store(
                        "cannot attach an empty timestamp response".into(),
                    ));
                }
                transaction.execute(
                    "UPDATE trackone_vtl_sealed_segment SET tsa_response=$3, tsa_status='verified', \
                     tsa_next_attempt=NULL, tsa_lease_until=NULL, tsa_last_error=NULL, tsa_attached_at=CURRENT_TIMESTAMP \
                     WHERE ledger_id=$1 AND segment_number=$2::text::numeric",
                    &[&self.ledger_id, &number, &response],
                ).map_err(db_error)?;
            }
            Err(error) => {
                let error: String = error
                    .chars()
                    .filter(|ch| !ch.is_control())
                    .take(512)
                    .collect();
                let status = if attempt >= i64::from(config.max_attempts) {
                    "failed"
                } else {
                    "queued"
                };
                let delay = config.retry_delay_ms(attempt) as f64;
                transaction.execute(
                    "UPDATE trackone_vtl_sealed_segment SET tsa_status=$3, tsa_lease_until=NULL, \
                     tsa_last_error=$4, tsa_next_attempt=CASE WHEN $3='failed' THEN NULL \
                     ELSE CURRENT_TIMESTAMP + $5::double precision * INTERVAL '1 millisecond' END \
                     WHERE ledger_id=$1 AND segment_number=$2::text::numeric",
                    &[&self.ledger_id, &number, &status, &error, &delay],
                ).map_err(db_error)?;
            }
        }
        transaction.commit().map_err(db_error)?;
        if result.is_ok() {
            self.events
                .storage_unavailable
                .store(false, Ordering::Relaxed);
        }
        if result.is_err() && attempt >= i64::from(config.max_attempts) {
            self.events
                .terminal_timestamp_failures
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(true)
    }

    pub fn timestamp_status(
        &mut self,
        number: u64,
    ) -> Result<Option<TimestampStatus>, ProducerError> {
        self.client.query_opt(
            "SELECT artifact_sha256, tsa_status, tsa_attempt_count::text, \
             to_char(tsa_next_attempt AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'), tsa_last_error \
             FROM trackone_vtl_sealed_segment WHERE ledger_id=$1 AND segment_number=$2::text::numeric",
            &[&self.ledger_id, &number.to_string()],
        ).map_err(db_error).map(|row| row.map(|row| {
            let state: String = row.get(1);
            TimestampStatus {
                ledger_id: self.ledger_id.clone(), segment_number: number.to_string(),
                artifact_sha256: row.get(0), state: if state == "verified" { "attached".into() } else { state },
                attempt_count: row.get(2), next_attempt: row.get(3), last_error: row.get(4),
            }
        }))
    }
}

/// Implementations return only responses validated against the artifact digest.
pub trait TimestampSubmitter: Send + Sync + 'static {
    fn submit(&self, artifact: &[u8]) -> Result<Vec<u8>, ProducerError>;
}

impl TimestampSubmitter for Rfc3161TimestampAuthority {
    fn submit(&self, artifact: &[u8]) -> Result<Vec<u8>, ProducerError> {
        self.stamp(artifact).map(|response| response.response_der)
    }
}

pub fn submit_claim(
    submitter: &dyn TimestampSubmitter,
    claim: &TimestampClaim,
) -> Result<Vec<u8>, String> {
    if sha256_hex(&claim.artifact_cbor) != claim.artifact_sha256 {
        return Err("stored artifact does not match its SHA-256 digest".into());
    }
    submitter
        .submit(&claim.artifact_cbor)
        .map_err(|error| error.to_string())
}

// A condition variable makes shutdown interrupt idle polling immediately.
type Stop = Arc<(Mutex<bool>, Condvar)>;

pub struct TimestampWorkers {
    stop: Stop,
    handles: Vec<JoinHandle<()>>,
}

impl TimestampWorkers {
    pub fn start<F>(
        config: TimestampWorkerConfig,
        submitter: Arc<dyn TimestampSubmitter>,
        connect: F,
    ) -> Result<Self, ProducerError>
    where
        F: Fn() -> Result<PostgresLedgerStore, ProducerError> + Send + Sync + 'static,
    {
        config.validate()?;
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let connect = Arc::new(connect);
        let mut workers = Self {
            stop,
            handles: Vec::new(),
        };
        for index in 0..config.concurrency {
            let stop = Arc::clone(&workers.stop);
            let connect = Arc::clone(&connect);
            let submitter = Arc::clone(&submitter);
            let config = config.clone();
            let handle = thread::Builder::new()
                .name(format!("trackone-tsa-{index}"))
                .spawn(move || {
                    let mut store = None;
                    // Retain a response across database reconnects, without resubmitting.
                    let mut pending = None;
                    while !stopped(&stop) {
                        if store.is_none() {
                            match connect() {
                                Ok(mut connected) => {
                                    match connected.client.batch_execute(
                                        "SET statement_timeout='10s'; SET lock_timeout='5s'",
                                    ) {
                                        Ok(()) => store = Some(connected),
                                        Err(error) => eprintln!(
                                            "timestamp worker database setup failed: {error}"
                                        ),
                                    }
                                }
                                Err(error) => {
                                    eprintln!("timestamp worker connection failed: {error}")
                                }
                            }
                            if store.is_none() {
                                pause(&stop);
                                continue;
                            }
                        }
                        let Some(connected) = store.as_mut() else {
                            pause(&stop);
                            continue;
                        };
                        if let Some((claim, result)) = pending.as_ref() {
                            match connected.finish_timestamp(claim, result, &config) {
                                Ok(_) => pending = None,
                                Err(error) => {
                                    if matches!(error, ProducerError::StorageUnavailable(_)) {
                                        connected
                                            .events
                                            .storage_unavailable
                                            .store(true, Ordering::Relaxed);
                                    }
                                    eprintln!("timestamp worker completion failed: {error}");
                                    store = None;
                                    pause(&stop);
                                }
                            }
                            continue;
                        }
                        if stopped(&stop) {
                            break;
                        }
                        match connected.claim_timestamp(config.max_attempts) {
                            Ok(Some(claim)) => {
                                // A committed claim consumes an attempt. Process it even
                                // when shutdown arrived while the claim was in flight.
                                let result = submit_claim(submitter.as_ref(), &claim);
                                if let Err(error) = &result {
                                    eprintln!(
                                        "timestamp submission failed for segment {}: {error}",
                                        claim.segment_number
                                    );
                                }
                                // Finish even when shutdown arrived during remote submission.
                                match connected.finish_timestamp(&claim, &result, &config) {
                                    Ok(_) => (),
                                    Err(error) => {
                                        if matches!(error, ProducerError::StorageUnavailable(_)) {
                                            connected
                                                .events
                                                .storage_unavailable
                                                .store(true, Ordering::Relaxed);
                                        }
                                        eprintln!("timestamp worker completion failed: {error}");
                                        pending = Some((claim, result));
                                        store = None;
                                        pause(&stop);
                                    }
                                }
                            }
                            Ok(None) => pause(&stop),
                            Err(error) => {
                                if matches!(error, ProducerError::StorageUnavailable(_)) {
                                    connected
                                        .events
                                        .storage_unavailable
                                        .store(true, Ordering::Relaxed);
                                }
                                eprintln!("timestamp worker claim failed: {error}");
                                store = None;
                                pause(&stop);
                            }
                        }
                    }
                })
                .map_err(|error| ProducerError::Store(error.to_string()))?;
            workers.handles.push(handle);
        }
        Ok(workers)
    }

    pub fn stop_claiming(&self) {
        *self
            .stop
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        self.stop.1.notify_all();
    }
}

impl Drop for TimestampWorkers {
    fn drop(&mut self) {
        self.stop_claiming();
        for handle in self.handles.drain(..) {
            if handle.join().is_err() {
                eprintln!("timestamp worker panicked; its durable claim will expire");
            }
        }
    }
}

fn stopped(stop: &Stop) -> bool {
    // A poisoned shutdown mutex stops further claims rather than panicking.
    stop.0.lock().map_or(true, |guard| *guard)
}
fn pause(stop: &Stop) {
    let Ok(guard) = stop.0.lock() else {
        return;
    };
    let _ = stop
        .1
        .wait_timeout_while(guard, Duration::from_secs(1), |value| !*value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poisoned_shutdown_mutex_stops_claims_and_allows_cleanup() {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let poison = Arc::clone(&stop);
        assert!(
            thread::spawn(move || {
                let _guard = poison.0.lock().unwrap();
                panic!("simulate a panic while holding the shutdown mutex");
            })
            .join()
            .is_err()
        );
        assert!(stopped(&stop));
        pause(&stop);
        let workers = TimestampWorkers {
            stop,
            handles: Vec::new(),
        };
        workers.stop_claiming();
        drop(workers);
    }

    #[test]
    fn backoff_is_capped_and_overflow_safe() {
        let config = TimestampWorkerConfig::default();
        for (attempt, expected) in [
            (1, 5_000),
            (2, 10_000),
            (6, 160_000),
            (7, 300_000),
            (i64::MAX, 300_000),
        ] {
            assert_eq!(config.retry_delay_ms(attempt), expected);
        }
    }

    #[test]
    fn invalid_worker_configuration_is_rejected() {
        for config in [
            TimestampWorkerConfig {
                concurrency: 0,
                ..Default::default()
            },
            TimestampWorkerConfig {
                concurrency: 17,
                ..Default::default()
            },
            TimestampWorkerConfig {
                max_attempts: 0,
                ..Default::default()
            },
            TimestampWorkerConfig {
                max_attempts: 1_001,
                ..Default::default()
            },
            TimestampWorkerConfig {
                retry_initial_ms: 0,
                ..Default::default()
            },
            TimestampWorkerConfig {
                retry_max_ms: 1,
                ..Default::default()
            },
            TimestampWorkerConfig {
                retry_max_ms: 86_400_001,
                ..Default::default()
            },
        ] {
            assert!(config.validate().is_err());
        }
        TimestampWorkerConfig::default().validate().unwrap();
    }
}
