//! Draft-08 gateway-service ledger producer state machine.
//!
//! The protocol rules live here independently of a concrete database. A store
//! commits the complete state transition and any sealed artifacts atomically;
//! production deployments can implement that contract with PostgreSQL while
//! tests use the in-memory implementation below.

use std::collections::BTreeMap;
use std::fmt;
use trackone_ledger::v2::{
    ClosurePolicyV1, EmptyMode, SegmentBatchV2, SegmentRecordV2, merkle_root_from_leaf_hashes,
    merkle_root_from_records, validate_canonical_record_v2,
};
use trackone_ledger::{hex_lower, sha256_hex};

/// A non-decreasing elapsed-time source. `continuity_id` changes whenever a
/// persisted tick can no longer be compared safely with current ticks.
pub trait ElapsedClock {
    fn now_ms(&self) -> Result<u64, ProducerError>;
    fn continuity_id(&self) -> u128;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenInterval {
    pub opened_at_ms: u64,
    pub clock_continuity_id: u128,
    pub policy: ClosurePolicyV1,
    pub records: Vec<Vec<u8>>,
    pub byte_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProducerState {
    pub revision: u64,
    pub ledger_id: String,
    pub site_id: String,
    pub next_segment_number: u64,
    pub predecessor_cbor: Option<Vec<u8>>,
    pub open: OpenInterval,
    pub next_policy: ClosurePolicyV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedSegment {
    pub segment_number: u64,
    pub close_reason: CloseReason,
    pub artifact_cbor: Vec<u8>,
    pub artifact_sha256: String,
    pub records: Vec<Vec<u8>>,
}

/// The store must make the state and all sealed artifacts in one call durable
/// as a single transaction before returning success.
pub trait LedgerStore {
    fn load(&mut self) -> Result<Option<ProducerState>, ProducerError>;
    fn lookup_idempotency(&mut self, key: &str)
    -> Result<Option<IdempotencyRecord>, ProducerError>;
    fn compare_and_swap(
        &mut self,
        expected_revision: Option<u64>,
        state: &ProducerState,
        sealed: &[SealedSegment],
        admission: Option<&IdempotencyRecord>,
    ) -> Result<(), ProducerError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    Recovery,
    Shutdown,
    Reconfigure,
    SizeLimit,
    RecordLimit,
    Interval,
    Manual,
}

impl CloseReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recovery => "recovery",
            Self::Shutdown => "shutdown",
            Self::Reconfigure => "reconfigure",
            Self::SizeLimit => "size_limit",
            Self::RecordLimit => "record_limit",
            Self::Interval => "interval",
            Self::Manual => "manual",
        }
    }

    const fn precedence(self) -> u8 {
        match self {
            Self::Recovery => 7,
            Self::Shutdown => 6,
            Self::Reconfigure => 5,
            Self::SizeLimit => 4,
            Self::RecordLimit => 3,
            Self::Interval => 2,
            Self::Manual => 1,
        }
    }

    pub fn highest(reasons: impl IntoIterator<Item = Self>) -> Option<Self> {
        reasons.into_iter().max_by_key(|reason| reason.precedence())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionOutcome {
    pub state_revision: u64,
    pub admitted_segment_number: u64,
    pub sealed: Vec<SealedSegment>,
    pub sealed_segment_numbers: Vec<u64>,
    pub replayed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdempotencyRecord {
    pub key: String,
    pub record_sha256: String,
    pub admitted_segment_number: u64,
    pub state_revision: u64,
    pub sealed_segment_numbers: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProducerError {
    InvalidConfiguration(&'static str),
    InvalidRecord(String),
    Clock(String),
    ClockDiscontinuity,
    SerialExhausted,
    CounterOverflow(&'static str),
    Store(String),
    ConcurrentWriter,
    IdempotencyConflict,
    Construction(String),
}

impl fmt::Display for ProducerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => formatter.write_str(message),
            Self::InvalidRecord(message) => {
                write!(formatter, "invalid canonical record: {message}")
            }
            Self::Clock(message) => write!(formatter, "elapsed clock failed: {message}"),
            Self::ClockDiscontinuity => {
                formatter.write_str("elapsed clock continuity is uncertain")
            }
            Self::SerialExhausted => formatter.write_str("segment serial is exhausted"),
            Self::CounterOverflow(name) => write!(formatter, "{name} counter overflow"),
            Self::Store(message) => write!(formatter, "ledger store failed: {message}"),
            Self::ConcurrentWriter => formatter.write_str("concurrent ledger writer detected"),
            Self::IdempotencyConflict => {
                formatter.write_str("idempotency key was already used for different bytes")
            }
            Self::Construction(message) => {
                write!(formatter, "segment construction failed: {message}")
            }
        }
    }
}

impl std::error::Error for ProducerError {}

fn validate_policy(policy: &ClosurePolicyV1) -> Result<(), ProducerError> {
    if policy.interval_ms == 0 {
        return Err(ProducerError::InvalidConfiguration(
            "interval_ms must be positive",
        ));
    }
    if policy.batch_record_limit == 0 {
        return Err(ProducerError::InvalidConfiguration(
            "batch_record_limit must be positive",
        ));
    }
    if policy.record_limit == Some(0) {
        return Err(ProducerError::InvalidConfiguration(
            "record_limit must be positive",
        ));
    }
    if policy.size_limit_bytes == Some(0) {
        return Err(ProducerError::InvalidConfiguration(
            "size_limit_bytes must be positive",
        ));
    }
    Ok(())
}

/// Single-writer producer. Every mutating method performs one store CAS; a
/// failed CAS is fatal to that operation and must be retried after reloading.
pub struct V2LedgerProducer<S, C> {
    store: S,
    clock: C,
    state: ProducerState,
}

impl<S: LedgerStore, C: ElapsedClock> V2LedgerProducer<S, C> {
    pub fn open_or_create(
        mut store: S,
        clock: C,
        ledger_id: impl Into<String>,
        site_id: impl Into<String>,
        policy: ClosurePolicyV1,
    ) -> Result<Self, ProducerError> {
        validate_policy(&policy)?;
        if let Some(state) = store.load()? {
            validate_policy(&state.open.policy)?;
            validate_policy(&state.next_policy)?;
            return Ok(Self {
                store,
                clock,
                state,
            });
        }
        let now = clock.now_ms()?;
        let state = ProducerState {
            revision: 0,
            ledger_id: ledger_id.into(),
            site_id: site_id.into(),
            next_segment_number: 0,
            predecessor_cbor: None,
            open: OpenInterval {
                opened_at_ms: now,
                clock_continuity_id: clock.continuity_id(),
                policy: policy.clone(),
                records: Vec::new(),
                byte_count: 0,
            },
            next_policy: policy,
        };
        if state.ledger_id.len() != 32 || state.site_id.is_empty() {
            return Err(ProducerError::InvalidConfiguration(
                "ledger_id must be 16-byte lowercase hex and site_id must be non-empty",
            ));
        }
        store.compare_and_swap(None, &state, &[], None)?;
        Ok(Self {
            store,
            clock,
            state,
        })
    }

    pub fn state(&self) -> &ProducerState {
        &self.state
    }

    pub fn into_store(self) -> S {
        self.store
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Recover uncertain elapsed/open-interval state before accepting more
    /// telemetry. Recoverable material is sealed; an empty suppress interval
    /// advances only the logical interval.
    pub fn recover(&mut self) -> Result<Vec<SealedSegment>, ProducerError> {
        let now = self.clock.now_ms()?;
        self.transition(now, Some(CloseReason::Recovery), None)
    }

    pub fn update_policy(
        &mut self,
        policy: ClosurePolicyV1,
        immediate: bool,
    ) -> Result<Vec<SealedSegment>, ProducerError> {
        validate_policy(&policy)?;
        let now = self.safe_now()?;
        if immediate {
            self.transition(now, Some(CloseReason::Reconfigure), Some(policy))
        } else {
            let mut next = self.state.clone();
            next.next_policy = policy;
            self.commit(next, Vec::new(), None)?;
            Ok(Vec::new())
        }
    }

    pub fn close(&mut self, reason: CloseReason) -> Result<Vec<SealedSegment>, ProducerError> {
        let now = self.safe_now()?;
        self.transition(now, Some(reason), None)
    }

    pub fn admit(&mut self, record: Vec<u8>) -> Result<AdmissionOutcome, ProducerError> {
        self.admit_inner(record, None)
    }

    pub fn admit_idempotent(
        &mut self,
        key: impl Into<String>,
        record: Vec<u8>,
    ) -> Result<AdmissionOutcome, ProducerError> {
        let key = key.into();
        if key.is_empty() || key.len() > 255 || key.chars().any(char::is_control) {
            return Err(ProducerError::InvalidConfiguration(
                "idempotency key must contain 1..255 non-control characters",
            ));
        }
        let digest = sha256_hex(&record);
        if let Some(existing) = self.store.lookup_idempotency(&key)? {
            if existing.record_sha256 != digest {
                return Err(ProducerError::IdempotencyConflict);
            }
            return Ok(AdmissionOutcome {
                state_revision: existing.state_revision,
                admitted_segment_number: existing.admitted_segment_number,
                sealed: Vec::new(),
                sealed_segment_numbers: existing.sealed_segment_numbers,
                replayed: true,
            });
        }
        self.admit_inner(record, Some((key, digest)))
    }

    fn admit_inner(
        &mut self,
        record: Vec<u8>,
        idempotency: Option<(String, String)>,
    ) -> Result<AdmissionOutcome, ProducerError> {
        validate_canonical_record_v2(&record)
            .map_err(|error| ProducerError::InvalidRecord(error.to_string()))?;
        let now = self.safe_now()?;
        let mut next = self.state.clone();
        let mut sealed = Self::close_expired(&mut next, now)?;
        let admitted_segment_number = next.next_segment_number;
        next.open.byte_count = next
            .open
            .byte_count
            .checked_add(
                u64::try_from(record.len())
                    .map_err(|_| ProducerError::CounterOverflow("interval byte"))?,
            )
            .ok_or(ProducerError::CounterOverflow("interval byte"))?;
        next.open.records.push(record);

        let record_limit = next
            .open
            .policy
            .record_limit
            .is_some_and(|limit| next.open.records.len() as u128 >= u128::from(limit));
        let size_limit = next
            .open
            .policy
            .size_limit_bytes
            .is_some_and(|limit| next.open.byte_count >= limit);
        if let Some(reason) = CloseReason::highest(
            [
                size_limit.then_some(CloseReason::SizeLimit),
                record_limit.then_some(CloseReason::RecordLimit),
            ]
            .into_iter()
            .flatten(),
        ) && let Some(segment) = Self::seal_open(&mut next, now, reason)?
        {
            sealed.push(segment);
        }
        let admission = idempotency
            .map(|(key, record_sha256)| {
                Ok(IdempotencyRecord {
                    key,
                    record_sha256,
                    admitted_segment_number,
                    state_revision: next
                        .revision
                        .checked_add(1)
                        .ok_or(ProducerError::CounterOverflow("state revision"))?,
                    sealed_segment_numbers: sealed
                        .iter()
                        .map(|segment| segment.segment_number)
                        .collect(),
                })
            })
            .transpose()?;
        self.commit(next, sealed.clone(), admission.as_ref())?;
        Ok(AdmissionOutcome {
            state_revision: self.state.revision,
            admitted_segment_number,
            sealed_segment_numbers: sealed
                .iter()
                .map(|segment| segment.segment_number)
                .collect(),
            sealed,
            replayed: false,
        })
    }

    fn safe_now(&self) -> Result<u64, ProducerError> {
        let now = self.clock.now_ms()?;
        if self.state.open.clock_continuity_id != self.clock.continuity_id()
            || now < self.state.open.opened_at_ms
        {
            return Err(ProducerError::ClockDiscontinuity);
        }
        Ok(now)
    }

    fn transition(
        &mut self,
        now: u64,
        requested: Option<CloseReason>,
        replacement_policy: Option<ClosurePolicyV1>,
    ) -> Result<Vec<SealedSegment>, ProducerError> {
        let mut next = self.state.clone();
        let mut sealed = Vec::new();
        if let Some(reason) = requested
            && let Some(segment) = Self::seal_open(&mut next, now, reason)?
        {
            sealed.push(segment);
        }
        if let Some(policy) = replacement_policy {
            next.next_policy = policy.clone();
            next.open.policy = policy;
        }
        next.open.opened_at_ms = now;
        next.open.clock_continuity_id = self.clock.continuity_id();
        self.commit(next, sealed.clone(), None)?;
        Ok(sealed)
    }

    fn close_expired(
        state: &mut ProducerState,
        now: u64,
    ) -> Result<Vec<SealedSegment>, ProducerError> {
        let mut sealed = Vec::new();
        loop {
            let elapsed = now
                .checked_sub(state.open.opened_at_ms)
                .ok_or(ProducerError::ClockDiscontinuity)?;
            if elapsed < state.open.policy.interval_ms {
                break;
            }
            let boundary = state
                .open
                .opened_at_ms
                .checked_add(state.open.policy.interval_ms)
                .ok_or(ProducerError::ClockDiscontinuity)?;
            if let Some(segment) = Self::seal_open(state, boundary, CloseReason::Interval)? {
                sealed.push(segment);
            }
        }
        Ok(sealed)
    }

    fn seal_open(
        state: &mut ProducerState,
        next_opened_at_ms: u64,
        reason: CloseReason,
    ) -> Result<Option<SealedSegment>, ProducerError> {
        let records = std::mem::take(&mut state.open.records);
        state.open.byte_count = 0;
        let policy = state.open.policy.clone();
        state.open.policy = state.next_policy.clone();
        state.open.opened_at_ms = next_opened_at_ms;

        if records.is_empty() && policy.empty_mode == EmptyMode::Suppress {
            return Ok(None);
        }
        if state.next_segment_number == u64::MAX && state.predecessor_cbor.is_some() {
            return Err(ProducerError::SerialExhausted);
        }
        let merkle = merkle_root_from_records(&records);
        let batch_limit = usize::try_from(policy.batch_record_limit).unwrap_or(usize::MAX);
        let mut batches = Vec::new();
        for hashes in merkle.leaf_hashes.chunks(batch_limit) {
            batches.push(SegmentBatchV2 {
                ledger_id: String::new(),
                site_id: String::new(),
                segment_number: 0,
                batch_number: 0,
                merkle_root: hex_lower(&merkle_root_from_leaf_hashes(hashes)),
                count: u64::try_from(hashes.len())
                    .map_err(|_| ProducerError::CounterOverflow("batch record"))?,
                leaf_hashes: hashes.iter().map(|hash| hex_lower(hash)).collect(),
            });
        }
        let segment = if let Some(predecessor) = &state.predecessor_cbor {
            SegmentRecordV2::new_successor(
                predecessor,
                policy,
                reason.as_str(),
                batches,
                merkle.root_hex(),
            )
        } else {
            SegmentRecordV2::new_epoch(
                state.ledger_id.clone(),
                state.site_id.clone(),
                policy,
                reason.as_str(),
                batches,
                merkle.root_hex(),
            )
        }
        .map_err(|error| ProducerError::Construction(error.to_string()))?;
        if segment.segment_number != state.next_segment_number {
            return Err(ProducerError::ConcurrentWriter);
        }
        let artifact_cbor = segment
            .canonical_cbor_bytes()
            .map_err(ProducerError::Construction)?;
        let artifact_sha256 = sha256_hex(&artifact_cbor);
        let sealed = SealedSegment {
            segment_number: segment.segment_number,
            close_reason: reason,
            artifact_cbor: artifact_cbor.clone(),
            artifact_sha256,
            records,
        };
        state.predecessor_cbor = Some(artifact_cbor);
        state.next_segment_number = state
            .next_segment_number
            .checked_add(1)
            .ok_or(ProducerError::SerialExhausted)?;
        Ok(Some(sealed))
    }

    fn commit(
        &mut self,
        mut next: ProducerState,
        sealed: Vec<SealedSegment>,
        admission: Option<&IdempotencyRecord>,
    ) -> Result<(), ProducerError> {
        let expected = self.state.revision;
        next.revision = expected
            .checked_add(1)
            .ok_or(ProducerError::CounterOverflow("state revision"))?;
        self.store
            .compare_and_swap(Some(expected), &next, &sealed, admission)?;
        self.state = next;
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryLedgerStore {
    pub state: Option<ProducerState>,
    pub sealed: BTreeMap<u64, SealedSegment>,
    pub idempotency: BTreeMap<String, IdempotencyRecord>,
}

impl LedgerStore for MemoryLedgerStore {
    fn load(&mut self) -> Result<Option<ProducerState>, ProducerError> {
        Ok(self.state.clone())
    }

    fn lookup_idempotency(
        &mut self,
        key: &str,
    ) -> Result<Option<IdempotencyRecord>, ProducerError> {
        Ok(self.idempotency.get(key).cloned())
    }

    fn compare_and_swap(
        &mut self,
        expected_revision: Option<u64>,
        state: &ProducerState,
        sealed: &[SealedSegment],
        admission: Option<&IdempotencyRecord>,
    ) -> Result<(), ProducerError> {
        if self.state.as_ref().map(|current| current.revision) != expected_revision {
            return Err(ProducerError::ConcurrentWriter);
        }
        for segment in sealed {
            if self.sealed.contains_key(&segment.segment_number) {
                return Err(ProducerError::ConcurrentWriter);
            }
        }
        if let Some(admission) = admission
            && self.idempotency.contains_key(&admission.key)
        {
            return Err(ProducerError::ConcurrentWriter);
        }
        self.state = Some(state.clone());
        for segment in sealed {
            self.sealed.insert(segment.segment_number, segment.clone());
        }
        if let Some(admission) = admission {
            self.idempotency
                .insert(admission.key.clone(), admission.clone());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct FakeClock {
        now: Cell<u64>,
        continuity: Cell<u128>,
    }

    impl FakeClock {
        fn new(now: u64) -> Self {
            Self {
                now: Cell::new(now),
                continuity: Cell::new(1),
            }
        }
        fn set(&self, now: u64) {
            self.now.set(now);
        }
    }

    impl ElapsedClock for &FakeClock {
        fn now_ms(&self) -> Result<u64, ProducerError> {
            Ok(self.now.get())
        }
        fn continuity_id(&self) -> u128 {
            self.continuity.get()
        }
    }

    fn policy(empty_mode: EmptyMode) -> ClosurePolicyV1 {
        ClosurePolicyV1 {
            interval_ms: 100,
            batch_record_limit: 2,
            record_limit: None,
            size_limit_bytes: None,
            empty_mode,
        }
    }

    fn record(fc: u8) -> Vec<u8> {
        vec![
            0x87, 0x01, 0x48, 0, 0, 0, 0, 0, 0, 0, fc, fc, 0, 0xf6, 0, 0xf6,
        ]
    }

    fn producer(
        clock: &FakeClock,
        empty_mode: EmptyMode,
    ) -> V2LedgerProducer<MemoryLedgerStore, &FakeClock> {
        V2LedgerProducer::open_or_create(
            MemoryLedgerStore::default(),
            clock,
            "b7a1d5e40c6f438e9a75db27c96f31aa",
            "an-001",
            policy(empty_mode),
        )
        .unwrap()
    }

    #[test]
    fn exact_boundary_closes_before_admission() {
        let clock = FakeClock::new(1_000);
        let mut producer = producer(&clock, EmptyMode::Suppress);
        producer.admit(record(1)).unwrap();
        clock.set(1_100);
        let outcome = producer.admit(record(2)).unwrap();
        assert_eq!(outcome.admitted_segment_number, 1);
        assert_eq!(outcome.sealed.len(), 1);
        assert_eq!(outcome.sealed[0].records, vec![record(1)]);
        assert_eq!(outcome.sealed[0].close_reason, CloseReason::Interval);
    }

    #[test]
    fn suppress_skips_empty_intervals_without_consuming_serials() {
        let clock = FakeClock::new(0);
        let mut producer = producer(&clock, EmptyMode::Suppress);
        clock.set(350);
        let outcome = producer.admit(record(1)).unwrap();
        assert!(outcome.sealed.is_empty());
        assert_eq!(outcome.admitted_segment_number, 0);
        assert_eq!(producer.state().open.opened_at_ms, 300);
    }

    #[test]
    fn emit_materializes_each_elapsed_interval() {
        let clock = FakeClock::new(0);
        let mut producer = producer(&clock, EmptyMode::Emit);
        clock.set(250);
        let outcome = producer.admit(record(1)).unwrap();
        assert_eq!(outcome.sealed.len(), 2);
        assert_eq!(outcome.sealed[0].segment_number, 0);
        assert_eq!(outcome.sealed[1].segment_number, 1);
        assert_eq!(outcome.admitted_segment_number, 2);
    }

    #[test]
    fn record_limit_seals_in_the_acceptance_transaction() {
        let clock = FakeClock::new(0);
        let mut configured = policy(EmptyMode::Suppress);
        configured.record_limit = Some(2);
        let mut producer = V2LedgerProducer::open_or_create(
            MemoryLedgerStore::default(),
            &clock,
            "b7a1d5e40c6f438e9a75db27c96f31aa",
            "an-001",
            configured,
        )
        .unwrap();
        producer.admit(record(1)).unwrap();
        let outcome = producer.admit(record(2)).unwrap();
        assert_eq!(outcome.sealed[0].close_reason, CloseReason::RecordLimit);
        assert_eq!(outcome.sealed[0].records.len(), 2);
    }

    #[test]
    fn immediate_policy_update_seals_under_old_snapshot() {
        let clock = FakeClock::new(0);
        let mut producer = producer(&clock, EmptyMode::Suppress);
        producer.admit(record(1)).unwrap();
        let mut replacement = policy(EmptyMode::Suppress);
        replacement.interval_ms = 500;
        let sealed = producer.update_policy(replacement.clone(), true).unwrap();
        let decoded =
            trackone_ledger::v2::decode_segment_record_v2(&sealed[0].artifact_cbor).unwrap();
        assert_eq!(decoded.closure_policy.interval_ms, 100);
        assert_eq!(decoded.close_reason, "reconfigure");
        assert_eq!(producer.state().open.policy, replacement);
    }

    #[test]
    fn restart_requires_recovery_when_clock_continuity_changes() {
        let clock = FakeClock::new(0);
        let mut producer = producer(&clock, EmptyMode::Suppress);
        producer.admit(record(1)).unwrap();
        let store = producer.into_store();
        clock.continuity.set(2);
        let mut restarted = V2LedgerProducer::open_or_create(
            store,
            &clock,
            "ignored",
            "ignored",
            policy(EmptyMode::Suppress),
        )
        .unwrap();
        assert_eq!(
            restarted.admit(record(2)),
            Err(ProducerError::ClockDiscontinuity)
        );
        let sealed = restarted.recover().unwrap();
        assert_eq!(sealed[0].close_reason, CloseReason::Recovery);
        restarted.admit(record(2)).unwrap();
    }

    #[test]
    fn close_reason_precedence_matches_draft() {
        assert_eq!(
            CloseReason::highest([
                CloseReason::Manual,
                CloseReason::Interval,
                CloseReason::Recovery
            ]),
            Some(CloseReason::Recovery)
        );
        assert_eq!(
            CloseReason::highest([CloseReason::RecordLimit, CloseReason::SizeLimit]),
            Some(CloseReason::SizeLimit)
        );
    }

    #[test]
    fn idempotency_replays_identical_bytes_and_rejects_key_reuse() {
        let clock = FakeClock::new(0);
        let mut producer = producer(&clock, EmptyMode::Suppress);
        let first = producer.admit_idempotent("request-1", record(1)).unwrap();
        let replay = producer.admit_idempotent("request-1", record(1)).unwrap();
        assert!(!first.replayed);
        assert!(replay.replayed);
        assert_eq!(replay.state_revision, first.state_revision);
        assert_eq!(producer.state().open.records.len(), 1);
        assert_eq!(
            producer.admit_idempotent("request-1", record(2)),
            Err(ProducerError::IdempotencyConflict)
        );
    }
}
