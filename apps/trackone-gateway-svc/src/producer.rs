//! Verifiable Telemetry Ledgers gateway-service producer state machine.
//!
//! The protocol rules live here independently of a concrete database. A store
//! commits the complete state transition and any sealed artifacts atomically;
//! production deployments can implement that contract with PostgreSQL while
//! tests use the in-memory implementation below.

use std::collections::BTreeMap;
use std::fmt;
use trackone_ledger::sha256_hex;
use trackone_ledger::vtl::{
    ClosurePolicy, EmptyMode, SegmentRecord, batch_roots_from_leaf_hashes,
    merkle_root_from_records, validate_canonical_record,
};

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
    pub policy: ClosurePolicy,
    pub records: Vec<Vec<u8>>,
    pub byte_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProducerState {
    pub revision: u64,
    pub active: bool,
    pub ledger_id: String,
    pub site_id: String,
    pub next_segment_number: u64,
    pub predecessor_cbor: Option<Vec<u8>>,
    pub open: OpenInterval,
    pub next_policy: ClosurePolicy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedSegment {
    pub segment_number: u64,
    pub close_reason: CloseReason,
    pub artifact_cbor: Vec<u8>,
    pub artifact_sha256: String,
    pub records: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordDestination {
    Open { ordinal: u64 },
    Sealed { segment_number: u64, ordinal: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedRecordDelta {
    pub record_cbor: Vec<u8>,
    pub destination: RecordDestination,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerTransition {
    pub previous_open_count: u64,
    pub admitted_records: Vec<AdmittedRecordDelta>,
    pub next_state: ProducerState,
    pub sealed: Vec<SealedSegment>,
    pub idempotency: Option<IdempotencyRecord>,
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
        transition: &LedgerTransition,
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
            Self::Manual => 4,
            Self::SizeLimit => 3,
            Self::RecordLimit => 2,
            Self::Interval => 1,
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
    pub admitted_record_count: u64,
    pub admission_runs: Vec<AdmissionRun>,
    pub sealed: Vec<SealedSegment>,
    pub sealed_segment_numbers: Vec<u64>,
    pub replayed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionRun {
    pub segment_number: u64,
    pub record_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdempotencyRecord {
    pub key: String,
    pub request_sha256: String,
    pub admitted_segment_numbers: Vec<u64>,
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
    TimestampConfiguration(String),
    TimestampSubmission(String),
    TimestampVerification(String),
    TimestampPersistence(String),
    ConcurrentWriter,
    IdempotencyConflict,
    Inactive,
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
            Self::TimestampConfiguration(message) => {
                write!(formatter, "timestamp configuration failed: {message}")
            }
            Self::TimestampSubmission(message) => {
                write!(formatter, "timestamp submission failed: {message}")
            }
            Self::TimestampVerification(message) => {
                write!(formatter, "timestamp verification failed: {message}")
            }
            Self::TimestampPersistence(message) => {
                write!(formatter, "timestamp persistence failed: {message}")
            }
            Self::ConcurrentWriter => formatter.write_str("concurrent ledger writer detected"),
            Self::IdempotencyConflict => {
                formatter.write_str("idempotency key was already used for different bytes")
            }
            Self::Inactive => formatter.write_str("ledger is shut down and must be reactivated"),
            Self::Construction(message) => {
                write!(formatter, "segment construction failed: {message}")
            }
        }
    }
}

impl std::error::Error for ProducerError {}

fn validate_policy(policy: &ClosurePolicy) -> Result<(), ProducerError> {
    if policy.interval_ms == 0 {
        return Err(ProducerError::InvalidConfiguration(
            "interval_ms must be positive",
        ));
    }
    if policy.batch_record_limit == 0
        || policy.batch_record_limit > trackone_ledger::vtl::MAX_BATCH_RECORD_LIMIT
        || !policy.batch_record_limit.is_power_of_two()
    {
        return Err(ProducerError::InvalidConfiguration(
            "batch_record_limit must be a power of two no greater than 2^63",
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
pub struct LedgerProducer<S, C> {
    store: S,
    clock: C,
    state: ProducerState,
}

impl<S: LedgerStore, C: ElapsedClock> LedgerProducer<S, C> {
    pub fn open_or_create(
        mut store: S,
        clock: C,
        ledger_id: impl Into<String>,
        site_id: impl Into<String>,
        policy: ClosurePolicy,
    ) -> Result<Self, ProducerError> {
        validate_policy(&policy)?;
        let ledger_id = ledger_id.into();
        let site_id = site_id.into();
        if ledger_id.len() != 32 || site_id.is_empty() {
            return Err(ProducerError::InvalidConfiguration(
                "ledger_id must be 16-byte lowercase hex and site_id must be non-empty",
            ));
        }
        if let Some(state) = store.load()? {
            validate_policy(&state.open.policy)?;
            validate_policy(&state.next_policy)?;
            if state.ledger_id != ledger_id || state.site_id != site_id {
                return Err(ProducerError::InvalidConfiguration(
                    "configured ledger_id and site_id do not match existing ledger state",
                ));
            }
            let mut producer = Self {
                store,
                clock,
                state,
            };
            if !producer.state.active {
                producer.reactivate()?;
            }
            return Ok(producer);
        }
        let now = clock.now_ms()?;
        let state = ProducerState {
            revision: 0,
            active: true,
            ledger_id,
            site_id,
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
        store.compare_and_swap(
            None,
            &LedgerTransition {
                previous_open_count: 0,
                admitted_records: Vec::new(),
                next_state: state.clone(),
                sealed: Vec::new(),
                idempotency: None,
            },
        )?;
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
        if !self.state.active {
            return Err(ProducerError::Inactive);
        }
        let now = self.clock.now_ms()?;
        self.transition(now, Some(CloseReason::Recovery), None)
    }

    /// Resume a ledger after a committed shutdown closure.
    pub fn reactivate(&mut self) -> Result<(), ProducerError> {
        if self.state.active {
            return Ok(());
        }
        let now = self.clock.now_ms()?;
        let mut next = self.state.clone();
        next.active = true;
        next.open.opened_at_ms = now;
        next.open.clock_continuity_id = self.clock.continuity_id();
        self.commit(next, Vec::new(), None, Vec::new())
    }

    pub fn update_policy(
        &mut self,
        policy: ClosurePolicy,
        immediate: bool,
    ) -> Result<Vec<SealedSegment>, ProducerError> {
        validate_policy(&policy)?;
        let now = self.safe_now()?;
        if immediate {
            self.transition(now, Some(CloseReason::Reconfigure), Some(policy))
        } else {
            let mut next = self.state.clone();
            next.next_policy = policy;
            self.commit(next, Vec::new(), None, Vec::new())?;
            Ok(Vec::new())
        }
    }

    pub fn close(&mut self, reason: CloseReason) -> Result<Vec<SealedSegment>, ProducerError> {
        let now = self.safe_now()?;
        self.transition(now, Some(reason), None)
    }

    pub fn admit(&mut self, record: Vec<u8>) -> Result<AdmissionOutcome, ProducerError> {
        self.admit_batch_inner(vec![record], None)
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
        self.admit_batch_idempotent_digest(key, vec![record], digest)
    }

    pub fn admit_batch_idempotent(
        &mut self,
        key: impl Into<String>,
        records: Vec<Vec<u8>>,
        canonical_envelope: &[u8],
    ) -> Result<AdmissionOutcome, ProducerError> {
        self.admit_batch_idempotent_digest(key.into(), records, sha256_hex(canonical_envelope))
    }

    fn admit_batch_idempotent_digest(
        &mut self,
        key: String,
        records: Vec<Vec<u8>>,
        digest: String,
    ) -> Result<AdmissionOutcome, ProducerError> {
        if key.is_empty() || key.len() > 255 || key.chars().any(char::is_control) {
            return Err(ProducerError::InvalidConfiguration(
                "idempotency key must contain 1..255 non-control characters",
            ));
        }
        if let Some(existing) = self.store.lookup_idempotency(&key)? {
            if existing.request_sha256 != digest {
                return Err(ProducerError::IdempotencyConflict);
            }
            let admission_runs = admission_runs(&existing.admitted_segment_numbers)?;
            return Ok(AdmissionOutcome {
                state_revision: existing.state_revision,
                admitted_segment_number: existing
                    .admitted_segment_numbers
                    .first()
                    .copied()
                    .unwrap_or(0),
                admitted_record_count: u64::try_from(existing.admitted_segment_numbers.len())
                    .map_err(|_| ProducerError::CounterOverflow("admitted record"))?,
                admission_runs,
                sealed: Vec::new(),
                sealed_segment_numbers: existing.sealed_segment_numbers,
                replayed: true,
            });
        }
        self.admit_batch_inner(records, Some((key, digest)))
    }

    fn admit_batch_inner(
        &mut self,
        records: Vec<Vec<u8>>,
        idempotency: Option<(String, String)>,
    ) -> Result<AdmissionOutcome, ProducerError> {
        if !self.state.active {
            return Err(ProducerError::Inactive);
        }
        if records.is_empty() {
            return Err(ProducerError::InvalidRecord(
                "record batch must not be empty".to_string(),
            ));
        }
        for (index, record) in records.iter().enumerate() {
            validate_canonical_record(record).map_err(|error| {
                ProducerError::InvalidRecord(format!("record {index}: {error}"))
            })?;
        }
        let now = self.safe_now()?;
        let mut next = self.state.clone();
        let mut sealed = Self::close_expired(&mut next, now)?;
        let admitted_records = records.clone();
        let mut admitted_segment_numbers = Vec::with_capacity(records.len());
        for record in records {
            admitted_segment_numbers.push(next.next_segment_number);
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
        }
        let admitted_segment_number = admitted_segment_numbers[0];
        let admission_runs = admission_runs(&admitted_segment_numbers)?;
        let admitted_record_count = u64::try_from(admitted_segment_numbers.len())
            .map_err(|_| ProducerError::CounterOverflow("admitted record"))?;
        let record_deltas = record_deltas(
            &self.state,
            &next,
            &sealed,
            &admitted_records,
            &admitted_segment_numbers,
        )?;
        let admission = idempotency
            .map(|(key, request_sha256)| {
                Ok(IdempotencyRecord {
                    key,
                    request_sha256,
                    admitted_segment_numbers,
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
        self.commit(next, sealed.clone(), admission.as_ref(), record_deltas)?;
        Ok(AdmissionOutcome {
            state_revision: self.state.revision,
            admitted_segment_number,
            admitted_record_count,
            admission_runs,
            sealed_segment_numbers: sealed
                .iter()
                .map(|segment| segment.segment_number)
                .collect(),
            sealed,
            replayed: false,
        })
    }

    fn safe_now(&self) -> Result<u64, ProducerError> {
        if !self.state.active {
            return Err(ProducerError::Inactive);
        }
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
        replacement_policy: Option<ClosurePolicy>,
    ) -> Result<Vec<SealedSegment>, ProducerError> {
        if !self.state.active {
            return Err(ProducerError::Inactive);
        }
        let mut next = self.state.clone();
        let mut sealed = Vec::new();
        if let Some(reason) = requested
            && let Some(segment) = Self::seal_open(&mut next, now, reason)?
        {
            sealed.push(segment);
        }
        if requested == Some(CloseReason::Shutdown) {
            next.active = false;
        }
        if let Some(policy) = replacement_policy {
            next.next_policy = policy.clone();
            next.open.policy = policy;
        }
        next.open.opened_at_ms = now;
        next.open.clock_continuity_id = self.clock.continuity_id();
        self.commit(next, sealed.clone(), None, Vec::new())?;
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

        if records.is_empty()
            && policy.empty_mode == EmptyMode::Suppress
            && !matches!(reason, CloseReason::Shutdown | CloseReason::Recovery)
        {
            return Ok(None);
        }
        if state.next_segment_number == u64::MAX && state.predecessor_cbor.is_some() {
            return Err(ProducerError::SerialExhausted);
        }
        let merkle = merkle_root_from_records(&records);
        let batch_roots =
            batch_roots_from_leaf_hashes(&merkle.leaf_hashes, policy.batch_record_limit).ok_or(
                ProducerError::InvalidConfiguration(
                    "batch_record_limit must be a power of two no greater than 2^63",
                ),
            )?;
        let record_count = u64::try_from(merkle.leaf_hashes.len())
            .map_err(|_| ProducerError::CounterOverflow("segment record"))?;
        let segment = if let Some(predecessor) = &state.predecessor_cbor {
            SegmentRecord::new_successor(
                predecessor,
                policy,
                reason.as_str(),
                record_count,
                batch_roots,
                merkle.root,
            )
        } else {
            SegmentRecord::new_epoch(
                state.ledger_id.clone(),
                policy,
                reason.as_str(),
                record_count,
                batch_roots,
                merkle.root,
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
        admitted_records: Vec<AdmittedRecordDelta>,
    ) -> Result<(), ProducerError> {
        let expected = self.state.revision;
        next.revision = expected
            .checked_add(1)
            .ok_or(ProducerError::CounterOverflow("state revision"))?;
        let transition = LedgerTransition {
            previous_open_count: u64::try_from(self.state.open.records.len())
                .map_err(|_| ProducerError::CounterOverflow("open record"))?,
            admitted_records,
            next_state: next.clone(),
            sealed,
            idempotency: admission.cloned(),
        };
        self.store.compare_and_swap(Some(expected), &transition)?;
        self.state = next;
        Ok(())
    }
}

fn record_deltas(
    previous: &ProducerState,
    next: &ProducerState,
    sealed: &[SealedSegment],
    records: &[Vec<u8>],
    segment_numbers: &[u64],
) -> Result<Vec<AdmittedRecordDelta>, ProducerError> {
    let sealed_numbers = sealed
        .iter()
        .map(|segment| segment.segment_number)
        .collect::<Vec<_>>();
    let previous_was_sealed = !previous.open.records.is_empty()
        && sealed
            .iter()
            .any(|segment| segment.records.starts_with(&previous.open.records));
    let mut sealed_ordinals = BTreeMap::<u64, u64>::new();
    if !previous.open.records.is_empty() && previous_was_sealed {
        sealed_ordinals.insert(
            previous.next_segment_number,
            u64::try_from(previous.open.records.len())
                .map_err(|_| ProducerError::CounterOverflow("sealed record"))?,
        );
    }
    let admitted_open_count = segment_numbers
        .iter()
        .filter(|&&number| number == next.next_segment_number)
        .count();
    let existing_open_count = next
        .open
        .records
        .len()
        .checked_sub(admitted_open_count)
        .ok_or(ProducerError::ConcurrentWriter)?;
    let mut open_ordinal = u64::try_from(existing_open_count)
        .map_err(|_| ProducerError::CounterOverflow("open record"))?;
    records
        .iter()
        .zip(segment_numbers)
        .map(|(record, &segment_number)| {
            let destination = if sealed_numbers.contains(&segment_number) {
                let ordinal = sealed_ordinals.entry(segment_number).or_default();
                let destination = RecordDestination::Sealed {
                    segment_number,
                    ordinal: *ordinal,
                };
                *ordinal = ordinal
                    .checked_add(1)
                    .ok_or(ProducerError::CounterOverflow("sealed record"))?;
                destination
            } else {
                let destination = RecordDestination::Open {
                    ordinal: open_ordinal,
                };
                open_ordinal = open_ordinal
                    .checked_add(1)
                    .ok_or(ProducerError::CounterOverflow("open record"))?;
                destination
            };
            Ok(AdmittedRecordDelta {
                record_cbor: record.clone(),
                destination,
            })
        })
        .collect()
}

fn admission_runs(segment_numbers: &[u64]) -> Result<Vec<AdmissionRun>, ProducerError> {
    let mut runs = Vec::<AdmissionRun>::new();
    for &segment_number in segment_numbers {
        if let Some(run) = runs.last_mut()
            && run.segment_number == segment_number
        {
            run.record_count = run
                .record_count
                .checked_add(1)
                .ok_or(ProducerError::CounterOverflow("admission run"))?;
        } else {
            runs.push(AdmissionRun {
                segment_number,
                record_count: 1,
            });
        }
    }
    Ok(runs)
}

#[derive(Clone, Debug, Default)]
pub struct MemoryLedgerStore {
    pub state: Option<ProducerState>,
    pub sealed: BTreeMap<u64, SealedSegment>,
    pub idempotency: BTreeMap<String, IdempotencyRecord>,
    pub transitions: Vec<LedgerTransition>,
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
        transition: &LedgerTransition,
    ) -> Result<(), ProducerError> {
        let state = &transition.next_state;
        let sealed = &transition.sealed;
        let admission = transition.idempotency.as_ref();
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
        self.transitions.push(transition.clone());
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

    fn policy(empty_mode: EmptyMode) -> ClosurePolicy {
        ClosurePolicy {
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
    ) -> LedgerProducer<MemoryLedgerStore, &FakeClock> {
        LedgerProducer::open_or_create(
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
        let mut producer = LedgerProducer::open_or_create(
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
            trackone_ledger::vtl::decode_segment_record(&sealed[0].artifact_cbor).unwrap();
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
        let mut restarted = LedgerProducer::open_or_create(
            store,
            &clock,
            "b7a1d5e40c6f438e9a75db27c96f31aa",
            "an-001",
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
    fn restart_rejects_a_site_that_does_not_match_the_existing_ledger() {
        let clock = FakeClock::new(0);
        let producer = producer(&clock, EmptyMode::Suppress);
        let store = producer.into_store();

        assert!(matches!(
            LedgerProducer::open_or_create(
                store,
                &clock,
                "b7a1d5e40c6f438e9a75db27c96f31aa",
                "an-002",
                policy(EmptyMode::Suppress),
            ),
            Err(ProducerError::InvalidConfiguration(
                "configured ledger_id and site_id do not match existing ledger state"
            ))
        ));
    }

    #[test]
    fn close_reason_precedence_matches_profile() {
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

    #[test]
    fn atomic_batch_rolls_back_invalid_input_and_commits_one_revision() {
        let clock = FakeClock::new(0);
        let mut producer = producer(&clock, EmptyMode::Suppress);
        let revision = producer.state().revision;
        assert!(matches!(
            producer.admit_batch_idempotent(
                "batch-invalid",
                vec![record(1), vec![0xff], record(2)],
                b"envelope-invalid"
            ),
            Err(ProducerError::InvalidRecord(_))
        ));
        assert_eq!(producer.state().revision, revision);
        assert!(producer.state().open.records.is_empty());

        let outcome = producer
            .admit_batch_idempotent(
                "batch-valid",
                vec![record(1), record(2), record(3)],
                b"envelope-valid",
            )
            .unwrap();
        assert_eq!(outcome.state_revision, revision + 1);
        assert_eq!(outcome.admitted_record_count, 3);
        assert_eq!(
            outcome.admission_runs,
            vec![AdmissionRun {
                segment_number: 0,
                record_count: 3
            }]
        );
    }

    #[test]
    fn batch_preserves_sequential_closures_duplicates_and_delta_uniqueness() {
        let clock = FakeClock::new(0);
        let mut configured = policy(EmptyMode::Suppress);
        configured.record_limit = Some(2);
        let mut producer = LedgerProducer::open_or_create(
            MemoryLedgerStore::default(),
            &clock,
            "b7a1d5e40c6f438e9a75db27c96f31aa",
            "an-001",
            configured,
        )
        .unwrap();
        let duplicate = record(7);
        let outcome = producer
            .admit_batch_idempotent(
                "batch-1",
                vec![
                    duplicate.clone(),
                    duplicate.clone(),
                    record(8),
                    record(9),
                    record(10),
                ],
                b"canonical-envelope",
            )
            .unwrap();
        assert_eq!(
            outcome.admission_runs,
            vec![
                AdmissionRun {
                    segment_number: 0,
                    record_count: 2
                },
                AdmissionRun {
                    segment_number: 1,
                    record_count: 2
                },
                AdmissionRun {
                    segment_number: 2,
                    record_count: 1
                }
            ]
        );
        assert_eq!(outcome.sealed_segment_numbers, vec![0, 1]);
        assert_eq!(
            outcome.sealed[0].records,
            vec![duplicate.clone(), duplicate]
        );
        let store = producer.into_store();
        let transition = store.transitions.last().unwrap();
        assert_eq!(transition.admitted_records.len(), 5);
        assert_eq!(
            transition
                .admitted_records
                .iter()
                .map(|delta| &delta.record_cbor)
                .collect::<Vec<_>>()
                .len(),
            5
        );
    }

    #[test]
    fn batch_idempotency_hashes_the_expanded_envelope() {
        let clock = FakeClock::new(0);
        let mut producer = producer(&clock, EmptyMode::Suppress);
        let records = vec![record(1), record(2)];
        let first = producer
            .admit_batch_idempotent("batch-replay", records.clone(), b"expanded")
            .unwrap();
        let replay = producer
            .admit_batch_idempotent("batch-replay", records.clone(), b"expanded")
            .unwrap();
        assert!(!first.replayed);
        assert!(replay.replayed);
        assert_eq!(replay.admission_runs, first.admission_runs);
        assert_eq!(
            producer.admit_batch_idempotent("batch-replay", records, b"different"),
            Err(ProducerError::IdempotencyConflict)
        );
    }

    #[test]
    fn shutdown_emits_an_empty_suppress_artifact_and_requires_reactivation() {
        let clock = FakeClock::new(0);
        let mut producer = producer(&clock, EmptyMode::Suppress);
        let sealed = producer.close(CloseReason::Shutdown).unwrap();
        assert_eq!(sealed.len(), 1);
        let segment =
            trackone_ledger::vtl::decode_segment_record(&sealed[0].artifact_cbor).unwrap();
        assert_eq!(segment.record_count, 0);
        assert_eq!(segment.close_reason, "shutdown");
        assert_eq!(segment.closure_policy.empty_mode, EmptyMode::Suppress);
        assert_eq!(producer.admit(record(1)), Err(ProducerError::Inactive));
        assert_eq!(
            producer.close(CloseReason::Manual),
            Err(ProducerError::Inactive)
        );
        assert_eq!(
            producer.update_policy(policy(EmptyMode::Emit), true),
            Err(ProducerError::Inactive)
        );
        producer.reactivate().unwrap();
        assert_eq!(
            producer.admit(record(1)).unwrap().admitted_segment_number,
            1
        );
    }

    #[test]
    fn machine_readable_lifecycle_cases_match_producer_transitions() {
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../../../toolset/vectors/vtl-interoperability/cases.json"
        ))
        .unwrap();
        for case in corpus["lifecycle_cases"].as_array().unwrap() {
            let case_id = case["id"].as_str().unwrap();
            let policy_value = &case["closure_policy"];
            let empty_mode = match policy_value["empty_mode"].as_str().unwrap() {
                "emit" => EmptyMode::Emit,
                "suppress" => EmptyMode::Suppress,
                value => panic!("{case_id}: unexpected empty mode {value}"),
            };
            let configured = ClosurePolicy {
                interval_ms: policy_value["interval_ms"].as_u64().unwrap(),
                batch_record_limit: policy_value["batch_record_limit"].as_u64().unwrap(),
                record_limit: policy_value["record_limit"].as_u64(),
                size_limit_bytes: policy_value["size_limit_bytes"].as_u64(),
                empty_mode,
            };
            let clock = FakeClock::new(0);
            let mut producer = LedgerProducer::open_or_create(
                MemoryLedgerStore::default(),
                &clock,
                "b7a1d5e40c6f438e9a75db27c96f31aa",
                "an-001",
                configured,
            )
            .unwrap();
            for (index, length) in case["records_before_trigger_lengths"]
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
            {
                let admitted = record(u8::try_from(index + 1).unwrap());
                assert_eq!(
                    admitted.len() as u64,
                    length.as_u64().unwrap(),
                    "{case_id}: fixture record length"
                );
                producer.admit(admitted).unwrap();
            }

            let trigger = &case["trigger"];
            clock.set(trigger["elapsed_ms"].as_u64().unwrap());
            let serial_before = producer.state().next_segment_number;
            let (sealed, admitted_segment) = match trigger["kind"].as_str().unwrap() {
                "elapsed_boundary" => (producer.close(CloseReason::Interval).unwrap(), None),
                "shutdown" => (producer.close(CloseReason::Shutdown).unwrap(), None),
                "recovery" => (producer.recover().unwrap(), None),
                "admission" => {
                    let admitted = record(9);
                    assert_eq!(
                        admitted.len() as u64,
                        trigger["record_length"].as_u64().unwrap(),
                        "{case_id}: triggering record length"
                    );
                    let outcome = producer.admit(admitted).unwrap();
                    (outcome.sealed, Some(outcome.admitted_segment_number))
                }
                value => panic!("{case_id}: unexpected trigger {value}"),
            };

            let expected = &case["expected"];
            assert_eq!(
                sealed.len() as u64,
                expected["emitted_segment_count"].as_u64().unwrap(),
                "{case_id}: emitted segment count"
            );
            assert_eq!(
                producer.state().next_segment_number - serial_before,
                expected["consumed_segment_numbers"].as_u64().unwrap(),
                "{case_id}: consumed segment numbers"
            );
            assert_eq!(
                sealed.first().map(|segment| segment.records.len() as u64),
                expected["closed_record_count"].as_u64(),
                "{case_id}: closed record count"
            );
            assert_eq!(
                sealed.first().map(|segment| segment.close_reason.as_str()),
                expected["close_reason"].as_str(),
                "{case_id}: close reason"
            );
            assert_eq!(
                producer.state().active,
                expected["successor_opened"].as_bool().unwrap(),
                "{case_id}: successor state"
            );
            match expected["triggering_record_assignment"].as_str().unwrap() {
                "none" => assert!(admitted_segment.is_none(), "{case_id}"),
                "closed_interval" => assert_eq!(
                    admitted_segment,
                    sealed.first().map(|segment| segment.segment_number),
                    "{case_id}: triggering record must remain in the closed interval"
                ),
                "successor_interval" => assert!(
                    admitted_segment.is_some_and(|number| {
                        sealed
                            .last()
                            .is_some_and(|segment| number > segment.segment_number)
                    }),
                    "{case_id}: triggering record must enter the successor interval"
                ),
                value => panic!("{case_id}: unexpected assignment {value}"),
            }
        }
    }
}
