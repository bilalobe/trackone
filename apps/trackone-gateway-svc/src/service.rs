//! HTTP handoff surface for exact VTL canonical-record CBOR bytes.

use crate::observability::{
    CapacityLimits, PipelineEvents, PipelineReadiness, ReadinessSample, SAMPLE_INTERVAL_SECONDS,
};
use std::sync::{
    Arc, Mutex, TryLockError,
    atomic::{AtomicBool, Ordering},
};

use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::{
    HeaderMap, HeaderName, HeaderValue, StatusCode,
    header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE, WWW_AUTHENTICATE},
};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router, extract::DefaultBodyLimit};
use flate2::{Crc, Decompress, FlushDecompress, Status};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};

use crate::postgres::PostgresLedgerStore;
use crate::producer::{ElapsedClock, LedgerProducer, ProducerError};

pub const CBOR_MEDIA_TYPE: &str = "application/cbor";
pub const BATCH_CBOR_MEDIA_TYPE: &str = "application/vnd.trackone.record-batch.v1+cbor";
pub const IDEMPOTENCY_KEY: &str = "idempotency-key";
pub const DEFAULT_MAX_BATCH_RECORDS: usize = 1_000;
pub const DEFAULT_MAX_ADMISSION_BYTES: usize = 4_194_304;
pub const HARD_MAX_BATCH_RECORDS: usize = 10_000;
pub const HARD_MAX_ADMISSION_BYTES: usize = 16_777_216;

pub type ServiceProducer<C> = LedgerProducer<PostgresLedgerStore, C>;

#[derive(Clone)]
pub struct AdmissionAuth {
    current_digest: [u8; 32],
    previous_digest: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionAuthError {
    InvalidCurrentToken,
    InvalidPreviousToken,
}

impl core::fmt::Display for AdmissionAuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidCurrentToken => {
                f.write_str("current ingest bearer token must be 32-256 visible ASCII bytes")
            }
            Self::InvalidPreviousToken => {
                f.write_str("previous ingest bearer token must be 32-256 visible ASCII bytes")
            }
        }
    }
}

impl std::error::Error for AdmissionAuthError {}

impl AdmissionAuth {
    pub fn new(current: &str, previous: Option<&str>) -> Result<Self, AdmissionAuthError> {
        if !valid_bearer_token(current) {
            return Err(AdmissionAuthError::InvalidCurrentToken);
        }
        if previous.is_some_and(|token| !valid_bearer_token(token)) {
            return Err(AdmissionAuthError::InvalidPreviousToken);
        }
        Ok(Self {
            current_digest: bearer_digest(current),
            previous_digest: previous.map(bearer_digest),
        })
    }

    fn authorizes(&self, headers: &HeaderMap) -> bool {
        let Some(raw) = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
        else {
            return false;
        };
        let Some((scheme, token)) = raw.split_once(' ') else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("bearer") || !valid_bearer_token(token) {
            return false;
        }
        let candidate = bearer_digest(token);
        let current_match = candidate.ct_eq(&self.current_digest);
        let previous_match = self
            .previous_digest
            .map_or_else(|| Choice::from(0), |previous| candidate.ct_eq(&previous));
        bool::from(current_match | previous_match)
    }
}

fn valid_bearer_token(token: &str) -> bool {
    (32..=256).contains(&token.len())
        && token
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_whitespace())
}

fn bearer_digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

pub struct GatewayHttpState<C> {
    producer: Arc<Mutex<ServiceProducer<C>>>,
    sample_requested: Arc<AtomicBool>,
    pub readiness: Arc<PipelineReadiness>,
    events: Arc<PipelineEvents>,
    admission_auth: AdmissionAuth,
    max_batch_records: usize,
    max_admission_bytes: usize,
}

impl<C> Clone for GatewayHttpState<C> {
    fn clone(&self) -> Self {
        Self {
            producer: Arc::clone(&self.producer),
            sample_requested: Arc::clone(&self.sample_requested),
            readiness: Arc::clone(&self.readiness),
            events: Arc::clone(&self.events),
            admission_auth: self.admission_auth.clone(),
            max_batch_records: self.max_batch_records,
            max_admission_bytes: self.max_admission_bytes,
        }
    }
}

impl<C: ElapsedClock> GatewayHttpState<C> {
    pub fn new(
        mut producer: ServiceProducer<C>,
        admission_auth: AdmissionAuth,
        max_batch_records: usize,
        max_admission_bytes: usize,
    ) -> Self {
        let events = producer.events();
        producer.store_mut().set_events(Arc::clone(&events));
        let limits = producer.store_mut().limits;
        Self {
            readiness: Arc::new(PipelineReadiness::new(limits)),
            events,
            producer: Arc::new(Mutex::new(producer)),
            sample_requested: Arc::new(AtomicBool::new(false)),
            admission_auth,
            max_batch_records,
            max_admission_bytes,
        }
    }
    pub fn with_capacity_limits(mut self, limits: CapacityLimits) -> Self {
        self.producer
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .store_mut()
            .set_capacity_limits(limits);
        self.readiness = Arc::new(PipelineReadiness::new(limits));
        self
    }

    pub fn sample_readiness(&self) {
        self.sample_requested.store(true, Ordering::Release);
        let mut producer = match self.producer.try_lock() {
            Ok(producer) => producer,
            // The active operation services the pending tick before releasing
            // the mutex. A stuck operation still lets cached observations expire.
            Err(TryLockError::WouldBlock) => return,
            Err(TryLockError::Poisoned(_)) => {
                self.readiness.observe(ReadinessSample {
                    database_available: false,
                    producer_state: "unavailable",
                    reasons: vec!["producer_lock_poisoned"],
                    statistics: None,
                });
                return;
            }
        };
        self.sample_if_requested(&mut producer);
    }

    fn with_producer<T>(
        &self,
        operation: impl FnOnce(&mut ServiceProducer<C>) -> Result<T, ProducerError>,
    ) -> Result<T, ProducerError> {
        let mut producer = self
            .producer
            .lock()
            .map_err(|_| ProducerError::Store("producer mutex is poisoned".into()))?;
        let result = operation(&mut producer);
        self.sample_if_requested(&mut producer);
        result
    }

    fn sample_if_requested(&self, producer: &mut ServiceProducer<C>) {
        if !self.sample_requested.swap(false, Ordering::AcqRel) {
            return;
        }
        let producer_state = producer.readiness_state();
        let mut reasons = match producer_state {
            "ready" => Vec::new(),
            "inactive" => vec!["producer_inactive"],
            "recovery_required" => vec!["producer_recovery_required"],
            _ => vec!["producer_clock_unavailable"],
        };
        let revision = producer.state().revision;
        let mut observed = producer.store_mut().pipeline_statistics(revision);
        // Seal elapsed intervals even when admission capacity is exhausted.
        // First check writability and revision, so a stale producer or a write
        // freeze cannot drive background mutations.
        if producer_state == "ready" && observed.is_ok() {
            match producer.seal_expired_intervals() {
                Ok(_) if producer.state().revision != revision => {
                    let revision = producer.state().revision;
                    observed = producer.store_mut().pipeline_statistics(revision);
                }
                Ok(_) => (),
                Err(_) => reasons.push("producer_sealing_failed"),
            }
        }
        let (database_available, statistics) = match observed {
            Ok(stats) => (true, Some(stats)),
            Err(ProducerError::DatabaseReadOnly) => {
                reasons.push("database_read_only");
                (true, None)
            }
            Err(ProducerError::ConcurrentWriter) => {
                reasons.push("producer_revision_mismatch");
                (true, None)
            }
            Err(_) => {
                reasons.push("database_unavailable");
                (false, None)
            }
        };
        self.readiness.observe(ReadinessSample {
            database_available,
            producer_state,
            reasons,
            statistics,
        });
    }
}

impl<C: ElapsedClock + Send + 'static> GatewayHttpState<C> {
    pub fn start_readiness_sampler(&self) -> tokio::task::JoinHandle<()> {
        let state = self.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(SAMPLE_INTERVAL_SECONDS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let sample_state = state.clone();
                if tokio::task::spawn_blocking(move || sample_state.sample_readiness())
                    .await
                    .is_err()
                {
                    state.readiness.observe(ReadinessSample {
                        database_available: false,
                        producer_state: "unavailable",
                        reasons: vec!["observation_unavailable"],
                        statistics: None,
                    });
                }
            }
        })
    }
}

pub fn router<C>(state: GatewayHttpState<C>) -> Router
where
    C: ElapsedClock + Send + 'static,
{
    let events = Arc::clone(&state.events);
    let protected = Router::new()
        .route("/v2/records", post(admit::<C>))
        .route("/v2/record-batches", post(admit_batch::<C>))
        .route(
            "/v2/segments/{segment_number}/timestamp",
            get(timestamp_status::<C>),
        )
        .route_layer(middleware::from_fn_with_state(
            state.admission_auth.clone(),
            require_bearer,
        ));
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(readiness::<C>))
        .merge(protected)
        .layer(DefaultBodyLimit::max(HARD_MAX_ADMISSION_BYTES))
        .layer(middleware::from_fn_with_state(
            events,
            count_admission_rejections,
        ))
        .with_state(state)
}

async fn count_admission_rejections(
    State(events): State<Arc<PipelineEvents>>,
    request: Request,
    next: Next,
) -> Response {
    let admission = request.method() == axum::http::Method::POST
        && matches!(request.uri().path(), "/v2/records" | "/v2/record-batches");
    let response = next.run(request).await;
    if admission && (response.status().is_client_error() || response.status().is_server_error()) {
        events.admission_rejections.fetch_add(1, Ordering::Relaxed);
    }
    response
}

async fn readiness<C: ElapsedClock>(State(state): State<GatewayHttpState<C>>) -> Response {
    let (ready, value) = state.readiness.response(&state.events);
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(value),
    )
        .into_response()
}

async fn require_bearer(
    State(auth): State<AdmissionAuth>,
    request: Request,
    next: Next,
) -> Response {
    if auth.authorizes(request.headers()) {
        next.run(request).await
    } else {
        unauthorized_response()
    }
}

async fn timestamp_status<C>(
    State(state): State<GatewayHttpState<C>>,
    Path(number): Path<String>,
) -> Response
where
    C: ElapsedClock + Send + 'static,
{
    let number = match number.parse::<u64>() {
        Ok(parsed) if number.bytes().all(|byte| byte.is_ascii_digit()) => parsed,
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "segment_number",
                "segment number must be uint64",
            );
        }
    };
    match tokio::task::spawn_blocking(move || {
        state.with_producer(|producer| producer.store_mut().timestamp_status(number))
    })
    .await
    {
        Ok(Ok(Some(status))) => Json(status).into_response(),
        Ok(Ok(None)) => error_response(
            StatusCode::NOT_FOUND,
            "segment_not_found",
            "sealed segment was not found",
        ),
        Ok(Err(error)) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "timestamp_status",
            &error.to_string(),
        ),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "blocking_task",
            &error.to_string(),
        ),
    }
}

async fn health() -> impl IntoResponse {
    Json(json!({"ok": true, "profile": trackone_ledger::vtl::COMMITMENT_PROFILE_ID}))
}

async fn admit<C>(
    State(state): State<GatewayHttpState<C>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    C: ElapsedClock + Send + 'static,
{
    if headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        != Some(CBOR_MEDIA_TYPE)
    {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "content_type",
            "Content-Type must be application/cbor",
        );
    }
    if headers.contains_key(CONTENT_ENCODING) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "content_encoding",
            "Content-Encoding is not supported for individual records",
        );
    }
    if body.len() > state.max_admission_bytes {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "admission_bytes",
            "expanded admission exceeds TRACKONE_MAX_ADMISSION_BYTES",
        );
    }
    admit_records(state, headers, vec![body.to_vec()], None, false).await
}

async fn admit_batch<C>(
    State(state): State<GatewayHttpState<C>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    C: ElapsedClock + Send + 'static,
{
    if media_type(&headers) != Some(BATCH_CBOR_MEDIA_TYPE) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "content_type",
            "Content-Type must be application/vnd.trackone.record-batch.v1+cbor",
        );
    }
    let expanded = match headers
        .get(CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
    {
        None | Some("identity") => body.to_vec(),
        Some("gzip") => match expand_gzip(&body, state.max_admission_bytes) {
            Ok(bytes) => bytes,
            Err(BatchEnvelopeError::Limit) => {
                return error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "admission_bytes",
                    "expanded admission exceeds TRACKONE_MAX_ADMISSION_BYTES",
                );
            }
            Err(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "batch_envelope",
                    "gzip body is malformed",
                );
            }
        },
        Some(_) => {
            return error_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "content_encoding",
                "Content-Encoding must be identity or gzip",
            );
        }
    };
    if expanded.len() > state.max_admission_bytes {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "admission_bytes",
            "expanded admission exceeds TRACKONE_MAX_ADMISSION_BYTES",
        );
    }
    let records = match parse_batch_envelope(&expanded, state.max_batch_records) {
        Ok(records) => records,
        Err(BatchEnvelopeError::Limit) => {
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "batch_records",
                "batch exceeds TRACKONE_MAX_BATCH_RECORDS",
            );
        }
        Err(BatchEnvelopeError::Malformed(message)) => {
            return error_response(StatusCode::BAD_REQUEST, "batch_envelope", message);
        }
    };
    admit_records(state, headers, records, Some(expanded), true).await
}

async fn admit_records<C>(
    state: GatewayHttpState<C>,
    headers: HeaderMap,
    records: Vec<Vec<u8>>,
    envelope: Option<Vec<u8>>,
    batch: bool,
) -> Response
where
    C: ElapsedClock + Send + 'static,
{
    let Some(key) = headers
        .get(IDEMPOTENCY_KEY)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
    else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "idempotency_key",
            "Idempotency-Key is required",
        );
    };
    let minimal = headers
        .get("prefer")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|item| item.trim().eq_ignore_ascii_case("return=minimal"))
        });
    let result = tokio::task::spawn_blocking(move || {
        let outcome = state.with_producer(|producer| {
            if let Some(envelope) = envelope {
                producer.admit_batch_idempotent(key, records, &envelope)
            } else {
                let record = records.into_iter().next().ok_or_else(|| {
                    ProducerError::Store("single-record admission contains no record".into())
                })?;
                producer.admit_idempotent(key, record)
            }
        })?;

        let tsa_status = if outcome.sealed_segment_numbers.is_empty() {
            "not_applicable"
        } else if outcome.replayed {
            // Status is a projection: a failed lookup cannot revoke durable admission.
            let statuses = state
                .with_producer(|producer| {
                    producer
                        .store_mut()
                        .tsa_statuses(&outcome.sealed_segment_numbers)
                })
                .unwrap_or_default();
            if statuses.iter().any(|status| status == "failed") {
                "failed"
            } else if statuses.len() == outcome.sealed_segment_numbers.len()
                && statuses.iter().all(|status| status == "verified")
            {
                "verified"
            } else {
                "queued"
            }
        } else {
            "queued"
        };
        Ok::<_, ProducerError>((outcome, tsa_status))
    })
    .await;
    match result {
        Ok(Ok((outcome, tsa_status))) => {
            let status = if outcome.replayed {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            };
            if minimal {
                let mut response = status.into_response();
                response.headers_mut().insert(
                    HeaderName::from_static("preference-applied"),
                    HeaderValue::from_static("return=minimal"),
                );
                return response;
            }
            let value = if batch {
                json!({
                    "state_revision": outcome.state_revision.to_string(),
                    "admitted_record_count": outcome.admitted_record_count.to_string(),
                    "admission_runs": outcome.admission_runs.iter().map(|run| json!({
                        "segment_number": run.segment_number.to_string(),
                        "record_count": run.record_count.to_string()
                    })).collect::<Vec<_>>(),
                    "sealed_segment_numbers": outcome.sealed_segment_numbers.iter()
                        .map(u64::to_string).collect::<Vec<_>>(),
                    "replayed": outcome.replayed,
                    "tsa_status": tsa_status
                })
            } else {
                json!({
                    "ok": true,
                    "replayed": outcome.replayed,
                    "state_revision": outcome.state_revision.to_string(),
                    "admitted_segment_number": outcome.admitted_segment_number.to_string(),
                    "tsa_status": tsa_status,
                    "sealed_segment_numbers": outcome.sealed_segment_numbers.iter()
                        .map(u64::to_string).collect::<Vec<_>>()
                })
            };
            (status, Json(value)).into_response()
        }
        Ok(Err(ProducerError::IdempotencyConflict)) => error_response(
            StatusCode::CONFLICT,
            "idempotency_conflict",
            "Idempotency-Key was already used for different canonical bytes",
        ),
        Ok(Err(ProducerError::InvalidRecord(message))) => {
            error_response(StatusCode::UNPROCESSABLE_ENTITY, "invalid_record", &message)
        }
        Ok(Err(error)) => {
            let code = match error {
                ProducerError::QueueCapacityExhausted => "queue_capacity_exhausted",
                ProducerError::StorageCapacityExhausted => "storage_capacity_exhausted",
                ProducerError::StorageUnavailable(_) => "storage_unavailable",
                _ => "producer_unavailable",
            };
            (StatusCode::SERVICE_UNAVAILABLE, Json(json!({
                "ok": false, "admission_available": false, "error": code, "message": error.to_string()
            }))).into_response()
        }
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "blocking_task",
            &error.to_string(),
        ),
    }
}

fn media_type(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
}

#[derive(Debug)]
enum BatchEnvelopeError {
    Malformed(&'static str),
    Limit,
}

fn expand_gzip(input: &[u8], limit: usize) -> Result<Vec<u8>, BatchEnvelopeError> {
    let offset = gzip_deflate_offset(input)?;
    let mut decompressor = Decompress::new(false);
    let mut output = Vec::new();
    let mut crc = Crc::new();
    let mut scratch = [0_u8; 8192];
    loop {
        let before_in = decompressor.total_in();
        let before_out = decompressor.total_out();
        let remaining = limit.saturating_sub(output.len()).saturating_add(1);
        let output_width = remaining.min(scratch.len());
        let consumed = usize::try_from(before_in)
            .map_err(|_| BatchEnvelopeError::Malformed("gzip member is too large"))?;
        let input_offset = offset
            .checked_add(consumed)
            .ok_or(BatchEnvelopeError::Malformed(
                "gzip member length overflows",
            ))?;
        let status = decompressor
            .decompress(
                input
                    .get(input_offset..)
                    .ok_or(BatchEnvelopeError::Malformed("truncated gzip stream"))?,
                &mut scratch[..output_width],
                FlushDecompress::None,
            )
            .map_err(|_| BatchEnvelopeError::Malformed("malformed gzip deflate stream"))?;
        let produced = usize::try_from(decompressor.total_out() - before_out)
            .map_err(|_| BatchEnvelopeError::Malformed("gzip output is too large"))?;
        crc.update(&scratch[..produced]);
        output.extend_from_slice(&scratch[..produced]);
        if output.len() > limit {
            return Err(BatchEnvelopeError::Limit);
        }
        if status == Status::StreamEnd {
            break;
        }
        if decompressor.total_in() == before_in && decompressor.total_out() == before_out {
            return Err(BatchEnvelopeError::Malformed(
                "truncated gzip deflate stream",
            ));
        }
    }
    let consumed = usize::try_from(decompressor.total_in())
        .map_err(|_| BatchEnvelopeError::Malformed("gzip member is too large"))?;
    let trailer = offset
        .checked_add(consumed)
        .ok_or(BatchEnvelopeError::Malformed(
            "gzip member length overflows",
        ))?;
    let end = trailer.checked_add(8).ok_or(BatchEnvelopeError::Malformed(
        "gzip member length overflows",
    ))?;
    if end != input.len() {
        return Err(BatchEnvelopeError::Malformed(
            "gzip body has trailing data or multiple members",
        ));
    }
    let expected_crc = u32::from_le_bytes(
        input[trailer..trailer + 4]
            .try_into()
            .map_err(|_| BatchEnvelopeError::Malformed("invalid gzip CRC trailer"))?,
    );
    let expected_size = u32::from_le_bytes(
        input[trailer + 4..end]
            .try_into()
            .map_err(|_| BatchEnvelopeError::Malformed("invalid gzip size trailer"))?,
    );
    if crc.sum() != expected_crc || crc.amount() != expected_size {
        return Err(BatchEnvelopeError::Malformed(
            "gzip data checksum or size is invalid",
        ));
    }
    Ok(output)
}

fn gzip_deflate_offset(input: &[u8]) -> Result<usize, BatchEnvelopeError> {
    if input.len() < 18 || input.get(0..3) != Some(&[0x1f, 0x8b, 8]) {
        return Err(BatchEnvelopeError::Malformed("invalid gzip header"));
    }
    let flags = input[3];
    if flags & 0xe0 != 0 {
        return Err(BatchEnvelopeError::Malformed("reserved gzip flags"));
    }
    let mut offset = 10_usize;
    if flags & 0x04 != 0 {
        let length = input
            .get(offset..offset + 2)
            .map(|bytes| usize::from(u16::from_le_bytes([bytes[0], bytes[1]])))
            .ok_or(BatchEnvelopeError::Malformed("truncated gzip extra field"))?;
        offset = offset
            .checked_add(2 + length)
            .ok_or(BatchEnvelopeError::Malformed("gzip header overflows"))?;
        if offset > input.len() {
            return Err(BatchEnvelopeError::Malformed("truncated gzip extra field"));
        }
    }
    for flag in [0x08, 0x10] {
        if flags & flag != 0 {
            let end = input
                .get(offset..)
                .and_then(|bytes| bytes.iter().position(|byte| *byte == 0))
                .ok_or(BatchEnvelopeError::Malformed(
                    "unterminated gzip string field",
                ))?;
            offset += end + 1;
        }
    }
    if flags & 0x02 != 0 {
        let expected = input
            .get(offset..offset + 2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
            .ok_or(BatchEnvelopeError::Malformed(
                "truncated gzip header checksum",
            ))?;
        let mut crc = Crc::new();
        crc.update(&input[..offset]);
        if crc.sum() as u16 != expected {
            return Err(BatchEnvelopeError::Malformed(
                "gzip header checksum is invalid",
            ));
        }
        offset = offset
            .checked_add(2)
            .ok_or(BatchEnvelopeError::Malformed("gzip header overflows"))?;
    }
    if offset
        .checked_add(8)
        .is_none_or(|minimum| minimum > input.len())
    {
        return Err(BatchEnvelopeError::Malformed("truncated gzip member"));
    }
    Ok(offset)
}

fn parse_batch_envelope(
    bytes: &[u8],
    max_records: usize,
) -> Result<Vec<Vec<u8>>, BatchEnvelopeError> {
    let mut offset = 0;
    let count = read_cbor_len(bytes, &mut offset, 4)?;
    let count = usize::try_from(count).map_err(|_| BatchEnvelopeError::Limit)?;
    if count == 0 {
        return Err(BatchEnvelopeError::Malformed("batch must not be empty"));
    }
    if count > max_records {
        return Err(BatchEnvelopeError::Limit);
    }
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let length = read_cbor_len(bytes, &mut offset, 2)?;
        let length = usize::try_from(length).map_err(|_| BatchEnvelopeError::Limit)?;
        let end = offset
            .checked_add(length)
            .ok_or(BatchEnvelopeError::Malformed("record length overflows"))?;
        let record = bytes.get(offset..end).ok_or(BatchEnvelopeError::Malformed(
            "truncated record byte string",
        ))?;
        records.push(record.to_vec());
        offset = end;
    }
    if offset != bytes.len() {
        return Err(BatchEnvelopeError::Malformed(
            "batch envelope has trailing bytes",
        ));
    }
    Ok(records)
}

fn read_cbor_len(
    bytes: &[u8],
    offset: &mut usize,
    expected_major: u8,
) -> Result<u64, BatchEnvelopeError> {
    let initial = *bytes
        .get(*offset)
        .ok_or(BatchEnvelopeError::Malformed("truncated CBOR envelope"))?;
    *offset += 1;
    if initial >> 5 != expected_major {
        return Err(BatchEnvelopeError::Malformed(
            "batch must be a definite array of byte strings",
        ));
    }
    let additional = initial & 0x1f;
    let (length, width) = match additional {
        value @ 0..=23 => (u64::from(value), 0),
        24 => (read_uint(bytes, offset, 1)?, 1),
        25 => (read_uint(bytes, offset, 2)?, 2),
        26 => (read_uint(bytes, offset, 4)?, 4),
        27 => (read_uint(bytes, offset, 8)?, 8),
        _ => {
            return Err(BatchEnvelopeError::Malformed(
                "indefinite or reserved CBOR length",
            ));
        }
    };
    if (width == 1 && length < 24)
        || (width == 2 && length <= u64::from(u8::MAX))
        || (width == 4 && length <= u64::from(u16::MAX))
        || (width == 8 && length <= u64::from(u32::MAX))
    {
        return Err(BatchEnvelopeError::Malformed(
            "CBOR envelope length is not shortest-form",
        ));
    }
    Ok(length)
}

fn read_uint(bytes: &[u8], offset: &mut usize, width: usize) -> Result<u64, BatchEnvelopeError> {
    let end = offset
        .checked_add(width)
        .ok_or(BatchEnvelopeError::Malformed("CBOR length overflows"))?;
    let slice = bytes
        .get(*offset..end)
        .ok_or(BatchEnvelopeError::Malformed("truncated CBOR length"))?;
    *offset = end;
    Ok(slice
        .iter()
        .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)))
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({"ok": false, "error": code, "message": message})),
    )
        .into_response()
}

fn unauthorized_response() -> Response {
    let mut response = error_response(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "valid bearer authentication is required",
    );
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"trackone-ingest\""),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use flate2::{Compression, GzBuilder};
    use std::io::Write;
    use tower::ServiceExt;

    fn record(counter: u8) -> Vec<u8> {
        vec![
            0x87, 0x01, 0x48, 0, 0, 0, 0, 0, 0, 0, counter, counter, 0, 0xf6, 0, 0xf6,
        ]
    }

    fn envelope(records: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = vec![0x80 | records.len() as u8];
        for record in records {
            bytes.push(0x40 | record.len() as u8);
            bytes.extend_from_slice(record);
        }
        bytes
    }

    #[test]
    fn batch_envelope_is_exact_shortest_form_and_preserves_order_and_duplicates() {
        let records = vec![record(2), record(1), record(2)];
        assert_eq!(
            parse_batch_envelope(&envelope(&records), 10).unwrap(),
            records
        );
        assert!(parse_batch_envelope(&[0x98, 0x01, 0x40], 10).is_err());
        let mut trailing = envelope(&[record(1)]);
        trailing.push(0);
        assert!(parse_batch_envelope(&trailing, 10).is_err());
    }

    #[test]
    fn gzip_expansion_is_representation_independent_and_bounded() {
        let expanded = envelope(&[record(1), record(2)]);
        let mut encoder = GzBuilder::new()
            .mtime(0)
            .write(Vec::new(), Compression::fast());
        encoder.write_all(&expanded).unwrap();
        let compressed = encoder.finish().unwrap();
        assert_eq!(expand_gzip(&compressed, expanded.len()).unwrap(), expanded);
        assert!(matches!(
            expand_gzip(&compressed, expanded.len() - 1),
            Err(BatchEnvelopeError::Limit)
        ));
        let mut trailing = compressed;
        trailing.push(0);
        assert!(matches!(
            expand_gzip(&trailing, expanded.len()),
            Err(BatchEnvelopeError::Malformed(_))
        ));
    }

    #[test]
    fn gzip_expansion_rejects_corrupt_trailers_and_multiple_members() {
        let expanded = vec![0x42; 4096];
        let mut encoder = GzBuilder::new()
            .mtime(0)
            .write(Vec::new(), Compression::best());
        encoder.write_all(&expanded).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut corrupt = compressed.clone();
        let trailer = corrupt.len() - 8;
        corrupt[trailer] ^= 0x01;
        assert!(matches!(
            expand_gzip(&corrupt, expanded.len()),
            Err(BatchEnvelopeError::Malformed(_))
        ));

        let mut multiple = compressed.clone();
        multiple.extend_from_slice(&compressed);
        assert!(matches!(
            expand_gzip(&multiple, expanded.len() * 2),
            Err(BatchEnvelopeError::Malformed(_))
        ));
    }

    #[test]
    fn gzip_expansion_stops_at_the_expanded_limit() {
        let expanded = vec![0; 1024 * 1024];
        let mut encoder = GzBuilder::new()
            .mtime(0)
            .write(Vec::new(), Compression::best());
        encoder.write_all(&expanded).unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(matches!(
            expand_gzip(&compressed, 1024),
            Err(BatchEnvelopeError::Limit)
        ));
    }

    #[test]
    fn bearer_auth_accepts_current_and_previous_tokens_only() {
        const CURRENT: &str = "current-token-0123456789abcdef0123456789";
        const PREVIOUS: &str = "previous-token-0123456789abcdef01234567";
        let auth = AdmissionAuth::new(CURRENT, Some(PREVIOUS)).unwrap();
        let mut headers = HeaderMap::new();

        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {CURRENT}")).unwrap(),
        );
        assert!(auth.authorizes(&headers));

        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("bearer {PREVIOUS}")).unwrap(),
        );
        assert!(auth.authorizes(&headers));

        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer wrong-token-0123456789abcdef0123456789"),
        );
        assert!(!auth.authorizes(&headers));
        headers.clear();
        assert!(!auth.authorizes(&headers));
    }

    #[test]
    fn bearer_auth_rejects_unsafe_configuration() {
        assert_eq!(
            AdmissionAuth::new("too-short", None).err(),
            Some(AdmissionAuthError::InvalidCurrentToken)
        );
        assert_eq!(
            AdmissionAuth::new(
                "current-token-0123456789abcdef0123456789",
                Some("previous token with spaces and enough bytes")
            )
            .err(),
            Some(AdmissionAuthError::InvalidPreviousToken)
        );
    }

    #[tokio::test]
    async fn bearer_middleware_blocks_unauthenticated_requests() {
        const TOKEN: &str = "current-token-0123456789abcdef0123456789";
        let auth = AdmissionAuth::new(TOKEN, None).unwrap();
        let app = Router::new()
            .route("/protected", post(|| async { StatusCode::NO_CONTENT }))
            .route_layer(middleware::from_fn_with_state(auth, require_bearer));

        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/protected")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            unauthorized.headers().get(WWW_AUTHENTICATE).unwrap(),
            "Bearer realm=\"trackone-ingest\""
        );

        let authorized = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/protected")
                    .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorized.status(), StatusCode::NO_CONTENT);
    }
}
