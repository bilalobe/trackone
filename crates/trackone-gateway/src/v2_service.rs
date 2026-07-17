//! HTTP handoff surface for exact v2 canonical-record CBOR bytes.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header::CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use crate::v2_postgres::PostgresLedgerStore;
use crate::v2_producer::{ElapsedClock, ProducerError, V2LedgerProducer};
use crate::v2_tsa::Rfc3161TimestampAuthority;

pub const CBOR_MEDIA_TYPE: &str = "application/cbor";
pub const IDEMPOTENCY_KEY: &str = "idempotency-key";

pub type ServiceProducer<C> = V2LedgerProducer<PostgresLedgerStore, C>;

type PendingTimestamp = (u64, Vec<u8>, String);
type StampedTimestamp = (u64, String, Vec<u8>);

fn stamp_pending_timestamps(
    pending: Vec<PendingTimestamp>,
    timestamp_authority: &Rfc3161TimestampAuthority,
) -> (BTreeMap<u64, bool>, Vec<StampedTimestamp>) {
    let mut outcomes = BTreeMap::new();
    let mut stamped = Vec::new();
    for (segment_number, artifact, digest) in pending {
        match timestamp_authority.stamp(&artifact) {
            Ok(response) => {
                outcomes.insert(segment_number, true);
                stamped.push((segment_number, digest, response));
            }
            Err(_) => {
                outcomes.insert(segment_number, false);
            }
        }
    }
    (outcomes, stamped)
}

pub fn submit_pending_timestamps<C>(
    producer: &mut ServiceProducer<C>,
    timestamp_authority: &Rfc3161TimestampAuthority,
) -> Result<BTreeMap<u64, bool>, ProducerError>
where
    C: ElapsedClock,
{
    let (mut outcomes, stamped) = stamp_pending_timestamps(
        producer.store_mut().load_pending_tsa_segments()?,
        timestamp_authority,
    );
    for (segment_number, digest, response) in stamped {
        producer
            .store_mut()
            .attach_tsa_response(segment_number, &digest, &response)?;
        outcomes.insert(segment_number, true);
    }
    Ok(outcomes)
}

pub struct GatewayHttpState<C> {
    producer: Arc<Mutex<ServiceProducer<C>>>,
    timestamp_authority: Arc<Rfc3161TimestampAuthority>,
}

impl<C> Clone for GatewayHttpState<C> {
    fn clone(&self) -> Self {
        Self {
            producer: Arc::clone(&self.producer),
            timestamp_authority: Arc::clone(&self.timestamp_authority),
        }
    }
}

impl<C> GatewayHttpState<C> {
    pub fn new(
        producer: ServiceProducer<C>,
        timestamp_authority: Rfc3161TimestampAuthority,
    ) -> Self {
        Self {
            producer: Arc::new(Mutex::new(producer)),
            timestamp_authority: Arc::new(timestamp_authority),
        }
    }
}

pub fn router<C>(state: GatewayHttpState<C>) -> Router
where
    C: ElapsedClock + Send + 'static,
{
    Router::new()
        .route("/healthz", get(health))
        .route("/v2/records", post(admit::<C>))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(json!({"ok": true, "profile": "verifiable-telemetry-canonical-cbor-v2"}))
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
    let producer = Arc::clone(&state.producer);
    let timestamp_authority = Arc::clone(&state.timestamp_authority);
    let result = tokio::task::spawn_blocking(move || {
        let outcome = producer
            .lock()
            .map_err(|_| ProducerError::Store("producer mutex is poisoned".to_string()))?
            .admit_idempotent(key, body.to_vec())?;
        let pending = producer
            .lock()
            .map_err(|_| ProducerError::Store("producer mutex is poisoned".to_string()))?
            .store_mut()
            .load_pending_tsa_segments()?;
        let (mut timestamped, stamped) = stamp_pending_timestamps(pending, &timestamp_authority);
        if !stamped.is_empty() {
            let mut producer = producer
                .lock()
                .map_err(|_| ProducerError::Store("producer mutex is poisoned".to_string()))?;
            for (segment_number, digest, response) in stamped {
                producer
                    .store_mut()
                    .attach_tsa_response(segment_number, &digest, &response)?;
                timestamped.insert(segment_number, true);
            }
        }
        let tsa_status = if outcome.sealed_segment_numbers.is_empty() {
            "not_applicable"
        } else if outcome
            .sealed_segment_numbers
            .iter()
            .all(|number| timestamped.get(number).copied().unwrap_or(true))
        {
            "verified"
        } else {
            "pending"
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
            (
                status,
                Json(json!({
                    "ok": true,
                    "replayed": outcome.replayed,
                    "state_revision": outcome.state_revision.to_string(),
                    "admitted_segment_number": outcome.admitted_segment_number.to_string(),
                    "tsa_status": tsa_status,
                    "sealed_segment_numbers": outcome.sealed_segment_numbers.iter()
                        .map(u64::to_string).collect::<Vec<_>>()
                })),
            )
                .into_response()
        }
        Ok(Err(ProducerError::IdempotencyConflict)) => error_response(
            StatusCode::CONFLICT,
            "idempotency_conflict",
            "Idempotency-Key was already used for different canonical bytes",
        ),
        Ok(Err(ProducerError::InvalidRecord(message))) => {
            error_response(StatusCode::UNPROCESSABLE_ENTITY, "invalid_record", &message)
        }
        Ok(Err(error)) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "producer_unavailable",
            &error.to_string(),
        ),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "blocking_task",
            &error.to_string(),
        ),
    }
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({"ok": false, "error": code, "message": message})),
    )
        .into_response()
}
