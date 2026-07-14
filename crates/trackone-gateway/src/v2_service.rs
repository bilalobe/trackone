//! HTTP handoff surface for exact v2 canonical-record CBOR bytes.

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

pub const CBOR_MEDIA_TYPE: &str = "application/cbor";
pub const IDEMPOTENCY_KEY: &str = "idempotency-key";

pub type ServiceProducer<C> = V2LedgerProducer<PostgresLedgerStore, C>;

pub struct GatewayHttpState<C> {
    producer: Arc<Mutex<ServiceProducer<C>>>,
}

impl<C> Clone for GatewayHttpState<C> {
    fn clone(&self) -> Self {
        Self {
            producer: Arc::clone(&self.producer),
        }
    }
}

impl<C> GatewayHttpState<C> {
    pub fn new(producer: ServiceProducer<C>) -> Self {
        Self {
            producer: Arc::new(Mutex::new(producer)),
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
    let result = tokio::task::spawn_blocking(move || {
        let mut producer = producer
            .lock()
            .map_err(|_| ProducerError::Store("producer mutex is poisoned".to_string()))?;
        producer.admit_idempotent(key, body.to_vec())
    })
    .await;
    match result {
        Ok(Ok(outcome)) => {
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
