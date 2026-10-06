//! Authenticated HTTP binding for exact VTL evidence and immutable disclosures.
use std::{collections::BTreeSet, sync::Arc};

use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use postgres::{Client, IsolationLevel};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use trackone_ledger::{sha256_hex, vtl::decode_segment_record};

use crate::snapshot::{DisclosureClass, ExportError, prepare_snapshot};

const MANIFEST: &str = "segment.verify.json";
const BASE: &str = "/v2/ledgers/{ledger}/segments/{segment}";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    ledger_id: String,
    read_segments: bool,
    classes: Vec<String>,
    batches: BatchGrant,
}

#[derive(Clone, Deserialize)]
#[serde(untagged)]
enum BatchGrant {
    All(String),
    Selected(Vec<String>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    principal_id: String,
    token: String,
    grants: Vec<Grant>,
}

#[derive(Clone, Default)]
pub struct DisclosureAuth {
    credentials: Vec<([u8; 32], Vec<Grant>)>,
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn number(value: &str) -> Option<u64> {
    let parsed = value.parse::<u64>().ok()?;
    (parsed.to_string() == value).then_some(parsed)
}
fn valid_token(value: &str) -> bool {
    (32..=256).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_graphic())
}
impl DisclosureAuth {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        let entries: Vec<Credential> = serde_json::from_slice(bytes)
            .map_err(|_| "invalid disclosure grants JSON".to_string())?;
        let mut credentials = Vec::new();
        let mut hashes = BTreeSet::new();
        for entry in entries {
            if entry.principal_id.trim().is_empty()
                || !valid_token(&entry.token)
                || entry.grants.is_empty()
            {
                return Err("invalid disclosure credential".into());
            }
            let hash: [u8; 32] = Sha256::digest(entry.token.as_bytes()).into();
            if !hashes.insert(hash) {
                return Err("duplicate disclosure credential".into());
            }
            let mut ledgers = BTreeSet::new();
            for grant in &entry.grants {
                if !hex(&grant.ledger_id, 32)
                    || !ledgers.insert(&grant.ledger_id)
                    || grant
                        .classes
                        .iter()
                        .any(|c| !matches!(c.as_str(), "A" | "B" | "C"))
                    || grant.classes.iter().collect::<BTreeSet<_>>().len() != grant.classes.len()
                {
                    return Err("invalid disclosure ledger or class grant".into());
                }
                match &grant.batches {
                    BatchGrant::All(value) if value == "all" => (),
                    BatchGrant::Selected(values)
                        if values.iter().all(|n| number(n).is_some())
                            && values.iter().collect::<BTreeSet<_>>().len() == values.len() => {}
                    _ => return Err("invalid disclosure batch grant".into()),
                }
            }
            credentials.push((hash, entry.grants));
        }
        Ok(Self { credentials })
    }
    fn authenticate(&self, headers: &HeaderMap) -> Result<Vec<Grant>, Failure> {
        if headers.get_all("authorization").iter().count() != 1 {
            return Err(Failure::Unauthorized);
        }
        let raw = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .ok_or(Failure::Unauthorized)?;
        let (scheme, token) = raw.split_once(' ').ok_or(Failure::Unauthorized)?;
        if !scheme.eq_ignore_ascii_case("bearer") || !valid_token(token) {
            return Err(Failure::Unauthorized);
        }
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut matched = None;
        for (candidate, grants) in &self.credentials {
            if bool::from(candidate.ct_eq(&hash)) {
                matched = Some(grants.clone());
            }
        }
        matched.ok_or(Failure::Unauthorized)
    }
}
impl Grant {
    fn permits(&self, class: &str, batches: &BTreeSet<u64>) -> bool {
        self.classes.iter().any(|c| c == class)
            && (class != "B"
                || match &self.batches {
                    BatchGrant::All(_) => true,
                    BatchGrant::Selected(allowed) => {
                        batches.iter().all(|b| allowed.contains(&b.to_string()))
                    }
                })
    }
}

type Connect = dyn Fn() -> Result<Client, String> + Send + Sync;
#[derive(Clone)]
pub struct EvidenceState {
    ledger: String,
    auth: DisclosureAuth,
    connect: Arc<Connect>,
    slots: Arc<tokio::sync::Semaphore>,
}
impl EvidenceState {
    pub fn new(
        ledger: String,
        auth: DisclosureAuth,
        connect: impl Fn() -> Result<Client, String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            ledger,
            auth,
            connect: Arc::new(connect),
            slots: Arc::new(tokio::sync::Semaphore::new(4)),
        }
    }
}
pub fn router(state: EvidenceState) -> Router {
    Router::new()
        .route(&format!("{BASE}/disclosures"), post(generate))
        .route(
            &format!("{BASE}/disclosures/{{digest}}/{{*path}}"),
            get(bundle_object),
        )
        .route(&format!("{BASE}/{{object}}"), get(current_object))
        .route_layer(axum::middleware::from_fn_with_state(
            state.auth.clone(),
            authenticate_request,
        ))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
        .with_state(state)
}

async fn authenticate_request(
    State(auth): State<DisclosureAuth>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if let Err(error) = auth.authenticate(request.headers()) {
        return error.into_response();
    }
    let headers = request.headers().clone();
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let mut response = next.run(request).await;
    if response.status() == StatusCode::ACCEPTED {
        let parts: Vec<_> = path.split('/').collect();
        if parts.len() >= 6 && hex(parts[3], 32) && number(parts[5]).is_some() {
            let monitor = format!("/v2/ledgers/{}/segments/{}/{MANIFEST}", parts[3], parts[5]);
            response
                .headers_mut()
                .insert("location", monitor.parse().unwrap());
        }
    }
    if matches!(method, axum::http::Method::GET | axum::http::Method::HEAD)
        && response.status() == StatusCode::OK
        && response.headers().contains_key("etag")
    {
        let etag = response.headers()["etag"].to_str().unwrap();
        let matches = |name: &str, weak: bool| {
            headers
                .get_all(name)
                .iter()
                .filter_map(|h| h.to_str().ok())
                .flat_map(|v| v.split(','))
                .any(|v| {
                    let v = v.trim();
                    v == "*"
                        || if weak {
                            v.strip_prefix("W/").unwrap_or(v) == etag
                        } else {
                            v == etag
                        }
                })
        };
        if headers.contains_key("if-match") && !matches("if-match", false) {
            return Failure::Precondition.into_response();
        }
        if headers.contains_key("if-none-match") && matches("if-none-match", true) {
            *response.status_mut() = StatusCode::NOT_MODIFIED;
            *response.body_mut() = axum::body::Body::empty();
            response.headers_mut().remove("content-length");
            response.headers_mut().remove("content-digest");
        }
    }
    if method == axum::http::Method::HEAD {
        // Content-Digest describes message content; HEAD has none. Repr-Digest
        // and ETag still describe the selected representation.
        response.headers_mut().remove("content-digest");
    }
    response
}

#[derive(Debug)]
enum Failure {
    Unauthorized,
    Denied,
    Absent,
    Pending,
    Unavailable(&'static str),
    Invalid,
    TooLarge,
    MediaType,
    Precondition,
}
impl From<postgres::Error> for Failure {
    fn from(_: postgres::Error) -> Self {
        Self::Unavailable("storage")
    }
}
impl From<ExportError> for Failure {
    fn from(error: ExportError) -> Self {
        match error {
            ExportError::Absent => Self::Absent,
            ExportError::Pending => Self::Pending,
            ExportError::Unavailable => Self::Unavailable("timestamp"),
            ExportError::Database(_) => Self::Unavailable("storage"),
            // Input selections are checked before calling the builder. Any other
            // builder rejection indicates incomplete or inconsistent storage.
            _ => Self::Unavailable("integrity"),
        }
    }
}
impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "bearer authentication required",
            ),
            Self::Denied => (
                StatusCode::FORBIDDEN,
                "policy_denied",
                "request is outside the credential grant",
            ),
            Self::Absent => (
                StatusCode::NOT_FOUND,
                "absent",
                "requested evidence was not found",
            ),
            Self::Pending => (
                StatusCode::ACCEPTED,
                "pending",
                "timestamp evidence is pending",
            ),
            Self::Unavailable(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "evidence is unavailable",
            ),
            Self::TooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "disclosure request exceeds 64 KiB",
            ),
            Self::MediaType => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                "disclosure requests require identity application/json",
            ),
            Self::Precondition => (
                StatusCode::PRECONDITION_FAILED,
                "precondition_failed",
                "object does not match the requested strong ETag",
            ),
            Self::Invalid => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid identifier or disclosure selection",
            ),
        };
        let mut body = if status == StatusCode::ACCEPTED {
            json!({"code":code,"message":message})
        } else {
            json!({
                "type": format!("https://github.com/bilalobe/trackone/blob/main/docs/vtl-http-binding.md#{}", code.replace('_', "-")),
                "title": status.canonical_reason().unwrap_or("Request failed"),
                "status": status.as_u16(), "detail": message, "code": code,
            })
        };
        if let Self::Unavailable(reason) = self {
            body["reason"] = json!(reason);
        }
        let mut response = (status, axum::Json(body)).into_response();
        if status != StatusCode::ACCEPTED {
            response
                .headers_mut()
                .insert("content-type", "application/problem+json".parse().unwrap());
        }
        response
            .headers_mut()
            .insert("cache-control", "private, no-store".parse().unwrap());
        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert("www-authenticate", "Bearer".parse().unwrap());
        }
        if status == StatusCode::ACCEPTED {
            response
                .headers_mut()
                .insert("retry-after", "5".parse().unwrap());
        }
        response
    }
}
fn base(ledger: &str, segment: u64) -> String {
    format!("/v2/ledgers/{ledger}/segments/{segment}")
}
fn authorize(
    state: &EvidenceState,
    headers: &HeaderMap,
    ledger: &str,
    segment: &str,
) -> Result<(Grant, u64), Failure> {
    let grants = state.auth.authenticate(headers)?;
    if !hex(ledger, 32) {
        return Err(Failure::Invalid);
    }
    let segment = number(segment).ok_or(Failure::Invalid)?;
    let grant = grants
        .into_iter()
        .find(|g| g.ledger_id == ledger)
        .ok_or(Failure::Denied)?;
    if ledger != state.ledger {
        return Err(Failure::Absent);
    }
    Ok((grant, segment))
}
fn object_response(bytes: Vec<u8>, path: &str, manifest: &str) -> Response {
    let digest = sha256_hex(&bytes);
    let media = if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".tsr") {
        "application/timestamp-reply"
    } else {
        "application/cbor"
    };
    let content_digest = format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(&bytes)));
    let mut response = bytes.into_response();
    for (name, value) in [
        ("content-type", media.to_string()),
        ("content-digest", content_digest.clone()),
        ("repr-digest", content_digest),
        ("etag", format!("\"{digest}\"")),
        ("cache-control", "private, no-store".into()),
        ("link", format!("<{manifest}>; rel=\"describedby\"")),
    ] {
        response.headers_mut().insert(
            axum::http::HeaderName::from_static(name),
            value.parse().unwrap(),
        );
    }
    response
}
async fn database_job<F>(state: EvidenceState, job: F) -> Result<Response, Failure>
where
    F: FnOnce(&mut Client) -> Result<Response, Failure> + Send + 'static,
{
    let permit = state
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| Failure::Unavailable("capacity"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut client = (state.connect)().map_err(|_| Failure::Unavailable("storage"))?;
        job(&mut client)
    })
    .await
    .map_err(|_| Failure::Unavailable("service"))?
}

// Current anchor view never reads record openings. One snapshot binds all of its
// references even if a worker attaches the timestamp concurrently.
type ObjectFiles = Vec<(String, Vec<u8>)>;

fn anchor_view(
    client: &mut Client,
    ledger: &str,
    segment: u64,
) -> Result<(Value, ObjectFiles), Failure> {
    let mut tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()?;
    let row = tx.query_opt("SELECT artifact_cbor, artifact_sha256, tsa_status, tsa_response FROM trackone_vtl_sealed_segment WHERE ledger_id=$1 AND segment_number=$2::text::numeric", &[&ledger, &segment.to_string()])?.ok_or(Failure::Absent)?;
    let bytes: Vec<u8> = row.get(0);
    let digest: String = row.get(1);
    let decoded = decode_segment_record(&bytes).map_err(|_| Failure::Unavailable("integrity"))?;
    if sha256_hex(&bytes) != digest
        || decoded.ledger_id != ledger
        || decoded.segment_number != segment
    {
        return Err(Failure::Unavailable("integrity"));
    }
    let mut artifacts = json!({"segment_cbor":{"path":"segment.cbor","sha256":digest}});
    let mut files = vec![("segment.cbor".into(), bytes)];
    if segment > 0 {
        let previous = tx.query_opt("SELECT artifact_cbor FROM trackone_vtl_sealed_segment WHERE ledger_id=$1 AND segment_number=$2::text::numeric", &[&ledger, &(segment - 1).to_string()])?.ok_or(Failure::Unavailable("integrity"))?;
        let bytes: Vec<u8> = previous.get(0);
        let prior = decode_segment_record(&bytes).map_err(|_| Failure::Unavailable("integrity"))?;
        if trackone_ledger::sha256_digest(&bytes) != decoded.prev_segment_sha256
            || prior.ledger_id != ledger
            || prior.segment_number != segment - 1
        {
            return Err(Failure::Unavailable("integrity"));
        }
        artifacts["predecessor_segment_cbor"] =
            json!({"path":"predecessor.cbor","sha256":sha256_hex(&bytes)});
        files.push(("predecessor.cbor".into(), bytes));
    }
    let status: String = row.get(2);
    let timestamp: Option<Vec<u8>> = row.get(3);
    let state = match (status.as_str(), timestamp) {
        ("queued", None) => "pending",
        ("failed", None) => "unavailable",
        ("verified", Some(bytes)) if !bytes.is_empty() => {
            artifacts["tsa_tsr"] = json!({"path":"timestamp.tsr","sha256":sha256_hex(&bytes)});
            files.push(("timestamp.tsr".into(), bytes));
            "present"
        }
        _ => return Err(Failure::Unavailable("integrity")),
    };
    tx.commit()?;
    Ok((
        json!({"version":1,"ledger_id":ledger,"segment_number":segment.to_string(),"commitment_profile_id":decoded.commitment_profile_id,"disclosure_class":"C","artifacts":artifacts,"anchoring":{"tsa":{"status":state}}}),
        files,
    ))
}
async fn current_object(
    State(state): State<EvidenceState>,
    Path((ledger, segment, object)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, Failure> {
    let (grant, segment) = authorize(&state, &headers, &ledger, &segment)?;
    if !grant.read_segments {
        return Err(Failure::Denied);
    }
    database_job(state, move |client| {
        let (manifest, files) = anchor_view(client, &ledger, segment)?;
        let link = format!("{}/{MANIFEST}", base(&ledger, segment));
        if object == MANIFEST {
            return Ok(object_response(
                serde_json::to_vec_pretty(&manifest).unwrap(),
                MANIFEST,
                &link,
            ));
        }
        if object == "timestamp.tsr" {
            match manifest["anchoring"]["tsa"]["status"].as_str() {
                Some("pending") => return Err(Failure::Pending),
                Some("unavailable") => return Err(Failure::Unavailable("timestamp")),
                _ => (),
            }
        }
        let (_, bytes) = files
            .into_iter()
            .find(|(path, _)| path == &object)
            .ok_or(Failure::Absent)?;
        Ok(object_response(bytes, &object, &link))
    })
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    class: String,
    #[serde(default)]
    batches: Vec<String>,
}
impl Selection {
    fn parse(&self) -> Result<(DisclosureClass, BTreeSet<u64>), Failure> {
        let class = DisclosureClass::parse(&self.class).map_err(|_| Failure::Invalid)?;
        let mut batches = BTreeSet::new();
        for batch in &self.batches {
            if !batches.insert(number(batch).ok_or(Failure::Invalid)?) {
                return Err(Failure::Invalid);
            }
        }
        if (class == DisclosureClass::B && batches.is_empty())
            || (class != DisclosureClass::B && !batches.is_empty())
        {
            return Err(Failure::Invalid);
        }
        Ok((class, batches))
    }
}
async fn generate(
    State(state): State<EvidenceState>,
    Path((ledger, segment)): Path<(String, String)>,
    headers: HeaderMap,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Response, Failure> {
    let (grant, segment) = authorize(&state, &headers, &ledger, &segment)?;
    let body = body.map_err(|error| {
        if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
            Failure::TooLarge
        } else {
            Failure::Invalid
        }
    })?;
    if headers.contains_key("content-encoding")
        || headers
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .map(|s| {
                s.split(';')
                    .next()
                    .unwrap()
                    .trim()
                    .eq_ignore_ascii_case("application/json")
            })
            != Some(true)
    {
        return Err(Failure::MediaType);
    }
    let selection: Selection = serde_json::from_slice(&body).map_err(|_| Failure::Invalid)?;
    let (class, batches) = selection.parse()?;
    if !grant.permits(&selection.class, &batches) {
        return Err(Failure::Denied);
    }
    database_job(state, move |client| {
        let (_, anchor_files) = anchor_view(client, &ledger, segment)?;
        let artifact = &anchor_files[0].1;
        let decoded = decode_segment_record(artifact).map_err(|_| Failure::Unavailable("integrity"))?;
        if class == DisclosureClass::B && (batches.len() >= decoded.batch_roots.len() || batches.iter().any(|b| *b >= decoded.batch_roots.len() as u64)) { return Err(Failure::Invalid); }
        let prepared = prepare_snapshot(client, &ledger, segment, class, &batches)?;
        let manifest = &prepared.files.iter().find(|(p, _)| p.to_str() == Some(MANIFEST)).ok_or(Failure::Unavailable("integrity"))?.1;
        let digest = sha256_hex(manifest);
        let mut tx = client.transaction()?;
        let created = tx.execute("INSERT INTO trackone_vtl_disclosure (ledger_id,segment_number,manifest_sha256,manifest) VALUES ($1,$2::text::numeric,$3,$4) ON CONFLICT DO NOTHING", &[&ledger, &segment.to_string(), &digest, manifest])? == 1;
        if created {
            for (path, bytes) in &prepared.files {
                if path.to_str() == Some(MANIFEST) { continue; }
                tx.execute("INSERT INTO trackone_vtl_disclosure_object (ledger_id,segment_number,manifest_sha256,path,bytes) VALUES ($1,$2::text::numeric,$3,$4,$5)", &[&ledger, &segment.to_string(), &digest, &path.to_str().ok_or(Failure::Unavailable("integrity"))?, bytes])?;
            }
        } else {
            let existing: Vec<u8> = tx.query_one("SELECT manifest FROM trackone_vtl_disclosure WHERE ledger_id=$1 AND segment_number=$2::text::numeric AND manifest_sha256=$3", &[&ledger, &segment.to_string(), &digest])?.get(0);
            if &existing != manifest { return Err(Failure::Unavailable("integrity")); }
        }
        tx.commit()?;
        let url = format!("{}/disclosures/{digest}/", base(&ledger, segment));
        let mut response = (if created { StatusCode::CREATED } else { StatusCode::OK }, axum::Json(json!({"ledger_id":ledger,"segment_number":segment.to_string(),"class":selection.class,"manifest_sha256":digest,"artifact_sha256":sha256_hex(artifact),"bundle_url":url}))).into_response();
        response.headers_mut().insert("location", format!("{url}{MANIFEST}").parse().unwrap());
        response.headers_mut().insert("cache-control", "private, no-store".parse().unwrap());
        Ok(response)
    }).await
}

fn manifest_selection(manifest: &Value) -> Result<Selection, Failure> {
    let class = manifest["disclosure_class"]
        .as_str()
        .ok_or(Failure::Unavailable("integrity"))?
        .to_string();
    let mut batches = Vec::new();
    if class == "B" {
        for batch in manifest["artifacts"]["record_batches"]
            .as_array()
            .ok_or(Failure::Unavailable("integrity"))?
        {
            batches.push(
                batch["batch_number"]
                    .as_str()
                    .ok_or(Failure::Unavailable("integrity"))?
                    .to_string(),
            );
        }
    }
    Ok(Selection { class, batches })
}
fn reference_digest<'a>(value: &'a Value, path: &str) -> Option<&'a str> {
    match value {
        Value::Object(map) => {
            if map.get("path").and_then(Value::as_str) == Some(path) {
                return map.get("sha256").and_then(Value::as_str);
            }
            map.values().find_map(|v| reference_digest(v, path))
        }
        Value::Array(values) => values.iter().find_map(|v| reference_digest(v, path)),
        _ => None,
    }
}
async fn bundle_object(
    State(state): State<EvidenceState>,
    Path((ledger, segment, digest, path)): Path<(String, String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, Failure> {
    let (grant, segment) = authorize(&state, &headers, &ledger, &segment)?;
    if grant.classes.is_empty() {
        return Err(Failure::Denied);
    }
    if !hex(&digest, 64) {
        return Err(Failure::Invalid);
    }
    database_job(state, move |client| {
        let row = client.query_opt("SELECT manifest FROM trackone_vtl_disclosure WHERE ledger_id=$1 AND segment_number=$2::text::numeric AND manifest_sha256=$3", &[&ledger, &segment.to_string(), &digest])?.ok_or(Failure::Absent)?;
        let bytes: Vec<u8> = row.get(0);
        if sha256_hex(&bytes) != digest { return Err(Failure::Unavailable("integrity")); }
        let manifest: Value = serde_json::from_slice(&bytes).map_err(|_| Failure::Unavailable("integrity"))?;
        if manifest["ledger_id"] != ledger || manifest["segment_number"].as_str().and_then(number) != Some(segment) { return Err(Failure::Unavailable("integrity")); }
        let selection = manifest_selection(&manifest)?;
        let (_, batches) = selection.parse().map_err(|_| Failure::Unavailable("integrity"))?;
        if !grant.permits(&selection.class, &batches) { return Err(Failure::Denied); }
        let link = format!("{}/disclosures/{digest}/{MANIFEST}", base(&ledger, segment));
        if path == MANIFEST { return Ok(object_response(bytes, &path, &link)); }
        let expected = reference_digest(&manifest["artifacts"], &path).ok_or(Failure::Absent)?;
        let row = client.query_opt("SELECT bytes FROM trackone_vtl_disclosure_object WHERE ledger_id=$1 AND segment_number=$2::text::numeric AND manifest_sha256=$3 AND path=$4", &[&ledger, &segment.to_string(), &digest, &path])?.ok_or(Failure::Unavailable("integrity"))?;
        let bytes: Vec<u8> = row.get(0);
        if sha256_hex(&bytes) != expected { return Err(Failure::Unavailable("integrity")); }
        Ok(object_response(bytes, &path, &link))
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential() -> Value {
        json!([{"principal_id":"auditor","token":"test-disclosure-credential-0000000000","grants":[{"ledger_id":"b7a1d5e40c6f438e9a75db27c96f31aa","read_segments":true,"classes":["B"],"batches":["0"]}]}])
    }
    #[test]
    fn configuration_is_explicit_and_fail_closed() {
        let valid = credential();
        assert!(DisclosureAuth::from_json(&serde_json::to_vec(&valid).unwrap()).is_ok());
        for (field, value) in [
            ("classes", json!(["D"])),
            ("classes", json!(["A", "A"])),
            ("batches", json!("*")),
            ("batches", json!(["00"])),
            ("batches", json!(["0", "0"])),
            ("ledger_id", json!("BAD")),
            ("extra", json!(true)),
        ] {
            let mut bad = valid.clone();
            bad[0]["grants"][0][field] = value;
            assert!(DisclosureAuth::from_json(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        let duplicated = json!([valid[0], valid[0]]);
        assert!(DisclosureAuth::from_json(&serde_json::to_vec(&duplicated).unwrap()).is_err());
        assert!(
            DisclosureAuth::default()
                .authenticate(&HeaderMap::new())
                .is_err()
        );
    }
    #[test]
    fn credentials_do_not_accept_ambiguous_headers() {
        let auth = DisclosureAuth::from_json(&serde_json::to_vec(&credential()).unwrap()).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer test-disclosure-credential-0000000000"
                .parse()
                .unwrap(),
        );
        let grant = auth.authenticate(&headers).unwrap().remove(0);
        assert!(grant.permits("B", &BTreeSet::from([0])));
        assert!(!grant.permits("B", &BTreeSet::from([1])));
        assert!(!grant.permits("A", &BTreeSet::new()));
        headers.append(
            "authorization",
            "Bearer test-disclosure-credential-0000000000"
                .parse()
                .unwrap(),
        );
        assert!(matches!(
            auth.authenticate(&headers),
            Err(Failure::Unauthorized)
        ));
    }
    #[test]
    fn fixture_errors_match_contract() {
        let fixtures: Value = serde_json::from_str(include_str!(
            "../../../toolset/vectors/vtl-http-binding/exchanges.json"
        ))
        .unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            for (name, failure) in [
                ("pending", Failure::Pending),
                ("unavailable", Failure::Unavailable("timestamp")),
                ("absent", Failure::Absent),
                ("unauthorized", Failure::Unauthorized),
                ("policy_denied", Failure::Denied),
            ] {
                let expected = &fixtures
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|f| f["name"] == name)
                    .unwrap()["response"];
                let response = failure.into_response();
                assert_eq!(
                    response.status().as_u16(),
                    expected["status"].as_u64().unwrap() as u16
                );
                for (key, value) in expected["headers"].as_object().unwrap() {
                    assert_eq!(response.headers()[key], value.as_str().unwrap());
                }
                let bytes = axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap();
                assert_eq!(
                    serde_json::from_slice::<Value>(&bytes).unwrap(),
                    expected["body"]
                );
            }
        });
    }
}
