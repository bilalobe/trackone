//! HTTP binding exercised against real PostgreSQL; CI requires the database.
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request},
};
use postgres::{Client, NoTls};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;
use trackone_gateway_svc::{
    evidence::{DisclosureAuth, EvidenceState, router},
    postgres::PostgresLedgerStore,
    producer::{ElapsedClock, LedgerProducer, ProducerError},
};
use trackone_ledger::{
    sha256_hex,
    vtl::{ClosurePolicy, EmptyMode},
};

const TOKEN: &str = "disclosure-test-token-0000000000000000";
const LIMITED: &str = "limited-disclosure-token-000000000000";
#[derive(Clone, Copy)]
struct Clock;
impl ElapsedClock for Clock {
    fn now_ms(&self) -> Result<u64, ProducerError> {
        Ok(0)
    }
    fn continuity_id(&self) -> u128 {
        1
    }
}
struct Database {
    url: String,
    schema: String,
    ledger: String,
}
impl Database {
    fn new() -> Option<Self> {
        let url = match std::env::var("TRACKONE_TEST_DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                assert!(
                    std::env::var_os("CI").is_none(),
                    "CI must provide PostgreSQL"
                );
                eprintln!("PostgreSQL binding test skipped: TRACKONE_TEST_DATABASE_URL unset");
                return None;
            }
        };
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let db = Self {
            url,
            schema: format!("binding_{unique:x}"),
            ledger: format!("{unique:032x}"),
        };
        Client::connect(&db.url, NoTls)
            .unwrap()
            .batch_execute(&format!("CREATE SCHEMA {}", db.schema))
            .unwrap();
        let mut store = PostgresLedgerStore::new(db.client(), &db.ledger);
        store.migrate().unwrap();
        store.migrate().unwrap();
        let mut producer = LedgerProducer::open_or_create(
            store,
            Clock,
            &db.ledger,
            "binding",
            ClosurePolicy {
                interval_ms: 60000,
                batch_record_limit: 2,
                record_limit: Some(5),
                size_limit_bytes: None,
                empty_mode: EmptyMode::Suppress,
            },
        )
        .unwrap();
        for counter in [3, 1, 1, 2, 4, 8, 7, 6, 5, 5] {
            producer
                .admit(vec![
                    0x87, 1, 0x48, 0, 0, 0, 0, 0, 0, 0, counter, counter, 0, 0xf6, 0, 0xf6,
                ])
                .unwrap();
        }
        Some(db)
    }
    fn client(&self) -> Client {
        connect(&self.url, &self.schema).unwrap()
    }
    fn app(&self) -> Router {
        let auth = DisclosureAuth::from_json(&serde_json::to_vec(&json!([
            {"principal_id":"auditor","token":TOKEN,"grants":[{"ledger_id":self.ledger,"read_segments":true,"classes":["A","B","C"],"batches":"all"}]},
            {"principal_id":"partner","token":LIMITED,"grants":[{"ledger_id":self.ledger,"read_segments":false,"classes":["B"],"batches":["0"]}]}
        ])).unwrap()).unwrap();
        let (url, schema) = (self.url.clone(), self.schema.clone());
        router(EvidenceState::new(self.ledger.clone(), auth, move || {
            connect(&url, &schema)
        }))
    }
    fn base(&self) -> String {
        format!("/v2/ledgers/{}/segments/1", self.ledger)
    }
    fn attach(&self) {
        self.client().execute("UPDATE trackone_vtl_sealed_segment SET tsa_status='verified',tsa_response=$1 WHERE ledger_id=$2", &[&b"retained-test-timestamp".to_vec(), &self.ledger]).unwrap();
    }
}
fn connect(url: &str, schema: &str) -> Result<Client, String> {
    let mut config = url.parse::<postgres::Config>().map_err(|e| e.to_string())?;
    config.options(&format!("-c search_path={schema}"));
    config.connect(NoTls).map_err(|e| e.to_string())
}
impl Drop for Database {
    fn drop(&mut self) {
        Client::connect(&self.url, NoTls)
            .unwrap()
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .unwrap();
    }
}
async fn request(
    app: &Router,
    path: &str,
    token: Option<&str>,
    selection: Option<Value>,
) -> (u16, HeaderMap, Vec<u8>) {
    let mut request =
        Request::builder()
            .uri(path)
            .method(if selection.is_some() { "POST" } else { "GET" });
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let body = if let Some(selection) = selection {
        request = request.header("content-type", "application/json");
        serde_json::to_vec(&selection).unwrap()
    } else {
        vec![]
    };
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    (status, headers, body)
}
fn value(body: &[u8]) -> Value {
    serde_json::from_slice(body).unwrap()
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

#[test]
fn states_authentication_and_immutable_artifact() {
    let Some(db) = Database::new() else { return };
    let app = db.app();
    let base = db.base();
    let rt = runtime();
    rt.block_on(async {
        for (credential, media, length, expected) in [
            (None, "application/json", 65537, 401),
            (Some(TOKEN), "application/json", 65537, 413),
            (Some(TOKEN), "application/cbor", 1, 415),
        ] {
            let mut req = Request::builder()
                .method("POST")
                .uri(format!("{base}/disclosures"))
                .header("content-type", media);
            if let Some(token) = credential {
                req = req.header("authorization", format!("Bearer {token}"));
            }
            let response = app
                .clone()
                .oneshot(req.body(Body::from(vec![0u8; length])).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), expected);
            assert_eq!(
                response.headers()["content-type"],
                "application/problem+json"
            );
        }

        let (status, headers, body) =
            request(&app, &format!("{base}/segment.cbor"), None, None).await;
        assert_eq!(status, 401);
        assert_eq!(value(&body)["code"], "unauthorized");
        assert_eq!(headers["www-authenticate"], "Bearer");
        assert_eq!(
            request(&app, &format!("{base}/segment.cbor"), Some(LIMITED), None)
                .await
                .0,
            403
        );
        assert_eq!(
            request(
                &app,
                &format!("{base}/disclosures"),
                Some(LIMITED),
                Some(json!({"class":"A"}))
            )
            .await
            .0,
            403
        );
        assert_eq!(
            request(
                &app,
                &format!("{base}/disclosures"),
                Some(LIMITED),
                Some(json!({"class":"B","batches":["1"]}))
            )
            .await
            .0,
            403
        );
        let (status, _, body) = request(
            &app,
            &format!("{base}/segment.verify.json"),
            Some(TOKEN),
            None,
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(value(&body)["anchoring"]["tsa"]["status"], "pending");
        let (status, headers, body) =
            request(&app, &format!("{base}/timestamp.tsr"), Some(TOKEN), None).await;
        assert_eq!(status, 202);
        assert_eq!(headers["retry-after"], "5");
        assert_eq!(headers["location"], format!("{base}/segment.verify.json"));
        assert_eq!(value(&body)["code"], "pending");
        assert_eq!(
            request(
                &app,
                &format!("{base}/disclosures"),
                Some(TOKEN),
                Some(json!({"class":"C"}))
            )
            .await
            .0,
            202
        );
        let (status, headers, bytes) =
            request(&app, &format!("{base}/segment.cbor"), Some(TOKEN), None).await;
        assert_eq!(status, 200);
        assert_eq!(headers["etag"], format!("\"{}\"", sha256_hex(&bytes)));
        assert!(headers.contains_key("content-digest"));
        let etag = headers["etag"].clone();
        for (method, header, expected) in [
            ("GET", "if-none-match", 304),
            ("GET", "if-match", 412),
            ("HEAD", "if-none-match", 304),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(format!("{base}/segment.cbor"))
                        .header("authorization", format!("Bearer {TOKEN}"))
                        .header(
                            header,
                            if header == "if-match" {
                                "\"wrong\"".parse().unwrap()
                            } else {
                                etag.clone()
                            },
                        )
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), expected);
            if expected == 304 {
                assert!(!response.headers().contains_key("content-digest"));
                assert!(response.headers().contains_key("repr-digest"));
                assert!(
                    to_bytes(response.into_body(), 1024)
                        .await
                        .unwrap()
                        .is_empty()
                );
            } else {
                assert_eq!(
                    response.headers()["content-type"],
                    "application/problem+json"
                );
            }
        }

        // Change operational state outside Tokio's runtime, then re-read below.
    });
    let stored: Vec<u8> = db.client().query_one("SELECT artifact_cbor FROM trackone_vtl_sealed_segment WHERE ledger_id=$1 AND segment_number=1", &[&db.ledger]).unwrap().get(0);
    db.client()
        .execute(
            "UPDATE trackone_vtl_sealed_segment SET tsa_status='failed' WHERE ledger_id=$1",
            &[&db.ledger],
        )
        .unwrap();
    rt.block_on(async {
        let (status, _, body) =
            request(&app, &format!("{base}/timestamp.tsr"), Some(TOKEN), None).await;
        assert_eq!(status, 503);
        assert_eq!(value(&body)["reason"], "timestamp");
        assert_eq!(
            request(&app, &format!("{base}/segment.cbor"), Some(TOKEN), None)
                .await
                .2,
            stored
        );
        assert_eq!(
            request(
                &app,
                &format!("/v2/ledgers/{}/segments/99/segment.cbor", db.ledger),
                Some(TOKEN),
                None
            )
            .await
            .0,
            404
        );
        assert_eq!(
            request(
                &app,
                "/v2/ledgers/00000000000000000000000000000000/segments/1/segment.cbor",
                Some(TOKEN),
                None
            )
            .await
            .0,
            403
        );
        assert_eq!(
            request(
                &app,
                &format!("/v2/ledgers/{}/segments/01/segment.cbor", db.ledger),
                Some(TOKEN),
                None
            )
            .await
            .0,
            400
        );
    });
    db.attach();
    rt.block_on(async {
        assert_eq!(
            request(&app, &format!("{base}/segment.cbor"), Some(TOKEN), None)
                .await
                .2,
            stored
        );
        assert_eq!(
            request(&app, &format!("{base}/timestamp.tsr"), Some(TOKEN), None)
                .await
                .2,
            b"retained-test-timestamp"
        );
        let (_, _, body) = request(
            &app,
            &format!("{base}/segment.verify.json"),
            Some(TOKEN),
            None,
        )
        .await;
        assert_eq!(value(&body)["anchoring"]["tsa"]["status"], "present");
    });
}

#[test]
fn complete_snapshots_replay_authorization_and_integrity() {
    let Some(db) = Database::new() else { return };
    db.attach();
    let app = db.app();
    let rt = runtime();
    let base = db.base();
    let mut class_b_url = String::new();
    rt.block_on(async {
        for selection in [
            json!({"class":"A"}),
            json!({"class":"B","batches":["0"]}),
            json!({"class":"C"}),
        ] {
            let (status, headers, body) = request(
                &app,
                &format!("{base}/disclosures"),
                Some(TOKEN),
                Some(selection.clone()),
            )
            .await;
            assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
            let response = value(&body);
            let url = response["bundle_url"].as_str().unwrap();
            let path = format!("{url}segment.verify.json");
            assert_eq!(headers["location"], path);
            let (status, _, manifest_bytes) = request(&app, &path, Some(TOKEN), None).await;
            assert_eq!(status, 200);
            assert_eq!(sha256_hex(&manifest_bytes), response["manifest_sha256"]);
            let manifest = value(&manifest_bytes);
            let mut refs = vec![
                manifest["artifacts"]["segment_cbor"].clone(),
                manifest["artifacts"]["predecessor_segment_cbor"].clone(),
                manifest["artifacts"]["tsa_tsr"].clone(),
            ];
            if let Some(batches) = manifest["artifacts"]["record_batches"].as_array() {
                for batch in batches {
                    refs.extend(batch["records"].as_array().unwrap().iter().cloned());
                }
            }
            for reference in refs {
                let (status, _, bytes) = request(
                    &app,
                    &format!("{url}{}", reference["path"].as_str().unwrap()),
                    Some(TOKEN),
                    None,
                )
                .await;
                assert_eq!(status, 200);
                assert_eq!(sha256_hex(&bytes), reference["sha256"]);
            }
            let expected = if selection["class"] == "B" {
                class_b_url = url.into();
                200
            } else {
                403
            };
            assert_eq!(
                request(&app, &format!("{url}segment.cbor"), Some(LIMITED), None)
                    .await
                    .0,
                expected
            );
            assert_eq!(
                request(&app, &format!("{url}unlisted.cbor"), Some(TOKEN), None)
                    .await
                    .0,
                404
            );
            assert_eq!(request(&app, &path, None, None).await.0, 401);
            let (status, _, body) = request(
                &app,
                &format!("{base}/disclosures"),
                Some(TOKEN),
                Some(selection),
            )
            .await;
            assert_eq!(status, 200);
            assert_eq!(value(&body), response);
        }
        for selection in [
            json!({"class":"B","batches":["0","0"]}),
            json!({"class":"B","batches":["0","1","2"]}),
            json!({"class":"B","batches":["9"]}),
            json!({"class":"A","batches":["0"]}),
            json!({"class":"C","extra":true}),
        ] {
            assert_eq!(
                request(
                    &app,
                    &format!("{base}/disclosures"),
                    Some(TOKEN),
                    Some(selection)
                )
                .await
                .0,
                400
            );
        }
    });
    // Fresh router/connection proves snapshots survive service reconstruction.
    let restarted = db.app();
    rt.block_on(async {
        assert_eq!(
            request(
                &restarted,
                &format!("{class_b_url}segment.cbor"),
                Some(TOKEN),
                None
            )
            .await
            .0,
            200
        );
    });
    db.client().execute("UPDATE trackone_vtl_disclosure_object SET bytes=$1 WHERE ledger_id=$2 AND path='segment.cbor'", &[&vec![0u8],&db.ledger]).unwrap();
    rt.block_on(async {
        assert_eq!(
            request(
                &restarted,
                &format!("{class_b_url}segment.cbor"),
                Some(TOKEN),
                None
            )
            .await
            .0,
            503
        );
    });
}

#[test]
fn concurrent_publication_is_atomic() {
    let Some(db) = Database::new() else { return };
    db.attach();
    let app = db.app();
    let path = format!("{}/disclosures", db.base());
    runtime().block_on(async {
        let (a, b) = tokio::join!(
            request(&app, &path, Some(TOKEN), Some(json!({"class":"A"}))),
            request(&app, &path, Some(TOKEN), Some(json!({"class":"A"})))
        );
        assert!((a.0 == 201 && b.0 == 200) || (a.0 == 200 && b.0 == 201));
        assert_eq!(a.2, b.2);
    });
}
