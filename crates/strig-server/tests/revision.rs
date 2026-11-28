//! Read your own writes against the decision server: a request that requires a revision is answered
//! from data that has reached it, or not answered.

mod support;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use strig::{Revision, Subject};
use strig_server::{ErrorCode, MIN_REVISION_HEADER, MemorySource, ServerConfig, TIMEOUT_HEADER};
use support::*;

fn check_body(user: &str) -> Value {
    json!({
        "subject": serde_json::to_value(Subject::user(user)).unwrap(),
        "permission": "document.view",
        "resource": serde_json::to_value(document("d1")).unwrap(),
    })
}

fn at(value: u64) -> Revision {
    Revision::new("tenant", value)
}

fn with_header(revision: &str, wait_ms: u64) -> Request<Body> {
    Request::post("/v1/check")
        .header(header::CONTENT_TYPE, "application/json")
        .header(MIN_REVISION_HEADER, revision)
        .header(TIMEOUT_HEADER, wait_ms.to_string())
        .body(Body::from(check_body("alice").to_string()))
        .unwrap()
}

fn source_at(value: u64) -> Arc<MemorySource> {
    Arc::new(MemorySource::new(snapshot().with_revision(at(value))))
}

#[tokio::test]
async fn a_snapshot_that_has_reached_the_revision_answers_and_echoes_it() {
    let router = server(source_at(5), ServerConfig::default());
    let mut body = check_body("alice");
    body["min_revision"] = json!("tenant@5");
    let (status, answer) = send(&router, json_post("/v1/check", &body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["decision"]["effect"], "allow");
    assert_eq!(answer["revision"], "tenant@5");

    let (status, answer) = send(&router, with_header("tenant@4", 1_000)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["revision"], "tenant@5");
}

#[tokio::test]
async fn without_a_requirement_the_answer_is_what_it_always_was() {
    let router = memory_server(ServerConfig::default());
    let (status, answer) = send(&router, json_post("/v1/check", &check_body("alice"))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(answer.get("revision").is_none());
}

#[tokio::test]
async fn data_behind_the_revision_is_refused_by_field_and_by_header() {
    let router = server(source_at(3), ServerConfig::default());
    let mut body = check_body("alice");
    body["min_revision"] = json!("tenant@4");
    let mut request = json_post("/v1/check", &body);
    request.headers_mut().insert(TIMEOUT_HEADER, "60".parse().unwrap());
    let (status, answer) = send(&router, request).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&answer), ErrorCode::RevisionNotReached.as_str());

    let (status, answer) = send(&router, with_header("tenant@4", 60)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&answer), "revision_not_reached");
}

#[tokio::test]
async fn the_header_covers_the_other_routes_too() {
    let router = server(source_at(3), ServerConfig::default());
    let request = Request::post("/v1/access")
        .header(header::CONTENT_TYPE, "application/json")
        .header(MIN_REVISION_HEADER, "tenant@9")
        .header(TIMEOUT_HEADER, "60")
        .body(Body::from(
            json!({"resource": serde_json::to_value(document("d1")).unwrap()}).to_string(),
        ))
        .unwrap();
    let (status, answer) = send(&router, request).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&answer), "revision_not_reached");
}

#[tokio::test]
async fn a_token_of_another_scope_is_a_mismatch_at_once() {
    let router = server(source_at(9), ServerConfig::default());
    let (status, answer) = send(&router, with_header("other@1", 5_000)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&answer), "revision_mismatch");
}

#[tokio::test]
async fn a_source_that_does_not_number_its_writes_cannot_prove_a_revision() {
    let router = memory_server(ServerConfig::default());
    let (status, answer) = send(&router, with_header("tenant@1", 5_000)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&answer), "revision_mismatch");
}

#[tokio::test]
async fn a_header_that_is_not_a_token_is_a_bad_request_never_ignored() {
    let router = server(source_at(9), ServerConfig::default());
    for raw in ["", "7", "tenant@", "tenant@x"] {
        let (status, answer) = send(&router, with_header(raw, 1_000)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{raw:?}");
        assert_eq!(error_code(&answer), "invalid_request");
    }
}

#[tokio::test]
async fn data_that_catches_up_before_the_deadline_answers() {
    let source = source_at(3);
    let router = server(source.clone(), ServerConfig::default());
    let lagging = source.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(80)).await;
        lagging.replace(snapshot().with_revision(at(4)));
    });
    let (status, answer) = send(&router, with_header("tenant@4", 2_000)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["revision"], "tenant@4");
}

#[tokio::test]
async fn a_batch_requires_the_revision_for_every_check() {
    let router = server(source_at(2), ServerConfig::default());
    let mut body = json!({"checks": [check_body("alice"), check_body("bob")], "min_revision": "tenant@2"});
    let (status, answer) = send(&router, json_post("/v1/check/batch", &body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["revision"], "tenant@2");
    body["min_revision"] = json!("tenant@3");
    let mut request = json_post("/v1/check/batch", &body);
    request.headers_mut().insert(TIMEOUT_HEADER, "50".parse().unwrap());
    let (status, answer) = send(&router, request).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&answer), "revision_not_reached");
}

#[cfg(feature = "client")]
mod client {
    use super::*;
    use strig_server::client::{Client, ClientConfig, ClientDecision, Failure, HttpTransport};
    use strig_server::wire::CheckRequest;

    async fn serve(source: Arc<MemorySource>) -> String {
        let router = server(source, ServerConfig::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        format!("http://{address}")
    }

    fn ask() -> CheckRequest {
        CheckRequest::new(Subject::user("alice"), "document.view", document("d1"))
    }

    #[tokio::test]
    async fn the_rust_client_passes_the_token_and_denies_when_the_server_is_behind() {
        let url = serve(source_at(3)).await;
        let client = Client::new(
            Arc::new(HttpTransport::new(url)),
            ClientConfig::default().with_timeout(Duration::from_millis(200)),
        );
        let reached = client.check_at_least(&ask(), &at(3)).await;
        assert!(reached.is_allowed());
        assert!(matches!(&reached, ClientDecision::Remote(answer) if answer.revision == Some(at(3))));

        let behind = client.check_at_least(&ask(), &at(4)).await;
        assert!(!behind.is_allowed());
        assert!(matches!(
            behind.failure(),
            Some(Failure::Server {
                code: Some(ErrorCode::RevisionNotReached),
                ..
            })
        ));

        let batch = client.check_batch_at_least(&[ask(), ask()], &at(4)).await;
        assert!(batch.iter().all(|decision| !decision.is_allowed()));
        // A server that is behind is not an outage: the breaker stays closed.
        assert_eq!(client.breaker_state(), strig_server::client::BreakerState::Closed);
    }
}
