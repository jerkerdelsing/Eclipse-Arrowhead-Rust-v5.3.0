// SPDX-License-Identifier: EPL-2.0
#[path = "../../ah5-support-runtime-rust/tests/common/mod.rs"]
mod common;
use arrowhead_localcloudmanager_rust::secure::{Config, Manager, console_router};
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use common::*;
use serde_json::{Value, json};
use tower::ServiceExt;

fn manager() -> (Fixture, Manager) {
    let f = Fixture::named("blacklist", "LocalCloudManager");
    let salt = vec![9; 16];
    let mut hash = vec![0; 32];
    scrypt::scrypt(
        b"console-test-password",
        &salt,
        &scrypt::Params::new(14, 8, 1, 32).unwrap(),
        &mut hash,
    )
    .unwrap();
    let password = f.temp.file(
        "console.hash",
        format!("scrypt:{}:{}", STANDARD.encode(salt), STANDARD.encode(hash)),
    );
    let gateway = f
        .temp
        .file("gateway.token", "isolated-gateway-test-secret-at-least32");
    let config = Config {
        cloud_suffix: SUFFIX.into(),
        project: "arrowhead-v53-test-cloud-rust".into(),
        listen: "127.0.0.1:0".into(),
        console_listen: "127.0.0.1:0".into(),
        certificate: f.config.certificate.clone(),
        private_key: f.config.private_key.clone(),
        ca: f.config.ca.clone(),
        crl_file: None,
        messaging: None,
        password_file: f.config.password_file.clone(),
        console_hash_file: password,
        console_origins: vec!["https://localhost:10590".into()],
        console_clients: Vec::new(),
        upstreams: [
            "Authentication",
            "ServiceRegistry",
            "ConsumerAuthorization",
            "DataManager",
            "SysMonitor",
            "PlantDescriptionEngine",
            "SimpleStoreServiceOrchestration",
            "Gatekeeper",
            "GateTunnel",
        ]
        .into_iter()
        .map(|n| (n.into(), "https://localhost:1/".into()))
        .collect(),
        docker_url: "http://localhost:1/".into(),
        docker_token_file: gateway,
        advertise_address: "localcloudmanager".into(),
        advertise_port: 8443,
    };
    let m = Manager::new(config, f.tls.clone()).unwrap();
    (f, m)
}
async fn request(
    app: axum::Router,
    method: &str,
    path: &str,
    body: Value,
    cookie: Option<&str>,
    origin: &str,
    confirm: bool,
) -> axum::response::Response {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", "localhost:10590")
        .header("Origin", origin)
        .header("Content-Type", "application/json");
    if let Some(cookie) = cookie {
        req = req.header("Cookie", cookie)
    }
    if confirm {
        req = req.header("X-Arrowhead-Action", "confirm")
    }
    app.oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}
#[tokio::test]
async fn secure_session_origin_and_confirm_guards() {
    let (_f, m) = manager();
    let app = console_router(m);
    let response = request(
        app.clone(),
        "GET",
        "/api/overview",
        json!({}),
        None,
        "https://localhost:10590",
        false,
    )
    .await;
    assert_eq!(response.status(), 401);
    let response = request(
        app.clone(),
        "POST",
        "/api/session",
        json!({"password":"console-test-password"}),
        None,
        "https://localhost:8590",
        false,
    )
    .await;
    assert_eq!(response.status(), 403);
    let response = request(
        app.clone(),
        "POST",
        "/api/session",
        json!({"password":"console-test-password"}),
        None,
        "https://localhost:10590",
        false,
    )
    .await;
    assert_eq!(response.status(), 204);
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(cookie.starts_with("__Host-ah_lcm_arrowhead-v53-test-cloud-rust="));
    for flag in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"] {
        assert!(cookie.contains(flag))
    }
    let cookie = cookie.split(';').next().unwrap();
    let response = request(
        app.clone(),
        "POST",
        "/api/plantdescriptions",
        json!({}),
        Some(cookie),
        "https://localhost:10590",
        false,
    )
    .await;
    assert_eq!(response.status(), 428);
    let response = request(
        app.clone(),
        "GET",
        "/api/session",
        json!({}),
        Some(cookie),
        "https://localhost:10590",
        false,
    )
    .await;
    assert_eq!(response.status(), 200);
    assert!(
        serde_json::from_slice::<Value>(&to_bytes(response.into_body(), 4096).await.unwrap())
            .unwrap()["authenticated"]
            == true
    );
    let response = request(
        app.clone(),
        "DELETE",
        "/api/session",
        json!({}),
        Some(cookie),
        "https://localhost:10590",
        false,
    )
    .await;
    assert_eq!(response.status(), 200);
    let response = request(
        app,
        "GET",
        "/api/overview",
        json!({}),
        Some(cookie),
        "https://localhost:10590",
        false,
    )
    .await;
    assert_eq!(response.status(), 401);
}
#[tokio::test]
async fn instances_do_not_share_sessions() {
    let (_f, m) = manager();
    let (_g, n) = manager();
    let response = request(
        console_router(m),
        "POST",
        "/api/session",
        json!({"password":"console-test-password"}),
        None,
        "https://localhost:10590",
        false,
    )
    .await;
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let response = request(
        console_router(n),
        "GET",
        "/api/overview",
        json!({}),
        Some(cookie),
        "https://localhost:10590",
        false,
    )
    .await;
    assert_eq!(response.status(), 401);
}
#[tokio::test]
async fn legacy_management_is_not_mounted() {
    let (_f, m) = manager();
    let app = console_router(m);
    let response = request(
        app,
        "GET",
        "/localcloud/management/systems",
        json!({}),
        None,
        "https://localhost:10590",
        false,
    )
    .await;
    assert_eq!(response.status(), 404);
}
#[test]
fn invalid_secrets_fail_at_start() {
    let (_f, m) = manager();
    let mut config = (*m.config).clone();
    config.console_hash_file = "/does/not/exist".into();
    let f = Fixture::named("blacklist", "LocalCloudManager");
    assert!(Manager::new(config, f.tls).is_err());
}
