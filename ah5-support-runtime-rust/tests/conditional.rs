// SPDX-License-Identifier: EPL-2.0
mod common;
use axum::{Json, Router, http::HeaderMap};
use common::*;
use serde_json::json;
#[tokio::test]
async fn conditional_headers_use_pinned_transport_without_authorization_override() {
    let (_auth, auth) = mock_auth().await;
    let provider = Fixture::named("blacklist", "SysMonitor");
    let router = Router::new().fallback(|headers: HeaderMap| async move {
        Json(json!({"revision":headers.get("if-match").and_then(|h|h.to_str().ok())}))
    });
    let server = start_router(provider.app.clone(), provider.tls.clone(), router).await;
    let mut client = Fixture::named("blacklist", "LocalCloudManager");
    client.config.authentication_url = auth.origin.clone();
    client
        .config
        .upstreams
        .insert("SysMonitor".into(), server.origin.clone());
    client.reconfigure();
    let response = client
        .app
        .remote
        .call_with_headers(
            "SysMonitor",
            "PUT",
            "/test",
            &json!({}),
            &[("If-Match", "\"7\"")],
        )
        .await
        .unwrap();
    assert_eq!(response["revision"], "\"7\"");
    assert_eq!(
        client
            .app
            .remote
            .call_with_headers(
                "SysMonitor",
                "PUT",
                "/test",
                &json!({}),
                &[("Authorization", "Bearer malicious")]
            )
            .await
            .unwrap_err()
            .code,
        400
    );
}
