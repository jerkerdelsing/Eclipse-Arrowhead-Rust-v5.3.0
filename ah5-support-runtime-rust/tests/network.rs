// SPDX-License-Identifier: EPL-2.0
mod common;
use arrowhead_support_rust::*;
use axum::{Json, Router};
use common::*;
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
#[tokio::test]
async fn all_fifteen_profiles_serve_real_mutual_tls_echo() {
    let client = Fixture::named("blacklist", "Client");
    for (role, name, base) in config::ROLES {
        let f = Fixture::new(role);
        let server = start(f.app.clone(), f.tls.clone()).await;
        let (code, body) = api(
            &client.tls,
            name,
            &server.origin,
            "GET",
            &format!("{base}/monitor/echo"),
            "",
            Value::Null,
        )
        .await;
        assert_eq!(code, 200, "{name}: {body}");
        assert_eq!(body, "Got it!");
        let unauth = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(&read(&pki().ca)).unwrap())
            .build()
            .unwrap();
        assert!(
            unauth
                .get(format!("{}{base}/monitor/echo", server.origin))
                .send()
                .await
                .is_err()
        );
    }
}
#[tokio::test]
async fn token_certificate_binding_and_management_guard() {
    let (_auth, auth) = mock_auth().await;
    let mut f = Fixture::new("blacklist");
    f.config.authentication_url = auth.origin.clone();
    f.reconfigure();
    let server = start(f.app.clone(), f.tls.clone()).await;
    let client = Fixture::named("blacklist", "Client");
    for (token, expected) in [("", 401), ("token-Sysop", 401), ("token-Client", 403)] {
        let (code, _) = api(
            &client.tls,
            "Blacklist",
            &server.origin,
            "POST",
            "/blacklist/mgmt/query",
            token,
            json!({}),
        )
        .await;
        assert_eq!(code, expected)
    }
    let sysop = Fixture::named("blacklist", "Sysop");
    let (code, result) = api(
        &sysop.tls,
        "Blacklist",
        &server.origin,
        "POST",
        "/blacklist/mgmt/create",
        "token-Sysop",
        json!({"entities":[{"systemName":"BadActor","reason":"test"}]}),
    )
    .await;
    assert_eq!(code, 201, "{result}");
    assert_eq!(server.app.store.rows("blacklist").len(), 1);
}
#[tokio::test]
async fn authority_substitution_rejected_before_credentials() {
    let impostor = Fixture::named("blacklist", "Impostor");
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let router = Router::new().fallback(move || {
        let c = counter.clone();
        async move {
            c.fetch_add(1, Ordering::SeqCst);
            Json(json!({"token":"stolen","expirationTime":expiry(60)}))
        }
    });
    let fake = start_router(impostor.app.clone(), impostor.tls.clone(), router).await;
    let mut f = Fixture::new("blacklist");
    f.config.authentication_url = fake.origin.clone();
    f.reconfigure();
    assert!(
        f.app
            .remote
            .call(
                "Authentication",
                "GET",
                "/authentication/identity/verify/test",
                &Value::Null
            )
            .await
            .is_err()
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn event_delivery_is_authorized_pinned_and_durable() {
    let (_auth, auth) = mock_auth().await;
    let authority = Fixture::named("blacklist", "ConsumerAuthorization");
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let c = auth_calls.clone();
    let router = Router::new().fallback(move || {
        let c = c.clone();
        async move {
            c.fetch_add(1, Ordering::SeqCst);
            Json(json!({"entries":[{"granted":true}]}))
        }
    });
    let authority_server = start_router(authority.app.clone(), authority.tls.clone(), router).await;
    let subscriber = Fixture::named("blacklist", "Subscriber");
    let deliveries = Arc::new(AtomicUsize::new(0));
    let count = deliveries.clone();
    let router = Router::new().fallback(move |Json(req): Json<Value>| {
        let count = count.clone();
        async move {
            assert_eq!(req["payload"], "hello");
            assert_eq!(req["sourceSystemName"], "Publisher");
            count.fetch_add(1, Ordering::SeqCst);
            Json(json!({"accepted":true}))
        }
    });
    let callback = start_router(subscriber.app.clone(), subscriber.tls.clone(), router).await;
    let mut f = Fixture::new("eventhandler");
    f.config.authentication_url = auth.origin.clone();
    f.config.authorization_url = authority_server.origin.clone();
    f.config
        .upstreams
        .insert("Subscriber".into(), format!("{}/", callback.origin));
    f.reconfigure();
    let params = std::collections::BTreeMap::new();
    events::handle(
        &f.app,
        "POST",
        "/eventhandler/event-subscription/subscribe",
        &params,
        &json!({}),
        &json!({"eventType":"Alarm","notifyUri":format!("{}/notify",callback.origin)}),
        &caller("Subscriber"),
    )
    .await
    .unwrap();
    let (code, response) = events::handle(
        &f.app,
        "POST",
        "/eventhandler/event-publish/publish",
        &params,
        &json!({}),
        &json!({"eventType":"Alarm","payload":"hello"}),
        &caller("Publisher"),
    )
    .await
    .unwrap();
    assert_eq!(code, 202);
    assert_eq!(response["acceptedDeliveries"], 1);
    assert_eq!(deliveries.load(Ordering::SeqCst), 0);
    events::deliver_once(&f.app).await.unwrap();
    assert_eq!(deliveries.load(Ordering::SeqCst), 1);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 2);
    assert_eq!(f.app.store.rows("event-outbox")[0]["status"], "DELIVERED");
    events::deliver_once(&f.app).await.unwrap();
    assert_eq!(deliveries.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn configuration_raw_bytes_and_http_management() {
    let (_auth, auth) = mock_auth().await;
    let mut f = Fixture::new("configuration");
    f.config.authentication_url = auth.origin.clone();
    f.reconfigure();
    let server = start(f.app.clone(), f.tls.clone()).await;
    let sysop = Fixture::named("configuration", "Sysop");
    let(code,response)=api(&sysop.tls,"Configuration",&server.origin,"PUT","/configuration/mgmt/config/Producer","token-Sysop",json!({"systemName":"Producer","fileName":"settings.txt","contentType":"text/plain","data":"aGVsbG8="})).await;
    assert_eq!(code, 200, "{response}");
    let (code, result) = api(
        &sysop.tls,
        "Configuration",
        &server.origin,
        "GET",
        "/configuration/config/raw/Producer",
        "token-Sysop",
        Value::Null,
    )
    .await;
    assert_eq!(code, 200);
    assert_eq!(result, "hello");
}
#[tokio::test]
async fn unsupported_operations_are_explicit_over_https() {
    let (_auth, auth) = mock_auth().await;
    let mut f = Fixture::new("gatekeeper");
    f.config.authentication_url = auth.origin.clone();
    f.reconfigure();
    let server = start(f.app.clone(), f.tls.clone()).await;
    let sysop = Fixture::named("gatekeeper", "Sysop");
    let (code, result) = api(
        &sysop.tls,
        "Gatekeeper",
        &server.origin,
        "POST",
        "/gatekeeper/init_gsd",
        "token-Sysop",
        json!({}),
    )
    .await;
    assert_eq!(code, 501, "{result}");
    assert!(f.app.store.rows("sessions").is_empty());
}
#[tokio::test]
async fn denied_event_type_is_never_enqueued() {
    let (_auth, auth) = mock_auth().await;
    let authority = Fixture::named("blacklist", "ConsumerAuthorization");
    let router = Router::new().fallback(|| async { Json(json!({"entries":[{"granted":false}]})) });
    let authority_server = start_router(authority.app.clone(), authority.tls.clone(), router).await;
    let mut f = Fixture::new("eventhandler");
    f.config.authentication_url = auth.origin.clone();
    f.config.authorization_url = authority_server.origin.clone();
    f.config
        .upstreams
        .insert("Subscriber".into(), "https://127.0.0.1:9999/".into());
    f.reconfigure();
    let p = std::collections::BTreeMap::new();
    events::handle(
        &f.app,
        "POST",
        "/eventhandler/event-subscription/subscribe",
        &p,
        &json!({}),
        &json!({"eventType":"Alarm","notifyUri":"https://127.0.0.1:9999/notify"}),
        &caller("Subscriber"),
    )
    .await
    .unwrap();
    let (_, response) = events::handle(
        &f.app,
        "POST",
        "/eventhandler/event-publish/publish",
        &p,
        &json!({}),
        &json!({"eventType":"Alarm","payload":"hello"}),
        &caller("Publisher"),
    )
    .await
    .unwrap();
    assert_eq!(response["acceptedDeliveries"], 0);
    assert!(f.app.store.rows("event-outbox").is_empty());
}
#[tokio::test]
async fn translation_adapter_lifecycle_and_owner_guard() {
    let (_auth, auth) = mock_auth().await;
    let adapter = Fixture::named("blacklist", "InterfaceTranslator");
    let router = Router::new().fallback(|request: axum::extract::Request| async {
        if request.uri().path().ends_with("/discovery") {
            return Json(json!({"candidates":[{"translator":"NativeAdapter"}]}));
        }
        if request.method() == "DELETE" {
            return Json(json!({"aborted":true}));
        }
        let bytes = axum::body::to_bytes(request.into_body(), 1 << 20)
            .await
            .unwrap();
        let req: Value = serde_json::from_slice(&bytes).unwrap();
        Json(json!({"bridgeId":req["bridgeId"],"bridgeInterface":{"protocol":"https"}}))
    });
    let adapter_server = start_router(adapter.app.clone(), adapter.tls.clone(), router).await;
    let mut f = Fixture::new("translationmanager");
    f.config.authentication_url = auth.origin.clone();
    f.config.upstreams.insert(
        "InterfaceTranslator".into(),
        format!("{}/", adapter_server.origin),
    );
    f.reconfigure();
    let p = std::collections::BTreeMap::new();
    let (_, result) = translation::handle(
        &f.app,
        "POST",
        "/translation/bridge/discovery",
        &p,
        &json!({}),
        &json!({"serviceDefinition":"test"}),
        &caller("Client"),
    )
    .await
    .unwrap();
    let req = json!({"bridgeId":result["bridgeId"]});
    assert_eq!(
        translation::handle(
            &f.app,
            "POST",
            "/translation/bridge/negotiation",
            &p,
            &json!({}),
            &req,
            &caller("Other")
        )
        .await
        .unwrap_err()
        .code,
        403
    );
    translation::handle(
        &f.app,
        "POST",
        "/translation/bridge/negotiation",
        &p,
        &json!({}),
        &req,
        &caller("Client"),
    )
    .await
    .unwrap();
    assert_eq!(
        row(&f.app, "bridges", s(&req, "bridgeId")).unwrap()["status"],
        "ACTIVE"
    );
    let params =
        std::collections::BTreeMap::from([("bridgeId".into(), s(&req, "bridgeId").into())]);
    translation::handle(
        &f.app,
        "DELETE",
        "/translation/bridge/abort/x",
        &params,
        &json!({}),
        &json!({}),
        &caller("Client"),
    )
    .await
    .unwrap();
    assert_eq!(
        row(&f.app, "bridges", s(&req, "bridgeId")).unwrap()["status"],
        "ABORTED"
    );
}
