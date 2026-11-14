// SPDX-License-Identifier: EPL-2.0
mod common;
use arrowhead_core_rust::*;
use axum::{Router, routing::post};
use common::*;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use tokio::net::TcpListener;

async fn login(tls: &security::Tls, origin: &str, name: &str) -> String {
    let (code, result) = api(
        tls,
        "Authentication",
        origin,
        "POST",
        "/authentication/identity/login",
        "",
        json!({"systemName":name,"credentials":{"password":"private-test-password"}}),
    )
    .await;
    assert_eq!(code, 200, "{result}");
    s(&result, "token").into()
}

#[tokio::test]
async fn all_five_core_systems_interoperate_over_real_mutual_tls() {
    let mut listeners = Vec::new();
    let mut origins = Vec::new();
    for _ in 0..5 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        origins.push(format!("https://{}", listener.local_addr().unwrap()));
        listeners.push(listener)
    }
    let mut fixtures = Vec::new();
    for (role, _, _) in config::ROLES {
        let mut f = Fixture::new(role);
        f.config.authentication_url = origins[1].clone();
        f.config.registry_url = origins[0].clone();
        f.config.authorization_url = origins[2].clone();
        f.config.discovery_direct_access = vec![
            "ConsumerAuthorization".into(),
            "DynamicServiceOrchestration".into(),
            "SimpleStoreServiceOrchestration".into(),
            "Authentication".into(),
        ];
        f.config.management_whitelist = vec![
            "ServiceRegistry".into(),
            "DynamicServiceOrchestration".into(),
        ];
        f.reconfigure();
        fixtures.push(f);
    }
    for name in [
        "ServiceRegistry",
        "Authentication",
        "ConsumerAuthorization",
        "DynamicServiceOrchestration",
        "SimpleStoreServiceOrchestration",
        "Sysop",
        "Provider",
        "Consumer",
    ] {
        seed_identity(
            &fixtures[1].app,
            name,
            "private-test-password",
            name == "Sysop",
        )
    }
    registry::initialize(&fixtures[0].app.store).unwrap();
    let mut servers = Vec::new();
    for (f, listener) in fixtures.iter().zip(listeners) {
        servers.push(
            start_bound(
                f.app.clone(),
                f.tls.clone(),
                web::router(f.app.clone()),
                listener,
            )
            .await,
        )
    }
    let sysop = Fixture::named("authentication", "Sysop");
    let provider = Fixture::named("authentication", "Provider");
    let consumer = Fixture::named("authentication", "Consumer");
    let st = login(&sysop.tls, &origins[1], "Sysop").await;
    let pt = login(&provider.tls, &origins[1], "Provider").await;
    let ct = login(&consumer.tls, &origins[1], "Consumer").await;
    let (code, result) = api(
        &provider.tls,
        "ServiceRegistry",
        &origins[0],
        "POST",
        "/serviceregistry/system-discovery/register",
        &pt,
        json!({"version":"5.4.0","addresses":["127.0.0.1"],"metadata":{"zone":"laboratory"}}),
    )
    .await;
    assert_eq!(code, 201, "{result}");
    let req = json!({"serviceDefinitionName":"temperature","version":"1.0.0","metadata":{"allowExclusivity":"60"},"interfaces":[{"templateName":"generic_https","protocol":"https","policy":"CERT_AUTH","properties":{"accessAddresses":["127.0.0.1"],"accessPort":12345,"basePath":"/temperature","operations":{"read":{"method":"GET","path":"/"}}}}]});
    let (code, result) = api(
        &provider.tls,
        "ServiceRegistry",
        &origins[0],
        "POST",
        "/serviceregistry/service-discovery/register",
        &pt,
        req,
    )
    .await;
    assert_eq!(code, 201, "{result}");
    let lookup = json!({"serviceDefinitionNames":["temperature"]});
    let (code, result) = api(
        &consumer.tls,
        "ServiceRegistry",
        &origins[0],
        "POST",
        "/serviceregistry/service-discovery/lookup",
        &ct,
        lookup.clone(),
    )
    .await;
    assert_eq!(code, 200, "{result}");
    assert_eq!(result["count"], 0);
    let grant = json!({"list":[{"provider":"Provider","cloud":"LOCAL","targetType":"SERVICE_DEF","target":"temperature","defaultPolicy":{"policyType":"WHITELIST","policyList":["Consumer"]}}]});
    let (code, result) = api(
        &sysop.tls,
        "ConsumerAuthorization",
        &origins[2],
        "POST",
        "/consumerauthorization/authorization/mgmt/grant",
        &st,
        grant,
    )
    .await;
    assert_eq!(code, 201, "{result}");
    let (code, result) = api(
        &consumer.tls,
        "ServiceRegistry",
        &origins[0],
        "POST",
        "/serviceregistry/service-discovery/lookup",
        &ct,
        lookup,
    )
    .await;
    assert_eq!(code, 200, "{result}");
    assert_eq!(result["count"], 1);
    let(code,result)=api(&consumer.tls,"DynamicServiceOrchestration",&origins[3],"POST","/serviceorchestration/orchestration/pull",&ct,json!({"serviceRequirement":{"serviceDefinition":"temperature","operations":["read"],"interfaceTemplateNames":["generic_https"]},"orchestrationFlags":{"MATCHMAKING":true},"exclusivityDuration":30})).await;
    assert_eq!(code, 200, "{result}");
    assert_eq!(result["results"][0]["providerName"], "Provider");
    assert!(result["results"][0]["exclusiveUntil"].is_string());
    assert_eq!(fixtures[3].app.store.rows("locks").len(), 1);
    let(code,result)=api(&sysop.tls,"SimpleStoreServiceOrchestration",&origins[4],"POST","/serviceorchestration/orchestration/mgmt/simple-store/create",&st,json!({"candidates":[{"consumer":"Consumer","serviceInstanceId":"Provider|temperature|1.0.0","priority":1}]})).await;
    assert_eq!(code, 200, "{result}");
    let (code, result) = api(
        &consumer.tls,
        "SimpleStoreServiceOrchestration",
        &origins[4],
        "POST",
        "/serviceorchestration/orchestration/pull",
        &ct,
        json!({"serviceRequirement":{"serviceDefinition":"temperature"}}),
    )
    .await;
    assert_eq!(code, 200, "{result}");
    assert_eq!(
        result["results"][0]["serviceInstanceId"],
        "Provider|temperature|1.0.0"
    );
    let (code, _) = api(
        &consumer.tls,
        "ServiceRegistry",
        &origins[0],
        "POST",
        "/serviceregistry/mgmt/systems/query",
        &ct,
        json!({}),
    )
    .await;
    assert_eq!(code, 403);
    let (code, _) = api(
        &consumer.tls,
        "ServiceRegistry",
        &origins[0],
        "POST",
        "/serviceregistry/service-discovery/lookup",
        &pt,
        json!({}),
    )
    .await;
    assert_eq!(code, 401);
    fixtures[2].app.store.update(|db|{authorization::grant(db,json!({"provider":"Provider","cloud":"LOCAL","targetType":"EVENT_TYPE","target":"alarm","defaultPolicy":{"policyType":"SYS_METADATA","policyMetadataRequirement":{"zone":"laboratory"}}}),"MGMT","Sysop")?;Ok(())}).unwrap();
    assert!(authorization::granted(&fixtures[2].app,json!({"provider":"Provider","consumer":"Provider","cloud":"LOCAL","targetType":"EVENT_TYPE","target":"alarm"})).await.unwrap());
    assert_eq!(servers.len(), 5);
}

#[tokio::test]
async fn persisted_push_job_delivers_to_the_pinned_subscriber() {
    let (_af, auth) = mock_auth().await;
    let mut f = Fixture::new("serviceorchestration-simple");
    f.config.authentication_url = auth.origin.clone();
    f.reconfigure();
    let consumer = Fixture::named("authentication", "Consumer");
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let received = Arc::new(std::sync::Mutex::new(Value::Null));
    let count = calls.clone();
    let record = received.clone();
    let router = Router::new().route(
        "/notify",
        post(move |axum::Json(body): axum::Json<Value>| {
            let count = count.clone();
            let record = record.clone();
            async move {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                *record.lock().unwrap() = body;
                axum::http::StatusCode::NO_CONTENT
            }
        }),
    );
    let callback = start_router(consumer.app.clone(), consumer.tls.clone(), router).await;
    let url = url::Url::parse(&callback.origin).unwrap();
    orchestration::handle(&f.app,"POST","/serviceorchestration/orchestration/mgmt/simple-store/create",&BTreeMap::new(),&empty(),&json!({"candidates":[{"consumer":"Consumer","serviceInstanceId":"Provider|temperature|1.0.0","priority":1}]}),&caller("Sysop")).await.unwrap();
    let(_,id)=orchestration::handle(&f.app,"POST","/serviceorchestration/orchestration/subscribe",&BTreeMap::new(),&empty(),&json!({"orchestrationRequest":{"serviceRequirement":{"serviceDefinition":"temperature"}},"notifyInterface":{"protocol":"HTTPS","properties":{"address":"127.0.0.1","port":url.port().unwrap().to_string(),"method":"POST","path":"/notify"}}}),&caller("Consumer")).await.unwrap();
    let (_, jobs) = orchestration::handle(
        &f.app,
        "POST",
        "/serviceorchestration/orchestration/mgmt/push/trigger",
        &BTreeMap::new(),
        &empty(),
        &json!({"subscriptionIds":[id]}),
        &caller("Sysop"),
    )
    .await
    .unwrap();
    assert_eq!(array(&jobs, "jobs").len(), 1);
    assert!(orchestration::push_once(&f.app).await.unwrap());
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        received.lock().unwrap()["results"][0]["providerName"],
        "Provider"
    );
    assert_eq!(f.app.store.rows("jobs")[0]["status"], "DONE");
    assert!(!orchestration::push_once(&f.app).await.unwrap());
}

#[tokio::test]
async fn missing_client_certificate_and_wrong_authority_are_rejected() {
    let f = Fixture::new("authentication");
    let server = start(f.app.clone(), f.tls.clone()).await;
    let root = reqwest::Certificate::from_pem(&read(&pki().ca)).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(root)
        .build()
        .unwrap();
    assert!(
        client
            .get(format!("{}/authentication/monitor/echo", server.origin))
            .send()
            .await
            .is_err()
    );
    let consumer = Fixture::named("authentication", "Consumer");
    let wrong = consumer
        .tls
        .client(&format!("ConsumerAuthorization.{SUFFIX}"))
        .unwrap();
    assert!(
        wrong
            .get(format!("{}/authentication/monitor/echo", server.origin))
            .send()
            .await
            .is_err()
    );
    let (code, text) = api(
        &consumer.tls,
        "Authentication",
        &server.origin,
        "GET",
        "/authentication/monitor/echo",
        "",
        Value::Null,
    )
    .await;
    assert_eq!(code, 200);
    assert_eq!(text, "Got it!");
}
