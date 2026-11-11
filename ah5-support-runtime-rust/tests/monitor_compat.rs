// SPDX-License-Identifier: EPL-2.0
mod common;
use arrowhead_support_rust::*;
use axum::http::HeaderMap;
use common::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
fn messaging() -> arrowhead_messaging_rust::Config {
    serde_json::from_value(json!({"amqpHost":"amqp-broker","amqpPort":5671,"amqpIdentity":"AmqpBroker","mqttHost":"mqtt-broker","mqttPort":8883,"mqttIdentity":"MqttBroker"})).unwrap()
}
fn fixture() -> Fixture {
    let mut f = Fixture::new("sysmonitor");
    f.config.messaging = Some(messaging());
    f.reconfigure();
    f
}
async fn call(
    f: &Fixture,
    method: &str,
    path: &str,
    q: Value,
    body: Value,
    headers: HeaderMap,
) -> Result<(u16, Value)> {
    let params = if path.contains("/subscriptions/") {
        BTreeMap::from([(
            "providerSystem".into(),
            path.rsplit('/').next().unwrap().to_string(),
        )])
    } else if path.contains("/systems/") {
        BTreeMap::from([("systemName".into(), "Producer".into())])
    } else {
        BTreeMap::new()
    };
    monitor::handle(
        &f.app,
        method,
        path,
        &params,
        &q,
        &body,
        &caller("Sysop"),
        &headers,
    )
    .await
}
#[tokio::test]
async fn java_monitor_subscription_optional_match_and_exact_envelopes() {
    let f = fixture();
    let (_, created) = call(
        &f,
        "PUT",
        "/sysmonitor/management/subscriptions/Producer",
        json!({}),
        json!({}),
        HeaderMap::new(),
    )
    .await
    .unwrap();
    assert_eq!(created["enabled"], true);
    assert_eq!(created["observationTypes"], json!(["*"]));
    assert_eq!(created["updatedBy"], "Sysop");
    let (_, list) = call(
        &f,
        "GET",
        "/sysmonitor/management/subscriptions",
        json!({}),
        json!({}),
        HeaderMap::new(),
    )
    .await
    .unwrap();
    assert_eq!(list["defaultSubscription"], "all");
    assert_eq!(list["list"][0]["providerSystem"], "Producer");
    let mut stale = HeaderMap::new();
    stale.insert("if-match", "\"0\"".parse().unwrap());
    assert_eq!(
        call(
            &f,
            "PUT",
            "/sysmonitor/management/subscriptions/Producer",
            json!({}),
            json!({}),
            stale.clone()
        )
        .await
        .unwrap_err()
        .code,
        409
    );
    assert_eq!(
        call(
            &f,
            "PUT",
            "/sysmonitor/management/subscriptions/Unknown",
            json!({}),
            json!({}),
            stale
        )
        .await
        .unwrap_err()
        .code,
        409
    );
    let (_, second) = call(
        &f,
        "PUT",
        "/sysmonitor/management/subscriptions/Producer",
        json!({}),
        json!({"enabled":false,"observationTypes":["echo"]}),
        HeaderMap::new(),
    )
    .await
    .unwrap();
    assert_eq!(second["revision"], 2);
    let (status, value) = call(
        &f,
        "DELETE",
        "/sysmonitor/management/subscriptions/Producer",
        json!({}),
        json!({}),
        HeaderMap::new(),
    )
    .await
    .unwrap();
    assert_eq!(status, 204);
    assert!(value.is_null());
    for types in [
        json!([]),
        json!(["*", "echo"]),
        json!(["bad.#"]),
        json!("echo"),
    ] {
        assert_eq!(
            call(
                &f,
                "PUT",
                "/sysmonitor/management/subscriptions/Producer",
                json!({}),
                json!({"observationTypes":types}),
                HeaderMap::new()
            )
            .await
            .unwrap_err()
            .code,
            400
        );
    }
}
#[tokio::test]
async fn java_history_latest_per_type_and_filters() {
    let f = fixture();
    for (id, kind, source, value) in [
        (
            "one",
            "echo",
            "2026-10-17T10:00:00Z",
            json!({"status":"alive"}),
        ),
        (
            "two",
            "power",
            "2026-10-17T11:00:00Z",
            json!({"supplyType":"line"}),
        ),
        (
            "three",
            "echo",
            "2026-10-17T12:00:00Z",
            json!({"status":"degraded"}),
        ),
    ] {
        monitor::ingest(
            &f.app,
            &format!("RustCloud.sysmonitor.Producer.main.{kind}"),
            &json!({"observationId":id,"sourceTime":source,"value":value}),
        )
        .unwrap();
    }
    let (_, systems) = call(
        &f,
        "GET",
        "/sysmonitor/history/systems",
        json!({}),
        json!({}),
        HeaderMap::new(),
    )
    .await
    .unwrap();
    assert_eq!(systems["systems"][0]["systemName"], "Producer");
    assert_eq!(systems["systems"][0]["observationCount"], 3);
    assert_eq!(systems["retentionDays"], 30);
    let (_, latest) = call(
        &f,
        "GET",
        "/sysmonitor/history/systems/Producer/latest",
        json!({}),
        json!({}),
        HeaderMap::new(),
    )
    .await
    .unwrap();
    assert_eq!(latest["systemName"], "Producer");
    assert_eq!(latest["latest"]["echo"]["observationId"], "three");
    assert_eq!(latest["latest"]["power"]["observationId"], "two");
    let (_, history) = call(
        &f,
        "GET",
        "/sysmonitor/history/systems/Producer/observations",
        json!({"type":["echo,power"],"from":["2026-10-17T10:30:00Z"],"count":["1"]}),
        json!({}),
        HeaderMap::new(),
    )
    .await
    .unwrap();
    assert_eq!(history["systemName"], "Producer");
    assert_eq!(history["count"], 1);
    assert_eq!(history["observations"][0]["observationId"], "three");
    assert_eq!(
        call(
            &f,
            "GET",
            "/sysmonitor/history/systems/Producer/observations",
            json!({"count":["1001"]}),
            json!({}),
            HeaderMap::new()
        )
        .await
        .unwrap_err()
        .code,
        400
    );
}
#[test]
fn sqlite_migration_is_atomic_idempotent_and_outbox_persists() {
    let f = Fixture::new("sysmonitor");
    let initial = json!({"observationId":"old","providerSystem":"Producer","serviceInstance":"main","observationType":"echo","sourceTime":now(),"receivedTime":now(),"value":{"status":"alive"}});
    f.app
        .store
        .update(|db| {
            table(db, "observations").insert("Producer:old".into(), initial.clone());
            table(db, "monitor-outbox").insert(
                "Producer:old".into(),
                json!({"topic":"test","observation":initial}),
            );
            Ok(())
        })
        .unwrap();
    let path = f.temp.0.join("monitor.sqlite");
    let db = monitor_store::MonitorDb::open(&path).unwrap();
    db.import(&f.app.store).unwrap();
    assert_eq!(db.counts().unwrap(), json!({"stored":1,"pending":1}));
    assert_eq!(db.append(&initial, "test").unwrap(), initial);
    assert_eq!(db.counts().unwrap()["pending"], 1);
    let mut altered = initial.clone();
    altered["value"] = json!({"status":"failed"});
    assert_eq!(db.append(&altered, "test").unwrap_err().code, 409);
    db.published("old").unwrap();
    drop(db);
    let db = monitor_store::MonitorDb::open(path).unwrap();
    db.import(&f.app.store).unwrap();
    assert_eq!(db.counts().unwrap(), json!({"stored":1,"pending":0}));
}
#[test]
fn aigym_consumes_only_bound_local_topics_and_deduplicates() {
    let f = Fixture::new("aigym");
    let value = json!({"schemaVersion":"1.0","observationId":"one","providerSystem":"Producer","observationType":"echo","sourceTime":now(),"value":{"status":"alive"}});
    let bytes = serde_json::to_vec(&value).unwrap();
    let topic = "arrowhead/RustCloud/sysmonitor/data/echo/Producer";
    aigym_mqtt::receive(&f.app, topic, &bytes).unwrap();
    aigym_mqtt::receive(&f.app, topic, &bytes).unwrap();
    assert_eq!(f.app.store.rows("ai-observations").len(), 1);
    assert!(
        aigym_mqtt::receive(
            &f.app,
            "arrowhead/Foreign/sysmonitor/data/echo/Producer",
            &bytes
        )
        .is_err()
    );
    assert!(
        aigym_mqtt::receive(
            &f.app,
            "arrowhead/RustCloud/sysmonitor/data/echo/Attacker",
            &bytes
        )
        .is_err()
    );
}
