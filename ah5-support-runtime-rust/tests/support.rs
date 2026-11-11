// SPDX-License-Identifier: EPL-2.0
mod common;
use arrowhead_support_rust::*;
use axum::http::HeaderMap;
use common::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
async fn call(
    f: &Fixture,
    method: &str,
    path: &str,
    q: Value,
    req: Value,
    who: &str,
) -> Result<(u16, Value)> {
    let route = contracts::routes(&f.config.role)
        .into_iter()
        .find_map(|r| {
            if r.method == method {
                web::parameters(&r.path, path).map(|p| (r, p))
            } else {
                None
            }
        })
        .expect("Known contract");
    if !route.0.implemented {
        return Err(Error::unsupported("Not ported"));
    }
    web::handle(
        &f.app,
        method,
        path,
        &route.1,
        &q,
        &req,
        &caller(who),
        &HeaderMap::new(),
    )
    .await
}
#[tokio::test]
async fn blacklist_atomic_expiry_and_revocation() {
    let f = Fixture::new("blacklist");
    let req =
        json!({"entities":[{"systemName":"Producer","reason":"test"},{"systemName":"bad/name"}]});
    assert_eq!(
        call(&f, "POST", "/blacklist/mgmt/create", empty(), req, "Sysop")
            .await
            .unwrap_err()
            .code,
        400
    );
    assert!(f.app.store.rows("blacklist").is_empty());
    call(
        &f,
        "POST",
        "/blacklist/mgmt/create",
        empty(),
        json!({"entities":[{"systemName":"Producer","expiresAt":expiry(60),"reason":"test"}]}),
        "Sysop",
    )
    .await
    .unwrap();
    assert_eq!(
        call(
            &f,
            "GET",
            "/blacklist/check/Producer",
            empty(),
            empty(),
            "Client"
        )
        .await
        .unwrap()
        .1,
        true
    );
    call(
        &f,
        "DELETE",
        "/blacklist/mgmt/remove",
        json!({"names":["Producer"]}),
        empty(),
        "Sysop",
    )
    .await
    .unwrap();
    let row = row(&f.app, "blacklist", "Producer").unwrap();
    assert!(!basic::active(&row));
    assert_eq!(row["revokedBy"], "Sysop");
}
#[tokio::test]
async fn blacklist_query_filters_and_validation() {
    let f = Fixture::new("blacklist");
    call(&f,"POST","/blacklist/mgmt/create",empty(),json!({"entities":[{"systemName":"Alpha","reason":"fault"},{"systemName":"Beta","reason":"test"}]}),"Sysop").await.unwrap();
    let result = call(
        &f,
        "POST",
        "/blacklist/mgmt/query",
        empty(),
        json!({"systemNames":["Alpha"],"mode":"ACTIVE","pagination":{"size":1}}),
        "Sysop",
    )
    .await
    .unwrap()
    .1;
    assert_eq!(result["count"], 1);
    assert_eq!(result["entries"][0]["systemName"], "Alpha");
    assert!(
        call(
            &f,
            "POST",
            "/blacklist/mgmt/query",
            empty(),
            json!({"mode":"NO"}),
            "Sysop"
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn configuration_owner_and_binary_roundtrip() {
    let f = Fixture::new("configuration");
    let req = json!({"systemName":"Producer","fileName":"settings.json","contentType":"application/json","data":"eyJ4IjoxfQ=="});
    call(
        &f,
        "PUT",
        "/configuration/mgmt/config/Producer",
        empty(),
        req.clone(),
        "Sysop",
    )
    .await
    .unwrap();
    let row = call(
        &f,
        "GET",
        "/configuration/config/Producer",
        empty(),
        empty(),
        "Producer",
    )
    .await
    .unwrap()
    .1;
    assert_eq!(row["size"], 7);
    assert_eq!(row["data"], req["data"]);
    assert_eq!(
        call(
            &f,
            "GET",
            "/configuration/config/Producer",
            empty(),
            empty(),
            "Other"
        )
        .await
        .unwrap_err()
        .code,
        403
    );
    assert!(
        call(
            &f,
            "PUT",
            "/configuration/proxy/save-config",
            empty(),
            req,
            "Other"
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn configuration_rejects_paths_and_bad_encoding() {
    let f = Fixture::new("configuration");
    for (filename, data) in [("../escape", "eA=="), ("ok", "%%%")] {
        let req = json!({"systemName":"Producer","fileName":filename,"contentType":"text/plain","data":data});
        assert!(
            call(
                &f,
                "PUT",
                "/configuration/mgmt/config/Producer",
                empty(),
                req,
                "Sysop"
            )
            .await
            .is_err()
        );
    }
    assert!(f.app.store.rows("configuration").is_empty());
}
#[tokio::test]
async fn time_never_fakes_external_trust() {
    let f = Fixture::new("timemanager");
    let result = call(&f, "GET", "/timemanager/time", empty(), empty(), "Client")
        .await
        .unwrap()
        .1;
    // Trust is only claimed with an SNTP measurement behind it (pool.ntp.org may be unreachable here).
    assert_eq!(
        result["trusted"] == true,
        result["timeSource"].is_string() && result["offsetMs"].is_i64()
    );
    assert!(result["lastCheckTime"].is_string());
    assert!(result["epochMs"].as_i64().unwrap() > 0);
}
#[tokio::test]
async fn aigym_missing_features_knn_and_restart_state() {
    let f = Fixture::new("aigym");
    for req in [
        json!({"features":{"x":1.},"target":2.}),
        json!({"features":{"x":3.,"y":1.},"target":6.}),
    ] {
        call(&f, "POST", "/aigym/samples", empty(), req, "Client")
            .await
            .unwrap();
    }
    let result = call(
        &f,
        "POST",
        "/aigym/predict",
        empty(),
        json!({"features":{"x":1.},"neighbours":1}),
        "Client",
    )
    .await
    .unwrap()
    .1;
    assert_eq!(result["value"], 2.);
    assert_eq!(result["model"], "default");
    assert_eq!(f.app.store.rows("ai-observations").len(), 1);
}
#[tokio::test]
async fn aigym_empty_model_rejected() {
    let f = Fixture::new("aigym");
    assert!(
        call(
            &f,
            "POST",
            "/aigym/predict",
            empty(),
            json!({"features":{"x":1.}}),
            "Client"
        )
        .await
        .is_err()
    );
    assert!(
        call(
            &f,
            "POST",
            "/aigym/samples",
            empty(),
            json!({"features":{"x":"bad"},"target":1}),
            "Client"
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn historian_preserves_filtered_base_context() {
    let f = Fixture::new("datamanager");
    let path = "/datamanager/data-historian/systems/Producer/services/temperature/data";
    call(&f,"PUT",path,empty(),json!([{"bn":"sensor/","bt":1000.,"n":"temperature","v":20.},{"n":"temperature","t":10.,"v":22.}]),"Producer").await.unwrap();
    let result = call(
        &f,
        "GET",
        path,
        json!({"from":["1005"],"count":["1"]}),
        empty(),
        "Client",
    )
    .await
    .unwrap()
    .1;
    assert_eq!(result.as_array().unwrap().len(), 1);
    assert_eq!(result[0]["bn"], "sensor/");
    assert_eq!(result[0]["bt"], 1000.);
    assert_eq!(result[0]["t"], 10.);
}
#[tokio::test]
async fn historian_owner_and_atomic_validation() {
    let f = Fixture::new("datamanager");
    let path = "/datamanager/data-historian/systems/Producer/services/test/data";
    assert_eq!(
        call(&f, "PUT", path, empty(), json!([{"v":1}]), "Other")
            .await
            .unwrap_err()
            .code,
        403
    );
    assert!(
        call(
            &f,
            "PUT",
            path,
            empty(),
            json!([{"v":1},{"v":1,"vs":"duplicate"}]),
            "Producer"
        )
        .await
        .is_err()
    );
    assert!(f.app.store.rows("senml").is_empty());
    assert_eq!(
        call(
            &f,
            "GET",
            path,
            json!({"signalCount":["0"]}),
            empty(),
            "Client"
        )
        .await
        .unwrap_err()
        .code,
        400
    );
}
#[tokio::test]
async fn qos_weighted_rank_and_missing_measurements() {
    let f = Fixture::new("deviceqosevaluator");
    f.app.store.update(|db|{for(name,value)in [("Alpha",1.),("Beta",3.)]{table(db,"measurements").insert(name.into(),json!({"systemName":name,"metricGroup":"latency","timestamp":now(),"current":value}));}Ok(())}).unwrap();
    let req = json!({"providers":["Beta","Absent","Alpha"],"configuration":{"metricNames":["latency"],"metricWeights":[2.],"timeWindow":300,"threshold":3.}});
    let result = call(
        &f,
        "POST",
        "/deviceqosevaluator/qualityevaluation/sort",
        empty(),
        req.clone(),
        "Client",
    )
    .await
    .unwrap()
    .1;
    assert_eq!(
        result["sortedProviders"],
        json!(["Alpha", "Beta", "Absent"])
    );
    let result = call(
        &f,
        "POST",
        "/deviceqosevaluator/qualityevaluation/filter",
        empty(),
        req,
        "Client",
    )
    .await
    .unwrap()
    .1;
    assert_eq!(result["passedProviders"], json!(["Alpha"]));
    assert_eq!(result["warnings"]["Absent"], json!(["latency"]));
}
#[tokio::test]
async fn qos_absent_adapter_keeps_history() {
    let f = Fixture::new("deviceqosevaluator");
    assert_eq!(
        call(
            &f,
            "POST",
            "/deviceqosevaluator/mgmt/reload",
            empty(),
            empty(),
            "Sysop"
        )
        .await
        .unwrap_err()
        .code,
        503
    );
}
#[tokio::test]
async fn plant_include_cycle_and_active_uniqueness() {
    let f = Fixture::new("plantdescriptionengine");
    let base = "/plantdescriptionengine/mgmt/plant-descriptions";
    let a = call(
        &f,
        "POST",
        base,
        empty(),
        json!({"plantDescription":"A","active":true,"include":[],"systems":[]}),
        "Sysop",
    )
    .await
    .unwrap()
    .1;
    assert_eq!(a["id"], 1);
    assert_eq!(
        call(
            &f,
            "POST",
            base,
            empty(),
            json!({"plantDescription":"B","active":true}),
            "Sysop"
        )
        .await
        .unwrap_err()
        .code,
        409
    );
    call(
        &f,
        "POST",
        base,
        empty(),
        json!({"plantDescription":"B","include":[1]}),
        "Sysop",
    )
    .await
    .unwrap();
    assert_eq!(
        call(
            &f,
            "PATCH",
            &format!("{base}/1"),
            empty(),
            json!({"include":[2]}),
            "Sysop"
        )
        .await
        .unwrap_err()
        .code,
        400
    );
    assert_eq!(
        call(
            &f,
            "DELETE",
            &format!("{base}/1"),
            empty(),
            empty(),
            "Sysop"
        )
        .await
        .unwrap_err()
        .code,
        409
    );
}
#[tokio::test]
async fn plant_rejects_dangling_ports() {
    let f = Fixture::new("plantdescriptionengine");
    assert!(call(&f,"POST","/plantdescriptionengine/mgmt/plant-descriptions",empty(),json!({"plantDescription":"Bad","systems":[{"systemId":1,"systemName":"Alpha","ports":["out"]}],"connections":[{"consumer":{"systemId":1,"portName":"missing"},"producer":{"systemId":1,"portName":"out"}}]}),"Sysop").await.is_err());
}
fn plan() -> Value {
    json!({"name":"Plan","firstActionName":"A","actions":[{"name":"A","firstStepNames":["S"],"steps":[{"name":"S","serviceRequirement":{"serviceDefinitionName":"test"}}]}]})
}
#[tokio::test]
async fn choreography_validates_before_side_effects() {
    let f = Fixture::new("choreographer");
    call(
        &f,
        "POST",
        "/choreographer/mgmt/plans",
        empty(),
        plan(),
        "Sysop",
    )
    .await
    .unwrap();
    assert_eq!(
        call(
            &f,
            "POST",
            "/choreographer/session/start",
            empty(),
            json!({"planName":"Plan","allowInterCloud":true}),
            "Client"
        )
        .await
        .unwrap_err()
        .code,
        501
    );
    assert!(f.app.store.rows("sessions").is_empty());
    let mut cyclic = plan();
    cyclic["actions"][0]["nextActionName"] = "A".into();
    assert!(choreography::validate_plan(&cyclic).is_err());
}
#[tokio::test]
async fn choreography_completion_is_owner_bound_and_one_shot() {
    let f = Fixture::new("choreographer");
    f.app
        .store
        .update(|db| {
            table(db, "sessions").insert(
                "one".into(),
                json!({"id":"one","executor":"Executor","sessionStepId":"step","status":"RUNNING"}),
            );
            Ok(())
        })
        .unwrap();
    let req = json!({"sessionId":"one","sessionStepId":"step","status":"DONE"});
    assert_eq!(
        call(
            &f,
            "POST",
            "/choreographer/executor/notify-step-done",
            empty(),
            req.clone(),
            "Other"
        )
        .await
        .unwrap_err()
        .code,
        403
    );
    let result = call(
        &f,
        "POST",
        "/choreographer/executor/notify-step-done",
        empty(),
        req.clone(),
        "Executor",
    )
    .await
    .unwrap()
    .1;
    assert_eq!(result["status"], "COMPLETED");
    assert_eq!(
        call(
            &f,
            "POST",
            "/choreographer/executor/notify-step-done",
            empty(),
            req,
            "Executor"
        )
        .await
        .unwrap_err()
        .code,
        409
    );
}
#[tokio::test]
async fn onboarding_unique_approval_and_reserved_names() {
    let f = Fixture::new("onboarding");
    let req = json!({"bootstrapFingerprint":"aa".repeat(32),"systems":["Sensor"]});
    call(
        &f,
        "PUT",
        "/onboarding/mgmt/enrollments/Device",
        empty(),
        req.clone(),
        "Sysop",
    )
    .await
    .unwrap();
    assert_eq!(
        call(
            &f,
            "PUT",
            "/onboarding/mgmt/enrollments/Another",
            empty(),
            req,
            "Sysop"
        )
        .await
        .unwrap_err()
        .code,
        400 // Java InvalidParameterException: the fingerprint is approved for another device
    );
    assert!(
        call(
            &f,
            "PUT",
            "/onboarding/mgmt/enrollments/Bad",
            empty(),
            json!({"bootstrapFingerprint":"bb".repeat(32),"systems":["ServiceRegistry"]}),
            "Sysop"
        )
        .await
        .is_err()
    );
    // Off-boarding is ported: with no upstreams reachable every withdrawal step is reported as failed,
    // and the approval stays as OFFBOARDED (Java EnrollmentService.offboard).
    let report = call(
        &f,
        "POST",
        "/onboarding/mgmt/enrollments/Device/offboard",
        empty(),
        empty(),
        "Sysop",
    )
    .await
    .unwrap()
    .1;
    assert_eq!(report["deviceName"], "Device");
    assert!(!report["failed"].as_array().unwrap().is_empty());
    assert_eq!(
        row(&f.app, "enrollments", "Device").unwrap()["state"],
        "OFFBOARDED"
    );
}
#[tokio::test]
async fn translation_absent_adapter_no_false_bridge() {
    let f = Fixture::new("translationmanager");
    assert_eq!(
        call(
            &f,
            "POST",
            "/translation/bridge/discovery",
            empty(),
            empty(),
            "Client"
        )
        .await
        .unwrap_err()
        .code,
        503
    );
    assert!(f.app.store.rows("bridges").is_empty());
}
#[tokio::test]
async fn gatekeeper_neighbours_and_no_false_federation() {
    let f = Fixture::new("gatekeeper");
    call(
        &f,
        "POST",
        "/gatekeeper/mgmt/clouds",
        empty(),
        json!({"name":"OtherCloud","operator":"Company"}),
        "Sysop",
    )
    .await
    .unwrap();
    let result = call(
        &f,
        "GET",
        "/gatekeeper/mgmt/clouds",
        empty(),
        empty(),
        "Sysop",
    )
    .await
    .unwrap()
    .1;
    assert_eq!(result["count"], 1);
    assert_eq!(
        call(
            &f,
            "POST",
            "/gatekeeper/init_gsd",
            empty(),
            empty(),
            "Client"
        )
        .await
        .unwrap_err()
        .code,
        501
    );
}
#[tokio::test]
async fn gatetunnel_public_key_and_no_dummy_session() {
    let f = Fixture::new("gatetunnel");
    let result = call(
        &f,
        "GET",
        "/gatetunnel/publickey",
        empty(),
        empty(),
        "Client",
    )
    .await
    .unwrap()
    .1;
    assert_eq!(result["format"], "X.509");
    assert!(!s(&result, "publicKey").is_empty());
    assert_eq!(
        call(
            &f,
            "POST",
            "/gatetunnel/connect_provider",
            empty(),
            json!({"consumer":"X"}),
            "Client"
        )
        .await
        .unwrap_err()
        .code,
        501
    );
    assert!(f.app.store.rows("sessions").is_empty());
}
async fn subscription(f: &Fixture) -> Value {
    let headers = HeaderMap::new();
    monitor::handle(
        &f.app,
        "PUT",
        "/sysmonitor/management/subscriptions/Producer",
        &BTreeMap::from([("providerSystem".into(), "Producer".into())]),
        &empty(),
        &json!({"enabled":true,"observationTypes":["echo"]}),
        &caller("Sysop"),
        &headers,
    )
    .await
    .unwrap()
    .1
}
#[tokio::test]
async fn monitor_revision_conflicts_and_atomic_deduplication() {
    let f = Fixture::new("sysmonitor");
    assert_eq!(subscription(&f).await["revision"], 1);
    let raw = json!({"schemaVersion":"1.0","sourceTime":now(),"value":{"status":"alive"}});
    let routing = "RustCloud.sysmonitor.Producer.main.echo";
    let first = monitor::ingest(&f.app, routing, &raw).unwrap();
    assert_eq!(monitor::ingest(&f.app, routing, &raw).unwrap(), first);
    assert_eq!(f.app.store.rows("observations").len(), 1);
    assert_eq!(f.app.store.rows("monitor-outbox").len(), 1);
    let mut headers = HeaderMap::new();
    headers.insert("if-match", "\"0\"".parse().unwrap());
    assert_eq!(
        monitor::handle(
            &f.app,
            "PUT",
            "/sysmonitor/management/subscriptions/Producer",
            &BTreeMap::from([("providerSystem".into(), "Producer".into())]),
            &empty(),
            &empty(),
            &caller("Sysop"),
            &headers
        )
        .await
        .unwrap_err()
        .code,
        409
    );
}
#[tokio::test]
async fn monitor_rejects_cross_cloud_spoofed_and_bad_schema() {
    let f = Fixture::new("sysmonitor");
    subscription(&f).await;
    for (routing, raw) in [
        (
            "Foreign.sysmonitor.Producer.main.echo",
            json!({"schemaVersion":"1.0","sourceTime":now(),"value":{"status":"alive"}}),
        ),
        (
            "RustCloud.sysmonitor.Producer.main.echo",
            json!({"schemaVersion":"2.0","sourceTime":now(),"value":{"status":"alive"}}),
        ),
        (
            "RustCloud.sysmonitor.Producer.main.echo",
            json!({"schemaVersion":"1.0","providerSystem":"Other","sourceTime":now(),"value":{"status":"alive"}}),
        ),
        (
            "RustCloud.sysmonitor.Producer.main.echo",
            json!({"schemaVersion":"1.0","sourceTime":now(),"value":{"status":"healthy"}}),
        ),
    ] {
        assert!(monitor::ingest(&f.app, routing, &raw).is_err())
    }
    assert!(f.app.store.rows("observations").is_empty());
}
#[tokio::test]
async fn monitor_reports_actual_missing_brokers() {
    let f = Fixture::new("sysmonitor");
    let result = call(
        &f,
        "GET",
        "/sysmonitor/management/status",
        empty(),
        empty(),
        "Sysop",
    )
    .await
    .unwrap()
    .1;
    assert_eq!(result["amqpConnected"], false);
    assert_eq!(result["mqttConnected"], false);
    assert_eq!(result["state"], "degraded");
}
#[test]
fn store_durability_lock_and_failed_transaction() {
    let temp = Temp::new();
    let path = temp.0.join("state.json");
    let store = Store::open(&path).unwrap();
    store
        .update(|db| {
            table(db, "items").insert("one".into(), json!({"value":1}));
            Ok(())
        })
        .unwrap();
    assert!(Store::open(&path).is_err());
    assert!(
        store
            .update::<()>(|db| {
                table(db, "items").clear();
                Err(Error::bad("abort"))
            })
            .is_err()
    );
    drop(store);
    let store = Store::open(&path).unwrap();
    assert_eq!(store.rows("items").len(), 1);
    drop(store);
    std::fs::write(&path, "not json").unwrap();
    assert!(Store::open(&path).is_err());
}
#[test]
fn routes_never_advertise_explicit_unported_operations() {
    assert_eq!(config::ROLES.len(), 15);
    for (role, _, _) in config::ROLES {
        let routes = contracts::routes(role);
        let mut unique = std::collections::BTreeSet::new();
        for route in &routes {
            assert!(unique.insert((&route.method, &route.path)));
        }
        for service in contracts::services(role) {
            for operation in service.operations.values() {
                let path = format!("{}{}", service.base_path, s(operation, "path"));
                assert!(routes.iter().any(|r| r.implemented
                    && r.method == s(operation, "method")
                    && r.path == path));
            }
        }
    }
}
#[test]
fn path_decoder_rejects_smuggling() {
    for path in ["/a/%2f", "/a/%00", "/a/%5c", "/a/..", "/a/%0d"] {
        assert!(web::parameters("/a/{id}", path).is_none())
    }
    assert_eq!(
        web::parameters("/a/{id}", "/a/Alpha").unwrap()["id"],
        "Alpha"
    );
}
#[tokio::test]
async fn strict_config_and_no_ca_key_in_other_roles() {
    let f = Fixture::new("blacklist");
    let mut value = serde_json::to_value(&f.config).unwrap();
    value["unknownOption"] = true.into();
    assert!(serde_json::from_value::<Config>(value).is_err());
    let mut c = f.config.clone();
    c.ca_signing_key = "sensitive".into();
    assert!(c.validate().is_err());
}
