// SPDX-License-Identifier: EPL-2.0
mod common;
use arrowhead_support_rust::*;
use axum::Router;
use common::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

type Log = Arc<Mutex<Vec<(String, Value)>>>;
struct Executor {
    log: Log,
    fail_start: Arc<AtomicBool>,
    _fixture: Fixture,
    server: Server,
}
async fn executor(name: &str) -> Executor {
    let fixture = Fixture::named("blacklist", name);
    let log: Log = Arc::default();
    let fail_start = Arc::new(AtomicBool::new(false));
    let (l, fail) = (log.clone(), fail_start.clone());
    let router = Router::new().fallback(move |request: axum::extract::Request| {
        let (l, fail) = (l.clone(), fail.clone());
        async move {
            let path = request.uri().path().to_owned();
            let bytes = axum::body::to_bytes(request.into_body(), 1 << 20)
                .await
                .unwrap();
            let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            l.lock().unwrap().push((path.clone(), body));
            if path.ends_with("/start") && fail.load(Ordering::SeqCst) {
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(json!({})),
                );
            }
            if path.ends_with("/service-info") {
                return (
                    axum::http::StatusCode::OK,
                    axum::Json(json!({"dependencies":[]})),
                );
            }
            (axum::http::StatusCode::OK, axum::Json(json!({})))
        }
    });
    let server = start_router(fixture.app.clone(), fixture.tls.clone(), router).await;
    Executor {
        log,
        fail_start,
        _fixture: fixture,
        server,
    }
}
impl Executor {
    fn starts(&self) -> Vec<Value> {
        self.calls("/start")
    }
    fn calls(&self, suffix: &str) -> Vec<Value> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.0.ends_with(suffix))
            .map(|c| c.1.clone())
            .collect()
    }
}
struct Cloud {
    f: Fixture,
    _auth: (Fixture, Server),
    executors: Vec<Executor>,
}
async fn cloud(names: &[&str]) -> Cloud {
    let auth = mock_auth().await;
    let mut executors = Vec::new();
    for name in names {
        executors.push(executor(name).await);
    }
    let mut f = Fixture::new("choreographer");
    f.config.authentication_url = auth.1.origin.clone();
    for (name, e) in names.iter().zip(&executors) {
        f.config
            .upstreams
            .insert((*name).into(), format!("{}/", e.server.origin));
    }
    f.reconfigure();
    for (name, e) in names.iter().zip(&executors) {
        let (address, port) = e
            .server
            .origin
            .trim_start_matches("https://")
            .split_once(':')
            .unwrap();
        call(
            &f,
            "POST",
            "/choreographer/mgmt/executors",
            json!({"systemName":name,"address":address,"port":port.parse::<u16>().unwrap(),
             "basePath":"/exec","serviceDefinitionName":"work"}),
            "Sysop",
        )
        .await
        .unwrap();
    }
    Cloud {
        f,
        _auth: auth,
        executors,
    }
}
async fn call(
    f: &Fixture,
    method: &str,
    path: &str,
    req: Value,
    who: &str,
) -> Result<(u16, Value)> {
    call_with(f, method, path, BTreeMap::new(), req, who).await
}
async fn call_with(
    f: &Fixture,
    method: &str,
    path: &str,
    p: BTreeMap<String, String>,
    req: Value,
    who: &str,
) -> Result<(u16, Value)> {
    choreography::handle(&f.app, method, path, &p, &json!({}), &req, &caller(who)).await
}
fn step(name: &str, next: &[&str]) -> Value {
    json!({"name":name,"serviceRequirement":{"serviceDefinition":"work"},"nextStepNames":next,"staticParameters":{"step":name}})
}
// A: S1 -> {S2, S3} -> S4 (S4 joins both), then action B: T
fn dag_plan() -> Value {
    json!({"name":"Dag","firstActionName":"A","actions":[
        {"name":"A","firstStepNames":["S1"],"nextActionName":"B","steps":[step("S1",&["S2","S3"]),step("S2",&["S4"]),step("S3",&["S4"]),step("S4",&[])]},
        {"name":"B","firstStepNames":["T"],"steps":[step("T",&[])]}]})
}
async fn wait_for(what: impl Fn() -> bool) {
    for _ in 0..200 {
        if what() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("condition not reached");
}
fn started_steps(e: &Executor) -> Vec<String> {
    e.starts()
        .iter()
        .map(|b| s(&b["staticParameters"], "step").to_owned())
        .collect()
}
async fn done(c: &Cloud, who: &str, start: &Value, status: &str) -> Result<(u16, Value)> {
    call(&c.f, "POST", "/choreographer/executor/notify-step-done",
         json!({"sessionId":start["sessionId"],"sessionStepId":start["sessionStepId"],"status":status,"message":"m"}), who).await
}
async fn start_plan(c: &Cloud, plan: Value, quantity: u64) -> Value {
    call(
        &c.f,
        "POST",
        "/choreographer/mgmt/plans",
        plan.clone(),
        "Sysop",
    )
    .await
    .unwrap();
    let (code, response) = call(
        &c.f,
        "POST",
        "/choreographer/session/start",
        json!({"planName":plan["name"],"quantity":quantity}),
        "Client",
    )
    .await
    .unwrap();
    assert_eq!(code, 201);
    let entry = response["entries"][0].clone();
    assert_eq!(entry["errorMessages"], json!([]), "{entry}");
    entry["sessionId"].clone()
}
fn session(c: &Cloud, id: &Value) -> Value {
    row(&c.f.app, "sessions", &id.to_string()).unwrap()
}

#[tokio::test]
async fn multi_action_dag_runs_in_dependency_order_and_repeats() {
    let c = cloud(&["ExecA"]).await;
    let e = &c.executors[0];
    let id = start_plan(&c, dag_plan(), 2).await;
    wait_for(|| e.starts().len() == 1).await;
    assert_eq!(started_steps(e), ["S1"]);
    assert_eq!(session(&c, &id)["status"], "RUNNING");
    done(&c, "ExecA", &e.starts()[0], "SUCCESS").await.unwrap();
    wait_for(|| e.starts().len() == 3).await;
    let mut parallel = started_steps(e)[1..].to_vec();
    parallel.sort();
    assert_eq!(parallel, ["S2", "S3"]);
    // the join step waits for both of its previous steps
    let s2 = e
        .starts()
        .into_iter()
        .find(|b| b["staticParameters"]["step"] == "S2")
        .unwrap();
    let s3 = e
        .starts()
        .into_iter()
        .find(|b| b["staticParameters"]["step"] == "S3")
        .unwrap();
    done(&c, "ExecA", &s2, "SUCCESS").await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(e.starts().len(), 3);
    // a duplicate notification is refused
    assert_eq!(
        done(&c, "ExecA", &s2, "SUCCESS").await.unwrap_err().code,
        409
    );
    done(&c, "ExecA", &s3, "SUCCESS").await.unwrap();
    wait_for(|| e.starts().len() == 4).await;
    assert_eq!(started_steps(e)[3], "S4");
    done(&c, "ExecA", &e.starts()[3], "SUCCESS").await.unwrap();
    wait_for(|| e.starts().len() == 5).await;
    assert_eq!(started_steps(e)[4], "T");
    done(&c, "ExecA", &e.starts()[4], "SUCCESS").await.unwrap();
    // second execution of the quantity goal starts over at the first action
    wait_for(|| e.starts().len() == 6).await;
    assert_eq!(started_steps(e)[5], "S1");
    assert_eq!(session(&c, &id)["quantityDone"], 1);
    assert_eq!(session(&c, &id)["executionNumber"], 2);
    for expected in [vec!["S1"], vec!["S2", "S3"], vec!["S4"], vec!["T"]] {
        let starts = e.starts();
        let batch: Vec<Value> = starts[starts.len() - expected.len()..].to_vec();
        for b in &batch {
            done(&c, "ExecA", b, "SUCCESS").await.unwrap();
        }
        if expected == ["T"] {
            break;
        }
        let total = starts.len();
        let next = if expected == ["S1"] { 2 } else { 1 };
        wait_for(|| e.starts().len() == total + next).await;
    }
    wait_for(|| session(&c, &id)["status"] == "DONE").await;
    assert_eq!(session(&c, &id)["quantityDone"], 2);
    let steps = filtered_steps(&c, &id);
    assert_eq!(steps.len(), 10);
    assert!(steps.iter().all(|r| r["status"] == "DONE"));
    let worklog = c.f.app.store.rows("worklog");
    assert!(
        worklog
            .iter()
            .any(|w| w["message"] == "Session is finished.")
    );
}
fn filtered_steps(c: &Cloud, id: &Value) -> Vec<Value> {
    c.f.app
        .store
        .rows("steps")
        .into_iter()
        .filter(|r| r["sessionId"] == *id)
        .collect()
}

#[tokio::test]
async fn step_error_moves_to_another_executor_then_aborts() {
    let c = cloud(&["ExecA", "ExecB"]).await;
    let plan = json!({"name":"One","firstActionName":"A","actions":[{"name":"A","firstStepNames":["S"],"steps":[step("S",&[])]}]});
    let id = start_plan(&c, plan, 1).await;
    let starts = || c.executors[0].starts().len() + c.executors[1].starts().len();
    wait_for(|| starts() == 1).await;
    let (first, second) = if c.executors[0].starts().is_empty() {
        (1, 0)
    } else {
        (0, 1)
    };
    let names = ["ExecA", "ExecB"];
    let start = c.executors[first].starts()[0].clone();
    // only the executor of the step may report it
    assert_eq!(
        done(&c, names[second], &start, "SUCCESS")
            .await
            .unwrap_err()
            .code,
        403
    );
    done(&c, names[first], &start, "ERROR").await.unwrap();
    wait_for(|| c.executors[second].starts().len() == 1).await;
    assert_eq!(session(&c, &id)["status"], "RUNNING");
    let retry = c.executors[second].starts()[0].clone();
    assert_eq!(retry["sessionStepId"], start["sessionStepId"]);
    done(&c, names[second], &retry, "ERROR").await.unwrap();
    wait_for(|| session(&c, &id)["status"] == "ABORTED").await;
    assert_eq!(filtered_steps(&c, &id)[0]["status"], "ABORTED");
}

#[tokio::test]
async fn fatal_error_and_start_failure_handling() {
    let c = cloud(&["ExecA", "ExecB"]).await;
    // an executor that refuses the start request is excluded and the next one is used
    c.executors[0].fail_start.store(true, Ordering::SeqCst);
    c.executors[1].fail_start.store(true, Ordering::SeqCst);
    let plan = json!({"name":"Fatal","firstActionName":"A","actions":[{"name":"A","firstStepNames":["S"],"steps":[step("S",&[])]}]});
    let id = start_plan(&c, plan.clone(), 1).await;
    wait_for(|| session(&c, &id)["status"] == "ABORTED").await;
    assert_eq!(
        c.executors[0].starts().len() + c.executors[1].starts().len(),
        2
    );
    c.executors[0].fail_start.store(false, Ordering::SeqCst);
    let (_, response) = call(
        &c.f,
        "POST",
        "/choreographer/session/start",
        json!({"planName":"Fatal"}),
        "Client",
    )
    .await
    .unwrap();
    let id = response["entries"][0]["sessionId"].clone();
    let before = c.executors[0].starts().len();
    wait_for(|| c.executors[0].starts().len() > before).await;
    let start = c.executors[0].starts().last().unwrap().clone();
    done(&c, "ExecA", &start, "FATAL_ERROR").await.unwrap();
    wait_for(|| session(&c, &id)["status"] == "ABORTED").await;
    // the step that caused the abort is not sent an abort request
    assert!(c.executors[0].calls("/abort").is_empty());
}

#[tokio::test]
async fn abort_stops_running_steps_and_rejects_late_results() {
    let c = cloud(&["ExecA"]).await;
    let e = &c.executors[0];
    let id = start_plan(&c, dag_plan(), 1).await;
    wait_for(|| e.starts().len() == 1).await;
    done(&c, "ExecA", &e.starts()[0], "SUCCESS").await.unwrap();
    wait_for(|| e.starts().len() == 3).await;
    // a consumer may abort only the sessions it started
    let p = BTreeMap::from([("id".to_owned(), id.to_string())]);
    assert_eq!(
        call_with(
            &c.f,
            "DELETE",
            "/choreographer/session/abort/x",
            p.clone(),
            json!({}),
            "Other"
        )
        .await
        .unwrap_err()
        .code,
        403
    );
    call_with(
        &c.f,
        "DELETE",
        "/choreographer/session/abort/x",
        p.clone(),
        json!({}),
        "Client",
    )
    .await
    .unwrap();
    assert_eq!(session(&c, &id)["status"], "ABORTED");
    let aborted: Vec<Value> = e.calls("/abort");
    assert_eq!(aborted.len(), 2);
    let steps = filtered_steps(&c, &id);
    assert_eq!(steps.iter().filter(|r| r["status"] == "DONE").count(), 1);
    assert!(
        steps
            .iter()
            .all(|r| r["status"] == "DONE" || r["status"] == "ABORTED")
    );
    assert_eq!(
        done(&c, "ExecA", &e.starts()[1], "SUCCESS")
            .await
            .unwrap_err()
            .code,
        409
    );
    // aborting an aborted session is a no-op, as in Java
    call_with(
        &c.f,
        "DELETE",
        "/choreographer/mgmt/sessions/x",
        p,
        json!({}),
        "Sysop",
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(e.starts().len(), 3);
}

#[tokio::test]
async fn missing_executor_is_reported_without_side_effects() {
    let c = cloud(&[]).await;
    call(
        &c.f,
        "POST",
        "/choreographer/mgmt/plans",
        dag_plan(),
        "Sysop",
    )
    .await
    .unwrap();
    let (_, response) = call(
        &c.f,
        "POST",
        "/choreographer/session/start",
        json!({"planName":"Dag","quantity":1001}),
        "Client",
    )
    .await
    .unwrap();
    let errors = response["entries"][0]["errorMessages"]
        .as_array()
        .unwrap()
        .clone();
    assert!(
        errors
            .iter()
            .any(|e| e.as_str().unwrap().contains("greater than 1000"))
    );
    assert!(
        errors
            .iter()
            .any(|e| e.as_str().unwrap().contains("executor for step: Dag.A.S1"))
    );
    assert!(c.f.app.store.rows("sessions").is_empty());
}

#[test]
fn step_graph_validation() {
    let mut cyclic = dag_plan();
    cyclic["actions"][0]["steps"][3]["nextStepNames"] = json!(["S2"]);
    assert!(
        choreography::validate_plan(&cyclic)
            .unwrap_err()
            .message
            .contains("Circular")
    );
    let mut first_is_next = dag_plan();
    first_is_next["actions"][0]["steps"][3]["nextStepNames"] = json!(["S1"]);
    assert!(choreography::validate_plan(&first_is_next).is_err());
    let mut unreachable = dag_plan();
    unreachable["actions"][0]["steps"][0]["nextStepNames"] = json!(["S2"]);
    assert!(
        choreography::validate_plan(&unreachable)
            .unwrap_err()
            .message
            .contains("unreachable")
    );
    let mut unknown = dag_plan();
    unknown["actions"][0]["steps"][0]["nextStepNames"] = json!(["Nope"]);
    assert!(choreography::validate_plan(&unknown).is_err());
    let mut orphan_action = dag_plan();
    orphan_action["actions"][0]["nextActionName"] = Value::Null;
    assert!(
        choreography::validate_plan(&orphan_action)
            .unwrap_err()
            .message
            .contains("Unreachable action")
    );
    let mut quantity = dag_plan();
    quantity["actions"][1]["steps"][0]["quantity"] = json!(0);
    assert!(choreography::validate_plan(&quantity).is_err());
    assert!(choreography::validate_plan(&dag_plan()).is_ok());
}
