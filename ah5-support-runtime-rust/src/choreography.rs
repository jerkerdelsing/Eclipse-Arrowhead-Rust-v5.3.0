// SPDX-License-Identifier: EPL-2.0
// Plan execution follows the Java ChoreographerEngine: multi-action plans, step DAGs (nextStepNames), quantities,
// executor selection with exclusion and fallback, abort, notifications and abort of sessions of a previous run.
use crate::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

const MAX_ITERATION: i64 = 1000;
const UNBOUNDED: i64 = i64::MAX;
const START_SESSION_MSG: &str = "Session is started.";
const START_PLAN_MSG: &str = "Plan execution is started.";
const FINISH_PLAN_MSG: &str = "Plan execution is finished.";
const FINISH_SESSION_MSG: &str = "Session is finished.";
const ABORT_SESSION_MSG: &str = "Session is aborted.";
const ORCHESTRATOR: &str = "DynamicServiceOrchestration";

fn plan_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
fn names(v: &Value, key: &str) -> Vec<String> {
    array(v, key)
        .iter()
        .map(|n| n.as_str().unwrap_or("").trim().to_owned())
        .collect()
}
fn definition(requirement: &Value) -> &str {
    let d = s(requirement, "serviceDefinition");
    if d.is_empty() {
        s(requirement, "serviceDefinitionName")
    } else {
        d
    }
}
fn major(version: &str) -> Option<i64> {
    version.trim().split('.').next()?.parse().ok()
}
// [min, max] major window of a requirement's version list, as Java Versions.window
fn window(requirement: &Value) -> Result<(i64, i64)> {
    let versions = array(requirement, "versions");
    if versions.is_empty() {
        return Ok((1, UNBOUNDED));
    }
    let majors = versions
        .iter()
        .map(|v| v.as_str().and_then(major))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| Error::bad("Invalid version in service requirement"))?;
    Ok((*majors.iter().min().unwrap(), *majors.iter().max().unwrap()))
}
fn int(v: &Value, key: &str, default: i64) -> i64 {
    v[key].as_i64().unwrap_or(default)
}
fn key_of(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), str::to_owned)
}
fn active(status: &str) -> bool {
    ["INITIATED", "RUNNING", "WAITING", "STARTING"].contains(&status)
}
fn validate_steps(action: &Value) -> Result<()> {
    let name = s(action, "name");
    let steps = array(action, "steps");
    let first = names(action, "firstStepNames");
    if first.is_empty() {
        return Err(Error::bad(format!(
            "First step list of action {name} is empty"
        )));
    }
    if steps.is_empty() {
        return Err(Error::bad(format!("Step list of action {name} is empty")));
    }
    let mut graph = BTreeMap::new();
    for step in &steps {
        let step_name = s(step, "name").trim();
        if !plan_name_ok(step_name) || graph.contains_key(step_name) {
            return Err(Error::bad("Unique steps and serviceRequirement required"));
        }
        let requirement = &step["serviceRequirement"];
        if !requirement.is_object() || definition(requirement).trim().is_empty() {
            return Err(Error::bad("Unique steps and serviceRequirement required"));
        }
        window(requirement)?;
        if int(step, "quantity", 1) < 1 {
            return Err(Error::bad(format!(
                "Quantity of step {step_name} must be at least 1"
            )));
        }
        graph.insert(step_name.to_owned(), names(step, "nextStepNames"));
    }
    for next in graph.values().flatten().chain(&first) {
        if !graph.contains_key(next) {
            return Err(Error::bad(format!("Step not found: {next}")));
        }
    }
    for start in &first {
        if graph.values().flatten().any(|n| n == start) {
            return Err(Error::bad(format!(
                "First step {start} of action {name} is also the next step of another step"
            )));
        }
    }
    // Kahn's algorithm: a step left with incoming edges lies on a cycle
    let mut incoming: BTreeMap<&str, usize> = graph.keys().map(|k| (k.as_str(), 0)).collect();
    for next in graph.values().flatten() {
        *incoming.get_mut(next.as_str()).unwrap() += 1;
    }
    let mut ready: Vec<&str> = incoming
        .iter()
        .filter(|e| *e.1 == 0)
        .map(|e| *e.0)
        .collect();
    let mut sorted = 0;
    while let Some(step) = ready.pop() {
        sorted += 1;
        for next in &graph[step] {
            let n = incoming.get_mut(next.as_str()).unwrap();
            *n -= 1;
            if *n == 0 {
                ready.push(next);
            }
        }
    }
    if sorted != graph.len() {
        return Err(Error::bad(format!(
            "Circular reference detected between the steps of action: {name}"
        )));
    }
    let mut reached = BTreeSet::new();
    let mut todo = first.clone();
    while let Some(step) = todo.pop() {
        if reached.insert(step.clone()) {
            todo.extend(graph[&step].iter().cloned());
        }
    }
    if let Some(step) = graph.keys().find(|k| !reached.contains(*k)) {
        return Err(Error::bad(format!("Step is unreachable: {step}")));
    }
    Ok(())
}
pub fn validate_plan(plan: &Value) -> Result<()> {
    required(plan, &["name", "firstActionName"])?;
    let actions = array(plan, "actions");
    if actions.is_empty() {
        return Err(Error::bad("Plan requires actions"));
    }
    let mut action_names = BTreeSet::new();
    for action in &actions {
        if !plan_name_ok(s(action, "name")) || !action_names.insert(s(action, "name").to_owned()) {
            return Err(Error::bad("Action names must be unique"));
        }
        if s(action, "nextActionName") == s(action, "name") {
            return Err(Error::bad("Action cycle"));
        }
        validate_steps(action)?;
    }
    if !action_names.contains(s(plan, "firstActionName")) {
        return Err(Error::bad("Unknown first action"));
    }
    for action in &actions {
        if !s(action, "nextActionName").is_empty()
            && !action_names.contains(s(action, "nextActionName"))
        {
            return Err(Error::bad("Unknown next action"));
        }
    }
    let mut seen = BTreeSet::new();
    let mut next = s(plan, "firstActionName");
    while !next.is_empty() {
        if !seen.insert(next) {
            return Err(Error::bad("Action cycle"));
        }
        let action = actions.iter().find(|a| s(a, "name") == next).unwrap();
        next = s(action, "nextActionName")
    }
    if let Some(unreachable) = action_names.iter().find(|a| !seen.contains(a.as_str())) {
        return Err(Error::bad(format!(
            "Unreachable action detected: {unreachable}"
        )));
    }
    Ok(())
}
fn executor(req: &Value, caller: &Principal) -> Result<Value> {
    required(
        req,
        &["systemName", "address", "basePath", "serviceDefinitionName"],
    )?;
    let min = int(req, "minVersion", 1);
    let max = int(req, "maxVersion", UNBOUNDED);
    if !valid_name(s(req, "systemName"))
        || int(req, "port", 0) == 0
        || int(req, "port", 0) > 65535
        || !s(req, "basePath").starts_with('/')
        || s(req, "basePath").contains(['?', '#', '{', '}', '\\'])
        || min < 0
        || max < min
    {
        return Err(Error::bad("Invalid executor endpoint"));
    }
    let mut result = req.clone();
    result["id"] = id().into();
    result["createdBy"] = caller.name.clone().into();
    result["createdAt"] = now().into();
    Ok(result)
}

// ------------------------------------------------------------------------------------------- plan model
struct PlanView {
    plan: Value,
}
impl PlanView {
    fn action(&self, name: &str) -> Option<Value> {
        array(&self.plan, "actions")
            .into_iter()
            .find(|a| s(a, "name") == name)
    }
    fn step(&self, action: &str, step: &str) -> Option<Value> {
        array(&self.action(action)?, "steps")
            .into_iter()
            .find(|st| s(st, "name").trim() == step)
    }
    fn all_steps(&self) -> Vec<(String, Value)> {
        array(&self.plan, "actions")
            .iter()
            .flat_map(|a| {
                array(a, "steps")
                    .into_iter()
                    .map(|st| (s(a, "name").to_owned(), st))
                    .collect::<Vec<_>>()
            })
            .collect()
    }
    fn previous(&self, action: &str, step: &str) -> Vec<String> {
        self.action(action).map_or_else(Vec::new, |a| {
            array(&a, "steps")
                .iter()
                .filter(|st| names(st, "nextStepNames").iter().any(|n| n == step))
                .map(|st| s(st, "name").trim().to_owned())
                .collect()
        })
    }
}
fn plan_of(db: &mut Database, session: &Value) -> Result<PlanView> {
    table(db, "plans")
        .get(&key_of(&session["planId"]))
        .cloned()
        .map(|plan| PlanView { plan })
        .ok_or_else(|| Error::new(409, "Plan of session disappeared"))
}
fn cache_key(requirement: &Value) -> String {
    let (min, max) = window(requirement).unwrap_or((1, UNBOUNDED));
    format!("{}|{min}|{max}", definition(requirement))
}
fn next_number(db: &mut Database, name: &str) -> u64 {
    table(db, name)
        .values()
        .filter_map(|r| r["id"].as_u64())
        .max()
        .unwrap_or(0)
        + 1
}
fn worklog(
    db: &mut Database,
    session: &Value,
    action: &str,
    step: &str,
    message: &str,
    exception: Option<&str>,
) {
    let number = next_number(db, "worklog");
    table(db, "worklog").insert(
        format!("{number:020}"),
        json!({"id":number,"entryDate":now(),"createdAt":now(),"planName":session["planName"],"actionName":action,"stepName":step,
               "sessionId":session["id"],"executionNumber":session["executionNumber"],"message":message,"exception":exception,
               "status":session["status"],"timestamp":now()}),
    );
}

// ------------------------------------------------------------------------------------------- executor selection
#[derive(Clone)]
struct Selected {
    executor: Value,
    dependencies: Vec<Value>,
}
fn orchestrator(app: &App) -> bool {
    app.config.upstreams.contains_key(ORCHESTRATOR)
}
async fn orchestrate(app: &App, requirement: &Value) -> Result<Option<Value>> {
    let response = app
        .remote
        .call(
            ORCHESTRATOR,
            "POST",
            "/serviceorchestration/orchestration/pull",
            &json!({"serviceRequirement":requirement}),
        )
        .await?;
    Ok(array(&response, "results").into_iter().next())
}
// As the Java ExecutorSelector: candidates for the definition and version window minus exclusions that answer
// service-info, ordered by the number of dependencies, whose dependencies have providers.
async fn select(app: &App, requirement: &Value, exclusions: &[String]) -> Option<Selected> {
    let name = definition(requirement);
    let (min, max) = window(requirement).ok()?;
    let mut answering = Vec::new();
    for e in app.store.rows("executors") {
        if s(&e, "serviceDefinitionName") != name
            || exclusions.iter().any(|x| x == s(&e, "id"))
            || min > int(&e, "maxVersion", UNBOUNDED)
            || int(&e, "minVersion", 1) > max
        {
            continue;
        }
        let target = format!("{}/service-info", s(&e, "basePath").trim_end_matches('/'));
        let body = json!({"serviceDefinition":name,"minVersion":min,"maxVersion":max.min(i64::from(i32::MAX))});
        if let Ok(info) = app
            .remote
            .call(s(&e, "systemName"), "POST", &target, &body)
            .await
        {
            answering.push(Selected {
                executor: e,
                dependencies: array(&info, "dependencies"),
            });
        }
    }
    answering.sort_by_key(|c| c.dependencies.len());
    for candidate in answering {
        let mut satisfied = true;
        for dependency in &candidate.dependencies {
            // without a pinned orchestrator a dependency cannot be verified, so it is treated as unsatisfiable
            if !orchestrator(app)
                || !matches!(
                    orchestrate(app, &dependency["serviceRequirement"]).await,
                    Ok(Some(_))
                )
            {
                satisfied = false;
                break;
            }
        }
        if satisfied {
            return Some(candidate);
        }
    }
    None
}
fn exclusions(app: &App, session_id: &str) -> Vec<String> {
    row(app, "sessions", session_id)
        .map(|r| names(&r, "excludedExecutors"))
        .unwrap_or_default()
}
fn exclude(app: &App, session_id: &str, requirement: &Value, executor_id: &str) -> Result<()> {
    app.store.update(|db| {
        if let Some(session) = table(db, "sessions").get_mut(session_id) {
            if let Some(cache) = session["executorCache"].as_object_mut() {
                cache.remove(&cache_key(requirement));
            }
            if let Some(list) = session["excludedExecutors"].as_array_mut() {
                list.push(executor_id.into());
            }
        }
        Ok(())
    })
}
async fn cached_or_select(app: &App, session_id: &str, requirement: &Value) -> Option<Selected> {
    let session = row(app, "sessions", session_id).ok()?;
    if let Some(executor_id) = session["executorCache"][cache_key(requirement)].as_str() {
        if let Ok(executor) = row(app, "executors", executor_id) {
            let dependencies = array(&session["executorDependencies"], executor_id);
            return Some(Selected {
                executor,
                dependencies,
            });
        }
    }
    let selected = select(app, requirement, &exclusions(app, session_id)).await?;
    app.store
        .update(|db| {
            if let Some(session) = table(db, "sessions").get_mut(session_id) {
                let id = s(&selected.executor, "id").to_owned();
                session["executorCache"][cache_key(requirement)] = id.clone().into();
                session["executorDependencies"][id] = selected.dependencies.clone().into();
            }
            Ok(())
        })
        .ok()?;
    Some(selected)
}

// ------------------------------------------------------------------------------------------- session engine
fn boot() -> &'static str {
    static BOOT: OnceLock<String> = OnceLock::new();
    BOOT.get_or_init(id)
}
// Sessions of a previous process cannot continue (Java abortSessionsOfPreviousRun); legacy single-step rows carry
// no boot marker and keep their old semantics.
fn abort_previous_run(app: &App) {
    let stale: Vec<String> = app
        .store
        .rows("sessions")
        .into_iter()
        .filter(|r| !s(r, "boot").is_empty() && s(r, "boot") != boot() && active(s(r, "status")))
        .map(|r| key_of(&r["id"]))
        .collect();
    for key in stale {
        let _ = mark_aborted(
            app,
            &key,
            "The Choreographer restarted; the session cannot be continued.",
        );
    }
}
fn notify(app: &App, session_id: &str, message: &str, details: String) {
    let Ok(session) = row(app, "sessions", session_id) else {
        return;
    };
    let provider = s(&session, "notifyProvider").to_owned();
    if provider.is_empty() {
        return;
    }
    let app = app.clone();
    let path = s(&session, "notifyPath").to_owned();
    let body = json!({"sessionId":session["id"],"planId":session["planId"],"planName":session["planName"],"timestamp":now(),
                      "status":session["status"],"message":message,"details":details});
    tokio::spawn(async move {
        let _ = app.remote.call(&provider, "POST", &path, &body).await;
    });
}
fn progress(session: &Value) -> String {
    format!(
        "Execution: {}/{}",
        session["executionNumber"], session["quantityGoal"]
    )
}
// Marks the session and its active steps ABORTED and returns the running steps with an executor.
fn mark_aborted(app: &App, session_id: &str, text: &str) -> Result<Option<(Value, Vec<Value>)>> {
    app.store.update(|db| {
        let Some(session) = table(db, "sessions").get_mut(session_id) else {
            return Ok(None);
        };
        if !active(s(session, "status")) {
            return Ok(None);
        }
        session["status"] = "ABORTED".into();
        session["updatedAt"] = now().into();
        session["message"] = text.into();
        let session = session.clone();
        let mut running = Vec::new();
        for step in table(db, "steps").values_mut() {
            if key_of(&step["sessionId"]) == session_id && active(s(step, "status")) {
                if s(step, "status") == "RUNNING" && !s(step, "executorName").is_empty() {
                    running.push(step.clone());
                }
                step["status"] = "ABORTED".into();
                step["updatedAt"] = now().into();
            }
        }
        // a pre-engine single-step session keeps its executor on the session row
        if running.is_empty() && !s(&session, "executor").is_empty() && session["boot"].is_null() {
            running.push(json!({"id":session["sessionStepId"],"executorName":session["executor"],"executorBasePath":session["executorBasePath"]}));
        }
        worklog(db, &session, "", "", &format!("{ABORT_SESSION_MSG} {text}"), None);
        Ok(Some((session, running)))
    })
}
pub async fn abort_session(
    app: &App,
    session_id: &str,
    causing: Option<&str>,
    message: &str,
) -> Result<()> {
    let text = message.trim();
    let Some((session, running)) = mark_aborted(app, session_id, text)? else {
        return Ok(());
    };
    for step in running {
        if causing == Some(key_of(&step["id"]).as_str()) {
            continue;
        }
        let base = if step["executorBasePath"].is_string() {
            s(&step, "executorBasePath").to_owned()
        } else {
            row(app, "executors", s(&step, "executorId"))
                .map(|e| s(&e, "basePath").to_owned())
                .unwrap_or_default()
        };
        let target = format!("{}/abort", base.trim_end_matches('/'));
        let body = json!({"sessionId":session["id"],"sessionStepId":step["id"]});
        if let Err(e) = app
            .remote
            .call(s(&step, "executorName"), "POST", &target, &body)
            .await
        {
            app.store.update(|db| {
                worklog(
                    db,
                    &session,
                    s(&step, "actionName"),
                    s(&step, "stepName"),
                    "Unable to send abort message to the executor",
                    Some(&e.message),
                );
                Ok(())
            })?;
        }
    }
    notify(
        app,
        session_id,
        ABORT_SESSION_MSG,
        format!("{}. {text}", progress(&session)),
    );
    Ok(())
}
fn spawn_steps(app: &App, session_id: &str, steps: Vec<String>) {
    for step in steps {
        let app = app.clone();
        let session_id = session_id.to_owned();
        tokio::spawn(async move {
            if let Err(e) = execute_step(&app, &session_id, &step).await {
                let _ = abort_session(&app, &session_id, Some(&step), &e.message).await;
            }
        });
    }
}
// Registers the session steps of a new execution, all WAITING, with their cached executors.
fn register_steps(db: &mut Database, session_id: &str) -> Result<Value> {
    let session = table(db, "sessions")
        .get_mut(session_id)
        .ok_or_else(|| Error::new(404, "Session absent"))?;
    session["executionNumber"] = (session["executionNumber"].as_i64().unwrap_or(0) + 1).into();
    session["updatedAt"] = now().into();
    let session = session.clone();
    let plan = plan_of(db, &session)?;
    for (action, step) in plan.all_steps() {
        let number = next_number(db, "steps");
        let executor_id = s(
            &session["executorCache"],
            &cache_key(&step["serviceRequirement"]),
        )
        .to_owned();
        let executor = table(db, "executors")
            .get(&executor_id)
            .cloned()
            .unwrap_or(Value::Null);
        table(db, "steps").insert(
            number.to_string(),
            json!({"id":number,"sessionStepId":number,"sessionId":session["id"],"planName":session["planName"],"actionName":action,
                   "stepName":s(&step,"name").trim(),"executorId":executor_id,"executorName":executor["systemName"],
                   "status":"WAITING","executionNumber":session["executionNumber"],"message":"","startedAt":now(),"updatedAt":now()}),
        );
    }
    Ok(session)
}
fn current_step<'a>(
    db: &'a mut Database,
    session: &Value,
    action: &str,
    step: &str,
) -> Option<&'a mut Value> {
    table(db, "steps").values_mut().find(|r| {
        key_of(&r["sessionId"]) == key_of(&session["id"])
            && r["executionNumber"] == session["executionNumber"]
            && s(r, "actionName") == action
            && s(r, "stepName") == step
    })
}
fn claim(db: &mut Database, session: &Value, action: &str, step: &str) -> Option<String> {
    let row = current_step(db, session, action, step)?;
    if s(row, "status") != "WAITING" {
        return None;
    }
    row["status"] = "RUNNING".into();
    row["message"] = format!("Running step: {}.{action}.{step}", s(session, "planName")).into();
    row["updatedAt"] = now().into();
    Some(key_of(&row["id"]))
}
fn claim_first(db: &mut Database, session: &Value, plan: &PlanView, action: &str) -> Vec<String> {
    let first = plan
        .action(action)
        .map(|a| names(&a, "firstStepNames"))
        .unwrap_or_default();
    first
        .iter()
        .filter_map(|st| claim(db, session, action, st))
        .collect()
}
async fn start_session(app: &App, session_id: &str) -> Result<()> {
    let session = app.store.update(|db| {
        let session = table(db, "sessions")
            .get_mut(session_id)
            .ok_or_else(|| Error::new(404, "Session absent"))?;
        session["status"] = "RUNNING".into();
        session["updatedAt"] = now().into();
        let session = session.clone();
        worklog(db, &session, "", "", START_SESSION_MSG, None);
        Ok(session)
    })?;
    notify(
        app,
        session_id,
        START_SESSION_MSG,
        format!("Quantity goal: {}", session["quantityGoal"]),
    );
    let plan = PlanView {
        plan: row(app, "plans", &key_of(&session["planId"]))?,
    };
    for (action, step) in plan.all_steps() {
        if cached_or_select(app, session_id, &step["serviceRequirement"])
            .await
            .is_none()
        {
            return Err(Error::unavailable(&format!(
                "Can't find properly working executor for step: {}.{action}.{}",
                s(&session, "planName"),
                s(&step, "name")
            )));
        }
    }
    let to_run = app.store.update(|db| {
        let session = register_steps(db, session_id)?;
        worklog(db, &session, "", "", "Found executors to all steps.", None);
        worklog(db, &session, "", "", START_PLAN_MSG, None);
        Ok(claim_first(
            db,
            &session,
            &plan,
            s(&plan.plan, "firstActionName"),
        ))
    })?;
    notify(
        app,
        session_id,
        START_PLAN_MSG,
        progress(&row(app, "sessions", session_id)?),
    );
    spawn_steps(app, session_id, to_run);
    Ok(())
}
async fn execute_step(app: &App, session_id: &str, step_id: &str) -> Result<()> {
    loop {
        let session = row(app, "sessions", session_id)?;
        let current = row(app, "steps", step_id)?;
        if s(&session, "status") != "RUNNING" || s(&current, "status") != "RUNNING" {
            return Ok(());
        }
        let plan = PlanView {
            plan: row(app, "plans", &key_of(&session["planId"]))?,
        };
        let step = plan
            .step(s(&current, "actionName"), s(&current, "stepName"))
            .ok_or_else(|| Error::new(409, "Session step not found in plan"))?;
        let requirement = step["serviceRequirement"].clone();
        let full = format!(
            "{}.{}.{}",
            s(&session, "planName"),
            s(&current, "actionName"),
            s(&current, "stepName")
        );
        let selected = cached_or_select(app, session_id, &requirement)
            .await
            .ok_or_else(|| {
                Error::unavailable(&format!(
                    "Can't find properly working executor for step: {full}"
                ))
            })?;
        let executor = selected.executor.clone();
        let executor_id = s(&executor, "id").to_owned();
        app.store.update(|db| {
            if let Some(r) = table(db, "steps").get_mut(step_id) {
                r["executorId"] = executor_id.clone().into();
                r["executorName"] = executor["systemName"].clone();
            }
            Ok(())
        })?;
        let mut preconditions = Vec::new();
        let mut main = Value::Null;
        if orchestrator(app) {
            let mut failed = false;
            for dependency in &selected.dependencies {
                match orchestrate(app, &dependency["serviceRequirement"]).await {
                    Ok(Some(result)) => preconditions.push(result),
                    _ => failed = true,
                }
            }
            if !failed {
                match orchestrate(app, &requirement).await {
                    Ok(Some(result)) => main = result,
                    Ok(None) => {
                        app.store.update(|db| {
                            worklog(
                                db,
                                &session,
                                s(&current, "actionName"),
                                s(&current, "stepName"),
                                &format!(
                                    "No providers found for executor {}",
                                    s(&executor, "systemName")
                                ),
                                None,
                            );
                            Ok(())
                        })?;
                        failed = true;
                    }
                    Err(e) => {
                        return Err(Error::new(
                            e.code,
                            format!("Problem occurred while orchestration for step {full}."),
                        ));
                    }
                }
            }
            if failed {
                exclude(app, session_id, &requirement, &executor_id)?;
                continue;
            }
        }
        let target = format!("{}/start", s(&executor, "basePath").trim_end_matches('/'));
        let payload = json!({"sessionId":session["id"],"sessionStepId":current["id"],"preconditionOrchestrationResults":preconditions,
                             "mainOrchestrationResult":main,"quantity":int(&step,"quantity",1),
                             "staticParameters":if step["staticParameters"].is_object(){step["staticParameters"].clone()}else{json!({})},
                             "serviceRequirement":requirement});
        if app
            .remote
            .call(s(&executor, "systemName"), "POST", &target, &payload)
            .await
            .is_ok()
        {
            return Ok(());
        }
        exclude(app, session_id, &requirement, &executor_id)?; // try again with another executor
    }
}
// Marks a step DONE and claims what it unblocks; returns None for a stale or duplicate notification.
fn step_success(app: &App, session_id: &str, step_id: &str) -> Result<Vec<String>> {
    let mut finished: Option<Value> = None;
    let mut plan_done: Option<Value> = None;
    let to_run = app.store.update(|db| {
        let session = table(db, "sessions")
            .get(session_id)
            .cloned()
            .ok_or_else(|| Error::new(404, "Session absent"))?;
        let step = table(db, "steps")
            .get_mut(step_id)
            .ok_or_else(|| Error::new(404, "Session step absent"))?;
        if s(&session, "status") != "RUNNING" || s(step, "status") != "RUNNING" {
            return Err(Error::new(409, "Session step not running"));
        }
        step["status"] = "DONE".into();
        step["message"] = "Step finished successfully.".into();
        step["updatedAt"] = now().into();
        let step = step.clone();
        let plan = plan_of(db, &session)?;
        let action_name = s(&step, "actionName");
        let definition = plan
            .step(action_name, s(&step, "stepName"))
            .ok_or_else(|| Error::new(409, "Session step not found in plan"))?;
        let next = names(&definition, "nextStepNames");
        let mut to_run = Vec::new();
        if !next.is_empty() {
            for n in next {
                let ready = plan.previous(action_name, &n).iter().all(|p| {
                    current_step(db, &session, action_name, p)
                        .is_some_and(|r| s(r, "status") == "DONE")
                });
                if ready {
                    to_run.extend(claim(db, &session, action_name, &n));
                }
            }
            return Ok(to_run);
        }
        let action = plan.action(action_name).unwrap_or(Value::Null);
        let action_done = array(&action, "steps").iter().all(|st| {
            current_step(db, &session, action_name, s(st, "name").trim())
                .is_some_and(|r| s(r, "status") == "DONE")
        });
        if !action_done {
            return Ok(to_run);
        }
        if !s(&action, "nextActionName").is_empty() {
            return Ok(claim_first(
                db,
                &session,
                &plan,
                s(&action, "nextActionName"),
            ));
        }
        let row = table(db, "sessions").get_mut(session_id).unwrap();
        row["quantityDone"] = (row["quantityDone"].as_i64().unwrap_or(0) + 1).into();
        row["updatedAt"] = now().into();
        let session = row.clone();
        worklog(db, &session, "", "", FINISH_PLAN_MSG, None);
        finished = Some(session.clone());
        if session["quantityDone"].as_i64() < session["quantityGoal"].as_i64() {
            let session = register_steps(db, session_id)?;
            worklog(db, &session, "", "", START_PLAN_MSG, None);
            Ok(claim_first(
                db,
                &session,
                &plan,
                s(&plan.plan, "firstActionName"),
            ))
        } else {
            let row = table(db, "sessions").get_mut(session_id).unwrap();
            row["status"] = "DONE".into();
            let session = row.clone();
            worklog(db, &session, "", "", FINISH_SESSION_MSG, None);
            plan_done = Some(session);
            Ok(to_run)
        }
    })?;
    if let Some(session) = finished {
        notify(
            app,
            session_id,
            FINISH_PLAN_MSG,
            format!(
                "Quantity: {}/{}",
                session["quantityDone"], session["quantityGoal"]
            ),
        );
        if plan_done.is_none() {
            notify(
                app,
                session_id,
                START_PLAN_MSG,
                progress(&row(app, "sessions", session_id)?),
            );
        }
    }
    if let Some(session) = plan_done {
        notify(
            app,
            session_id,
            FINISH_SESSION_MSG,
            format!("Number of executions: {}", session["quantityDone"]),
        );
    }
    Ok(to_run)
}
async fn step_error(
    app: &App,
    session: &Value,
    step: &Value,
    fatal: bool,
    detail: String,
) -> Result<()> {
    let session_id = key_of(&session["id"]);
    let step_id = key_of(&step["id"]);
    if fatal {
        return abort_session(app, &session_id, Some(&step_id), &detail).await;
    }
    app.store.update(|db| {
        worklog(
            db,
            session,
            s(step, "actionName"),
            s(step, "stepName"),
            &detail,
            None,
        );
        Ok(())
    })?;
    let plan = PlanView {
        plan: row(app, "plans", &key_of(&session["planId"]))?,
    };
    let requirement = plan
        .step(s(step, "actionName"), s(step, "stepName"))
        .map(|st| st["serviceRequirement"].clone())
        .unwrap_or(Value::Null);
    exclude(app, &session_id, &requirement, s(step, "executorId"))?;
    if cached_or_select(app, &session_id, &requirement)
        .await
        .is_none()
    {
        return abort_session(app, &session_id, Some(&step_id), &detail).await;
    }
    spawn_steps(app, &session_id, vec![step_id]);
    Ok(())
}
// The pre-engine single-step profile stored its step on the session row; such persisted sessions finish as before.
fn legacy_step_done(
    app: &App,
    key: &str,
    mut session: Value,
    req: &Value,
    caller: &Principal,
) -> Result<(u16, Value)> {
    own(caller, s(&session, "executor"))?;
    if !["RUNNING", "STARTING"].contains(&s(&session, "status"))
        || s(req, "sessionStepId") != s(&session, "sessionStepId")
    {
        return Err(Error::new(409, "Session step not running"));
    }
    let status = s(req, "status");
    if !["DONE", "SUCCESS", "ERROR", "FAILED", "FATAL_ERROR"].contains(&status) {
        return Err(Error::bad("Invalid step completion status"));
    }
    let success = ["DONE", "SUCCESS"].contains(&status);
    session["status"] = if success { "COMPLETED" } else { "ERROR" }.into();
    session["updatedAt"] = now().into();
    session["message"] = req["message"].clone();
    app.store.update(|db| {
        let current = table(db, "sessions")
            .get_mut(key)
            .ok_or_else(|| Error::new(404, "Session absent"))?;
        if !["RUNNING", "STARTING"].contains(&s(current, "status")) {
            return Err(Error::new(409, "Session changed"));
        }
        *current = session.clone();
        if let Some(step) = table(db, "steps").get_mut(s(req, "sessionStepId")) {
            step["status"] = session["status"].clone();
        }
        table(db, "worklog").insert(
            format!("{}-{}", now(), id()),
            json!({"sessionId":key,"status":session["status"],"timestamp":now()}),
        );
        Ok(())
    })?;
    Ok((200, session))
}
async fn notify_step_done(app: &App, req: &Value, caller: &Principal) -> Result<(u16, Value)> {
    let key = key_of(&req["sessionId"]);
    let session = row(app, "sessions", &key)?;
    if session["boot"].is_null() {
        return legacy_step_done(app, &key, session, req, caller);
    }
    let step_id = key_of(&req["sessionStepId"]);
    let step = row(app, "steps", &step_id)?;
    if key_of(&step["sessionId"]) != key {
        return Err(Error::new(404, "Session step absent"));
    }
    own(caller, s(&step, "executorName"))?;
    let detail = format!(
        "{}{}",
        s(req, "message"),
        if s(req, "exception").is_empty() {
            String::new()
        } else {
            format!(" {}", s(req, "exception"))
        }
    );
    match s(req, "status") {
        "SUCCESS" | "DONE" => {
            let to_run = step_success(app, &key, &step_id)?;
            spawn_steps(app, &key, to_run);
        }
        "ABORTED" => app.store.update(|db| {
            worklog(
                db,
                &session,
                s(&step, "actionName"),
                s(&step, "stepName"),
                "The execution of this step has aborted successfully.",
                None,
            );
            Ok(())
        })?,
        status @ ("ERROR" | "FAILED" | "FATAL_ERROR") => {
            if s(&session, "status") != "RUNNING" || s(&step, "status") != "RUNNING" {
                return Err(Error::new(409, "Session step not running"));
            }
            step_error(app, &session, &step, status == "FATAL_ERROR", detail).await?
        }
        _ => return Err(Error::bad("Invalid step completion status")),
    }
    Ok((200, row(app, "sessions", &key)?))
}

// ------------------------------------------------------------------------------------------- start
fn notify_target(
    app: &App,
    request: &Value,
    errors: &mut Vec<String>,
) -> Option<(String, String, String)> {
    let address = s(request, "notifyAddress").trim();
    if address.is_empty() {
        return None;
    }
    let protocol = s(request, "notifyProtocol").to_ascii_lowercase();
    if protocol != "http" && protocol != "https" {
        errors.push("Invalid notify protocol.".into());
    }
    let port = int(request, "notifyPort", 0);
    if !(1..=65535).contains(&port) {
        errors.push("Notify port must be between 1 and 65535.".into());
    }
    if !errors.is_empty() {
        return None;
    }
    let path = s(request, "notifyPath");
    let path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    let origin = format!("{protocol}://{address}:{port}/");
    // outbound calls are mutual TLS to explicitly pinned systems only
    match app.config.upstreams.iter().find(|(_, o)| **o == origin) {
        Some((provider, _)) if protocol == "https" => {
            let uri = format!("{origin}{}", path.trim_start_matches('/'));
            Some((provider.clone(), path, uri))
        }
        _ => {
            errors.push("Notify address must be an https origin pinned in upstreams.".into());
            None
        }
    }
}
async fn check(app: &App, plan: &Value, quantity: i64) -> Vec<String> {
    let mut errors = Vec::new();
    if quantity < 1 {
        errors.push("Quantity must be greater than 0.".into());
    }
    if quantity > MAX_ITERATION {
        errors.push(format!(
            "Quantity could not be greater than {MAX_ITERATION}."
        ));
    }
    let view = PlanView { plan: plan.clone() };
    for (action, step) in view.all_steps() {
        if select(app, &step["serviceRequirement"], &[])
            .await
            .is_none()
        {
            errors.push(format!(
                "Can't find properly working executor for step: {}.{action}.{}",
                s(plan, "name"),
                s(&step, "name")
            ));
        }
    }
    errors
}
async fn start(app: &App, request: &Value, caller: &Principal) -> Result<Value> {
    let quantity = int(request, "quantity", 1);
    let plan = if request["planId"].is_number() || request["planId"].is_string() {
        app.store
            .snapshot()
            .get("plans")
            .and_then(|t| t.get(&key_of(&request["planId"])))
            .cloned()
    } else {
        app.store
            .rows("plans")
            .into_iter()
            .find(|p| s(p, "name") == s(request, "planName").trim())
    };
    let Some(plan) = plan else {
        return Ok(
            json!({"planId":request["planId"],"sessionId":null,"quantity":quantity,"status":null,
                         "errorMessages":[format!("Plan not found: {}", key_of(&request[if request["planId"].is_null(){"planName"}else{"planId"}]))],"needInterCloud":false}),
        );
    };
    let mut errors = Vec::new();
    let target = notify_target(app, request, &mut errors);
    if validate_plan(&plan).is_err() {
        errors.push("Plan is not executable by this Choreographer.".into());
    } else {
        errors.extend(check(app, &plan, quantity).await);
    }
    if !errors.is_empty() {
        return Ok(
            json!({"planId":plan["id"],"sessionId":null,"quantity":quantity,"status":null,"errorMessages":errors,"needInterCloud":false}),
        );
    }
    let (provider, path, uri) = target.unwrap_or_default();
    let session = app.store.update(|db| {
        let number = next_number(db, "sessions");
        let session = json!({"id":number,"sessionId":number,"planId":plan["id"],"planName":plan["name"],"status":"INITIATED",
            "quantityDone":0,"quantityGoal":quantity,"executionNumber":0,"owner":caller.name,"createdBy":caller.name,
            "notifyUri":if uri.is_empty(){Value::Null}else{uri.clone().into()},"notifyProvider":provider,"notifyPath":path,
            "allowInterCloud":false,"chooseOptimalExecutor":request["chooseOptimalExecutor"]==true,
            "executorCache":{},"executorDependencies":{},"excludedExecutors":[],"boot":boot(),
            "startedAt":now(),"createdAt":now(),"updatedAt":now()});
        table(db, "sessions").insert(number.to_string(), session.clone());
        Ok(session)
    })?;
    let session_id = key_of(&session["id"]);
    let app = app.clone();
    tokio::spawn(async move {
        if let Err(e) = start_session(&app, &session_id).await {
            let _ = abort_session(&app, &session_id, None, &e.message).await;
        }
    });
    Ok(
        json!({"planId":plan["id"],"sessionId":session["id"],"quantity":quantity,"status":"INITIATED","errorMessages":[],"needInterCloud":false}),
    )
}
fn filtered(app: &App, bucket: &str, q: &Value) -> Vec<Value> {
    let filters: Vec<(&str, String)> = [
        "planId",
        "sessionId",
        "status",
        "planName",
        "actionName",
        "stepName",
    ]
    .iter()
    .filter(|k| !q[**k].is_null() && !key_of(&q[**k]).is_empty())
    .map(|k| (*k, key_of(&q[*k]).to_ascii_uppercase()))
    .collect();
    app.store
        .rows(bucket)
        .into_iter()
        .filter(|r| {
            filters.iter().all(|(k, v)| {
                let field = if bucket == "sessions" && *k == "sessionId" {
                    "id"
                } else {
                    k
                };
                key_of(&r[field]).to_ascii_uppercase() == *v
            })
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub async fn handle(
    app: &App,
    method: &str,
    path: &str,
    p: &BTreeMap<String, String>,
    q: &Value,
    req: &Value,
    caller: &Principal,
) -> Result<(u16, Value)> {
    abort_previous_run(app);
    if path.contains("/plans") {
        if method == "GET" {
            if let Some(key) = p.get("id") {
                let plan = row(app, "plans", key)?;
                if path.ends_with("/check") {
                    validate_plan(&plan)?;
                    let quantity = int(q, "quantity", 1);
                    let errors = check(app, &plan, quantity).await;
                    return Ok((
                        200,
                        json!({"planId":plan["id"],"errorMessages":errors,"needInterCloud":false,"valid":errors.is_empty()}),
                    ));
                }
                return Ok((200, plan));
            }
            return Ok((200, page(app.store.rows("plans"), q, "entries")?));
        }
        if method == "DELETE" {
            let key = &p["id"];
            app.store.update(|db| {
                if table(db, "sessions")
                    .values()
                    .any(|r| key_of(&r["planId"]) == *key && active(s(r, "status")))
                {
                    return Err(Error::new(409, "Plan has running session"));
                }
                table(db, "plans")
                    .remove(key)
                    .ok_or_else(|| Error::new(404, "Plan absent"))
            })?;
            return Ok((200, Value::Null));
        }
        validate_plan(req)?;
        let plan = app.store.update(|db| {
            let t = table(db, "plans");
            if t.values().any(|r| s(r, "name") == s(req, "name")) {
                return Err(Error::new(409, "Plan name exists"));
            }
            let mut plan = req.clone();
            let id = (t
                .values()
                .filter_map(|r| r["id"].as_u64())
                .max()
                .unwrap_or(0)
                + 1)
            .to_string();
            plan["id"] = id.parse::<u64>().unwrap().into();
            plan["createdAt"] = now().into();
            t.insert(id, plan.clone());
            Ok(plan)
        })?;
        return Ok((201, plan));
    }
    if path.contains("/executor/") || path.contains("/executors") {
        if path.ends_with("/notify-step-done") {
            return notify_step_done(app, req, caller).await;
        }
        if method == "GET" {
            return Ok((
                200,
                if let Some(key) = p.get("id") {
                    row(app, "executors", key)?
                } else {
                    page(app.store.rows("executors"), q, "entries")?
                },
            ));
        }
        if method == "DELETE" {
            let keys = if let Some(key) = p.get("id") {
                vec![key.clone()]
            } else {
                app.store
                    .rows("executors")
                    .iter()
                    .filter(|r| s(r, "systemName") == caller.name)
                    .map(|r| s(r, "id").into())
                    .collect()
            };
            app.store.update(|db| {
                for key in keys {
                    let old = table(db, "executors")
                        .get(&key)
                        .ok_or_else(|| Error::new(404, "Executor absent"))?;
                    if !path.contains("/mgmt/") {
                        own(caller, s(old, "systemName"))?
                    }
                    let busy = table(db, "sessions")
                        .values()
                        .any(|r| s(r, "executorId") == key && s(r, "status") == "RUNNING")
                        || table(db, "steps")
                            .values()
                            .any(|r| s(r, "executorId") == key && s(r, "status") == "RUNNING");
                    if busy {
                        return Err(Error::new(409, "Executor has running session"));
                    }
                    table(db, "executors").remove(&key);
                }
                Ok(())
            })?;
            return Ok((200, Value::Null));
        }
        let value = executor(req, caller)?;
        if !path.contains("/mgmt/") {
            own(caller, s(&value, "systemName"))?
        }
        let origin = format!(
            "https://{}:{}/",
            s(&value, "address"),
            int(&value, "port", 0)
        );
        if app.config.upstreams.get(s(&value, "systemName")) != Some(&origin) {
            return Err(Error::bad(
                "Executor origin must be explicitly pinned in upstreams",
            ));
        }
        app.store.update(|db| {
            table(db, "executors").insert(s(&value, "id").into(), value.clone());
            Ok(())
        })?;
        return Ok((201, value));
    }
    if method == "GET" {
        let bucket = if path.ends_with("/session-steps") {
            "steps"
        } else if path.ends_with("/worklog") {
            "worklog"
        } else {
            "sessions"
        };
        return Ok((200, page(filtered(app, bucket, q), q, "entries")?));
    }
    if method == "DELETE" {
        let key = &p["id"];
        let old = row(app, "sessions", key)?;
        if !path.contains("/mgmt/") {
            own(caller, s(&old, "createdBy"))?
        }
        abort_session(app, key, None, &format!("Aborted by {}.", caller.name)).await?;
        return Ok((200, Value::Null));
    }
    let requests = req
        .as_array()
        .cloned()
        .unwrap_or_else(|| array(req, "sessions"));
    let requests = if requests.is_empty() {
        vec![req.clone()]
    } else {
        requests
    };
    // Inter-cloud orchestration on behalf of executors is not available to this Choreographer; reject before any start.
    if requests.iter().any(|r| r["allowInterCloud"] == true) {
        return Err(Error::unsupported(
            "Inter-cloud plan execution is not ported",
        ));
    }
    let mut entries = Vec::new();
    for request in &requests {
        entries.push(start(app, request, caller).await?);
    }
    Ok((201, json!({"entries":entries})))
}
