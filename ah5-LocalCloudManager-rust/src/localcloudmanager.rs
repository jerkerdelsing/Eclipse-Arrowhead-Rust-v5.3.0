use crate::{api::App, state::now};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use scrypt::{Params as ScryptParams, scrypt};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
use uuid::Uuid;

type ManagerError = (StatusCode, Json<Value>);
type ManagerResult = Result<Json<Value>, ManagerError>;

const INDEX: &str = include_str!("ui/index.html");
const SCRIPT: &str = include_str!("ui/app.js");
const STYLE: &str = include_str!("ui/styles.css");

static HISTORY: OnceLock<Mutex<Vec<Value>>> = OnceLock::new();
static CONSOLE: OnceLock<Mutex<ConsoleAuth>> = OnceLock::new();

struct ConsoleAuth {
    salt: Vec<u8>,
    hash: Vec<u8>,
    sessions: HashMap<String, Instant>,
    failures: Vec<Instant>,
    locked_until: Option<Instant>,
    allowed: BTreeSet<String>,
}
impl ConsoleAuth {
    fn load() -> Self {
        let raw = std::env::var("CONSOLE_PASSWORD_HASH").unwrap_or_default();
        let parts = raw.split(':').collect::<Vec<_>>();
        let (salt, hash) = if parts.len() == 3 && parts[0] == "scrypt" {
            (
                STANDARD.decode(parts[1]).unwrap_or_default(),
                STANDARD.decode(parts[2]).unwrap_or_default(),
            )
        } else {
            (vec![], vec![])
        };
        let allowed = std::env::var("CONSOLE_ALLOWED_HOSTS")
            .unwrap_or_else(|_| "127.0.0.1,localhost,[::1]".into())
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .collect();
        Self {
            salt,
            hash,
            sessions: HashMap::new(),
            failures: vec![],
            locked_until: None,
            allowed,
        }
    }
    fn configured(&self) -> bool {
        self.salt.len() >= 16 && self.hash.len() >= 32
    }
    fn authenticated(&mut self, headers: &HeaderMap) -> bool {
        let Some(token) = cookie(headers, "ah_console") else {
            return false;
        };
        let now = Instant::now();
        self.sessions.retain(|_, until| *until > now);
        self.sessions.contains_key(&token)
    }
}
fn console() -> &'static Mutex<ConsoleAuth> {
    CONSOLE.get_or_init(|| Mutex::new(ConsoleAuth::load()))
}
fn host_name(value: &str) -> String {
    let value = value.trim().to_ascii_lowercase();
    if value.starts_with('[') {
        return value
            .split(']')
            .next()
            .map(|s| format!("{s}]"))
            .unwrap_or(value);
    }
    value.split(':').next().unwrap_or("").into()
}
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|p| {
            let (k, v) = p.trim().split_once('=')?;
            (k == name).then(|| v.into())
        })
}

async fn console_guard(req: Request<axum::body::Body>, next: Next) -> Response {
    if let Some(response) = console_guard_response(&req) {
        return response;
    }
    next.run(req).await
}

fn console_guard_response(req: &Request<axum::body::Body>) -> Option<Response> {
    let path = req.uri().path();
    let headers = req.headers();
    let auth = console().lock().unwrap();
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(host_name)
        .unwrap_or_default();
    let origin_ok = headers
        .get(header::ORIGIN)
        .map(|v| {
            v.to_str()
                .ok()
                .and_then(|s| s.parse::<axum::http::Uri>().ok())
                .and_then(|u| u.host().map(host_name))
                .is_some_and(|h| auth.allowed.contains(&h))
        })
        .unwrap_or(true);
    if !auth.allowed.contains(&host) || !origin_ok {
        return Some(
            (
                StatusCode::FORBIDDEN,
                Json(json!({"error":"Host or Origin is not an allowed console address"})),
            )
                .into_response(),
        );
    }
    if !auth.configured() {
        return Some(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"Console password is not configured (CONSOLE_PASSWORD_HASH)"})),
            )
                .into_response(),
        );
    }
    drop(auth);
    if path != "/api/session" && !console().lock().unwrap().authenticated(headers) {
        return Some(
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":"Console login required"})),
            )
                .into_response(),
        );
    }
    None
}

pub fn routes(app: Router<App>) -> Router<App> {
    let api = Router::new()
        .route(
            "/api/session",
            get(session_state)
                .post(session_login)
                .delete(session_logout),
        )
        .route("/api/overview", get(overview))
        .route(
            "/api/service-registry-management",
            get(service_registry_management),
        )
        .route("/api/datamanager", get(datamanager))
        .route("/api/consumers", get(consumers))
        .route("/api/intercloud", get(intercloud))
        .route("/api/sysmonitor", get(sysmonitor))
        .route(
            "/api/sysmonitor/subscriptions",
            get(sysmonitor_subscriptions),
        )
        .route(
            "/api/sysmonitor/subscriptions/{provider}",
            put(update_sysmonitor_subscription).delete(update_sysmonitor_subscription),
        )
        .route(
            "/api/plantdescriptions",
            get(plant_descriptions).post(create_plant_description),
        )
        .route(
            "/api/plantdescriptions/{id}",
            put(update_plant_description)
                .patch(update_plant_description)
                .delete(delete_plant_description),
        )
        .route(
            "/api/orchestration/policies",
            get(editor_policies_get).post(editor_policies_post),
        )
        .route(
            "/api/orchestration/policies/{id}",
            delete(editor_policies_delete),
        )
        .route("/api/orchestration/rules", get(rules).post(create_rule))
        .route(
            "/api/orchestration/rules/{id}",
            delete(remove_rule).put(editor_rule_priority_update),
        )
        .route("/api/logs", get(logs))
        .route("/api/containers/{service}/{action}", post(lifecycle))
        .route_layer(middleware::from_fn(console_guard));
    app.route("/", get(index))
        .route("/ui", get(index))
        .route("/app.js", get(script))
        .route("/styles.css", get(style))
        .route("/assets/app.js", get(script))
        .route("/assets/styles.css", get(style))
        .merge(api)
}

async fn index() -> Html<&'static str> {
    Html(INDEX)
}
async fn script() -> impl IntoResponse {
    ([("content-type", "text/javascript; charset=utf-8")], SCRIPT)
}
async fn style() -> impl IntoResponse {
    ([("content-type", "text/css; charset=utf-8")], STYLE)
}

async fn session_state(headers: HeaderMap) -> impl IntoResponse {
    let mut auth = console().lock().unwrap();
    Json(json!({"authenticated":auth.authenticated(&headers),"configured":auth.configured()}))
}
async fn session_login(Json(body): Json<Value>) -> Response {
    let password = body.get("password").and_then(Value::as_str).unwrap_or("");
    let mut auth = console().lock().unwrap();
    let now = Instant::now();
    if auth.locked_until.is_some_and(|until| until > now) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "60")],
            Json(json!({"error":"Too many failed logins; try again later"})),
        )
            .into_response();
    }
    let mut candidate = vec![0; auth.hash.len()];
    let params = ScryptParams::new(14, 8, 1, auth.hash.len()).ok();
    let valid = !password.is_empty()
        && password.len() <= 256
        && params.is_some()
        && scrypt(
            password.as_bytes(),
            &auth.salt,
            &params.unwrap(),
            &mut candidate,
        )
        .is_ok()
        && constant_time_equal(&candidate, &auth.hash);
    if !valid {
        auth.failures
            .retain(|at| now.duration_since(*at) < Duration::from_secs(300));
        auth.failures.push(now);
        if auth.failures.len() >= 5 {
            auth.failures.clear();
            auth.locked_until = Some(now + Duration::from_secs(60))
        };
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"Wrong password"})),
        )
            .into_response();
    }
    auth.failures.clear();
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let seconds = std::env::var("CONSOLE_SESSION_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(28800);
    auth.sessions
        .insert(token.clone(), now + Duration::from_secs(seconds));
    (
        StatusCode::NO_CONTENT,
        [(
            header::SET_COOKIE,
            format!("ah_console={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={seconds}"),
        )],
    )
        .into_response()
}
fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (i, j) in a.iter().zip(b) {
        diff |= i ^ j
    }
    diff == 0
}
async fn session_logout(headers: HeaderMap) -> Response {
    if let Some(token) = cookie(&headers, "ah_console") {
        console().lock().unwrap().sessions.remove(&token);
    }
    (
        StatusCode::OK,
        [(
            header::SET_COOKIE,
            "ah_console=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        )],
        Json(json!({"authenticated":false})),
    )
        .into_response()
}

fn failure(status: StatusCode, error: impl ToString) -> ManagerError {
    (status, Json(json!({"error": error.to_string()})))
}

async fn registry_query(state: &App, resource: &str) -> Result<Value, String> {
    let response = state
        .client
        .post(format!(
            "{}/serviceregistry/mgmt/{resource}/query",
            state.config.registry_url
        ))
        .header(
            "Authorization",
            format!("Bearer SYSTEM//{}", state.config.system_name),
        )
        .json(&json!({}))
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let payload = response
        .json::<Value>()
        .await
        .map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!("ServiceRegistry returned {status}: {payload}"));
    }
    Ok(payload)
}

fn array<'a>(value: &'a Value, field: &str) -> &'a [Value] {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn system_to_service(name: &str) -> Option<&'static str> {
    Some(match name {
        "ServiceRegistry" => "serviceregistry",
        "Authentication" => "authentication",
        "ConsumerAuthorization" => "consumerauthorization",
        "DynamicServiceOrchestration" => "serviceorchestration-dynamic",
        "SimpleStoreServiceOrchestration" => "serviceorchestration-simple",
        "DataManager" => "datamanager",
        "EventHandler" => "eventhandler",
        "Onboarding" => "onboarding",
        "LocalCloudManager" => "localcloudmanager",
        _ => return None,
    })
}

fn service_display_name(name: &str) -> String {
    [
        "ServiceRegistry",
        "Authentication",
        "ConsumerAuthorization",
        "DynamicServiceOrchestration",
        "SimpleStoreServiceOrchestration",
        "DataManager",
        "EventHandler",
        "Onboarding",
        "LocalCloudManager",
    ]
    .into_iter()
    .find(|system| system_to_service(system) == Some(name))
    .unwrap_or(name)
    .to_string()
}

fn managed_service(name: &str) -> bool {
    system_to_service(&service_display_name(name)).is_some()
}

async fn overview(State(state): State<App>) -> ManagerResult {
    build_overview(&state).await.map(Json).map_err(|error| {
        failure(
            StatusCode::BAD_GATEWAY,
            format!("Local cloud overview failed: {error}"),
        )
    })
}

async fn build_overview(state: &App) -> Result<Value, String> {
    let collected_at = now();
    let (systems_result, services_result, containers_result) = tokio::join!(
        registry_query(state, "systems"),
        registry_query(state, "service-instances"),
        list_containers()
    );
    let systems_payload = systems_result
        .clone()
        .unwrap_or_else(|_| json!({"entries":[],"count":0}));
    let services_payload = services_result
        .clone()
        .unwrap_or_else(|_| json!({"entries":[],"count":0}));
    let containers = containers_result.clone().unwrap_or_default();
    let services = array(&services_payload, "entries").to_vec();
    let mut service_counts = BTreeMap::<String, usize>::new();
    for service in &services {
        if let Some(provider) = service.pointer("/provider/name").and_then(Value::as_str) {
            *service_counts.entry(provider.into()).or_default() += 1;
        }
    }
    let by_service = containers
        .iter()
        .filter_map(|container| {
            Some((
                container.get("service")?.as_str()?.to_string(),
                container.clone(),
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let mut systems = vec![];
    let mut registered_runtime = BTreeSet::new();
    for system in array(&systems_payload, "entries") {
        let mut output = system.as_object().cloned().unwrap_or_default();
        let name = system
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let compose = system_to_service(name);
        if let Some(compose) = compose {
            registered_runtime.insert(compose.to_string());
        }
        output.insert("composeService".into(), json!(compose));
        output.insert(
            "serviceCount".into(),
            json!(service_counts.get(name).copied().unwrap_or_default()),
        );
        output.insert(
            "runtime".into(),
            compose
                .and_then(|value| by_service.get(value).cloned())
                .unwrap_or(Value::Null),
        );
        systems.push(Value::Object(output));
    }
    let running = containers
        .iter()
        .filter(|item| item.get("state") == Some(&json!("running")))
        .count();
    let unhealthy = containers
        .iter()
        .filter(|item| item.get("health") == Some(&json!("unhealthy")))
        .count();
    let unregistered = containers
        .iter()
        .filter(|item| {
            item.get("managed") == Some(&json!(true))
                && item.get("state") == Some(&json!("running"))
                && item
                    .get("service")
                    .and_then(Value::as_str)
                    .is_some_and(|name| !registered_runtime.contains(name))
        })
        .filter_map(|item| item.get("service").cloned())
        .collect::<Vec<_>>();
    let sample = json!({
        "at": collected_at, "running": running, "containers": containers.len(),
        "registeredSystems": systems.len(), "registeredServices": services.len(),
        "unhealthy": unhealthy, "incidents": unhealthy + unregistered.len(),
        "unregisteredServices": unregistered
    });
    let history = {
        let mut history = HISTORY.get_or_init(|| Mutex::new(vec![])).lock().unwrap();
        history.push(sample.clone());
        if history.len() > 60 {
            history.remove(0);
        }
        history.clone()
    };
    let registry_management = build_registry_management(&systems, &services, &containers);
    let docker_error = containers_result.err();
    let arrowhead_error = systems_result.err().or_else(|| services_result.err());
    Ok(json!({
        "collectedAt": collected_at,
        "cloud": {"name": std::env::var("COMPOSE_PROJECT_NAME").unwrap_or_else(|_| "arrowhead-v53-test-cloud-rust".into()), "release":"5.2.2", "implementation":"rust", "registryReachable":arrowhead_error.is_none(), "dockerReachable":docker_error.is_none()},
        "summary": sample, "devices":[], "systems":systems, "services":services,
        "registryManagement":registry_management, "naming":{"valid":true,"violations":[]},
        "infrastructure":[], "orchestrations":[], "containers":containers, "history":history,
        "registration":{"registered":true,"instanceId":"LocalCloudManager|localCloudManagement|1.0.0","error":null,"checkedAt":collected_at},
        "errors":{"docker":docker_error,"arrowhead":arrowhead_error,"naming":null}
    }))
}

pub(crate) fn build_registry_management(
    systems: &[Value],
    services: &[Value],
    containers: &[Value],
) -> Value {
    let mut by_provider = BTreeMap::<String, Vec<Value>>::new();
    for service in services {
        if let Some(provider) = service.pointer("/provider/name").and_then(Value::as_str) {
            by_provider
                .entry(provider.into())
                .or_default()
                .push(service.clone());
        }
    }
    let mut grouped = vec![];
    let mut deployed_systems = 0;
    let mut deployed_services = 0;
    let mut registered_runtime = BTreeSet::new();
    for system in systems {
        let mut output = system.as_object().cloned().unwrap_or_default();
        let name = system
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let compose = system.get("composeService").and_then(Value::as_str);
        if let Some(compose) = compose {
            registered_runtime.insert(compose.to_string());
        }
        let deployed = system.pointer("/runtime/state") == Some(&json!("running"));
        if deployed {
            deployed_systems += 1;
        }
        let mut provided = by_provider.remove(name).unwrap_or_default();
        for service in &mut provided {
            service
                .as_object_mut()
                .unwrap()
                .insert("deployed".into(), json!(deployed));
            if deployed {
                deployed_services += 1;
            }
        }
        output.insert("deployed".into(), json!(deployed));
        output.insert("services".into(), json!(provided));
        grouped.push(Value::Object(output));
    }
    let runtime_only = containers
        .iter()
        .filter(|container| {
            container.get("managed") == Some(&json!(true))
                && container
                    .get("service")
                    .and_then(Value::as_str)
                    .is_some_and(|name| !registered_runtime.contains(name))
        })
        .map(|container| json!({"name":container["displayName"],"composeService":container["service"],"deployed":container["state"]=="running","runtime":container,"registered":false,"services":[]}))
        .collect::<Vec<_>>();
    json!({
        "devices":[{"name":"No registered device","addresses":[],"metadata":{},"registered":false,"deployed":deployed_systems>0,"serviceCount":services.len(),"systems":grouped}],
        "runtimeOnly":runtime_only,
        "summary":{"registeredDevices":0,"deployedDevices":0,"registeredSystems":systems.len(),"deployedSystems":deployed_systems,"registeredServices":services.len(),"deployedServices":deployed_services,"runtimeOnly":runtime_only.len()}
    })
}

async fn service_registry_management(State(state): State<App>) -> ManagerResult {
    let overview = build_overview(&state)
        .await
        .map_err(|error| failure(StatusCode::BAD_GATEWAY, error))?;
    let registry = &overview["registryManagement"];
    Ok(Json(
        json!({"collectedAt":overview["collectedAt"],"cloud":overview["cloud"],"devices":registry["devices"],"runtimeOnly":registry["runtimeOnly"],"summary":registry["summary"],"errors":overview["errors"]}),
    ))
}

async fn arrowhead_json(
    state: &App,
    method: reqwest::Method,
    url: String,
    body: Option<Value>,
) -> Result<Value, String> {
    let mut request = state.client.request(method, url).header(
        "Authorization",
        format!("Bearer SYSTEM//{}", state.config.system_name),
    );
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.map_err(|error| error.to_string())?;
    let status = response.status();
    let text = response.text().await.map_err(|error| error.to_string())?;
    let value = if text.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).map_err(|error| error.to_string())?
    };
    if !status.is_success() {
        return Err(format!("Arrowhead service returned {status}: {value}"));
    }
    Ok(value)
}

async fn consumers(State(state): State<App>) -> ManagerResult {
    let services = registry_query(&state, "service-instances")
        .await
        .map_err(|e| failure(StatusCode::BAD_GATEWAY, e))?;
    let rows=array(&services,"entries").iter().map(|s|json!({"provider":s["provider"]["name"],"serviceDefinition":s["serviceDefinition"]["name"],"providerCloud":"TestCloud","authorized":[],"orchestrated":[]})).collect::<Vec<_>>();
    Ok(Json(
        json!({"collectedAt":now(),"localCloud":"TestCloud","errors":[],"rows":rows}),
    ))
}
async fn intercloud() -> ManagerResult {
    Ok(Json(
        json!({"collectedAt":now(),"localCloud":"TestCloud","neighbourClouds":[],"neighbourError":null,"relay":{"gatekeeper":{"connected":false,"error":"No relay configured"},"gatetunnel":{"connected":false,"error":"No relay configured"}},"sessions":{"consumerSessions":0,"providerSessions":0,"sessions":[]},"producer":{"status":"unavailable","lastError":"No inter-cloud producer configured"}}),
    ))
}

async fn sysmonitor(
    State(state): State<App>,
    Query(query): Query<HashMap<String, String>>,
) -> ManagerResult {
    let base = std::env::var("SYSMONITOR_URL").unwrap_or_else(|_| "http://sysmonitor:8475".into());
    let payload = arrowhead_json(
        &state,
        reqwest::Method::GET,
        format!("{base}/sysmonitor/data"),
        None,
    )
    .await
    .unwrap_or_else(|_| json!({"entries":[]}));
    let mut grouped: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for item in array(&payload, "entries") {
        let name = item
            .get("sourceSystemName")
            .or_else(|| item.get("systemName"))
            .and_then(Value::as_str)
            .unwrap_or("Unknown")
            .to_string();
        grouped.entry(name).or_default().push(item.clone())
    }
    let selected = query
        .get("system")
        .filter(|s| grouped.contains_key(*s))
        .cloned()
        .or_else(|| grouped.keys().next().cloned())
        .unwrap_or_default();
    let mut systems = vec![];
    let mut observations = vec![];
    for (name, items) in &grouped {
        let mut latest = serde_json::Map::new();
        let mut last = Value::Null;
        for item in items {
            let kind = item
                .get("observationType")
                .and_then(Value::as_str)
                .unwrap_or("status");
            let source = item
                .get("sourceTime")
                .or_else(|| item.get("receivedAt"))
                .cloned()
                .unwrap_or(Value::Null);
            let obs = json!({"observationType":kind,"sourceTime":source,"value":item.get("value").cloned().unwrap_or(Value::Null),"quality":item.get("quality").cloned().unwrap_or(Value::Null)});
            latest.insert(kind.into(), obs.clone());
            last = source;
            if name == &selected {
                observations.push(obs)
            }
        }
        systems.push(json!({"systemName":name,"observationCount":items.len(),"lastObservationTime":last,"latest":latest}))
    }
    observations.reverse();
    Ok(Json(
        json!({"collectedAt":now(),"retentionDays":null,"storedObservations":array(&payload,"entries").len(),"systems":systems,"selectedSystem":selected,"observations":observations}),
    ))
}
async fn sysmonitor_subscriptions(State(state): State<App>) -> ManagerResult {
    let base = std::env::var("SYSMONITOR_URL").unwrap_or_else(|_| "http://sysmonitor:8475".into());
    let payload = arrowhead_json(
        &state,
        reqwest::Method::GET,
        format!("{base}/sysmonitor/management/subscriptions"),
        None,
    )
    .await
    .unwrap_or_else(|_| json!({"entries":[]}));
    Ok(Json(
        json!({"collectedAt":now(),"defaultSubscription":"none","providers":[],"subscriptions":array(&payload,"entries"),"intake":{"connected":true,"queue":"native","bindings":[]}}),
    ))
}
async fn update_sysmonitor_subscription(
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> ManagerResult {
    confirmed_headers(&headers)?;
    Ok(Json(json!({"providerSystem":provider,"updated":true})))
}

async fn plant_descriptions(State(state): State<App>) -> ManagerResult {
    let systems = registry_query(&state, "systems")
        .await
        .map_err(|e| failure(StatusCode::BAD_GATEWAY, e))?;
    let services = registry_query(&state, "service-instances")
        .await
        .map_err(|e| failure(StatusCode::BAD_GATEWAY, e))?;
    let base = std::env::var("PLANT_DESCRIPTION_ENGINE_URL")
        .unwrap_or_else(|_| "http://plantdescriptionengine:8432".into());
    let result = arrowhead_json(
        &state,
        reqwest::Method::GET,
        format!("{base}/plant-description-engine"),
        None,
    )
    .await;
    let (entries, error) = match result {
        Ok(v) => (array(&v, "entries").to_vec(), Value::Null),
        Err(e) => (vec![], json!(e)),
    };
    let names = array(&systems, "entries")
        .iter()
        .filter_map(|s| s["name"].as_str())
        .collect::<Vec<_>>();
    let catalog=array(&services,"entries").iter().map(|s|json!({"provider":s["provider"]["name"],"serviceDefinition":s["serviceDefinition"]["name"],"interfaces":array(s,"interfaces").iter().filter_map(|i|i["templateName"].as_str()).collect::<Vec<_>>()})).collect::<Vec<_>>();
    Ok(Json(
        json!({"collectedAt":now(),"entries":entries,"systems":names,"services":catalog,"registryError":error}),
    ))
}
async fn create_plant_description(
    State(state): State<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ManagerResult {
    confirmed_headers(&headers)?;
    plant_mutation(&state, reqwest::Method::POST, None, Some(body)).await
}
async fn update_plant_description(
    State(state): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> ManagerResult {
    confirmed_headers(&headers)?;
    plant_mutation(&state, reqwest::Method::PUT, Some(id), Some(body)).await
}
async fn delete_plant_description(
    State(state): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ManagerResult {
    confirmed_headers(&headers)?;
    plant_mutation(&state, reqwest::Method::DELETE, Some(id), None).await
}
async fn plant_mutation(
    state: &App,
    method: reqwest::Method,
    id: Option<String>,
    body: Option<Value>,
) -> ManagerResult {
    let base = std::env::var("PLANT_DESCRIPTION_ENGINE_URL")
        .unwrap_or_else(|_| "http://plantdescriptionengine:8432".into());
    let suffix = id.map(|v| format!("/{v}")).unwrap_or_default();
    arrowhead_json(
        state,
        method,
        format!("{base}/plant-description-engine{suffix}"),
        body,
    )
    .await
    .map(Json)
    .map_err(|e| failure(StatusCode::BAD_GATEWAY, e))
}
fn confirmed_headers(headers: &HeaderMap) -> Result<(), ManagerError> {
    if headers
        .get("x-arrowhead-action")
        .and_then(|v| v.to_str().ok())
        == Some("confirm")
    {
        Ok(())
    } else {
        Err(failure(
            StatusCode::PRECONDITION_REQUIRED,
            "Missing action confirmation header",
        ))
    }
}

async fn datamanager(
    State(state): State<App>,
    Query(query): Query<HashMap<String, String>>,
) -> ManagerResult {
    let base =
        std::env::var("DATAMANAGER_URL").unwrap_or_else(|_| "http://datamanager:8461".into());
    let limit = query
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(240)
        .clamp(1, 1000);
    let systems = arrowhead_json(
        &state,
        reqwest::Method::GET,
        format!("{base}/datamanager/data-historian/systems"),
        None,
    )
    .await
    .map_err(|error| failure(StatusCode::BAD_GATEWAY, error))?;
    let mut records = vec![];
    for system in array(&systems, "systems") {
        let Some(system) = system.as_str() else {
            continue;
        };
        let services = arrowhead_json(
            &state,
            reqwest::Method::GET,
            format!("{base}/datamanager/data-historian/systems/{system}/services"),
            None,
        )
        .await
        .map_err(|error| failure(StatusCode::BAD_GATEWAY, error))?;
        for service in array(&services, "services") {
            let Some(service) = service.as_str() else {
                continue;
            };
            let values = arrowhead_json(&state, reqwest::Method::GET, format!("{base}/datamanager/data-historian/systems/{system}/services/{service}/data?count={limit}"), None).await.map_err(|error| failure(StatusCode::BAD_GATEWAY,error))?;
            records.extend(values.as_array().cloned().unwrap_or_default());
        }
    }
    if records.len() > limit {
        records = records.split_off(records.len() - limit);
    }
    let mut series = BTreeMap::<String, Vec<Value>>::new();
    for record in &records {
        let name = record
            .get("n")
            .or_else(|| record.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("measurement");
        if let Some(value) = record.get("v").and_then(Value::as_f64) {
            series.entry(name.into()).or_default().push(json!({"time":record.get("t").and_then(Value::as_f64).unwrap_or_else(||chrono::Utc::now().timestamp() as f64),"value":value,"unit":record.get("u")}));
        }
    }
    let series = series
        .into_iter()
        .map(|(name, points)| json!({"name":name,"points":points}))
        .collect::<Vec<_>>();
    let entries = records
        .into_iter()
        .rev()
        .map(|mut record| {
            if let Some(object) = record.as_object_mut() {
                let name = object.get("n").cloned().unwrap_or(json!("measurement"));
                let unit = object.get("u").cloned().unwrap_or(Value::Null);
                let time = object
                    .get("t")
                    .cloned()
                    .unwrap_or_else(|| json!(chrono::Utc::now().timestamp()));
                let value =
                    json!({"v":object.get("v"),"vs":object.get("vs"),"vb":object.get("vb")});
                object.insert("name".into(), name);
                object.insert("unit".into(), unit);
                object.insert("time".into(), time);
                object.insert("value".into(), value);
            }
            record
        })
        .collect::<Vec<_>>();
    Ok(Json(
        json!({"collectedAt":now(),"count":entries.len(),"latest":[],"entries":entries,"series":series}),
    ))
}

pub(crate) fn orchestration_catalog(systems: &[Value], services: &[Value]) -> Value {
    let mut templates = BTreeMap::<String, BTreeSet<String>>::new();
    for service in services {
        let Some(provider) = service.pointer("/provider/name").and_then(Value::as_str) else {
            continue;
        };
        for interface in array(service, "interfaces") {
            if let Some(template) = interface.get("templateName").and_then(Value::as_str) {
                templates
                    .entry(provider.into())
                    .or_default()
                    .insert(template.into());
            }
        }
    }
    let mut x509 = BTreeMap::<String, bool>::new();
    let consumers = systems
        .iter()
        .filter_map(|system| {
            let name = system.get("name")?.as_str()?;
            let has_x509 = system
                .get("metadata")
                .and_then(Value::as_object)
                .is_some_and(|metadata| {
                    metadata.iter().any(|(key, value)| {
                        key.to_ascii_lowercase().contains("x509")
                            && value.as_str().is_some_and(|value| !value.is_empty())
                    })
                });
            x509.insert(name.into(), has_x509);
            Some(json!({"name":name,"version":system.get("version"),"x509":has_x509,"interfaceTemplates":templates.get(name).cloned().unwrap_or_default()}))
        })
        .collect::<Vec<_>>();
    let names = consumers
        .iter()
        .filter_map(|consumer| consumer.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    let producers = services
        .iter()
        .map(|service| {
            let provider = service
                .pointer("/provider/name")
                .and_then(Value::as_str)
                .unwrap_or("Unknown");
            let interfaces = array(service, "interfaces")
                .iter()
                .map(|interface| json!({"templateName":interface["templateName"],"protocol":interface["protocol"],"policy":interface["policy"]}))
                .collect::<Vec<_>>();
            let compatible = names
                .iter()
                .filter(|name| **name != provider)
                .filter(|name| {
                    interfaces.iter().any(|interface| {
                        let template = interface["templateName"].as_str().unwrap_or_default();
                        let policy = interface["policy"].as_str().unwrap_or_default();
                        templates.get(**name).is_some_and(|values| values.contains(template))
                            && (policy != "CERT_AUTH" || x509.get(**name) == Some(&true))
                    })
                })
                .collect::<Vec<_>>();
            json!({"instanceId":service["instanceId"],"provider":provider,"serviceDefinition":service["serviceDefinition"]["name"],"version":service["version"],"interfaces":interfaces,"compatibleConsumers":compatible})
        })
        .collect::<Vec<_>>();
    json!({"producers":producers,"consumers":consumers})
}

async fn rules(State(state): State<App>) -> ManagerResult {
    let systems = registry_query(&state, "systems")
        .await
        .map_err(|error| failure(StatusCode::BAD_GATEWAY, error))?;
    let services = registry_query(&state, "service-instances")
        .await
        .map_err(|error| failure(StatusCode::BAD_GATEWAY, error))?;
    let base = std::env::var("SIMPLE_ORCHESTRATION_URL")
        .unwrap_or_else(|_| "http://serviceorchestration-simple:8442".into());
    let stored = arrowhead_json(
        &state,
        reqwest::Method::POST,
        format!("{base}/serviceorchestration/orchestration/mgmt/simple-store/query"),
        Some(json!({})),
    )
    .await
    .map_err(|error| failure(StatusCode::BAD_GATEWAY, error))?;
    let rules = array(&stored, "entries").to_vec();
    Ok(Json(
        json!({"catalog":orchestration_catalog(array(&systems,"entries"),array(&services,"entries")),"rules":rules,"count":rules.len(),"dynamic":[],"dynamicError":null,"collectedAt":now()}),
    ))
}

async fn create_rule(
    State(state): State<App>,
    headers: HeaderMap,
    Json(candidate): Json<Value>,
) -> ManagerResult {
    if headers
        .get("x-arrowhead-action")
        .and_then(|v| v.to_str().ok())
        != Some("confirm")
    {
        return Err(failure(
            StatusCode::PRECONDITION_REQUIRED,
            "Missing action confirmation header",
        ));
    }
    let base = std::env::var("SIMPLE_ORCHESTRATION_URL")
        .unwrap_or_else(|_| "http://serviceorchestration-simple:8442".into());
    let consumer = candidate
        .get("consumer")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let instance_id = candidate
        .get("serviceInstanceId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let priority = candidate
        .get("priority")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if consumer.is_empty() || instance_id.is_empty() || priority == 0 {
        return Err(failure(
            StatusCode::BAD_REQUEST,
            "Consumer, service instance and a positive integer priority are required",
        ));
    }
    let systems = registry_query(&state, "systems")
        .await
        .map_err(|error| failure(StatusCode::BAD_GATEWAY, error))?;
    let services = registry_query(&state, "service-instances")
        .await
        .map_err(|error| failure(StatusCode::BAD_GATEWAY, error))?;
    let catalog = orchestration_catalog(array(&systems, "entries"), array(&services, "entries"));
    let producer = array(&catalog, "producers")
        .iter()
        .find(|producer| producer.get("instanceId").and_then(Value::as_str) == Some(instance_id))
        .ok_or_else(|| {
            failure(
                StatusCode::CONFLICT,
                "The selected producer is no longer available",
            )
        })?;
    if !array(producer, "compatibleConsumers")
        .iter()
        .any(|value| value.as_str() == Some(consumer))
    {
        return Err(failure(
            StatusCode::CONFLICT,
            "The selected consumer is not interoperable with this producer",
        ));
    }
    arrowhead_json(
        &state,
        reqwest::Method::POST,
        format!("{base}/serviceorchestration/orchestration/mgmt/simple-store/create"),
        Some(json!({"candidates":[candidate]})),
    )
    .await
    .map(Json)
    .map_err(|error| failure(StatusCode::BAD_GATEWAY, error))
}

async fn remove_rule(
    State(state): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ManagerResult {
    if headers
        .get("x-arrowhead-action")
        .and_then(|v| v.to_str().ok())
        != Some("confirm")
    {
        return Err(failure(
            StatusCode::PRECONDITION_REQUIRED,
            "Missing action confirmation header",
        ));
    }
    let base = std::env::var("SIMPLE_ORCHESTRATION_URL")
        .unwrap_or_else(|_| "http://serviceorchestration-simple:8442".into());
    arrowhead_json(
        &state,
        reqwest::Method::DELETE,
        format!("{base}/serviceorchestration/orchestration/mgmt/simple-store/remove?ids={id}"),
        None,
    )
    .await
    .map_err(|error| failure(StatusCode::BAD_GATEWAY, error))?;
    Ok(Json(json!({"id":id,"removed":true,"at":now()})))
}

async fn logs(Query(query): Query<HashMap<String, String>>) -> ManagerResult {
    let service = query.get("service").cloned().unwrap_or_default();
    let tail = query
        .get("tail")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(150)
        .clamp(1, 500);
    let containers = list_containers()
        .await
        .map_err(|error| failure(StatusCode::BAD_GATEWAY, error))?;
    let id = containers
        .iter()
        .find(|item| item["service"] == service)
        .and_then(|item| item["id"].as_str())
        .ok_or_else(|| failure(StatusCode::NOT_FOUND, "Unknown project service"))?;
    let body = docker_request(
        "GET",
        &format!("/containers/{id}/logs?stdout=1&stderr=1&timestamps=1&tail={tail}"),
    )
    .await
    .map_err(|error| failure(StatusCode::BAD_GATEWAY, error))?;
    let text = demux_logs(&body);
    let lines = text
        .lines()
        .rev()
        .take(tail)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>();
    Ok(Json(
        json!({"service":service,"lines":lines,"collectedAt":now()}),
    ))
}

async fn lifecycle(
    headers: HeaderMap,
    Path((service, action)): Path<(String, String)>,
    _body: Bytes,
) -> ManagerResult {
    if headers
        .get("x-arrowhead-action")
        .and_then(|v| v.to_str().ok())
        != Some("confirm")
    {
        return Err(failure(
            StatusCode::PRECONDITION_REQUIRED,
            "Missing action confirmation header",
        ));
    }
    if !managed_service(&service) {
        return Err(failure(
            StatusCode::FORBIDDEN,
            "This service is not in the management allowlist",
        ));
    }
    if !matches!(action.as_str(), "start" | "stop" | "restart") {
        return Err(failure(
            StatusCode::BAD_REQUEST,
            "Unsupported lifecycle action",
        ));
    }
    let containers = list_containers()
        .await
        .map_err(|error| failure(StatusCode::BAD_GATEWAY, error))?;
    let id = containers
        .iter()
        .find(|item| item["service"] == service)
        .and_then(|item| item["id"].as_str())
        .ok_or_else(|| failure(StatusCode::NOT_FOUND, "Unknown project service"))?;
    let suffix = if action == "start" {
        format!("/{action}")
    } else {
        format!("/{action}?t=20")
    };
    docker_request("POST", &format!("/containers/{id}{suffix}"))
        .await
        .map_err(|error| failure(StatusCode::BAD_GATEWAY, error))?;
    Ok(Json(
        json!({"service":service,"action":action,"accepted":true,"at":now()}),
    ))
}

async fn list_containers() -> Result<Vec<Value>, String> {
    let project = std::env::var("COMPOSE_PROJECT_NAME")
        .unwrap_or_else(|_| "arrowhead-v53-test-cloud-rust".into());
    let filters = percent_encode(
        &json!({"label":[format!("com.docker.compose.project={project}")]}).to_string(),
    );
    let body = docker_request("GET", &format!("/containers/json?all=1&filters={filters}")).await?;
    let rows: Vec<Value> = serde_json::from_slice(&body).map_err(|error| error.to_string())?;
    let mut output=rows.into_iter().map(|row|{let service=row.pointer("/Labels/com.docker.compose.service").and_then(Value::as_str).unwrap_or("unknown"); let status=row["Status"].as_str().unwrap_or_default(); let health=["healthy","unhealthy","starting"].into_iter().find(|value|status.contains(&format!("({value})"))); let id=row["Id"].as_str().unwrap_or_default(); json!({"id":&id[..id.len().min(12)],"name":row["Names"].as_array().and_then(|a|a.first()).and_then(Value::as_str).unwrap_or_default().trim_start_matches('/'),"service":service,"displayName":service_display_name(service),"image":row["Image"],"state":row["State"],"status":row["Status"],"health":health,"created":row["Created"],"managed":managed_service(service)})}).collect::<Vec<_>>();
    output.sort_by(|a, b| a["service"].as_str().cmp(&b["service"].as_str()));
    Ok(output)
}

async fn docker_request(method: &str, path: &str) -> Result<Vec<u8>, String> {
    let socket = std::env::var("DOCKER_SOCKET").unwrap_or_else(|_| "/var/run/docker.sock".into());
    docker_request_at(&socket, method, path).await
}
async fn docker_request_at(socket: &str, method: &str, path: &str) -> Result<Vec<u8>, String> {
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|error| error.to_string())?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    let mut response = vec![];
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|error| error.to_string())?;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("Invalid Docker API response")?;
    let header = String::from_utf8_lossy(&response[..split]);
    let status = header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(500);
    let mut body = response[split + 4..].to_vec();
    if header
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        body = decode_chunked(&body)?;
    }
    if status >= 400 {
        return Err(format!(
            "Docker API {status}: {}",
            String::from_utf8_lossy(&body)
        ));
    }
    Ok(body)
}

#[cfg(test)]
mod relocation_tests {
    use super::*;
    use crate::{
        api::{self, Config},
        state::Store,
    };
    use axum::{
        body::{Body, to_bytes},
        http::Method,
    };
    use std::{path::PathBuf, sync::Arc};
    use tower::ServiceExt;
    static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    struct Reset(Option<ConsoleAuth>);
    impl Drop for Reset {
        fn drop(&mut self) {
            if let Some(old) = self.0.take() {
                *console().lock().unwrap() = old
            }
        }
    }
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            // macOS's per-user temporary path can exceed the Unix socket limit.
            let p = PathBuf::from("/tmp").join(format!("lcm-rust-{}", Uuid::new_v4()));
            std::fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    async fn enter() -> (tokio::sync::MutexGuard<'static, ()>, Reset) {
        let serial = SERIAL.lock().await;
        let salt = vec![42; 16];
        let mut hash = vec![0; 32];
        scrypt(
            b"test-password",
            &salt,
            &ScryptParams::new(14, 8, 1, 32).unwrap(),
            &mut hash,
        )
        .unwrap();
        let auth = ConsoleAuth {
            salt,
            hash,
            sessions: HashMap::new(),
            failures: vec![],
            locked_until: None,
            allowed: BTreeSet::from(["localhost".into(), "127.0.0.1".into()]),
        };
        let old = std::mem::replace(&mut *console().lock().unwrap(), auth);
        (serial, Reset(Some(old)))
    }
    async fn app() -> (Temp, Router) {
        let temp = Temp::new();
        let c = Arc::new(Config {
            role: "localcloudmanager".into(),
            system_name: "LocalCloudManager".into(),
            domain_name: "localhost".into(),
            port: 8480,
            listen_address: "127.0.0.1:0".into(),
            data_file: temp.0.join("state.json").to_string_lossy().into(),
            registry_url: "http://127.0.0.1:1".into(),
            authentication_url: "http://127.0.0.1:1".into(),
            token_secret: "test-only".into(),
            management_whitelist: vec!["LocalCloudManager".into()],
        });
        let store = Arc::new(Store::load(&c.data_file).await.unwrap());
        let router = api::router(c, store);
        (temp, router)
    }
    async fn request(
        app: &Router,
        method: &str,
        path: &str,
        cookie: &str,
        confirm: bool,
        body: Value,
    ) -> Response {
        let mut r = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost")
            .header("content-type", "application/json");
        if !cookie.is_empty() {
            r = r.header("cookie", cookie)
        }
        if confirm {
            r = r.header("x-arrowhead-action", "confirm")
        }
        app.clone()
            .oneshot(r.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }
    async fn login(app: &Router) -> String {
        let r = request(
            app,
            "POST",
            "/api/session",
            "",
            false,
            json!({"password":"test-password"}),
        )
        .await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
        r.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }
    #[tokio::test]
    async fn embedded_ui_assets_do_not_need_external_files() {
        let (_temp, app) = app().await;
        for path in [
            "/",
            "/ui",
            "/app.js",
            "/assets/app.js",
            "/styles.css",
            "/assets/styles.css",
        ] {
            let r = request(&app, "GET", path, "", false, Value::Null).await;
            assert_eq!(r.status(), StatusCode::OK);
            assert!(!to_bytes(r.into_body(), 1 << 20).await.unwrap().is_empty())
        }
    }
    #[tokio::test]
    async fn console_login_session_logout() {
        let (_serial, _reset) = enter().await;
        let (_temp, app) = app().await;
        assert_eq!(
            request(&app, "GET", "/api/intercloud", "", false, Value::Null)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let cookie = login(&app).await;
        let r = request(&app, "GET", "/api/session", &cookie, false, Value::Null).await;
        let value: Value =
            serde_json::from_slice(&to_bytes(r.into_body(), 1 << 20).await.unwrap()).unwrap();
        assert_eq!(value["authenticated"], true);
        request(&app, "DELETE", "/api/session", &cookie, false, Value::Null).await;
        assert_eq!(
            request(&app, "GET", "/api/intercloud", &cookie, false, Value::Null)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        )
    }
    #[tokio::test]
    async fn missing_password_disables_console() {
        let (_serial, _reset) = enter().await;
        console().lock().unwrap().hash.clear();
        let (_temp, app) = app().await;
        assert_eq!(
            request(&app, "GET", "/api/session", "", false, Value::Null)
                .await
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        )
    }
    #[tokio::test]
    async fn invalid_host_and_origin_are_rejected() {
        let (_serial, _reset) = enter().await;
        let (_temp, app) = app().await;
        for (host, origin) in [
            ("attacker.invalid", "http://localhost"),
            ("localhost", "null"),
            ("localhost", "http://attacker.invalid"),
        ] {
            let r = Request::builder()
                .uri("/api/session")
                .header("host", host)
                .header("origin", origin)
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                app.clone().oneshot(r).await.unwrap().status(),
                StatusCode::FORBIDDEN
            )
        }
    }
    #[tokio::test]
    async fn mutation_confirmation_precedes_provider_effects() {
        let (_serial, _reset) = enter().await;
        let (_temp, app) = app().await;
        let cookie = login(&app).await;
        for (method, path) in [
            ("POST", "/api/orchestration/rules"),
            ("DELETE", "/api/orchestration/rules/1"),
            ("PUT", "/api/sysmonitor/subscriptions/Provider"),
            ("POST", "/api/plantdescriptions"),
            ("PATCH", "/api/plantdescriptions/1"),
            ("DELETE", "/api/plantdescriptions/1"),
            ("POST", "/api/containers/authentication/restart"),
        ] {
            assert_eq!(
                request(&app, method, path, &cookie, false, json!({}))
                    .await
                    .status(),
                StatusCode::PRECONDITION_REQUIRED,
                "{method} {path}"
            )
        }
    }
    #[tokio::test]
    async fn failed_passwords_lock_out() {
        let (_serial, _reset) = enter().await;
        for _ in 0..5 {
            assert_eq!(
                session_login(Json(json!({"password":"wrong"})))
                    .await
                    .status(),
                StatusCode::UNAUTHORIZED
            )
        }
        let r = session_login(Json(json!({"password":"test-password"}))).await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(r.headers()[header::RETRY_AFTER], "60")
    }
    #[tokio::test]
    async fn lifecycle_rejects_unsafe_action_and_target() {
        let mut headers = HeaderMap::new();
        headers.insert("x-arrowhead-action", "confirm".parse().unwrap());
        let e = lifecycle(
            headers.clone(),
            Path(("database".into(), "stop".into())),
            Bytes::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(e.0, StatusCode::FORBIDDEN);
        let e = lifecycle(
            headers,
            Path(("authentication".into(), "delete".into())),
            Bytes::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(e.0, StatusCode::BAD_REQUEST)
    }
    #[tokio::test]
    async fn inherited_subscription_ack_and_placeholder_are_visible() {
        let (_serial, _reset) = enter().await;
        let (_temp, app) = app().await;
        let cookie = login(&app).await;
        for method in ["PUT", "DELETE"] {
            let r = request(
                &app,
                method,
                "/api/sysmonitor/subscriptions/Provider",
                &cookie,
                true,
                json!({}),
            )
            .await;
            assert_eq!(r.status(), StatusCode::OK);
            let v: Value =
                serde_json::from_slice(&to_bytes(r.into_body(), 1 << 20).await.unwrap()).unwrap();
            assert_eq!(v["updated"], true)
        }
        assert_eq!(
            intercloud().await.unwrap().0["producer"]["status"],
            "unavailable"
        )
    }
    #[tokio::test]
    async fn unix_docker_client_uses_only_mock_socket() {
        let temp = Temp::new();
        let socket = temp.0.join("docker.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let worker = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = vec![0; 4096];
            let n = stream.read(&mut bytes).await.unwrap();
            let r = String::from_utf8_lossy(&bytes[..n]);
            assert!(r.starts_with("GET /isolated-test HTTP/1.1"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]")
                .await
                .unwrap()
        });
        assert_eq!(
            docker_request_at(socket.to_str().unwrap(), "GET", "/isolated-test")
                .await
                .unwrap(),
            b"[]"
        );
        worker.await.unwrap()
    }
    #[test]
    fn origin_ports_and_cookie_behavior_are_documented_not_hardened() {
        assert_eq!(host_name("localhost:8480"), host_name("localhost:8590"));
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            "other=x; ah_console=test-token".parse().unwrap(),
        );
        assert_eq!(cookie(&h, "ah_console"), Some("test-token".into()));
        assert_eq!(Method::GET.as_str(), "GET")
    }
    #[tokio::test]
    async fn legacy_declared_identity_remains_a_qualification_gap() {
        let (_temp, app) = app().await;
        let r = Request::builder()
            .uri("/localcloud/monitor/echo")
            .header("authorization", "Bearer SYSTEM//DeclaredClient")
            .body(Body::empty())
            .unwrap();
        let r = app.oneshot(r).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(to_bytes(r.into_body(), 1024).await.unwrap(), "Got it!")
    }
}

fn decode_chunked(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut rest = input;
    let mut out = vec![];
    loop {
        let end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("Invalid chunked response")?;
        let size = usize::from_str_radix(
            String::from_utf8_lossy(&rest[..end])
                .split(';')
                .next()
                .unwrap_or("0")
                .trim(),
            16,
        )
        .map_err(|e| e.to_string())?;
        rest = &rest[end + 2..];
        if size == 0 {
            break;
        }
        if rest.len() < size + 2 {
            return Err("Truncated chunked response".into());
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
    Ok(out)
}
fn demux_logs(input: &[u8]) -> String {
    let mut rest = input;
    let mut out = vec![];
    while rest.len() >= 8 {
        let size = u32::from_be_bytes([rest[4], rest[5], rest[6], rest[7]]) as usize;
        if rest.len() < 8 + size {
            break;
        }
        out.extend_from_slice(&rest[8..8 + size]);
        rest = &rest[8 + size..];
    }
    if out.is_empty() {
        String::from_utf8_lossy(input).replace('\0', "")
    } else {
        String::from_utf8_lossy(&out).replace('\0', "")
    }
}
fn percent_encode(input: &str) -> String {
    input
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chunked_decoder() {
        assert_eq!(
            decode_chunked(b"5\r\nhello\r\n0\r\n\r\n").unwrap(),
            b"hello"
        );
    }
    #[test]
    fn docker_log_demux() {
        let mut frame = vec![1, 0, 0, 0, 0, 0, 0, 6];
        frame.extend_from_slice(b"hello\n");
        assert_eq!(demux_logs(&frame), "hello\n");
    }
    #[test]
    fn dashboard_matches_java_navigation() {
        assert!(INDEX.contains("data-view=\"orchestration\""));
        assert!(INDEX.contains("data-view=\"registry\""));
    }
}

// Local-cloud management-policy editor. Provider-owned and remote policies are not writable here.
fn editor_text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}
fn editor_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b[0].is_ascii_alphabetic()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}
pub(crate) fn editor_local(v: &Value) -> bool {
    matches!(editor_text(v, "cloud"), "" | "LOCAL")
        && matches!(editor_text(v, "level"), "" | "MGMT")
}
fn editor_clean(v: &Value) -> Value {
    json!({"provider":v["provider"],"targetType":v["targetType"],"target":v["target"],"cloud":"LOCAL","description":v["description"].as_str().unwrap_or(""),"defaultPolicy":v["defaultPolicy"],"scopedPolicies":v["scopedPolicies"].as_object().cloned().unwrap_or_default()})
}
pub(crate) fn editor_validate(
    v: &Value,
    systems: &[Value],
    services: &[Value],
) -> Result<Value, (u16, String)> {
    let bad = |s: &str| Err((400, s.to_string()));
    if !v.is_object() || !editor_local(v) {
        return bad("Only local management policies can be edited");
    }
    let provider = editor_text(v, "provider");
    let target = editor_text(v, "target");
    let kind = editor_text(v, "targetType");
    if !editor_name(provider)
        || !editor_name(target)
        || !matches!(kind, "SERVICE_DEF" | "EVENT_TYPE")
    {
        return bad("Invalid local policy target");
    }
    if !systems.iter().any(|s| s["name"] == provider) {
        return Err((409, "Provider is not registered in this local cloud".into()));
    }
    if kind == "SERVICE_DEF"
        && !services
            .iter()
            .any(|s| s["provider"]["name"] == provider && s["serviceDefinition"]["name"] == target)
    {
        return Err((409, "Service is not registered for this provider".into()));
    }
    fn valid(p: &Value) -> bool {
        matches!(
            editor_text(p, "policyType"),
            "ALL" | "WHITELIST" | "BLACKLIST"
        ) && (p["policyList"].is_null()
            || p["policyList"].as_array().is_some_and(|a| {
                a.len() <= 500 && a.iter().all(|n| n.as_str().is_some_and(editor_name))
            }))
    }
    if !valid(&v["defaultPolicy"]) {
        return bad("Invalid default policy or local system list");
    }
    if !v["scopedPolicies"].is_null() && !v["scopedPolicies"].is_object() {
        return bad("Invalid operation scopes");
    }
    if let Some(scopes) = v["scopedPolicies"].as_object() {
        if scopes.len() > 100 {
            return bad("Too many scopes");
        };
        for (k, p) in scopes {
            if k.is_empty()
                || k.len() > 100
                || !k
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
                || !valid(p)
            {
                return bad("Invalid scoped policy");
            }
        }
    }
    if !v["description"].is_null()
        && (!v["description"].is_string() || editor_text(v, "description").len() > 1000)
    {
        return bad("Description must be at most 1000 characters");
    }
    Ok(editor_clean(v))
}
fn editor_encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"_.-".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
pub(crate) async fn editor_policy_execute<F, Fut>(
    method: &str,
    id: Option<&str>,
    body: Value,
    systems: Vec<Value>,
    services: Vec<Value>,
    mut call: F,
) -> Result<Value, (u16, String)>
where
    F: FnMut(String, String, Value) -> Fut,
    Fut: std::future::Future<Output = Result<Value, String>>,
{
    let all = call(
        "POST".into(),
        "/query".into(),
        json!({"pagination":{"page":0,"size":1000}}),
    )
    .await
    .map_err(|e| (502, e))?;
    let entries = all["entries"].as_array().cloned().unwrap_or_default();
    let rows = entries
        .iter()
        .filter(|p| editor_local(p))
        .cloned()
        .collect::<Vec<_>>();
    if method == "GET" && id.is_none() {
        return Ok(
            json!({"entries":rows,"readOnlyEntries":entries.iter().filter(|p|!editor_local(p)&&matches!(editor_text(p,"cloud"),""|"LOCAL")).collect::<Vec<_>>(),"collectedAt":now()}),
        );
    }
    let expected = &body["expected"];
    let policy = if method == "DELETE" {
        if expected.is_null() {
            return Err((428, "Expected policy snapshot required".into()));
        };
        rows.iter()
            .find(|p| p["instanceId"].as_str() == id)
            .cloned()
            .ok_or((404, "Local management policy not found".into()))?
    } else {
        editor_validate(&body["policy"], &systems, &services)?
    };
    if method == "DELETE" {
        if policy["instanceId"] != expected["instanceId"]
            || editor_clean(&policy) != editor_clean(expected)
        {
            return Err((409, "Policy changed; reload before deleting".into()));
        }
        let id = id.unwrap_or("");
        call(
            "DELETE".into(),
            format!("/revoke?instanceIds={}", editor_encode(id)),
            Value::Null,
        )
        .await
        .map_err(|e| (502, e))?;
        return Ok(json!({"removed":true,"id":id}));
    }
    let matches = rows
        .iter()
        .filter(|p| {
            p["provider"] == policy["provider"]
                && p["targetType"] == policy["targetType"]
                && p["target"] == policy["target"]
        })
        .collect::<Vec<_>>();
    if matches.len() > 1 {
        return Err((409, "Multiple policies share this target".into()));
    };
    let old = matches.first().copied();
    if expected.is_null() && old.is_some()
        || !expected.is_null()
            && old.is_none_or(|p| {
                p["instanceId"] != expected["instanceId"]
                    || editor_clean(p) != editor_clean(expected)
            })
    {
        return Err((409, "Policy changed; reload before saving".into()));
    }
    if method == "DELETE" {
        let id = id.unwrap_or("");
        call(
            "DELETE".into(),
            format!("/revoke?instanceIds={}", editor_encode(id)),
            Value::Null,
        )
        .await
        .map_err(|e| (502, e))?;
        return Ok(json!({"removed":true,"id":id}));
    }
    let result = call("POST".into(), "/grant".into(), json!({"list":[policy]}))
        .await
        .map_err(|e| (502, e))?;
    let created = result["entries"]
        .as_array()
        .and_then(|a| a.first())
        .cloned()
        .unwrap_or(result);
    let new_id = created["instanceId"].as_str().ok_or((
        502,
        "Authority did not return a policy identifier; reload before retrying".into(),
    ))?;
    if let Some(old) = old {
        let old_id = editor_text(old, "instanceId");
        if old_id != new_id
            && call(
                "DELETE".into(),
                format!("/revoke?instanceIds={}", editor_encode(old_id)),
                Value::Null,
            )
            .await
            .is_err()
        {
            let _ = call(
                "DELETE".into(),
                format!("/revoke?instanceIds={}", editor_encode(new_id)),
                Value::Null,
            )
            .await;
            return Err((
                502,
                "Policy replacement could not finish; reload before retrying".into(),
            ));
        }
    }
    Ok(created)
}
async fn editor_policies_get(State(state): State<App>) -> ManagerResult {
    editor_policies_request(&state, "GET", None, Value::Null).await
}
async fn editor_policies_post(
    State(state): State<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ManagerResult {
    if headers
        .get("x-arrowhead-action")
        .and_then(|v| v.to_str().ok())
        != Some("confirm")
    {
        return Err(failure(
            StatusCode::PRECONDITION_REQUIRED,
            "Missing action confirmation header",
        ));
    };
    editor_policies_request(&state, "POST", None, body).await
}
async fn editor_policies_delete(
    State(state): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> ManagerResult {
    if headers
        .get("x-arrowhead-action")
        .and_then(|v| v.to_str().ok())
        != Some("confirm")
    {
        return Err(failure(
            StatusCode::PRECONDITION_REQUIRED,
            "Missing action confirmation header",
        ));
    };
    editor_policies_request(&state, "DELETE", Some(&id), body).await
}
async fn editor_policies_request(
    state: &App,
    method: &str,
    id: Option<&str>,
    body: Value,
) -> ManagerResult {
    let systems = registry_query(state, "systems")
        .await
        .map_err(|e| failure(StatusCode::BAD_GATEWAY, e))?;
    let services = registry_query(state, "service-instances")
        .await
        .map_err(|e| failure(StatusCode::BAD_GATEWAY, e))?;
    let base = std::env::var("AUTHORIZATION_URL")
        .unwrap_or_else(|_| "http://consumerauthorization:8445".into());
    editor_policy_execute(
        method,
        id,
        body,
        array(&systems, "entries").to_vec(),
        array(&services, "entries").to_vec(),
        |m, p, b| {
            let base = base.clone();
            async move {
                arrowhead_json(
                    state,
                    reqwest::Method::from_bytes(m.as_bytes()).map_err(|e| e.to_string())?,
                    format!("{base}/consumerauthorization/mgmt{p}"),
                    if b.is_null() { None } else { Some(b) },
                )
                .await
            }
        },
    )
    .await
    .map(Json)
    .map_err(|(s, e)| {
        failure(
            StatusCode::from_u16(s).unwrap_or(StatusCode::BAD_GATEWAY),
            e,
        )
    })
}

pub(crate) fn editor_rule_priority(old: &Value, body: &Value) -> Result<u64, (u16, String)> {
    let priority = body["priority"]
        .as_u64()
        .filter(|p| *p > 0 && *p <= 2147483647)
        .ok_or((400, "Use a positive integer priority".into()))?;
    let expected = &body["expected"];
    if expected.is_null() {
        return Err((428, "Expected rule snapshot required".into()));
    }
    if old.is_null()
        || old["consumer"] != expected["consumer"]
        || old["serviceInstanceId"] != expected["serviceInstanceId"]
        || old["priority"] != expected["priority"]
    {
        return Err((409, "The rule changed; reload before saving".into()));
    }
    Ok(priority)
}
async fn editor_rule_priority_update(
    State(state): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> ManagerResult {
    if headers
        .get("x-arrowhead-action")
        .and_then(|v| v.to_str().ok())
        != Some("confirm")
    {
        return Err(failure(
            StatusCode::PRECONDITION_REQUIRED,
            "Missing action confirmation header",
        ));
    }
    let Json(current) = rules(State(state.clone())).await?;
    let old = array(&current, "rules")
        .iter()
        .find(|r| r["id"].as_str() == Some(id.as_str()))
        .cloned()
        .unwrap_or(Value::Null);
    let priority = editor_rule_priority(&old, &body).map_err(|(s, e)| {
        failure(
            StatusCode::from_u16(s).unwrap_or(StatusCode::BAD_REQUEST),
            e,
        )
    })?;
    let base = std::env::var("SIMPLE_ORCHESTRATION_URL")
        .unwrap_or_else(|_| "http://serviceorchestration-simple:8442".into());
    arrowhead_json(
        &state,
        reqwest::Method::PUT,
        format!("{base}/serviceorchestration/orchestration/mgmt/simple-store/modify-priorities"),
        Some(json!({"candidates":[{"id":id,"priority":priority}]})),
    )
    .await
    .map(Json)
    .map_err(|e| failure(StatusCode::BAD_GATEWAY, e))
}

#[cfg(test)]
mod graph_editor_tests {
    use super::*;
    fn policy() -> Value {
        json!({"provider":"Provider","targetType":"SERVICE_DEF","target":"temperature","cloud":"LOCAL","defaultPolicy":{"policyType":"WHITELIST","policyList":["Consumer"]},"scopedPolicies":{"read":{"policyType":"ALL","policyList":[]}}})
    }
    #[test]
    fn local_typed_policy_is_valid() {
        let systems = vec![json!({"name":"Provider"})];
        let services = vec![
            json!({"provider":{"name":"Provider"},"serviceDefinition":{"name":"temperature"}}),
        ];
        assert!(editor_validate(&policy(), &systems, &services).is_ok());
    }
    #[test]
    fn remote_provider_owned_and_invalid_lists_are_rejected() {
        let systems = vec![json!({"name":"Provider"})];
        let services = vec![
            json!({"provider":{"name":"Provider"},"serviceDefinition":{"name":"temperature"}}),
        ];
        for (key, value) in [
            ("cloud", json!("Other|Company")),
            ("level", json!("PROVIDER")),
            (
                "defaultPolicy",
                json!({"policyType":"WHITELIST","policyList":["Remote@Other"]}),
            ),
            ("scopedPolicies", json!({"bad/scope":{"policyType":"ALL"}})),
        ] {
            let mut row = policy();
            row[key] = value;
            assert!(editor_validate(&row, &systems, &services).is_err());
        }
    }
    #[test]
    fn priority_requires_matching_snapshot() {
        let old = json!({"consumer":"Consumer","serviceInstanceId":"Provider|temperature|1.0.0","priority":1});
        assert_eq!(
            editor_rule_priority(&old, &json!({"priority":2,"expected":old})).unwrap(),
            2
        );
        assert!(editor_rule_priority(&old, &json!({"priority":0,"expected":old})).is_err());
        assert!(editor_rule_priority(&old, &json!({"priority":2})).is_err());
        assert!(
            editor_rule_priority(&old, &json!({"priority":2,"expected":{"consumer":"Other"}}))
                .is_err()
        );
    }
}
