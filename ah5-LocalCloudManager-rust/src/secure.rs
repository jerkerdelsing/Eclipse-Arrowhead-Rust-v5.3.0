// SPDX-License-Identifier: EPL-2.0
//! Candidate-cloud manager. The legacy declared-identity router is never mounted.
use arrowhead_support_rust::{
    config::secret,
    security::{self, Remote, RemoteIdentity, Tls},
};
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use scrypt::{Params, scrypt};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, Semaphore, watch},
    task::JoinSet,
};

pub const SYSTEMS: &[(&str, &str)] = &[
    ("Authentication", "authentication"),
    ("ConsumerAuthorization", "consumer-authorization"),
    (
        "DynamicServiceOrchestration",
        "serviceorchestration-dynamic",
    ),
    (
        "SimpleStoreServiceOrchestration",
        "serviceorchestration-simple",
    ),
    ("ServiceRegistry", "serviceregistry"),
    ("AIGym", "aigym"),
    ("Blacklist", "blacklist"),
    ("CertificateAuthority", "certificateauthority"),
    ("Choreographer", "choreographer"),
    ("Configuration", "configuration"),
    ("DataManager", "datamanager"),
    ("DeviceQoSEvaluator", "deviceqosevaluator"),
    ("EventHandler", "eventhandler"),
    ("Gatekeeper", "gatekeeper"),
    ("GateTunnel", "gatetunnel"),
    ("Onboarding", "onboarding"),
    ("PlantDescriptionEngine", "plantdescriptionengine"),
    ("SysMonitor", "sysmonitor"),
    ("TimeManager", "timemanager"),
    ("TranslationManager", "translationmanager"),
    ("LocalCloudManager", "localcloudmanager"),
    ("RandomDataProducer", "random-data-producer"),
];

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub cloud_suffix: String,
    pub project: String,
    /// System API listening address; optional, defaults to `DEFAULT_LISTEN` (see `resolve_listen`).
    #[serde(default)]
    pub listen: String,
    pub console_listen: String,
    pub certificate: String,
    pub private_key: String,
    pub ca: String,
    #[serde(default)]
    pub crl_file: Option<String>,
    #[serde(default)]
    pub messaging: Option<arrowhead_messaging_rust::Config>,
    pub password_file: String,
    pub console_hash_file: String,
    pub console_origins: Vec<String>,
    /// Extra console clients besides loopback and the container's network gateways: IP addresses, CIDR ranges or DNS
    /// names (see `console_clients`). Optional; empty means loopback and gateways only.
    #[serde(default)]
    pub console_clients: Vec<String>,
    pub upstreams: BTreeMap<String, String>,
    pub docker_url: String,
    pub docker_token_file: String,
    pub advertise_address: String,
    pub advertise_port: u16,
}
/// Endpoint principles: built-in system API listening address (port 8480, as the Go LocalCloudManager).
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8480";
impl Config {
    /// Listening address of the system API, highest precedence first: `--server.port N` (`flag`), `SERVER_PORT=N`
    /// (`env`), `listen` in CONFIG.json, `DEFAULT_LISTEN`. Port overrides keep the configured host. The console
    /// listener (`consoleListen`) is configured separately.
    pub fn resolve_listen(&mut self, env: Option<&str>, flag: Option<u16>) -> Result<(), String> {
        let port = arrowhead_support_rust::listen::with_port;
        if self.listen.is_empty() {
            self.listen = DEFAULT_LISTEN.into();
        }
        if let Some(v) = env.map(str::trim).filter(|v| !v.is_empty()) {
            let p = arrowhead_support_rust::listen::parse_port(v)
                .map_err(|e| format!("SERVER_PORT: {}", e.message))?;
            self.listen = port(&self.listen, p).map_err(|e| e.message)?;
        }
        if let Some(p) = flag {
            self.listen = port(&self.listen, p).map_err(|e| e.message)?;
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<(), String> {
        if let Some(messaging) = &self.messaging {
            messaging.validate()?;
        }
        if self.cloud_suffix.split('.').count() != 4
            || !self.cloud_suffix.ends_with(".arrowhead.eu")
            || self.project.is_empty()
            || !self
                .project
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || self.advertise_port == 0
            || self.advertise_address.is_empty()
        {
            return Err("Invalid cloud/project/advertised identity".into());
        }
        for name in [
            "Authentication",
            "ServiceRegistry",
            "ConsumerAuthorization",
            "DataManager",
            "SysMonitor",
            "PlantDescriptionEngine",
            "SimpleStoreServiceOrchestration",
            "Gatekeeper",
            "GateTunnel",
        ] {
            if !self.upstreams.contains_key(name) {
                return Err(format!("Missing pinned upstream {name}"));
            }
        }
        for (name, origin) in &self.upstreams {
            if !arrowhead_support_rust::valid_name(name) || !bare_origin(origin, "https") {
                return Err("Upstreams must be named bare HTTPS origins".into());
            }
        }
        if self.console_origins.is_empty()
            || self
                .console_origins
                .iter()
                .any(|o| !bare_origin(o, "https"))
        {
            return Err("Explicit HTTPS console origins required".into());
        }
        crate::console_clients::ConsoleClients::new(&self.console_clients)?;
        if !bare_origin(&self.docker_url, "http") {
            return Err("Docker gateway requires explicit private HTTP origin".into());
        }
        self.listen
            .parse::<std::net::SocketAddr>()
            .map_err(|_| "Invalid API listen address")?;
        self.console_listen
            .parse::<std::net::SocketAddr>()
            .map_err(|_| "Invalid console listen address")?;
        Ok(())
    }
}
fn bare_origin(raw: &str, scheme: &str) -> bool {
    url::Url::parse(raw).is_ok_and(|u| {
        u.scheme() == scheme
            && u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
            && u.path() == "/"
            && u.query().is_none()
            && u.fragment().is_none()
    })
}
fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
fn rows(v: &Value) -> Vec<Value> {
    v["entries"]
        .as_array()
        .or_else(|| v["list"].as_array())
        .or_else(|| v["observations"].as_array())
        .cloned()
        .unwrap_or_default()
}
fn enc(s: &str) -> String {
    security::encode(s)
}
fn reply(code: u16, v: Value) -> Response {
    let status = StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY);
    if v.is_null() {
        status.into_response()
    } else {
        (status, Json(v)).into_response()
    }
}
type Failure = (u16, String);
fn bad(s: impl Into<String>) -> Failure {
    (400, s.into())
}
fn upstream(e: arrowhead_support_rust::Error) -> Failure {
    (e.code, e.message)
}

struct Sessions {
    sessions: HashMap<String, Instant>,
    failures: Vec<Instant>,
    locked_until: Option<Instant>,
}
#[derive(Clone)]
pub struct Manager {
    pub config: Arc<Config>,
    remote: Arc<Remote>,
    sessions: Arc<Mutex<Sessions>>,
    hash: Arc<(Vec<u8>, Vec<u8>)>,
    workers: Arc<Semaphore>,
    cookie: String,
    docker: reqwest::Client,
    docker_token: String,
    history: Arc<Mutex<Vec<Value>>>,
}
impl Manager {
    pub fn new(config: Config, tls: Tls) -> Result<Self, Box<dyn std::error::Error>> {
        config.validate()?;
        let raw = String::from_utf8(secret(&config.console_hash_file)?)?;
        let p = raw.trim().split(':').collect::<Vec<_>>();
        if p.len() != 3 || p[0] != "scrypt" {
            return Err("Invalid console hash file".into());
        }
        let salt = STANDARD.decode(p[1])?;
        let hash = STANDARD.decode(p[2])?;
        if salt.len() < 16 || hash.len() != 32 {
            return Err("Invalid console hash dimensions".into());
        }
        let remote = Remote::from_identity(
            RemoteIdentity {
                name: "LocalCloudManager".into(),
                cloud_suffix: config.cloud_suffix.clone(),
                password_file: config.password_file.clone(),
                authentication_url: config.upstreams["Authentication"].clone(),
                registry_url: config.upstreams["ServiceRegistry"].clone(),
                authorization_url: config.upstreams["ConsumerAuthorization"].clone(),
                upstreams: config.upstreams.clone(),
            },
            tls,
        );
        let docker_token = String::from_utf8(secret(&config.docker_token_file)?)?
            .trim()
            .to_owned();
        if docker_token.len() < 32 {
            return Err("Short Docker gateway token".into());
        }
        Ok(Self {
            cookie: format!("__Host-ah_lcm_{}", config.project),
            config: Arc::new(config),
            remote: Arc::new(remote),
            sessions: Arc::new(Mutex::new(Sessions {
                sessions: HashMap::new(),
                failures: vec![],
                locked_until: None,
            })),
            hash: Arc::new((salt, hash)),
            workers: Arc::new(Semaphore::new(2)),
            docker: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(8))
                .build()?,
            docker_token,
            history: Arc::new(Mutex::new(vec![])),
        })
    }
    async fn call(
        &self,
        provider: &str,
        method: &str,
        path: &str,
        body: Value,
    ) -> Result<Value, Failure> {
        self.remote
            .call(provider, method, path, &body)
            .await
            .map_err(upstream)
    }
    async fn query(&self, resource: &str) -> Result<Vec<Value>, Failure> {
        let v = self
            .call(
                "ServiceRegistry",
                "POST",
                &format!("/serviceregistry/mgmt/{resource}/query"),
                json!({"pagination":{"size":1000}}),
            )
            .await?;
        let list = rows(&v);
        if v["count"].as_u64().unwrap_or(0) > list.len() as u64 {
            return Err((
                502,
                "Registry result exceeds console inventory limit; refine via system API".into(),
            ));
        }
        Ok(list)
    }
    async fn docker(&self, method: &str, path: &str) -> Result<Value, Failure> {
        let mut response = self
            .docker
            .request(
                method
                    .parse::<reqwest::Method>()
                    .map_err(|_| bad("Invalid gateway method"))?,
                format!("{}{}", self.config.docker_url.trim_end_matches('/'), path),
            )
            .bearer_auth(&self.docker_token)
            .send()
            .await
            .map_err(|_| (502, "Docker gateway unavailable".into()))?;
        let code = response.status().as_u16();
        let mut bytes = vec![];
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| (502, "Invalid gateway response".into()))?
        {
            if bytes.len() + chunk.len() > 8 * 1024 * 1024 {
                return Err((502, "Gateway response too large".into()));
            }
            bytes.extend_from_slice(&chunk)
        }
        if !(200..300).contains(&code) {
            return Err((code, "Docker gateway rejected request".into()));
        }
        serde_json::from_slice(&bytes).map_err(|_| (502, "Invalid gateway JSON".into()))
    }
    async fn containers(&self) -> Result<Vec<Value>, Failure> {
        let list = self.docker("GET", "/containers").await?;
        Ok(list.as_array().cloned().unwrap_or_default())
    }
}

fn cookie_token<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|p| {
            let (k, v) = p.trim().split_once('=')?;
            (k == name).then_some(v)
        })
}
fn same_origin(config: &Config, headers: &axum::http::HeaderMap) -> bool {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let host_ok = config.console_origins.iter().any(|o| {
        url::Url::parse(o)
            .is_ok_and(|u| u[url::Position::BeforeHost..url::Position::AfterPort] == *host)
    });
    let origin_ok = headers
        .get(header::ORIGIN)
        .map(|h| {
            h.to_str().is_ok_and(|s| {
                config
                    .console_origins
                    .iter()
                    .any(|o| o.trim_end_matches('/') == s)
            })
        })
        .unwrap_or(true);
    host_ok && origin_ok
}
async fn guard(State(m): State<Manager>, req: Request, next: Next) -> Response {
    if !req.uri().path().starts_with("/api/") {
        return next.run(req).await;
    }
    if !same_origin(&m.config, req.headers()) {
        return reply(
            403,
            json!({"error":"Host/Origin must match the exact console origin"}),
        );
    }
    if req.uri().path() != "/api/session" {
        let token = cookie_token(req.headers(), &m.cookie).unwrap_or("");
        let mut sessions = m.sessions.lock().await;
        let at = Instant::now();
        sessions.sessions.retain(|_, t| *t > at);
        if !sessions.sessions.contains_key(token) {
            return reply(401, json!({"error":"Console login required"}));
        }
    }
    next.run(req).await
}
async fn headers(req: Request, next: Next) -> Response {
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    for (k, v) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        (
            "content-security-policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    ] {
        h.insert(k, v.parse().unwrap());
    }
    r
}

pub fn console_router(m: Manager) -> Router {
    Router::new()
        .route(
            "/api/session",
            get(session_get).post(session_post).delete(session_delete),
        )
        .route(
            "/",
            get(|| async { axum::response::Html(include_str!("ui/index.html")) }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [("content-type", "text/javascript")],
                    include_str!("ui/app.js"),
                )
            }),
        )
        .route(
            "/styles.css",
            get(|| async {
                (
                    [("content-type", "text/css")],
                    include_str!("ui/styles.css"),
                )
            }),
        )
        .route("/health", get(|| async { "OK" }))
        .fallback(console_dispatch)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn_with_state(m.clone(), guard))
        .layer(middleware::from_fn(headers))
        .with_state(m)
}
async fn session_get(State(m): State<Manager>, headers: axum::http::HeaderMap) -> Json<Value> {
    let token = cookie_token(&headers, &m.cookie).unwrap_or("");
    Json(
        json!({"authenticated":m.sessions.lock().await.sessions.get(token).is_some_and(|t|*t>Instant::now()),"configured":true}),
    )
}
async fn session_post(State(m): State<Manager>, Json(body): Json<Value>) -> Response {
    let password = body["password"].as_str().unwrap_or("").to_owned();
    if password.is_empty() || password.len() > 256 {
        return reply(401, json!({"error":"Wrong password"}));
    }
    {
        let sessions = m.sessions.lock().await;
        if sessions.locked_until.is_some_and(|t| t > Instant::now()) {
            return reply(429, json!({"error":"Console login temporarily locked"}));
        }
    }
    let Ok(permit) = m.workers.clone().try_acquire_owned() else {
        return reply(429, json!({"error":"Login capacity reached"}));
    };
    let hash = m.hash.clone();
    let valid = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut got = vec![0; 32];
        scrypt(
            password.as_bytes(),
            &hash.0,
            &Params::new(14, 8, 1, 32).unwrap(),
            &mut got,
        )
        .is_ok()
            && got.iter().zip(&hash.1).fold(0, |d, (a, b)| d | (a ^ b)) == 0
    })
    .await
    .unwrap_or(false);
    let mut sessions = m.sessions.lock().await;
    let at = Instant::now();
    if !valid {
        sessions
            .failures
            .retain(|t| at.duration_since(*t) < Duration::from_secs(300));
        sessions.failures.push(at);
        if sessions.failures.len() >= 5 {
            sessions.locked_until = Some(at + Duration::from_secs(60));
            sessions.failures.clear()
        }
        return reply(401, json!({"error":"Wrong password"}));
    }
    sessions.sessions.retain(|_, t| *t > at);
    if sessions.sessions.len() >= 128 {
        return reply(429, json!({"error":"Session capacity reached"}));
    }
    sessions.failures.clear();
    let token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    sessions
        .sessions
        .insert(token.clone(), at + Duration::from_secs(3600));
    (
        StatusCode::NO_CONTENT,
        [(
            header::SET_COOKIE,
            format!(
                "{}={token}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600",
                m.cookie
            ),
        )],
    )
        .into_response()
}
async fn session_delete(State(m): State<Manager>, headers: axum::http::HeaderMap) -> Response {
    if let Some(token) = cookie_token(&headers, &m.cookie) {
        m.sessions.lock().await.sessions.remove(token);
    }
    (
        [(
            header::SET_COOKIE,
            format!(
                "{}=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
                m.cookie
            ),
        )],
        Json(json!({"authenticated":false})),
    )
        .into_response()
}

async fn console_dispatch(State(m): State<Manager>, req: Request) -> Response {
    let method = req.method().as_str().to_owned();
    let path = req.uri().path().to_owned();
    let headers = req.headers().clone();
    let q: HashMap<String, String> =
        url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
            .into_owned()
            .collect();
    let result = async {
        if method != "GET"
            && headers
                .get("x-arrowhead-action")
                .and_then(|v| v.to_str().ok())
                != Some("confirm")
        {
            return Err((428, "Explicit action confirmation required".into()));
        }
        let bytes = axum::body::to_bytes(req.into_body(), 1024 * 1024)
            .await
            .map_err(|_| (413, "Request body too large".into()))?;
        let body = if bytes.is_empty() {
            json!({})
        } else {
            serde_json::from_slice::<Value>(&bytes).map_err(|_| bad("Invalid JSON"))?
        };
        dispatch(&m, &method, &path, &q, &headers, body).await
    }
    .await;
    match result {
        Ok((status, v)) => reply(status, v),
        Err((code, message)) => reply(code, json!({"error":message,"errorCode":code})),
    }
}
async fn overview(m: &Manager) -> Result<Value, Failure> {
    let (systems, services, devices, containers) = tokio::join!(
        m.query("systems"),
        m.query("service-instances"),
        m.query("devices"),
        m.containers()
    );
    let registry_error = systems
        .as_ref()
        .err()
        .or(services.as_ref().err())
        .or(devices.as_ref().err())
        .map(|e| e.1.clone());
    let docker_error = containers.as_ref().err().map(|e| e.1.clone());
    let containers = containers.unwrap_or_default();
    let services = services.unwrap_or_default();
    let devices = devices.unwrap_or_default();
    let mut systems = systems.unwrap_or_default();
    for s in &mut systems {
        let name = s["name"].as_str().unwrap_or("");
        let role = SYSTEMS.iter().find(|v| v.0 == name).map(|v| v.1);
        let runtime = containers
            .iter()
            .find(|c| c["service"].as_str() == role)
            .cloned()
            .unwrap_or(Value::Null);
        let count = services
            .iter()
            .filter(|v| v["provider"]["name"] == s["name"])
            .count();
        s["composeService"] = json!(role);
        s["runtime"] = runtime;
        s["serviceCount"] = json!(count);
    }
    let registered = services.iter().any(|s| {
        s["provider"]["name"] == "LocalCloudManager"
            && s["serviceDefinition"]["name"] == "localCloudManagement"
    });
    let sample = json!({"at":now(),"running":containers.iter().filter(|c|c["state"]=="running").count(),"containers":containers.len(),"registeredSystems":systems.len(),"registeredServices":services.len(),"unhealthy":containers.iter().filter(|c|c["health"]=="unhealthy").count(),"incidents":if registry_error.is_some()||docker_error.is_some(){1}else{0},"unregisteredServices":[]});
    let mut history = m.history.lock().await;
    history.push(sample.clone());
    if history.len() > 60 {
        history.remove(0);
    }
    Ok(
        json!({"collectedAt":now(),"cloud":{"name":m.config.project,"release":"5.4.0","implementation":"rust","registryReachable":registry_error.is_none(),"dockerReachable":docker_error.is_none()},"summary":sample,"registryManagement":crate::localcloudmanager::build_registry_management(&systems,&services,&containers),"systems":systems,"services":services,"devices":devices,"containers":containers,"history":*history,"registration":{"registered":registered,"instanceId":"LocalCloudManager|localCloudManagement|1.0.0","error":registry_error,"checkedAt":now()},"errors":{"arrowhead":registry_error,"docker":docker_error},"naming":{"valid":null,"violations":[],"status":"not-evaluated"},"infrastructure":[],"orchestrations":[]}),
    )
}
fn route_segment(path: &str, prefix: &str) -> Result<String, Failure> {
    let raw = path
        .strip_prefix(prefix)
        .ok_or_else(|| bad("Invalid route"))?;
    let decoded = url::form_urlencoded::parse(format!("v={raw}").as_bytes())
        .next()
        .map(|v| v.1.into_owned())
        .unwrap_or_default();
    if decoded.is_empty() || decoded.contains(['/', '\\', '\r', '\n', '\0']) {
        return Err(bad("Invalid path parameter"));
    }
    Ok(decoded)
}

async fn dispatch(
    m: &Manager,
    method: &str,
    path: &str,
    q: &HashMap<String, String>,
    headers: &axum::http::HeaderMap,
    body: Value,
) -> Result<(u16, Value), Failure> {
    if path == "/api/orchestration/policies" || path.starts_with("/api/orchestration/policies/") {
        let id = if path == "/api/orchestration/policies" {
            None
        } else {
            Some(route_segment(path, "/api/orchestration/policies/")?)
        };
        if !matches!(method, "GET" | "POST" | "DELETE")
            || method == "GET" && id.is_some()
            || method == "POST" && id.is_some()
            || method == "DELETE" && id.is_none()
        {
            return Err((405, "Method not allowed".into()));
        }
        if method != "GET"
            && headers
                .get("x-arrowhead-action")
                .and_then(|v| v.to_str().ok())
                != Some("confirm")
        {
            return Err((428, "Missing action confirmation header".into()));
        }
        let systems = m.query("systems").await?;
        let services = m.query("service-instances").await?;
        let result = crate::localcloudmanager::editor_policy_execute(
            method,
            id.as_deref(),
            body,
            systems,
            services,
            |verb, suffix, value| async move {
                m.call(
                    "ConsumerAuthorization",
                    &verb,
                    &format!("/consumerauthorization/authorization/mgmt{suffix}"),
                    value,
                )
                .await
                .map_err(|(_, e)| e)
            },
        )
        .await?;
        return Ok((200, result));
    }
    let val = match (method, path) {
        ("GET", "/api/overview") => overview(m).await?,
        ("GET", "/api/service-registry-management") => {
            let o = overview(m).await?;
            json!({"collectedAt":now(),"cloud":o["cloud"],"devices":o["registryManagement"]["devices"],"runtimeOnly":o["registryManagement"]["runtimeOnly"],"summary":o["registryManagement"]["summary"],"errors":o["errors"]})
        }
        ("GET", "/api/orchestration/rules") => {
            let systems = m.query("systems").await?;
            let services = m.query("service-instances").await?;
            let rules = m
                .call(
                    "SimpleStoreServiceOrchestration",
                    "POST",
                    "/serviceorchestration/orchestration/mgmt/simple-store/query",
                    json!({}),
                )
                .await?;
            let mut catalog = crate::localcloudmanager::orchestration_catalog(&systems, &services);
            for p in catalog["producers"].as_array_mut().unwrap() {
                p["compatibleConsumers"] = json!(
                    systems
                        .iter()
                        .filter_map(|s| s["name"].as_str())
                        .filter(|n| Some(*n) != p["provider"].as_str())
                        .collect::<Vec<_>>()
                );
            }
            let history = m
                .call(
                    "DynamicServiceOrchestration",
                    "POST",
                    "/serviceorchestration/orchestration/mgmt/history/query",
                    json!({"pagination":{"size":500,"direction":"DESC","sortField":"createdAt"}}),
                )
                .await?;
            let dynamic=rows(&history).iter().map(|j|json!({"consumer":j["requesterSystem"],"serviceDefinition":j["serviceDefinition"],"kind":j["type"],"count":1,"lastAt":j["finishedAt"],"lastStatus":j["status"],"lastMessage":j["message"].as_str().unwrap_or("Candidate history does not retain selected provider details"),"providers":[]})).collect::<Vec<_>>();
            json!({"catalog":catalog,"rules":rules["entries"],"count":rules["count"],"dynamic":dynamic,"dynamicError":null,"collectedAt":now(),"qualification":"Candidates do not establish provider authorization or client interface compatibility"})
        }
        ("POST", "/api/orchestration/rules") => {
            let result = m
                .call(
                    "SimpleStoreServiceOrchestration",
                    "POST",
                    "/serviceorchestration/orchestration/mgmt/simple-store/create",
                    json!({"candidates":[body]}),
                )
                .await?;
            return Ok((200, result));
        }
        ("GET", "/api/plantdescriptions") => {
            let systems = m.query("systems").await?;
            let services = m.query("service-instances").await?;
            let result = m
                .call(
                    "PlantDescriptionEngine",
                    "GET",
                    "/plantdescriptionengine/mgmt/plant-descriptions",
                    Value::Null,
                )
                .await?;
            json!({"collectedAt":now(),"entries":rows(&result),"systems":systems.iter().map(|s|s["name"].clone()).collect::<Vec<_>>(),"services":services.iter().map(|s|json!({"provider":s["provider"]["name"],"serviceDefinition":s["serviceDefinition"]["name"],"interfaces":s["interfaces"].as_array().unwrap_or(&vec![]).iter().map(|i|i["templateName"].clone()).collect::<Vec<_>>()})).collect::<Vec<_>>(),"registryError":null})
        }
        ("POST", "/api/plantdescriptions") => {
            return Ok((
                201,
                m.call(
                    "PlantDescriptionEngine",
                    "POST",
                    "/plantdescriptionengine/mgmt/plant-descriptions",
                    body,
                )
                .await?,
            ));
        }
        ("GET", "/api/sysmonitor/subscriptions") => {
            let v = m
                .call(
                    "SysMonitor",
                    "GET",
                    "/sysmonitor/management/subscriptions",
                    Value::Null,
                )
                .await?;
            let status = m
                .call(
                    "SysMonitor",
                    "GET",
                    "/sysmonitor/management/status",
                    Value::Null,
                )
                .await?;
            let actual = m
                .call(
                    "SysMonitor",
                    "GET",
                    "/sysmonitor/management/providers",
                    Value::Null,
                )
                .await?;
            json!({"collectedAt":now(),"defaultSubscription":v["defaultSubscription"],"providers":rows(&actual),"subscriptions":rows(&v),"intake":status["amqp"],"status":status})
        }
        ("GET", "/api/sysmonitor") => sysmonitor(m, q).await?,
        ("GET", "/api/datamanager") => historian(m, q).await?,
        ("GET", "/api/consumers") => {
            let services = m.query("service-instances").await?;
            let policies = m
                .call(
                    "ConsumerAuthorization",
                    "POST",
                    "/consumerauthorization/authorization/mgmt/query",
                    json!({}),
                )
                .await?;
            let stored = m
                .call(
                    "SimpleStoreServiceOrchestration",
                    "POST",
                    "/serviceorchestration/orchestration/mgmt/simple-store/query",
                    json!({}),
                )
                .await?;
            let plant = m
                .call(
                    "DynamicServiceOrchestration",
                    "POST",
                    "/serviceorchestration/mgmt/plant-rules/query",
                    json!({}),
                )
                .await?;
            json!({"collectedAt":now(),"localCloud":m.config.cloud_suffix,"errors":[],"policies":policies,"plantRules":plant["rules"],"rows":services.iter().map(|s|json!({"provider":s["provider"]["name"],"serviceDefinition":s["serviceDefinition"]["name"],"providerCloud":m.config.cloud_suffix,"authorized":rows(&policies).iter().filter(|p|p["provider"]==s["provider"]["name"]&&p["target"]==s["serviceDefinition"]["name"]).map(|p|json!({"consumerCloud":m.config.cloud_suffix,"consumers":p["defaultPolicy"].to_string(),"scoped":[]})).collect::<Vec<_>>(),"orchestrated":rows(&stored).iter().filter(|r|r["serviceInstanceId"]==s["instanceId"]).cloned().collect::<Vec<_>>()})).collect::<Vec<_>>()})
        }
        ("GET", "/api/intercloud") => {
            let neighbours = m
                .call("Gatekeeper", "GET", "/gatekeeper/mgmt/clouds", Value::Null)
                .await?;
            let gatekeeper = m
                .call("Gatekeeper", "GET", "/gatekeeper/mgmt/status", Value::Null)
                .await?;
            let tunnel = m
                .call("GateTunnel", "GET", "/gatetunnel/mgmt/status", Value::Null)
                .await?;
            let producer = m
                .call(
                    "RandomDataProducer",
                    "GET",
                    "/random-data-producer/latest",
                    Value::Null,
                )
                .await
                .ok();
            json!({"collectedAt":now(),"localCloud":m.config.cloud_suffix,"neighbourClouds":rows(&neighbours),"neighbourError":null,"relay":{"gatekeeper":gatekeeper["relay"],"gatetunnel":tunnel["relay"]},"sessions":tunnel["interCloud"],"producer":producer.map(|v|v["interCloud"].clone()).unwrap_or_else(||json!({"status":"unavailable","lastError":"Producer endpoint unavailable"})),"capabilityAvailable":gatekeeper["relay"]["configured"]==true&&tunnel["relay"]["configured"]==true})
        }
        ("GET", "/api/logs") => {
            let role = q.get("service").ok_or_else(|| bad("Service required"))?;
            m.docker("GET", &format!("/logs/{}", enc(role))).await?
        }
        _ => {
            if path.starts_with("/api/sysmonitor/subscriptions/")
                && ["PUT", "DELETE"].contains(&method)
            {
                let provider = route_segment(path, "/api/sysmonitor/subscriptions/")?;
                let current = m
                    .call(
                        "SysMonitor",
                        "GET",
                        "/sysmonitor/management/subscriptions",
                        Value::Null,
                    )
                    .await?;
                let revision = rows(&current)
                    .iter()
                    .find(|r| r["providerSystem"] == provider)
                    .and_then(|r| r["revision"].as_u64())
                    .unwrap_or(0);
                let expected = headers
                    .get("if-match")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("\"{revision}\""));
                let result = if revision == 0 && !headers.contains_key("if-match") {
                    m.call(
                        "SysMonitor",
                        method,
                        &format!("/sysmonitor/management/subscriptions/{}", enc(&provider)),
                        body,
                    )
                    .await?
                } else {
                    call_revision(
                        m,
                        method,
                        &format!("/sysmonitor/management/subscriptions/{}", enc(&provider)),
                        body,
                        &expected,
                    )
                    .await?
                };
                return Ok((200, result));
            } else if path.starts_with("/api/plantdescriptions/")
                && ["PUT", "PATCH", "DELETE"].contains(&method)
            {
                let id = route_segment(path, "/api/plantdescriptions/")?;
                id.parse::<u64>()
                    .map_err(|_| bad("Numeric plant id required"))?;
                return Ok((
                    200,
                    m.call(
                        "PlantDescriptionEngine",
                        method,
                        &format!("/plantdescriptionengine/mgmt/plant-descriptions/{id}"),
                        body,
                    )
                    .await?,
                ));
            } else if path.starts_with("/api/orchestration/rules/") && method == "PUT" {
                let id = route_segment(path, "/api/orchestration/rules/")?;
                let stored = m
                    .call(
                        "SimpleStoreServiceOrchestration",
                        "POST",
                        "/serviceorchestration/orchestration/mgmt/simple-store/query",
                        json!({}),
                    )
                    .await?;
                let old = rows(&stored)
                    .into_iter()
                    .find(|r| r["id"].as_str() == Some(id.as_str()))
                    .unwrap_or(Value::Null);
                let priority = crate::localcloudmanager::editor_rule_priority(&old, &body)?;
                let mut changes = serde_json::Map::new();
                changes.insert(id, priority.into());
                return Ok((
                    200,
                    m.call(
                        "SimpleStoreServiceOrchestration",
                        "PUT",
                        "/serviceorchestration/orchestration/mgmt/simple-store/modify-priorities",
                        Value::Object(changes),
                    )
                    .await?,
                ));
            } else if path.starts_with("/api/orchestration/rules/") && method == "DELETE" {
                let id = route_segment(path, "/api/orchestration/rules/")?;
                m.call(
                    "SimpleStoreServiceOrchestration",
                    "DELETE",
                    &format!(
                        "/serviceorchestration/orchestration/mgmt/simple-store/remove?uuids={}",
                        enc(&id)
                    ),
                    Value::Null,
                )
                .await?;
                json!({"removed":true,"id":id})
            } else if path.starts_with("/api/containers/") && method == "POST" {
                let parts = path
                    .trim_start_matches("/api/containers/")
                    .split('/')
                    .collect::<Vec<_>>();
                if parts.len() != 2
                    || !SYSTEMS.iter().any(|(_, r)| *r == parts[0])
                    || !["start", "stop", "restart"].contains(&parts[1])
                {
                    return Err(bad("Unsupported lifecycle target/action"));
                }
                m.docker("POST", &format!("/containers/{}/{}", parts[0], parts[1]))
                    .await?
            } else {
                return Err((404, "No such manager operation".into()));
            }
        }
    };
    Ok((200, val))
}

async fn call_revision(
    m: &Manager,
    method: &str,
    path: &str,
    body: Value,
    revision: &str,
) -> Result<Value, Failure> {
    // Reuse the same pinned, certificate-bound transport including token refresh and bounds.
    m.remote
        .call_with_headers("SysMonitor", method, path, &body, &[("If-Match", revision)])
        .await
        .map_err(upstream)
}
async fn sysmonitor(m: &Manager, q: &HashMap<String, String>) -> Result<Value, Failure> {
    let list = m
        .call(
            "SysMonitor",
            "GET",
            "/sysmonitor/history/systems",
            Value::Null,
        )
        .await?;
    let names = list["systems"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|v| {
            if v.is_string() {
                v.clone()
            } else {
                v["systemName"].clone()
            }
        })
        .collect::<Vec<_>>();
    let selected = selected_system(&names, q.get("system").map(String::as_str));
    let mut systems = vec![];
    let mut observations = vec![];
    for name in names.iter().filter_map(Value::as_str) {
        let data = m
            .call(
                "SysMonitor",
                "GET",
                &format!(
                    "/sysmonitor/history/systems/{}/observations?count=1000",
                    enc(name)
                ),
                Value::Null,
            )
            .await?;
        let entries = rows(&data);
        let mut latest = BTreeMap::new();
        for obs in entries.iter().rev() {
            latest.insert(
                obs["observationType"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_owned(),
                obs.clone(),
            );
        }
        if name == selected {
            observations = entries.clone()
        }
        systems.push(json!({"systemName":name,"observationCount":entries.len(),"lastObservationTime":entries.first().map(|o|o["sourceTime"].clone()),"latest":latest}));
    }
    Ok(
        json!({"collectedAt":now(),"retentionDays":list["retentionDays"],"storedObservations":systems.iter().filter_map(|s|s["observationCount"].as_u64()).sum::<u64>(),"systems":systems,"selectedSystem":selected,"observations":observations}),
    )
}
fn selected_system(names: &[Value], requested: Option<&str>) -> String {
    requested
        .filter(|s| !s.is_empty() && names.iter().any(|n| n.as_str() == Some(*s)))
        .or_else(|| names.first().and_then(Value::as_str))
        .unwrap_or("")
        .to_owned()
}
async fn historian(m: &Manager, q: &HashMap<String, String>) -> Result<Value, Failure> {
    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(240)
        .clamp(1, 1000);
    let systems = m
        .call(
            "DataManager",
            "GET",
            "/datamanager/data-historian/systems",
            Value::Null,
        )
        .await?;
    let names: Vec<String> = systems["systems"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    // DataManager calls are orchestrated one by one; fetch them a few at a time
    // (each opens its own pinned TLS connection) and restore the order afterwards.
    let slots = Arc::new(Semaphore::new(4));
    let mut listing = JoinSet::new();
    for (i, name) in names.into_iter().enumerate() {
        let m = m.clone();
        let slots = slots.clone();
        listing.spawn(async move {
            let _slot = slots.acquire_owned().await;
            let path = format!(
                "/datamanager/data-historian/systems/{}/services",
                enc(&name)
            );
            (
                i,
                name,
                m.call("DataManager", "GET", &path, Value::Null).await,
            )
        });
    }
    let mut services = vec![];
    while let Some(joined) = listing.join_next().await {
        let (i, name, listed) = joined.map_err(|_| (500, "Historian task failed".to_owned()))?;
        for service in listed?["services"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            services.push((i, name.clone(), service.to_owned()));
        }
    }
    if services.len() > 32 {
        return Err((503, "Console historian fan-out limit exceeded".into()));
    }
    services.sort_by_key(|(i, _, _)| *i);
    let mut fetching = JoinSet::new();
    for (j, (_, name, service)) in services.into_iter().enumerate() {
        let m = m.clone();
        let slots = slots.clone();
        fetching.spawn(async move {
            let _slot = slots.acquire_owned().await;
            let path = format!(
                "/datamanager/data-historian/systems/{}/services/{}/data?count={limit}",
                enc(&name),
                enc(&service)
            );
            (
                j,
                name,
                service,
                m.call("DataManager", "GET", &path, Value::Null).await,
            )
        });
    }
    let mut packs = vec![];
    while let Some(joined) = fetching.join_next().await {
        let (j, name, service, pack) =
            joined.map_err(|_| (500, "Historian task failed".to_owned()))?;
        packs.push((j, name, service, pack?));
    }
    packs.sort_by_key(|(j, _, _, _)| *j);
    let mut entries = vec![];
    let mut series: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for (_, name, service, pack) in packs {
        {
            let mut bn = String::new();
            let mut bt = 0.;
            for record in pack.as_array().into_iter().flatten() {
                if let Some(n) = record["bn"].as_str() {
                    bn = n.into()
                }
                if let Some(t) = record["bt"].as_f64() {
                    bt = t
                }
                let signal = format!("{bn}{}", record["n"].as_str().unwrap_or("measurement"));
                let time = bt + record["t"].as_f64().unwrap_or(0.);
                if let Some(value) = record["v"].as_f64() {
                    series
                        .entry(format!("{name}/{service}/{signal}"))
                        .or_default()
                        .push(json!({"time":time,"value":value,"unit":record["u"]}));
                }
                entries.push(json!({"name":signal,"systemName":name,"serviceName":service,"time":time,"unit":record["u"],"value":{"v":record["v"],"vs":record["vs"],"vb":record["vb"]}}));
            }
        }
    }
    entries.reverse();
    entries.truncate(limit);
    Ok(
        json!({"collectedAt":now(),"count":entries.len(),"entries":entries,"latest":[],"series":series.into_iter().map(|(name,points)|json!({"name":name,"points":points})).collect::<Vec<_>>()}),
    )
}

async fn system_dispatch(
    State(m): State<Manager>,
    Extension(peer): Extension<arrowhead_support_rust::Principal>,
    req: Request,
) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    drop(req);
    let result = async {
        if method != "GET" {
            return Err((405, "Read-only system interface".into()));
        }
        if path == "/localcloud/monitor/echo" {
            return Ok((StatusCode::OK, "Got it!").into_response());
        }
        let token = auth
            .strip_prefix("Bearer IDENTITY-TOKEN//")
            .filter(|t| !t.is_empty() && t.len() < 4096 && !t.contains(['/', '?', '#', '\r', '\n']))
            .ok_or((401, "Identity token required".into()))?;
        let verified = m
            .call(
                "Authentication",
                "GET",
                &format!("/authentication/identity/verify/{}", enc(token)),
                Value::Null,
            )
            .await?;
        if verified["verified"] != true || verified["systemName"] != peer.name {
            return Err((401, "Token/certificate mismatch".into()));
        }
        if verified["sysop"] != true {
            return Err((403, "Sysop required".into()));
        }
        match path.as_str() {
            "/localcloud/management/status" => Ok(reply(200, overview(&m).await?)),
            "/localcloud/management/systems" => {
                Ok(reply(200, json!({"entries":m.query("systems").await?})))
            }
            "/localcloud/management/services" => Ok(reply(
                200,
                json!({"entries":m.query("service-instances").await?}),
            )),
            _ => Err((404, "Unknown manager system interface".into())),
        }
    }
    .await;
    result.unwrap_or_else(|(code, error)| reply(code, json!({"error":error})))
}
async fn registration(m: Manager, mut stop: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {_=stop.changed()=>break,_=interval.tick()=>{let result=async{let r=m.call("ServiceRegistry","POST","/serviceregistry/system-discovery/register",json!({"version":"5.4.0","addresses":[m.config.advertise_address],"metadata":{"implementation":"Rust","qualification":"candidate"}})).await;if let Err(e)=r&& e.0!=409{return Err(e)}let r=m.call("ServiceRegistry","POST","/serviceregistry/service-discovery/register",json!({"serviceDefinitionName":"localCloudManagement","version":"1.0.0","metadata":{"implementation":"Rust","qualification":"candidate"},"interfaces":[{"templateName":"generic_https","protocol":"https","policy":"CERT_AUTH","properties":{"accessAddresses":[m.config.advertise_address],"accessPort":m.config.advertise_port,"basePath":"/localcloud","operations":{"status":{"method":"GET","path":"/management/status"},"systems":{"method":"GET","path":"/management/systems"},"services":{"method":"GET","path":"/management/services"}}}}]})).await;if let Err(e)=r&& e.0!=409{return Err(e)}Ok::<_,Failure>(())}.await;if let Err((code,_))=result{eprintln!("LocalCloudManager registration unavailable ({code})")}
            if let Some(config)=&m.config.messaging {
                let registered=m.call("ServiceRegistry","POST","/serviceregistry/service-discovery/register",arrowhead_messaging_rust::monitor_descriptor("LocalCloudManager",&m.config.cloud_suffix,config)).await;
                if registered.is_ok() {
                    let remote=m.remote.clone();
                    let tls:arrowhead_messaging_rust::TlsFactory=Arc::new(move |expected|Ok(remote.tls_config(expected)?));
                    let status=json!({"state":"running","sourceTime":now(),"implementation":"rust","version":"5.4.0"});
                    if arrowhead_messaging_rust::publish_monitor(config,"LocalCloudManager",&m.config.cloud_suffix,&tls,&status).await.is_err(){eprintln!("LocalCloudManager AMQP publication unavailable");}
                }
            }
        }}
    }
}

async fn serve(
    listener: TcpListener,
    tls: Tls,
    router: Router,
    suffix: String,
    verify_peer: bool,
    clients: Option<Arc<crate::console_clients::ConsoleClients>>,
    mut stop: watch::Receiver<bool>,
) {
    let capacity = Arc::new(Semaphore::new(64));
    let mut jobs = JoinSet::new();
    loop {
        tokio::select! {_=stop.changed()=>break,Some(_)=jobs.join_next(),if !jobs.is_empty()=>{},accepted=listener.accept()=>{let Ok((stream,remote))=accepted else{break};let Ok(permit)=capacity.clone().try_acquire_owned()else{continue};let server=if verify_peer{tls.server_current()}else{tls.console_current()};let Ok(server)=server else{eprintln!("TLS material unavailable; rejecting connection");continue};let acceptor=tokio_rustls::TlsAcceptor::from(server);let router=router.clone();let suffix=suffix.clone();let mut stopping=stop.clone();let clients=clients.clone();jobs.spawn(async move{let _permit=permit;if let Some(c)=&clients&&!c.allowed(remote.ip()).await{eprintln!("Console connection from {} refused (not a console client)",remote.ip());return}let stream=tokio::select!{_=stopping.changed()=>return,v=tokio::time::timeout(Duration::from_secs(5),acceptor.accept(stream))=>{let Ok(Ok(s))=v else{return};s}};let router=if verify_peer{let Some(cert)=stream.get_ref().1.peer_certificates().and_then(|c|c.first())else{return};let Ok(peer)=security::peer(cert.as_ref(),&suffix)else{return};router.layer(Extension(peer))}else{router};let mut builder=Builder::new(TokioExecutor::new());builder.http1().timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(10)).max_buf_size(1024*1024);builder.http2().max_concurrent_streams(16);let conn=builder.serve_connection_with_upgrades(TokioIo::new(stream),TowerToHyperService::new(router));tokio::pin!(conn);tokio::select!{_=&mut conn=>{},_=stopping.changed()=>{conn.as_mut().graceful_shutdown();let _=tokio::time::timeout(Duration::from_secs(5),&mut conn).await;},_=tokio::time::sleep(Duration::from_secs(60))=>{}}});}}
    }
    let _ = tokio::time::timeout(Duration::from_secs(7), async {
        while jobs.join_next().await.is_some() {}
    })
    .await;
    jobs.abort_all();
}
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let all = std::env::args().skip(1).collect::<Vec<_>>();
    let port = arrowhead_support_rust::listen::port_argument(&all)?;
    let args = arrowhead_support_rust::listen::without_port_argument(&all);
    if args == ["--help"] || args == ["-h"] {
        println!(
            "LocalCloudManager --config CONFIG.json [--server.port N]; native mTLS system API and HTTPS console (legacy plain http://127.0.0.1:8480 is no longer served). System API port: --server.port N > SERVER_PORT > listen in CONFIG.json > 127.0.0.1:8480."
        );
        return Ok(());
    }
    if std::env::var("ARROWHEAD_ROLE").is_ok_and(|r| r != "localcloudmanager") {
        return Err("This executable only runs the localcloudmanager role".into());
    }
    if args.len() != 2 || args[0] != "--config" {
        return Err("Usage: LocalCloudManager --config CONFIG.json [--server.port N]".into());
    }
    let mut config: Config = serde_json::from_slice(&std::fs::read(&args[1])?)?;
    config.resolve_listen(std::env::var("SERVER_PORT").ok().as_deref(), port)?;
    config.validate()?;
    let tls = Tls::load_identity(
        "LocalCloudManager",
        &config.cloud_suffix,
        &config.certificate,
        &config.private_key,
        &config.ca,
        config.crl_file.as_deref(),
    )?;
    let api_listener = TcpListener::bind(&config.listen).await?;
    let ui_listener = TcpListener::bind(&config.console_listen).await?;
    let m = Manager::new(config.clone(), tls.clone())?;
    let system_router = Router::new()
        .fallback(system_dispatch)
        .with_state(m.clone())
        .layer(DefaultBodyLimit::max(1024 * 1024));
    let (tx, rx) = watch::channel(false);
    let api = tokio::spawn(serve(
        api_listener,
        tls.clone(),
        system_router,
        config.cloud_suffix.clone(),
        true,
        None,
        rx.clone(),
    ));
    let ui = tokio::spawn(serve(
        ui_listener,
        tls,
        console_router(m.clone()),
        config.cloud_suffix.clone(),
        false,
        Some(Arc::new(crate::console_clients::ConsoleClients::new(
            &config.console_clients,
        )?)),
        rx.clone(),
    ));
    let worker = tokio::spawn(registration(m, rx));
    eprintln!(
        "LocalCloudManager ready: mTLS API {}, HTTPS console {}",
        config.listen, config.console_listen
    );
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
    let _ = tx.send(true);
    let _ = tokio::join!(api, ui, worker);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_or_unknown_monitor_selection_defaults_to_real_provider() {
        let names = vec![json!("TestProvider")];
        for selected in [None, Some(""), Some("Unknown"), Some("TestProvider")] {
            assert_eq!(selected_system(&names, selected), "TestProvider")
        }
        assert!(selected_system(&[], Some("")).is_empty());
    }
    #[test]
    fn listening_port_default_and_overrides() {
        let mut c: Config = serde_json::from_value(json!({"cloudSuffix":"RustCloud.Company.arrowhead.eu","project":"p","consoleListen":"127.0.0.1:8490","certificate":"c","privateKey":"k","ca":"a","passwordFile":"p","consoleHashFile":"h","consoleOrigins":["https://localhost:8490"],"upstreams":{},"dockerUrl":"http://docker:2375","dockerTokenFile":"t","advertiseAddress":"localcloudmanager","advertisePort":8480})).unwrap();
        c.resolve_listen(None, None).unwrap();
        assert_eq!(c.listen, DEFAULT_LISTEN);
        c.listen = "0.0.0.0:9480".into();
        c.resolve_listen(Some(""), None).unwrap();
        assert_eq!(c.listen, "0.0.0.0:9480");
        c.resolve_listen(Some("9481"), None).unwrap();
        assert_eq!(c.listen, "0.0.0.0:9481");
        c.resolve_listen(Some("9482"), Some(9483)).unwrap();
        assert_eq!(c.listen, "0.0.0.0:9483");
        assert!(c.resolve_listen(Some("0"), None).is_err());
        assert!(c.resolve_listen(Some("abc"), None).is_err());
    }
    #[test]
    fn console_clients_are_optional_and_validated() {
        let base = json!({"cloudSuffix":"RustCloud.Company.arrowhead.eu","project":"p","consoleListen":"0.0.0.0:8480","certificate":"c","privateKey":"k","ca":"a","passwordFile":"p","consoleHashFile":"h","consoleOrigins":["https://localhost:8490"],"upstreams":{},"dockerUrl":"http://docker:2375","dockerTokenFile":"t","advertiseAddress":"localcloudmanager","advertisePort":8480});
        let c: Config = serde_json::from_value(base.clone()).unwrap();
        assert!(c.console_clients.is_empty());
        let mut v = base.clone();
        v["consoleClients"] = json!(["edge", "10.0.0.0/8"]);
        assert_eq!(
            serde_json::from_value::<Config>(v)
                .unwrap()
                .console_clients
                .len(),
            2
        );
        let mut c: Config = serde_json::from_value(base).unwrap();
        c.console_clients = vec!["edge/24".into()];
        let err = c.validate().unwrap_err();
        assert!(
            err.contains("consoleClients") || err.contains("upstream"),
            "{err}"
        );
        c.console_clients = vec!["edge/24".into()];
        assert!(crate::console_clients::ConsoleClients::new(&c.console_clients).is_err());
    }
    #[test]
    fn origins_reject_downgrade_and_redirect_parts() {
        assert!(!bare_origin("http://localhost:8/", "https"));
        assert!(!bare_origin("https://a/x", "https"));
        assert!(!bare_origin("https://user:secret@a/", "https"));
        assert!(bare_origin("https://localhost:10590/", "https"));
    }
    #[test]
    fn route_values_cannot_escape() {
        assert!(route_segment("/x/a%2Fb", "/x/").is_err());
        assert!(route_segment("/x/a%0Ab", "/x/").is_err());
        assert_eq!(
            route_segment("/x/TestProvider", "/x/").unwrap(),
            "TestProvider"
        );
    }
    #[test]
    fn all_profiles_map_to_distinct_compose_roles() {
        let roles = SYSTEMS
            .iter()
            .map(|(_, r)| r)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(roles.len(), 22);
    }
}
