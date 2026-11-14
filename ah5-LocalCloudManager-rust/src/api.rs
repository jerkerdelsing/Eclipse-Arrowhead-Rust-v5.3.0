use crate::state::{Identity, Session, Store, now};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Config {
    pub role: String,
    pub system_name: String,
    pub domain_name: String,
    pub port: u16,
    pub listen_address: String,
    pub data_file: String,
    pub registry_url: String,
    pub authentication_url: String,
    pub token_secret: String,
    pub management_whitelist: Vec<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Self::from_env_with_default_role("authentication")
    }
    pub fn from_env_with_default_role(
        default_role: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let role = std::env::var("ARROWHEAD_ROLE").unwrap_or_else(|_| default_role.into());
        let (system_name, port) = match role.as_str() {
            "authentication" => ("Authentication", 8444),
            "authorization" => ("ConsumerAuthorization", 8445),
            "orchestration-dynamic" => ("DynamicServiceOrchestration", 8441),
            "orchestration-simple" => ("SimpleStoreServiceOrchestration", 8442),
            "datamanager" => ("DataManager", 8461),
            "eventhandler" => ("EventHandler", 8455),
            "onboarding" => ("Onboarding", 8476),
            "localcloudmanager" => ("LocalCloudManager", 8480),
            _ => return Err(format!("unknown ARROWHEAD_ROLE: {role}").into()),
        };
        let port = std::env::var("SERVER_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(port);
        let system_name = std::env::var("SYSTEM_NAME").unwrap_or_else(|_| system_name.into());
        Ok(Self {
            role,
            domain_name: std::env::var("DOMAIN_NAME")
                .unwrap_or_else(|_| system_name.to_ascii_lowercase()),
            system_name,
            port,
            listen_address: std::env::var("LISTEN_ADDRESS")
                .unwrap_or_else(|_| format!("0.0.0.0:{port}")),
            data_file: std::env::var("DATA_FILE").unwrap_or_else(|_| "/data/state.json".into()),
            registry_url: std::env::var("SERVICE_REGISTRY_URL")
                .unwrap_or_else(|_| "http://serviceregistry:8443".into()),
            authentication_url: std::env::var("AUTHENTICATION_URL")
                .unwrap_or_else(|_| "http://authentication:8444".into()),
            token_secret: std::env::var("TOKEN_SECRET")
                .unwrap_or_else(|_| "change-this-test-cloud-secret".into()),
            management_whitelist: std::env::var("MANAGEMENT_WHITELIST")
                .unwrap_or_else(|_| {
                    "LocalCloudManager,Authentication,DynamicServiceOrchestration".into()
                })
                .split(',')
                .map(|s| s.trim().into())
                .collect(),
        })
    }
}

#[derive(Clone)]
pub struct App {
    pub config: Arc<Config>,
    pub store: Arc<Store>,
    pub(crate) client: reqwest::Client,
}

#[derive(Debug)]
pub struct ApiError(StatusCode, String, String);
impl ApiError {
    fn bad(m: impl Into<String>, o: &str) -> Self {
        Self(StatusCode::BAD_REQUEST, m.into(), o.into())
    }
    fn unauthorized() -> Self {
        Self(
            StatusCode::UNAUTHORIZED,
            "Missing or invalid Arrowhead identity".into(),
            "authentication".into(),
        )
    }
    fn forbidden(m: impl Into<String>, o: &str) -> Self {
        Self(StatusCode::FORBIDDEN, m.into(), o.into())
    }
    fn internal(m: impl Into<String>, o: &str) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, m.into(), o.into())
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0,Json(json!({"errorMessage":self.1,"errorCode":self.0.as_u16(),"exceptionType":self.0.canonical_reason().unwrap_or("Error"),"origin":self.2}))).into_response()
    }
}

pub fn router(config: Arc<Config>, store: Arc<Store>) -> Router {
    let state = App {
        config: config.clone(),
        store,
        client: reqwest::Client::new(),
    };
    let mut app = Router::new();
    app = match config.role.as_str() {
        "authentication" => authentication_routes(app),
        "authorization" => authorization_routes(app),
        "orchestration-dynamic" | "orchestration-simple" => orchestration_routes(app),
        "datamanager" => datamanager_routes(app),
        "eventhandler" => eventhandler_routes(app),
        "onboarding" => onboarding_routes(app),
        "localcloudmanager" => localcloudmanager_routes(app),
        _ => app,
    };
    app.route("/health", get(health))
        .fallback(not_found)
        .with_state(state)
}

async fn health() -> &'static str {
    "OK"
}

fn localcloudmanager_routes(app: Router<App>) -> Router<App> {
    crate::localcloudmanager::routes(app)
        .route("/localcloud/monitor/echo", get(echo))
        .route("/localcloud/management/status", get(localcloud_status))
        .route("/localcloud/management/systems", get(localcloud_systems))
        .route("/localcloud/management/services", get(localcloud_services))
}

async fn localcloud_status(
    State(state): State<App>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    requester(&state, &headers).await?;
    Ok(Json(json!({
        "systemName": state.config.system_name,
        "status": "AVAILABLE",
        "version": "5.4.0",
        "implementation": "rust",
        "timestamp": now()
    })))
}

async fn registry_management_query(
    state: &App,
    headers: &HeaderMap,
    resource: &str,
) -> Result<Json<Value>, ApiError> {
    manager(state, headers, "GET local cloud inventory").await?;
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
        .map_err(|e| ApiError::internal(e.to_string(), "ServiceRegistry inventory"))?;
    if !response.status().is_success() {
        return Err(ApiError::internal(
            format!("ServiceRegistry returned {}", response.status()),
            "ServiceRegistry inventory",
        ));
    }
    response
        .json::<Value>()
        .await
        .map(Json)
        .map_err(|e| ApiError::internal(e.to_string(), "ServiceRegistry inventory"))
}

async fn localcloud_systems(
    State(state): State<App>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    registry_management_query(&state, &headers, "systems").await
}

async fn localcloud_services(
    State(state): State<App>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    registry_management_query(&state, &headers, "service-instances").await
}
async fn echo(State(state): State<App>, headers: HeaderMap) -> Result<&'static str, ApiError> {
    requester(&state, &headers).await?;
    Ok("Got it!")
}
async fn not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"errorMessage":"No such Arrowhead operation","errorCode":404})),
    )
}
async fn persist(state: &App, origin: &str) -> Result<(), ApiError> {
    state
        .store
        .save()
        .await
        .map_err(|e| ApiError::internal(e.to_string(), origin))
}

fn declared(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer SYSTEM//")
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}
fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|v| !v.starts_with("SYSTEM//") && !v.is_empty())
        .map(str::to_owned)
}
async fn requester(state: &App, headers: &HeaderMap) -> Result<String, ApiError> {
    if let Some(name) = declared(headers) {
        return Ok(name);
    }
    let token = bearer(headers).ok_or_else(ApiError::unauthorized)?;
    if let Some(session) = state.store.data.read().await.sessions.get(&token)
        && session.expiration_time > now()
    {
        return Ok(session.system_name.clone());
    }
    let response = state
        .client
        .get(format!(
            "{}/authentication/identity/verify/{}",
            state.config.authentication_url, token
        ))
        .header(
            "Authorization",
            format!("Bearer SYSTEM//{}", state.config.system_name),
        )
        .send()
        .await
        .map_err(|_| ApiError::unauthorized())?;
    if !response.status().is_success() {
        return Err(ApiError::unauthorized());
    }
    let body: Value = response
        .json()
        .await
        .map_err(|_| ApiError::unauthorized())?;
    body.get("systemName")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(ApiError::unauthorized)
}
async fn manager(state: &App, headers: &HeaderMap, origin: &str) -> Result<String, ApiError> {
    let name = requester(state, headers).await?;
    if state
        .config
        .management_whitelist
        .iter()
        .any(|n| n.eq_ignore_ascii_case(&name))
    {
        Ok(name)
    } else {
        Err(ApiError::forbidden(
            format!("System {name} is not allowed to use management services"),
            origin,
        ))
    }
}

fn authentication_routes(app: Router<App>) -> Router<App> {
    app.route("/authentication/monitor/echo", get(echo))
        .route("/authentication/identity/login", post(identity_login))
        .route("/authentication/identity/logout", post(identity_logout))
        .route("/authentication/identity/change", post(identity_change))
        .route(
            "/authentication/identity/verify/{token}",
            get(identity_verify),
        )
        .route(
            "/authentication/mgmt/identities",
            post(identity_create)
                .put(identity_update)
                .delete(identity_remove),
        )
        .route(
            "/authentication/mgmt/identities/query",
            post(identity_query),
        )
        .route(
            "/authentication/mgmt/sessions",
            post(session_query).delete(session_remove),
        )
        .route("/authentication/general/mgmt/config", get(config_get))
        .route("/authentication/general/mgmt/logs", post(logs_get))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityRequest {
    system_name: String,
    #[serde(default)]
    credentials: BTreeMap<String, String>,
}
fn initial_password(system: &str) -> Option<String> {
    std::env::var("INITIAL_IDENTITIES")
        .ok()?
        .split(',')
        .find_map(|item| {
            let (n, p) = item.split_once('=')?;
            n.eq_ignore_ascii_case(system).then(|| p.to_owned())
        })
}
async fn identity_login(
    State(state): State<App>,
    Json(req): Json<IdentityRequest>,
) -> Result<Json<Value>, ApiError> {
    let origin = "POST /authentication/identity/login";
    if req.system_name.trim().is_empty() {
        return Err(ApiError::bad("systemName is empty", origin));
    }
    let mut data = state.store.data.write().await;
    let valid = data
        .identities
        .get(&req.system_name)
        .is_some_and(|i| i.credentials == req.credentials)
        || initial_password(&req.system_name)
            .is_some_and(|p| req.credentials.get("password") == Some(&p));
    if !valid {
        return Err(ApiError::unauthorized());
    }
    let login = now();
    let expiration = (chrono::Utc::now() + chrono::Duration::hours(12))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let token = Uuid::new_v4().to_string();
    let sysop = data
        .identities
        .get(&req.system_name)
        .is_some_and(|i| i.sysop);
    data.sessions.insert(
        token.clone(),
        Session {
            token: token.clone(),
            system_name: req.system_name,
            sysop,
            login_time: login,
            expiration_time: expiration.clone(),
        },
    );
    drop(data);
    persist(&state, origin).await?;
    Ok(Json(json!({"token":token,"expirationTime":expiration})))
}
async fn identity_logout(
    State(state): State<App>,
    Json(req): Json<IdentityRequest>,
) -> Result<StatusCode, ApiError> {
    let origin = "POST /authentication/identity/logout";
    let mut d = state.store.data.write().await;
    d.sessions
        .retain(|_, s| !s.system_name.eq_ignore_ascii_case(&req.system_name));
    drop(d);
    persist(&state, origin).await?;
    Ok(StatusCode::OK)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityChange {
    system_name: String,
    credentials: BTreeMap<String, String>,
    new_credentials: BTreeMap<String, String>,
}
async fn identity_change(
    State(state): State<App>,
    Json(req): Json<IdentityChange>,
) -> Result<StatusCode, ApiError> {
    let origin = "POST /authentication/identity/change";
    let mut d = state.store.data.write().await;
    let i = d
        .identities
        .get_mut(&req.system_name)
        .ok_or_else(ApiError::unauthorized)?;
    if i.credentials != req.credentials {
        return Err(ApiError::unauthorized());
    }
    i.credentials = req.new_credentials;
    i.updated_at = now();
    drop(d);
    persist(&state, origin).await?;
    Ok(StatusCode::OK)
}
async fn identity_verify(
    State(state): State<App>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Result<Json<Value>, ApiError> {
    declared(&headers).ok_or_else(ApiError::unauthorized)?;
    let d = state.store.data.read().await;
    let s = d.sessions.get(&token);
    Ok(Json(match s {
        Some(s) if s.expiration_time > now() => {
            json!({"verified":true,"systemName":s.system_name,"sysop":s.sysop,"loginTime":s.login_time,"expirationTime":s.expiration_time})
        }
        _ => {
            json!({"verified":false,"systemName":null,"sysop":null,"loginTime":null,"expirationTime":null})
        }
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityList {
    #[serde(default)]
    authentication_method: Option<String>,
    identities: Vec<IdentityInput>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityInput {
    system_name: String,
    #[serde(default)]
    credentials: BTreeMap<String, String>,
    #[serde(default)]
    sysop: Option<bool>,
}
async fn identity_create(
    State(state): State<App>,
    headers: HeaderMap,
    Json(list): Json<IdentityList>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    upsert_identities(state, headers, list, true).await
}
async fn identity_update(
    State(state): State<App>,
    headers: HeaderMap,
    Json(value): Json<Value>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let identities: Vec<IdentityInput> =
        serde_json::from_value(value.get("identities").cloned().unwrap_or(json!([])))
            .map_err(|e| ApiError::bad(e.to_string(), "PUT /authentication/mgmt/identities"))?;
    upsert_identities(
        state,
        headers,
        IdentityList {
            authentication_method: None,
            identities,
        },
        false,
    )
    .await
}
async fn upsert_identities(
    state: App,
    headers: HeaderMap,
    list: IdentityList,
    created: bool,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let origin = "/authentication/mgmt/identities";
    let actor = manager(&state, &headers, origin).await?;
    let mut d = state.store.data.write().await;
    let mut result = vec![];
    for input in list.identities {
        let time = now();
        let item = Identity {
            system_name: input.system_name.clone(),
            credentials: input.credentials,
            sysop: input.sysop.unwrap_or(false),
            created_at: d
                .identities
                .get(&input.system_name)
                .map(|v| v.created_at.clone())
                .unwrap_or_else(|| time.clone()),
            updated_at: time.clone(),
        };
        d.identities.insert(input.system_name.clone(), item.clone());
        result.push(json!({"systemName":item.system_name,"authenticationMethod":list.authentication_method.as_deref().unwrap_or("password"),"sysop":item.sysop,"createdBy":actor,"createdAt":item.created_at,"updatedBy":actor,"updatedAt":item.updated_at}));
    }
    drop(d);
    persist(&state, origin).await?;
    Ok((
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(json!({"identities":result,"count":result.len()})),
    ))
}
async fn identity_remove(
    State(state): State<App>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Result<StatusCode, ApiError> {
    let origin = "DELETE /authentication/mgmt/identities";
    manager(&state, &headers, origin).await?;
    let names = q
        .get("systemNames")
        .or_else(|| q.get("names"))
        .map(|s| s.split(',').collect::<Vec<_>>())
        .unwrap_or_default();
    let mut d = state.store.data.write().await;
    d.identities
        .retain(|n, _| !names.iter().any(|x| x.eq_ignore_ascii_case(n)));
    drop(d);
    persist(&state, origin).await?;
    Ok(StatusCode::OK)
}
async fn identity_query(
    State(state): State<App>,
    headers: HeaderMap,
    Json(_): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    manager(
        &state,
        &headers,
        "POST /authentication/mgmt/identities/query",
    )
    .await?;
    let d = state.store.data.read().await;
    let entries:Vec<_>=d.identities.values().map(|i|json!({"systemName":i.system_name,"authenticationMethod":"password","sysop":i.sysop,"createdBy":"LocalCloudManager","createdAt":i.created_at,"updatedBy":"LocalCloudManager","updatedAt":i.updated_at})).collect();
    Ok(Json(json!({"identities":entries,"count":entries.len()})))
}
async fn session_query(
    State(state): State<App>,
    headers: HeaderMap,
    Json(_): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    manager(&state, &headers, "POST /authentication/mgmt/sessions").await?;
    let d = state.store.data.read().await;
    let sessions:Vec<_>=d.sessions.values().map(|s|json!({"systemName":s.system_name,"loginTime":s.login_time,"expirationTime":s.expiration_time})).collect();
    Ok(Json(json!({"sessions":sessions,"count":sessions.len()})))
}
async fn session_remove(
    State(state): State<App>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Result<StatusCode, ApiError> {
    manager(&state, &headers, "DELETE /authentication/mgmt/sessions").await?;
    let names = q
        .get("systemNames")
        .map(|s| s.split(',').collect::<Vec<_>>())
        .unwrap_or_default();
    let mut d = state.store.data.write().await;
    d.sessions
        .retain(|_, v| !names.iter().any(|n| n.eq_ignore_ascii_case(&v.system_name)));
    drop(d);
    persist(&state, "DELETE /authentication/mgmt/sessions").await?;
    Ok(StatusCode::OK)
}

fn authorization_routes(app: Router<App>) -> Router<App> {
    app.route("/consumerauthorization/monitor/echo", get(echo))
        .route("/consumerauthorization/authorization/grant", post(grant))
        .route(
            "/consumerauthorization/authorization/revoke/{instance_id}",
            delete(revoke_grant),
        )
        .route(
            "/consumerauthorization/authorization/lookup",
            post(query_grants),
        )
        .route(
            "/consumerauthorization/authorization/verify",
            post(verify_grants),
        )
        .route("/consumerauthorization/mgmt/grant", post(grant))
        .route(
            "/consumerauthorization/mgmt/revoke",
            delete(revoke_grants_query),
        )
        .route("/consumerauthorization/mgmt/query", post(query_grants))
        .route("/consumerauthorization/mgmt/check", post(verify_grants))
        .route(
            "/consumerauthorization/authorization-token/generate",
            post(token_generate),
        )
        .route(
            "/consumerauthorization/authorization-token/verify/{token}",
            get(token_verify),
        )
        .route(
            "/consumerauthorization/authorization-token/public-key",
            get(public_key),
        )
        .route(
            "/consumerauthorization/authorization-token/encryption-key",
            post(encryption_key).delete(encryption_key_remove),
        )
        .route(
            "/consumerauthorization/mgmt/token/generate",
            post(token_generate),
        )
        .route("/consumerauthorization/mgmt/token/query", post(token_query))
        .route(
            "/consumerauthorization/mgmt/token/revoke",
            delete(token_revoke),
        )
        .route(
            "/consumerauthorization/general/mgmt/config",
            get(config_get),
        )
        .route("/consumerauthorization/general/mgmt/logs", post(logs_get))
}

async fn grant(
    State(state): State<App>,
    headers: HeaderMap,
    Json(value): Json<Value>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let origin = "POST authorization grant";
    let actor = requester(&state, &headers).await?;
    let inputs = value
        .get("list")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| vec![value]);
    let mut d = state.store.data.write().await;
    let mut entries = vec![];
    for input in inputs {
        let id = Uuid::new_v4().to_string();
        let mut item = input.as_object().cloned().unwrap_or_default();
        item.insert("instanceId".into(), json!(id));
        item.insert("createdBy".into(), json!(actor));
        item.insert("createdAt".into(), json!(now()));
        let item = Value::Object(item);
        d.grants.insert(id, item.clone());
        entries.push(item);
    }
    drop(d);
    persist(&state, origin).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"entries":entries,"count":entries.len()})),
    ))
}
async fn revoke_grant(
    State(state): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    requester(&state, &headers).await?;
    let removed = state.store.data.write().await.grants.remove(&id).is_some();
    persist(&state, "DELETE authorization revoke").await?;
    Ok(if removed {
        StatusCode::OK
    } else {
        StatusCode::NO_CONTENT
    })
}
async fn revoke_grants_query(
    State(state): State<App>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Result<StatusCode, ApiError> {
    manager(&state, &headers, "DELETE authorization mgmt revoke").await?;
    let ids = q
        .get("instanceIds")
        .map(|v| v.split(',').collect::<Vec<_>>())
        .unwrap_or_default();
    state
        .store
        .data
        .write()
        .await
        .grants
        .retain(|id, _| !ids.contains(&id.as_str()));
    persist(&state, "DELETE authorization mgmt revoke").await?;
    Ok(StatusCode::OK)
}
async fn query_grants(
    State(state): State<App>,
    headers: HeaderMap,
    Json(_): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    requester(&state, &headers).await?;
    let d = state.store.data.read().await;
    let entries: Vec<_> = d.grants.values().cloned().collect();
    Ok(Json(json!({"entries":entries,"count":entries.len()})))
}
async fn verify_grants(
    State(state): State<App>,
    headers: HeaderMap,
    Json(value): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    requester(&state, &headers).await?;
    let list = value
        .get("list")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| vec![value]);
    let d = state.store.data.read().await;
    let entries: Vec<_> = list
        .into_iter()
        .map(|req| {
            let mut out = req.as_object().cloned().unwrap_or_default();
            let granted = d
                .grants
                .values()
                .any(|g| grant_matches(g, &Value::Object(out.clone())));
            out.insert("granted".into(), json!(granted));
            Value::Object(out)
        })
        .collect();
    Ok(Json(json!({"entries":entries,"count":entries.len()})))
}
fn grant_matches(grant: &Value, req: &Value) -> bool {
    ["provider", "target", "cloud"]
        .iter()
        .all(|k| req.get(k).is_none() || grant.get(k) == req.get(k))
}

async fn token_generate(
    State(state): State<App>,
    headers: HeaderMap,
    Json(value): Json<Value>,
) -> Result<Response, ApiError> {
    let origin = "POST authorization token generate";
    let consumer = requester(&state, &headers).await?;
    let inputs = value
        .get("list")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| vec![value]);
    let mut d = state.store.data.write().await;
    let mut outputs = vec![];
    for req in inputs {
        let expires = (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let payload = json!({"consumer":consumer,"provider":req.get("provider"),"targetType":req.get("targetType"),"target":req.get("target"),"scope":req.get("scope"),"expiresAt":expires,"nonce":Uuid::new_v4()});
        let token = sign(&state.config.token_secret, &payload);
        let record = json!({"tokenType":"IDENTITY","variant":req.get("tokenVariant").and_then(Value::as_str).unwrap_or("NONE"),"token":token,"tokenReference":token,"requester":consumer,"consumerCloud":"LOCAL","consumer":consumer,"provider":req.get("provider"),"targetType":req.get("targetType"),"target":req.get("target"),"scope":req.get("scope"),"createdAt":now(),"usageLimit":null,"usageLeft":null,"expiresAt":expires});
        d.authorization_tokens.insert(token.clone(), record);
        outputs.push(json!({"tokenType":"IDENTITY","targetType":req.get("targetType"),"token":token,"usageLimit":null,"expiresAt":expires}));
    }
    drop(d);
    persist(&state, origin).await?;
    if outputs.len() == 1 {
        Ok(Json(outputs.remove(0)).into_response())
    } else {
        Ok((
            StatusCode::CREATED,
            Json(json!({"entries":outputs,"count":outputs.len()})),
        )
            .into_response())
    }
}
fn sign(secret: &str, payload: &Value) -> String {
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(encoded.as_bytes());
    format!(
        "{}.{}",
        encoded,
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}
async fn token_verify(
    State(state): State<App>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Result<Json<Value>, ApiError> {
    requester(&state, &headers).await?;
    let d = state.store.data.read().await;
    let result=d.authorization_tokens.get(&token).map(|v|json!({"verified":true,"consumerCloud":v["consumerCloud"],"consumer":v["consumer"],"targetType":v["targetType"],"target":v["target"],"scope":v["scope"]})).unwrap_or_else(||json!({"verified":false,"consumerCloud":null,"consumer":null,"targetType":null,"target":null,"scope":null}));
    Ok(Json(result))
}
async fn token_query(
    State(state): State<App>,
    headers: HeaderMap,
    Json(_): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    manager(&state, &headers, "POST token query").await?;
    let d = state.store.data.read().await;
    let entries: Vec<_> = d.authorization_tokens.values().cloned().collect();
    Ok(Json(json!({"entries":entries,"count":entries.len()})))
}
async fn token_revoke(
    State(state): State<App>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Result<StatusCode, ApiError> {
    manager(&state, &headers, "DELETE token revoke").await?;
    if let Some(tokens) = q.get("tokens") {
        for token in tokens.split(',') {
            state
                .store
                .data
                .write()
                .await
                .authorization_tokens
                .remove(token);
        }
    }
    persist(&state, "DELETE token revoke").await?;
    Ok(StatusCode::OK)
}
async fn public_key() -> &'static str {
    "RUST-HMAC-SHA256"
}
async fn encryption_key(
    State(state): State<App>,
    headers: HeaderMap,
    Json(_): Json<Value>,
) -> Result<(StatusCode, String), ApiError> {
    requester(&state, &headers).await?;
    Ok((StatusCode::CREATED, "registered".into()))
}
async fn encryption_key_remove(
    State(state): State<App>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    requester(&state, &headers).await?;
    Ok(StatusCode::OK)
}

fn orchestration_routes(app: Router<App>) -> Router<App> {
    app.route("/serviceorchestration/monitor/echo", get(echo))
        .route(
            "/serviceorchestration/orchestration/pull",
            post(orchestration_pull),
        )
        .route(
            "/serviceorchestration/orchestration/subscribe",
            post(subscription_create),
        )
        .route(
            "/serviceorchestration/orchestration/unsubscribe/{id}",
            delete(subscription_remove),
        )
        .route(
            "/serviceorchestration/orchestration/mgmt/push/subscribe",
            post(subscription_create),
        )
        .route(
            "/serviceorchestration/orchestration/mgmt/push/query",
            post(subscription_query),
        )
        .route(
            "/serviceorchestration/orchestration/mgmt/push/trigger",
            post(push_trigger),
        )
        .route(
            "/serviceorchestration/orchestration/mgmt/push/unsubscribe",
            delete(subscription_bulk_remove),
        )
        .route(
            "/serviceorchestration/orchestration/mgmt/lock/create",
            post(lock_create),
        )
        .route(
            "/serviceorchestration/orchestration/mgmt/lock/query",
            post(lock_query),
        )
        .route(
            "/serviceorchestration/orchestration/mgmt/lock/remove/{owner}",
            delete(lock_remove),
        )
        .route(
            "/serviceorchestration/orchestration/mgmt/history/query",
            post(history_query),
        )
        .route(
            "/serviceorchestration/orchestration/mgmt/simple-store/create",
            post(route_create),
        )
        .route(
            "/serviceorchestration/orchestration/mgmt/simple-store/query",
            post(route_query),
        )
        .route(
            "/serviceorchestration/orchestration/mgmt/simple-store/modify-priorities",
            put(route_update),
        )
        .route(
            "/serviceorchestration/orchestration/mgmt/simple-store/remove",
            delete(route_remove),
        )
        .route("/serviceorchestration/general/mgmt/config", get(config_get))
        .route("/serviceorchestration/general/mgmt/logs", post(logs_get))
}

async fn orchestration_pull(
    State(state): State<App>,
    headers: HeaderMap,
    Json(req): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let consumer = requester(&state, &headers).await?;
    let requirement = req.get("serviceRequirement").cloned().unwrap_or(json!({}));
    let definition = requirement
        .get("serviceDefinition")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ApiError::bad(
                "serviceRequirement.serviceDefinition is missing",
                "POST orchestration pull",
            )
        })?;
    let lookup = json!({"serviceDefinitionNames":[definition],"versions":requirement.get("versions").cloned().unwrap_or(json!([])),"interfaceTemplateNames":requirement.get("interfaceTemplateNames").cloned().unwrap_or(json!([])),"policies":requirement.get("securityPolicies").cloned().unwrap_or(json!([])),"alivesAt":requirement.get("alivesAt")});
    let response = state
        .client
        .post(format!(
            "{}/serviceregistry/service-discovery/lookup",
            state.config.registry_url
        ))
        .header(
            "Authorization",
            format!("Bearer SYSTEM//{}", state.config.system_name),
        )
        .json(&lookup)
        .send()
        .await
        .map_err(|e| ApiError::internal(e.to_string(), "service discovery"))?;
    if !response.status().is_success() {
        return Err(ApiError::internal(
            "ServiceRegistry lookup failed",
            "service discovery",
        ));
    }
    let found: Value = response
        .json()
        .await
        .map_err(|e| ApiError::internal(e.to_string(), "service discovery"))?;
    let results=found.get("entries").and_then(Value::as_array).cloned().unwrap_or_default().into_iter().map(|s|json!({"serviceInstanceId":s["instanceId"],"cloudIdentitifer":"LOCAL","providerName":s["provider"]["name"],"serviceDefinitition":s["serviceDefinition"]["name"],"version":s["version"],"aliveUntil":s["expiresAt"],"exclusiveUntil":null,"metadata":s["metadata"],"interfaces":s["interfaces"],"authorizationTokens":{}})).collect::<Vec<_>>();
    let history = json!({"id":Uuid::new_v4(),"status":"DONE","type":"PULL","requesterSystem":consumer,"targetSystem":null,"serviceDefinition":definition,"subscriptionId":null,"message":null,"createdAt":now(),"startedAt":now(),"finishedAt":now()});
    state.store.data.write().await.history.push(history);
    persist(&state, "POST orchestration pull").await?;
    Ok(Json(json!({"results":results,"warnings":[]})))
}

async fn subscription_create(
    State(state): State<App>,
    headers: HeaderMap,
    Json(value): Json<Value>,
) -> Result<(StatusCode, String), ApiError> {
    let owner = requester(&state, &headers).await?;
    let id = Uuid::new_v4().to_string();
    let mut item = value.as_object().cloned().unwrap_or_default();
    item.insert("id".into(), json!(id));
    item.insert("ownerSystemName".into(), json!(owner));
    item.insert("createdAt".into(), json!(now()));
    item.insert("expiredAt".into(), Value::Null);
    state
        .store
        .data
        .write()
        .await
        .subscriptions
        .insert(id.clone(), Value::Object(item));
    persist(&state, "POST orchestration subscribe").await?;
    Ok((StatusCode::CREATED, id))
}
async fn subscription_remove(
    State(state): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    requester(&state, &headers).await?;
    let found = state
        .store
        .data
        .write()
        .await
        .subscriptions
        .remove(&id)
        .is_some();
    persist(&state, "DELETE orchestration unsubscribe").await?;
    Ok(if found {
        StatusCode::OK
    } else {
        StatusCode::NO_CONTENT
    })
}
async fn subscription_query(
    State(state): State<App>,
    headers: HeaderMap,
    Json(_): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    manager(&state, &headers, "POST push query").await?;
    let d = state.store.data.read().await;
    let entries: Vec<_> = d.subscriptions.values().cloned().collect();
    Ok(Json(json!({"entries":entries,"count":entries.len()})))
}
async fn subscription_bulk_remove(
    State(state): State<App>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Result<StatusCode, ApiError> {
    manager(&state, &headers, "DELETE push unsubscribe").await?;
    let ids = q
        .get("ids")
        .map(|v| v.split(',').collect::<Vec<_>>())
        .unwrap_or_default();
    state
        .store
        .data
        .write()
        .await
        .subscriptions
        .retain(|id, _| !ids.contains(&id.as_str()));
    persist(&state, "DELETE push unsubscribe").await?;
    Ok(StatusCode::OK)
}
async fn push_trigger(
    State(state): State<App>,
    headers: HeaderMap,
    Json(_): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    manager(&state, &headers, "POST push trigger").await?;
    Ok(Json(json!({"jobs":[]})))
}

async fn lock_create(
    State(state): State<App>,
    headers: HeaderMap,
    Json(value): Json<Value>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    manager(&state, &headers, "POST lock create").await?;
    let inputs = value
        .get("locks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut entries = vec![];
    for item in inputs {
        let id = state.store.next_id("locks").await;
        let mut obj = item.as_object().cloned().unwrap_or_default();
        obj.insert("id".into(), json!(id));
        obj.insert("orchestrationJobId".into(), Value::Null);
        obj.insert("temporary".into(), json!(false));
        let out = Value::Object(obj);
        state
            .store
            .data
            .write()
            .await
            .locks
            .insert(id.to_string(), out.clone());
        entries.push(out);
    }
    persist(&state, "POST lock create").await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"entries":entries,"count":entries.len()})),
    ))
}
async fn lock_query(
    State(state): State<App>,
    headers: HeaderMap,
    Json(_): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    manager(&state, &headers, "POST lock query").await?;
    let d = state.store.data.read().await;
    let entries: Vec<_> = d.locks.values().cloned().collect();
    Ok(Json(json!({"entries":entries,"count":entries.len()})))
}
async fn lock_remove(
    State(state): State<App>,
    headers: HeaderMap,
    Path(owner): Path<String>,
) -> Result<StatusCode, ApiError> {
    manager(&state, &headers, "DELETE lock remove").await?;
    state
        .store
        .data
        .write()
        .await
        .locks
        .retain(|_, v| v.get("owner").and_then(Value::as_str) != Some(&owner));
    persist(&state, "DELETE lock remove").await?;
    Ok(StatusCode::OK)
}
async fn history_query(
    State(state): State<App>,
    headers: HeaderMap,
    Json(_): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    manager(&state, &headers, "POST history query").await?;
    let d = state.store.data.read().await;
    Ok(Json(json!({"entries":d.history,"count":d.history.len()})))
}

async fn route_create(
    State(state): State<App>,
    headers: HeaderMap,
    Json(value): Json<Value>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let actor = manager(&state, &headers, "POST simple-store create").await?;
    let inputs = value
        .get("candidates")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut entries = vec![];
    for input in inputs {
        let id = Uuid::new_v4().to_string();
        let mut obj = input.as_object().cloned().unwrap_or_default();
        obj.insert("id".into(), json!(id));
        obj.insert("createdBy".into(), json!(actor));
        obj.insert("updatedBy".into(), json!(actor));
        obj.insert("createdAt".into(), json!(now()));
        obj.insert("updatedAt".into(), json!(now()));
        let out = Value::Object(obj);
        state
            .store
            .data
            .write()
            .await
            .routes
            .insert(id, out.clone());
        entries.push(out);
    }
    persist(&state, "POST simple-store create").await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"entries":entries,"count":entries.len()})),
    ))
}
async fn route_query(
    State(state): State<App>,
    headers: HeaderMap,
    Json(_): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    manager(&state, &headers, "POST simple-store query").await?;
    let d = state.store.data.read().await;
    let entries: Vec<_> = d.routes.values().cloned().collect();
    Ok(Json(json!({"entries":entries,"count":entries.len()})))
}
async fn route_update(
    State(state): State<App>,
    headers: HeaderMap,
    Json(value): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    manager(&state, &headers, "PUT simple-store modify-priorities").await?;
    let inputs = value
        .get("candidates")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut d = state.store.data.write().await;
    for item in inputs {
        if let Some(id) = item.get("id").and_then(Value::as_str)
            && let Some(old) = d.routes.get_mut(id)
        {
            if let Some(priority) = item.get("priority") {
                old["priority"] = priority.clone()
            }
            old["updatedAt"] = json!(now());
        }
    }
    let entries: Vec<_> = d.routes.values().cloned().collect();
    drop(d);
    persist(&state, "PUT simple-store modify-priorities").await?;
    Ok(Json(json!({"entries":entries,"count":entries.len()})))
}
async fn route_remove(
    State(state): State<App>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Result<StatusCode, ApiError> {
    manager(&state, &headers, "DELETE simple-store remove").await?;
    let ids = q
        .get("ids")
        .map(|v| v.split(',').collect::<Vec<_>>())
        .unwrap_or_default();
    state
        .store
        .data
        .write()
        .await
        .routes
        .retain(|id, _| !ids.contains(&id.as_str()));
    persist(&state, "DELETE simple-store remove").await?;
    Ok(StatusCode::OK)
}

fn datamanager_routes(app: Router<App>) -> Router<App> {
    app.route("/datamanager/monitor/echo", get(echo))
        .route("/datamanager/data-proxy/systems", get(data_systems))
        .route(
            "/datamanager/data-proxy/systems/{system}/services",
            get(data_services),
        )
        .route(
            "/datamanager/data-proxy/systems/{system}/services/{service}/data",
            get(data_get).put(data_put),
        )
        .route("/datamanager/data-historian/systems", get(data_systems))
        .route(
            "/datamanager/data-historian/systems/{system}/services",
            get(data_services),
        )
        .route(
            "/datamanager/data-historian/systems/{system}/services/{service}/data",
            get(data_get).put(data_put),
        )
}
fn stream_key(system: &str, service: &str) -> String {
    format!("{system}|{service}")
}
async fn data_systems(
    State(state): State<App>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    requester(&state, &headers).await?;
    let d = state.store.data.read().await;
    let mut systems = d
        .data_streams
        .keys()
        .filter_map(|k| k.split_once('|').map(|v| v.0.to_string()))
        .collect::<Vec<_>>();
    systems.sort();
    systems.dedup();
    Ok(Json(json!({"systems":systems})))
}
async fn data_services(
    State(state): State<App>,
    headers: HeaderMap,
    Path(system): Path<String>,
) -> Result<Json<Value>, ApiError> {
    requester(&state, &headers).await?;
    let d = state.store.data.read().await;
    let services = d
        .data_streams
        .keys()
        .filter_map(|k| k.split_once('|'))
        .filter(|(s, _)| *s == system)
        .map(|(_, v)| v)
        .collect::<Vec<_>>();
    Ok(Json(json!({"services":services})))
}
async fn data_get(
    State(state): State<App>,
    headers: HeaderMap,
    Path((system, service)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    requester(&state, &headers).await?;
    let count = q
        .get("count")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1)
        .min(1000);
    let d = state.store.data.read().await;
    let mut records = d
        .data_streams
        .get(&stream_key(&system, &service))
        .cloned()
        .unwrap_or_default();
    records.reverse();
    records.truncate(count);
    records.reverse();
    Ok(Json(Value::Array(records)))
}
async fn data_put(
    State(state): State<App>,
    headers: HeaderMap,
    Path((system, service)): Path<(String, String)>,
    Json(records): Json<Value>,
) -> Result<StatusCode, ApiError> {
    requester(&state, &headers).await?;
    let records = records.as_array().cloned().unwrap_or_default();
    state
        .store
        .data
        .write()
        .await
        .data_streams
        .entry(stream_key(&system, &service))
        .or_default()
        .extend(records);
    persist(&state, "PUT datamanager data").await?;
    Ok(StatusCode::NO_CONTENT)
}

fn eventhandler_routes(app: Router<App>) -> Router<App> {
    app.route("/eventhandler/monitor/echo", get(echo))
        .route("/eventhandler/event-publish/publish", post(event_publish))
        .route(
            "/eventhandler/event-subscription/subscribe",
            post(event_subscribe),
        )
        .route(
            "/eventhandler/event-subscription/unsubscribe/{id}",
            delete(event_unsubscribe),
        )
        .route(
            "/eventhandler/management/subscriptions",
            get(event_subscriptions),
        )
        .route(
            "/eventhandler/management/subscriptions/{id}",
            put(event_update).delete(event_unsubscribe),
        )
        .route("/eventhandler/general/mgmt/config", get(config_get))
        .route("/eventhandler/general/mgmt/logs", post(logs_get))
}
async fn event_subscribe(
    State(state): State<App>,
    headers: HeaderMap,
    Json(value): Json<Value>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let owner = requester(&state, &headers).await?;
    let id = state.store.next_id("events").await;
    let mut obj = value.as_object().cloned().unwrap_or_default();
    obj.insert("id".into(), json!(id));
    obj.insert("subscriberSystemName".into(), json!(owner));
    obj.insert("createdAt".into(), json!(now()));
    obj.insert("updatedAt".into(), json!(now()));
    let output = Value::Object(obj);
    state
        .store
        .data
        .write()
        .await
        .subscriptions
        .insert(id.to_string(), output.clone());
    persist(&state, "POST event subscribe").await?;
    Ok((StatusCode::CREATED, Json(output)))
}
async fn event_unsubscribe(
    State(state): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    requester(&state, &headers).await?;
    let found = state
        .store
        .data
        .write()
        .await
        .subscriptions
        .remove(&id)
        .is_some();
    persist(&state, "DELETE event subscription").await?;
    Ok(if found {
        StatusCode::OK
    } else {
        StatusCode::NO_CONTENT
    })
}
async fn event_subscriptions(
    State(state): State<App>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    manager(&state, &headers, "GET event subscriptions").await?;
    let d = state.store.data.read().await;
    let entries: Vec<_> = d.subscriptions.values().cloned().collect();
    Ok(Json(json!({"entries":entries,"count":entries.len()})))
}
async fn event_update(
    State(state): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(value): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    manager(&state, &headers, "PUT event subscription").await?;
    let mut d = state.store.data.write().await;
    let old = d
        .subscriptions
        .get_mut(&id)
        .ok_or_else(|| ApiError::bad("Unknown subscription", "PUT event subscription"))?;
    for (k, v) in value.as_object().cloned().unwrap_or_default() {
        old[k] = v;
    }
    old["updatedAt"] = json!(now());
    let output = old.clone();
    drop(d);
    persist(&state, "PUT event subscription").await?;
    Ok(Json(output))
}
async fn event_publish(
    State(state): State<App>,
    headers: HeaderMap,
    Json(value): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    requester(&state, &headers).await?;
    let event_type = value.get("eventType");
    let d = state.store.data.read().await;
    let matched = d
        .subscriptions
        .values()
        .filter(|s| s.get("eventType") == event_type)
        .count();
    Ok(Json(
        json!({"matchedSubscriptions":matched,"acceptedDeliveries":matched}),
    ))
}

fn onboarding_routes(app: Router<App>) -> Router<App> {
    app.route("/onboarding/echo", get(|| async { "Got it!" }))
        .route("/onboarding/monitor/echo", get(echo))
        .route("/onboarding/certificate/name", post(onboard_name))
        .route("/onboarding/sharedsecret/name", post(onboard_name))
        .route("/onboarding/certificate/csr", post(onboard_csr))
        .route("/onboarding/sharedsecret/csr", post(onboard_csr))
        .route("/onboarding/general/mgmt/config", get(config_get))
        .route("/onboarding/general/mgmt/logs", post(logs_get))
}
async fn onboard_name(Json(value): Json<Value>) -> Result<(StatusCode, Json<Value>), ApiError> {
    let name = value
        .get("systemName")
        .or_else(|| value.get("name"))
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad("system name is missing", "POST onboarding name"))?;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({"systemName":name,"certificate":"TEST-CLOUD-CERTIFICATE","certificateChain":[],"sharedSecret":Uuid::new_v4().to_string()}),
        ),
    ))
}
async fn onboard_csr(Json(value): Json<Value>) -> Result<(StatusCode, Json<Value>), ApiError> {
    if value.get("csr").and_then(Value::as_str).is_none() {
        return Err(ApiError::bad("csr is missing", "POST onboarding csr"));
    }
    Ok((
        StatusCode::CREATED,
        Json(json!({"certificate":"TEST-CLOUD-CERTIFICATE","certificateChain":[]})),
    ))
}

async fn config_get(State(state): State<App>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    manager(&state, &headers, "GET general config").await?;
    Ok(Json(
        json!({"map":{"system.name":state.config.system_name,"domain.name":state.config.domain_name,"server.port":state.config.port,"implementation":"rust"}}),
    ))
}
async fn logs_get(
    State(state): State<App>,
    headers: HeaderMap,
    Json(_): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    manager(&state, &headers, "POST general logs").await?;
    Ok(Json(json!({"entries":[],"count":0})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;
    fn cfg(role: &str) -> Arc<Config> {
        let (system, port) = match role {
            "authentication" => ("Authentication", 8444),
            "authorization" => ("ConsumerAuthorization", 8445),
            "localcloudmanager" => ("LocalCloudManager", 8480),
            _ => ("EventHandler", 8455),
        };
        Arc::new(Config {
            role: role.into(),
            system_name: system.into(),
            domain_name: "localhost".into(),
            port,
            listen_address: "127.0.0.1:0".into(),
            data_file: std::env::temp_dir()
                .join(format!("arrowhead-{role}-{}.json", Uuid::new_v4()))
                .display()
                .to_string(),
            registry_url: "http://127.0.0.1:1".into(),
            authentication_url: "http://127.0.0.1:1".into(),
            token_secret: "test".into(),
            management_whitelist: vec!["LocalCloudManager".into()],
        })
    }
    async fn app(role: &str) -> Router {
        let c = cfg(role);
        let s = Arc::new(Store::load(&c.data_file).await.unwrap());
        router(c, s)
    }
    fn req(method: &str, path: &str, who: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer SYSTEM//{who}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }
    #[tokio::test]
    async fn authorization_grant_round_trip() {
        let app = app("authorization").await;
        let r = app
            .clone()
            .oneshot(req(
                "POST",
                "/consumerauthorization/authorization/grant",
                "Provider",
                json!({"provider":"Provider","targetType":"SERVICE_DEF","target":"temperature"}),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
        let r = app
            .oneshot(req(
                "POST",
                "/consumerauthorization/authorization/verify",
                "Consumer",
                json!({"provider":"Provider","target":"temperature"}),
            ))
            .await
            .unwrap();
        let b: Value =
            serde_json::from_slice(&to_bytes(r.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(b["entries"][0]["granted"], true);
    }
    #[tokio::test]
    async fn event_subscription_and_publish() {
        let app = app("eventhandler").await;
        let r = app
            .clone()
            .oneshot(req(
                "POST",
                "/eventhandler/event-subscription/subscribe",
                "Consumer",
                json!({"eventType":"alarm","notifyUri":"http://consumer/events"}),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
        let r = app
            .oneshot(req(
                "POST",
                "/eventhandler/event-publish/publish",
                "Producer",
                json!({"eventType":"alarm","payload":"x"}),
            ))
            .await
            .unwrap();
        let b: Value =
            serde_json::from_slice(&to_bytes(r.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(b["matchedSubscriptions"], 1);
    }
    #[tokio::test]
    async fn localcloudmanager_dashboard_is_served() {
        let response = app("localcloudmanager")
            .await
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(
            body.windows(17)
                .any(|window| window == b"LocalCloudManager")
        );
    }
}
