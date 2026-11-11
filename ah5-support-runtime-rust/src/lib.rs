// SPDX-License-Identifier: EPL-2.0
pub mod aigym_mqtt;
pub mod basic;
pub mod ca;
pub mod choreography;
pub mod config;
pub mod contracts;
pub mod data;
pub mod events;
pub mod federation;
pub mod listen;
pub mod monitor;
pub mod monitor_store;
pub mod onboarding;
pub mod plant;
pub mod plant_sync;
pub mod producer;
pub mod qos;
pub mod runner;
pub mod security;
pub mod store;
pub mod telemetry;
pub mod translation;
pub mod web;

pub use config::Config;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
pub use store::{Database, Store, table};
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
pub struct Error {
    pub code: u16,
    pub message: String,
}
impl Error {
    pub fn new(code: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    pub fn bad(s: impl Into<String>) -> Self {
        Self::new(400, s)
    }
    pub fn denied() -> Self {
        Self::new(403, "Access denied")
    }
    pub fn unavailable(s: &str) -> Self {
        Self::new(503, s)
    }
    pub fn unsupported(s: &str) -> Self {
        Self::new(501, s)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::new(500, "Private storage or key file unavailable")
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::bad("Invalid JSON document")
    }
}
#[derive(Clone)]
pub struct App {
    pub config: Arc<Config>,
    pub store: Arc<Store>,
    pub remote: Arc<security::Remote>,
    pub identity_workers: Arc<tokio::sync::Semaphore>,
    pub monitor_runtime: Arc<std::sync::Mutex<Value>>,
    pub monitor_db: Option<Arc<monitor_store::MonitorDb>>,
    pub federation: Arc<federation::Runtime>,
}
impl App {
    pub fn new(config: Config, store: Store, tls: security::Tls) -> Result<Self> {
        let monitor_db = if config.role == "sysmonitor" && config.messaging.is_some() {
            let path = std::path::Path::new(&config.state).with_extension("monitor.sqlite");
            let db = monitor_store::MonitorDb::open(path)?;
            db.import(&store)?;
            Some(Arc::new(db))
        } else {
            None
        };
        let remote = Arc::new(security::Remote::new(config.clone(), tls));
        Ok(Self {
            config: Arc::new(config),
            store: Arc::new(store),
            remote,
            identity_workers: Arc::new(tokio::sync::Semaphore::new(8)),
            monitor_runtime: Arc::new(std::sync::Mutex::new(json!({}))),
            monitor_db,
            federation: Arc::new(federation::Runtime::default()),
        })
    }
}
#[derive(Clone, Debug)]
pub struct Principal {
    pub name: String,
    pub sysop: bool,
    pub profile: String,
}
pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
pub fn expiry(seconds: u32) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(seconds.into()))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
pub fn expired(time: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(time).map_or(true, |t| t <= chrono::Utc::now())
}
pub fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}
pub fn array(v: &Value, key: &str) -> Vec<Value> {
    v.get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}
pub fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= 63
        && bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
pub fn required(v: &Value, keys: &[&str]) -> Result<()> {
    for key in keys {
        if s(v, key).trim().is_empty() {
            return Err(Error::bad(format!("{key} is required")));
        }
    }
    Ok(())
}
pub fn digest(data: impl AsRef<[u8]>) -> String {
    Sha256::digest(data.as_ref())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn selected(v: &Value, key: &str, name: &str) -> bool {
    let a = array(v, key);
    a.is_empty() || a.iter().any(|v| v == name)
}
pub fn page(mut rows: Vec<Value>, request: &Value, key: &str) -> Result<Value> {
    let p = if request["pagination"].is_object() {
        &request["pagination"]
    } else {
        request
    };
    let field = p["sortField"].as_str().unwrap_or("createdAt");
    let direction = p["direction"].as_str().unwrap_or("ASC");
    if direction != "ASC" && direction != "DESC" {
        return Err(Error::bad("Invalid sort direction"));
    }
    rows.sort_by(|a, b| {
        let cmp = match (a[field].as_f64(), b[field].as_f64()) {
            (Some(a), Some(b)) => a.total_cmp(&b),
            _ => a[field].to_string().cmp(&b[field].to_string()),
        };
        cmp.then_with(|| a.to_string().cmp(&b.to_string()))
    });
    if direction == "DESC" {
        rows.reverse()
    };
    let count = rows.len();
    let size = p["size"].as_u64().unwrap_or(1000);
    let number = p["page"].as_u64().unwrap_or(0);
    if size == 0 || size > 1000 {
        return Err(Error::bad("Page size must be 1..1000"));
    }
    let start = number.saturating_mul(size);
    let data = rows
        .into_iter()
        .skip(usize::try_from(start).unwrap_or(usize::MAX))
        .take(size as usize)
        .collect::<Vec<_>>();
    Ok(json!({key:data,"count":count}))
}
pub fn metadata_match(actual: &Value, requirement: &Value) -> Result<bool> {
    if requirement.is_null() {
        return Ok(true);
    }
    let req = requirement
        .as_object()
        .ok_or_else(|| Error::bad("Metadata requirements must be an object"))?;
    for (key, wanted) in req {
        let value = &actual[key];
        if let Some(op) = wanted.as_object() {
            for (operator, operand) in op {
                let pass = match operator.as_str() {
                    "$eq" => value == operand,
                    "$ne" => value != operand,
                    "$in" => operand.as_array().is_some_and(|a| a.contains(value)),
                    "$gt" | "$gte" | "$lt" | "$lte" => match (value.as_f64(), operand.as_f64()) {
                        (Some(v), Some(o)) => match operator.as_str() {
                            "$gt" => v > o,
                            "$gte" => v >= o,
                            "$lt" => v < o,
                            _ => v <= o,
                        },
                        _ => false,
                    },
                    _ => return Err(Error::unsupported("Metadata operator not implemented")),
                };
                if !pass {
                    return Ok(false);
                }
            }
        } else if value != wanted {
            return Ok(false);
        }
    }
    Ok(true)
}
pub fn row(app: &App, bucket: &str, id: &str) -> Result<Value> {
    app.store
        .snapshot()
        .get(bucket)
        .and_then(|t| t.get(id))
        .cloned()
        .ok_or_else(|| Error::new(404, "Record not found"))
}
pub fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}
pub fn reserved_name(name: &str) -> bool {
    config::ROLES.iter().any(|r| r.1 == name)
        || [
            "ServiceRegistry",
            "Authentication",
            "ConsumerAuthorization",
            "DynamicServiceOrchestration",
            "SimpleStoreServiceOrchestration",
            "LocalCloudManager",
            "Sysop",
            "Relay",
            "SmokeClient",
            "RandomDataProducer",
        ]
        .contains(&name)
}
pub fn integer(v: &Value, key: &str, default: u64) -> u64 {
    v[key].as_u64().unwrap_or(default)
}
pub fn own(caller: &Principal, name: &str) -> Result<()> {
    if caller.sysop || caller.name == name {
        Ok(())
    } else {
        Err(Error::denied())
    }
}
pub async fn authorize(
    app: &App,
    caller: &Principal,
    service: &str,
    operation: &str,
) -> Result<()> {
    if caller.sysop {
        return Ok(());
    }
    let result=app.remote.call("ConsumerAuthorization","POST","/consumerauthorization/authorization/verify",&json!({"consumer":caller.name,"provider":app.config.name,"cloud":"LOCAL","targetType":"SERVICE_DEF","target":service,"scope":operation})).await?;
    if result == true {
        Ok(())
    } else {
        Err(Error::denied())
    }
}
