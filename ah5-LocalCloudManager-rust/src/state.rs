use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use tokio::sync::RwLock;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub system_name: String,
    pub credentials: BTreeMap<String, String>,
    pub sysop: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub token: String,
    pub system_name: String,
    pub sysop: bool,
    pub login_time: String,
    pub expiration_time: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Data {
    pub identities: BTreeMap<String, Identity>,
    pub sessions: BTreeMap<String, Session>,
    pub grants: BTreeMap<String, Value>,
    pub authorization_tokens: BTreeMap<String, Value>,
    pub subscriptions: BTreeMap<String, Value>,
    pub routes: BTreeMap<String, Value>,
    pub locks: BTreeMap<String, Value>,
    pub history: Vec<Value>,
    pub data_streams: BTreeMap<String, Vec<Value>>,
    pub counters: BTreeMap<String, u64>,
}

pub struct Store {
    pub data: RwLock<Data>,
    path: PathBuf,
}

impl Store {
    pub async fn load(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_owned();
        let data = match tokio::fs::read(&path).await {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Data::default(),
            Err(error) => return Err(error),
        };
        Ok(Self {
            data: RwLock::new(data),
            path,
        })
    }

    pub async fn save(&self) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let bytes =
            serde_json::to_vec_pretty(&*self.data.read().await).expect("serializable state");
        let temp = self.path.with_extension("tmp");
        tokio::fs::write(&temp, bytes).await?;
        tokio::fs::rename(temp, &self.path).await
    }

    pub async fn next_id(&self, namespace: &str) -> u64 {
        let mut data = self.data.write().await;
        let value = data.counters.entry(namespace.into()).or_default();
        *value += 1;
        *value
    }
}

pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
