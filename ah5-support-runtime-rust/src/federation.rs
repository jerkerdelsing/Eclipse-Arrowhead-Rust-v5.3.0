// SPDX-License-Identifier: EPL-2.0
pub mod crypto;
pub mod gatekeeper;
pub mod relay;
pub mod tunnel;
use crate::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub relay_common_name: String,
    pub certificate: String,
    pub private_key: String,
    pub ca: String,
    pub crl_files: Vec<String>,
    /// Cloud -> organisation. Remote organisations are explicit, never inferred.
    pub peers: BTreeMap<String, String>,
    /// SOS-7 (2026-11-10): neighbours of another organisation this cloud's consumers may reach, "Cloud|Organisation".
    /// Empty by default: inter-cloud discovery and negotiation stay within the own organisation.
    #[serde(default)]
    pub foreign_targets: Vec<String>,
    pub min_port: u16,
    pub max_port: u16,
}
impl Config {
    pub fn validate(&self, role: &str, suffix: &str) -> Result<()> {
        let own = suffix.split('.').next().unwrap_or("");
        let own_organisation = suffix.split('.').nth(1).unwrap_or("");
        if self.foreign_targets.len() > 32
            || self.foreign_targets.iter().any(|entry| {
                let mut part = entry.split('|');
                match (part.next(), part.next(), part.next()) {
                    (Some(cloud), Some(org), None) => {
                        cloud == own
                            || org == own_organisation
                            || self.peers.get(cloud).map(String::as_str) != Some(org)
                    }
                    _ => true,
                }
            })
        {
            return Err(Error::bad(
                "foreignTargets: each entry must be Cloud|Organisation of a peer of another organisation",
            ));
        }
        if !["gatekeeper", "gatetunnel"].contains(&role)
            || self.port == 0
            || self.host.is_empty()
            || self.host.len() > 253
            || !self
                .host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
            || self.relay_common_name.is_empty()
            || self.relay_common_name.contains(['\n', '\r', '\0'])
            || self.crl_files.is_empty()
            || self.crl_files.len() > 32
            || self.peers.len() > 32
            || self.min_port < 1024
            || self.max_port < self.min_port
            || self.max_port - self.min_port > 99
            || [&self.certificate, &self.private_key, &self.ca]
                .iter()
                .any(|p| p.is_empty())
            || self
                .peers
                .iter()
                .any(|(cloud, org)| !valid_name(cloud) || !valid_name(org) || cloud == own)
        {
            return Err(Error::bad("Invalid explicit federation configuration"));
        }
        Ok(())
    }
}
#[derive(Default)]
pub struct Runtime {
    pub relay: relay::Runtime,
    pub tunnel: tunnel::Runtime,
}
pub fn cloud(app: &App) -> String {
    app.config
        .cloud_suffix
        .split('.')
        .take(2)
        .collect::<Vec<_>>()
        .join("|")
}
/// SOS-7: whether this cloud's consumers may reach the neighbour: own organisation, or listed in foreignTargets.
pub fn target_allowed(app: &App, cloud: &str) -> bool {
    let Some(config) = app.config.federation.as_ref() else {
        return false;
    };
    let own_organisation = app.config.cloud_suffix.split('.').nth(1).unwrap_or("");
    match config.peers.get(cloud) {
        Some(org) => {
            org == own_organisation
                || config
                    .foreign_targets
                    .iter()
                    .any(|entry| *entry == format!("{cloud}|{org}"))
        }
        None => false,
    }
}
pub fn own_cn(app: &App) -> String {
    format!("{}.{}", app.config.name, app.config.cloud_suffix)
}
pub fn peer(app: &App, name: &str, role: &str) -> Result<String> {
    let config = app
        .config
        .federation
        .as_ref()
        .ok_or_else(|| Error::unsupported("Federation is not configured"))?;
    let organisation = config.peers.get(name).ok_or_else(Error::denied)?;
    Ok(format!("{role}.{name}.{organisation}.arrowhead.eu"))
}
pub fn trusted(app: &App, cn: &str) -> bool {
    let parts = cn.split('.').collect::<Vec<_>>();
    let role = if app.config.role == "gatekeeper" {
        "Gatekeeper"
    } else {
        "GateTunnel"
    };
    if parts.len() != 5 || !peer(app, parts[1], role).is_ok_and(|expected| expected == cn) {
        return false;
    }
    app.config.role == "gatetunnel"
        || app
            .store
            .rows("clouds")
            .iter()
            .any(|c| s(c, "name") == parts[1] && s(c, "operator") == parts[2])
}
pub async fn incoming(app: &App, sender: &str, message: &Value) -> Result<Value> {
    if !trusted(app, sender) {
        return Err(Error::denied());
    }
    if app.config.role == "gatetunnel" {
        tunnel::incoming(app, sender, message).await
    } else {
        gatekeeper::incoming(app, sender, message).await
    }
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
    if app.config.role == "gatetunnel" {
        tunnel::handle(app, method, path, req, caller).await
    } else {
        gatekeeper::handle(app, method, path, p, q, req, caller).await
    }
}
