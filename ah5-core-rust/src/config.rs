// SPDX-License-Identifier: EPL-2.0
use crate::{Error, Result, valid_name};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Seed {
    pub system_name: String,
    pub password_file: String,
    #[serde(default)]
    pub sysop: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub role: String,
    #[serde(default)]
    pub name: String,
    pub cloud_suffix: String,
    /// Listening address `host:port`; optional, see `crate::listen` for the default and overrides.
    #[serde(default)]
    pub listen: String,
    pub certificate: String,
    pub private_key: String,
    pub ca: String,
    pub state: String,
    #[serde(default)]
    pub crl_file: Option<String>,
    #[serde(default)]
    pub messaging: Option<arrowhead_messaging_rust::Config>,
    #[serde(default)]
    pub intercloud_enabled: bool,
    #[serde(default)]
    pub password_file: String,
    #[serde(default)]
    pub authentication_url: String,
    #[serde(default)]
    pub registry_url: String,
    #[serde(default)]
    pub authorization_url: String,
    #[serde(default)]
    pub management_whitelist: Vec<String>,
    #[serde(default)]
    pub bootstrap_identities: Vec<Seed>,
    #[serde(default)]
    pub discovery_direct_access: Vec<String>,
    #[serde(default = "identity_ttl")]
    pub identity_ttl: u32,
    #[serde(default = "token_ttl")]
    pub token_ttl: u32,
    #[serde(default)]
    pub token_secret_file: String,
    #[serde(default)]
    pub signing_key: String,
    #[serde(default)]
    pub register: bool,
    #[serde(default)]
    pub advertise_address: String,
    #[serde(default)]
    pub advertise_port: u16,
    #[serde(default)]
    pub upstreams: BTreeMap<String, String>,
    // Blacklist enforcement (J12/J17): with upstreams.Blacklist set, every requester except Sysop, this system, Blacklist
    // and blacklistExclude is checked with Blacklist check; while Blacklist cannot be reached the request is refused,
    // unless blacklistOptional is set. The Go and Java counterparts are blacklistURL and enable.blacklist.filter.
    #[serde(default)]
    pub blacklist_exclude: Vec<String>,
    #[serde(default)]
    pub blacklist_optional: bool,
    // DynamicServiceOrchestration integrations, off by default like the Java enable.translation, enable.qos,
    // enable.blacklist.filter and force.blacklist.filter. TranslationManager, qualityEvaluation and Blacklist are found
    // by ServiceRegistry lookup; blacklistExclude also exempts providers from the candidate filter.
    #[serde(default)]
    pub translation_enabled: bool,
    #[serde(default)]
    pub qos_enabled: bool,
    #[serde(default)]
    pub blacklist_filter: bool,
    #[serde(default = "forced")]
    pub blacklist_filter_forced: bool,
}
fn forced() -> bool {
    true
}
fn identity_ttl() -> u32 {
    3600
}
fn token_ttl() -> u32 {
    600
}
pub const ROLES: [(&str, &str, &str); 5] = [
    ("serviceregistry", "ServiceRegistry", "/serviceregistry"),
    ("authentication", "Authentication", "/authentication"),
    (
        "consumer-authorization",
        "ConsumerAuthorization",
        "/consumerauthorization",
    ),
    (
        "serviceorchestration-dynamic",
        "DynamicServiceOrchestration",
        "/serviceorchestration",
    ),
    (
        "serviceorchestration-simple",
        "SimpleStoreServiceOrchestration",
        "/serviceorchestration",
    ),
];
impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let mut c: Self = serde_json::from_slice(&fs::read(path)?)?;
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&mut self) -> Result<()> {
        if let Some(messaging) = &self.messaging {
            messaging.validate().map_err(Error::bad)?;
        }
        let role = ROLES
            .iter()
            .find(|r| r.0 == self.role)
            .ok_or_else(|| Error::bad("Unknown core role"))?;
        if self.name.is_empty() {
            self.name = role.1.into()
        }
        self.listen = crate::listen::resolve(
            &self.role,
            &self.listen,
            std::env::var(crate::listen::PORT_ENV).ok().as_deref(),
        )?;
        if !valid_name(&self.name)
            || self.cloud_suffix.split('.').count() != 4
            || !self.cloud_suffix.ends_with(".arrowhead.eu")
            || self.state.is_empty()
        {
            return Err(Error::bad("Invalid identity, cloud suffix or state path"));
        }
        if self.identity_ttl < 10
            || self.identity_ttl > 86400
            || self.token_ttl < 1
            || self.token_ttl > 86400
        {
            return Err(Error::bad("Invalid token lifetime"));
        }
        if self.register && (self.advertise_address.is_empty() || self.advertise_port == 0) {
            return Err(Error::bad("Registration needs advertised address and port"));
        }
        if self.role != "authentication" && !self.bootstrap_identities.is_empty() {
            return Err(Error::bad(
                "Bootstrap identities belong only to Authentication",
            ));
        }
        for name in &self.management_whitelist {
            if !valid_name(name) {
                return Err(Error::bad("Invalid management whitelist"));
            }
        }
        for name in &self.blacklist_exclude {
            if !valid_name(name) {
                return Err(Error::bad("Invalid blacklist exclusion"));
            }
        }
        for raw in [
            &self.authentication_url,
            &self.registry_url,
            &self.authorization_url,
        ]
        .into_iter()
        .chain(self.upstreams.values())
        {
            if !raw.is_empty() {
                let u = url::Url::parse(raw).map_err(|_| Error::bad("Invalid authority URL"))?;
                if u.scheme() != "https"
                    || u.host_str().is_none()
                    || !u.username().is_empty()
                    || u.password().is_some()
                    || u.query().is_some()
                    || u.fragment().is_some()
                    || u.path() != "/"
                {
                    return Err(Error::bad("Authority requires a bare HTTPS origin"));
                }
            }
        }
        Ok(())
    }
    pub fn base(&self) -> &'static str {
        ROLES
            .iter()
            .find(|r| r.0 == self.role)
            .expect("validated role")
            .2
    }
}
pub fn secret(path: &str) -> Result<Vec<u8>> {
    let meta = fs::metadata(path)?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
        return Err(Error::bad("Private file must have owner-only permissions"));
    }
    let data = fs::read(path)?;
    if data.is_empty() {
        return Err(Error::bad("Empty secret"));
    };
    Ok(data)
}
