// SPDX-License-Identifier: EPL-2.0
use crate::{Error, Result, valid_name};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::{collections::BTreeMap, fs, path::Path};

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
    /// Onboarding only: manufacturer CA(s) of bootstrap certificates and their CRL, trusted for inbound TLS only.
    #[serde(default)]
    pub bootstrap_ca: Option<String>,
    #[serde(default)]
    pub bootstrap_crl: Option<String>,
    #[serde(default)]
    pub messaging: Option<arrowhead_messaging_rust::Config>,
    #[serde(default)]
    pub federation: Option<crate::federation::Config>,
    #[serde(default)]
    pub crl_publish_file: Option<String>,
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
    pub ca_certificate: String,
    #[serde(default)]
    pub ca_signing_key: String,
    #[serde(default)]
    pub register: bool,
    #[serde(default)]
    pub advertise_address: String,
    #[serde(default)]
    pub advertise_port: u16,
    #[serde(default)]
    pub upstreams: BTreeMap<String, String>,
    /// DataManager: dataHistorian (SenML) records older than this many days are deleted, as in the Go DataManager
    /// (retentionDays, default 30, 1..3650).
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    /// DataManager: at most this many dataHistorian records are kept, the oldest received are deleted first (default
    /// 5000, 1..1000000). The state is held in memory (about 4-7 KiB per record) and rewritten on every put; unbounded,
    /// it was OOM-killed under a 256 MiB limit.
    #[serde(default = "default_max_senml_records")]
    pub max_senml_records: usize,
}
pub const DEFAULT_RETENTION_DAYS: u32 = 30;
pub const DEFAULT_MAX_SENML_RECORDS: usize = 5_000;
fn default_retention_days() -> u32 {
    DEFAULT_RETENTION_DAYS
}
fn default_max_senml_records() -> usize {
    DEFAULT_MAX_SENML_RECORDS
}
pub const ROLES: [(&str, &str, &str); 15] = [
    ("blacklist", "Blacklist", "/blacklist"),
    ("configuration", "Configuration", "/configuration"),
    ("datamanager", "DataManager", "/datamanager"),
    ("timemanager", "TimeManager", "/timemanager"),
    ("aigym", "AIGym", "/aigym"),
    ("eventhandler", "EventHandler", "/eventhandler"),
    (
        "deviceqosevaluator",
        "DeviceQoSEvaluator",
        "/deviceqosevaluator",
    ),
    (
        "plantdescriptionengine",
        "PlantDescriptionEngine",
        "/plantdescriptionengine",
    ),
    ("choreographer", "Choreographer", "/choreographer"),
    (
        "certificateauthority",
        "CertificateAuthority",
        "/certificate-authority",
    ),
    ("sysmonitor", "SysMonitor", "/sysmonitor"),
    ("onboarding", "Onboarding", "/onboarding"),
    ("translationmanager", "TranslationManager", "/translation"),
    ("gatekeeper", "Gatekeeper", "/gatekeeper"),
    ("gatetunnel", "GateTunnel", "/gatetunnel"),
];
impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let mut c: Self = serde_json::from_slice(&fs::read(path)?)?;
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&mut self) -> Result<()> {
        if let Some(federation) = &self.federation {
            federation.validate(&self.role, &self.cloud_suffix)?;
        }
        if let Some(messaging) = &self.messaging {
            messaging.validate().map_err(Error::bad)?;
        }
        let role = ROLES
            .iter()
            .find(|r| r.0 == self.role)
            .ok_or_else(|| Error::bad("Unknown support role"))?;
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
        if self.register && (self.advertise_address.is_empty() || self.advertise_port == 0) {
            return Err(Error::bad("Registration needs advertised address and port"));
        }
        if self.role != "certificateauthority"
            && (!self.ca_certificate.is_empty()
                || !self.ca_signing_key.is_empty()
                || self.crl_publish_file.is_some())
        {
            return Err(Error::bad(
                "CA signing material belongs only to CertificateAuthority",
            ));
        }
        if (self.bootstrap_ca.is_some() || self.bootstrap_crl.is_some())
            && (self.role != "onboarding"
                || self.bootstrap_ca.is_none()
                || self.bootstrap_crl.is_none()
                || self.crl_file.is_none())
        {
            return Err(Error::bad(
                "Bootstrap trust belongs only to Onboarding and needs bootstrapCa, bootstrapCrl and crlFile",
            ));
        }
        if !(1..=3650).contains(&self.retention_days) {
            return Err(Error::bad("retentionDays must be 1..3650"));
        }
        if !(1..=1_000_000).contains(&self.max_senml_records) {
            return Err(Error::bad("maxSenmlRecords must be 1..1000000"));
        }
        for name in &self.management_whitelist {
            if !valid_name(name) {
                return Err(Error::bad("Invalid management whitelist"));
            }
        }
        for name in self.upstreams.keys() {
            if !valid_name(name) {
                return Err(Error::bad("Invalid upstream system name"));
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
