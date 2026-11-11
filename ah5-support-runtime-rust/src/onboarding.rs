// SPDX-License-Identifier: EPL-2.0
// Arrowhead 5.2.2 onboarding procedure, following the Java reference (ah5-support-java-spring/Onboarding).
// Each step returns the credential for the next one: bootstrap (manufacturer) certificate -> onboarding (on)
// certificate -> device (de) certificate and registry entry -> per approved hosted system a system (sy)
// certificate and an Authentication identity. The CertificateAuthority signs everything; Onboarding holds no CA key.
// Private keys and passwords generated here are returned to the device once and never stored or logged.
use crate::*;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use openssl::{
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey},
    rsa::Rsa,
    x509::{X509, X509NameBuilder, X509Req},
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Principal profile of a TLS peer that only Onboarding admits: a bootstrap, on or de certificate.
pub const DEVICE: &str = "device";
const MAX_SYSTEMS: usize = 32;
const CA: &str = "CertificateAuthority";
const ENROLLMENTS: &str = "enrollments";
const SYSTEMS: &str = "onboarded-systems";
/// Core and support system and operator names (Java security finding M1): never a device or an onboarded system.
const RESERVED: [&str; 25] = [
    "ServiceRegistry",
    "Authentication",
    "ConsumerAuthorization",
    "DynamicServiceOrchestration",
    "SimpleStoreServiceOrchestration",
    "Blacklist",
    "TranslationManager",
    "DeviceQoSEvaluator",
    "Onboarding",
    "CertificateAuthority",
    "DataManager",
    "TimeManager",
    "EventHandler",
    "PlantDescriptionEngine",
    "Configuration",
    "Choreographer",
    "SysMonitor",
    "Gatekeeper",
    "GateTunnel",
    "AIGym",
    "LocalCloudManager",
    "Sysop",
    "RandomDataProducer",
    "SmokeClient",
    "Relay",
];

/// The verified TLS client certificate (DER) and the client's address, attached per connection by Onboarding only.
#[derive(Clone, Debug)]
pub struct PeerCertificate {
    pub der: Arc<Vec<u8>>,
    pub address: String,
}

/// TLS admission. Every role admits only sy/op peers of the local cloud; Onboarding additionally admits the
/// credentials of the procedure (bootstrap, on, de) as a restricted DEVICE principal that web.rs confines to
/// the onboarding service and this module confines to the step its certificate belongs to.
pub fn admit(role: &str, cert: &[u8], suffix: &str) -> Result<Principal> {
    match security::peer(cert, suffix) {
        Ok(peer) => Ok(peer),
        Err(e) if role != "onboarding" => Err(e),
        Err(_) => Ok(Principal {
            name: String::new(),
            sysop: false,
            profile: DEVICE.into(),
        }),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle(
    app: &App,
    method: &str,
    path: &str,
    p: &BTreeMap<String, String>,
    _q: &Value,
    req: &Value,
    caller: &Principal,
    peer: Option<&PeerCertificate>,
) -> Result<(u16, Value)> {
    if path.contains("/mgmt/") {
        return management(app, method, p, path, req, caller).await;
    }
    let peer = peer.ok_or_else(|| Error::new(401, "Client certificate required"))?;
    let step = path.strip_prefix(app.config.base()).unwrap_or(path);
    let value = match step {
        "/certificate/name" => {
            let enrollment = bootstrap(app, peer)?;
            let device = s(&enrollment, "deviceName").to_owned();
            let name = s(req, "commonName");
            if name.trim().is_empty() {
                return Err(Error::bad("commonName is required"));
            }
            let expected = common_name(app, &device);
            if name != expected {
                return Err(Error::new(
                    403,
                    "Requested name does not match enrollment identity",
                ));
            }
            onboarding_certificate(app, &device, generate(&expected)?, peer).await?
        }
        "/certificate/csr" => {
            let enrollment = bootstrap(app, peer)?;
            let device = s(&enrollment, "deviceName").to_owned();
            let encoded = s(req, "certificateSigningRequest");
            let public_key = check_csr(encoded, &common_name(app, &device))?;
            let csr = Csr {
                encoded: encoded.into(),
                public_key,
                private_key: None,
            };
            onboarding_certificate(app, &device, csr, peer).await?
        }
        "/device" => {
            let caller = cloud(app, peer, "on").await?;
            device(app, &caller, req, peer).await?
        }
        "/system" => {
            let caller = cloud(app, peer, "de").await?;
            system(app, &caller, req).await?
        }
        "/device/offboard" => {
            let caller = cloud(app, peer, "de").await?;
            current_device(app, &caller)?;
            offboard(app, &caller.name, &caller.name).await?
        }
        _ => return Err(Error::new(404, "No such onboarding operation")),
    };
    Ok((200, value))
}

// ---- operator side: approve, inspect, off-board and remove devices ----
async fn management(
    app: &App,
    method: &str,
    p: &BTreeMap<String, String>,
    path: &str,
    req: &Value,
    caller: &Principal,
) -> Result<(u16, Value)> {
    let Some(name) = p.get("deviceName") else {
        let entries = app
            .store
            .rows(ENROLLMENTS)
            .iter()
            .map(|e| view(app, e))
            .collect::<Vec<_>>();
        return Ok((200, json!({"count":entries.len(),"entries":entries})));
    };
    require_name(name)?;
    let value = match method {
        "GET" => view(app, &find(app, name)?),
        "PUT" => approve(app, name, req, &caller.name).await?,
        "POST" if path.ends_with("/offboard") => offboard(app, name, &caller.name).await?,
        "DELETE" => remove(app, name, &caller.name).await?,
        _ => return Err(Error::new(404, "No such onboarding management operation")),
    };
    Ok((200, value))
}

async fn approve(app: &App, device: &str, req: &Value, actor: &str) -> Result<Value> {
    let raw = s(req, "bootstrapFingerprint");
    if raw.is_empty() {
        return Err(Error::bad("bootstrapFingerprint is required"));
    }
    let fingerprint = raw.replace(':', "").to_ascii_lowercase();
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::bad(
            "bootstrapFingerprint must be the SHA-256 of the DER certificate (64 hex digits)",
        ));
    }
    let mut systems = Vec::<String>::new();
    for system in array(req, "systems") {
        let system = require_name(system.as_str().unwrap_or(""))?.to_owned();
        if !systems.contains(&system) {
            systems.push(system);
        }
    }
    if systems.is_empty() || systems.len() > MAX_SYSTEMS {
        return Err(Error::bad(format!(
            "Approve 1..{MAX_SYSTEMS} systems for the device"
        )));
    }
    for name in systems.iter().map(String::as_str).chain([device]) {
        if reserved(name) {
            return Err(Error::bad(format!("{name} is a reserved system name")));
        }
    }
    if systems.iter().any(|s| s == device) {
        return Err(Error::bad(format!(
            "A system cannot have the device's name {device}"
        )));
    }
    let (record, fresh) = app.store.update(|db| {
        let t = table(db, ENROLLMENTS);
        for (other, row) in t.iter() {
            if other == device {
                continue;
            }
            let row = normalized(row);
            let mut taken = approved(&row);
            taken.push(other.clone());
            if let Some(name) = systems.iter().map(String::as_str).chain([device]).find(|n| taken.iter().any(|t| t == n)) {
                return Err(Error::bad(format!("{name} is already used by device {other}")));
            }
            if s(&row, "bootstrapFingerprint") == fingerprint {
                return Err(Error::bad(format!(
                    "The bootstrap certificate is already approved for device {other}"
                )));
            }
        }
        let existing = t.get(device).map(normalized);
        let now = now();
        let (record, fresh) = match existing {
            Some(mut row) if s(&row, "state") == "DEVICE_REGISTERED" => {
                if s(&row, "bootstrapFingerprint") != fingerprint {
                    return Err(Error::bad(format!(
                        "Device {device} is onboarded; off-board it before changing its bootstrap certificate"
                    )));
                }
                // keeps the device onboarded; adds or withdraws approvals
                row["approvedSystems"] = json!(systems);
                row["approvedBy"] = actor.into();
                touch(&mut row, &format!("approved systems updated by {actor}"));
                (row, false)
            }
            existing => {
                let approved_at = existing.as_ref().map_or_else(|| now.clone().into(), |r| r["approvedAt"].clone());
                let mut row = json!({"deviceName":device,"bootstrapFingerprint":fingerprint,"approvedSystems":systems,"state":"APPROVED","onboardingCertificateId":null,"onboardingCertificateSerial":null,"deviceCertificateId":null,"deviceCertificateSerial":null,"deviceCertificateExpiresAt":null,"approvedBy":actor,"approvedAt":approved_at});
                touch(&mut row, &format!("approved by {actor}"));
                (row, true)
            }
        };
        t.insert(device.into(), record.clone());
        if fresh {
            table(db, SYSTEMS).retain(|_, r| s(r, "deviceName") != device);
        }
        Ok((record, fresh))
    })?;
    if fresh {
        // a re-approved device may host systems that were blacklisted when it was off-boarded
        let names = systems
            .iter()
            .map(|n| security::encode(n))
            .collect::<Vec<_>>()
            .join(",");
        let (mut done, mut failed) = (Vec::new(), Vec::new());
        best(
            &format!("unblacklist {systems:?}"),
            app.remote.call(
                "Blacklist",
                "DELETE",
                &format!("/blacklist/mgmt/remove?names={names}"),
                &Value::Null,
            ),
            &mut done,
            &mut failed,
        )
        .await;
    }
    Ok(view(app, &record))
}

/// Withdraws everything the procedure created: registry entries, identities, certificates; blacklists the systems.
async fn offboard(app: &App, device: &str, actor: &str) -> Result<Value> {
    let enrollment = find(app, device)?;
    let (mut done, mut failed) = (Vec::new(), Vec::new());
    for system in issued(app, device) {
        let name = s(&system, "systemName").to_owned();
        let id = system["certificateId"].as_u64().unwrap_or(0);
        best(
            &format!("ServiceRegistry system-remove {name}"),
            remove_names(
                app,
                "ServiceRegistry",
                "/serviceregistry/mgmt/systems",
                &name,
            ),
            &mut done,
            &mut failed,
        )
        .await;
        best(
            &format!("Authentication identity-mgmt-remove {name}"),
            remove_names(
                app,
                "Authentication",
                "/authentication/mgmt/identities",
                &name,
            ),
            &mut done,
            &mut failed,
        )
        .await;
        best(
            &format!("CertificateAuthority revoke-certificate {id} ({name})"),
            revoke(app, id),
            &mut done,
            &mut failed,
        )
        .await;
        let entry = json!({"entities":[{"systemName":name,"expiresAt":system["certificateExpiresAt"],"reason":format!("Off-boarded from device {device} by {actor}")}]});
        best(
            &format!("Blacklist create {name}"),
            app.remote
                .call("Blacklist", "POST", "/blacklist/mgmt/create", &entry),
            &mut done,
            &mut failed,
        )
        .await;
        app.store.update(|db| {
            table(db, SYSTEMS).remove(&name);
            Ok(())
        })?;
    }
    best(
        &format!("ServiceRegistry device-remove {device}"),
        remove_names(
            app,
            "ServiceRegistry",
            "/serviceregistry/mgmt/devices",
            device,
        ),
        &mut done,
        &mut failed,
    )
    .await;
    for key in ["deviceCertificateId", "onboardingCertificateId"] {
        if let Some(id) = enrollment[key].as_u64() {
            best(
                &format!("CertificateAuthority revoke-certificate {id} ({device})"),
                revoke(app, id),
                &mut done,
                &mut failed,
            )
            .await;
        }
    }
    let message = if failed.is_empty() {
        format!("off-boarded by {actor}")
    } else {
        format!("off-boarded by {actor}; failed: {}", failed.join("; "))
    };
    update(app, device, |row| {
        row["state"] = "OFFBOARDED".into();
        for key in [
            "onboardingCertificateId",
            "onboardingCertificateSerial",
            "deviceCertificateId",
            "deviceCertificateSerial",
        ] {
            row[key] = Value::Null;
        }
        touch(row, &message);
        Ok(())
    })?;
    eprintln!(
        "Off-boarded device {device} by {actor}: {} steps done, {} failed",
        done.len(),
        failed.len()
    );
    Ok(json!({"deviceName":device,"completed":done,"failed":failed}))
}

/// Removes the approval; an onboarded device is off-boarded first.
async fn remove(app: &App, device: &str, actor: &str) -> Result<Value> {
    let enrollment = find(app, device)?;
    let report =
        if s(&enrollment, "state") == "DEVICE_REGISTERED" || !issued(app, device).is_empty() {
            offboard(app, device, actor).await?
        } else {
            json!({"deviceName":device,"completed":[],"failed":[]})
        };
    app.store.update(|db| {
        table(db, ENROLLMENTS).remove(device);
        Ok(())
    })?;
    Ok(report)
}

// ---- device side: steps 1..3 ----
struct Csr {
    encoded: String,
    public_key: String,
    private_key: Option<String>,
}
struct Signed {
    id: u64,
    chain: Vec<Value>,
    serial: String,
    expires_at: String,
}
/// An on or de certificate of the local cloud: the device name and its decimal serial number.
struct Cloud {
    name: String,
    serial: String,
}

async fn onboarding_certificate(
    app: &App,
    device: &str,
    csr: Csr,
    peer: &PeerCertificate,
) -> Result<Value> {
    let services = discover(app).await?; // Resolve dependencies before issuing any certificate.
    let signed = sign(
        app,
        &csr.encoded,
        "on",
        &certificate_addresses(std::slice::from_ref(&peer.address)),
    )
    .await?;
    let fingerprint = digest(peer.der.as_slice());
    let previous = update(app, device, |row| {
        if s(row, "state") == "OFFBOARDED" || s(row, "bootstrapFingerprint") != fingerprint {
            return Err(Error::new(
                403,
                "Enrollment changed during the onboarding step",
            ));
        }
        let previous = row["onboardingCertificateId"].as_u64();
        row["onboardingCertificateId"] = signed.id.into();
        row["onboardingCertificateSerial"] = signed.serial.clone().into();
        touch(row, "onboarding certificate issued");
        Ok(previous)
    });
    let previous = match previous {
        Ok(previous) => previous,
        Err(e) => {
            quietly(
                "revoke unused onboarding certificate",
                revoke(app, signed.id),
            )
            .await;
            return Err(e);
        }
    };
    if let Some(previous) = previous {
        quietly(
            "revoke previous onboarding certificate",
            revoke(app, previous),
        )
        .await;
    }
    Ok(
        json!({"certificateChain":signed.chain,"onboardingCertificate":result(&signed,"ON_BOARDING",&csr),"services":services,
        "nextStep":"POST /onboarding/device with this onboarding certificate to obtain the device certificate and register the device."}),
    )
}

async fn device(app: &App, caller: &Cloud, req: &Value, peer: &PeerCertificate) -> Result<Value> {
    let device = caller.name.as_str();
    let enrollment = find(app, device)?;
    if s(&enrollment, "state") == "OFFBOARDED" {
        return Err(Error::new(403, format!("Device {device} was off-boarded")));
    }
    if s(&enrollment, "onboardingCertificateSerial") != caller.serial {
        return Err(Error::new(
            403,
            format!("Only the onboarding certificate issued last for {device} is accepted"),
        ));
    }
    let csr = csr_or_generate(
        s(req, "certificateSigningRequest"),
        &common_name(app, device),
    )?;
    let mut addresses = array(req, "addresses")
        .iter()
        .map(|a| {
            a.as_str()
                .map(String::from)
                .ok_or_else(|| Error::bad("addresses must be strings"))
        })
        .collect::<Result<Vec<_>>>()?;
    if addresses.is_empty() {
        addresses.push(peer.address.clone());
    }
    let signed = sign(app, &csr.encoded, "de", &certificate_addresses(&addresses)).await?;
    if let Some(previous) = enrollment["deviceCertificateId"].as_u64() {
        quietly("revoke previous device certificate", revoke(app, previous)).await;
    }
    let mut metadata = if req["metadata"].is_object() {
        req["metadata"].clone()
    } else {
        json!({})
    };
    metadata["onboarding"] = json!({"bootstrapFingerprint":enrollment["bootstrapFingerprint"],"deviceCertificateId":signed.id});
    let entry = json!({"devices":[{"name":device,"metadata":metadata,"addresses":addresses}]});
    if app
        .remote
        .call(
            "ServiceRegistry",
            "POST",
            "/serviceregistry/mgmt/devices",
            &entry,
        )
        .await
        .is_err()
    {
        // an earlier run registered the device already (it may host systems): update the entry
        if let Err(e) = app
            .remote
            .call(
                "ServiceRegistry",
                "PUT",
                "/serviceregistry/mgmt/devices",
                &entry,
            )
            .await
        {
            quietly("revoke device certificate", revoke(app, signed.id)).await;
            return Err(e);
        }
    }
    let record = update(app, device, |row| {
        row["deviceCertificateId"] = signed.id.into();
        row["deviceCertificateSerial"] = signed.serial.clone().into();
        row["deviceCertificateExpiresAt"] = signed.expires_at.clone().into();
        row["state"] = "DEVICE_REGISTERED".into();
        touch(row, "device registered");
        Ok(row.clone())
    })?;
    eprintln!(
        "Device {device} onboarded (device certificate {})",
        signed.id
    );
    Ok(
        json!({"deviceName":device,"certificateChain":signed.chain,"deviceCertificate":result(&signed,"DEVICE",&csr),"approvedSystems":approved(&record),
        "nextStep":"POST /onboarding/system with this device certificate once per approved system to obtain its system certificate and identity."}),
    )
}

async fn system(app: &App, caller: &Cloud, req: &Value) -> Result<Value> {
    let device = caller.name.as_str();
    let enrollment = current_device(app, caller)?;
    let system = require_name(s(req, "systemName"))?.to_owned();
    if !approved(&enrollment).contains(&system) {
        return Err(Error::new(
            403,
            format!("{system} is not approved for device {device}"),
        ));
    }
    let existing = app
        .store
        .snapshot()
        .get(SYSTEMS)
        .and_then(|t| t.get(&system))
        .cloned();
    if existing
        .as_ref()
        .is_some_and(|e| s(e, "deviceName") != device)
    {
        return Err(Error::new(
            403,
            format!("{system} is hosted by another device"),
        ));
    }
    let services = discover(app).await?;
    let csr = csr_or_generate(
        s(req, "certificateSigningRequest"),
        &common_name(app, &system),
    )?;
    let signed = sign(app, &csr.encoded, "sy", &[]).await?;
    if let Some(previous) = &existing {
        // re-issue: the earlier certificate and password are withdrawn
        quietly(
            "revoke previous system certificate",
            revoke(app, previous["certificateId"].as_u64().unwrap_or(0)),
        )
        .await;
        quietly(
            "remove previous identity",
            remove_names(
                app,
                "Authentication",
                "/authentication/mgmt/identities",
                &system,
            ),
        )
        .await;
    }
    let mut bytes = [0u8; 24];
    openssl::rand::rand_bytes(&mut bytes)?;
    let password = URL_SAFE_NO_PAD.encode(bytes);
    let identity = json!({"authenticationMethod":"PASSWORD","identities":[{"systemName":system,"credentials":{"password":password},"sysop":false}]});
    if let Err(e) = app
        .remote
        .call(
            "Authentication",
            "POST",
            "/authentication/mgmt/identities",
            &identity,
        )
        .await
    {
        quietly("revoke system certificate", revoke(app, signed.id)).await;
        return Err(e);
    }
    app.store.update(|db| {
        table(db, SYSTEMS).insert(system.clone(), json!({"systemName":system,"deviceName":device,"certificateId":signed.id,"certificateExpiresAt":signed.expires_at,"issuedAt":now()}));
        Ok(())
    })?;
    eprintln!(
        "System {system} on device {device} onboarded (system certificate {})",
        signed.id
    );
    Ok(
        json!({"systemName":system,"deviceName":device,"certificateChain":signed.chain,"systemCertificate":result(&signed,"SYSTEM",&csr),
        "authenticationMethod":"PASSWORD","credentials":{"password":password},"services":services,
        "nextStep":format!("Log in at Authentication identity-login as {system} with these credentials and the system certificate, register the system with systemDiscovery register (deviceName {device}) and its services with serviceDiscovery register, then consume services through orchestration. Store the password securely; Onboarding does not keep it.")}),
    )
}

// ---- authentication of the device credentials ----
/// Step 1: the SHA-256 fingerprint of the bootstrap certificate must belong to an approved, not off-boarded device.
fn bootstrap(app: &App, peer: &PeerCertificate) -> Result<Value> {
    if issued_by_cloud(app, &peer.der)? {
        return Err(Error::new(
            403,
            "A bootstrap certificate is required for this step",
        ));
    }
    let fingerprint = digest(peer.der.as_slice());
    let enrollment = app
        .store
        .rows(ENROLLMENTS)
        .iter()
        .map(normalized)
        .find(|r| s(r, "bootstrapFingerprint") == fingerprint)
        .ok_or_else(|| Error::new(401, "Certificate is not approved for enrollment"))?;
    if s(&enrollment, "state") == "OFFBOARDED" {
        return Err(Error::new(
            403,
            format!(
                "Device {} was off-boarded; an operator must approve it again",
                s(&enrollment, "deviceName")
            ),
        ));
    }
    Ok(enrollment)
}
/// Steps 2 and 3: an on or de certificate of this cloud's CA that the CertificateAuthority still reports GOOD.
async fn cloud(app: &App, peer: &PeerCertificate, expected: &str) -> Result<Cloud> {
    let required = || {
        Error::new(
            403,
            format!(
                "A {} certificate is required for this step",
                if expected == "on" {
                    "ON_BOARDING"
                } else {
                    "DEVICE"
                }
            ),
        )
    };
    if !issued_by_cloud(app, &peer.der)? {
        return Err(required());
    }
    let (cn, profile) = security::subject(&peer.der).map_err(|_| required())?;
    if profile != expected {
        return Err(required());
    }
    let name = cn
        .strip_suffix(&format!(".{}", app.config.cloud_suffix))
        .ok_or_else(|| Error::new(403, "Certificate belongs to another cloud"))?;
    let name = require_name(name).map_err(|_| required())?.to_owned();
    let status = app
        .remote
        .call(
            CA,
            "POST",
            "/certificate-authority/checkCertificate",
            &json!({"certificate":STANDARD.encode(peer.der.as_slice())}),
        )
        .await
        .map_err(|e| {
            Error::new(
                401,
                format!("Certificate status unavailable: {}", e.message),
            )
        })?;
    if s(&status, "status") != "GOOD" {
        return Err(Error::new(
            403,
            format!(
                "Certificate is {} at the CertificateAuthority",
                s(&status, "status")
            ),
        ));
    }
    let serial = X509::from_der(&peer.der)?
        .serial_number()
        .to_bn()?
        .to_dec_str()?
        .to_string();
    Ok(Cloud { name, serial })
}
fn current_device(app: &App, caller: &Cloud) -> Result<Value> {
    let enrollment = find(app, &caller.name)?;
    if s(&enrollment, "state") != "DEVICE_REGISTERED" {
        return Err(Error::new(
            403,
            format!("Device {} is not onboarded", caller.name),
        ));
    }
    if s(&enrollment, "deviceCertificateSerial") != caller.serial {
        return Err(Error::new(
            403,
            format!(
                "Only the device certificate issued last for {} is accepted",
                caller.name
            ),
        ));
    }
    Ok(enrollment)
}
fn issued_by_cloud(app: &App, der: &[u8]) -> Result<bool> {
    let cert = X509::from_der(der)?;
    let issuer = cert.issuer_name().to_der()?;
    for root in X509::stack_from_pem(&std::fs::read(&app.config.ca)?)? {
        if root.subject_name().to_der()? == issuer && cert.verify(root.public_key()?.as_ref())? {
            return Ok(true);
        }
    }
    Ok(false)
}

// ---- CSRs ----
fn generate(common_name: &str) -> Result<Csr> {
    let key = PKey::from_rsa(Rsa::generate(3072)?)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)?;
    let mut req = X509Req::builder()?;
    req.set_subject_name(&name.build())?;
    req.set_pubkey(&key)?;
    req.sign(&key, MessageDigest::sha256())?;
    Ok(Csr {
        encoded: STANDARD.encode(req.build().to_der()?),
        public_key: STANDARD.encode(key.public_key_to_der()?),
        private_key: Some(STANDARD.encode(key.private_key_to_pkcs8()?)),
    })
}
fn csr_or_generate(encoded: &str, expected: &str) -> Result<Csr> {
    if encoded.trim().is_empty() {
        return generate(expected);
    }
    Ok(Csr {
        public_key: check_csr(encoded, expected)?,
        encoded: encoded.into(),
        private_key: None,
    })
}
/// Validates a client CSR (RSA 2048..8192, SHA-2 with RSA, proof of possession, exactly the expected CN) and
/// returns its public key (Base64 DER).
pub fn check_csr(encoded: &str, expected: &str) -> Result<String> {
    if encoded.trim().is_empty() || encoded.len() > 32768 {
        return Err(Error::bad(
            "CSR must be Base64 DER PKCS#10, at most 32768 characters",
        ));
    }
    let invalid = || Error::bad("Invalid CSR: require a signed RSA PKCS#10 with one matching CN");
    let der = STANDARD.decode(encoded).map_err(|_| invalid())?;
    // sha256WithRSAEncryption, sha384WithRSAEncryption, sha512WithRSAEncryption
    const RSA_SHA2: [u8; 8] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01];
    let oid = signature_algorithm(&der).ok_or_else(invalid)?;
    if oid.len() != 9 || oid[..8] != RSA_SHA2 || !(0x0b..=0x0d).contains(&oid[8]) {
        return Err(invalid());
    }
    let req = X509Req::from_der(&der).map_err(|_| invalid())?;
    let key = req.public_key().map_err(|_| invalid())?;
    if key.id() != Id::RSA
        || !(2048..=8192).contains(&key.bits())
        || !req.verify(&key).unwrap_or(false)
    {
        return Err(invalid());
    }
    let names = req
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .collect::<Vec<_>>();
    if names.len() != 1 || names[0].data().to_string().ok().as_deref() != Some(expected) {
        return Err(Error::new(
            403,
            format!("CSR common name must be {expected}"),
        ));
    }
    Ok(STANDARD.encode(key.public_key_to_der()?))
}
/// The OID of CertificationRequest.signatureAlgorithm (RFC 2986), read from the DER encoding.
fn signature_algorithm(der: &[u8]) -> Option<&[u8]> {
    fn tlv<'a>(input: &mut &'a [u8]) -> Option<(u8, &'a [u8])> {
        let (&tag, rest) = input.split_first()?;
        let (&first, mut rest) = rest.split_first()?;
        let len = if first < 0x80 {
            first as usize
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 || count > 4 || rest.len() < count {
                return None;
            }
            let len = rest[..count]
                .iter()
                .fold(0usize, |n, b| n << 8 | *b as usize);
            rest = &rest[count..];
            len
        };
        if rest.len() < len {
            return None;
        }
        *input = &rest[len..];
        Some((tag, &rest[..len]))
    }
    let mut outer = der;
    let (0x30, mut request) = tlv(&mut outer)? else {
        return None;
    };
    let (0x30, _) = tlv(&mut request)? else {
        return None;
    };
    let (0x30, mut algorithm) = tlv(&mut request)? else {
        return None;
    };
    let (0x06, oid) = tlv(&mut algorithm)? else {
        return None;
    };
    Some(oid)
}

// ---- consumed operations of the CertificateAuthority, ServiceRegistry, Authentication and Blacklist ----
async fn sign(app: &App, csr: &str, profile: &str, addresses: &[String]) -> Result<Signed> {
    let mut body = json!({"encodedCSR":csr,"profile":profile});
    if !addresses.is_empty() {
        body["addresses"] = json!(addresses);
    }
    let r = app
        .remote
        .call(CA, "POST", "/certificate-authority/sign", &body)
        .await?;
    let chain = array(&r, "certificateChain");
    match (r["id"].as_u64(), chain.first()) {
        (Some(id), Some(Value::String(_))) => Ok(Signed {
            id,
            serial: s(&r, "serialNumber").into(),
            expires_at: s(&r, "validBefore").into(),
            chain,
        }),
        _ => Err(Error::new(
            500,
            "CertificateAuthority returned no certificate",
        )),
    }
}
async fn revoke(app: &App, id: u64) -> Result<Value> {
    app.remote
        .call(
            CA,
            "DELETE",
            &format!("/certificate-authority/mgmt/certificates/{id}"),
            &Value::Null,
        )
        .await
}
async fn remove_names(app: &App, provider: &str, path: &str, name: &str) -> Result<Value> {
    app.remote
        .call(
            provider,
            "DELETE",
            &format!("{path}?names={}", security::encode(name)),
            &Value::Null,
        )
        .await
}
async fn discover(app: &App) -> Result<Vec<Value>> {
    let wanted = ["deviceDiscovery", "systemDiscovery", "serviceDiscovery"];
    let response = app
        .remote
        .call("ServiceRegistry", "POST", "/serviceregistry/service-discovery/lookup?verbose=false",
            &json!({"providerNames":["ServiceRegistry"],"serviceDefinitionNames":wanted,"interfaceTemplateNames":["generic_https"]}))
        .await?;
    let entries = array(&response, "entries");
    if !wanted.iter().all(|w| {
        entries
            .iter()
            .any(|e| s(&e["serviceDefinition"], "name") == *w)
    }) {
        return Err(Error::new(
            500,
            "Required v5 registry services are unavailable",
        ));
    }
    Ok(entries)
}
async fn best(
    step: &str,
    action: impl Future<Output = Result<Value>>,
    done: &mut Vec<String>,
    failed: &mut Vec<String>,
) {
    match action.await {
        Ok(_) => done.push(step.into()),
        Err(e) => {
            eprintln!("{step} failed: {}", e.message);
            failed.push(format!("{step}: {}", e.message));
        }
    }
}
async fn quietly(step: &str, action: impl Future<Output = Result<Value>>) {
    if let Err(e) = action.await {
        eprintln!("{step} failed: {}", e.message);
    }
}

// ---- records ----
fn find(app: &App, device: &str) -> Result<Value> {
    app.store
        .snapshot()
        .get(ENROLLMENTS)
        .and_then(|t| t.get(device))
        .map(normalized)
        .ok_or_else(|| Error::new(404, format!("No enrollment for device {device}")))
}
fn update<T>(app: &App, device: &str, change: impl FnOnce(&mut Value) -> Result<T>) -> Result<T> {
    app.store.update(|db| {
        let t = table(db, ENROLLMENTS);
        let mut row = t
            .get(device)
            .map(normalized)
            .ok_or_else(|| Error::new(404, format!("No enrollment for device {device}")))?;
        let out = change(&mut row)?;
        t.insert(device.into(), row);
        Ok(out)
    })
}
/// Approvals stored before the procedure was ported used "systems" and "status".
fn normalized(row: &Value) -> Value {
    let mut row = row.clone();
    if row.get("state").is_none() {
        row["state"] = row["status"].clone();
        row["approvedSystems"] = row["systems"].clone();
        row["approvedAt"] = row["createdAt"].clone();
        if let Some(map) = row.as_object_mut() {
            map.remove("status");
            map.remove("systems");
            map.remove("createdAt");
        }
    }
    row
}
fn touch(row: &mut Value, message: &str) {
    row["updatedAt"] = now().into();
    row["lastMessage"] = message.chars().take(1024).collect::<String>().into();
}
fn approved(row: &Value) -> Vec<String> {
    array(row, "approvedSystems")
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect()
}
fn issued(app: &App, device: &str) -> Vec<Value> {
    app.store
        .rows(SYSTEMS)
        .into_iter()
        .filter(|r| s(r, "deviceName") == device)
        .collect()
}
/// The Java EnrollmentView; "status" repeats "state" for clients of the earlier approval-only API.
fn view(app: &App, row: &Value) -> Value {
    let row = normalized(row);
    let systems = issued(app, s(&row, "deviceName"))
        .iter()
        .map(|r| json!({"systemName":r["systemName"],"certificateId":r["certificateId"],"certificateExpiresAt":r["certificateExpiresAt"],"issuedAt":r["issuedAt"]}))
        .collect::<Vec<_>>();
    json!({"deviceName":row["deviceName"],"bootstrapFingerprint":row["bootstrapFingerprint"],"approvedSystems":row["approvedSystems"],"state":row["state"],"status":row["state"],
        "deviceCertificateId":row["deviceCertificateId"],"deviceCertificateExpiresAt":row["deviceCertificateExpiresAt"],"systems":systems,
        "approvedBy":row["approvedBy"],"approvedAt":row["approvedAt"],"updatedAt":row["updatedAt"],"lastMessage":row["lastMessage"]})
}
fn result(signed: &Signed, kind: &str, csr: &Csr) -> Value {
    let mut out = json!({"certificate":signed.chain[0],"certificateFormat":"X.509","certificateType":kind,"publicKey":csr.public_key,"expiresAt":signed.expires_at});
    if let Some(key) = &csr.private_key {
        out["privateKey"] = key.clone().into();
    }
    out
}
fn common_name(app: &App, name: &str) -> String {
    format!("{name}.{}", app.config.cloud_suffix)
}
pub fn require_name(name: &str) -> Result<&str> {
    let mut bytes = name.bytes();
    if name.len() <= 63
        && bytes.next().is_some_and(|b| b.is_ascii_uppercase())
        && bytes.all(|b| b.is_ascii_alphanumeric())
    {
        Ok(name)
    } else {
        Err(Error::bad(
            "Device and system names must be PascalCase, at most 63 characters",
        ))
    }
}
fn reserved(name: &str) -> bool {
    RESERVED.contains(&name) || reserved_name(name)
}
/// Addresses that can go into the certificate (IP addresses and host names); others, such as MAC addresses,
/// only into the registry.
pub fn certificate_addresses(addresses: &[String]) -> Vec<String> {
    let mac = regex::Regex::new(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$").unwrap();
    let host =
        regex::Regex::new(r"^([0-9A-Fa-f:.]+|[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)$")
            .unwrap();
    addresses
        .iter()
        .filter(|a| !mac.is_match(a) && host.is_match(a))
        .cloned()
        .collect()
}
