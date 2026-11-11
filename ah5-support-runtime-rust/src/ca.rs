// SPDX-License-Identifier: EPL-2.0
use crate::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{
        X509, X509Crl, X509CrlBuilder, X509NameBuilder, X509Req, X509RevokedBuilder,
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
            SubjectAlternativeName, SubjectKeyIdentifier,
        },
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};
/// Age after which the periodic check republishes an unchanged CRL (SOS-15, 2026-11-10). CRLs are valid for 7 days;
/// a revocation publishes at once (`publish_crl`), so the periodic check only keeps the CRL fresh. Republishing every
/// minute made the relay reload its combined CRL about 1,440 times a day.
pub const CRL_REFRESH_SECONDS: i64 = 24 * 3600;
/// Periodic check: republish only when the published CRL is missing, unreadable, not signed by this CA, lists other
/// serials than the revoked certificates, is older than `CRL_REFRESH_SECONDS` or expires within a day. Returns
/// whether it published.
pub fn refresh_crl(app: &App) -> Result<bool> {
    let Some(path) = &app.config.crl_publish_file else {
        return Ok(false);
    };
    let current = fs::read(path)
        .map(|pem| !crl_needs_refresh(app, &pem, chrono::Utc::now().timestamp()))
        .unwrap_or(false);
    if current {
        return Ok(false);
    }
    publish_crl(app)?;
    Ok(true)
}
/// Whether a published CRL (PEM) must be replaced at `now` (Unix seconds).
pub fn crl_needs_refresh(app: &App, pem: &[u8], now: i64) -> bool {
    let check = || -> Result<bool> {
        let crl = X509Crl::from_pem(pem)?;
        let root = X509::from_pem(&fs::read(&app.config.ca_certificate)?)?;
        let key = root.public_key()?;
        if crl.issuer_name().to_der()? != root.subject_name().to_der()? || !crl.verify(&key)? {
            return Ok(true);
        }
        let Some(next) = crl.next_update() else {
            return Ok(true);
        };
        if crl.last_update() < Asn1Time::from_unix(now - CRL_REFRESH_SECONDS)?
            || next < Asn1Time::from_unix(now + 24 * 3600)?
        {
            return Ok(true);
        }
        let mut listed = BTreeSet::new();
        for entry in crl.get_revoked().into_iter().flatten() {
            listed.insert(entry.serial_number().to_bn()?.to_dec_str()?.to_string());
        }
        let mut revoked = BTreeSet::new();
        for row in app.store.rows("certificates") {
            if !row["revoked_at"].is_null() {
                revoked.insert(
                    BigNum::from_dec_str(s(&row, "serial_number"))?
                        .to_dec_str()?
                        .to_string(),
                );
            }
        }
        Ok(listed != revoked)
    };
    check().unwrap_or(true)
}
/// Publish only public revocation data; readers mount the directory read-only.
/// Serialisation prevents concurrent revocations publishing older CRLs last.
pub fn publish_crl(app: &App) -> Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path, sync::Mutex};
    static PUBLISH: Mutex<()> = Mutex::new(());
    let Some(path) = &app.config.crl_publish_file else {
        return Ok(());
    };
    let _guard = PUBLISH
        .lock()
        .map_err(|_| Error::unavailable("CRL publisher unavailable"))?;
    let path = Path::new(path);
    let parent = path
        .parent()
        .ok_or_else(|| Error::bad("CRL publication needs parent directory"))?;
    let pending = parent.join(format!(".crl-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let pem = crl(app)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&pending)?;
        file.write_all(&pem)?;
        file.sync_all()?;
        fs::rename(&pending, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(pending);
    }
    result
}
impl From<openssl::error::ErrorStack> for Error {
    fn from(_: openssl::error::ErrorStack) -> Self {
        Error::bad("Invalid cryptographic material or operation")
    }
}
fn signer(c: &Config) -> Result<(X509, PKey<Private>)> {
    if c.ca_certificate.is_empty() || c.ca_signing_key.is_empty() {
        return Err(Error::unavailable("CA signing material is not configured"));
    }
    let root = X509::from_pem(&fs::read(&c.ca_certificate)?)?;
    let key = PKey::private_key_from_pem(&config::secret(&c.ca_signing_key)?)?;
    if !root.public_key()?.public_eq(&key)
        || root.not_after() <= Asn1Time::days_from_now(0)?.as_ref()
        || root.not_before() > Asn1Time::days_from_now(0)?.as_ref()
    {
        return Err(Error::bad("CA key mismatch or expired certificate"));
    }
    if !security::ca_usages(&root.to_der()?)? {
        return Err(Error::bad(
            "Signer must be a CA with keyCertSign and cRLSign usage",
        ));
    }
    Ok((root, key))
}
pub fn validate_signer(c: &Config) -> Result<()> {
    if c.role == "certificateauthority" {
        signer(c)?;
    }
    Ok(())
}
pub fn certificate(encoded: &str) -> Result<X509> {
    if encoded.contains("-----BEGIN CERTIFICATE-----") {
        Ok(X509::from_pem(encoded.as_bytes())?)
    } else {
        Ok(X509::from_der(&STANDARD.decode(encoded).map_err(
            |_| Error::bad("Invalid certificate encoding"),
        )?)?)
    }
}
fn manager(caller: &Principal) -> Result<()> {
    if ["Sysop", "LocalCloudManager", "CertificateAuthority"].contains(&caller.name.as_str()) {
        Ok(())
    } else {
        Err(Error::denied())
    }
}
fn serial(cert: &X509) -> Result<String> {
    Ok(cert.serial_number().to_bn()?.to_dec_str()?.to_string())
}
fn common(cert: &X509) -> Result<String> {
    let entry = cert
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .ok_or_else(|| Error::bad("Certificate lacks CN"))?;
    Ok(entry.data().to_string()?)
}
fn own_cert(root: &X509, cert: &X509) -> Result<bool> {
    Ok(
        root.subject_name().to_der()? == cert.issuer_name().to_der()?
            && cert.verify(root.public_key()?.as_ref())?,
    )
}
fn timestamp(req: &Value, key: &str, default: i64) -> Result<i64> {
    if s(req, key).is_empty() {
        return Ok(default);
    }
    Ok(chrono::DateTime::parse_from_rfc3339(s(req, key))
        .map_err(|_| Error::bad("Invalid RFC3339 validity"))?
        .timestamp())
}
pub fn sign(app: &App, req: &Value, caller: &Principal) -> Result<Value> {
    let (root, key) = signer(&app.config)?;
    let raw = if s(req, "encodedCSR").is_empty() {
        s(req, "csr")
    } else {
        s(req, "encodedCSR")
    };
    let csr = if raw.contains("-----BEGIN") {
        X509Req::from_pem(raw.as_bytes())?
    } else {
        X509Req::from_der(
            &STANDARD
                .decode(raw)
                .map_err(|_| Error::bad("Invalid CSR encoding"))?,
        )?
    };
    let public = csr.public_key()?;
    if !csr.verify(&public)? {
        return Err(Error::bad("CSR signature invalid"));
    }
    if !(public.id() == openssl::pkey::Id::RSA && public.bits() >= 2048
        || public.id() == openssl::pkey::Id::EC && public.bits() >= 256)
    {
        return Err(Error::bad("CSR requires RSA >=2048 or EC >=256 bits"));
    }
    let names = csr
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .collect::<Vec<_>>();
    if names.len() != 1 {
        return Err(Error::bad("CSR requires exactly one CN"));
    }
    let cn = names[0].data().to_string()?;
    let suffix = format!(".{}", app.config.cloud_suffix);
    let short = cn
        .strip_suffix(&suffix)
        .ok_or_else(|| Error::bad("CSR must belong to the local cloud"))?;
    if !short.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
        || !short.bytes().all(|b| b.is_ascii_alphanumeric())
        || short.len() > 63
    {
        return Err(Error::bad("CSR requires PascalCase system name"));
    }
    let reserved = reserved_name(short);
    if reserved && caller.name != "Sysop" {
        return Err(Error::denied());
    }
    let qualifier = csr
        .subject_name()
        .entries_by_nid(Nid::DNQUALIFIER)
        .next()
        .map(|e| e.data().to_string())
        .transpose()?;
    let profile = if s(req, "profile").is_empty() {
        qualifier.as_deref().unwrap_or("sy")
    } else {
        s(req, "profile")
    };
    let permitted = match caller.name.as_str() {
        "Sysop" => ["on", "de", "sy", "op"].contains(&profile),
        "Onboarding" => ["on", "de", "sy"].contains(&profile),
        "LocalCloudManager" | "CertificateAuthority" => profile == "sy",
        _ => false,
    };
    if !permitted {
        return Err(Error::denied());
    }
    // Relay certificates use a separate, constrained namespace. Never honour
    // an arbitrary CSR OU or grant this capability to onboarding/management.
    let relay = match req.get("relay") {
        None => false,
        Some(Value::Bool(value)) => *value,
        _ => return Err(Error::bad("relay must be a boolean")),
    };
    if relay
        && (caller.name != "Sysop"
            || profile != "sy"
            || !["Gatekeeper", "GateTunnel"].contains(&short))
    {
        return Err(Error::denied());
    }
    let now = chrono::Utc::now().timestamp();
    let start = timestamp(req, "validAfter", now - 60)?;
    let max = if profile == "on" { 86400 } else { 365 * 86400 };
    let root_end = Asn1Time::from_unix(0)?.diff(root.not_after())?;
    let root_end = i64::from(root_end.days) * 86400 + i64::from(root_end.secs);
    let end = timestamp(req, "validBefore", start + max)?.min(root_end);
    if end <= start || end > start + max || start < now - 300 || end <= now {
        return Err(Error::bad("Invalid certificate validity"));
    }
    let mut subject = X509NameBuilder::new()?;
    for nid in [Nid::COUNTRYNAME, Nid::ORGANIZATIONNAME] {
        if relay && nid == Nid::ORGANIZATIONNAME {
            subject.append_entry_by_nid(
                nid,
                app.config.cloud_suffix.split('.').nth(1).unwrap_or(""),
            )?;
            continue;
        }
        for entry in root.subject_name().entries_by_nid(nid) {
            subject.append_entry_by_nid(nid, &entry.data().to_string()?)?;
        }
    }
    let cloud = app.config.cloud_suffix.split('.').next().unwrap_or("");
    subject.append_entry_by_nid(
        Nid::ORGANIZATIONALUNITNAME,
        if relay { cloud } else { "Arrowhead Systems" },
    )?;
    subject.append_entry_by_nid(Nid::COMMONNAME, &cn)?;
    subject.append_entry_by_nid(Nid::DNQUALIFIER, profile)?;
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    let mut num = BigNum::new()?;
    num.rand(159, MsbOption::ONE, false)?;
    let sn = num.to_asn1_integer()?;
    builder.set_serial_number(&sn)?;
    builder.set_subject_name(&subject.build())?;
    builder.set_issuer_name(root.subject_name())?;
    builder.set_pubkey(&public)?;
    builder.set_not_before(Asn1Time::from_unix(start)?.as_ref())?;
    builder.set_not_after(Asn1Time::from_unix(end)?.as_ref())?;
    builder.append_extension(BasicConstraints::new().critical().build()?)?;
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;
    let mut usage = ExtendedKeyUsage::new();
    usage.client_auth();
    if !relay {
        usage.server_auth();
    }
    builder.append_extension(usage.build()?)?;
    let ski = SubjectKeyIdentifier::new().build(&builder.x509v3_context(Some(&root), None))?;
    builder.append_extension(ski)?;
    let aki = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&builder.x509v3_context(Some(&root), None))?;
    builder.append_extension(aki)?;
    // Deliberately accept only explicit validated SANs, never arbitrary CSR extensions.
    let addresses = array(req, "addresses");
    if addresses.len() > 16 {
        return Err(Error::bad("At most 16 addresses"));
    }
    if !addresses.is_empty() {
        let dns = regex::Regex::new(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$").unwrap();
        let mut san = SubjectAlternativeName::new();
        for address in addresses {
            let address = address
                .as_str()
                .ok_or_else(|| Error::bad("Invalid address"))?;
            if address.parse::<std::net::IpAddr>().is_ok() {
                san.ip(address);
            } else if address.len() <= 253
                && dns.is_match(address)
                && address.split('.').all(|l| {
                    !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-')
                })
            {
                san.dns(address);
            } else {
                return Err(Error::bad("Invalid DNS/IP SAN"));
            }
        }
        let ext = san.build(&builder.x509v3_context(Some(&root), None))?;
        builder.append_extension(ext)?;
    }
    builder.sign(&key, MessageDigest::sha256())?;
    let cert = builder.build();
    let serial = serial(&cert)?;
    let issued_id=app.store.update(|db|{if table(db,"certificates").values().any(|r|s(r,"common_name")==cn&&s(r,"created_by")!=caller.name&&r["revoked_at"].is_null()&&!expired(s(r,"valid_until"))){return Err(Error::denied())}let id=table(db,"certificates").values().filter_map(|r|r["id"].as_u64()).max().unwrap_or(0)+1;table(db,"certificates").insert(id.to_string(),json!({"id":id,"serial_number":serial,"common_name":cn,"created_by":caller.name,"valid_from":chrono::DateTime::from_timestamp(start,0).unwrap().to_rfc3339(),"valid_until":chrono::DateTime::from_timestamp(end,0).unwrap().to_rfc3339(),"revoked_at":null,"certificate_pem":String::from_utf8(cert.to_pem()?).unwrap()}));Ok(id)})?;
    Ok(
        json!({"id":issued_id,"certificateChain":[STANDARD.encode(cert.to_der()?),STANDARD.encode(root.to_der()?)],"commonName":cn,"profile":match profile{"on"=>"ON_BOARDING","de"=>"DEVICE","op"=>"OPERATOR",_=>"SYSTEM"},"serialNumber":serial,"validAfter":chrono::DateTime::from_timestamp(start,0).unwrap().to_rfc3339(),"validBefore":chrono::DateTime::from_timestamp(end,0).unwrap().to_rfc3339()}),
    )
}
pub fn crl(app: &App) -> Result<Vec<u8>> {
    let (root, key) = signer(&app.config)?;
    let mut builder = X509CrlBuilder::new()?;
    let context = X509::builder()?;
    builder.append_extension(
        AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&context.x509v3_context(Some(&root), None))?,
    )?;
    let number = app.store.update(|db| {
        let t = table(db, "ca-meta");
        let next = t.get("crl-number").and_then(Value::as_u64).unwrap_or(0) + 1;
        t.insert("crl-number".into(), next.into());
        Ok(next)
    })?;
    let mut bytes = number.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    let mut der = vec![2, bytes.len() as u8];
    der.extend(bytes);
    builder.append_extension(openssl::x509::X509Extension::new_from_der(
        openssl::asn1::Asn1Object::from_str("2.5.29.20")?.as_ref(),
        false,
        openssl::asn1::Asn1OctetString::new_from_bytes(&der)?.as_ref(),
    )?)?;
    builder.set_issuer_name(root.subject_name())?;
    builder.set_last_update(Asn1Time::from_unix(chrono::Utc::now().timestamp() - 60)?.as_ref())?;
    builder.set_next_update(Asn1Time::days_from_now(7)?.as_ref())?;
    for row in app.store.rows("certificates") {
        if row["revoked_at"].is_null() {
            continue;
        }
        let mut revoked = X509RevokedBuilder::new()?;
        revoked.set_serial_number(
            BigNum::from_dec_str(s(&row, "serial_number"))?
                .to_asn1_integer()?
                .as_ref(),
        )?;
        let at = chrono::DateTime::parse_from_rfc3339(s(&row, "revoked_at"))
            .map_err(|_| Error::new(500, "Corrupt revocation"))?;
        revoked.set_revocation_date(Asn1Time::from_unix(at.timestamp())?.as_ref())?;
        builder.add_revoked(revoked.build())?;
    }
    builder.sort()?;
    builder.sign(&key, MessageDigest::sha256())?;
    Ok(builder.build()?.to_pem()?)
}
#[allow(clippy::too_many_arguments)]
pub fn handle(
    app: &App,
    method: &str,
    path: &str,
    p: &BTreeMap<String, String>,
    _q: &Value,
    req: &Value,
    caller: &Principal,
) -> Result<(u16, Value)> {
    if path.ends_with("/sign") {
        return Ok((201, sign(app, req, caller)?));
    }
    if path.ends_with("/crl") {
        return Ok((200, json!({"pem":String::from_utf8(crl(app)?).unwrap()})));
    }
    if path.ends_with("/checkCertificate") {
        let encoded = if s(req, "certificate").is_empty() {
            s(req, "encodedCertificate")
        } else {
            s(req, "certificate")
        };
        let cert = certificate(encoded)?;
        let (root, _) = signer(&app.config)?;
        let serial = serial(&cert)?;
        let record = app
            .store
            .rows("certificates")
            .into_iter()
            .find(|r| s(r, "serial_number") == serial);
        let t = Asn1Time::days_from_now(0)?;
        let status = if !own_cert(&root, &cert)? {
            "UNKNOWN"
        } else if record.as_ref().is_some_and(|r| !r["revoked_at"].is_null()) {
            "REVOKED"
        } else if cert.not_before() > t.as_ref() || cert.not_after() < t.as_ref() {
            "EXPIRED"
        } else {
            "GOOD"
        };
        return Ok((
            200,
            json!({"status":status,"valid":status=="GOOD","known":record.is_some(),"serialNumber":serial}),
        ));
    }
    if path.ends_with("/checkTrustedKey") {
        let key = if s(req, "publicKey").is_empty() {
            s(req, "publicKeyPem")
        } else {
            s(req, "publicKey")
        };
        let record = app
            .store
            .rows("trusted-keys")
            .into_iter()
            .find(|r| s(r, "public_key_pem") == key);
        let trusted = record.as_ref().is_some_and(|r| {
            !expired(s(r, "valid_before"))
                && chrono::DateTime::parse_from_rfc3339(s(r, "valid_after"))
                    .is_ok_and(|t| t <= chrono::Utc::now())
        });
        return Ok((200, json!({"trusted":trusted,"key":record})));
    }
    let own_revoke =
        method == "DELETE" && path.contains("/certificates/") && caller.name == "Onboarding";
    if !own_revoke {
        manager(caller)?
    }
    let bucket = if path.contains("/keys") {
        "trusted-keys"
    } else {
        "certificates"
    };
    if method == "GET" {
        return Ok((200, app.store.rows(bucket).into()));
    }
    if method == "PUT" {
        let key = if s(req, "publicKey").is_empty() {
            s(req, "publicKeyPem")
        } else {
            s(req, "publicKey")
        };
        PKey::public_key_from_pem(key.as_bytes())?;
        let now = chrono::Utc::now().timestamp();
        let start = timestamp(req, "validAfter", now)?;
        let end = timestamp(req, "validBefore", now + 365 * 86400)?;
        if end <= start {
            return Err(Error::bad("Invalid key validity"));
        }
        let record=app.store.update(|db|{if table(db,bucket).values().any(|r|s(r,"public_key_pem")==key){return Err(Error::new(409,"Duplicate key"))}let id=table(db,bucket).values().filter_map(|r|r["id"].as_u64()).max().unwrap_or(0)+1;let row=json!({"id":id,"public_key_pem":key,"description":req["description"],"valid_after":chrono::DateTime::from_timestamp(start,0).unwrap().to_rfc3339(),"valid_before":chrono::DateTime::from_timestamp(end,0).unwrap().to_rfc3339(),"created_at":crate::now()});table(db,bucket).insert(id.to_string(),row.clone());Ok(row)})?;
        return Ok((201, json!({"id":record["id"],"trusted":true})));
    }
    if method == "POST" && path.ends_with("/revocations") {
        let cert = certificate(if s(req, "certificate").is_empty() {
            s(req, "encodedCertificate")
        } else {
            s(req, "certificate")
        })?;
        let (root, _) = signer(&app.config)?;
        if !own_cert(&root, &cert)? {
            return Err(Error::bad("Certificate not issued by this CA"));
        }
        let serial = serial(&cert)?;
        let value=app.store.update(|db|{let t=table(db,"certificates");let key=t.iter().find(|(_,r)|s(r,"serial_number")==serial).map(|(k,_)|k.clone()).unwrap_or_else(||(t.values().filter_map(|r|r["id"].as_u64()).max().unwrap_or(0)+1).to_string());let r=t.entry(key.clone()).or_insert(json!({"id":key.parse::<u64>().unwrap(),"serial_number":serial,"common_name":common(&cert)?,"created_by":format!("revoked-by:{}",caller.name),"certificate_pem":String::from_utf8(cert.to_pem()?).unwrap(),"revoked_at":null}));let changed=r["revoked_at"].is_null();r["revoked_at"]=now().into();Ok(json!({"id":r["id"],"serialNumber":serial,"revoked":true,"changed":changed}))})?;
        return Ok((200, value));
    }
    if method == "DELETE" {
        let id = p.get("id").ok_or_else(|| Error::bad("id required"))?;
        app.store.update(|db| {
            let r = table(db, bucket)
                .get_mut(id)
                .ok_or_else(|| Error::new(404, "Record not found"))?;
            if own_revoke && s(r, "created_by") != "Onboarding" {
                return Err(Error::denied());
            }
            if bucket == "certificates" {
                r["revoked_at"] = now().into();
            } else {
                table(db, bucket).remove(id);
            }
            Ok(())
        })?;
        return Ok((200, json!({"success":true})));
    }
    Err(Error::new(404, "Unknown CA operation"))
}
