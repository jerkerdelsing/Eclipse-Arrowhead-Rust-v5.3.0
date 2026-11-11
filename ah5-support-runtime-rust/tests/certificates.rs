// SPDX-License-Identifier: EPL-2.0
mod common;
use arrowhead_support_rust::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use common::*;
use openssl::{
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    rsa::Rsa,
    x509::{X509Crl, X509NameBuilder, X509Req},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
fn csr(name: &str) -> String {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut subject = X509NameBuilder::new().unwrap();
    subject.append_entry_by_nid(Nid::COMMONNAME, name).unwrap();
    let mut req = X509Req::builder().unwrap();
    req.set_subject_name(&subject.build()).unwrap();
    req.set_pubkey(&key).unwrap();
    req.sign(&key, MessageDigest::sha256()).unwrap();
    String::from_utf8(req.build().to_pem().unwrap()).unwrap()
}
fn ca_fixture() -> Fixture {
    let mut f = Fixture::new("certificateauthority");
    f.config.ca_certificate = pki().ca.clone();
    f.config.ca_signing_key = pki().key.clone();
    f.reconfigure();
    f
}
#[test]
fn relay_credentials_are_explicit_sysop_only_and_client_only() {
    let f = ca_fixture();
    for system in ["Gatekeeper", "GateTunnel"] {
        let req =
            json!({"encodedCSR":csr(&format!("{system}.{SUFFIX}")),"profile":"sy","relay":true});
        let signed = ca::sign(&f.app, &req, &caller("Sysop")).unwrap();
        let cert = ca::certificate(signed["certificateChain"][0].as_str().unwrap()).unwrap();
        assert_eq!(
            cert.subject_name()
                .entries_by_nid(Nid::ORGANIZATIONALUNITNAME)
                .next()
                .unwrap()
                .data()
                .to_string()
                .unwrap(),
            SUFFIX.split('.').next().unwrap()
        );
        let text = String::from_utf8(cert.to_text().unwrap()).unwrap();
        assert!(text.contains("TLS Web Client Authentication"));
        assert!(!text.contains("TLS Web Server Authentication"));
        assert!(
            f.app
                .store
                .rows("certificates")
                .iter()
                .any(|r| r["serial_number"] == signed["serialNumber"])
        );
        for caller_name in [
            "Onboarding",
            "LocalCloudManager",
            "CertificateAuthority",
            "Client",
        ] {
            assert_eq!(
                ca::sign(&f.app, &req, &caller(caller_name))
                    .unwrap_err()
                    .code,
                403
            );
        }
    }
    for (name, profile, relay) in [
        ("Sensor", "sy", json!(true)),
        ("Gatekeeper", "op", json!(true)),
        ("GateTunnel", "sy", json!("true")),
    ] {
        assert!(
            ca::sign(
                &f.app,
                &json!({"csr":csr(&format!("{name}.{SUFFIX}")),"profile":profile,"relay":relay}),
                &caller("Sysop")
            )
            .is_err()
        );
    }
    let signed = ca::sign(
        &f.app,
        &json!({"csr":csr(&format!("Sensor.{SUFFIX}")),"profile":"sy"}),
        &caller("Sysop"),
    )
    .unwrap();
    let cert = ca::certificate(signed["certificateChain"][0].as_str().unwrap()).unwrap();
    assert_eq!(
        cert.subject_name()
            .entries_by_nid(Nid::ORGANIZATIONALUNITNAME)
            .next()
            .unwrap()
            .data()
            .to_string()
            .unwrap(),
        "Arrowhead Systems"
    );
}
#[test]
fn native_ca_sign_verify_revoke_and_crl() {
    let f = ca_fixture();
    ca::validate_signer(&f.config).unwrap();
    let signed=ca::sign(&f.app,&json!({"encodedCSR":csr(&format!("Sensor.{SUFFIX}")),"profile":"sy","addresses":["127.0.0.1","sensor.local"]}),&caller("Onboarding")).unwrap();
    assert_eq!(signed["profile"], "SYSTEM");
    let cert = ca::certificate(signed["certificateChain"][0].as_str().unwrap()).unwrap();
    assert_eq!(
        security::subject(&cert.to_der().unwrap()).unwrap(),
        (format!("Sensor.{SUFFIX}"), "sy".into())
    );
    assert_eq!(cert.subject_alt_names().unwrap().len(), 2);
    assert!(cert.verify(pki_key().as_ref()).unwrap());
    let req = json!({"certificate":STANDARD.encode(cert.to_der().unwrap())});
    assert_eq!(
        ca::handle(
            &f.app,
            "POST",
            "/certificate-authority/checkCertificate",
            &BTreeMap::new(),
            &json!({}),
            &req,
            &caller("Client")
        )
        .unwrap()
        .1["status"],
        "GOOD"
    );
    let params = BTreeMap::from([("id".into(), signed["id"].to_string())]);
    ca::handle(
        &f.app,
        "DELETE",
        "/certificate-authority/mgmt/certificates/1",
        &params,
        &json!({}),
        &json!({}),
        &caller("Onboarding"),
    )
    .unwrap();
    assert_eq!(
        ca::handle(
            &f.app,
            "POST",
            "/certificate-authority/checkCertificate",
            &BTreeMap::new(),
            &json!({}),
            &req,
            &caller("Client")
        )
        .unwrap()
        .1["status"],
        "REVOKED"
    );
    let crl = X509Crl::from_pem(&ca::crl(&f.app).unwrap()).unwrap();
    assert!(crl.verify(pki_key().as_ref()).unwrap());
    assert_eq!(crl.get_revoked().unwrap().len(), 1);
}
fn pki_key() -> PKey<openssl::pkey::Public> {
    openssl::x509::X509::from_pem(&read(&pki().ca))
        .unwrap()
        .public_key()
        .unwrap()
}
#[test]
fn ca_enforces_profiles_reserved_names_and_holder_ownership() {
    let f = ca_fixture();
    let encoded = csr(&format!("Sensor.{SUFFIX}"));
    for (actor, profile) in [
        ("Client", "sy"),
        ("Onboarding", "op"),
        ("LocalCloudManager", "de"),
    ] {
        assert_eq!(
            ca::sign(
                &f.app,
                &json!({"csr":encoded,"profile":profile}),
                &caller(actor)
            )
            .unwrap_err()
            .code,
            403
        )
    }
    assert_eq!(
        ca::sign(
            &f.app,
            &json!({"csr":csr(&format!("ServiceRegistry.{SUFFIX}")),"profile":"sy"}),
            &caller("Onboarding")
        )
        .unwrap_err()
        .code,
        403
    );
    ca::sign(
        &f.app,
        &json!({"csr":encoded,"profile":"sy"}),
        &caller("Onboarding"),
    )
    .unwrap();
    assert_eq!(
        ca::sign(
            &f.app,
            &json!({"csr":encoded,"profile":"sy"}),
            &caller("LocalCloudManager")
        )
        .unwrap_err()
        .code,
        403
    );
    assert!(
        ca::sign(
            &f.app,
            &json!({"csr":csr("Sensor.Foreign.Company.arrowhead.eu"),"profile":"sy"}),
            &caller("Sysop")
        )
        .is_err()
    );
}
#[test]
fn ca_own_revoke_and_trusted_key_management() {
    let f = ca_fixture();
    let signed = ca::sign(
        &f.app,
        &json!({"csr":csr(&format!("Sensor.{SUFFIX}")),"profile":"sy"}),
        &caller("Sysop"),
    )
    .unwrap();
    let params = BTreeMap::from([("id".into(), signed["id"].to_string())]);
    assert_eq!(
        ca::handle(
            &f.app,
            "DELETE",
            "/certificate-authority/mgmt/certificates/1",
            &params,
            &Value::Null,
            &Value::Null,
            &caller("Onboarding")
        )
        .unwrap_err()
        .code,
        403
    );
    let key = String::from_utf8(pki_key().public_key_to_pem().unwrap()).unwrap();
    let req = json!({"publicKey":key,"description":"test"});
    let result = ca::handle(
        &f.app,
        "PUT",
        "/certificate-authority/mgmt/keys",
        &BTreeMap::new(),
        &Value::Null,
        &req,
        &caller("Sysop"),
    )
    .unwrap()
    .1;
    assert_eq!(result["trusted"], true);
    assert_eq!(
        ca::handle(
            &f.app,
            "POST",
            "/certificate-authority/checkTrustedKey",
            &BTreeMap::new(),
            &Value::Null,
            &req,
            &caller("Client")
        )
        .unwrap()
        .1["trusted"],
        true
    );
    assert_eq!(
        ca::handle(
            &f.app,
            "GET",
            "/certificate-authority/mgmt/keys",
            &BTreeMap::new(),
            &Value::Null,
            &Value::Null,
            &caller("Client")
        )
        .unwrap_err()
        .code,
        403
    );
}
#[test]
fn ca_rejects_leaf_as_signer_and_supports_empty_crl() {
    let mut f = ca_fixture();
    let crl = X509Crl::from_pem(&ca::crl(&f.app).unwrap()).unwrap();
    assert!(crl.verify(pki_key().as_ref()).unwrap());
    assert!(crl.get_revoked().is_none());
    f.config.ca_certificate = f.config.certificate.clone();
    f.config.ca_signing_key = f.config.private_key.clone();
    assert!(ca::validate_signer(&f.config).is_err());
}
/// SOS-15 (2026-11-10): the periodic check republishes only when needed, so the relay's CRL watcher reloads about once
/// a day instead of every minute; a revocation still shows at the next check (and at once through publish_crl).
#[test]
fn periodic_crl_refresh_only_when_needed() {
    let mut f = ca_fixture();
    let published = f.temp.0.join("current.crl.pem");
    f.config.crl_publish_file = Some(published.to_string_lossy().into());
    f.reconfigure();
    let now = chrono::Utc::now().timestamp();
    // nothing published yet: publish; then the fresh CRL is kept
    assert!(ca::refresh_crl(&f.app).unwrap());
    let first = std::fs::read(&published).unwrap();
    assert!(!ca::crl_needs_refresh(&f.app, &first, now));
    assert!(!ca::refresh_crl(&f.app).unwrap());
    assert_eq!(
        std::fs::read(&published).unwrap(),
        first,
        "unchanged CRL rewritten"
    );
    // age and expiry
    assert!(!ca::crl_needs_refresh(
        &f.app,
        &first,
        now + ca::CRL_REFRESH_SECONDS - 120
    ));
    assert!(ca::crl_needs_refresh(
        &f.app,
        &first,
        now + ca::CRL_REFRESH_SECONDS + 120
    ));
    assert!(ca::crl_needs_refresh(
        &f.app,
        &first,
        now + 6 * 24 * 3600 + 120
    ));
    // corrupt, empty or foreign
    assert!(ca::crl_needs_refresh(&f.app, b"not a CRL", now));
    assert!(ca::crl_needs_refresh(&f.app, b"", now));
    // another issuer: the configured CA certificate is not the CRL's signer
    let mut other = ca_fixture();
    other.config.ca_certificate = pki().leaf(&other.temp, "Other", "sy").0;
    other.reconfigure();
    assert!(ca::crl_needs_refresh(&other.app, &first, now));
    // a revocation makes the published CRL stale
    let signed = ca::sign(
        &f.app,
        &json!({"encodedCSR":csr(&format!("Sensor.{SUFFIX}")),"profile":"sy"}),
        &caller("Onboarding"),
    )
    .unwrap();
    let params = BTreeMap::from([("id".into(), signed["id"].to_string())]);
    ca::handle(
        &f.app,
        "DELETE",
        "/certificate-authority/mgmt/certificates/1",
        &params,
        &json!({}),
        &json!({}),
        &caller("Onboarding"),
    )
    .unwrap();
    // the periodic check alone catches it (the web layer also publishes at once after a revocation)
    assert!(ca::crl_needs_refresh(&f.app, &first, now));
    assert!(ca::refresh_crl(&f.app).unwrap());
    let second = std::fs::read(&published).unwrap();
    assert_ne!(second, first);
    assert_eq!(
        X509Crl::from_pem(&second)
            .unwrap()
            .get_revoked()
            .unwrap()
            .len(),
        1
    );
    assert!(!ca::crl_needs_refresh(&f.app, &second, now));
    assert!(!ca::refresh_crl(&f.app).unwrap());
}
