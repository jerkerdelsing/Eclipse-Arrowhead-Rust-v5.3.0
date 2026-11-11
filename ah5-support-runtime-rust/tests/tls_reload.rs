// SPDX-License-Identifier: EPL-2.0
mod common;
use arrowhead_support_rust::*;
use common::*;
use serde_json::json;
use std::{collections::BTreeMap, fs, sync::Arc};

#[tokio::test]
async fn published_crl_rejects_clients_and_servers_without_restart() {
    let mut ca = Fixture::new("certificateauthority");
    ca.config.ca_certificate = pki().ca.clone();
    ca.config.ca_signing_key = pki().key.clone();
    ca.reconfigure();
    let crl = ca.temp.file("current.crl", ca::crl(&ca.app).unwrap());
    ca.config.crl_file = Some(crl.clone());
    let server_tls = security::Tls::load(&ca.config).unwrap();
    let server = start_router(
        ca.app.clone(),
        server_tls.clone(),
        axum::Router::new().route("/", axum::routing::get(|| async { "ok" })),
    )
    .await;
    let mut client = Fixture::new("timemanager");
    client.config.crl_file = Some(crl.clone());
    let client_tls = security::Tls::load(&client.config).unwrap();
    let expected = format!("CertificateAuthority.{SUFFIX}");
    assert!(
        client_tls
            .client(&expected)
            .unwrap()
            .get(&server.origin)
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    let revoke = |certificate: &str| {
        ca::handle(
            &ca.app,
            "POST",
            "/certificate-authority/mgmt/certificates/revocations",
            &BTreeMap::new(),
            &json!({}),
            &json!({"certificate": fs::read_to_string(certificate).unwrap()}),
            &caller("Sysop"),
        )
        .unwrap();
        // Atomic replace, not an in-place write or process restart.
        let pending = ca.temp.file("pending.crl", ca::crl(&ca.app).unwrap());
        fs::rename(pending, &crl).unwrap();
    };
    revoke(&client.config.certificate);
    assert!(
        client_tls
            .client(&expected)
            .unwrap()
            .get(&server.origin)
            .send()
            .await
            .is_err(),
        "revoked client still accepted"
    );
    let other = Fixture::new("blacklist");
    let mut other_config = other.config.clone();
    other_config.crl_file = Some(crl.clone());
    let other_tls = security::Tls::load(&other_config).unwrap();
    assert!(
        other_tls
            .client(&expected)
            .unwrap()
            .get(&server.origin)
            .send()
            .await
            .is_ok()
    );
    revoke(&ca.config.certificate);
    assert!(
        other_tls
            .client(&expected)
            .unwrap()
            .get(&server.origin)
            .send()
            .await
            .is_err(),
        "revoked server still accepted outbound"
    );
    fs::write(&crl, "invalid CRL").unwrap();
    assert!(server_tls.server_current().is_err());
    assert!(other_tls.client(&expected).is_err());
    fs::remove_file(&crl).unwrap();
    assert!(server_tls.server_current().is_err());
    fs::write(&crl, ca::crl(&ca.app).unwrap()).unwrap();
    assert!(server_tls.server_current().is_ok());
    let old = server_tls.server_current().unwrap();
    let (cert, key) = pki().leaf(&ca.temp, "CertificateAuthority", "sy");
    let original_key = fs::read(&ca.config.private_key).unwrap();
    fs::copy(cert, &ca.config.certificate).unwrap();
    assert!(
        server_tls.server_current().is_err(),
        "mismatched key must fail closed"
    );
    fs::copy(key, &ca.config.private_key).unwrap();
    let fresh = server_tls.server_current().unwrap();
    assert!(!Arc::ptr_eq(&old, &fresh));
    assert!(server_tls.console_current().is_ok());
    assert!(
        other_tls
            .client(&expected)
            .unwrap()
            .get(&server.origin)
            .send()
            .await
            .is_ok(),
        "renewed server certificate not loaded"
    );
    fs::write(&ca.config.private_key, original_key).unwrap();
    assert!(server_tls.server_current().is_err());
}
