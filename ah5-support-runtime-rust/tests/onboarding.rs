// SPDX-License-Identifier: EPL-2.0
// Onboarding procedure (WI6c): TLS admission of device credentials, their confinement to the onboarding
// steps, the step-to-certificate binding, CSR checks and the fail-closed manufacturer CRL.
mod common;
use arrowhead_support_rust::*;
use axum::{body::Body, http::Request};
use common::*;
use serde_json::{Value, json};
use std::{fs, sync::Arc};
use tower::ServiceExt;

/// A manufacturer CA outside the cloud PKI and a bootstrap certificate it issued (CN=Device1, no dnQualifier).
struct Manufacturer {
    ca: String,
    key: String,
    bootstrap: String,
    bootstrap_key: String,
}
fn manufacturer(temp: &Temp) -> Manufacturer {
    let dir = |n: &str| temp.0.join(n).to_string_lossy().to_string();
    let (ca, key) = (dir("maker.pem"), dir("maker.key"));
    let cnf = temp.file("maker.cnf", "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=v3\n[dn]\nO=Test Manufacturer\nCN=Test Manufacturer Device CA\n[v3]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n");
    openssl(&[
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", &key, "-out", &ca, "-days",
        "2", "-config", &cnf,
    ]);
    let (bootstrap, bootstrap_key, csr) =
        (dir("device1.pem"), dir("device1.key"), dir("device1.csr"));
    openssl(&[
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        &bootstrap_key,
        "-out",
        &csr,
        "-subj",
        "/O=Test Manufacturer/CN=Device1",
    ]);
    let ext = temp.file("device1.ext", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n");
    openssl(&[
        "x509",
        "-req",
        "-in",
        &csr,
        "-CA",
        &ca,
        "-CAkey",
        &key,
        "-set_serial",
        "0x1234",
        "-out",
        &bootstrap,
        "-days",
        "1",
        "-extfile",
        &ext,
    ]);
    Manufacturer {
        ca,
        key,
        bootstrap,
        bootstrap_key,
    }
}
/// An empty CRL of `ca`, valid for `seconds`.
fn crl(temp: &Temp, name: &str, ca: &str, key: &str, seconds: u32) -> String {
    let db = temp.file(&format!("{name}.index"), "");
    let number = temp.file(&format!("{name}.crlnumber"), "01\n");
    let cnf = temp.file(
        &format!("{name}.ca.cnf"),
        format!("[ca]\ndefault_ca=c\n[c]\ndatabase={db}\ncrlnumber={number}\ndefault_md=sha256\n"),
    );
    let out = temp
        .0
        .join(format!("{name}.crl.pem"))
        .to_string_lossy()
        .to_string();
    openssl(&[
        "ca",
        "-gencrl",
        "-config",
        &cnf,
        "-keyfile",
        key,
        "-cert",
        ca,
        "-out",
        &out,
        "-crlsec",
        &seconds.to_string(),
    ]);
    out
}
fn der(pem: &str) -> Vec<u8> {
    openssl::x509::X509::from_pem(&fs::read(pem).unwrap())
        .unwrap()
        .to_der()
        .unwrap()
}
fn device(der: Vec<u8>) -> (Principal, onboarding::PeerCertificate) {
    (
        Principal {
            name: String::new(),
            sysop: false,
            profile: onboarding::DEVICE.into(),
        },
        onboarding::PeerCertificate {
            der: Arc::new(der),
            address: "127.0.0.1".into(),
        },
    )
}
async fn send(
    app: &App,
    who: (Principal, onboarding::PeerCertificate),
    method: &str,
    path: &str,
    body: Value,
) -> (u16, Value) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .extension(who.0)
        .extension(who.1)
        .body(if body.is_null() {
            Body::empty()
        } else {
            Body::from(body.to_string())
        })
        .unwrap();
    let response = web::router(app.clone()).oneshot(request).await.unwrap();
    let code = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}
async fn approve(f: &Fixture, device: &str, fingerprint: &str) {
    onboarding::handle(
        &f.app,
        "PUT",
        &format!("/onboarding/mgmt/enrollments/{device}"),
        &[("deviceName".to_string(), device.to_string())].into(),
        &empty(),
        &json!({"bootstrapFingerprint":fingerprint,"systems":["DemoSensor"]}),
        &caller("Sysop"),
        None,
    )
    .await
    .unwrap();
}

#[test]
fn only_onboarding_admits_device_credentials() {
    let temp = Temp::new();
    let maker = manufacturer(&temp);
    let (on, _) = pki().leaf(&temp, "Device1", "on");
    let (sy, _) = pki().leaf(&temp, "TestProvider", "sy");
    for role in [
        "blacklist",
        "certificateauthority",
        "datamanager",
        "gatekeeper",
    ] {
        assert!(
            onboarding::admit(role, &der(&on), SUFFIX).is_err(),
            "{role} admitted an on certificate"
        );
        assert!(
            onboarding::admit(role, &der(&maker.bootstrap), SUFFIX).is_err(),
            "{role} admitted a bootstrap certificate"
        );
        assert_eq!(
            onboarding::admit(role, &der(&sy), SUFFIX).unwrap().name,
            "TestProvider"
        );
    }
    assert_eq!(
        onboarding::admit("onboarding", &der(&on), SUFFIX)
            .unwrap()
            .profile,
        onboarding::DEVICE
    );
    assert_eq!(
        onboarding::admit("onboarding", &der(&maker.bootstrap), SUFFIX)
            .unwrap()
            .profile,
        onboarding::DEVICE
    );
    let system = onboarding::admit("onboarding", &der(&sy), SUFFIX).unwrap();
    assert_eq!(
        (system.name.as_str(), system.profile.as_str()),
        ("TestProvider", "sy")
    );
}

#[tokio::test]
async fn device_principal_reaches_only_onboarding_steps() {
    let f = Fixture::new("onboarding");
    let temp = Temp::new();
    let maker = manufacturer(&temp);
    for (method, path) in [
        ("GET", "/onboarding/mgmt/enrollments"),
        ("PUT", "/onboarding/mgmt/enrollments/Device1"),
        ("POST", "/onboarding/mgmt/enrollments/Device1/offboard"),
        ("DELETE", "/onboarding/mgmt/enrollments/Device1"),
        ("GET", "/onboarding/general/mgmt/get-config"),
        ("POST", "/onboarding/general/mgmt/logs"),
        ("GET", "/onboarding/monitor/echo"),
        ("GET", "/onboarding/echo"),
    ] {
        let (code, _) = send(
            &f.app,
            device(der(&maker.bootstrap)),
            method,
            path,
            json!({}),
        )
        .await;
        assert_eq!(code, 403, "{method} {path}");
    }
    // another role refuses a device principal on every route, even if one were injected
    let other = Fixture::new("blacklist");
    assert_eq!(
        send(
            &other.app,
            device(der(&maker.bootstrap)),
            "GET",
            "/blacklist/check/Device1",
            Value::Null
        )
        .await
        .0,
        403
    );
    assert_eq!(
        send(
            &other.app,
            device(der(&maker.bootstrap)),
            "GET",
            "/blacklist/monitor/echo",
            Value::Null
        )
        .await
        .0,
        403
    );
}

#[tokio::test]
async fn each_step_requires_its_own_credential() {
    let f = Fixture::new("onboarding");
    let temp = Temp::new();
    let maker = manufacturer(&temp);
    let bootstrap = der(&maker.bootstrap);
    let name = json!({"commonName":format!("Device1.{SUFFIX}")});
    // unapproved bootstrap certificate
    assert_eq!(
        send(
            &f.app,
            device(bootstrap.clone()),
            "POST",
            "/onboarding/certificate/name",
            name.clone()
        )
        .await
        .0,
        401
    );
    // bootstrap certificate on the steps of the on and de certificates
    for path in [
        "/onboarding/device",
        "/onboarding/system",
        "/onboarding/device/offboard",
    ] {
        assert_eq!(
            send(
                &f.app,
                device(bootstrap.clone()),
                "POST",
                path,
                json!({"systemName":"DemoSensor"})
            )
            .await
            .0,
            403,
            "{path}"
        );
    }
    // cloud certificates on the bootstrap steps and on the wrong later step
    let (on, _) = pki().leaf(&temp, "Device1", "on");
    let (de, _) = pki().leaf(&temp, "Device1", "de");
    for path in [
        "/onboarding/certificate/name",
        "/onboarding/certificate/csr",
    ] {
        assert_eq!(
            send(&f.app, device(der(&on)), "POST", path, name.clone())
                .await
                .0,
            403,
            "{path}"
        );
    }
    assert_eq!(
        send(
            &f.app,
            device(der(&de)),
            "POST",
            "/onboarding/device",
            json!({})
        )
        .await
        .0,
        403
    );
    for path in ["/onboarding/system", "/onboarding/device/offboard"] {
        assert_eq!(
            send(
                &f.app,
                device(der(&on)),
                "POST",
                path,
                json!({"systemName":"DemoSensor"})
            )
            .await
            .0,
            403,
            "{path}"
        );
    }
    // an approved device: the requested name must be its own; an off-boarded one is refused
    approve(&f, "Device1", &digest(&bootstrap)).await;
    let wrong = json!({"commonName":format!("Other.{SUFFIX}")});
    assert_eq!(
        send(
            &f.app,
            device(bootstrap.clone()),
            "POST",
            "/onboarding/certificate/name",
            wrong
        )
        .await
        .0,
        403
    );
    f.app
        .store
        .update(|db| {
            table(db, "enrollments").get_mut("Device1").unwrap()["state"] = "OFFBOARDED".into();
            Ok(())
        })
        .unwrap();
    assert_eq!(
        send(
            &f.app,
            device(bootstrap),
            "POST",
            "/onboarding/certificate/name",
            name
        )
        .await
        .0,
        403
    );
    // without the TLS peer certificate (direct callers) every device step is refused
    for path in [
        "/onboarding/certificate/name",
        "/onboarding/device",
        "/onboarding/system",
    ] {
        let e = onboarding::handle(
            &f.app,
            "POST",
            path,
            &Default::default(),
            &empty(),
            &json!({}),
            &caller("Sysop"),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, 401, "{path}");
    }
}

#[tokio::test]
async fn approval_follows_java_rules_and_legacy_rows() {
    let f = Fixture::new("onboarding");
    let p = |d: &str| [("deviceName".to_string(), d.to_string())].into();
    let put = |d: &'static str, body: Value| {
        let f = &f;
        async move {
            onboarding::handle(
                &f.app,
                "PUT",
                &format!("/onboarding/mgmt/enrollments/{d}"),
                &p(d),
                &empty(),
                &body,
                &caller("Sysop"),
                None,
            )
            .await
        }
    };
    let ok = put(
        "Device1",
        json!({"bootstrapFingerprint":"AB:".repeat(31), "systems":["DemoSensor","DemoSensor"]}),
    )
    .await;
    assert_eq!(ok.unwrap_err().code, 400, "62 hex digits");
    let view = put(
        "Device1",
        json!({"bootstrapFingerprint":"ab".repeat(32),"systems":["DemoSensor","DemoSensor"]}),
    )
    .await
    .unwrap()
    .1;
    assert_eq!(
        (
            view["state"].as_str(),
            view["status"].as_str(),
            view["approvedSystems"].clone()
        ),
        (Some("APPROVED"), Some("APPROVED"), json!(["DemoSensor"]))
    );
    assert_eq!(view["systems"], json!([]));
    for (device, body) in [
        (
            "Device2",
            json!({"bootstrapFingerprint":"cd".repeat(32),"systems":["DemoSensor"]}),
        ), // system taken
        (
            "Device2",
            json!({"bootstrapFingerprint":"cd".repeat(32),"systems":["Device1"]}),
        ), // device name taken
        (
            "Device2",
            json!({"bootstrapFingerprint":"cd".repeat(32),"systems":["Device2"]}),
        ), // own name
        (
            "Device2",
            json!({"bootstrapFingerprint":"cd".repeat(32),"systems":["Onboarding"]}),
        ), // reserved
        (
            "Device2",
            json!({"bootstrapFingerprint":"cd".repeat(32),"systems":["lowercase"]}),
        ),
        (
            "Device2",
            json!({"bootstrapFingerprint":"cd".repeat(32),"systems":[]}),
        ),
        (
            "Sysop",
            json!({"bootstrapFingerprint":"cd".repeat(32),"systems":["Other"]}),
        ),
    ] {
        assert_eq!(
            put(device, body.clone()).await.unwrap_err().code,
            400,
            "{device} {body}"
        );
    }
    // a row stored by the approval-only implementation is read in the Java shape
    f.app.store.update(|db| { table(db, "enrollments").insert("Legacy".into(), json!({"deviceName":"Legacy","bootstrapFingerprint":"ef".repeat(32),"systems":["LegacySensor"],"status":"APPROVED","createdAt":"2026-10-01T00:00:00Z"})); Ok(()) }).unwrap();
    let legacy = onboarding::handle(
        &f.app,
        "GET",
        "/onboarding/mgmt/enrollments/Legacy",
        &p("Legacy"),
        &empty(),
        &empty(),
        &caller("Sysop"),
        None,
    )
    .await
    .unwrap()
    .1;
    assert_eq!(
        (legacy["state"].as_str(), legacy["approvedSystems"].clone()),
        (Some("APPROVED"), json!(["LegacySensor"]))
    );
    assert_eq!(
        put(
            "Device2",
            json!({"bootstrapFingerprint":"cd".repeat(32),"systems":["LegacySensor"]})
        )
        .await
        .unwrap_err()
        .code,
        400
    );
    // remove of a never-onboarded device needs no withdrawal steps
    let report = onboarding::handle(
        &f.app,
        "DELETE",
        "/onboarding/mgmt/enrollments/Device1",
        &p("Device1"),
        &empty(),
        &empty(),
        &caller("Sysop"),
        None,
    )
    .await
    .unwrap()
    .1;
    assert_eq!(
        report,
        json!({"deviceName":"Device1","completed":[],"failed":[]})
    );
    assert!(row(&f.app, "enrollments", "Device1").is_err());
}

#[test]
fn csr_checks_follow_java() {
    let temp = Temp::new();
    let csr = |subject: &str, digest: &str, bits: &str| {
        let out = temp
            .0
            .join(format!("{}.csr", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let key = temp
            .0
            .join(format!("{}.key", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        openssl(&[
            "req",
            "-new",
            "-newkey",
            &format!("rsa:{bits}"),
            "-nodes",
            &format!("-{digest}"),
            "-keyout",
            &key,
            "-out",
            &out,
            "-outform",
            "DER",
            "-subj",
            subject,
        ]);
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            fs::read(out).unwrap(),
        )
    };
    let expected = format!("Device1.{SUFFIX}");
    assert!(
        !onboarding::check_csr(
            &csr(&format!("/CN={expected}"), "sha256", "2048"),
            &expected
        )
        .unwrap()
        .is_empty()
    );
    assert!(
        onboarding::check_csr(
            &csr(&format!("/CN={expected}"), "sha512", "3072"),
            &expected
        )
        .is_ok()
    );
    assert_eq!(
        onboarding::check_csr(
            &csr(&format!("/CN=Other.{SUFFIX}"), "sha256", "2048"),
            &expected
        )
        .unwrap_err()
        .code,
        403
    );
    assert_eq!(
        onboarding::check_csr(&csr(&format!("/CN={expected}"), "sha1", "2048"), &expected)
            .unwrap_err()
            .code,
        400
    );
    assert_eq!(
        onboarding::check_csr(
            &csr(&format!("/CN={expected}"), "sha256", "1024"),
            &expected
        )
        .unwrap_err()
        .code,
        400
    );
    assert_eq!(
        onboarding::check_csr("not base64!", &expected)
            .unwrap_err()
            .code,
        400
    );
    assert_eq!(
        onboarding::check_csr(&"A".repeat(40000), &expected)
            .unwrap_err()
            .code,
        400
    );
    assert_eq!(
        onboarding::certificate_addresses(&[
            "10.0.0.7".into(),
            "device1.local".into(),
            "aa:bb:cc:dd:ee:ff".into(),
            "bad host".into()
        ]),
        vec!["10.0.0.7".to_string(), "device1.local".to_string()]
    );
}

/// TLS handshake of a client certificate against an Onboarding server configuration.
async fn handshake(server: Arc<rustls::ServerConfig>, cert: &str, key: &str) -> bool {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(&fs::read(&pki().ca).unwrap()).unwrap())
        .unwrap();
    let chain = CertificateDer::pem_slice_iter(&fs::read(cert).unwrap())
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_client_auth_cert(
        chain,
        PrivateKeyDer::from_pem_slice(&fs::read(key).unwrap()).unwrap(),
    )
    .unwrap();
    let (a, b) = tokio::io::duplex(1 << 16);
    let accept = tokio_rustls::TlsAcceptor::from(server).accept(a);
    let connect = tokio_rustls::TlsConnector::from(Arc::new(client))
        .connect(ServerName::try_from("localhost").unwrap(), b);
    let (accepted, connected) = tokio::join!(accept, connect);
    accepted.is_ok() && connected.is_ok()
}

#[tokio::test]
async fn manufacturer_trust_is_inbound_onboarding_only_and_fails_closed() {
    let temp = Temp::new();
    let maker = manufacturer(&temp);
    let cloud_crl = crl(&temp, "cloud", &pki().ca, &pki().key, 3600);
    let maker_crl = crl(&temp, "maker", &maker.ca, &maker.key, 3600);
    let mut f = Fixture::new("onboarding");
    f.config.crl_file = Some(cloud_crl.clone());
    // without bootstrap trust the bootstrap certificate is refused at the handshake
    assert!(
        !handshake(
            security::Tls::load(&f.config)
                .unwrap()
                .server_current()
                .unwrap(),
            &maker.bootstrap,
            &maker.bootstrap_key
        )
        .await
    );
    f.config.bootstrap_ca = Some(maker.ca.clone());
    f.config.bootstrap_crl = Some(maker_crl.clone());
    f.config.validate().unwrap();
    let tls = security::Tls::load(&f.config).unwrap();
    assert!(
        handshake(
            tls.server_current().unwrap(),
            &maker.bootstrap,
            &maker.bootstrap_key
        )
        .await
    );
    let (sy, sy_key) = pki().leaf(&temp, "TestProvider", "sy");
    assert!(
        handshake(tls.server_current().unwrap(), &sy, &sy_key).await,
        "cloud peers still admitted"
    );
    // never outbound: a manufacturer-issued "server" certificate is not trusted by the pinned client verifier
    let maker_server = temp
        .0
        .join("maker-server.pem")
        .to_string_lossy()
        .to_string();
    let maker_server_key = temp
        .0
        .join("maker-server.key")
        .to_string_lossy()
        .to_string();
    let csr = temp
        .0
        .join("maker-server.csr")
        .to_string_lossy()
        .to_string();
    openssl(&[
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        &maker_server_key,
        "-out",
        &csr,
        "-subj",
        &format!("/CN=CertificateAuthority.{SUFFIX}/dnQualifier=sy"),
    ]);
    let ext = temp.file("maker-server.ext", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost\n");
    openssl(&[
        "x509",
        "-req",
        "-in",
        &csr,
        "-CA",
        &maker.ca,
        "-CAkey",
        &maker.key,
        "-set_serial",
        "0x99",
        "-out",
        &maker_server,
        "-days",
        "1",
        "-extfile",
        &ext,
    ]);
    let fake = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        rustls::pki_types::pem::PemObject::pem_slice_iter(&fs::read(&maker_server).unwrap())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap(),
        rustls::pki_types::pem::PemObject::from_pem_slice(&fs::read(&maker_server_key).unwrap())
            .unwrap(),
    )
    .unwrap();
    let (a, b) = tokio::io::duplex(1 << 16);
    let accept = tokio_rustls::TlsAcceptor::from(Arc::new(fake)).accept(a);
    let connect = tokio_rustls::TlsConnector::from(Arc::new(
        tls.client_config("CertificateAuthority.RustCloud.Company.arrowhead.eu")
            .unwrap(),
    ))
    .connect(
        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
        b,
    );
    let (_, connected) = tokio::join!(accept, connect);
    assert!(
        connected.is_err(),
        "outbound verifier trusted the manufacturer CA"
    );
    // fail closed: missing manufacturer CRL, expired manufacturer CRL, bootstrap trust on another role
    let mut missing = f.config.clone();
    missing.bootstrap_crl = Some(temp.0.join("absent.crl.pem").to_string_lossy().to_string());
    assert!(security::Tls::load(&missing).is_err());
    let mut no_crl = f.config.clone();
    no_crl.bootstrap_crl = None;
    assert!(no_crl.validate().is_err());
    let mut expired = f.config.clone();
    expired.bootstrap_crl = Some(crl(&temp, "expired", &maker.ca, &maker.key, 1));
    std::thread::sleep(std::time::Duration::from_secs(2));
    let tls = security::Tls::load(&expired).unwrap();
    assert!(
        !handshake(
            tls.server_current().unwrap(),
            &maker.bootstrap,
            &maker.bootstrap_key
        )
        .await
    );
    let mut other = Fixture::new("blacklist");
    other.config.crl_file = Some(cloud_crl);
    other.config.bootstrap_ca = Some(maker.ca.clone());
    other.config.bootstrap_crl = Some(maker_crl);
    assert!(other.config.validate().is_err());
    assert!(security::Tls::load(&other.config).is_err());
}
