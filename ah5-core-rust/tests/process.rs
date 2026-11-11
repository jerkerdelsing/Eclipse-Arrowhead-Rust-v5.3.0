// SPDX-License-Identifier: EPL-2.0
mod common;
use arrowhead_core_rust::*;
use common::*;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn all_five_named_executables_start_and_reject_role_mismatch() {
    for binary in [
        env!("CARGO_BIN_EXE_serviceregistry"),
        env!("CARGO_BIN_EXE_authentication"),
        env!("CARGO_BIN_EXE_consumer-authorization"),
        env!("CARGO_BIN_EXE_serviceorchestration-dynamic"),
        env!("CARGO_BIN_EXE_serviceorchestration-simple"),
    ] {
        let out = Command::new(binary).arg("--help").output().unwrap();
        assert!(out.status.success());
        assert!(String::from_utf8_lossy(&out.stdout).contains("--config"));
    }
    let f = Fixture::new("authentication");
    let path = f
        .temp
        .file("config.json", serde_json::to_vec(&f.config).unwrap());
    let out = Command::new(env!("CARGO_BIN_EXE_serviceregistry"))
        .args(["--config", &path])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("role does not match"));
}

#[tokio::test]
async fn native_authentication_process_persists_and_shuts_down_gracefully() {
    let mut f = Fixture::new("authentication");
    f.config.bootstrap_identities = vec![config::Seed {
        system_name: "Sysop".into(),
        password_file: f.config.password_file.clone(),
        sysop: true,
    }];
    let path = f
        .temp
        .file("config.json", serde_json::to_vec(&f.config).unwrap());
    let child = Command::new(env!("CARGO_BIN_EXE_authentication"))
        .args(["--config", &path])
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let mut guard = ChildGuard(child);
    let stderr = guard.0.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let result = BufReader::new(stderr).read_line(&mut text);
        let _ = tx.send((result, text));
    });
    let (result, line) = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("Native server did not report startup");
    result.unwrap();
    assert!(line.contains("mandatory mutual TLS"), "{line}");
    let address = line
        .split("listening on ")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap();
    let origin = format!("https://{address}");
    let sysop = Fixture::named("authentication", "Sysop");
    let (code, response) = api(
        &sysop.tls,
        "Authentication",
        &origin,
        "POST",
        "/authentication/identity/login",
        "",
        json!({"systemName":"Sysop","credentials":{"password":"private-test-password"}}),
    )
    .await;
    assert_eq!(code, 200, "{response}");
    let token = s(&response, "token");
    let (code, response) = api(
        &sysop.tls,
        "Authentication",
        &origin,
        "POST",
        "/authentication/mgmt/identities/query",
        token,
        json!({}),
    )
    .await;
    assert_eq!(code, 200, "{response}");
    assert_eq!(response["count"], 1);
    assert!(
        Command::new("kill")
            .args(["-TERM", &guard.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = guard.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "Native server did not shut down");
        std::thread::sleep(Duration::from_millis(20));
    }
    let store = Store::open(&f.config.state).unwrap();
    assert_eq!(store.rows("identities").len(), 1);
    assert_eq!(store.rows("sessions").len(), 1);
    let raw = String::from_utf8(read(&f.config.state)).unwrap();
    assert!(!raw.contains("private-test-password") && !raw.contains(token));
}

#[tokio::test]
async fn configured_crl_rejects_a_revoked_client_certificate() {
    let mut f = Fixture::new("authentication");
    let consumer = Fixture::named("authentication", "Consumer");
    let ca = pki();
    let index = f.temp.file("index.txt", "");
    let serial = f.temp.file("serial", "01\n");
    let crlnumber = f.temp.file("crlnumber", "01\n");
    let cnf=f.temp.file("ca.cnf",format!("[ca]\ndefault_ca=CA_default\n[CA_default]\ndatabase={index}\nnew_certs_dir={}\ncertificate={}\nprivate_key={}\nserial={serial}\ncrlnumber={crlnumber}\ndefault_md=sha256\ndefault_crl_days=1\npolicy=policy\n[policy]\ncommonName=supplied\n",f.temp.0.display(),ca.ca,ca.key));
    openssl(&[
        "ca",
        "-batch",
        "-config",
        &cnf,
        "-revoke",
        &consumer.config.certificate,
    ]);
    let crl = f
        .temp
        .0
        .join("revocations.pem")
        .to_string_lossy()
        .to_string();
    openssl(&["ca", "-batch", "-config", &cnf, "-gencrl", "-out", &crl]);
    f.config.crl_file = Some(crl);
    let tls = security::Tls::load(&f.config).unwrap();
    let app = App::new(f.config.clone(), Store::memory(), tls.clone()).unwrap();
    let server = start(app, tls).await;
    let client = consumer
        .tls
        .client(&format!("Authentication.{SUFFIX}"))
        .unwrap();
    assert!(
        client
            .get(format!("{}/authentication/monitor/echo", server.origin))
            .send()
            .await
            .is_err()
    );
    let sysop = Fixture::named("authentication", "Sysop");
    let (code, text) = api(
        &sysop.tls,
        "Authentication",
        &server.origin,
        "GET",
        "/authentication/monitor/echo",
        "",
        Value::Null,
    )
    .await;
    assert_eq!(code, 200);
    assert_eq!(text, "Got it!");
}
