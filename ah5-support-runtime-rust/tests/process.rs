// SPDX-License-Identifier: EPL-2.0
mod common;
use arrowhead_support_rust::*;
use common::*;
use serde_json::Value;
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
fn fifteen_binaries_and_enforced_role() {
    for bin in [
        env!("CARGO_BIN_EXE_blacklist"),
        env!("CARGO_BIN_EXE_configuration"),
        env!("CARGO_BIN_EXE_datamanager"),
        env!("CARGO_BIN_EXE_timemanager"),
        env!("CARGO_BIN_EXE_aigym"),
        env!("CARGO_BIN_EXE_eventhandler"),
        env!("CARGO_BIN_EXE_deviceqosevaluator"),
        env!("CARGO_BIN_EXE_plantdescriptionengine"),
        env!("CARGO_BIN_EXE_choreographer"),
        env!("CARGO_BIN_EXE_certificateauthority"),
        env!("CARGO_BIN_EXE_sysmonitor"),
        env!("CARGO_BIN_EXE_onboarding"),
        env!("CARGO_BIN_EXE_translationmanager"),
        env!("CARGO_BIN_EXE_gatekeeper"),
        env!("CARGO_BIN_EXE_gatetunnel"),
    ] {
        let out = Command::new(bin).arg("--help").output().unwrap();
        assert!(out.status.success());
        assert!(String::from_utf8_lossy(&out.stdout).contains("--config"));
    }
    let f = Fixture::new("configuration");
    let path = f
        .temp
        .file("config.json", serde_json::to_vec(&f.config).unwrap());
    let out = Command::new(env!("CARGO_BIN_EXE_blacklist"))
        .args(["--config", &path])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("role does not match"));
}
#[tokio::test]
async fn native_process_mutual_tls_state_and_bounded_shutdown() {
    let f = Fixture::new("blacklist");
    let path = f
        .temp
        .file("config.json", serde_json::to_vec(&f.config).unwrap());
    let child = Command::new(env!("CARGO_BIN_EXE_blacklist"))
        .args(["--config", &path])
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let mut guard = ChildGuard(child);
    let stderr = guard.0.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stderr).read_line(&mut line);
        let _ = tx.send((result, line));
    });
    let (result, line) = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("Native listener startup timeout");
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
    let client = Fixture::named("blacklist", "Client");
    let (code, _) = api(
        &client.tls,
        "Blacklist",
        &origin,
        "GET",
        "/blacklist/monitor/echo",
        "",
        Value::Null,
    )
    .await;
    assert_eq!(code, 200);
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
        assert!(
            Instant::now() < deadline,
            "Graceful shutdown exceeded bound"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let store = Store::open(&f.config.state).unwrap();
    assert!(!store.rows("logs").is_empty());
}
