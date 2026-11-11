// SPDX-License-Identifier: EPL-2.0
use std::process::Command;
#[test]
fn dedicated_launcher_help_and_role_guard() {
    let bin = env!("CARGO_BIN_EXE_LocalCloudManager");
    let out = Command::new(bin).arg("--help").output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("127.0.0.1:8480"));
    let out = Command::new(bin)
        .env("ARROWHEAD_ROLE", "authentication")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("only runs the localcloudmanager role"))
}
