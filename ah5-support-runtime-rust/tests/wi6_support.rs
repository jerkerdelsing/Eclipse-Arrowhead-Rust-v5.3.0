// SPDX-License-Identifier: EPL-2.0
mod common;
use arrowhead_support_rust::basic::time;
use arrowhead_support_rust::*;
use axum::http::HeaderMap;
use common::*;
use serde_json::{Value, json};
async fn call(
    f: &Fixture,
    method: &str,
    path: &str,
    q: Value,
    req: Value,
    who: &str,
) -> Result<(u16, Value)> {
    let route = contracts::routes(&f.config.role)
        .into_iter()
        .find_map(|r| {
            if r.method == method {
                web::parameters(&r.path, path).map(|p| (r, p))
            } else {
                None
            }
        })
        .expect("Known contract");
    web::handle(
        &f.app,
        method,
        path,
        &route.1,
        &q,
        &req,
        &caller(who),
        &HeaderMap::new(),
    )
    .await
}
const PATH: &str = "/datamanager/data-historian/systems/Producer/services/power/data";
#[tokio::test]
async fn senml_base_value_sum_and_version() {
    let f = Fixture::new("datamanager");
    call(&f, "PUT", PATH, empty(), json!([{"bn":"m/","bt":1000.,"bu":"W","bv":100.,"bs":5.,"bver":10,"n":"p","v":1.},{"n":"p","t":1.,"v":2.,"s":3.},{"n":"q","t":2.}]), "Producer").await.unwrap();
    let rows = f.app.store.rows("senml");
    let mut values = rows
        .iter()
        .map(|r| {
            (
                r["epoch"].as_f64().unwrap(),
                r["value"].clone(),
                r["sum"].clone(),
            )
        })
        .collect::<Vec<_>>();
    values.sort_by(|a, b| a.0.total_cmp(&b.0));
    assert_eq!(values[0].1, 101.);
    assert_eq!(values[1].1, 102.);
    assert_eq!(values[1].2, 8.);
    assert_eq!(values[2].1, 100.);
    let out = call(
        &f,
        "GET",
        PATH,
        json!({"from":["1001"],"to":["1001"]}),
        empty(),
        "Client",
    )
    .await
    .unwrap()
    .1;
    assert_eq!(out[0]["bv"], 100.);
    assert_eq!(out[0]["bs"], 5.);
    assert_eq!(out[0]["bu"], "W");
    assert_eq!(out[0]["bver"], 10);
    assert_eq!(out[0]["bn"], "m/");
    // Legacy "ver" alias and version bounds.
    call(
        &f,
        "PUT",
        PATH,
        empty(),
        json!([{"bn":"x","ver":10,"v":1.}]),
        "Producer",
    )
    .await
    .unwrap();
    for bad in [
        json!([{"bn":"x","bver":11,"v":1.}]),
        json!([{"bn":"x","bv":"a","v":1.}]),
        json!([{"bn":"x","n":"y"}]),
    ] {
        assert_eq!(
            call(&f, "PUT", PATH, empty(), bad, "Producer")
                .await
                .unwrap_err()
                .code,
            400
        );
    }
}
#[tokio::test]
async fn senml_signal_count_per_signal() {
    let f = Fixture::new("datamanager");
    call(&f, "PUT", PATH, empty(), json!([{"bn":"m/","bt":1000.,"n":"a","v":1.},{"n":"a","t":1.,"v":2.},{"n":"a","t":2.,"v":3.},{"n":"b","t":3.,"v":4.},{"n":"b","t":4.,"v":5.}]), "Producer").await.unwrap();
    let out = call(
        &f,
        "GET",
        PATH,
        json!({"signals":["m/a","m/b"],"signalCount":["2"]}),
        empty(),
        "Client",
    )
    .await
    .unwrap()
    .1;
    let names = out
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["n"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(names, ["b", "b", "a", "a"]);
    assert_eq!(out[2]["t"], 2.);
    assert_eq!(
        call(
            &f,
            "GET",
            PATH,
            json!({"signalCount":["1001"]}),
            empty(),
            "Client"
        )
        .await
        .unwrap_err()
        .code,
        400
    );
}
#[test]
fn ntp_timestamp_roundtrip_and_offset() {
    let mut b = [0u8; 48];
    time::write_timestamp(&mut b, 40, 1_700_000_000_123);
    assert!((time::read_timestamp(&b, 40) - 1_700_000_000_123).abs() <= 1);
    assert_eq!(time::offset(1000, 1600, 1610, 1020), 595);
    assert_eq!(time::delay(1000, 1600, 1610, 1020), 10);
}
#[test]
fn ntp_evaluate_rejects_bad_replies() {
    let req = time::request(1_700_000_000_000);
    let mut resp = [0u8; 48];
    resp[0] = 0x24;
    resp[1] = 2;
    resp[24..32].copy_from_slice(&req[40..48]);
    time::write_timestamp(&mut resp, 32, 1_700_000_000_500);
    time::write_timestamp(&mut resp, 40, 1_700_000_000_500);
    let m = time::evaluate("s", &req, &resp, 1_700_000_000_000, 1_700_000_000_000).unwrap();
    assert_eq!((m.offset_ms, m.stratum), (500, 2));
    let mut kod = resp;
    kod[1] = 0;
    assert!(time::evaluate("s", &req, &kod, 0, 0).is_err());
    let mut stale = resp;
    stale[24] ^= 1;
    assert!(time::evaluate("s", &req, &stale, 0, 0).is_err());
    let mut client = resp;
    client[0] = 0x23;
    assert!(time::evaluate("s", &req, &client, 0, 0).is_err());
}
async fn fake_server(skew_ms: i64) -> u16 {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 48];
        while let Ok((_, peer)) = socket.recv_from(&mut buf).await {
            let now = chrono::Utc::now().timestamp_millis() + skew_ms;
            let mut resp = [0u8; 48];
            resp[0] = 0x24;
            resp[1] = 1;
            resp[24..32].copy_from_slice(&buf[40..48]);
            time::write_timestamp(&mut resp, 32, now);
            time::write_timestamp(&mut resp, 40, now);
            let _ = socket.send_to(&resp, peer).await;
        }
    });
    port
}
#[tokio::test]
async fn trust_follows_threshold_and_fallback() {
    let settings = |t| time::Settings {
        servers: vec!["127.0.0.1".into()],
        threshold_ms: t,
        interval_ms: 1000,
        timeout_ms: 500,
    };
    let port = fake_server(2000).await;
    let ok = time::check(&settings(5000), port).await;
    assert!(ok.trusted, "{}", ok.detail);
    assert!((ok.offset_ms.unwrap() - 2000).abs() < 200);
    let skewed = time::check(&settings(1000), port).await;
    assert!(!skewed.trusted && skewed.detail.contains("exceeds"));
    let none = time::check(
        &time::Settings {
            servers: vec![],
            ..settings(1000)
        },
        port,
    )
    .await;
    assert_eq!(none.detail, "No NTP server configured");
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead = time::check(&settings(5000), silent.local_addr().unwrap().port()).await;
    assert!(!dead.trusted && dead.detail.contains("No NTP server reachable"));
}
