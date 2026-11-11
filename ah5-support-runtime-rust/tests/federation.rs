// SPDX-License-Identifier: EPL-2.0
mod common;
use arrowhead_support_rust::*;
use common::*;
use serde_json::json;
use std::collections::BTreeMap;
#[test]
fn negotiated_operations_are_segment_scoped_and_traversal_safe() {
    let ops = json!({"put-data":{"method":"PUT","path":"/{systemName}/{serviceName}"}});
    assert!(federation::tunnel::operation_allowed(
        "PUT",
        "/data/RandomDataProducer/randomNumberProducer?x=1",
        "/data",
        &ops
    ));
    for path in [
        "/data/a/b/extra",
        "/database/a/b",
        "//data/a/b",
        "https://evil/data/a/b",
        "/data/../b",
        "/data/%2E/b",
        "/data/%252e/b",
        "/data/a%2fb/b",
        "/data/a\\b/b",
        "/data/a/b#fragment",
    ] {
        assert!(
            !federation::tunnel::operation_allowed("PUT", path, "/data", &ops),
            "{path}"
        );
    }
    assert!(!federation::tunnel::operation_allowed(
        "GET",
        "/data/a/b",
        "/data",
        &ops
    ));
}
#[test]
fn peer_requires_explicit_cloud_organisation_and_gatekeeper_neighbour() {
    let mut f = Fixture::new("gatekeeper");
    f.config.federation = Some(federation::Config {
        host: "relay".into(),
        port: 8883,
        relay_common_name: "Relay.Company.arrowhead.eu".into(),
        certificate: f.config.certificate.clone(),
        private_key: f.config.private_key.clone(),
        ca: f.config.ca.clone(),
        crl_files: vec!["/public/crl".into()],
        peers: BTreeMap::from([("RustDev".into(), "Lab".into())]),
        foreign_targets: Vec::new(),
        min_port: 8200,
        max_port: 8207,
    });
    f.reconfigure();
    let expected = "Gatekeeper.RustDev.Lab.arrowhead.eu";
    assert!(!federation::trusted(&f.app, expected));
    f.app
        .store
        .update(|db| {
            table(db, "clouds").insert(
                "Lab|RustDev".into(),
                json!({"name":"RustDev","operator":"Lab"}),
            );
            Ok(())
        })
        .unwrap();
    assert!(federation::trusted(&f.app, expected));
    for peer in [
        "Gatekeeper.RustDev.Company.arrowhead.eu",
        "GateTunnel.RustDev.Lab.arrowhead.eu",
        "Gatekeeper.Other.Lab.arrowhead.eu",
    ] {
        assert!(!federation::trusted(&f.app, peer));
    }
}
#[tokio::test]
async fn ordinary_caller_cannot_open_an_intercloud_listener() {
    let f = Fixture::new("gatetunnel");
    assert_eq!(
        federation::tunnel::handle(
            &f.app,
            "POST",
            "/gatetunnel/intercloud/consumer",
            &json!({}),
            &caller("Sysop")
        )
        .await
        .unwrap_err()
        .code,
        403
    );
}

/// SOS-7 (2026-11-10): consumers reach a neighbour of another organisation only when foreignTargets lists it.
#[test]
fn foreign_targets_are_explicit() {
    let mut f = Fixture::new("gatekeeper");
    let own_org = SUFFIX.split('.').nth(1).unwrap().to_string();
    let (certificate, private_key, ca) = (
        f.config.certificate.clone(),
        f.config.private_key.clone(),
        f.config.ca.clone(),
    );
    let config = |foreign: Vec<String>| federation::Config {
        host: "relay".into(),
        port: 8883,
        relay_common_name: "Relay.Company.arrowhead.eu".into(),
        certificate: certificate.clone(),
        private_key: private_key.clone(),
        ca: ca.clone(),
        crl_files: vec!["/public/crl".into()],
        peers: BTreeMap::from([
            ("RustDev".into(), "Lab".into()),
            ("Sibling".into(), own_org.clone()),
        ]),
        foreign_targets: foreign,
        min_port: 8200,
        max_port: 8207,
    };
    let own = SUFFIX.split('.').next().unwrap();
    for bad in [
        "RustDev",
        "RustDev|Other",
        &format!("RustDev|{own_org}"),
        &format!("Sibling|{own_org}"),
        "Unknown|Lab",
        &format!("{own}|Lab"),
        "RustDev|Lab|x",
    ] {
        assert!(
            config(vec![bad.to_string()])
                .validate("gatekeeper", SUFFIX)
                .is_err(),
            "{bad}"
        );
    }
    f.config.federation = Some(config(Vec::new()));
    f.reconfigure();
    assert!(federation::target_allowed(&f.app, "Sibling"));
    assert!(!federation::target_allowed(&f.app, "RustDev"));
    assert!(!federation::target_allowed(&f.app, "Unknown"));
    f.config.federation = Some(config(vec!["RustDev|Lab".into()]));
    f.reconfigure();
    assert!(federation::target_allowed(&f.app, "RustDev"));
}
