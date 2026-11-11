// SPDX-License-Identifier: EPL-2.0
mod common;
use arrowhead_core_rust::*;
use common::*;
use serde_json::json;
#[tokio::test]
async fn snapshot_permissions_empty_scopes_and_intercloud_guard() {
    let f = Fixture::new("serviceorchestration-dynamic");
    let pde = Principal {
        name: "PlantDescriptionEngine".into(),
        sysop: false,
        profile: "sy".into(),
    };
    let console = Principal {
        name: "LocalCloudManager".into(),
        sysop: false,
        profile: "sy".into(),
    };
    let snapshot =
        json!({"rules":[{"consumer":"Consumer","serviceDefinition":"temperature","providers":[]}]});
    assert_eq!(
        plant_rules::handle(&f.app, "PUT", &snapshot, &console)
            .unwrap_err()
            .code,
        403
    );
    plant_rules::handle(&f.app, "PUT", &snapshot, &pde).unwrap();
    assert_eq!(
        plant_rules::handle(&f.app, "POST", &json!({}), &console)
            .unwrap()
            .1,
        snapshot
    );
    assert!(plant_rules::handle(&f.app, "PUT", &json!({"rules":null}), &pde).is_err());
    assert_eq!(plant_rules::snapshot(&f.app), snapshot);
    assert!(
        plant_rules::ranks(&f.app, "Consumer", "temperature")
            .unwrap()
            .is_empty()
    );
    let result=orchestration::pull(&f.app,&json!({"serviceRequirement":{"serviceDefinition":"temperature"},"orchestrationFlags":{"ONLY_INTERCLOUD":true}}),"Consumer","").await.unwrap();
    assert_eq!(result["results"], json!([]));
}
