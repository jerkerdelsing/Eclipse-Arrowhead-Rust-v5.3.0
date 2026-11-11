// SPDX-License-Identifier: EPL-2.0
mod common;
use arrowhead_core_rust::*;
use axum::{body::Body, http::Request};
use common::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tower::ServiceExt;
#[tokio::test]
async fn foreign_policy_and_tokens_are_bound_to_both_cloud_components() {
    let f = Fixture::new("consumer-authorization");
    f.app.store.update(|db|{authorization::grant(db,json!({"provider":"Provider","cloud":"RustDev|Lab","targetType":"SERVICE_DEF","target":"sample","defaultPolicy":{"policyType":"WHITELIST","policyList":["Consumer"]}}),"MGMT","Sysop")?;Ok(())}).unwrap();
    let target = json!({"provider":"Provider","consumer":"Consumer","cloud":"RustDev|Lab","targetType":"SERVICE_DEF","target":"sample"});
    assert!(
        authorization::granted(&f.app, target.clone())
            .await
            .unwrap()
    );
    for cloud in ["LOCAL", "RustDev|Company", "Other|Lab"] {
        let mut req = target.clone();
        req["cloud"] = cloud.into();
        assert!(!authorization::granted(&f.app, req).await.unwrap());
    }
    let req = json!({"list":[{"provider":"Provider","consumer":"Consumer","consumerCloud":"RustDev|Lab","targetType":"SERVICE_DEF","target":"sample","tokenVariant":"USAGE_LIMITED_TOKEN_AUTH","usageLimit":2}]});
    let (_, result) = tokens::handle(
        &f.app,
        "POST",
        "/consumerauthorization/authorization/mgmt/token/generate",
        &BTreeMap::new(),
        &json!({}),
        &req,
        &caller("Sysop"),
    )
    .await
    .unwrap();
    assert_eq!(result["entries"][0]["consumerCloud"], "RustDev|Lab");
    let mut wrong = req;
    wrong["list"][0]["consumerCloud"] = "RustDev|Company".into();
    assert_eq!(
        tokens::handle(
            &f.app,
            "POST",
            "/consumerauthorization/authorization/mgmt/token/generate",
            &BTreeMap::new(),
            &json!({}),
            &wrong,
            &caller("Sysop")
        )
        .await
        .unwrap_err()
        .code,
        403
    );
    for cloud in ["RustDev|Lab|extra", "|Lab", "RustDev|", "RustDev\n|Lab"] {
        assert!(!authorization::valid_cloud(cloud));
    }
}
#[tokio::test]
async fn check_policy_delegation_does_not_grant_policy_administration() {
    let (_auth, auth) = mock_auth().await;
    let mut f = Fixture::new("consumer-authorization");
    f.config.authentication_url = auth.origin.clone();
    f.reconfigure();
    f.app.store.update(|db|{authorization::grant(db,json!({"provider":"ConsumerAuthorization","targetType":"SERVICE_DEF","target":"authorizationManagement","defaultPolicy":{"policyType":"WHITELIST","policyList":[]},"scopedPolicies":{"check-policies":{"policyType":"WHITELIST","policyList":["Gatekeeper"]}}}),"MGMT","Sysop")?;Ok(())}).unwrap();
    for (operation, body, expected) in [
        (
            "check",
            json!({"list":[{"provider":"Provider","consumer":"Consumer","cloud":"RustDev|Lab","targetType":"SERVICE_DEF","target":"sample"}]}),
            200,
        ),
        ("grant", json!({"list":[]}), 403),
    ] {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!(
                "/consumerauthorization/authorization/mgmt/{operation}"
            ))
            .header("authorization", "Bearer IDENTITY-TOKEN//token-Gatekeeper")
            .body(Body::from(body.to_string()))
            .unwrap();
        request.extensions_mut().insert(caller("Gatekeeper"));
        let response = web::router(f.app.clone()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), expected);
    }
}
#[tokio::test]
async fn intercloud_flags_require_enabled_config_and_exactly_one_operation() {
    let f = Fixture::new("serviceorchestration-dynamic");
    for operations in [
        json!([]),
        json!(["put-data", "get-data"]),
        json!(["put-data"]),
    ] {
        let request = json!({"serviceRequirement":{"serviceDefinition":"dataHistorian","operations":operations},"orchestrationFlags":{"ONLY_INTERCLOUD":true}});
        assert_eq!(
            orchestration::pull(&f.app, &request, "Consumer", "job")
                .await
                .unwrap_err()
                .code,
            400
        );
    }
    let mut f = f;
    f.config.intercloud_enabled = true;
    f.reconfigure();
    let response=orchestration::pull(&f.app,&json!({"serviceRequirement":{"serviceDefinition":"dataHistorian","operations":["put-data"]},"orchestrationFlags":{"ONLY_INTERCLOUD":true}}),"Consumer","job").await.unwrap();
    assert!(response["results"].as_array().unwrap().is_empty());
    assert!(
        response["warnings"]
            .as_array()
            .unwrap()
            .contains(&Value::String("interCloudFailed".into()))
    );
}
