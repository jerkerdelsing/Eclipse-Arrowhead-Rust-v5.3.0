// SPDX-License-Identifier: EPL-2.0
mod common;
use arrowhead_core_rust::*;
use axum::{body::Body, http::Request};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use common::*;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, sync::Arc};
use tower::ServiceExt;

#[test]
fn generated_configuration_examples_match_the_strict_rust_schema() {
    for (role, _, _) in config::ROLES {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join(format!("{role}.json"));
        let config = Config::load(path).unwrap();
        assert_eq!(config.role, role);
        assert!(!config.register);
    }
}

#[tokio::test]
async fn malformed_nested_grants_and_token_batches_return_errors_instead_of_panicking() {
    let (_fixture, auth) = mock_auth().await;
    let mut f = Fixture::new("consumer-authorization");
    f.config.authentication_url = auth.origin.clone();
    f.reconfigure();
    for path in [
        "/consumerauthorization/authorization/mgmt/grant",
        "/consumerauthorization/authorization/mgmt/token/generate",
    ] {
        let mut request = Request::builder()
            .method("POST")
            .uri(path)
            .header("authorization", "Bearer IDENTITY-TOKEN//token-Sysop")
            .body(Body::from(r#"{"list":[null,[],42]}"#))
            .unwrap();
        request.extensions_mut().insert(caller("Sysop"));
        let response = web::router(f.app.clone()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), 400);
    }
}

#[test]
fn all_five_roles_have_unique_complete_route_descriptors() {
    for (role, _, _) in config::ROLES {
        let routes = contracts::routes(role);
        let mut keys = std::collections::BTreeSet::new();
        for route in &routes {
            assert!(keys.insert(format!("{} {}", route.method, route.path)));
            assert!(!route.access.is_empty());
            assert!(route.implemented)
        }
        for service in contracts::services(role) {
            for operation in service.operations.values() {
                assert!(routes.iter().any(|r| r.method == operation["method"]
                    && r.path
                        == format!(
                            "{}{}",
                            service.base_path,
                            operation["path"].as_str().unwrap()
                        )));
            }
        }
    }
}
#[test]
fn config_is_strict_and_has_no_insecure_transport_mode() {
    let f = Fixture::new("authentication");
    let mut v = serde_json::to_value(&f.config).unwrap();
    v["insecure"] = true.into();
    assert!(serde_json::from_value::<Config>(v).is_err());
    let mut c = f.config.clone();
    c.authentication_url = "http://127.0.0.1:1".into();
    assert!(c.validate().is_err());
}
#[test]
fn der_identity_is_profile_bound_and_rejects_malformed_values() {
    let f = Fixture::new("authentication");
    let cert = CertificateDer::from_pem_slice(&read(&f.config.certificate)).unwrap();
    let peer = security::peer(&cert, SUFFIX).unwrap();
    assert_eq!(peer.name, "Authentication");
    assert_eq!(peer.profile, "sy");
    assert!(security::peer(&cert, "Other.Company.arrowhead.eu").is_err());
    let mut trailing = cert.to_vec();
    trailing.push(0);
    assert!(security::subject(&trailing).is_err());
    for bad in [vec![], vec![0x30, 0x80], vec![0x30, 0xff, 0xff]] {
        assert!(security::subject(&bad).is_err());
    }
}
#[test]
fn private_key_permissions_are_enforced() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new("authentication");
    fs::set_permissions(&f.config.private_key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(security::Tls::load(&f.config).is_err());
}
#[test]
fn state_lock_corruption_and_failed_commit_do_not_reset_data() {
    let temp = Temp::new();
    let path = temp.0.join("db.json");
    let store = Store::open(&path).unwrap();
    assert!(Store::open(&path).is_err());
    store
        .update(|db| {
            table(db, "records").insert("one".into(), json!({"value":1}));
            Ok(())
        })
        .unwrap();
    assert!(
        store
            .update(|db| {
                table(db, "records").clear();
                Err::<(), _>(Error::bad("rollback"))
            })
            .is_err()
    );
    assert_eq!(store.rows("records").len(), 1);
    drop(store);
    let store = Store::open(&path).unwrap();
    assert_eq!(store.rows("records").len(), 1);
    drop(store);
    fs::write(&path, "not-json").unwrap();
    assert!(Store::open(&path).is_err());
    let blocked = temp.0.join("blocked.json");
    let store = Store::open(&blocked).unwrap();
    fs::create_dir(&blocked).unwrap();
    assert!(
        store
            .update(|db| {
                table(db, "records").insert("bad".into(), json!({}));
                Ok(())
            })
            .is_err()
    );
    assert!(store.rows("records").is_empty());
}
#[test]
fn state_updates_are_serialized_and_do_not_publish_aliases() {
    let store = Arc::new(Store::memory());
    let mut handles = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                store
                    .update(|db| {
                        let row = table(db, "count")
                            .entry("total".into())
                            .or_insert(json!({"value":0}));
                        row["value"] = (row["value"].as_u64().unwrap() + 1).into();
                        Ok(())
                    })
                    .unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap()
    }
    assert_eq!(store.rows("count")[0]["value"], 800);
    let mut snapshot = store.snapshot();
    snapshot.clear();
    assert!(!store.rows("count").is_empty());
}
#[test]
fn authentication_revokes_previous_sessions_and_credentials() {
    let f = Fixture::new("authentication");
    seed_identity(&f.app, "Consumer", "one-password", false);
    let p = caller("Consumer");
    let request = json!({"systemName":"Consumer","credentials":{"password":"one-password"}});
    let (_, first) = authentication::handle(
        &f.app,
        "POST",
        "/authentication/identity/login",
        &BTreeMap::new(),
        &empty(),
        &request,
        &p,
    )
    .unwrap();
    let (_, second) = authentication::handle(
        &f.app,
        "POST",
        "/authentication/identity/login",
        &BTreeMap::new(),
        &empty(),
        &request,
        &p,
    )
    .unwrap();
    assert_eq!(
        authentication::verify(&f.app.store, s(&first, "token"))["verified"],
        false
    );
    assert_eq!(
        authentication::verify(&f.app.store, s(&second, "token"))["verified"],
        true
    );
    let mut change = request.clone();
    change["newCredentials"] = json!({"password":"second-password"});
    authentication::handle(
        &f.app,
        "POST",
        "/authentication/identity/change",
        &BTreeMap::new(),
        &empty(),
        &change,
        &p,
    )
    .unwrap();
    assert_eq!(
        authentication::verify(&f.app.store, s(&second, "token"))["verified"],
        false
    );
    assert!(
        authentication::handle(
            &f.app,
            "POST",
            "/authentication/identity/login",
            &BTreeMap::new(),
            &empty(),
            &request,
            &p
        )
        .is_err()
    );
    assert!(
        authentication::handle(
            &f.app,
            "POST",
            "/authentication/identity/login",
            &BTreeMap::new(),
            &empty(),
            &change,
            &caller("Other")
        )
        .is_err()
    );
    let raw = serde_json::to_string(&f.app.store.snapshot()).unwrap();
    assert!(
        !raw.contains("one-password")
            && !raw.contains("second-password")
            && !raw.contains(s(&second, "token"))
    );
}
#[tokio::test]
async fn declared_identity_and_unverified_headers_are_rejected() {
    let f = Fixture::new("authentication");
    let request = Request::builder()
        .uri("/authentication/mgmt/identities/query")
        .method("POST")
        .header("authorization", "Bearer SYSTEM//Sysop")
        .header("x-arrowhead-verified-identity", "Sysop")
        .body(Body::from("{}"))
        .unwrap();
    let response = web::router(f.app).oneshot(request).await.unwrap();
    assert_eq!(response.status(), 401);
}
#[tokio::test]
async fn token_certificate_binding_and_management_guard_fail_closed() {
    let f = Fixture::new("authentication");
    seed_identity(&f.app, "Consumer", "password", false);
    let (_, login) = authentication::handle(
        &f.app,
        "POST",
        "/authentication/identity/login",
        &BTreeMap::new(),
        &empty(),
        &json!({"systemName":"Consumer","credentials":{"password":"password"}}),
        &caller("Consumer"),
    )
    .unwrap();
    assert!(
        security::authenticate(
            &f.app,
            caller("Other"),
            Some(&format!("Bearer IDENTITY-TOKEN//{}", s(&login, "token")))
        )
        .await
        .is_err()
    );
    let mut request = Request::builder()
        .method("POST")
        .uri("/authentication/mgmt/identities/query")
        .header(
            "authorization",
            format!("Bearer IDENTITY-TOKEN//{}", s(&login, "token")),
        )
        .body(Body::from("{}"))
        .unwrap();
    request.extensions_mut().insert(caller("Consumer"));
    assert_eq!(
        web::router(f.app).oneshot(request).await.unwrap().status(),
        403
    );
}
#[tokio::test]
async fn policy_precedence_scopes_and_revocation_follow_java_model() {
    let f = Fixture::new("consumer-authorization");
    let req = json!({"provider":"Provider","consumer":"Consumer","cloud":"LOCAL","targetType":"SERVICE_DEF","target":"temperature","scope":"read"});
    f.app.store.update(|db|{authorization::grant(db,json!({"provider":"Provider","targetType":"SERVICE_DEF","target":"temperature","defaultPolicy":{"policyType":"ALL"},"scopedPolicies":{"write":{"policyType":"WHITELIST","policyList":["Writer"]}}}),"PROVIDER","Provider")?;Ok(())}).unwrap();
    assert!(authorization::granted(&f.app, req.clone()).await.unwrap());
    let mut write = req.clone();
    write["scope"] = "write".into();
    assert!(!authorization::granted(&f.app, write).await.unwrap());
    let mut scopeless = req.clone();
    scopeless["scope"] = Value::Null;
    assert!(!authorization::granted(&f.app, scopeless).await.unwrap());
    f.app.store.update(|db|{authorization::grant(db,json!({"provider":"Provider","targetType":"SERVICE_DEF","target":"temperature","defaultPolicy":{"policyType":"WHITELIST","policyList":[]}}),"MGMT","Sysop")?;Ok(())}).unwrap();
    assert!(!authorization::granted(&f.app, req.clone()).await.unwrap());
    f.app
        .store
        .update(|db| {
            table(db, "policies").retain(|_, r| r["level"] != "MGMT");
            Ok(())
        })
        .unwrap();
    assert!(authorization::granted(&f.app, req).await.unwrap());
}
#[tokio::test]
async fn registry_roundtrip_filters_and_ownership_are_enforced() {
    let f = Fixture::new("serviceregistry");
    registry::initialize(&f.app.store).unwrap();
    let p = caller("Provider");
    let a = BTreeMap::new();
    registry::handle(
        &f.app,
        "POST",
        "/serviceregistry/system-discovery/register",
        &a,
        &empty(),
        &json!({"version":"5.2.2","addresses":["127.0.0.1"]}),
        &p,
    )
    .await
    .unwrap();
    let req = json!({"serviceDefinitionName":"temperature","version":"1.0.0","metadata":{"unit":"C"},"interfaces":[{"templateName":"generic_https","protocol":"https","policy":"CERT_AUTH","properties":{"accessAddresses":["127.0.0.1"],"accessPort":12345,"basePath":"/temperature","operations":{"read":{"method":"GET","path":"/"}}}}]});
    let (_, created) = registry::handle(
        &f.app,
        "POST",
        "/serviceregistry/service-discovery/register",
        &a,
        &empty(),
        &req,
        &p,
    )
    .await
    .unwrap();
    assert_eq!(created["provider"]["name"], "Provider");
    let response=registry::query(&f.app.store,"services",&json!({"serviceDefinitionNames":["temperature"],"metadataRequirementsList":[{"unit":"C"}]})).unwrap();
    assert_eq!(response["count"], 1);
    let response = registry::query(
        &f.app.store,
        "services",
        &json!({"metadataRequirementsList":[{"unit":"K"}]}),
    )
    .unwrap();
    assert_eq!(response["count"], 0);
    let mut params = BTreeMap::new();
    params.insert("instanceId".into(), s(&created, "instanceId").into());
    assert!(
        registry::handle(
            &f.app,
            "DELETE",
            "/serviceregistry/service-discovery/revoke/Provider|temperature|1.0.0",
            &params,
            &empty(),
            &empty(),
            &caller("Other")
        )
        .await
        .is_err()
    );
    registry::handle(
        &f.app,
        "DELETE",
        "/serviceregistry/system-discovery/revoke",
        &a,
        &empty(),
        &empty(),
        &p,
    )
    .await
    .unwrap();
    assert!(f.app.store.rows("services").is_empty());
}
#[tokio::test]
async fn registry_rejects_invalid_interfaces_and_rolls_back_batch() {
    let f = Fixture::new("serviceregistry");
    registry::initialize(&f.app.store).unwrap();
    let req = json!({"systems":[{"name":"First","addresses":["127.0.0.1"]},{"name":"Bad Name","addresses":["127.0.0.1"]}]});
    assert!(
        registry::handle(
            &f.app,
            "POST",
            "/serviceregistry/mgmt/systems",
            &BTreeMap::new(),
            &empty(),
            &req,
            &caller("Sysop")
        )
        .await
        .is_err()
    );
    assert!(f.app.store.rows("systems").is_empty());
    registry::handle(
        &f.app,
        "POST",
        "/serviceregistry/system-discovery/register",
        &BTreeMap::new(),
        &empty(),
        &json!({"addresses":["127.0.0.1"],"version":"5.2.2"}),
        &caller("Provider"),
    )
    .await
    .unwrap();
    for port in [json!(0), json!(65536), Value::Null, json!("8443")] {
        let req = json!({"serviceDefinitionName":"temperature","version":"1.0.0","interfaces":[{"templateName":"generic_https","protocol":"https","policy":"CERT_AUTH","properties":{"accessAddresses":["127.0.0.1"],"accessPort":port,"basePath":"/temperature"}}]});
        assert!(
            registry::handle(
                &f.app,
                "POST",
                "/serviceregistry/service-discovery/register",
                &BTreeMap::new(),
                &empty(),
                &req,
                &caller("Provider")
            )
            .await
            .is_err()
        );
    }
    assert!(f.app.store.rows("services").is_empty());
}
#[tokio::test]
async fn usage_limited_tokens_are_atomically_consumed_and_not_stored_raw() {
    let f = Fixture::new("consumer-authorization");
    let generated=f.app.store.update(|db|tokens::generate(&f.app,db,&json!({"provider":"Provider","consumer":"Consumer","targetType":"SERVICE_DEF","target":"temperature","tokenVariant":"USAGE_LIMITED_TOKEN_AUTH","usageLimit":2}),"Consumer")).unwrap();
    let token = s(&generated, "token");
    assert!(
        !serde_json::to_string(&f.app.store.snapshot())
            .unwrap()
            .contains(token)
    );
    let mut params = BTreeMap::new();
    params.insert("token".into(), token.into());
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let app = f.app.clone();
        let params = params.clone();
        tasks.push(tokio::spawn(async move {
            tokens::handle(
                &app,
                "GET",
                "/consumerauthorization/authorization-token/token/verify/token",
                &params,
                &empty(),
                &empty(),
                &caller("Provider"),
            )
            .await
            .unwrap()
            .1["verified"]
                == true
        }));
    }
    let mut count = 0;
    for task in tasks {
        if task.await.unwrap() {
            count += 1
        }
    }
    assert_eq!(count, 2);
}
#[test]
fn aes_wire_formats_match_openssl() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    for (algorithm, flag, iv) in [
        ("AES/ECB/PKCS5Padding", "-aes-128-ecb", ""),
        (
            "AES/CBC/PKCS5Padding",
            "-aes-128-cbc",
            "AAECAwQFBgcICQoLDA0ODw==",
        ),
    ] {
        let encrypted = tokens::encrypt_wire(
            "Arrowhead authorization token",
            b"0123456789abcdef",
            algorithm,
            iv,
        )
        .unwrap();
        let mut command = Command::new("openssl");
        command.args([
            "enc",
            flag,
            "-K",
            "30313233343536373839616263646566",
            "-nosalt",
        ]);
        if !iv.is_empty() {
            command.args(["-iv", "000102030405060708090a0b0c0d0e0f"]);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"Arrowhead authorization token")
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        assert_eq!(STANDARD.decode(encrypted).unwrap(), out.stdout);
    }
}
#[test]
fn rsa_jwt_signature_and_claims_are_real() {
    use ring::signature::{self, KeyPair};
    use rustls::pki_types::PrivateKeyDer;
    let f = Fixture::new("consumer-authorization");
    for variant in [
        "RSA_SHA256_JSON_WEB_TOKEN_AUTH",
        "RSA_SHA512_JSON_WEB_TOKEN_AUTH",
    ] {
        let generated=f.app.store.update(|db|tokens::generate(&f.app,db,&json!({"provider":"Provider","consumer":"Consumer","targetType":"SERVICE_DEF","target":"temperature","scope":"read","tokenVariant":variant}),"Consumer")).unwrap();
        let parts = s(&generated, "token").split('.').collect::<Vec<_>>();
        assert_eq!(parts.len(), 3);
        let key = PrivateKeyDer::from_pem_slice(&read(&f.config.private_key)).unwrap();
        let pair = match key {
            PrivateKeyDer::Pkcs8(key) => {
                signature::RsaKeyPair::from_pkcs8(key.secret_pkcs8_der()).unwrap()
            }
            PrivateKeyDer::Pkcs1(key) => {
                signature::RsaKeyPair::from_der(key.secret_pkcs1_der()).unwrap()
            }
            _ => panic!("RSA test fixture"),
        };
        let algorithm = if variant.contains("SHA512") {
            &signature::RSA_PKCS1_2048_8192_SHA512
        } else {
            &signature::RSA_PKCS1_2048_8192_SHA256
        };
        signature::UnparsedPublicKey::new(algorithm, pair.public_key().as_ref())
            .verify(
                format!("{}.{}", parts[0], parts[1]).as_bytes(),
                &URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
            )
            .unwrap();
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["psn"], "Provider");
        assert_eq!(claims["csn"], "Consumer");
        assert_eq!(claims["sco"], "read");
        assert!(claims["exp"].as_i64().unwrap() > chrono::Utc::now().timestamp());
    }
}
#[tokio::test]
async fn provider_encryption_keys_are_authenticated_at_rest() {
    let f = Fixture::new("consumer-authorization");
    tokens::handle(
        &f.app,
        "POST",
        "/consumerauthorization/authorization-token/encryption-key",
        &BTreeMap::new(),
        &empty(),
        &json!({"key":"0123456789abcdef","algorithm":"AES/CBC/PKCS5Padding"}),
        &caller("Provider"),
    )
    .await
    .unwrap();
    let snapshot = serde_json::to_string(&f.app.store.snapshot()).unwrap();
    assert!(!snapshot.contains("0123456789abcdef"));
    let generated=f.app.store.update(|db|tokens::generate(&f.app,db,&json!({"provider":"Provider","consumer":"Consumer","targetType":"SERVICE_DEF","target":"temperature","tokenVariant":"BASE64_SELF_CONTAINED_TOKEN_AUTH"}),"Consumer")).unwrap();
    assert!(!s(&generated, "token").is_empty());
    f.app
        .store
        .update(|db| {
            table(db, "encryptionKeys").get_mut("Provider").unwrap()["sealedKey"] =
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".into();
            Ok(())
        })
        .unwrap();
    assert!(f.app.store.update(|db|tokens::generate(&f.app,db,&json!({"provider":"Provider","consumer":"Consumer","targetType":"SERVICE_DEF","target":"temperature","tokenVariant":"BASE64_SELF_CONTAINED_TOKEN_AUTH"}),"Consumer")).is_err());
}
#[tokio::test]
async fn simple_store_priorities_are_atomic_and_control_selection() {
    let f = Fixture::new("serviceorchestration-simple");
    let base = "/serviceorchestration/orchestration/mgmt/simple-store";
    let req = json!({"candidates":[{"consumer":"Consumer","serviceInstanceId":"ProviderB|temperature|1.0.0","priority":2},{"consumer":"Consumer","serviceInstanceId":"ProviderA|temperature|1.0.0","priority":1}]});
    let (_, created) = orchestration::handle(
        &f.app,
        "POST",
        &format!("{base}/create"),
        &BTreeMap::new(),
        &empty(),
        &req,
        &caller("Sysop"),
    )
    .await
    .unwrap();
    let result=orchestration::simple(&f.app,&json!({"serviceRequirement":{"serviceDefinition":"temperature"},"orchestrationFlags":{"MATCHMAKING":true}}),"Consumer").unwrap();
    assert_eq!(result["results"][0]["providerName"], "ProviderA");
    let ids = array(&created, "entries");
    let mut changes = json!({});
    for row in &ids {
        changes[s(row, "id")] = 1.into();
    }
    assert!(
        orchestration::handle(
            &f.app,
            "PUT",
            &format!("{base}/modify-priorities"),
            &BTreeMap::new(),
            &empty(),
            &changes,
            &caller("Sysop")
        )
        .await
        .is_err()
    );
    assert_eq!(
        f.app
            .store
            .rows("simpleStore")
            .iter()
            .map(|r| r["priority"].as_u64().unwrap())
            .sum::<u64>(),
        3
    );
}
#[tokio::test]
async fn dynamic_translation_flag_is_validated_like_java() {
    let f = Fixture::new("serviceorchestration-dynamic");
    for flag in ["ALLOW_TRANSLATION"] {
        let req = json!({"serviceRequirement":{"serviceDefinition":"temperature"},"orchestrationFlags":{flag:true}});
        assert_eq!(
            orchestration::pull(&f.app, &req, "Consumer", "test")
                .await
                .unwrap_err()
                .code,
            400
        );
    }
}
#[tokio::test]
async fn subscription_ownership_callbacks_and_management_batch_are_validated() {
    let f = Fixture::new("serviceorchestration-simple");
    let req = json!({"orchestrationRequest":{"serviceRequirement":{"serviceDefinition":"temperature"}},"notifyInterface":{"protocol":"HTTPS","properties":{"address":"127.0.0.1","port":"12345","method":"POST","path":"/notify"}},"duration":60});
    let (_, id) = orchestration::handle(
        &f.app,
        "POST",
        "/serviceorchestration/orchestration/subscribe",
        &BTreeMap::new(),
        &empty(),
        &req,
        &caller("Consumer"),
    )
    .await
    .unwrap();
    let mut params = BTreeMap::new();
    params.insert("id".into(), id.as_str().unwrap().into());
    assert!(
        orchestration::handle(
            &f.app,
            "DELETE",
            "/serviceorchestration/orchestration/unsubscribe/id",
            &params,
            &empty(),
            &empty(),
            &caller("Other")
        )
        .await
        .is_err()
    );
    let mut bad = req.clone();
    bad["notifyInterface"]["protocol"] = "HTTP".into();
    assert!(
        orchestration::handle(
            &f.app,
            "POST",
            "/serviceorchestration/orchestration/subscribe",
            &BTreeMap::new(),
            &empty(),
            &bad,
            &caller("Consumer")
        )
        .await
        .is_err()
    );
    let mut managed = req.clone();
    managed["targetSystemName"] = "Other".into();
    let (_, result) = orchestration::handle(
        &f.app,
        "POST",
        "/serviceorchestration/orchestration/mgmt/push/subscribe",
        &BTreeMap::new(),
        &empty(),
        &json!({"subscriptions":[managed]}),
        &caller("Sysop"),
    )
    .await
    .unwrap();
    assert_eq!(result["count"], 1);
}
#[tokio::test]
async fn authority_cn_pinning_rejects_same_ca_substitution_before_credentials() {
    let (_, auth) = mock_auth().await;
    let mut client = Fixture::new("serviceregistry");
    client.config.authentication_url = auth.origin.clone();
    client.reconfigure();
    let result = client
        .app
        .remote
        .request(
            "ConsumerAuthorization",
            &auth.origin,
            "POST",
            "/authentication/identity/login",
            "",
            &json!({"systemName":"ServiceRegistry","credentials":{"password":"must-not-be-sent"}}),
        )
        .await;
    assert!(result.is_err());
    let good = client
        .app
        .remote
        .request(
            "Authentication",
            &auth.origin,
            "POST",
            "/authentication/identity/login",
            "",
            &json!({"systemName":"ServiceRegistry","credentials":{"password":"fixture"}}),
        )
        .await
        .unwrap();
    assert_eq!(s(&good, "token"), "token-ServiceRegistry");
}
#[tokio::test]
async fn blacklisted_requesters_are_refused_and_an_unreachable_blacklist_fails_closed() {
    let (_auth_fixture, auth) = mock_auth().await;
    let blacklist_fixture = Fixture::named("serviceregistry", "Blacklist");
    let router = axum::Router::new().fallback(|request: axum::extract::Request| async move {
        axum::Json(json!(request.uri().path() == "/blacklist/check/Bad"))
    });
    let blacklist = start_router(
        blacklist_fixture.app.clone(),
        blacklist_fixture.tls.clone(),
        router,
    )
    .await;
    let echo = |name: &str| {
        let mut request = Request::builder()
            .uri("/consumerauthorization/monitor/echo")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(caller(name));
        request
    };
    let mut f = Fixture::new("consumer-authorization");
    f.config.authentication_url = auth.origin.clone();
    f.config
        .upstreams
        .insert("Blacklist".into(), blacklist.origin.clone());
    f.reconfigure();
    let status = |app: &App, name: &str| {
        let app = app.clone();
        let request = echo(name);
        async move { web::router(app).oneshot(request).await.unwrap().status() }
    };
    assert_eq!(status(&f.app, "Bad").await, 403);
    assert_eq!(status(&f.app, "Good").await, 200);
    assert_eq!(status(&f.app, "Sysop").await, 200);
    f.config.blacklist_exclude = vec!["Bad".into()];
    f.reconfigure();
    assert_eq!(status(&f.app, "Bad").await, 200);
    // no listener on the upstream port: refused, unless the check is optional
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("https://{}", closed.local_addr().unwrap());
    drop(closed);
    f.config.blacklist_exclude.clear();
    f.config.upstreams.insert("Blacklist".into(), origin);
    f.reconfigure();
    assert_eq!(status(&f.app, "Good").await, 403);
    f.config.blacklist_optional = true;
    f.reconfigure();
    assert_eq!(status(&f.app, "Good").await, 200);
    // without upstreams.Blacklist nothing is checked
    f.config.upstreams.clear();
    f.config.blacklist_optional = false;
    f.reconfigure();
    assert_eq!(status(&f.app, "Bad").await, 200);
}
