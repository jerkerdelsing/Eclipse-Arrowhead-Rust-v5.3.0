// SPDX-License-Identifier: EPL-2.0
// Translation, QoS and Blacklist integrations of DynamicServiceOrchestration against mock ServiceRegistry,
// ConsumerAuthorization, Blacklist, qualityEvaluation and TranslationManager providers over mutual TLS.
mod common;
use arrowhead_core_rust::*;
use axum::Router;
use common::*;
use serde_json::{Value, json};

async fn body(request: axum::extract::Request) -> Value {
    let bytes = axum::body::to_bytes(request.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}
fn http(origin: &str, base: &str, operations: Value) -> Value {
    let port: u16 = origin.rsplit(':').next().unwrap().parse().unwrap();
    json!({"templateName":"generic_https","protocol":"https","policy":"CERT_AUTH","properties":{"accessAddresses":["127.0.0.1"],"accessPort":port,"basePath":base,"operations":operations}})
}
fn instance(provider: &str, definition: &str, interfaces: Value) -> Value {
    json!({"instanceId":format!("{provider}|{definition}|1.0.0"),"provider":{"name":provider},"serviceDefinition":{"name":definition},"version":"1.0.0","metadata":{},"interfaces":interfaces})
}
// Blacklist lists ProviderA; the evaluator sorts by reverse name and filters ProviderA out; TranslationManager
// bridges the first discovered candidate's generic_mqtt interface.
async fn support(name: &str, blacklist_up: bool) -> (Fixture, Server) {
    let f = Fixture::named("serviceregistry", name);
    let router = Router::new().fallback(move |request: axum::extract::Request| async move {
        let path = request.uri().path().to_owned();
        let req = body(request).await;
        let mut providers = array(&req, "providers")
            .into_iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect::<Vec<_>>();
        let out = if let Some(name) = path.strip_prefix("/blacklist/check/") {
            if !blacklist_up {
                return (axum::http::StatusCode::SERVICE_UNAVAILABLE, axum::Json(Value::Null));
            }
            json!(name == "ProviderA")
        } else if path == "/qos/sort" {
            providers.sort();
            providers.reverse();
            json!({"sortedProviders":providers})
        } else if path == "/qos/filter" {
            json!({"passedProviders":providers.into_iter().filter(|p| p != "ProviderA").collect::<Vec<_>>()})
        } else if path.ends_with("/discovery") {
            let first = &array(&req, "candidates")[0];
            assert_eq!(req["operation"], "read");
            assert_eq!(req["flags"]["TRANSLATORS_AUTH_CHECK"], true);
            json!({"bridgeId":"bridge-1","candidates":[{"serviceInstanceId":first["instanceId"],"interfaceTemplateName":"generic_mqtt"}]})
        } else if path.ends_with("/negotiation") {
            json!({"bridgeId":req["bridgeId"],"targetInstanceId":req["targetInstanceId"],"bridgeInterface":{"templateName":"generic_https","protocol":"https","policy":"TRANSLATION_BRIDGE_TOKEN_AUTH","properties":{"accessAddresses":["translator"],"accessPort":8443,"basePath":"/bridge","operations":{"read":{"method":"POST","path":"/read"}}}},"tokenExpiresAt":"2099-01-01T00:00:00Z","tokenUsageLimit":5})
        } else {
            return (axum::http::StatusCode::NOT_FOUND, axum::Json(Value::Null));
        };
        (axum::http::StatusCode::OK, axum::Json(out))
    });
    let server = start_router(f.app.clone(), f.tls.clone(), router).await;
    (f, server)
}
struct World {
    _servers: Vec<(Fixture, Server)>,
    dso: Fixture,
}
async fn world(providers: Vec<Value>, blacklist_up: bool, configure: impl FnOnce(&mut Config)) -> World {
    let mut servers = vec![mock_auth().await];
    for name in ["Blacklist", "DeviceQoSEvaluator", "TranslationManager"] {
        servers.push(support(name, blacklist_up).await);
    }
    let support_entries = json!({
        "blacklistDiscovery": instance("Blacklist","blacklistDiscovery",json!([http(&servers[1].1.origin,"/blacklist",json!({"check":{"method":"GET","path":"/check/{systemName}"}}))])),
        "qualityEvaluation": instance("DeviceQoSEvaluator","qualityEvaluation",json!([http(&servers[2].1.origin,"/qos",json!({"sort":{"method":"POST","path":"/sort"},"filter":{"method":"POST","path":"/filter"}}))])),
        "translationBridgeManagement": instance("TranslationManager","translationBridgeManagement",json!([http(&servers[3].1.origin,"/translation/bridge/mgmt",json!({"discovery":{"method":"POST","path":"/discovery"},"negotiation":{"method":"POST","path":"/negotiation"}}))])),
    });
    let registry = Fixture::named("serviceregistry", "ServiceRegistry");
    let router = Router::new().fallback(move |request: axum::extract::Request| {
        let providers = providers.clone();
        let support_entries = support_entries.clone();
        async move {
            let req = body(request).await;
            let definition = req["serviceDefinitionNames"][0].as_str().unwrap_or("").to_owned();
            let templates = array(&req, "interfaceTemplateNames");
            let entries: Vec<Value> = if definition == "temperature" {
                providers
                    .into_iter()
                    .filter(|p| templates.is_empty() || array(p, "interfaces").iter().any(|i| templates.contains(&i["templateName"])))
                    .collect()
            } else {
                support_entries.get(&definition).cloned().into_iter().collect()
            };
            axum::Json(json!({"entries":entries,"count":entries.len()}))
        }
    });
    let registry_server = start_router(registry.app.clone(), registry.tls.clone(), router).await;
    let authorization = Fixture::named("consumer-authorization", "ConsumerAuthorization");
    let router = Router::new().fallback(|request: axum::extract::Request| async move {
        let req = body(request).await;
        let entries = array(&req, "list")
            .into_iter()
            .map(|mut e| {
                e["granted"] = true.into();
                e
            })
            .collect::<Vec<_>>();
        axum::Json(json!({"entries":entries}))
    });
    let authorization_server = start_router(authorization.app.clone(), authorization.tls.clone(), router).await;
    let mut dso = Fixture::new("serviceorchestration-dynamic");
    dso.config.authentication_url = format!("{}/", servers[0].1.origin);
    dso.config.registry_url = format!("{}/", registry_server.origin);
    dso.config.authorization_url = format!("{}/", authorization_server.origin);
    configure(&mut dso.config);
    dso.reconfigure();
    servers.push((registry, registry_server));
    servers.push((authorization, authorization_server));
    World { _servers: servers, dso }
}
fn https_providers(names: &[&str]) -> Vec<Value> {
    names
        .iter()
        .map(|n| instance(n, "temperature", json!([{"templateName":"generic_https","protocol":"https","policy":"CERT_AUTH","properties":{"accessAddresses":[n.to_lowercase()],"accessPort":8443,"basePath":"/t","operations":{"read":{"method":"GET","path":"/read"}}}}])))
        .collect()
}
fn names(response: &Value) -> Vec<String> {
    array(response, "results").iter().map(|r| s(r, "providerName").to_owned()).collect()
}
fn warnings(response: &Value) -> Vec<String> {
    array(response, "warnings").iter().map(|w| w.as_str().unwrap().to_owned()).collect()
}
async fn pull(w: &World, request: Value) -> Result<Value> {
    orchestration::pull(&w.dso.app, &request, "Consumer", "job-1").await
}

#[tokio::test]
async fn blacklisted_providers_are_filtered_and_an_unreachable_blacklist_follows_the_forced_setting() {
    let request = json!({"serviceRequirement":{"serviceDefinition":"temperature","operations":["read"]}});
    let w = world(https_providers(&["ProviderA", "ProviderB"]), true, |_| {}).await;
    assert_eq!(names(&pull(&w, request.clone()).await.unwrap()), ["ProviderA", "ProviderB"]);
    let w = world(https_providers(&["ProviderA", "ProviderB"]), true, |c| c.blacklist_filter = true).await;
    assert_eq!(names(&pull(&w, request.clone()).await.unwrap()), ["ProviderB"]);
    let w = world(https_providers(&["ProviderA", "ProviderB"]), true, |c| {
        c.blacklist_filter = true;
        c.blacklist_exclude = vec!["ProviderA".into()];
    })
    .await;
    assert_eq!(names(&pull(&w, request.clone()).await.unwrap()), ["ProviderA", "ProviderB"]);
    let w = world(https_providers(&["ProviderA", "ProviderB"]), false, |c| c.blacklist_filter = true).await;
    assert!(names(&pull(&w, request.clone()).await.unwrap()).is_empty());
    let w = world(https_providers(&["ProviderA", "ProviderB"]), false, |c| {
        c.blacklist_filter = true;
        c.blacklist_filter_forced = false;
    })
    .await;
    assert_eq!(names(&pull(&w, request).await.unwrap()), ["ProviderA", "ProviderB"]);
}

#[tokio::test]
async fn quality_requirements_sort_filter_and_warn_like_the_java_qos_driver() {
    let providers = https_providers(&["ProviderA", "ProviderB", "ProviderC"]);
    let sort = json!({"serviceRequirement":{"serviceDefinition":"temperature","operations":["read"]},"qualityRequirements":[{"type":"DEVICE","operation":"sort","requirements":{"metricNames":["rtt"],"metricWeights":[1]}}]});
    let w = world(providers.clone(), true, |_| {}).await;
    let response = pull(&w, sort.clone()).await.unwrap();
    assert_eq!(names(&response), ["ProviderA", "ProviderB", "ProviderC"]);
    assert_eq!(warnings(&response), ["qosNotEnabled"]);
    let w = world(providers, true, |c| c.qos_enabled = true).await;
    let response = pull(&w, sort.clone()).await.unwrap();
    assert_eq!(names(&response), ["ProviderC", "ProviderB", "ProviderA"]);
    assert!(warnings(&response).is_empty());
    let mut matchmaking = sort.clone();
    matchmaking["orchestrationFlags"] = json!({"matchmaking":true});
    assert_eq!(names(&pull(&w, matchmaking).await.unwrap()), ["ProviderC"]);
    let mut both = sort.clone();
    both["qualityRequirements"] = json!([{"type":"DEVICE","operation":"FILTER","requirements":{}},{"type":"DEVICE","operation":"SORT","requirements":{}}]);
    assert_eq!(names(&pull(&w, both).await.unwrap()), ["ProviderC", "ProviderB"]);
    assert_eq!(w.dso.app.store.rows("qosEvaluations").len(), 4);
    for (quality, message) in [
        (json!({"type":"","operation":"SORT"}), "QoS type is empty"),
        (json!({"type":"DEVICE","operation":""}), "QoS operation is empty"),
        (json!({"type":"DEVICE","operation":"RANK"}), "Invalid QoS operation"),
    ] {
        let mut bad = sort.clone();
        bad["qualityRequirements"] = json!([quality]);
        let error = pull(&w, bad).await.unwrap_err();
        assert_eq!((error.code, error.message.as_str()), (400, message));
    }
}

#[tokio::test]
async fn unreachable_evaluator_only_warns_qos_compliance_failure() {
    let mut w = world(https_providers(&["ProviderA", "ProviderB"]), true, |c| c.qos_enabled = true).await;
    w._servers.remove(2);
    let response = pull(&w, json!({"serviceRequirement":{"serviceDefinition":"temperature"},"qualityRequirements":[{"type":"DEVICE","operation":"FILTER","requirements":{}}]})).await.unwrap();
    assert_eq!(names(&response), ["ProviderA", "ProviderB"]);
    assert_eq!(warnings(&response), ["qosComplianceFailure"]);
}

#[tokio::test]
async fn translation_bridges_non_native_providers_and_prefers_native_ones() {
    let mqtt = |n: &str| instance(n, "temperature", json!([{"templateName":"generic_mqtt","protocol":"tcp","policy":"CERT_AUTH","properties":{"accessAddresses":["broker"],"accessPort":1883,"baseTopic":"t","operations":["read"]}}]));
    let request = json!({"serviceRequirement":{"serviceDefinition":"temperature","operations":["read"],"interfaceTemplateNames":["generic_https"]},"orchestrationFlags":{"ALLOW_TRANSLATION":true}});
    let w = world(vec![mqtt("ProviderA"), mqtt("ProviderB")], true, |_| {}).await;
    assert!(names(&pull(&w, request.clone()).await.unwrap()).is_empty());
    let w = world(vec![mqtt("ProviderA"), mqtt("ProviderB")], true, |c| c.translation_enabled = true).await;
    let response = pull(&w, request.clone()).await.unwrap();
    assert_eq!(names(&response), ["ProviderA"]);
    let result = &response["results"][0];
    assert_eq!(result["interfaces"][0]["properties"]["basePath"], "/bridge");
    assert_eq!(result["authorizationTokens"]["TRANSLATION_BRIDGE_TOKEN_AUTH"]["read"], json!({"tokenType":"TRANSLATION_BRIDGE_TOKEN","targetType":"SERVICE_DEF","token":"bridge-1","usageLimit":5,"expiresAt":"2099-01-01T00:00:00Z"}));
    let mut found = warnings(&response);
    found.sort();
    assert_eq!(found, ["autoMatchmaking", "forcedInterfaceSecurityPolicy"]);
    let mut providers = vec![mqtt("ProviderA")];
    providers.extend(https_providers(&["ProviderB"]));
    let w = world(providers, true, |c| c.translation_enabled = true).await;
    let response = pull(&w, request.clone()).await.unwrap();
    assert_eq!(names(&response), ["ProviderB"]);
    assert_eq!(response["results"][0]["interfaces"][0]["templateName"], "generic_https");
    assert!(warnings(&response).is_empty());
    for (flags, operations, templates, message) in [
        (json!({"ALLOW_TRANSLATION":true,"ONLY_INTERCLOUD":true}), json!(["read"]), json!(["generic_https"]), "ONLY_INTERCLOUD and ALLOW_TRANSLATION flags cannot be present at the same time"),
        (json!({"ALLOW_TRANSLATION":true}), json!(["read"]), json!([]), "Interface template name(s) must be defined when translation is allowed"),
        (json!({"ALLOW_TRANSLATION":true}), json!(["read","write"]), json!(["generic_https"]), "Exactly one operation must be defined when translation is allowed"),
        (json!({"NOTAFLAG":false}), json!(["read"]), json!(["generic_https"]), "Invalid orchestration flag: NOTAFLAG"),
    ] {
        let bad = json!({"serviceRequirement":{"serviceDefinition":"temperature","operations":operations,"interfaceTemplateNames":templates},"orchestrationFlags":flags});
        let error = pull(&w, bad).await.unwrap_err();
        assert_eq!((error.code, error.message.as_str()), (400, message));
    }
}

#[tokio::test]
async fn present_preferred_providers_exclude_the_others_like_java() {
    let w = world(https_providers(&["ProviderA", "ProviderB", "ProviderC"]), true, |_| {}).await;
    let request = |preferred: Value| json!({"serviceRequirement":{"serviceDefinition":"temperature","preferredProviders":preferred}});
    assert_eq!(names(&pull(&w, request(json!(["ProviderB"]))).await.unwrap()), ["ProviderB"]);
    assert_eq!(names(&pull(&w, request(json!(["Absent"]))).await.unwrap()), ["ProviderA", "ProviderB", "ProviderC"]);
}
