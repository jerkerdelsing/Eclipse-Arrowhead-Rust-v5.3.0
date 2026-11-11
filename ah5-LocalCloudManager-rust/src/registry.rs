use crate::api::Config;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

pub async fn registration_loop(config: Arc<Config>) {
    loop {
        match register(&config).await {
            Ok(()) => {
                tracing::info!(system=%config.system_name, "published associated services in ServiceRegistry");
                return;
            }
            Err(error) => tracing::warn!(%error, "ServiceRegistry publication failed; retrying"),
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn register(config: &Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::new();
    let auth = format!("Bearer SYSTEM//{}", config.system_name);
    client.post(format!("{}/serviceregistry/system-discovery/register", config.registry_url))
        .header("Authorization", &auth).json(&json!({"version":"5.2.2","addresses":[config.domain_name],"metadata":{"implementation":"rust"}}))
        .send().await?.error_for_status()?;
    for service in services(&config.role) {
        let body = json!({
            "serviceDefinitionName": service.definition, "version":"1.0.0", "metadata":service.metadata,
            "interfaces":[{"templateName":"generic_http","protocol":"http","policy":"NONE","properties":{
                "accessAddresses":[config.domain_name],"accessPort":config.port,"basePath":service.base_path,"operations":service.operations
            }}]
        });
        client
            .post(format!(
                "{}/serviceregistry/service-discovery/register",
                config.registry_url
            ))
            .header("Authorization", &auth)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
    }
    Ok(())
}

pub struct Service {
    definition: &'static str,
    base_path: &'static str,
    operations: Value,
    metadata: Value,
}
fn ops(items: &[(&str, &str, &str)]) -> Value {
    let map: BTreeMap<_, _> = items
        .iter()
        .map(|(n, m, p)| ((*n).to_string(), json!({"method":m,"path":p})))
        .collect();
    json!(map)
}
fn svc(
    definition: &'static str,
    base_path: &'static str,
    operations: &[(&str, &str, &str)],
) -> Service {
    Service {
        definition,
        base_path,
        operations: ops(operations),
        metadata: json!({}),
    }
}

pub fn services(role: &str) -> Vec<Service> {
    let general = |path| {
        svc(
            "generalManagement",
            path,
            &[("getLog", "POST", "/logs"), ("getConfig", "GET", "/config")],
        )
    };
    match role {
        "authentication" => vec![
            general("/authentication/general/mgmt"),
            svc(
                "identityManagement",
                "/authentication/mgmt",
                &[
                    ("create", "POST", "/identities"),
                    ("update", "PUT", "/identities"),
                    ("remove", "DELETE", "/identities"),
                    ("query", "POST", "/identities/query"),
                ],
            ),
            Service {
                metadata: json!({"unrestrictedDiscovery":true}),
                ..svc(
                    "identity",
                    "/authentication/identity",
                    &[
                        ("login", "POST", "/login"),
                        ("logout", "POST", "/logout"),
                        ("change", "POST", "/change"),
                        ("verify", "GET", "/verify/{token}"),
                    ],
                )
            },
        ],
        "authorization" => vec![
            general("/consumerauthorization/general/mgmt"),
            svc(
                "authorizationManagement",
                "/consumerauthorization/mgmt",
                &[
                    ("grant", "POST", "/grant"),
                    ("revoke", "DELETE", "/revoke"),
                    ("query", "POST", "/query"),
                    ("check", "POST", "/check"),
                ],
            ),
            svc(
                "authorizationTokenManagement",
                "/consumerauthorization/mgmt/token",
                &[
                    ("generate", "POST", "/generate"),
                    ("query", "POST", "/query"),
                    ("revoke", "DELETE", "/revoke"),
                ],
            ),
            svc(
                "authorization",
                "/consumerauthorization/authorization",
                &[
                    ("grant", "POST", "/grant"),
                    ("lookup", "POST", "/lookup"),
                    ("verify", "POST", "/verify"),
                ],
            ),
            svc(
                "authorizationToken",
                "/consumerauthorization/authorization-token",
                &[
                    ("generate", "POST", "/generate"),
                    ("verify", "GET", "/verify/{token}"),
                    ("publicKey", "GET", "/public-key"),
                ],
            ),
        ],
        "orchestration-dynamic" => vec![
            general("/serviceorchestration/general/mgmt"),
            svc(
                "monitor",
                "/serviceorchestration/monitor",
                &[("echo", "GET", "/echo")],
            ),
            Service {
                metadata: json!({"orchestrationStrategy":"dynamic"}),
                ..svc(
                    "serviceOrchestration",
                    "/serviceorchestration/orchestration",
                    &[
                        ("pull", "POST", "/pull"),
                        ("subscribe", "POST", "/subscribe"),
                        ("unsubscribe", "DELETE", "/unsubscribe/{id}"),
                    ],
                )
            },
            svc(
                "serviceOrchestrationPushManagement",
                "/serviceorchestration/orchestration/mgmt/push",
                &[("query", "POST", "/query"), ("trigger", "POST", "/trigger")],
            ),
            svc(
                "serviceOrchestrationLockManagement",
                "/serviceorchestration/orchestration/mgmt/lock",
                &[
                    ("create", "POST", "/create"),
                    ("query", "POST", "/query"),
                    ("remove", "DELETE", "/remove/{owner}"),
                ],
            ),
            svc(
                "serviceOrchestrationHistoryManagement",
                "/serviceorchestration/orchestration/mgmt/history",
                &[("query", "POST", "/query")],
            ),
        ],
        "orchestration-simple" => vec![
            general("/serviceorchestration/general/mgmt"),
            svc(
                "monitor",
                "/serviceorchestration/monitor",
                &[("echo", "GET", "/echo")],
            ),
            Service {
                metadata: json!({"orchestrationStrategy":"simpleStore"}),
                ..svc(
                    "serviceOrchestration",
                    "/serviceorchestration/orchestration",
                    &[
                        ("pull", "POST", "/pull"),
                        ("subscribe", "POST", "/subscribe"),
                        ("unsubscribe", "DELETE", "/unsubscribe/{id}"),
                    ],
                )
            },
            svc(
                "serviceOrchestrationSimpleStoreManagement",
                "/serviceorchestration/orchestration/mgmt/simple-store",
                &[
                    ("create", "POST", "/create"),
                    ("query", "POST", "/query"),
                    ("modifyPriorities", "PUT", "/modify-priorities"),
                    ("remove", "DELETE", "/remove"),
                ],
            ),
            svc(
                "serviceOrchestrationPushManagement",
                "/serviceorchestration/orchestration/mgmt/push",
                &[("query", "POST", "/query"), ("trigger", "POST", "/trigger")],
            ),
            svc(
                "serviceOrchestrationHistoryManagement",
                "/serviceorchestration/orchestration/mgmt/history",
                &[("query", "POST", "/query")],
            ),
        ],
        "datamanager" => vec![
            svc(
                "dataProxy",
                "/datamanager/data-proxy",
                &[
                    ("list-systems", "GET", "/systems"),
                    ("list-services", "GET", "/systems/{systemName}/services"),
                    (
                        "get-data",
                        "GET",
                        "/systems/{systemName}/services/{serviceName}/data",
                    ),
                    (
                        "put-data",
                        "PUT",
                        "/systems/{systemName}/services/{serviceName}/data",
                    ),
                ],
            ),
            svc(
                "dataHistorian",
                "/datamanager/data-historian",
                &[
                    ("list-systems", "GET", "/systems"),
                    ("list-services", "GET", "/systems/{systemName}/services"),
                    (
                        "get-data",
                        "GET",
                        "/systems/{systemName}/services/{serviceName}/data",
                    ),
                    (
                        "put-data",
                        "PUT",
                        "/systems/{systemName}/services/{serviceName}/data",
                    ),
                ],
            ),
        ],
        "eventhandler" => vec![
            general("/eventhandler/general/mgmt"),
            svc(
                "eventHandlerManagement",
                "/eventhandler/management",
                &[
                    ("query-subscriptions", "GET", "/subscriptions"),
                    (
                        "update-subscription",
                        "PUT",
                        "/subscriptions/{subscriptionId}",
                    ),
                    (
                        "remove-subscription",
                        "DELETE",
                        "/subscriptions/{subscriptionId}",
                    ),
                ],
            ),
            svc(
                "eventPublish",
                "/eventhandler/event-publish",
                &[("publish", "POST", "/publish")],
            ),
            svc(
                "eventSubscription",
                "/eventhandler/event-subscription",
                &[
                    ("subscribe", "POST", "/subscribe"),
                    ("unsubscribe", "DELETE", "/unsubscribe/{subscriptionId}"),
                ],
            ),
        ],
        "onboarding" => vec![
            general("/onboarding/general/mgmt"),
            svc(
                "onboarding",
                "/onboarding/certificate",
                &[
                    ("onboard-with-name", "POST", "/name"),
                    ("onboard-with-csr", "POST", "/csr"),
                ],
            ),
        ],
        "localcloudmanager" => vec![
            svc(
                "localCloudManagement",
                "/api",
                &[
                    ("overview", "GET", "/overview"),
                    (
                        "service-registry-management",
                        "GET",
                        "/service-registry-management",
                    ),
                    ("datamanager", "GET", "/datamanager"),
                    ("consumers", "GET", "/consumers"),
                    ("intercloud", "GET", "/intercloud"),
                    ("sysmonitor", "GET", "/sysmonitor"),
                    (
                        "sysmonitor-subscriptions",
                        "GET",
                        "/sysmonitor/subscriptions",
                    ),
                    ("plantdescriptions", "GET", "/plantdescriptions"),
                    ("orchestration-rules", "GET", "/orchestration/rules"),
                    ("create-orchestration-rule", "POST", "/orchestration/rules"),
                    (
                        "remove-orchestration-rule",
                        "DELETE",
                        "/orchestration/rules/{id}",
                    ),
                    ("logs", "GET", "/logs"),
                    ("lifecycle", "POST", "/containers/{service}/{action}"),
                ],
            ),
            svc(
                "monitor",
                "/localcloud/monitor",
                &[("echo", "GET", "/echo")],
            ),
        ],
        _ => vec![],
    }
}
