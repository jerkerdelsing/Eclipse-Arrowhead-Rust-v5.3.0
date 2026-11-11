// SPDX-License-Identifier: EPL-2.0
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize)]
pub struct Route {
    pub method: String,
    pub path: String,
    pub access: String,
    pub service: String,
    pub operation: String,
    pub implemented: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Service {
    pub definition: String,
    pub base_path: String,
    pub operations: BTreeMap<String, serde_json::Value>,
}
pub fn routes(role: &str) -> Vec<Route> {
    let base = crate::config::ROLES
        .iter()
        .find(|r| r.0 == role)
        .expect("known role")
        .2;
    let mut out = Vec::new();
    let mut add = |service: &str, path: &str, access: &str, spec: &str| {
        for line in spec.lines().filter(|s| !s.is_empty()) {
            let p = line.split_whitespace().collect::<Vec<_>>();
            out.push(Route {
                method: p[1].into(),
                path: format!("{path}{}", p[2]),
                access: access.into(),
                service: service.into(),
                operation: p[0].into(),
                implemented: true,
            });
        }
    };
    add(
        "generalManagement",
        &format!("{base}/general/mgmt"),
        "management",
        "get-config GET /get-config\nget-log POST /logs",
    );
    if !role.starts_with("serviceorchestration") {
        add(
            "echo",
            &format!("{base}/monitor"),
            "certificate",
            "echo GET /echo",
        );
    }
    match role {
        "authentication" => {
            add(
                "identity",
                "/authentication/identity",
                "certificate",
                "identity-login POST /login\nidentity-logout POST /logout\nidentity-change-credentials POST /change",
            );
            add(
                "identity",
                "/authentication/identity",
                "identity",
                "identity-verify GET /verify/{token}",
            );
            add(
                "identityManagement",
                "/authentication/mgmt",
                "management",
                "identity-mgmt-create POST /identities\nidentity-mgmt-update PUT /identities\nidentity-mgmt-remove DELETE /identities\nidentity-mgmt-query POST /identities/query\nidentity-mgmt-session-close DELETE /sessions\nidentity-mgmt-session-query POST /sessions",
            );
        }
        "serviceregistry" => {
            for (kind, definition) in [
                ("device", "deviceDiscovery"),
                ("system", "systemDiscovery"),
                ("service", "serviceDiscovery"),
            ] {
                let path = format!("/serviceregistry/{kind}-discovery");
                add(definition, &path, "certificate", "register POST /register");
                add(definition, &path, "identity", "lookup POST /lookup");
                add(
                    definition,
                    &path,
                    "identity",
                    if kind == "service" {
                        "revoke DELETE /revoke/{instanceId}"
                    } else if kind == "device" {
                        "revoke DELETE /revoke/{name}"
                    } else {
                        "revoke DELETE /revoke"
                    },
                );
            }
            // operation names follow the Java reference (<entity>-<verb>)
            for (resource, entity) in [
                ("devices", "device"),
                ("systems", "system"),
                ("service-definitions", "service-definition"),
                ("service-instances", "service"),
                ("interface-templates", "interface-template"),
            ] {
                let path = format!("/serviceregistry/mgmt/{resource}");
                add("serviceRegistryManagement",&path,"management",&format!("{entity}-query POST /query\n{entity}-create POST /\n{entity}-remove DELETE /"));
                if matches!(resource, "devices" | "systems" | "service-instances") {
                    add(
                        "serviceRegistryManagement",
                        &path,
                        "management",
                        &format!("{entity}-update PUT /"),
                    );
                }
            }
        }
        "consumer-authorization" => {
            add(
                "authorization",
                "/consumerauthorization/authorization",
                "identity",
                "grant POST /grant\nrevoke DELETE /revoke/{instanceId}\nlookup POST /lookup\nverify POST /verify",
            );
            add(
                "authorizationManagement",
                "/consumerauthorization/authorization/mgmt",
                "management",
                "grant-policies POST /grant\nrevoke-policies DELETE /revoke\nquery-policies POST /query\ncheck-policies POST /check",
            );
            add(
                "authorizationToken",
                "/consumerauthorization/authorization-token",
                "identity",
                "generate POST /generate\nverify GET /token/verify/{token}\nget-public-key GET /public-key\nregister-encryption-key POST /encryption-key\nunregister-encryption-key DELETE /encryption-key",
            );
            add(
                "authorizationTokenManagement",
                "/consumerauthorization/authorization/mgmt/token",
                "management",
                "generate-tokens POST /generate\nquery-tokens POST /query\nrevoke-tokens DELETE /revoke\nadd-encryption-keys POST /encryption-key\nremove-encryption-keys DELETE /encryption-key",
            );
        }
        _ => {
            add(
                "serviceOrchestration",
                "/serviceorchestration/orchestration",
                "identity",
                "pull POST /pull\nsubscribe POST /subscribe\nunsubscribe DELETE /unsubscribe/{id}",
            );
            add(
                "serviceOrchestrationPushManagement",
                "/serviceorchestration/orchestration/mgmt/push",
                "management",
                "subscribe POST /subscribe\ntrigger POST /trigger\nunsubscribe DELETE /unsubscribe\nquery POST /query",
            );
            add(
                "serviceOrchestrationHistoryManagement",
                "/serviceorchestration/orchestration/mgmt/history",
                "management",
                "query POST /query",
            );
            if role.ends_with("simple") {
                add(
                    "serviceOrchestrationSimpleStoreManagement",
                    "/serviceorchestration/orchestration/mgmt/simple-store",
                    "management",
                    "create POST /create\nquery POST /query\nmodify-priorities PUT /modify-priorities\nremove DELETE /remove",
                );
            } else {
                add(
                    "serviceOrchestrationPlantManagement",
                    "/serviceorchestration/mgmt/plant-rules",
                    "management",
                    "query POST /query\nreplace PUT /replace",
                );
                add(
                    "serviceOrchestrationLockManagement",
                    "/serviceorchestration/orchestration/mgmt/lock",
                    "management",
                    "create POST /create\nquery POST /query\nremove DELETE /remove/{owner}",
                );
            }
        }
    }
    for r in &mut out {
        if r.path.ends_with('/') {
            r.path.pop();
        }
    }
    out
}
pub fn services(role: &str) -> Vec<Service> {
    let mut groups: BTreeMap<String, Service> = BTreeMap::new();
    for r in routes(role) {
        if !r.implemented {
            continue;
        }
        let base = if r.service == "serviceRegistryManagement" {
            "/serviceregistry/mgmt".into()
        } else {
            r.path
                .rsplit_once('/')
                .map(|p| p.0.to_owned())
                .unwrap_or_default()
        };
        let group = groups.entry(r.service.clone()).or_insert_with(|| Service {
            definition: r.service.clone(),
            base_path: String::new(),
            operations: BTreeMap::new(),
        });
        let _ = base;
        group.operations.insert(
            r.operation,
            serde_json::json!({"method":r.method,"path":r.path}),
        );
    }
    groups
        .into_values()
        .map(|mut group| {
            let root = crate::config::ROLES.iter().find(|r| r.0 == role).unwrap().2;
            group.base_path = root.into();
            for op in group.operations.values_mut() {
                let path = op["path"]
                    .as_str()
                    .unwrap()
                    .strip_prefix(root)
                    .unwrap()
                    .to_owned();
                op["path"] = path.into();
            }
            group
        })
        .collect()
}
