// SPDX-License-Identifier: EPL-2.0
use serde::Serialize;
use serde_json::{Value, json};
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
    pub operations: BTreeMap<String, Value>,
}
pub fn routes(role: &str) -> Vec<Route> {
    let base = crate::config::ROLES
        .iter()
        .find(|r| r.0 == role)
        .expect("validated role")
        .2;
    let mut out = Vec::new();
    let mut add = |service: &str, prefix: &str, access: &str, spec: &str| {
        for line in spec.lines().filter(|l| !l.is_empty()) {
            let p = line.split_whitespace().collect::<Vec<_>>();
            out.push(Route {
                operation: p[0].into(),
                method: p[1].into(),
                path: format!("{prefix}{}", p[2]),
                access: access.into(),
                service: service.into(),
                implemented: p.get(3) != Some(&"unsupported"),
            });
        }
    };
    add(
        "generalManagement",
        &format!("{base}/general/mgmt"),
        "management",
        "get-config GET /get-config\nget-log POST /logs",
    );
    add("echo", base, "certificate", "echo GET /monitor/echo");
    match role {
        "blacklist" => {
            add(
                "blacklistDiscovery",
                base,
                "identity",
                "check GET /check/{systemName}\nlookup GET /lookup",
            );
            add(
                "blacklistManagement",
                &format!("{base}/mgmt"),
                "management",
                "create POST /create\nquery POST /query\nremove DELETE /remove",
            );
        }
        "configuration" => {
            add(
                "configuration",
                base,
                "identity",
                "get-configuration GET /config/{systemName}\nget-raw-configuration GET /config/raw/{systemName}",
            );
            add(
                "configurationProxy",
                &format!("{base}/proxy"),
                "identity",
                "get-configuration GET /config/{systemName}\nstore-configuration PUT /save-config",
            );
            add(
                "configurationManagement",
                &format!("{base}/mgmt"),
                "management",
                "list-configurations GET /config\nstore-configuration PUT /config/{systemName}\nremove-configuration DELETE /config/{systemName}",
            );
        }
        "timemanager" => add("time", base, "identity", "get-time GET /time"),
        "aigym" => {
            add(
                "aiGym",
                base,
                "identity",
                "status GET /status\nadd-sample POST /samples\npredict POST /predict\nobservations GET /observations",
            );
            add("health", "", "certificate", "health GET /health");
        }
        "datamanager" => {
            for (area, service) in [
                ("data-historian", "dataHistorian"),
                ("data-proxy", "dataProxy"),
            ] {
                add(
                    service,
                    &format!("{base}/{area}"),
                    "identity",
                    "list-systems GET /systems\nlist-services GET /systems/{systemName}/services\nget-data GET /systems/{systemName}/services/{serviceName}/data\nput-data PUT /systems/{systemName}/services/{serviceName}/data",
                );
            }
        }
        "eventhandler" => {
            add(
                "eventPublish",
                &format!("{base}/event-publish"),
                "identity",
                "publish POST /publish",
            );
            add(
                "eventSubscription",
                &format!("{base}/event-subscription"),
                "identity",
                "subscribe POST /subscribe\nunsubscribe DELETE /unsubscribe/{subscriptionId}",
            );
            add(
                "eventHandlerManagement",
                &format!("{base}/management"),
                "management",
                "query-subscriptions GET /subscriptions\nupdate-subscription PUT /subscriptions/{subscriptionId}\nremove-subscription DELETE /subscriptions/{subscriptionId}",
            );
        }
        "deviceqosevaluator" => {
            add(
                "qualityEvaluation",
                &format!("{base}/qualityevaluation"),
                "identity",
                "filter POST /filter\nsort POST /sort",
            );
            add(
                "deviceQualityDataManagement",
                &format!("{base}/mgmt"),
                "management",
                "query POST /query\nreload POST /reload",
            );
        }
        "plantdescriptionengine" => {
            add(
                "plantDescriptionManagement",
                &format!("{base}/mgmt"),
                "management",
                "sync-status GET /sync-status",
            );
            add(
                "plantDescriptionManagement",
                &format!("{base}/mgmt"),
                "management",
                "query GET /plant-descriptions\ncreate POST /plant-descriptions\nget GET /plant-descriptions/{id}\nreplace PUT /plant-descriptions/{id}\nupdate PATCH /plant-descriptions/{id}\nremove DELETE /plant-descriptions/{id}",
            );
            add(
                "plantDescriptionMonitor",
                &format!("{base}/monitor"),
                "identity",
                "query-plant-descriptions GET /plant-descriptions\nget-plant-description GET /plant-descriptions/{id}\nquery-alarms GET /alarms\nget-alarm GET /alarms/{id}\nacknowledge-alarm PATCH /alarms/{id}",
            );
        }
        "choreographer" => {
            add(
                "choreographerExecutor",
                &format!("{base}/executor"),
                "identity",
                "register POST /register\nunregister DELETE /unregister\nnotify-step-done POST /notify-step-done",
            );
            add(
                "choreographerSession",
                &format!("{base}/session"),
                "identity",
                "start-session POST /start\nabort-session DELETE /abort/{id}",
            );
            add(
                "choreographerSession",
                base,
                "identity",
                "orchestration-result POST /orchestration-result/{correlationId} unsupported",
            );
            add(
                "choreographerManagement",
                &format!("{base}/mgmt"),
                "management",
                "query-plans GET /plans\ncreate-plan POST /plans\nget-plan GET /plans/{id}\nremove-plan DELETE /plans/{id}\ncheck-plan GET /plans/{id}/check\nstart-sessions POST /sessions/start\nabort-session DELETE /sessions/{id}\nquery-sessions GET /sessions\nquery-session-steps GET /session-steps\nquery-worklog GET /worklog\nquery-executors GET /executors\ncreate-executor POST /executors\nget-executor GET /executors/{id}\nremove-executor DELETE /executors/{id}",
            );
        }
        "certificateauthority" => {
            add("certificateSigning", base, "certificate", "sign POST /sign");
            add(
                "certificateValidation",
                base,
                "certificate",
                "get-crl GET /crl\ncheck-certificate POST /checkCertificate\ncheck-trusted-key POST /checkTrustedKey",
            );
            add(
                "certificateAuthorityManagement",
                &format!("{base}/mgmt"),
                "certificate",
                "list-certificates GET /certificates\nrevoke-certificate DELETE /certificates/{id}\nrevoke-certificate-by-content POST /revocations\nlist-keys GET /keys\nadd-key PUT /keys\ndelete-key DELETE /keys/{id}",
            );
        }
        "sysmonitor" => {
            add(
                "sysMonitorManagement",
                &format!("{base}/management"),
                "management",
                "status GET /status\nproviders GET /providers\nsubscriptions GET /subscriptions\nsubscribe PUT /subscriptions/{providerSystem}\nunsubscribe DELETE /subscriptions/{providerSystem}\nreconcile POST /reconcile",
            );
            add(
                "sysMonitorHistory",
                &format!("{base}/history"),
                "identity",
                "list-systems GET /systems\nlatest GET /systems/{systemName}/latest\nquery GET /systems/{systemName}/observations",
            );
            add(
                "sysMonitorIntake",
                base,
                "management",
                "ingest POST /observations",
            );
        }
        "onboarding" => {
            add(
                "onboardingManagement",
                &format!("{base}/mgmt"),
                "management",
                "query-enrollments GET /enrollments\nget-enrollment GET /enrollments/{deviceName}\napprove-device PUT /enrollments/{deviceName}\nremove-enrollment DELETE /enrollments/{deviceName}\noffboard-device POST /enrollments/{deviceName}/offboard",
            );
            add(
                "onboarding",
                base,
                "certificate",
                "onboard-with-name POST /certificate/name\nonboard-with-csr POST /certificate/csr\nonboard-device POST /device\nonboard-system POST /system\noffboard-device POST /device/offboard\necho GET /echo",
            );
        }
        "translationmanager" => {
            for (suffix, access, service) in [
                ("", "identity", "translationBridge"),
                ("/mgmt", "management", "translationBridgeManagement"),
            ] {
                add(
                    service,
                    &format!("{base}/bridge{suffix}"),
                    access,
                    "discovery POST /discovery\nnegotiation POST /negotiation",
                );
            }
            add(
                "translationBridge",
                &format!("{base}/bridge"),
                "identity",
                "abort DELETE /abort/{bridgeId}",
            );
            add(
                "translationBridgeManagement",
                &format!("{base}/bridge/mgmt"),
                "management",
                "query POST /query\nabort DELETE /abort",
            );
            add(
                "translationReport",
                base,
                "identity",
                "report POST /event/report",
            );
        }
        "gatekeeper" => {
            add(
                "globalServiceDiscovery",
                base,
                "identity",
                "query POST /init_gsd\nmulti-query POST /init_multi_gsd",
            );
            add(
                "interCloudNegotiation",
                base,
                "identity",
                "negotiate POST /init_icn",
            );
            add(
                "gatekeeperManagement",
                &format!("{base}/mgmt"),
                "management",
                "status GET /status\nclouds GET /clouds\nadd-cloud POST /clouds\nremove-cloud DELETE /clouds/{operator}/{name}\nrelays GET /relays\nadd-relay POST /relays",
            );
        }
        "gatetunnel" => {
            add(
                "gateTunnelKey",
                base,
                "identity",
                "public-key GET /publickey",
            );
            add(
                "gateTunnelConnection",
                base,
                "identity",
                "connect-provider POST /connect_provider\nconnect-consumer POST /connect_consumer\nclose-sessions POST /close_sessions",
            );
            add(
                "gateTunnelManagement",
                &format!("{base}/mgmt"),
                "management",
                "status GET /status\nsessions GET /sessions\nclose POST /sessions/close",
            );
            add(
                "gateTunnelConnection",
                base,
                "identity",
                "open-provider-session POST /intercloud/provider\nopen-consumer-session POST /intercloud/consumer",
            );
        }
        _ => unreachable!(),
    };
    out
}
pub fn services(role: &str) -> Vec<Service> {
    let mut groups = BTreeMap::<String, Service>::new();
    for r in routes(role)
        .into_iter()
        .filter(|r| r.implemented && r.service != "health" && r.service != "sysMonitorIntake")
    {
        let base = crate::config::ROLES.iter().find(|r| r.0 == role).unwrap().2;
        let group = groups.entry(r.service.clone()).or_insert_with(|| Service {
            definition: r.service.clone(),
            base_path: base.into(),
            operations: BTreeMap::new(),
        });
        group.operations.insert(
            r.operation,
            json!({"method":r.method,"path":r.path.strip_prefix(base).unwrap_or(&r.path)}),
        );
    }
    groups.into_values().collect()
}
/// Data models a service declares in its interface properties (`dataModels`, per operation), so that the
/// TranslationManager can decide on data model translation (Java interface property convention): the DataManager
/// historian stores and returns SenML.
pub fn data_models(role: &str, definition: &str) -> Option<Value> {
    match (role, definition) {
        ("datamanager", "dataHistorian") => {
            Some(json!({"get-data":{"output":"senml"},"put-data":{"input":"senml"}}))
        }
        _ => None,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn data_historian_declares_senml() {
        let models = data_models("datamanager", "dataHistorian").expect("declared");
        assert_eq!(models["get-data"]["output"], "senml");
        assert_eq!(models["put-data"]["input"], "senml");
        assert!(data_models("datamanager", "dataProxy").is_none());
        assert!(data_models("timemanager", "time").is_none());
    }
}
