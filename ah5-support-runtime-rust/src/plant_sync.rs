// SPDX-License-Identifier: EPL-2.0
use crate::*;
use std::collections::{BTreeMap, BTreeSet};
fn subset(required: &Value, actual: &Value) -> bool {
    required
        .as_object()
        .is_none_or(|m| m.iter().all(|(k, v)| actual.get(k) == Some(v)))
}
fn matches(system: &Value, registered: &[Value]) -> Vec<Value> {
    registered
        .iter()
        .filter(|r| {
            (s(system, "systemName").is_empty() || s(system, "systemName") == s(r, "name"))
                && subset(&system["metadata"], &r["metadata"])
        })
        .cloned()
        .collect()
}
fn port<'a>(systems: &'a [Value], reference: &Value) -> Option<&'a Value> {
    systems
        .iter()
        .find(|v| v["systemId"] == reference["systemId"])
        .and_then(|v| v["ports"].as_array())
        .and_then(|ps| {
            ps.iter()
                .find(|p| s(p, "portName") == s(reference, "portName"))
        })
}
pub fn active(plants: &BTreeMap<String, Value>) -> (Vec<Value>, Vec<Value>, bool) {
    fn visit(
        id: &str,
        all: &BTreeMap<String, Value>,
        seen: &mut BTreeSet<String>,
        systems: &mut Vec<Value>,
        connections: &mut Vec<Value>,
    ) {
        if !seen.insert(id.into()) {
            return;
        }
        if let Some(p) = all.get(id) {
            for inc in array(p, "include") {
                if let Some(n) = inc.as_u64() {
                    visit(&n.to_string(), all, seen, systems, connections)
                }
            }
            systems.extend(array(p, "systems"));
            connections.extend(array(p, "connections"));
        }
    }
    let mut systems = vec![];
    let mut connections = vec![];
    let current = plants.iter().find(|(_, p)| p["active"] == true);
    if let Some((id, _)) = current {
        visit(
            id,
            plants,
            &mut BTreeSet::new(),
            &mut systems,
            &mut connections,
        )
    }
    (systems, connections, current.is_some())
}
pub fn resolve(
    systems: &[Value],
    connections: &[Value],
    registered: &[Value],
    instances: &[Value],
) -> Value {
    let mut scopes: BTreeMap<(String, String), BTreeMap<String, u64>> = BTreeMap::new();
    for c in connections {
        let (Some(cp), Some(pp)) = (port(systems, &c["consumer"]), port(systems, &c["producer"]))
        else {
            continue;
        };
        let Some(cs) = systems
            .iter()
            .find(|v| v["systemId"] == c["consumer"]["systemId"])
        else {
            continue;
        };
        let Some(ps) = systems
            .iter()
            .find(|v| v["systemId"] == c["producer"]["systemId"])
        else {
            continue;
        };
        let mut names: BTreeSet<String> = matches(cs, registered)
            .iter()
            .map(|v| s(v, "name").to_owned())
            .collect();
        if !s(cs, "systemName").is_empty() {
            names.insert(s(cs, "systemName").into());
        }
        let definition = if s(pp, "serviceDefinition").is_empty() {
            s(cp, "serviceDefinition")
        } else {
            s(pp, "serviceDefinition")
        };
        for name in names {
            let providers = scopes.entry((name, definition.into())).or_default();
            let producers = matches(ps, registered);
            if producers.len() != 1 {
                continue;
            }
            let iface = if s(pp, "serviceInterface").is_empty() {
                s(cp, "serviceInterface")
            } else {
                s(pp, "serviceInterface")
            };
            let priority = c["priority"].as_u64().unwrap_or(1);
            for inst in instances {
                if inst["provider"]["name"] != producers[0]["name"]
                    || s(&inst["serviceDefinition"], "name") != definition
                    || !subset(&pp["metadata"], &inst["metadata"])
                    || (!iface.is_empty()
                        && !array(inst, "interfaces")
                            .iter()
                            .any(|i| s(i, "templateName").eq_ignore_ascii_case(iface)))
                {
                    continue;
                }
                providers
                    .entry(s(inst, "instanceId").into())
                    .and_modify(|p| *p = (*p).min(priority))
                    .or_insert(priority);
            }
        }
    }
    let rules=scopes.into_iter().map(|((consumer,definition),ps)|{let mut ps=ps.into_iter().collect::<Vec<_>>();ps.sort_by_key(|(id,p)|(*p,id.clone()));json!({"consumer":consumer,"serviceDefinition":definition,"providers":ps.into_iter().map(|(id,p)|json!({"serviceInstanceId":id,"priority":p})).collect::<Vec<_>>()})}).collect::<Vec<_>>();
    json!({"rules":rules})
}
fn alarms(app: &App, active: bool, systems: &[Value], registered: &[Value]) -> Result<()> {
    let mut detected: BTreeMap<String, Value> = BTreeMap::new();
    let mut described = BTreeSet::new();
    if active {
        for system in systems {
            let ms = matches(system, registered);
            for m in &ms {
                described.insert(s(m, "name").to_owned());
            }
            let cause = if ms.is_empty() {
                "SYSTEM_NOT_REGISTERED"
            } else if ms.len() > 1 {
                "MULTIPLE_MATCHES"
            } else {
                continue;
            };
            let id = format!(
                "{}|{}|{}",
                system["systemId"],
                s(system, "systemName"),
                cause
            );
            detected.insert(id,json!({"systemId":system["systemId"],"systemName":system["systemName"],"cause":cause}));
        }
        for system in registered {
            let name = s(system, "name");
            if !described.contains(name)
                && !matches!(
                    name,
                    "ServiceRegistry"
                        | "DynamicServiceOrchestration"
                        | "SimpleStoreServiceOrchestration"
                        | "Authentication"
                        | "ConsumerAuthorization"
                        | "Blacklist"
                        | "SysMonitor"
                        | "LocalCloudManager"
                        | "PlantDescriptionEngine"
                        | "Sysop"
                        | "TranslationManager"
                        | "DeviceQoSEvaluator"
                )
            {
                detected.insert(
                    format!("|{name}|SYSTEM_NOT_IN_DESCRIPTION"),
                    json!({"systemId":null,"systemName":name,"cause":"SYSTEM_NOT_IN_DESCRIPTION"}),
                );
            }
        }
    }
    app.store.update(|db| {
        let rows = table(db, "alarms");
        let mut open = BTreeSet::new();
        for row in rows.values_mut() {
            if !row["clearedAt"].is_null() {
                continue;
            }
            let key = format!(
                "{}|{}|{}",
                if row["systemId"].is_null() {
                    String::new()
                } else {
                    row["systemId"].to_string()
                },
                s(row, "systemName"),
                s(row, "cause")
            );
            if detected.contains_key(&key) {
                open.insert(key);
            } else if matches!(
                s(row, "cause"),
                "SYSTEM_NOT_REGISTERED" | "MULTIPLE_MATCHES" | "SYSTEM_NOT_IN_DESCRIPTION"
            ) {
                row["clearedAt"] = now().into();
                row["updatedAt"] = now().into();
            }
        }
        for (key, mut row) in detected {
            if open.contains(&key) {
                continue;
            }
            let id = rows
                .values()
                .filter_map(|r| r["id"].as_u64())
                .max()
                .unwrap_or(0)
                + 1;
            row["id"] = id.into();
            row["acknowledged"] = false.into();
            row["severity"] = "ERROR".into();
            row["description"] = row["cause"].clone();
            row["raisedAt"] = now().into();
            row["updatedAt"] = now().into();
            row["clearedAt"] = Value::Null;
            rows.insert(id.to_string(), row);
        }
        Ok(())
    })
}
pub async fn sync(app: &App) -> Result<Value> {
    let db = app.store.snapshot();
    let (systems, connections, is_active) = active(db.get("plants").unwrap_or(&BTreeMap::new()));
    let response = app
        .remote
        .call(
            "ServiceRegistry",
            "POST",
            "/serviceregistry/mgmt/systems/query",
            &json!({"pagination":{"page":0,"size":1000}}),
        )
        .await?;
    let registered = response["entries"]
        .as_array()
        .ok_or_else(|| Error::new(502, "Invalid system query response"))?;
    if response["count"]
        .as_u64()
        .is_some_and(|n| n > registered.len() as u64)
    {
        return Err(Error::unavailable("Registry system page incomplete"));
    }
    alarms(app, is_active, &systems, registered)?;
    let definitions: BTreeSet<String> = systems
        .iter()
        .flat_map(|s| array(s, "ports"))
        .filter(|p| p["consumer"] != true)
        .map(|p| s(&p, "serviceDefinition").to_owned())
        .filter(|d| !d.is_empty())
        .collect();
    let instances = if is_active && !definitions.is_empty() {
        let response = app
            .remote
            .call(
                "ServiceRegistry",
                "POST",
                "/serviceregistry/mgmt/service-instances/query",
                &json!({"pagination":{"page":0,"size":1000},"serviceDefinitionNames":definitions}),
            )
            .await?;
        let entries = response["entries"]
            .as_array()
            .ok_or_else(|| Error::new(502, "Invalid service query response"))?;
        if response["count"]
            .as_u64()
            .is_some_and(|n| n > entries.len() as u64)
        {
            return Err(Error::unavailable("Registry service page incomplete"));
        }
        entries.clone()
    } else {
        vec![]
    };
    let desired = resolve(&systems, &connections, registered, &instances);
    let current = app
        .remote
        .call(
            "DynamicServiceOrchestration",
            "POST",
            "/serviceorchestration/mgmt/plant-rules/query",
            &json!({}),
        )
        .await?;
    if !current["rules"].is_array() {
        return Err(Error::new(502, "Invalid DSO snapshot"));
    }
    if current != desired {
        let ack = app
            .remote
            .call(
                "DynamicServiceOrchestration",
                "PUT",
                "/serviceorchestration/mgmt/plant-rules/replace",
                &desired,
            )
            .await?;
        if ack != desired {
            return Err(Error::new(
                502,
                "DSO acknowledgment differs from desired snapshot",
            ));
        }
    }
    Ok(
        json!({"ok":true,"detail":if is_active{"active plant in force"}else{"no active plant description"},"time":now(),"rules":desired["rules"].as_array().unwrap().len()}),
    )
}
pub async fn tick(app: &App) {
    let state = match sync(app).await {
        Ok(state) => state,
        Err(e) => {
            json!({"ok":false,"detail":format!("DSO synchronization failed ({})",e.code),"time":now()})
        }
    };
    if let Err(e) = app.store.update(|db| {
        table(db, "pdeSync").insert("state".into(), state);
        Ok(())
    }) {
        eprintln!("PDE state unavailable ({})", e.code)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_producer_retains_named_consumer() {
        let systems = json!([{"systemId":"c","systemName":"Consumer","ports":[{"portName":"in","consumer":true,"serviceDefinition":"temperature"}]},{"systemId":"p","systemName":"Producer","ports":[{"portName":"out","serviceDefinition":"temperature"}]}]);
        let connections = json!([{"consumer":{"systemId":"c","portName":"in"},"producer":{"systemId":"p","portName":"out"},"priority":0}]);
        let result = resolve(
            systems.as_array().unwrap(),
            connections.as_array().unwrap(),
            &[],
            &[],
        );
        assert_eq!(
            result,
            json!({"rules":[{"consumer":"Consumer","serviceDefinition":"temperature","providers":[]}]})
        );
    }
}
