// SPDX-License-Identifier: EPL-2.0
use crate::*;
use std::collections::{BTreeMap, BTreeSet};
pub const PATH: &str = "/serviceorchestration/mgmt/plant-rules";
pub fn normalize(req: &Value) -> Result<Value> {
    let rules = req["rules"]
        .as_array()
        .filter(|v| v.len() <= 10000)
        .ok_or_else(|| Error::bad("rules array required (at most 10000 scopes)"))?;
    let mut scopes = BTreeSet::new();
    let mut out = Vec::new();
    for rule in rules {
        if !valid_name(s(rule, "consumer")) || !valid_name(s(rule, "serviceDefinition")) {
            return Err(Error::bad("Invalid consumer/serviceDefinition"));
        }
        if !scopes.insert((s(rule, "consumer"), s(rule, "serviceDefinition"))) {
            return Err(Error::bad("Duplicate scope"));
        }
        let providers = rule["providers"]
            .as_array()
            .filter(|v| v.len() <= 1000)
            .ok_or_else(|| Error::bad("providers array required (at most 1000 entries)"))?;
        let mut ids = BTreeSet::new();
        let mut ps = Vec::new();
        for p in providers {
            let id = s(p, "serviceInstanceId");
            let priority = p["priority"]
                .as_u64()
                .filter(|n| *n <= 2147483647)
                .ok_or_else(|| Error::bad("Nonnegative integer priority required"))?;
            if id.trim().is_empty() || id.len() > 255 || !ids.insert(id) {
                return Err(Error::bad("Unique nonempty provider IDs required"));
            }
            ps.push(json!({"serviceInstanceId":id,"priority":priority}));
        }
        ps.sort_by_key(|p| {
            (
                p["priority"].as_u64().unwrap(),
                s(p, "serviceInstanceId").to_owned(),
            )
        });
        out.push(json!({"consumer":rule["consumer"],"serviceDefinition":rule["serviceDefinition"],"providers":ps}));
    }
    out.sort_by_key(|r| {
        (
            s(r, "consumer").to_owned(),
            s(r, "serviceDefinition").to_owned(),
        )
    });
    Ok(json!({"rules":out}))
}
pub fn snapshot(app: &App) -> Value {
    app.store
        .snapshot()
        .get("plantRules")
        .and_then(|t| t.get("active"))
        .cloned()
        .unwrap_or_else(|| json!({"rules":[]}))
}
pub fn ranks(app: &App, consumer: &str, definition: &str) -> Option<BTreeMap<String, u64>> {
    array(&snapshot(app), "rules")
        .into_iter()
        .find(|r| s(r, "consumer") == consumer && s(r, "serviceDefinition") == definition)
        .map(|r| {
            array(&r, "providers")
                .iter()
                .map(|p| {
                    (
                        s(p, "serviceInstanceId").to_owned(),
                        p["priority"].as_u64().unwrap(),
                    )
                })
                .collect()
        })
}
pub fn handle(app: &App, method: &str, req: &Value, caller: &Principal) -> Result<(u16, Value)> {
    if !caller.sysop
        && caller.name != "PlantDescriptionEngine"
        && (method != "POST" || caller.name != "LocalCloudManager")
    {
        return Err(Error::denied());
    }
    if method == "POST" {
        return Ok((200, snapshot(app)));
    }
    let snapshot = normalize(req)?;
    app.store.update(|db| {
        table(db, "plantRules").insert("active".into(), snapshot.clone());
        Ok(())
    })?;
    Ok((200, snapshot))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_snapshots() {
        for r in [
            json!({}),
            json!({"rules":null}),
            json!({"rules":[{"consumer":"C","serviceDefinition":"temperature","providers":[{"serviceInstanceId":"P|temperature|1.0.0","priority":-1}]}]}),
            json!({"rules":[{"consumer":"C","serviceDefinition":"temperature","providers":null}]}),
        ] {
            assert!(normalize(&r).is_err());
        }
    }
    #[test]
    fn preserves_empty_scope_and_zero() {
        let r = json!({"rules":[{"consumer":"C","serviceDefinition":"temperature","providers":[]},{"consumer":"B","serviceDefinition":"temperature","providers":[{"serviceInstanceId":"P|temperature|1.0.0","priority":0}]}]});
        let n = normalize(&r).unwrap();
        assert_eq!(n["rules"][0]["consumer"], "B");
        assert_eq!(n["rules"][0]["providers"][0]["priority"], 0);
        assert_eq!(n["rules"][1]["providers"], json!([]));
    }
}
