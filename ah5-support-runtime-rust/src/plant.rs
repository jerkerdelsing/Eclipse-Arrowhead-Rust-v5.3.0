// SPDX-License-Identifier: EPL-2.0
use crate::*;
use std::collections::{BTreeMap, BTreeSet};
fn validate(document: &Value, all: &BTreeMap<String, Value>, current: &str) -> Result<()> {
    let systems = array(document, "systems");
    let mut ids = BTreeMap::new();
    for system in &systems {
        let id = system["systemId"].to_string();
        if id == "null"
            || (!s(system, "systemName").is_empty() && !valid_name(s(system, "systemName")))
            || ids.insert(id, system).is_some()
        {
            return Err(Error::bad(
                "Unique systemIds and valid systemNames required",
            ));
        }
        let mut ports = BTreeSet::new();
        for port in array(system, "ports") {
            let name = if port.is_string() {
                port.as_str().unwrap()
            } else {
                s(&port, "portName")
            };
            if name.is_empty() || !ports.insert(name.to_owned()) {
                return Err(Error::bad("Unique nonempty ports required"));
            }
        }
    }
    for connection in array(document, "connections") {
        if !connection["priority"].is_null()
            && connection["priority"]
                .as_u64()
                .is_none_or(|p| p > 2147483647)
        {
            return Err(Error::bad("Nonnegative integer priority required"));
        }
        for side in ["consumer", "producer"] {
            let endpoint = &connection[side];
            let system = ids
                .get(&endpoint["systemId"].to_string())
                .ok_or_else(|| Error::bad("Connection system does not exist"))?;
            let ports = array(system, "ports");
            if !ports.iter().any(|p| {
                p.as_str() == Some(s(endpoint, "portName"))
                    || s(p, "portName") == s(endpoint, "portName")
            }) {
                return Err(Error::bad("Connection port does not exist"));
            }
        }
    }
    fn visit(
        id: &str,
        all: &BTreeMap<String, Value>,
        visiting: &mut BTreeSet<String>,
        done: &mut BTreeSet<String>,
    ) -> Result<()> {
        if done.contains(id) {
            return Ok(());
        }
        if !visiting.insert(id.into()) {
            return Err(Error::bad("Plant include cycle"));
        }
        let doc = all
            .get(id)
            .ok_or_else(|| Error::bad("Included description does not exist"))?;
        for value in array(doc, "include") {
            let next = value
                .as_u64()
                .ok_or_else(|| Error::bad("Include must be numeric id"))?
                .to_string();
            visit(&next, all, visiting, done)?
        }
        visiting.remove(id);
        done.insert(id.into());
        Ok(())
    }
    let mut all = all.clone();
    all.insert(current.into(), document.clone());
    visit(current, &all, &mut BTreeSet::new(), &mut BTreeSet::new())?;
    if document["active"] == true && all.iter().any(|(k, r)| k != current && r["active"] == true) {
        return Err(Error::new(409, "Another plant description is active"));
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub async fn handle(
    app: &App,
    method: &str,
    path: &str,
    p: &BTreeMap<String, String>,
    q: &Value,
    req: &Value,
    _caller: &Principal,
) -> Result<(u16, Value)> {
    if path.ends_with("/sync-status") {
        return Ok((
            200,
            app.store
                .snapshot()
                .get("pdeSync")
                .and_then(|t| t.get("state"))
                .cloned()
                .unwrap_or_else(|| json!({"ok":false,"detail":"not synchronized yet"})),
        ));
    }
    let key = p.get("id");
    let bucket = if path.contains("/alarms") {
        "alarms"
    } else {
        "plants"
    };
    if method == "GET" {
        if let Some(key) = key {
            return Ok((200, row(app, bucket, key)?));
        }
        return Ok((200, page(app.store.rows(bucket), q, "entries")?));
    }
    if bucket == "alarms" {
        let acknowledged = req["acknowledged"]
            .as_bool()
            .ok_or_else(|| Error::bad("acknowledged boolean required"))?;
        let record = app.store.update(|db| {
            let r = table(db, bucket)
                .get_mut(key.unwrap())
                .ok_or_else(|| Error::new(404, "Alarm not found"))?;
            r["acknowledged"] = acknowledged.into();
            r["updatedAt"] = now().into();
            Ok(r.clone())
        })?;
        return Ok((200, record));
    }
    let result = app.store.update(|db| {
        let t = table(db, "plants");
        let id = key.cloned().unwrap_or_else(|| {
            (t.values()
                .filter_map(|r| r["id"].as_u64())
                .max()
                .unwrap_or(0)
                + 1)
            .to_string()
        });
        if method == "DELETE" {
            if t.values().any(|r| {
                array(r, "include")
                    .iter()
                    .any(|v| v.as_u64().map(|n| n.to_string()) == Some(id.clone()))
            }) {
                return Err(Error::new(409, "Description is included by another plant"));
            }
            return t
                .remove(&id)
                .ok_or_else(|| Error::new(404, "Plant description not found"));
        }
        let old = t.get(&id);
        if method != "POST" && old.is_none() {
            return Err(Error::new(404, "Plant description not found"));
        }
        let mut doc = if method == "PATCH" {
            let mut old = old.unwrap().clone();
            for (k, v) in req.as_object().unwrap() {
                old[k] = v.clone()
            }
            old
        } else {
            req.clone()
        };
        doc["id"] = id
            .parse::<u64>()
            .map_err(|_| Error::bad("Numeric id required"))?
            .into();
        if s(&doc, "plantDescription").trim().is_empty() {
            return Err(Error::bad("plantDescription required"));
        }
        validate(&doc, t, &id)?;
        doc["createdAt"] = old
            .map(|r| r["createdAt"].clone())
            .unwrap_or_else(|| now().into());
        doc["updatedAt"] = now().into();
        t.insert(id, doc.clone());
        Ok(doc)
    })?;
    Ok((if method == "POST" { 201 } else { 200 }, result))
}
