// SPDX-License-Identifier: EPL-2.0
use crate::*;
use std::collections::BTreeMap;
#[allow(clippy::too_many_arguments)]
pub async fn handle(
    app: &App,
    method: &str,
    path: &str,
    p: &BTreeMap<String, String>,
    q: &Value,
    req: &Value,
    caller: &Principal,
) -> Result<(u16, Value)> {
    let management = path.contains("/mgmt/");
    if path.ends_with("/query") {
        let rows = app
            .store
            .rows("bridges")
            .into_iter()
            .filter(|r| {
                selected(req, "bridgeIds", s(r, "bridgeId"))
                    && selected(req, "creators", s(r, "createdBy"))
                    && selected(req, "statuses", s(r, "status"))
                    && selected(req, "consumers", s(r, "consumer"))
            })
            .collect();
        return Ok((200, page(rows, req, "entries")?));
    }
    if path.ends_with("/discovery") {
        let consumer = if management {
            s(req, "consumer")
        } else {
            &caller.name
        };
        if !valid_name(consumer) {
            return Err(Error::bad("consumer required"));
        }
        let response = app
            .remote
            .call("InterfaceTranslator", "POST", "/translation/discovery", req)
            .await?;
        if !response["candidates"].is_array() {
            return Err(Error::new(502, "Adapter returned no candidate array"));
        }
        let id = id();
        let value = json!({"bridgeId":id,"consumer":consumer,"createdBy":caller.name,"createdAt":now(),"updatedAt":now(),"status":"DISCOVERED","candidates":response["candidates"],"request":req,"usageReportCount":0});
        app.store.update(|db| {
            table(db, "bridges").insert(id.clone(), value);
            Ok(())
        })?;
        return Ok((
            200,
            json!({"bridgeId":id,"candidates":response["candidates"]}),
        ));
    }
    let ids = if method == "DELETE" && management {
        array(q, "ids")
            .iter()
            .filter_map(Value::as_str)
            .map(String::from)
            .collect::<Vec<_>>()
    } else {
        vec![
            p.get("bridgeId")
                .cloned()
                .unwrap_or_else(|| s(req, "bridgeId").into()),
        ]
    };
    if ids.is_empty() {
        return Err(Error::bad("bridgeId or ids required"));
    }
    for id in &ids {
        let old = row(app, "bridges", id)?;
        if !management {
            own(caller, s(&old, "createdBy"))?
        }
        if path.ends_with("/report") {
            if caller.name != "InterfaceTranslator" && caller.name != s(&old, "consumer") {
                return Err(Error::denied());
            }
            app.store.update(|db| {
                let value = table(db, "bridges")
                    .get_mut(id)
                    .ok_or_else(|| Error::new(404, "Bridge disappeared"))?;
                value["usageReportCount"] = (integer(value, "usageReportCount", 0) + 1).into();
                value["lastReport"] = req.clone();
                Ok(())
            })?;
            continue;
        }
        let state = if method == "DELETE" {
            "ABORTING"
        } else {
            "NEGOTIATING"
        };
        if method != "DELETE" && s(&old, "status") != "DISCOVERED" {
            return Err(Error::new(409, "Bridge is not discovered"));
        }
        if ["NEGOTIATING", "ABORTING"].contains(&s(&old, "status")) {
            return Err(Error::new(409, "Bridge operation in progress"));
        }
        // Reserve before network effects. An uncertain failure is durable ERROR, not a fake rollback.
        app.store.update(|db| {
            let current = table(db, "bridges")
                .get_mut(id)
                .ok_or_else(|| Error::new(404, "Bridge disappeared"))?;
            if current["status"] != old["status"] {
                return Err(Error::new(409, "Bridge changed"));
            }
            current["status"] = state.into();
            Ok(())
        })?;
        let mut input = req.clone();
        input["discovery"] = old["request"].clone();
        let target = if method == "DELETE" {
            format!("/translation/abort/{}", security::encode(id))
        } else {
            "/translation/negotiation".into()
        };
        let result = app
            .remote
            .call(
                "InterfaceTranslator",
                if method == "DELETE" { "DELETE" } else { "POST" },
                &target,
                if method == "DELETE" {
                    &Value::Null
                } else {
                    &input
                },
            )
            .await;
        let result = result.and_then(|v| {
            if method != "DELETE" && (s(&v, "bridgeId") != id || !v["bridgeInterface"].is_object())
            {
                Err(Error::new(502, "Invalid adapter negotiation result"))
            } else {
                Ok(v)
            }
        });
        app.store.update(|db| {
            let current = table(db, "bridges")
                .get_mut(id)
                .ok_or_else(|| Error::new(404, "Bridge disappeared"))?;
            current["status"] = if result.is_err() {
                "ERROR"
            } else if method == "DELETE" {
                "ABORTED"
            } else {
                "ACTIVE"
            }
            .into();
            current["updatedAt"] = now().into();
            if let Ok(v) = &result {
                current["bridgeInterface"] = v["bridgeInterface"].clone()
            }
            Ok(())
        })?;
        let response = result?;
        if method != "DELETE" {
            return Ok((200, response));
        }
    }
    Ok((200, Value::Null))
}
