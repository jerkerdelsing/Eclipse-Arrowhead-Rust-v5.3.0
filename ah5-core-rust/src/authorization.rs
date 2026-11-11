// SPDX-License-Identifier: EPL-2.0
use crate::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
// Policy names have role-specific forms; the shared valid_name helper also
// accepts other identifier kinds and must not be tightened globally.
fn valid_policy_name(name: &str, system: bool) -> bool {
    let mut bytes = name.bytes();
    name.len() <= 63
        && bytes.next().is_some_and(|b| {
            if system {
                b.is_ascii_uppercase()
            } else {
                b.is_ascii_lowercase()
            }
        })
        && bytes.all(|b| b.is_ascii_alphanumeric())
}

fn valid_policy_scope(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_lowercase()
        && bytes
            .last()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        && !name.contains("--")
}

pub fn valid_cloud(cloud: &str) -> bool {
    if cloud == "LOCAL" {
        return true;
    }
    let parts = cloud.split('|').collect::<Vec<_>>();
    parts.len() == 2 && parts.iter().all(|v| valid_name(v))
}

pub fn validate_target(request: &mut Value) -> Result<()> {
    if !request.is_object() {
        return Err(Error::bad("Authorization target must be an object"));
    }
    if s(request, "cloud").is_empty() {
        request["cloud"] = "LOCAL".into()
    }
    let target_type = s(request, "targetType").trim().to_uppercase();
    request["targetType"] = target_type.into();
    required(request, &["provider", "consumer", "target", "targetType"])?;
    if !valid_name(s(request, "provider"))
        || !valid_name(s(request, "consumer"))
        || !["SERVICE_DEF", "EVENT_TYPE"].contains(&s(request, "targetType"))
        || s(request, "target").contains(['|', '\r', '\n'])
        || !valid_cloud(s(request, "cloud"))
        || s(request, "scope").contains(['|', '\r', '\n'])
    {
        return Err(Error::bad("Invalid authorization target"));
    }
    Ok(())
}
fn policy_id(level: &str, req: &Value) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        if level == "MGMT" { "MGMT" } else { "PR" },
        s(req, "cloud"),
        s(req, "provider"),
        s(req, "targetType"),
        s(req, "target")
    )
}
fn validate_policy(policy: &Value) -> Result<()> {
    match s(policy, "policyType") {
        "ALL" => {}
        "WHITELIST" | "BLACKLIST" => {
            let a = policy["policyList"]
                .as_array()
                .ok_or_else(|| Error::bad("policyList required"))?;
            if a.iter()
                .any(|v| !v.as_str().is_some_and(|name| valid_policy_name(name, true)))
            {
                return Err(Error::bad("Invalid policy identity"));
            }
        }
        "SYS_METADATA" => {
            if !policy["policyMetadataRequirement"].is_object() {
                return Err(Error::bad("Metadata policy requirement required"));
            }
        }
        _ => return Err(Error::bad("Invalid policy type")),
    }
    Ok(())
}
pub fn grant(db: &mut Database, mut req: Value, level: &str, creator: &str) -> Result<Value> {
    if !req.is_object() {
        return Err(Error::bad("Grant must be an object"));
    }
    if s(&req, "cloud").is_empty() {
        req["cloud"] = "LOCAL".into()
    }
    required(&req, &["provider", "targetType", "target"])?;
    if !valid_policy_name(s(&req, "provider"), true)
        || !valid_policy_name(s(&req, "target"), false)
        || !valid_cloud(s(&req, "cloud"))
        || !["SERVICE_DEF", "EVENT_TYPE"].contains(&s(&req, "targetType"))
    {
        return Err(Error::bad("Invalid grant target"));
    }
    validate_policy(&req["defaultPolicy"])?;
    if let Some(scoped) = req["scopedPolicies"].as_object() {
        for (name, p) in scoped {
            if !valid_policy_scope(name) {
                return Err(Error::bad("Invalid scope"));
            }
            validate_policy(p)?
        }
    } else if !req["scopedPolicies"].is_null() {
        return Err(Error::bad("scopedPolicies must be an object"));
    }
    let id = policy_id(level, &req);
    let old = table(db, "policies").get(&id).cloned();
    if level == "PROVIDER"
        && old.as_ref().is_some_and(|r| {
            r["defaultPolicy"] != req["defaultPolicy"]
                || r["scopedPolicies"] != req["scopedPolicies"]
        })
    {
        return Err(Error::bad(
            "Revoke differing provider policy before replacing it",
        ));
    }
    let row = json!({"instanceId":id,"level":level,"provider":req["provider"],"cloud":req["cloud"],"targetType":req["targetType"],"target":req["target"],"defaultPolicy":req["defaultPolicy"],"scopedPolicies":req["scopedPolicies"],"description":req["description"],"createdBy":old.as_ref().map(|r|r["createdBy"].clone()).unwrap_or_else(||creator.into()),"createdAt":old.as_ref().map(|r|r["createdAt"].clone()).unwrap_or_else(||now().into())});
    table(db, "policies").insert(id, row.clone());
    Ok(row)
}
async fn evaluate(app: &App, policy: &Value, consumer: &str, cloud: &str) -> Result<bool> {
    Ok(match s(policy, "policyType") {
        "ALL" => true,
        "WHITELIST" => array(policy, "policyList").iter().any(|v| v == consumer),
        "BLACKLIST" => !array(policy, "policyList").iter().any(|v| v == consumer),
        "SYS_METADATA" => {
            // A local system with the same short name is not evidence about a
            // foreign consumer. Remote metadata needs an attested peer source.
            if cloud != "LOCAL" {
                return Ok(false);
            }
            let result = app
                .remote
                .call(
                    "ServiceRegistry",
                    "POST",
                    "/serviceregistry/system-discovery/lookup",
                    &json!({"systemNames":[consumer]}),
                )
                .await?;
            if let Some(system) = array(&result, "entries").first() {
                metadata_match(&system["metadata"], &policy["policyMetadataRequirement"])?
            } else {
                false
            }
        }
        _ => false,
    })
}
pub async fn granted(app: &App, mut request: Value) -> Result<bool> {
    validate_target(&mut request)?;
    let db = app.store.snapshot();
    let policies = db.get("policies");
    let row = policies.and_then(|m| {
        m.get(&policy_id("MGMT", &request))
            .or_else(|| m.get(&policy_id("PROVIDER", &request)))
    });
    let Some(row) = row else { return Ok(false) };
    let mut checks = Vec::new();
    let scope = s(&request, "scope");
    if scope.is_empty() {
        if !row["defaultPolicy"].is_null() {
            checks.push(row["defaultPolicy"].clone())
        }
        if let Some(scoped) = row["scopedPolicies"].as_object() {
            checks.extend(scoped.values().cloned())
        }
    } else if let Some(policy) = row["scopedPolicies"].get(scope) {
        checks.push(policy.clone())
    } else if !row["defaultPolicy"].is_null() {
        checks.push(row["defaultPolicy"].clone())
    }
    if checks.is_empty() {
        return Ok(false);
    }
    for policy in checks {
        if !evaluate(app, &policy, s(&request, "consumer"), s(&request, "cloud")).await? {
            return Ok(false);
        }
    }
    Ok(true)
}
pub async fn handle(
    app: &App,
    method: &str,
    path: &str,
    params: &BTreeMap<String, String>,
    query: &Value,
    request: &Value,
    caller: &Principal,
) -> Result<(u16, Value)> {
    if path.contains("authorization-token") || path.contains("/mgmt/token/") {
        return crate::tokens::handle(app, method, path, params, query, request, caller).await;
    }
    if path.ends_with("/verify") {
        let mut req = request.clone();
        for field in ["provider", "consumer"] {
            if s(&req, field).is_empty() {
                req[field] = caller.name.clone().into()
            }
        }
        if s(&req, "provider") != caller.name && s(&req, "consumer") != caller.name {
            return Err(Error::denied());
        }
        return Ok((200, granted(app, req).await?.into()));
    }
    if path.ends_with("/check") {
        let items = array(request, "list");
        if items.is_empty() || items.len() > 1000 {
            return Err(Error::bad("list must contain 1..1000 checks"));
        }
        let mut rows = Vec::new();
        for mut req in items {
            if !req.is_object() {
                return Err(Error::bad("Check must be an object"));
            }
            req["granted"] = granted(app, req.clone()).await?.into();
            rows.push(req)
        }
        return Ok((200, json!({"count":rows.len(),"entries":rows})));
    }
    let management = path.contains("/mgmt/");
    if path.ends_with("/grant") {
        let mut requests = if management {
            array(request, "list")
        } else {
            vec![request.clone()]
        };
        if requests.is_empty() || requests.len() > 1000 {
            return Err(Error::bad("Nonempty bounded grant list required"));
        }
        if !management {
            requests[0]["provider"] = caller.name.clone().into()
        }
        return app.store.update(|db| {
            let mut rows = Vec::new();
            for req in requests {
                rows.push(grant(
                    db,
                    req,
                    if management { "MGMT" } else { "PROVIDER" },
                    &caller.name,
                )?)
            }
            Ok((
                201,
                if management {
                    json!({"count":rows.len(),"entries":rows})
                } else {
                    rows.remove(0)
                },
            ))
        });
    }
    if method == "DELETE" {
        let ids = if management {
            array(query, "instanceIds")
        } else {
            vec![params["instanceId"].clone().into()]
        };
        if ids.is_empty() {
            return Err(Error::bad("instanceIds required"));
        }
        return app.store.update(|db| {
            for id in ids {
                let id = id
                    .as_str()
                    .ok_or_else(|| Error::bad("Invalid instance id"))?;
                if let Some(row) = table(db, "policies").get(id)
                    && !management
                    && (s(row, "provider") != caller.name || s(row, "level") != "PROVIDER")
                {
                    return Err(Error::denied());
                }
                table(db, "policies").remove(id);
            }
            Ok((200, Value::Null))
        });
    }
    let rows = app
        .store
        .rows("policies")
        .into_iter()
        .filter(|r| {
            (management || s(r, "provider") == caller.name && s(r, "level") == "PROVIDER")
                && selected(request, "providers", s(r, "provider"))
                && selected(request, "instanceIds", s(r, "instanceId"))
                && selected(request, "cloudIdentifiers", s(r, "cloud"))
                && selected(request, "targetNames", s(r, "target"))
                && (s(request, "targetType").is_empty() || request["targetType"] == r["targetType"])
                && (s(request, "level").is_empty() || request["level"] == r["level"])
        })
        .collect();
    Ok((200, page(rows, request, "entries")?))
}
