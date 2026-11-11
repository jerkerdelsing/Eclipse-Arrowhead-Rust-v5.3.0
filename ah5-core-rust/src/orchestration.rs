// SPDX-License-Identifier: EPL-2.0
use crate::*;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

fn parts(id: &str) -> Result<(&str, &str, &str)> {
    let p = id.split('|').collect::<Vec<_>>();
    if p.len() != 3 || !valid_name(p[0]) || !valid_name(p[1]) || p[2].is_empty() {
        return Err(Error::bad(
            "serviceInstanceId must be provider|definition|version",
        ));
    }
    Ok((p[0], p[1], p[2]))
}
fn flag(req: &Value, name: &str) -> bool {
    req["orchestrationFlags"][name] == true
}
async fn intercloud(app: &App, req: &Value, consumer: &str) -> Result<Value> {
    let mut warnings = vec![json!("interCloud")];
    if !flag(req, "MATCHMAKING") {
        warnings.push(json!("autoMatchmaking"));
    }
    if !app.config.intercloud_enabled {
        warnings.push(json!("interCloudDisabled"));
        return Ok(json!({"results":[],"warnings":warnings}));
    }
    let result=async {
        let discovered=app.remote.call("Gatekeeper","POST","/gatekeeper/init_gsd",&json!({"serviceRequirement":req["serviceRequirement"],"consumerSystem":consumer})).await?;
        let preferred=array(&req["serviceRequirement"],"preferredProviders");
        let mut candidates=array(&discovered,"results");
        candidates.sort_by_key(|v|(!preferred.iter().any(|p|p==&v["providerName"]),s(v,"providerName").to_owned(),s(v,"cloud").to_owned()));
        for candidate in candidates {
            if flag(req,"ONLY_PREFERRED")&&!preferred.iter().any(|p|p==&candidate["providerName"]){continue;}
            let negotiated=app.remote.call("Gatekeeper","POST","/gatekeeper/init_icn",&json!({"targetCloud":candidate["cloud"],"providerName":candidate["providerName"],"serviceDefinition":req["serviceRequirement"]["serviceDefinition"],"consumerSystem":consumer,"operations":array(&req["serviceRequirement"],"operations")})).await?;
            if negotiated["negotiated"]!=true{continue;}
            if negotiated["providerName"]!=candidate["providerName"]||negotiated["providerCloud"]!=candidate["cloud"]||negotiated["serviceDefinition"]!=req["serviceRequirement"]["serviceDefinition"]||negotiated["interface"]["policy"]!="CERT_AUTH"||negotiated["interface"]["protocol"]!="https"{return Err(Error::new(502,"Invalid inter-cloud negotiation binding"));}
            return Ok::<_,Error>(vec![json!({"serviceInstanceId":format!("{}|{}|{}",s(&negotiated,"providerName"),s(&negotiated,"serviceDefinition"),s(&negotiated,"version")),"cloudIdentitifer":negotiated["providerCloud"],"providerName":negotiated["providerName"],"serviceDefinitition":negotiated["serviceDefinition"],"version":negotiated["version"],"aliveUntil":null,"exclusiveUntil":null,"metadata":negotiated["metadata"],"interfaces":[negotiated["interface"]],"authorizationTokens":null})]);
        }
        Ok(Vec::new())
    }.await;
    match result {
        Ok(results) => Ok(json!({"results":results,"warnings":warnings})),
        Err(_) => {
            warnings.push(json!("interCloudFailed"));
            Ok(json!({"results":[],"warnings":warnings}))
        }
    }
}
const FLAGS: [&str; 6] = [
    "MATCHMAKING",
    "ONLY_PREFERRED",
    "ONLY_EXCLUSIVE",
    "ALLOW_TRANSLATION",
    "ALLOW_INTERCLOUD",
    "ONLY_INTERCLOUD",
];
fn provider(row: &Value) -> &str {
    s(&row["provider"], "name")
}
// Finds a provider of a support service by ServiceRegistry lookup, the way the Java orchestrator's collector resolves
// its bootstrap dependencies. With an evaluation type, an instance carrying that evaluationType metadata wins and one
// without the key is the fallback (the Rust DeviceQoSEvaluator does not publish it).
async fn locate(app: &App, definition: &str, evaluation: Option<&str>) -> Result<Value> {
    let response = app
        .remote
        .call(
            "ServiceRegistry",
            "POST",
            "/serviceregistry/service-discovery/lookup",
            &json!({"serviceDefinitionNames":[definition]}),
        )
        .await?;
    let entries = array(&response, "entries");
    match evaluation {
        Some(kind) => entries
            .iter()
            .find(|e| e["metadata"]["evaluationType"] == kind)
            .or_else(|| entries.iter().find(|e| e["metadata"]["evaluationType"].is_null())),
        None => entries.first(),
    }
    .cloned()
    .ok_or_else(|| Error::unavailable(&format!("No {definition} provider is registered")))
}
async fn invoke(
    app: &App,
    instance: &Value,
    operation: &str,
    params: &[(&str, &str)],
    body: &Value,
) -> Result<Value> {
    for interface in array(instance, "interfaces") {
        let p = &interface["properties"];
        let op = &p["operations"][operation];
        let (Some(address), Some(port)) = (
            p["accessAddresses"].get(0).and_then(Value::as_str),
            p["accessPort"].as_u64(),
        ) else {
            continue;
        };
        if !s(&interface, "protocol").eq_ignore_ascii_case("https") || s(op, "path").is_empty() {
            continue;
        }
        let mut path = format!("{}{}", s(p, "basePath"), s(op, "path"));
        for (name, value) in params {
            path = path.replace(&format!("{{{name}}}"), &security::encode(value));
        }
        let method = if s(op, "method").is_empty() { "POST" } else { s(op, "method") };
        return app
            .remote
            .call_at(provider(instance), &format!("https://{address}:{port}/"), method, &path, body)
            .await;
    }
    Err(Error::unavailable(&format!("No HTTPS {operation} operation offered")))
}
// Java filterOutBlacklistedOnes: 401/403 propagate, any other Blacklist failure drops every candidate when the filter
// is forced and keeps them otherwise. Uses blacklistDiscovery check per provider instead of the management query.
async fn without_blacklisted(app: &App, rows: Vec<Value>) -> Result<Vec<Value>> {
    let names = rows
        .iter()
        .map(|r| provider(r).to_owned())
        .filter(|n| !app.config.blacklist_exclude.contains(n))
        .collect::<BTreeSet<_>>();
    if names.is_empty() {
        return Ok(rows);
    }
    let checked = async {
        let blacklist = locate(app, "blacklistDiscovery", None).await?;
        let mut listed = BTreeSet::new();
        for name in names {
            match invoke(app, &blacklist, "check", &[("systemName", &name)], &Value::Null).await? {
                Value::Bool(true) => {
                    listed.insert(name);
                }
                Value::Bool(false) => {}
                _ => return Err(Error::new(502, "Invalid Blacklist answer")),
            }
        }
        Ok(listed)
    }
    .await;
    match checked {
        Ok(listed) => Ok(rows.into_iter().filter(|r| !listed.contains(provider(r))).collect()),
        Err(e) if e.code == 401 || e.code == 403 => Err(e),
        Err(_) if app.config.blacklist_filter_forced => Ok(Vec::new()),
        Err(_) => Ok(rows),
    }
}
// Java QoSDriver.doQoSCompliance: each requirement sorts or filters the remaining candidates; a missing or failing
// evaluator only adds qosComplianceFailure. Every evaluation is recorded with the job like the Java qos_eval_result.
async fn quality(
    app: &App,
    job: &str,
    mut rows: Vec<Value>,
    requirements: &[Value],
    warnings: &mut BTreeSet<String>,
) -> Result<Vec<Value>> {
    let providers = rows.iter().map(|r| provider(r).to_owned()).collect::<Vec<_>>();
    for requirement in requirements {
        let operation = s(requirement, "operation").to_lowercase();
        let outcome = async {
            let evaluator = locate(app, "qualityEvaluation", Some(s(requirement, "type"))).await?;
            invoke(app, &evaluator, &operation, &[], &json!({"providers":providers,"configuration":requirement["requirements"]})).await
        }
        .await;
        let recorded = match &outcome {
            Ok(v) => v.to_string(),
            Err(e) => e.message.clone(),
        };
        app.store.update(|db| {
            table(db, "qosEvaluations").insert(uuid::Uuid::new_v4().to_string(), json!({"orchestrationJobId":job,"type":requirement["type"],"operation":requirement["operation"],"result":recorded,"createdAt":now()}));
            Ok(())
        })?;
        let key = if operation == "sort" { "sortedProviders" } else { "passedProviders" };
        let Some(names) = outcome.ok().and_then(|v| v[key].as_array().cloned()) else {
            warnings.insert("qosComplianceFailure".into());
            continue;
        };
        rows = names
            .iter()
            .filter_map(|n| rows.iter().find(|r| provider(r) == n.as_str().unwrap_or("")).cloned())
            .collect();
    }
    Ok(rows)
}
// dataModels.<operation>.input/output requested with an equality requirement, as Java extractInterfaceModelIDRequirements.
fn model_requirement(requirements: &[Value], key: &str) -> Option<String> {
    requirements.iter().find_map(|r| match &r[key] {
        Value::String(v) => Some(v.clone()),
        v => v["$eq"].as_str().map(String::from),
    })
}
fn model_offer(properties: &Value, operation: &str, direction: &str) -> Option<String> {
    let flat = &properties[format!("dataModels.{operation}.{direction}")];
    let nested = &properties["dataModels"][operation][direction];
    [flat, nested]
        .into_iter()
        .find_map(|v| v.as_str().filter(|v| !v.is_empty()).map(String::from))
}
fn token_type(policy: &str) -> Option<&'static str> {
    match policy {
        "BASE64_SELF_CONTAINED_TOKEN_AUTH"
        | "RSA_SHA256_JSON_WEB_TOKEN_AUTH"
        | "RSA_SHA512_JSON_WEB_TOKEN_AUTH" => Some("SELF_CONTAINED_TOKEN"),
        "TIME_LIMITED_TOKEN_AUTH" => Some("TIME_LIMITED_TOKEN"),
        "USAGE_LIMITED_TOKEN_AUTH" => Some("USAGE_LIMITED_TOKEN"),
        "TRANSLATION_BRIDGE_TOKEN_AUTH" => Some("TRANSLATION_BRIDGE_TOKEN"),
        _ => None,
    }
}
// Java assortInterfacesAndMarkIfNonNative + translation discovery. Returns the bridge id when no candidate has a native
// interface and TranslationManager found translatable ones; candidates then carry only their translatable interface.
async fn translate(
    app: &App,
    req: &Value,
    consumer: &str,
    rows: &mut Vec<Value>,
) -> Result<Option<String>> {
    let requirement = &req["serviceRequirement"];
    let templates = array(requirement, "interfaceTemplateNames");
    let properties = array(requirement, "interfacePropertyRequirements");
    let operation = array(requirement, "operations")[0].as_str().unwrap_or("").to_owned();
    let wanted_in = model_requirement(&properties, &format!("dataModels.{operation}.input"));
    let wanted_out = model_requirement(&properties, &format!("dataModels.{operation}.output"));
    let mut translatable = Vec::new();
    let mut natives = Vec::new();
    for row in rows.iter_mut() {
        let mut native = Vec::new();
        let mut other = Vec::new();
        for interface in array(row, "interfaces") {
            let template_ok = templates.is_empty() || templates.contains(&interface["templateName"]);
            let mut props_ok = properties.is_empty();
            for p in &properties {
                props_ok |= metadata_match(&interface["properties"], p)?;
            }
            if template_ok && props_ok {
                native.push(interface);
            } else if native.is_empty() && !templates.is_empty() {
                let offered_in = model_offer(&interface["properties"], &operation, "input");
                let offered_out = model_offer(&interface["properties"], &operation, "output");
                if wanted_in.is_some() == offered_in.is_some() && wanted_out.is_some() == offered_out.is_some() {
                    other.push(interface);
                }
            }
        }
        natives.push(!native.is_empty());
        translatable.push(other);
        if !native.is_empty() {
            row["interfaces"] = Value::Array(native);
        }
    }
    if natives.contains(&true) {
        let mut native = natives.into_iter();
        rows.retain(|_| native.next().unwrap_or(false));
        return Ok(None);
    }
    let candidates = rows
        .iter()
        .zip(&translatable)
        .filter(|(_, other)| !other.is_empty())
        .map(|(r, other)| {
            let mut r = r.clone();
            r["interfaces"] = Value::Array(other.clone());
            r
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        rows.clear();
        return Ok(None);
    }
    let manager = locate(app, "translationBridgeManagement", None).await?;
    let discovered = invoke(app, &manager, "discovery", &[], &json!({"candidates":candidates,"consumer":consumer,"operation":operation,"interfaceTemplateNames":templates,"inputDataModelId":wanted_in,"outputDataModelId":wanted_out,"flags":{"CONSUMER_BLACKLIST_CHECK":false,"CANDIDATES_BLACKLIST_CHECK":false,"CANDIDATES_AUTH_CHECK":false,"TRANSLATORS_BLACKLIST_CHECK":app.config.blacklist_filter,"TRANSLATORS_AUTH_CHECK":true}})).await?;
    let found = array(&discovered, "candidates");
    if found.is_empty() {
        rows.clear();
        return Ok(None);
    }
    let bridge = s(&discovered, "bridgeId");
    if bridge.is_empty() {
        return Err(Error::new(502, "TranslationManager returned no bridgeId"));
    }
    *rows = candidates
        .into_iter()
        .filter_map(|mut r| {
            let chosen = array(&r, "interfaces").into_iter().find(|i| {
                found.iter().any(|f| {
                    f["serviceInstanceId"] == r["instanceId"] && f["interfaceTemplateName"] == i["templateName"]
                })
            })?;
            r["interfaces"] = json!([chosen]);
            Some(r)
        })
        .collect();
    Ok(Some(bridge.to_owned()))
}
pub fn simple(app: &App, req: &Value, consumer: &str) -> Result<Value> {
    let requirement = &req["serviceRequirement"];
    let preferred = array(requirement, "preferredProviders");
    if flag(req, "ONLY_PREFERRED") && preferred.is_empty() {
        return Err(Error::bad("ONLY_PREFERRED requires preferredProviders"));
    }
    let mut rows = app
        .store
        .rows("simpleStore")
        .into_iter()
        .filter(|row| {
            s(row, "consumer") == consumer
                && (s(requirement, "serviceDefinition").is_empty()
                    || row["serviceDefinition"] == requirement["serviceDefinition"])
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|r| {
        let provider = s(r, "serviceInstanceId").split('|').next().unwrap_or("");
        (
            !preferred.iter().any(|v| v == provider),
            r["priority"].as_i64().unwrap_or(0),
            s(r, "id").to_owned(),
        )
    });
    let mut results = Vec::new();
    let mut seen = BTreeSet::new();
    for row in rows {
        let (p, d, v) = parts(s(&row, "serviceInstanceId"))?;
        if flag(req, "ONLY_PREFERRED") && !preferred.iter().any(|v| v == p) {
            continue;
        }
        if flag(req, "MATCHMAKING") && !seen.insert(d.to_owned()) {
            continue;
        }
        results.push(json!({"serviceInstanceId":row["serviceInstanceId"],"cloudIdentitifer":"LOCAL","providerName":p,"serviceDefinitition":d,"version":v,"aliveUntil":null,"exclusiveUntil":null,"metadata":null,"interfaces":null,"authorizationTokens":null}));
    }
    let mut warnings = Vec::new();
    if let Some(fields) = requirement.as_object() {
        for (k, v) in fields {
            if !["serviceDefinition", "preferredProviders"].contains(&k.as_str()) && !v.is_null() {
                warnings.push(format!("ignoredFields: {k}"))
            }
        }
    }
    if let Some(flags) = req["orchestrationFlags"].as_object() {
        for (k, v) in flags {
            if !["MATCHMAKING", "ONLY_PREFERRED"].contains(&k.as_str()) && v == true {
                warnings.push(format!("ignoredFlags: {k}"))
            }
        }
    }
    Ok(json!({"results":results,"warnings":warnings}))
}
pub async fn pull(app: &App, req: &Value, consumer: &str, job: &str) -> Result<Value> {
    if app.config.role.ends_with("simple") {
        return simple(app, req, consumer);
    }
    let requirement = &req["serviceRequirement"];
    required(requirement, &["serviceDefinition"])?;
    if !req["orchestrationFlags"].is_null() && !req["orchestrationFlags"].is_object() {
        return Err(Error::bad("Orchestration flags must be an object"));
    }
    // Java OrchestrationFormValidation/Normalization: known flags only, keys normalized to upper case.
    let mut normalized = req.clone();
    if let Some(flags) = req["orchestrationFlags"].as_object() {
        let mut upper = serde_json::Map::new();
        for (name, v) in flags {
            if !v.is_boolean() {
                return Err(Error::bad("Orchestration flags must be booleans"));
            }
            let name = name.trim().to_uppercase();
            if !FLAGS.contains(&name.as_str()) {
                return Err(Error::bad(format!("Invalid orchestration flag: {name}")));
            }
            upper.insert(name, v.clone());
        }
        normalized["orchestrationFlags"] = Value::Object(upper);
    }
    let req = &normalized;
    let requirement = &req["serviceRequirement"];
    if !req["qualityRequirements"].is_null() && !req["qualityRequirements"].is_array() {
        return Err(Error::bad("Quality requirements must be a list"));
    }
    let qualities = array(req, "qualityRequirements");
    for quality in &qualities {
        if s(quality, "type").trim().is_empty() {
            return Err(Error::bad("QoS type is empty"));
        }
        if s(quality, "operation").trim().is_empty() {
            return Err(Error::bad("QoS operation is empty"));
        }
        if !["SORT", "FILTER"].contains(&s(quality, "operation").trim().to_uppercase().as_str()) {
            return Err(Error::bad("Invalid QoS operation"));
        }
    }
    if flag(req, "ALLOW_TRANSLATION") {
        if flag(req, "ONLY_INTERCLOUD") {
            return Err(Error::bad(
                "ONLY_INTERCLOUD and ALLOW_TRANSLATION flags cannot be present at the same time",
            ));
        }
        if array(requirement, "interfaceTemplateNames").is_empty() {
            return Err(Error::bad(
                "Interface template name(s) must be defined when translation is allowed",
            ));
        }
        if array(requirement, "operations").len() != 1 {
            return Err(Error::bad(
                "Exactly one operation must be defined when translation is allowed",
            ));
        }
    }
    let translation = flag(req, "ALLOW_TRANSLATION") && app.config.translation_enabled;
    let mut warnings = BTreeSet::new();
    let preferred = array(requirement, "preferredProviders");
    if flag(req, "ONLY_PREFERRED") && preferred.is_empty() {
        return Err(Error::bad("ONLY_PREFERRED requires preferredProviders"));
    }
    let plant = crate::plant_rules::ranks(app, consumer, s(requirement, "serviceDefinition"));
    if plant.is_some() && flag(req, "ONLY_INTERCLOUD") {
        return Ok(json!({"results":[],"warnings":[]}));
    }
    if plant.is_none() && (flag(req, "ONLY_INTERCLOUD") || flag(req, "ALLOW_INTERCLOUD")) {
        if array(requirement, "operations").len() != 1 {
            return Err(Error::bad(
                "Inter-cloud orchestration requires exactly one operation",
            ));
        }
        if flag(req, "ONLY_INTERCLOUD") && !app.config.intercloud_enabled {
            return Err(Error::bad("Inter-cloud orchestration is not enabled"));
        }
    }
    if flag(req, "ONLY_INTERCLOUD") {
        return intercloud(app, req, consumer).await;
    }
    let mut lookup = json!({"serviceDefinitionNames":[requirement["serviceDefinition"]],"versions":requirement["versions"],"alivesAt":requirement["alivesAt"],"metadataRequirementsList":requirement["metadataRequirements"],"addressTypes":requirement["interfaceAddressTypes"],"interfaceTemplateNames":requirement["interfaceTemplateNames"],"interfacePropertyRequirementsList":requirement["interfacePropertyRequirements"],"policies":requirement["securityPolicies"]});
    if translation {
        // Interfaces are assorted locally into native and translatable ones (Java serviceDiscovery withoutInterface).
        for key in ["addressTypes", "interfaceTemplateNames", "interfacePropertyRequirementsList"] {
            lookup[key] = Value::Null;
        }
    }
    let response = app
        .remote
        .call(
            "ServiceRegistry",
            "POST",
            "/serviceregistry/service-discovery/lookup",
            &lookup,
        )
        .await?;
    let mut instances = array(&response, "entries")
        .into_iter()
        .filter(|r| {
            plant
                .as_ref()
                .is_none_or(|ranks| ranks.contains_key(s(r, "instanceId")))
                && (!flag(req, "ONLY_PREFERRED")
                    || preferred.iter().any(|p| p == s(&r["provider"], "name")))
        })
        .collect::<Vec<_>>();
    if app.config.blacklist_filter {
        instances = without_blacklisted(app, instances).await?;
    }
    if instances.is_empty() {
        if plant.is_none() && flag(req, "ALLOW_INTERCLOUD") {
            return intercloud(app, req, consumer).await;
        }
        return Ok(json!({"results":[],"warnings":[]}));
    }
    let scopes = array(requirement, "operations");
    if scopes.iter().any(|v| {
        v.as_str()
            .is_none_or(|v| v.is_empty() || v.contains(['|', '\r', '\n']))
    }) {
        return Err(Error::bad("Invalid requested operation"));
    }
    let mut checks = Vec::new();
    for row in &instances {
        let mut check = json!({"provider":row["provider"]["name"],"consumer":consumer,"cloud":"LOCAL","targetType":"SERVICE_DEF","target":requirement["serviceDefinition"]});
        if scopes.is_empty() {
            checks.push(check);
        } else {
            for scope in &scopes {
                check["scope"] = scope.clone();
                checks.push(check.clone());
            }
        }
    }
    let expected_checks = checks.len();
    let permissions = app
        .remote
        .call(
            "ConsumerAuthorization",
            "POST",
            "/consumerauthorization/authorization/mgmt/check",
            &json!({"list":checks}),
        )
        .await?;
    let answers = array(&permissions, "entries");
    if answers.len() != expected_checks {
        return Err(Error::new(502, "Authorization response count mismatch"));
    }
    let mut allowed = Vec::new();
    for (row, permissions) in instances.drain(..).zip(answers.chunks(scopes.len().max(1))) {
        for (index, answer) in permissions.iter().enumerate() {
            if answer["provider"] != row["provider"]["name"]
                || answer["consumer"] != consumer
                || answer["target"] != requirement["serviceDefinition"]
                || (!scopes.is_empty() && answer["scope"] != scopes[index])
            {
                return Err(Error::new(
                    502,
                    "Authorization response identity/scope mismatch",
                ));
            }
        }
        if permissions.iter().all(|answer| answer["granted"] == true) {
            allowed.push(row);
        }
    }
    allowed.sort_by_key(|r| {
        (
            plant
                .as_ref()
                .and_then(|p| p.get(s(r, "instanceId")))
                .copied()
                .unwrap_or(0),
            plant.is_none() && !preferred.iter().any(|v| v == s(&r["provider"], "name")),
            s(r, "instanceId").to_owned(),
        )
    });
    // Java filterOutNonPreferredProviders: preferred providers, when any is a candidate, exclude the others.
    if !flag(req, "ONLY_PREFERRED") && allowed.iter().any(|r| preferred.iter().any(|p| p == provider(r))) {
        allowed.retain(|r| preferred.iter().any(|p| p == provider(r)));
    }
    let mut matchmaking = flag(req, "MATCHMAKING");
    let bridge = if translation {
        let bridge = translate(app, req, consumer, &mut allowed).await?;
        if bridge.is_some() && !matchmaking {
            matchmaking = true;
            warnings.insert("autoMatchmaking".to_owned());
        }
        bridge
    } else {
        None
    };
    if !qualities.is_empty() && !allowed.is_empty() {
        if app.config.qos_enabled {
            allowed = quality(app, job, allowed, &qualities, &mut warnings).await?;
            if let Some(ranks) = &plant {
                allowed.sort_by_key(|r| ranks.get(s(r, "instanceId")).copied().unwrap_or(0));
            }
        } else {
            warnings.insert("qosNotEnabled".to_owned());
        }
    }
    let duration = req["exclusivityDuration"].as_u64().unwrap_or(0);
    if !req["exclusivityDuration"].is_null() && req["exclusivityDuration"].as_u64().is_none() {
        return Err(Error::bad("Exclusivity must be an unsigned integer"));
    }
    if duration > 86400 {
        return Err(Error::bad("Exclusivity must be 0..86400 seconds"));
    }
    let mut results = Vec::new();
    for row in allowed {
        let id = s(&row, "instanceId");
        if app.store.rows("locks").iter().any(|l| {
            s(l, "serviceInstanceId") == id
                && s(l, "owner") != consumer
                && !expired(s(l, "expiresAt"))
        }) {
            continue;
        }
        let maximum = s(&row["metadata"], "allowExclusivity")
            .parse::<u64>()
            .unwrap_or(0)
            .min(86400);
        let lock_duration = if flag(req, "ONLY_EXCLUSIVE") && duration == 0 {
            maximum
        } else {
            duration.min(maximum)
        };
        if flag(req, "ONLY_EXCLUSIVE") && lock_duration == 0 {
            continue;
        }
        let mut interfaces = Vec::new();
        let mut tokens = json!({});
        if let Some(bridge) = &bridge {
            // Java buildTranslationBridge: the bridge interface replaces the provider's and its token is the bridge id.
            let manager = locate(app, "translationBridgeManagement", None).await?;
            let negotiated = invoke(app, &manager, "negotiation", &[], &json!({"bridgeId":bridge,"targetInstanceId":id})).await?;
            let interface = &negotiated["bridgeInterface"];
            let policy = s(interface, "policy");
            if s(&negotiated, "bridgeId") != bridge || !interface.is_object() {
                return Err(Error::new(502, "Translation negotiation binding mismatch"));
            }
            if policy != "NONE" && policy != "CERT_AUTH" {
                let kind = token_type(policy)
                    .ok_or_else(|| Error::new(502, "Invalid translation bridge policy"))?;
                let operation = array(requirement, "operations")[0].as_str().unwrap_or("").to_owned();
                tokens[policy] = json!({operation:{"tokenType":kind,"targetType":"SERVICE_DEF","token":bridge,"usageLimit":negotiated["tokenUsageLimit"],"expiresAt":negotiated["tokenExpiresAt"]}});
            }
            interfaces.push(interface.clone());
            warnings.insert("forcedInterfaceSecurityPolicy".to_owned());
        }
        for interface in array(&row, "interfaces").into_iter().filter(|_| bridge.is_none()) {
            let operations = array(requirement, "operations");
            let offered = &interface["properties"]["operations"];
            if operations.iter().any(|op| {
                !op.as_str().is_some_and(|op| {
                    offered.get(op).is_some()
                        || offered
                            .as_array()
                            .is_some_and(|a| a.contains(&Value::String(op.into())))
                })
            }) {
                continue;
            }
            let policy = s(&interface, "policy");
            if policy != "NONE" && policy != "CERT_AUTH" {
                let scopes = if operations.is_empty() {
                    vec![Value::String(String::new())]
                } else {
                    operations
                };
                let requests=scopes.iter().map(|scope|json!({"tokenVariant":policy,"targetType":"SERVICE_DEF","consumer":consumer,"consumerCloud":"LOCAL","provider":row["provider"]["name"],"target":requirement["serviceDefinition"],"scope":scope})).collect::<Vec<_>>();
                let response = app
                    .remote
                    .call(
                        "ConsumerAuthorization",
                        "POST",
                        "/consumerauthorization/authorization/mgmt/token/generate",
                        &json!({"list":requests}),
                    )
                    .await?;
                let generated = array(&response, "entries");
                if generated.len() != scopes.len() {
                    return Err(Error::new(502, "Token response count mismatch"));
                }
                let mut scoped = json!({});
                for (scope, token) in scopes.into_iter().zip(generated) {
                    if token["provider"] != row["provider"]["name"]
                        || token["consumer"] != consumer
                        || token["target"] != requirement["serviceDefinition"]
                        || s(&token, "token").is_empty()
                    {
                        return Err(Error::new(502, "Token binding mismatch"));
                    }
                    let key = scope
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .unwrap_or(s(requirement, "serviceDefinition"));
                    scoped[key] = json!({"tokenType":token["tokenType"],"targetType":token["targetType"],"token":token["token"],"usageLimit":token["usageLimit"],"expiresAt":token["expiresAt"]});
                }
                tokens[policy] = scoped;
            }
            interfaces.push(interface);
        }
        if interfaces.is_empty() {
            continue;
        }
        let until = if lock_duration > 0 {
            Value::String(expiry(lock_duration as u32))
        } else {
            Value::Null
        };
        results.push(json!({"serviceInstanceId":id,"cloudIdentitifer":"LOCAL","providerName":row["provider"]["name"],"serviceDefinitition":requirement["serviceDefinition"],"version":row["version"],"aliveUntil":row["expiresAt"],"exclusiveUntil":until,"metadata":row["metadata"],"interfaces":interfaces,"authorizationTokens":tokens}));
        if matchmaking {
            break;
        }
    }
    app.store.update(|db|{for result in &results{if table(db,"locks").values().any(|l|l["serviceInstanceId"]==result["serviceInstanceId"]&&s(l,"owner")!=consumer&&!expired(s(l,"expiresAt"))){return Err(Error::new(409,"Concurrent exclusive allocation"))}
if !result["exclusiveUntil"].is_null(){let id=s(result,"serviceInstanceId");table(db,"locks").insert(id.into(),json!({"serviceInstanceId":id,"owner":consumer,"expiresAt":result["exclusiveUntil"],"orchestrationJobId":job,"createdAt":now()}));}}Ok(())})?;
    if results.is_empty() && plant.is_none() && flag(req, "ALLOW_INTERCLOUD") {
        return intercloud(app, req, consumer).await;
    }
    Ok(json!({"results":results,"warnings":warnings}))
}
fn create_job(
    app: &App,
    requester: &str,
    target: &str,
    kind: &str,
    subscription: &str,
    definition: &str,
) -> Result<Value> {
    app.store.update(|db|{if table(db,"jobs").len()>10000{let mut completed=table(db,"jobs").iter().filter(|(_,r)|matches!(s(r,"status"),"DONE"|"ERROR")).map(|(k,r)|(s(r,"createdAt").to_owned(),k.clone())).collect::<Vec<_>>();completed.sort();for(_,key)in completed.into_iter().take(1000){table(db,"jobs").remove(&key);}
if table(db,"jobs").len()>10000{return Err(Error::unavailable("Job queue is full"))}}let id=uuid::Uuid::new_v4().to_string();let row=json!({"id":id,"type":kind,"status":"PENDING","requesterSystem":requester,"targetSystem":target,"serviceDefinition":definition,"subscriptionId":subscription,"createdAt":now(),"startedAt":null,"finishedAt":null,"message":null});table(db,"jobs").insert(id,row.clone());Ok(row)})
}
fn finish(app: &App, id: &str, result: &Result<Value>) -> Result<()> {
    app.store.update(|db| {
        let row = table(db, "jobs")
            .get_mut(id)
            .ok_or_else(|| Error::new(404, "Job not found"))?;
        row["status"] = if result.is_ok() { "DONE" } else { "ERROR" }.into();
        row["finishedAt"] = now().into();
        row["message"] = result.as_ref().err().map(|e| e.message.clone()).into();
        Ok(())
    })
}
fn notify_origin(req: &Value) -> Result<(String, String, String)> {
    if !s(req, "protocol").eq_ignore_ascii_case("HTTPS") {
        return Err(Error::bad("HTTPS notification required"));
    }
    let p = &req["properties"];
    required(p, &["address", "method", "path"])?;
    let port = if let Some(n) = p["port"].as_u64() {
        n
    } else {
        s(p, "port").parse().unwrap_or(0)
    };
    if port == 0
        || port > 65535
        || !matches!(s(p, "method"), "POST" | "PUT")
        || !s(p, "path").starts_with('/')
        || s(p, "path").starts_with("//")
        || s(p, "path").contains(['?', '#', '\r', '\n'])
        || s(p, "address").contains(['/', '@', '?', '#', '\r', '\n'])
    {
        return Err(Error::bad("Invalid callback properties"));
    }
    let address = s(p, "address");
    let host = if address.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{address}]")
    } else {
        address.into()
    };
    let origin = format!("https://{host}:{port}");
    url::Url::parse(&origin).map_err(|_| Error::bad("Invalid callback host"))?;
    Ok((origin, s(p, "method").into(), s(p, "path").into()))
}
fn subscribe(
    app: &App,
    db: &mut Database,
    req: &Value,
    caller: &Principal,
    management: bool,
) -> Result<(bool, Value)> {
    let target = if s(req, "targetSystemName").is_empty() {
        &caller.name
    } else {
        s(req, "targetSystemName")
    };
    if !valid_name(target) || !management && target != caller.name {
        return Err(Error::denied());
    }
    notify_origin(&req["notifyInterface"])?;
    if !req["orchestrationRequest"].is_object() {
        return Err(Error::bad("orchestrationRequest required"));
    }
    let duration = req["duration"].as_u64().unwrap_or(3600);
    if duration == 0 || duration > 31536000 {
        return Err(Error::bad("Invalid subscription duration"));
    }
    if app.config.role.ends_with("dynamic") {
        required(
            &req["orchestrationRequest"]["serviceRequirement"],
            &["serviceDefinition"],
        )?
    }
    let previous = table(db, "subscriptions")
        .values()
        .find(|r| {
            s(r, "ownerSystemName") == caller.name
                && s(r, "targetSystemName") == target
                && r["orchestrationRequest"]["serviceRequirement"]["serviceDefinition"]
                    == req["orchestrationRequest"]["serviceRequirement"]["serviceDefinition"]
        })
        .cloned();
    let id = previous
        .as_ref()
        .map(|r| s(r, "id").to_owned())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let row = json!({"id":id,"ownerSystemName":caller.name,"targetSystemName":target,"orchestrationRequest":req["orchestrationRequest"],"notifyInterface":req["notifyInterface"],"expiredAt":expiry(duration as u32),"createdAt":previous.as_ref().map(|r|r["createdAt"].clone()).unwrap_or_else(||now().into())});
    table(db, "subscriptions").insert(id, row.clone());
    Ok((previous.is_some(), row))
}
pub async fn handle(
    app: &App,
    method: &str,
    path: &str,
    params: &BTreeMap<String, String>,
    query: &Value,
    req: &Value,
    caller: &Principal,
) -> Result<(u16, Value)> {
    if path.starts_with(crate::plant_rules::PATH) {
        return crate::plant_rules::handle(app, method, req, caller);
    }
    let management = path.contains("/mgmt/");
    if path.ends_with("/pull") {
        let job = create_job(
            app,
            &caller.name,
            &caller.name,
            "PULL",
            "",
            s(&req["serviceRequirement"], "serviceDefinition"),
        )?;
        let result = pull(app, req, &caller.name, s(&job, "id")).await;
        finish(app, s(&job, "id"), &result)?;
        return Ok((200, result?));
    }
    if path.ends_with("/subscribe") && !path.ends_with("/unsubscribe") {
        return app.store.update(|db| {
            if management {
                let requests = array(req, "subscriptions");
                if requests.is_empty() || requests.len() > 1000 {
                    return Err(Error::bad("Nonempty bounded subscriptions required"));
                }
                let mut rows = Vec::new();
                for request in requests {
                    rows.push(subscribe(app, db, &request, caller, true)?.1)
                }
                Ok((200, json!({"entries":rows,"count":rows.len()})))
            } else {
                let (exists, row) = subscribe(app, db, req, caller, false)?;
                Ok((if exists { 200 } else { 201 }, row["id"].clone()))
            }
        });
    }
    if path.contains("/unsubscribe") {
        let ids = if management {
            array(query, "ids")
        } else {
            vec![params["id"].clone().into()]
        };
        if ids.is_empty() {
            return Err(Error::bad("ids required"));
        }
        return app.store.update(|db| {
            for id in ids {
                let id = id.as_str().ok_or_else(|| Error::bad("Invalid id"))?;
                if let Some(row) = table(db, "subscriptions").get(id)
                    && !management
                    && s(row, "ownerSystemName") != caller.name
                {
                    return Err(Error::denied());
                }
                table(db, "subscriptions").remove(id);
            }
            Ok((200, Value::Null))
        });
    }
    if path.ends_with("/trigger") {
        let ids = array(req, "subscriptionIds");
        if ids.is_empty() && array(req, "targetSystems").is_empty() {
            return Err(Error::bad("subscriptionIds or targetSystems required"));
        }
        let subscriptions = app
            .store
            .rows("subscriptions")
            .into_iter()
            .filter(|row| {
                !expired(s(row, "expiredAt"))
                    && (ids.is_empty() || ids.iter().any(|v| v == &row["id"]))
                    && selected(req, "targetSystems", s(row, "targetSystemName"))
            })
            .collect::<Vec<_>>();
        let mut jobs = Vec::new();
        for sub in subscriptions {
            jobs.push(create_job(
                app,
                &caller.name,
                s(&sub, "targetSystemName"),
                "PUSH",
                s(&sub, "id"),
                s(
                    &sub["orchestrationRequest"]["serviceRequirement"],
                    "serviceDefinition",
                ),
            )?);
        }
        return Ok((200, json!({"jobs":jobs})));
    }
    if path.contains("/simple-store/") {
        if path.ends_with("/query") {
            let rows = app
                .store
                .rows("simpleStore")
                .into_iter()
                .filter(|r| {
                    selected(req, "consumerNames", s(r, "consumer"))
                        && selected(req, "serviceDefinitions", s(r, "serviceDefinition"))
                        && selected(req, "ids", s(r, "id"))
                        && selected(req, "serviceInstanceIds", s(r, "serviceInstanceId"))
                        && req["minPriority"]
                            .as_u64()
                            .is_none_or(|p| r["priority"].as_u64().unwrap_or(0) >= p)
                        && req["maxPriority"]
                            .as_u64()
                            .is_none_or(|p| r["priority"].as_u64().unwrap_or(0) <= p)
                })
                .collect();
            return Ok((200, page(rows, req, "entries")?));
        }
        if method == "DELETE" {
            let ids = array(query, "uuids");
            if ids.is_empty() {
                return Err(Error::bad("uuids required"));
            }
            return app.store.update(|db| {
                for id in ids {
                    table(db, "simpleStore")
                        .remove(id.as_str().ok_or_else(|| Error::bad("Invalid id"))?);
                }
                Ok((200, Value::Null))
            });
        }
        let items = if method == "PUT" {
            req.as_object()
                .ok_or_else(|| Error::bad("Priority map required"))?
                .iter()
                .map(|(id, p)| json!({"id":id,"priority":p}))
                .collect()
        } else {
            array(req, "candidates")
        };
        if items.is_empty() {
            return Err(Error::bad("Nonempty store list required"));
        }
        return app.store.update(|db| {
            let mut rows=Vec::new();
            for item in items {
                let priority=item["priority"].as_u64().filter(|p|*p>0).ok_or_else(||Error::bad("Positive integer priority required"))?;
                if method=="PUT" {
                    let row=table(db,"simpleStore").get_mut(s(&item,"id")).ok_or_else(||Error::new(404,"Store candidate missing"))?;
                    row["priority"]=priority.into();row["updatedBy"]=caller.name.clone().into();row["updatedAt"]=now().into();rows.push(row.clone());
                } else {
                    required(&item,&["consumer","serviceInstanceId"])?;if !valid_name(s(&item,"consumer")){return Err(Error::bad("Invalid consumer"))}
                    let(_,definition,_)=parts(s(&item,"serviceInstanceId"))?;
                    if table(db,"simpleStore").values().any(|r|r["consumer"]==item["consumer"]&&r["serviceInstanceId"]==item["serviceInstanceId"]){return Err(Error::new(409,"Candidate already exists"))}
                    let id=uuid::Uuid::new_v4().to_string();let row=json!({"id":id,"consumer":item["consumer"],"serviceDefinition":definition,"serviceInstanceId":item["serviceInstanceId"],"priority":priority,"createdBy":caller.name,"updatedBy":null,"createdAt":now(),"updatedAt":null});table(db,"simpleStore").insert(id,row.clone());rows.push(row);
                }
            }
            let mut priorities=BTreeSet::new();for row in table(db,"simpleStore").values(){let key=format!("{}|{}|{}",s(row,"consumer"),s(row,"serviceDefinition"),row["priority"]);if !priorities.insert(key){return Err(Error::bad("Duplicate priority for consumer/service"))}}
            Ok((200,json!({"entries":rows,"count":rows.len()})))
        });
    }
    if path.contains("/lock/") {
        if method == "DELETE" {
            let owner = &params["owner"];
            return app.store.update(|db| {
                table(db, "locks").retain(|_, r| s(r, "owner") != owner);
                Ok((200, Value::Null))
            });
        }
        if path.ends_with("/create") {
            let requests = array(req, "locks");
            if requests.is_empty() {
                return Err(Error::bad("locks required"));
            }
            return app.store.update(|db| {
                let mut rows = Vec::new();
                for r in requests {
                    required(&r, &["owner", "serviceInstanceId", "expiresAt"])?;
                    parts(s(&r, "serviceInstanceId"))?;
                    if !valid_name(s(&r, "owner")) || expired(s(&r, "expiresAt")) {
                        return Err(Error::bad("Invalid owner/expiry"));
                    }
                    if table(db, "locks")
                        .get(s(&r, "serviceInstanceId"))
                        .is_some_and(|l| !expired(s(l, "expiresAt")) && l["owner"] != r["owner"])
                    {
                        return Err(Error::new(409, "Instance already locked"));
                    }
                    table(db, "locks").insert(s(&r, "serviceInstanceId").into(), r.clone());
                    rows.push(r);
                }
                Ok((201, json!({"entries":rows,"count":rows.len()})))
            });
        }
    }
    let kind = if path.contains("/lock/") {
        "locks"
    } else if path.contains("/history/") {
        "jobs"
    } else {
        "subscriptions"
    };
    let rows = app
        .store
        .rows(kind)
        .into_iter()
        .filter(|r| {
            (kind != "locks" || !expired(s(r, "expiresAt")))
                && (kind != "subscriptions" || !expired(s(r, "expiredAt")))
                && selected(req, "ids", s(r, "id"))
                && selected(req, "owners", s(r, "owner"))
                && selected(req, "targetSystemNames", s(r, "targetSystemName"))
        })
        .collect();
    Ok((200, page(rows, req, "entries")?))
}
pub async fn push_once(app: &App) -> Result<bool> {
    let selected = app.store.update(|db| {
        let candidate = table(db, "jobs")
            .iter()
            .find(|(_, r)| s(r, "type") == "PUSH" && s(r, "status") == "PENDING")
            .map(|(k, _)| k.clone());
        if let Some(id) = candidate {
            let row = table(db, "jobs").get_mut(&id).unwrap();
            row["status"] = "IN_PROGRESS".into();
            row["startedAt"] = now().into();
            Ok(Some(row.clone()))
        } else {
            Ok(None)
        }
    })?;
    let Some(job) = selected else {
        return Ok(false);
    };
    let id = s(&job, "id");
    let db = app.store.snapshot();
    let sub = db
        .get("subscriptions")
        .and_then(|m| m.get(s(&job, "subscriptionId")))
        .cloned();
    let result = async {
        let sub = sub.ok_or_else(|| Error::new(404, "Subscription removed"))?;
        if expired(s(&sub, "expiredAt")) {
            return Err(Error::bad("Subscription expired"));
        }
        let response = pull(
            app,
            &sub["orchestrationRequest"],
            s(&sub, "targetSystemName"),
            id,
        )
        .await?;
        let (origin, method, path) = notify_origin(&sub["notifyInterface"])?;
        app.remote
            .call_at(
                s(&sub, "targetSystemName"),
                &origin,
                &method,
                &path,
                &response,
            )
            .await?;
        Ok(response)
    }
    .await;
    finish(app, id, &result)?;
    Ok(true)
}
