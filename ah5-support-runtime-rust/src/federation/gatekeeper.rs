// SPDX-License-Identifier: EPL-2.0
use super::*;
use std::collections::BTreeSet;
fn target(app: &App, value: &Value) -> Result<String> {
    let (name, org) = if let Some(text) = value.as_str() {
        let mut p = text.split('|');
        (p.next().unwrap_or(""), p.next())
    } else {
        (s(value, "name"), value["operator"].as_str())
    };
    let expected = peer(app, name, "Gatekeeper")?;
    if org.is_some_and(|org| expected.split('.').nth(2) != Some(org)) || !trusted(app, &expected) {
        return Err(Error::denied());
    }
    Ok(name.into())
}
pub fn properties(instance: &Value) -> Option<&Value> {
    instance["interfaces"]
        .as_array()?
        .iter()
        .find(|v| {
            s(v, "templateName") == "generic_https"
                && s(v, "protocol").eq_ignore_ascii_case("https")
                && s(v, "policy") == "CERT_AUTH"
        })
        .map(|v| &v["properties"])
}
async fn instances(app: &App, definition: &str) -> Result<Vec<Value>> {
    if definition.is_empty() || definition.len() > 128 {
        return Err(Error::bad("serviceDefinition is required"));
    }
    let response=app.remote.call("ServiceRegistry","POST","/serviceregistry/service-discovery/lookup",&json!({"serviceDefinitionNames":[definition],"interfaceTemplateNames":["generic_https"]})).await?;
    Ok(array(&response, "entries"))
}
async fn authorized(
    app: &App,
    provider: &str,
    consumer: &str,
    foreign: &str,
    definition: &str,
    operations: &[Value],
) -> bool {
    if !valid_name(provider) || !valid_name(consumer) || definition.is_empty() {
        return false;
    }
    let mut checks=operations.iter().map(|operation|json!({"provider":provider,"consumer":consumer,"cloud":foreign,"targetType":"SERVICE_DEF","target":definition,"scope":operation})).collect::<Vec<_>>();
    if checks.is_empty() {
        checks.push(json!({"provider":provider,"consumer":consumer,"cloud":foreign,"targetType":"SERVICE_DEF","target":definition}));
    }
    let count = checks.len();
    let Ok(response) = app
        .remote
        .call(
            "ConsumerAuthorization",
            "POST",
            "/consumerauthorization/authorization/mgmt/check",
            &json!({"list":checks}),
        )
        .await
    else {
        return false;
    };
    let entries = array(&response, "entries");
    entries.len() == count && entries.iter().all(|v| v["granted"] == true)
}
pub async fn incoming(app: &App, sender: &str, message: &Value) -> Result<Value> {
    let parts = sender.split('.').collect::<Vec<_>>();
    let foreign = format!("{}|{}", parts[1], parts[2]);
    let consumer = s(message, "consumer");
    if !valid_name(consumer) {
        return Err(Error::bad("Invalid consumer"));
    }
    if s(message, "type") == "gsd-request" {
        let requirement = &message["serviceRequirement"];
        let definition = s(requirement, "serviceDefinition");
        let mut results = Vec::new();
        for instance in instances(app, definition).await? {
            let provider = s(&instance["provider"], "name");
            if let Some(properties) = properties(&instance) {
                let offered = properties["operations"]
                    .as_object()
                    .ok_or_else(|| Error::bad("Invalid provider operations"))?;
                let requested = array(requirement, "operations");
                if requested
                    .iter()
                    .any(|op| op.as_str().is_none_or(|op| !offered.contains_key(op)))
                {
                    continue;
                }
                if !s(requirement, "version").is_empty()
                    && requirement["version"] != instance["version"]
                {
                    continue;
                }
                if !metadata_match(&instance["metadata"], &requirement["metadataRequirements"])? {
                    continue;
                }
                if authorized(app, provider, consumer, &foreign, definition, &requested).await {
                    results.push(json!({"providerName":provider,"serviceDefinition":definition,"version":instance["version"],"metadata":instance["metadata"],"operations":offered.keys().collect::<Vec<_>>()}));
                }
            }
        }
        return Ok(json!({"cloud":cloud(app),"results":results}));
    }
    if s(message, "type") != "icn-request" {
        return Err(Error::bad("Unknown relay operation"));
    }
    let definition = s(message, "serviceDefinition");
    let provider = s(message, "providerName");
    for instance in instances(app, definition).await? {
        if s(&instance["provider"], "name") != provider {
            continue;
        }
        let Some(properties) = properties(&instance) else {
            continue;
        };
        let offered = properties["operations"]
            .as_object()
            .ok_or_else(|| Error::bad("Invalid provider operations"))?;
        let mut operations = array(message, "operations");
        if operations.is_empty() {
            operations = offered.keys().cloned().map(Value::String).collect();
        }
        if operations.is_empty()
            || operations
                .iter()
                .any(|v| v.as_str().is_none_or(|op| !offered.contains_key(op)))
            || !authorized(app, provider, consumer, &foreign, definition, &operations).await
        {
            return Ok(
                json!({"accepted":false,"reason":"Operation not offered or not authorized"}),
            );
        }
        let selected = operations
            .iter()
            .map(|v| {
                (
                    v.as_str().unwrap().to_owned(),
                    offered[v.as_str().unwrap()].clone(),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        let address = properties["accessAddresses"][0]
            .as_str()
            .ok_or_else(|| Error::bad("Provider address missing"))?;
        let session=app.remote.call("GateTunnel","POST","/gatetunnel/intercloud/provider",&json!({"consumer":consumer,"consumerCloud":foreign,"provider":provider,"serviceDefinition":definition,"peer":peer(app,parts[1],"GateTunnel")?,"target":{"address":address,"port":properties["accessPort"],"basePath":properties["basePath"],"operations":selected}})).await?;
        return Ok(
            json!({"accepted":true,"sessionId":session["sessionId"],"keyExchange":session["keyExchange"],"providerName":provider,"serviceDefinition":definition,"version":instance["version"],"metadata":instance["metadata"],"basePath":properties["basePath"],"operations":selected}),
        );
    }
    Ok(json!({"accepted":false,"reason":"Provider not found"}))
}
async fn gsd(app: &App, req: &Value, consumer: &str) -> Result<Value> {
    let requirement = req
        .get("serviceRequirement")
        .or_else(|| req.get("requestedService"))
        .ok_or_else(|| Error::bad("serviceRequirement required"))?;
    if s(requirement, "serviceDefinition").is_empty() {
        return Err(Error::bad("serviceRequirement.serviceDefinition required"));
    }
    // SOS-7: neighbours of another organisation only when foreignTargets lists them, also when named
    let mut targets = array(req, "targetClouds");
    if targets.is_empty() {
        targets = app
            .store
            .rows("clouds")
            .iter()
            .filter(|v| super::target_allowed(app, s(v, "name")))
            .map(|v| json!({"name":v["name"],"operator":v["operator"]}))
            .collect();
    }
    if targets.len() > 32 {
        return Err(Error::bad("At most 32 target clouds"));
    }
    let mut results = Vec::new();
    let mut refused = Vec::new();
    let mut failures = 0;
    for cloud in &targets {
        if let Ok(name) = target(app, cloud)
            && !super::target_allowed(app, &name)
        {
            let org = app
                .config
                .federation
                .as_ref()
                .and_then(|c| c.peers.get(&name).cloned())
                .unwrap_or_default();
            refused.push(json!(format!("{name}|{org}")));
            failures += 1;
            continue;
        }
        let response = async {
            let target = target(app, cloud)?;
            relay::request(
                app,
                &peer(app, &target, "Gatekeeper")?,
                json!({"type":"gsd-request","consumer":consumer,"serviceRequirement":requirement}),
            )
            .await
        }
        .await;
        match response {
            Ok(response) => {
                let expected = target(app, cloud)?;
                let cn = peer(app, &expected, "Gatekeeper")?;
                let p = cn.split('.').collect::<Vec<_>>();
                let id = format!("{}|{}", p[1], p[2]);
                if response["cloud"] != id {
                    failures += 1;
                    continue;
                }
                for mut result in array(&response, "results") {
                    result["cloud"] = id.clone().into();
                    results.push(result);
                }
            }
            Err(_) => failures += 1,
        }
    }
    Ok(
        json!({"results":results,"unsuccessfulRequests":failures,"queriedClouds":targets.len()-refused.len(),"refusedClouds":refused}),
    )
}
async fn icn(app: &App, req: &Value, consumer: &str) -> Result<Value> {
    let target = target(
        app,
        req.get("targetCloud")
            .or_else(|| req.get("providerCloud"))
            .ok_or_else(|| Error::bad("targetCloud required"))?,
    )?;
    required(req, &["providerName", "serviceDefinition"])?;
    if !super::target_allowed(app, &target) {
        return Err(Error::new(
            403,
            "Target cloud belongs to another organisation and is not allowed by this cloud's policy (foreignTargets)",
        ));
    }
    let response=relay::request(app,&peer(app,&target,"Gatekeeper")?,json!({"type":"icn-request","consumer":consumer,"providerName":req["providerName"],"serviceDefinition":req["serviceDefinition"],"operations":array(req,"operations")})).await?;
    if response["accepted"] != true {
        return Ok(json!({"negotiated":false,"targetCloud":target,"reason":response["reason"]}));
    }
    if !response["keyExchange"].is_object() {
        return Err(Error::new(502, "AH-GT-1 required; no profile downgrade"));
    }
    let cn = peer(app, &target, "GateTunnel")?;
    let p = cn.split('.').collect::<Vec<_>>();
    let provider_cloud = format!("{}|{}", p[1], p[2]);
    if response["providerName"] != req["providerName"]
        || response["serviceDefinition"] != req["serviceDefinition"]
    {
        return Err(Error::new(502, "Negotiated provider mismatch"));
    }
    let tunnel=app.remote.call("GateTunnel","POST","/gatetunnel/intercloud/consumer",&json!({"sessionId":response["sessionId"],"consumer":consumer,"providerCloud":provider_cloud,"provider":response["providerName"],"serviceDefinition":response["serviceDefinition"],"peer":cn,"keyExchange":response["keyExchange"]})).await?;
    Ok(
        json!({"negotiated":true,"providerCloud":provider_cloud,"providerName":response["providerName"],"serviceDefinition":response["serviceDefinition"],"version":response["version"],"metadata":response["metadata"],"sessionId":response["sessionId"],"interface":{"templateName":"generic_https","protocol":"https","policy":"CERT_AUTH","properties":{"accessAddresses":[tunnel["address"]],"accessPort":tunnel["port"],"basePath":response["basePath"],"operations":response["operations"]}}}),
    )
}
#[allow(clippy::too_many_arguments)]
pub async fn handle(
    app: &App,
    method: &str,
    path: &str,
    p: &BTreeMap<String, String>,
    _q: &Value,
    req: &Value,
    caller: &Principal,
) -> Result<(u16, Value)> {
    if path.ends_with("/mgmt/status") {
        return Ok((
            200,
            json!({"system":"Gatekeeper","implementation":"Rust","relay":relay::status(app)}),
        ));
    }
    if path.contains("/mgmt/") {
        let bucket = if path.contains("/relays") {
            "relays"
        } else {
            "clouds"
        };
        if method == "GET" {
            let rows = app.store.rows(bucket);
            return Ok((200, json!({"entries":rows,"count":rows.len()})));
        }
        if method == "DELETE" {
            let key = format!(
                "{}|{}",
                p.get("operator")
                    .ok_or_else(|| Error::bad("operator required"))?,
                p.get("name").ok_or_else(|| Error::bad("name required"))?
            );
            let removed = app
                .store
                .update(|db| Ok(table(db, bucket).remove(&key).is_some()))?;
            return Ok((if removed { 200 } else { 404 }, json!({"removed":removed})));
        }
        let values = req.as_array().cloned().unwrap_or_else(|| {
            req["list"]
                .as_array()
                .cloned()
                .unwrap_or_else(|| vec![req.clone()])
        });
        if values.is_empty() || values.len() > 100 {
            return Err(Error::bad("Expected 1..100 neighbours/relays"));
        }
        let mut seen = BTreeSet::new();
        for value in &values {
            required(value, &["name"])?;
            if !valid_name(s(value, "name")) {
                return Err(Error::bad("Invalid neighbour/relay name"));
            }
            if bucket == "clouds" {
                required(value, &["operator"])?;
                if !valid_name(s(value, "operator")) {
                    return Err(Error::bad("Invalid neighbour operator"));
                }
            } else if s(value, "address").is_empty()
                || value["port"].as_u64().is_none_or(|v| v == 0 || v > 65535)
                || value["secure"] == false
            {
                return Err(Error::bad("Secure relay address and port required"));
            }
            if !seen.insert(format!("{}|{}", s(value, "operator"), s(value, "name"))) {
                return Err(Error::bad("Duplicate neighbour/relay"));
            }
        }
        app.store.update(|db| {
            for value in values {
                let key = format!("{}|{}", s(&value, "operator"), s(&value, "name"));
                let mut value = value;
                value["updatedAt"] = now().into();
                table(db, bucket).insert(key, value);
            }
            Ok(())
        })?;
        let rows = app.store.rows(bucket);
        return Ok((201, json!({"entries":rows,"count":rows.len()})));
    }
    if app.config.federation.is_none() {
        return Err(Error::unsupported("Federation is not configured"));
    }
    if ![
        "Gatekeeper",
        "DynamicServiceOrchestration",
        "SimpleStoreServiceOrchestration",
        "LocalCloudManager",
        "Sysop",
    ]
    .contains(&caller.name.as_str())
    {
        return Err(Error::denied());
    }
    let consumer = req["consumerSystem"].as_str().unwrap_or(&caller.name);
    if !valid_name(consumer)
        || consumer != caller.name
            && ![
                "DynamicServiceOrchestration",
                "SimpleStoreServiceOrchestration",
                "LocalCloudManager",
                "Sysop",
            ]
            .contains(&caller.name.as_str())
    {
        return Err(Error::denied());
    }
    Ok((
        200,
        if path.ends_with("/init_icn") {
            icn(app, req, consumer).await?
        } else {
            gsd(app, req, consumer).await?
        },
    ))
}
