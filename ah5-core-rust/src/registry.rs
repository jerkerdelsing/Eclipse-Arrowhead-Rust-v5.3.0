// SPDX-License-Identifier: EPL-2.0
use crate::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn version(v: &str) -> bool {
    let parts = v.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|s| {
            !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && s.parse::<u32>().is_ok()
        })
}
pub fn initialize(store: &Store) -> Result<()> {
    store.update(|db|{for(name,protocol,base)in[("generic_http","http","basePath"),("generic_https","https","basePath"),("generic_mqtt","tcp","baseTopic"),("generic_mqtts","ssl","baseTopic"),("generic_amqps","amqps","baseRoutingKey")]{table(db,"templates").entry(name.into()).or_insert_with(||json!({"name":name,"protocol":protocol,"propertyRequirements":[{"name":"accessAddresses","mandatory":true,"validator":"NOT_EMPTY_ADDRESS_LIST","validatorParams":[]},{"name":"accessPort","mandatory":true,"validator":"PORT","validatorParams":[]},{"name":base,"mandatory":true,"validator":null,"validatorParams":[]}],"createdAt":now(),"updatedAt":now()}));}Ok(())})
}
fn addresses(values: &Value) -> Result<Value> {
    let a = values
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or_else(|| Error::bad("Nonempty addresses required"))?;
    let mut out = Vec::new();
    for value in a {
        let raw = value
            .as_str()
            .filter(|s| !s.is_empty() && !s.contains(['/', '\r', '\n', ' ']))
            .ok_or_else(|| Error::bad("Invalid address"))?;
        let typ = if raw.parse::<std::net::Ipv4Addr>().is_ok() {
            "IPV4"
        } else if raw.parse::<std::net::Ipv6Addr>().is_ok() {
            "IPV6"
        } else {
            "HOSTNAME"
        };
        out.push(json!({"type":typ,"address":raw}));
    }
    Ok(Value::Array(out))
}
fn record(db: &mut Database, kind: &str, request: &Value, update: bool) -> Result<Value> {
    let name = s(request, "name");
    if !valid_name(name) {
        return Err(Error::bad("Invalid name"));
    }
    let old = table(db, kind).get(name).cloned();
    if update && old.is_none() {
        return Err(Error::new(404, "Record not found"));
    }
    let mut row = json!({"name":name,"metadata":request["metadata"],"addresses":addresses(&request["addresses"])? ,"createdAt":old.as_ref().map(|r|r["createdAt"].clone()).unwrap_or_else(||now().into()),"updatedAt":now()});
    if kind == "systems" {
        let v = s(request, "version");
        if !v.is_empty() && !version(v) {
            return Err(Error::bad("Invalid version"));
        }
        row["version"] = request["version"].clone();
        let device = s(request, "deviceName");
        row["device"] = if device.is_empty() {
            Value::Null
        } else {
            table(db, "devices")
                .get(device)
                .cloned()
                .ok_or_else(|| Error::bad("Device does not exist"))?
        };
    }
    table(db, kind).insert(name.into(), row.clone());
    Ok(row)
}
fn validate_interfaces(db: &mut Database, interfaces: &Value) -> Result<()> {
    let list = interfaces
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or_else(|| Error::bad("At least one interface required"))?;
    let mut names = std::collections::BTreeSet::new();
    for interface in list {
        let name = s(interface, "templateName");
        if !names.insert(name) {
            return Err(Error::bad("Duplicate interface template"));
        }
        let template = table(db, "templates")
            .get(name)
            .ok_or_else(|| Error::bad("Unknown interface template"))?;
        if interface["protocol"] != template["protocol"] {
            return Err(Error::bad("Interface protocol mismatch"));
        }
        if ![
            "NONE",
            "CERT_AUTH",
            "TIME_LIMITED_TOKEN_AUTH",
            "USAGE_LIMITED_TOKEN_AUTH",
            "BASE64_SELF_CONTAINED_TOKEN_AUTH",
            "RSA_SHA256_JSON_WEB_TOKEN_AUTH",
            "RSA_SHA512_JSON_WEB_TOKEN_AUTH",
            "TRANSLATION_BRIDGE_TOKEN_AUTH",
        ]
        .contains(&s(interface, "policy"))
        {
            return Err(Error::bad("Unknown interface policy"));
        }
        let properties = &interface["properties"];
        if !properties.is_object() {
            return Err(Error::bad("Interface properties must be an object"));
        }
        for r in array(template, "propertyRequirements") {
            let key = s(&r, "name");
            if r["mandatory"] == true && properties.get(key).is_none_or(Value::is_null) {
                return Err(Error::bad(format!("Missing property {key}")));
            }
            let value = &properties[key];
            if value.is_null() {
                continue;
            }
            match s(&r, "validator") {
                "" => {}
                "PORT" => {
                    if !value.as_u64().is_some_and(|p| (1..=65535).contains(&p)) {
                        return Err(Error::bad("Invalid interface port"));
                    }
                }
                "NOT_EMPTY_ADDRESS_LIST" => {
                    addresses(value)?;
                }
                _ => {
                    return Err(Error::unsupported(
                        "Custom template property validator is not implemented",
                    ));
                }
            }
        }
        if name == "generic_https" || name == "generic_http" {
            let path = s(properties, "basePath");
            if !path.starts_with('/') || path.contains(['?', '#', '\r', '\n']) {
                return Err(Error::bad("HTTP basePath must be an absolute path"));
            }
        }
    }
    Ok(())
}
fn instance(db: &mut Database, request: &Value, update: bool) -> Result<Value> {
    if update {
        let id = s(request, "instanceId");
        let mut row = table(db, "services")
            .get(id)
            .cloned()
            .ok_or_else(|| Error::new(404, "Service instance not found"))?;
        if !request["interfaces"].is_null() {
            validate_interfaces(db, &request["interfaces"])?;
            row["interfaces"] = request["interfaces"].clone();
        }
        for key in ["metadata", "expiresAt"] {
            if !request[key].is_null() {
                row[key] = request[key].clone();
            }
        }
        if !row["expiresAt"].is_null() && expired(s(&row, "expiresAt")) {
            return Err(Error::bad("expiresAt must be in the future"));
        }
        row["updatedAt"] = now().into();
        table(db, "services").insert(id.into(), row.clone());
        return Ok(row);
    }
    let provider = s(request, "systemName");
    let definition = s(request, "serviceDefinitionName");
    if definition == "serviceOrchestrationPlantManagement"
        && provider != "DynamicServiceOrchestration"
    {
        return Err(Error::denied());
    }
    let v = s(request, "version");
    if !valid_name(provider) || !valid_name(definition) || !version(v) {
        return Err(Error::bad("Invalid provider/service/version"));
    }
    let system = table(db, "systems")
        .get(provider)
        .cloned()
        .ok_or_else(|| Error::bad("Provider system is not registered"))?;
    validate_interfaces(db, &request["interfaces"])?;
    if !request["expiresAt"].is_null() && expired(s(request, "expiresAt")) {
        return Err(Error::bad("expiresAt must be in the future"));
    }
    if !request["metadata"]["allowExclusivity"].is_null()
        && s(&request["metadata"], "allowExclusivity")
            .parse::<u32>()
            .is_err()
    {
        return Err(Error::bad(
            "allowExclusivity must be a nonnegative integer string",
        ));
    }
    let def = table(db, "serviceDefinitions")
        .entry(definition.into())
        .or_insert_with(|| json!({"name":definition,"createdAt":now(),"updatedAt":now()}))
        .clone();
    let id = format!("{provider}|{definition}|{v}");
    let created = table(db, "services")
        .get(&id)
        .map(|r| r["createdAt"].clone())
        .unwrap_or_else(|| now().into());
    let row = json!({"instanceId":id,"provider":system,"serviceDefinition":def,"version":v,"expiresAt":request["expiresAt"],"metadata":request["metadata"],"interfaces":request["interfaces"],"createdAt":created,"updatedAt":now()});
    table(db, "services").insert(id, row.clone());
    Ok(row)
}
fn hydrated(db: &Database, row: &Value) -> Value {
    let mut row = row.clone();
    if let Some(system) = db
        .get("systems")
        .and_then(|m| m.get(s(&row["provider"], "name")))
    {
        row["provider"] = system.clone()
    }
    row
}
pub fn query(store: &Store, kind: &str, req: &Value) -> Result<Value> {
    let db = store.snapshot();
    let mut rows = Vec::new();
    for raw in db.get(kind).into_iter().flat_map(|m| m.values()) {
        let row = if kind == "services" {
            hydrated(&db, raw)
        } else {
            raw.clone()
        };
        let name = s(&row, "name");
        if !selected(req, "names", name)
            || !selected(req, "deviceNames", name) && kind == "devices"
            || !selected(req, "systemNames", name) && kind == "systems"
            || !selected(req, "templateNames", name) && kind == "templates"
        {
            continue;
        }
        if kind == "services" {
            if !selected(req, "providerNames", s(&row["provider"], "name"))
                || !selected(
                    req,
                    "serviceDefinitionNames",
                    s(&row["serviceDefinition"], "name"),
                )
                || !selected(req, "instanceIds", s(&row, "instanceId"))
                || !selected(req, "versions", s(&row, "version"))
            {
                continue;
            }
            if !row["expiresAt"].is_null() && expired(s(&row, "expiresAt")) {
                continue;
            }
            let mut interfaces = Vec::new();
            for interface in array(&row, "interfaces") {
                if !selected(req, "interfaceTemplateNames", s(&interface, "templateName"))
                    || !selected(req, "policies", s(&interface, "policy"))
                {
                    continue;
                }
                let requirements = array(req, "interfacePropertyRequirementsList");
                if !requirements.is_empty() {
                    let mut matches = false;
                    for r in requirements {
                        if metadata_match(&interface["properties"], &r)? {
                            matches = true;
                            break;
                        }
                    }
                    if !matches {
                        continue;
                    }
                }
                interfaces.push(interface);
            }
            if interfaces.is_empty() {
                continue;
            }
            let mut row = row;
            row["interfaces"] = interfaces.into();
            if !matches_metadata(&row["metadata"], req)? {
                continue;
            }
            rows.push(row);
        } else if matches_metadata(&row["metadata"], req)? {
            rows.push(row)
        }
    }
    page(rows, req, "entries")
}
fn matches_metadata(metadata: &Value, req: &Value) -> Result<bool> {
    let requirements = array(req, "metadataRequirementsList");
    if requirements.is_empty() {
        return Ok(true);
    }
    for requirement in requirements {
        if metadata_match(metadata, &requirement)? {
            return Ok(true);
        }
    }
    Ok(false)
}
fn remove(db: &mut Database, kind: &str, ids: &[Value]) -> Result<()> {
    for id in ids {
        let name = id
            .as_str()
            .ok_or_else(|| Error::bad("Names must be strings"))?;
        table(db, kind).remove(name);
        match kind {
            "systems" => {
                table(db, "services").retain(|_, r| s(&r["provider"], "name") != name);
            }
            "devices" => {
                let systems = table(db, "systems")
                    .values()
                    .filter(|r| s(&r["device"], "name") == name)
                    .map(|r| r["name"].clone())
                    .collect::<Vec<_>>();
                remove(db, "systems", &systems)?
            }
            "serviceDefinitions" => {
                table(db, "services").retain(|_, r| s(&r["serviceDefinition"], "name") != name);
            }
            "templates"
                if table(db, "services").values().any(|r| {
                    array(r, "interfaces")
                        .iter()
                        .any(|i| s(i, "templateName") == name)
                }) =>
            {
                return Err(Error::new(409, "Interface template is in use"));
            }
            _ => {}
        }
    }
    Ok(())
}
pub async fn handle(
    app: &App,
    method: &str,
    path: &str,
    params: &BTreeMap<String, String>,
    q: &Value,
    request: &Value,
    caller: &Principal,
) -> Result<(u16, Value)> {
    if path.contains("-discovery/") {
        let kind = if path.contains("device-discovery") {
            "devices"
        } else if path.contains("system-discovery") {
            "systems"
        } else {
            "services"
        };
        if path.ends_with("/lookup") {
            if caller.profile == "bootstrap" {
                let definitions = array(request, "serviceDefinitionNames");
                if kind != "services" || definitions.len() != 1 || definitions[0] != "identity" {
                    return Err(Error::new(401, "Identity token required"));
                }
            }
            let direct = caller.sysop || app.config.discovery_direct_access.contains(&caller.name);
            if kind != "services" && !direct {
                return Err(Error::denied());
            }
            // Apply authorization before pagination, so counts never disclose unauthorized entries.
            let mut lookup = request.clone();
            lookup["pagination"] = json!({"size":1000});
            let response = query(&app.store, kind, &lookup)?;
            if direct {
                return Ok((200, query(&app.store, kind, request)?));
            }
            if response["count"].as_u64().unwrap_or(0) > 1000 {
                return Err(Error::unavailable(
                    "Authorized lookup exceeds development-profile bound",
                ));
            }
            let mut rows = Vec::new();
            for row in array(&response, "entries") {
                let provider = s(&row["provider"], "name");
                let unrestricted = row["metadata"]["unrestrictedDiscovery"]
                    .as_bool()
                    .unwrap_or(false);
                let granted = if provider == caller.name || unrestricted {
                    true
                } else {
                    let response=app.remote.call("ConsumerAuthorization","POST","/consumerauthorization/authorization/mgmt/check",&json!({"list":[{"provider":provider,"consumer":caller.name,"cloud":"LOCAL","targetType":"SERVICE_DEF","target":row["serviceDefinition"]["name"]}]})).await?;
                    let answers = array(&response, "entries");
                    if answers.len() != 1
                        || answers[0]["provider"] != provider
                        || answers[0]["consumer"] != caller.name
                        || answers[0]["target"] != row["serviceDefinition"]["name"]
                    {
                        return Err(Error::new(502, "Authorization answer binding mismatch"));
                    }
                    answers[0]["granted"]
                        .as_bool()
                        .ok_or_else(|| Error::new(502, "Invalid authorization answer"))?
                };
                if granted {
                    rows.push(row)
                }
            }
            return Ok((200, page(rows, request, "entries")?));
        }
        if method == "DELETE" {
            let name = if kind == "systems" {
                caller.name.clone()
            } else if kind == "services" {
                params["instanceId"].clone()
            } else {
                params["name"].clone()
            };
            return app.store.update(|db| {
                if kind == "devices"
                    && !caller.sysop
                    && caller.name != "Onboarding"
                    && caller.name != "LocalCloudManager"
                {
                    return Err(Error::denied());
                }
                if kind == "services"
                    && let Some(row) = table(db, kind).get(&name)
                    && s(&row["provider"], "name") != caller.name
                    && !caller.sysop
                {
                    return Err(Error::denied());
                }
                remove(db, kind, &[name.into()])?;
                Ok((200, Value::Null))
            });
        }
        let mut req = request.clone();
        if kind == "systems" {
            req["name"] = caller.name.clone().into()
        }
        if kind == "services" {
            if !s(&req, "systemName").is_empty()
                && s(&req, "systemName") != caller.name
                && !caller.sysop
            {
                return Err(Error::denied());
            }
            req["systemName"] = caller.name.clone().into()
        }
        if kind == "devices"
            && !caller.sysop
            && caller.name != "Onboarding"
            && caller.name != "LocalCloudManager"
        {
            return Err(Error::denied());
        }
        return app.store.update(|db| {
            let key = if kind == "services" {
                format!(
                    "{}|{}|{}",
                    s(&req, "systemName"),
                    s(&req, "serviceDefinitionName"),
                    s(&req, "version")
                )
            } else {
                s(&req, "name").into()
            };
            let created = !table(db, kind).contains_key(&key);
            let row = if kind == "services" {
                instance(db, &req, false)?
            } else {
                record(db, kind, &req, false)?
            };
            Ok((if created { 201 } else { 200 }, row))
        });
    }
    let resource = path
        .strip_prefix("/serviceregistry/mgmt/")
        .ok_or_else(|| Error::new(404, "Unknown registry route"))?
        .split('/')
        .next()
        .unwrap_or("");
    let (kind, field) = match resource {
        "devices" => ("devices", "devices"),
        "systems" => ("systems", "systems"),
        "service-definitions" => ("serviceDefinitions", "serviceDefinitionNames"),
        "service-instances" => ("services", "instances"),
        "interface-templates" => ("templates", "interfaceTemplates"),
        _ => return Err(Error::new(404, "Unknown registry resource")),
    };
    if path.ends_with("/query") {
        return Ok((200, query(&app.store, kind, request)?));
    }
    if method == "DELETE" {
        let key = if kind == "services" {
            "serviceInstances"
        } else {
            "names"
        };
        let ids = array(q, key);
        if ids.is_empty() {
            return Err(Error::bad(format!("{key} required")));
        }
        return app.store.update(|db| {
            remove(db, kind, &ids)?;
            Ok((200, Value::Null))
        });
    }
    let items = array(request, field);
    if items.is_empty() || items.len() > 1000 {
        return Err(Error::bad(format!("{field} must contain 1..1000 items")));
    }
    app.store.update(|db| {
        let mut rows = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for item in items {
            let key = if kind == "serviceDefinitions" {
                item.as_str().unwrap_or("").to_owned()
            } else if kind == "services" {
                if method == "PUT" {
                    s(&item, "instanceId").into()
                } else {
                    format!(
                        "{}|{}|{}",
                        s(&item, "systemName"),
                        s(&item, "serviceDefinitionName"),
                        s(&item, "version")
                    )
                }
            } else {
                s(&item, "name").into()
            };
            if !seen.insert(key.clone()) {
                return Err(Error::bad("Duplicate resource"));
            }
            if method == "POST" && table(db, kind).contains_key(&key) {
                return Err(Error::new(409, "Resource already exists"));
            }
            let row = match kind {
                "devices" | "systems" => record(db, kind, &item, method == "PUT")?,
                "services" => instance(db, &item, method == "PUT")?,
                "serviceDefinitions" => {
                    if !valid_name(&key) {
                        return Err(Error::bad("Invalid service definition"));
                    }
                    let row = json!({"name":key,"createdAt":now(),"updatedAt":now()});
                    table(db, kind).insert(key, row.clone());
                    row
                }
                "templates" => {
                    required(&item, &["name", "protocol"])?;
                    let mut row = item.clone();
                    for rule in array(&item, "propertyRequirements") {
                        required(&rule, &["name"])?;
                        if !["", "PORT", "NOT_EMPTY_ADDRESS_LIST"].contains(&s(&rule, "validator"))
                        {
                            return Err(Error::unsupported(
                                "Custom property validator is not implemented",
                            ));
                        }
                    }
                    row["createdAt"] = now().into();
                    row["updatedAt"] = now().into();
                    table(db, kind).insert(key, row.clone());
                    row
                }
                _ => unreachable!(),
            };
            rows.push(row);
        }
        Ok((
            if method == "POST" { 201 } else { 200 },
            json!({"count":rows.len(),"entries":rows}),
        ))
    })
}
