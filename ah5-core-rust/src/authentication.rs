// SPDX-License-Identifier: EPL-2.0
use crate::{config::secret, *};
use serde_json::{Value, json};

pub fn hash_password(credentials: &Value) -> Result<String> {
    let password = s(credentials, "password");
    if password.is_empty()
        || password.len() > 72
        || credentials.as_object().map_or(0, |o| o.len()) != 1
    {
        return Err(Error::bad(
            "PASSWORD credentials require only a password (1..72 bytes)",
        ));
    }
    bcrypt::hash(password, 10).map_err(|_| Error::new(500, "Password hashing failed"))
}
pub fn password_matches(password: &str, hash: &str) -> bool {
    password.len() <= 72 && bcrypt::verify(password, hash).unwrap_or(false)
}
pub fn verify(store: &Store, token: &str) -> Value {
    let db = store.snapshot();
    if let Some(session) = db.get("sessions").and_then(|m| m.get(&digest(token)))
        && !expired(s(session, "expirationTime"))
        && let Some(identity) = db
            .get("identities")
            .and_then(|m| m.get(s(session, "systemName")))
    {
        return json!({"verified":true,"systemName":session["systemName"],"sysop":identity["sysop"],"loginTime":session["loginTime"],"expirationTime":session["expirationTime"]});
    }
    json!({"verified":false,"systemName":null,"sysop":null,"loginTime":null,"expirationTime":null})
}
fn public(row: &Value) -> Value {
    let mut out = row.clone();
    if let Some(m) = out.as_object_mut() {
        m.remove("credentialHash");
    }
    out
}
fn close_sessions(db: &mut Database, name: &str) {
    table(db, "sessions").retain(|_, row| s(row, "systemName") != name);
}
pub fn bootstrap(app: &App) -> Result<()> {
    if app.config.role != "authentication" || !app.store.rows("identities").is_empty() {
        return Ok(());
    }
    let mut seeds = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for seed in &app.config.bootstrap_identities {
        if !valid_name(&seed.system_name) || !names.insert(seed.system_name.clone()) {
            return Err(Error::bad("Invalid or duplicate bootstrap identity"));
        }
        let password = String::from_utf8(secret(&seed.password_file)?)
            .map_err(|_| Error::bad("Invalid bootstrap password encoding"))?;
        seeds.push((
            seed,
            hash_password(&json!({"password":password.trim_end_matches(['\r','\n'])}))?,
        ));
    }
    app.store.update(|db|{if !table(db,"identities").is_empty(){return Ok(())}for(seed,hash)in seeds{table(db,"identities").insert(seed.system_name.clone(),json!({"systemName":seed.system_name,"authenticationMethod":"PASSWORD","credentialHash":hash,"sysop":seed.sysop,"createdBy":"bootstrap","createdAt":now(),"updatedBy":null,"updatedAt":null}));}Ok(())})
}
pub fn handle(
    app: &App,
    method: &str,
    path: &str,
    params: &std::collections::BTreeMap<String, String>,
    query: &Value,
    request: &Value,
    caller: &Principal,
) -> Result<(u16, Value)> {
    if path.starts_with("/authentication/identity/verify/") {
        return Ok((200, verify(&app.store, &params["token"])));
    }
    if path.starts_with("/authentication/identity/") {
        let name = s(request, "systemName");
        if name != caller.name || !valid_name(name) {
            return Err(Error::new(
                401,
                "Credentials must match certificate identity",
            ));
        }
        let current = app.store.snapshot();
        let row = current
            .get("identities")
            .and_then(|t| t.get(name))
            .ok_or_else(|| Error::new(401, "Invalid credentials"))?;
        if !password_matches(
            s(&request["credentials"], "password"),
            s(row, "credentialHash"),
        ) {
            return Err(Error::new(401, "Invalid credentials"));
        }
        let expected_hash = s(row, "credentialHash").to_owned();
        let new_hash = if path.ends_with("/change") {
            Some(hash_password(&request["newCredentials"])?)
        } else {
            None
        };
        let token = uuid::Uuid::new_v4().to_string();
        let expiration = expiry(app.config.identity_ttl);
        return app.store.update(|db| {
            let row = table(db, "identities")
                .get_mut(name)
                .ok_or_else(|| Error::new(401, "Identity changed"))?;
            if s(row, "credentialHash") != expected_hash {
                return Err(Error::new(401, "Credentials changed"));
            }
            if let Some(hash) = new_hash {
                row["credentialHash"] = hash.into();
                row["updatedBy"] = caller.name.clone().into();
                row["updatedAt"] = now().into();
            }
            close_sessions(db, name);
            if path.ends_with("/login") {
                table(db, "sessions").insert(
                    digest(&token),
                    json!({"systemName":name,"loginTime":now(),"expirationTime":expiration}),
                );
                Ok((200, json!({"token":token,"expirationTime":expiration})))
            } else {
                Ok((200, Value::Null))
            }
        });
    }
    if path.ends_with("/identities") && matches!(method, "POST" | "PUT") {
        let items = array(request, "identities");
        if items.is_empty() || items.len() > 100 {
            return Err(Error::bad("identities must contain 1..100 items"));
        }
        if method == "POST" && s(request, "authenticationMethod") != "PASSWORD" {
            return Err(Error::bad("Only PASSWORD authentication supported"));
        }
        let mut prepared = Vec::new();
        for item in items {
            let hash = if method == "POST" || !item["credentials"].is_null() {
                Some(hash_password(&item["credentials"])?)
            } else {
                None
            };
            prepared.push((item, hash));
        }
        return app.store.update(|db|{let mut seen=std::collections::BTreeSet::new();let mut rows=Vec::new();for(item,hash)in prepared{let name=s(&item,"systemName");if !valid_name(name)||!seen.insert(name.to_string()){return Err(Error::bad("Invalid or duplicate system name"))}let existing=table(db,"identities").get(name).cloned();if method=="POST"&&existing.is_some(){return Err(Error::new(409,"Identity already exists"))}
if method=="PUT"&&existing.is_none(){return Err(Error::new(404,"Identity not found"))}let mut row=existing.unwrap_or_else(||json!({"systemName":name,"authenticationMethod":"PASSWORD","sysop":false,"createdBy":caller.name,"createdAt":now(),"updatedBy":null,"updatedAt":null}));if let Some(hash)=hash{row["credentialHash"]=hash.into()}
if !item["sysop"].is_null(){row["sysop"]=item["sysop"].as_bool().ok_or_else(||Error::bad("sysop must be boolean"))?.into()}
if method=="PUT"{row["updatedBy"]=caller.name.clone().into();row["updatedAt"]=now().into();close_sessions(db,name);}table(db,"identities").insert(name.into(),row.clone());rows.push(public(&row));}Ok((if method=="POST"{201}else{200},json!({"count":rows.len(),"identities":rows})))});
    }
    if method == "DELETE" {
        let names = array(query, "names");
        if names.is_empty() {
            return Err(Error::bad("names required"));
        }
        return app.store.update(|db| {
            for name in names {
                let name = name.as_str().ok_or_else(|| Error::bad("Invalid names"))?;
                if path.ends_with("/identities") {
                    table(db, "identities").remove(name);
                }
                close_sessions(db, name);
            }
            Ok((200, Value::Null))
        });
    }
    let sessions = path.ends_with("/sessions");
    let db = app.store.snapshot();
    let table_name = if sessions { "sessions" } else { "identities" };
    let mut rows = Vec::new();
    for row in db.get(table_name).into_iter().flat_map(|m| m.values()) {
        let name = s(row, "systemName");
        if !name
            .to_lowercase()
            .contains(&s(request, "namePart").to_lowercase())
        {
            continue;
        }
        if sessions && expired(s(row, "expirationTime")) {
            continue;
        }
        if !request["isSysop"].is_null() && request["isSysop"] != row["sysop"] {
            continue;
        }
        if !s(request, "createdBy").is_empty() && request["createdBy"] != row["createdBy"] {
            continue;
        }
        if let Some(expected) = request["hasSession"].as_bool() {
            let has = db.get("sessions").is_some_and(|m| {
                m.values()
                    .any(|r| s(r, "systemName") == name && !expired(s(r, "expirationTime")))
            });
            if has != expected {
                continue;
            }
        }
        rows.push(if sessions { row.clone() } else { public(row) });
    }
    Ok((200, page(rows, request, table_name)?))
}
