// SPDX-License-Identifier: EPL-2.0
use crate::*;
use std::collections::BTreeMap;
fn callback(app: &App, subscriber: &str, raw: &str) -> Result<(String, String)> {
    let url = url::Url::parse(raw).map_err(|_| Error::bad("Invalid notifyUri"))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::bad(
            "Callback requires HTTPS without credentials or fragment",
        ));
    }
    let origin = format!("{}/", url.origin().ascii_serialization());
    if app.config.upstreams.get(subscriber) != Some(&origin) {
        return Err(Error::denied());
    }
    let mut path = url.path().to_string();
    if let Some(q) = url.query() {
        path.push('?');
        path.push_str(q)
    }
    Ok((origin, path))
}
fn validate(app: &App, req: &Value, subscriber: &str) -> Result<()> {
    required(req, &["eventType", "notifyUri"])?;
    callback(app, subscriber, s(req, "notifyUri"))?;
    for key in ["startsAt", "expiresAt"] {
        if !s(req, key).is_empty() && chrono::DateTime::parse_from_rfc3339(s(req, key)).is_err() {
            return Err(Error::bad("Invalid subscription timestamp"));
        }
    }
    if !s(req, "expiresAt").is_empty() && expired(s(req, "expiresAt")) {
        return Err(Error::bad("Subscription expired"));
    }
    if !s(req, "startsAt").is_empty()
        && !s(req, "expiresAt").is_empty()
        && chrono::DateTime::parse_from_rfc3339(s(req, "startsAt")).unwrap()
            >= chrono::DateTime::parse_from_rfc3339(s(req, "expiresAt")).unwrap()
    {
        return Err(Error::bad("Subscription time interval invalid"));
    }
    metadata_match(&json!({}), &req["metadataFilter"])?;
    Ok(())
}
async fn event_authorized(app: &App, consumer: &str, publisher: &str, event: &str) -> Result<bool> {
    let result=app.remote.call("ConsumerAuthorization","POST","/consumerauthorization/authorization/mgmt/check",&json!({"list":[{"provider":publisher,"consumer":consumer,"cloud":"LOCAL","targetType":"EVENT_TYPE","target":event}]})).await?;
    let entries = array(&result, "entries");
    Ok(entries.len() == 1 && entries[0]["granted"] == true)
}
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
    if path.ends_with("/publish") {
        required(req, &["eventType"])?;
        if !req["payload"].is_string() {
            return Err(Error::bad("payload must be a string"));
        }
        let timestamp = if s(req, "timestamp").is_empty() {
            now()
        } else {
            chrono::DateTime::parse_from_rfc3339(s(req, "timestamp"))
                .map_err(|_| Error::bad("Invalid timestamp"))?;
            s(req, "timestamp").into()
        };
        let mut pending = Vec::new();
        for subscription in app.store.rows("event-subscriptions") {
            if s(&subscription, "eventType") != s(req, "eventType")
                || !s(&subscription, "expiresAt").is_empty()
                    && expired(s(&subscription, "expiresAt"))
                || !s(&subscription, "startsAt").is_empty()
                    && chrono::DateTime::parse_from_rfc3339(s(&subscription, "startsAt"))
                        .is_ok_and(|t| t > chrono::Utc::now())
            {
                continue;
            }
            if subscription["matchMetadata"] == true
                && !metadata_match(&req["metadata"], &subscription["metadataFilter"])?
            {
                continue;
            }
            if !event_authorized(
                app,
                s(&subscription, "subscriberSystemName"),
                &caller.name,
                s(req, "eventType"),
            )
            .await?
            {
                continue;
            }
            let (origin, path) = callback(
                app,
                s(&subscription, "subscriberSystemName"),
                s(&subscription, "notifyUri"),
            )?;
            pending.push(json!({"id":id(),"subscriptionId":subscription["id"],"provider":subscription["subscriberSystemName"],"publisher":caller.name,"origin":origin,"path":path,"status":"PENDING","attempts":0,"createdAt":now(),"body":{"eventType":req["eventType"],"payload":req["payload"],"metadata":req["metadata"],"timestamp":timestamp,"sourceSystemName":caller.name}}));
        }
        let count = app.store.update(|db| {
            if table(db, "event-outbox")
                .values()
                .filter(|r| s(r, "status") == "PENDING")
                .count()
                + pending.len()
                > 10000
            {
                return Err(Error::unavailable("Outbox capacity reached"));
            }
            let mut accepted = 0;
            for item in pending {
                let sub = s(&item, "subscriptionId");
                if table(db, "event-subscriptions").contains_key(sub) {
                    table(db, "event-outbox").insert(s(&item, "id").into(), item);
                    accepted += 1
                }
            }
            Ok(accepted)
        })?;
        return Ok((
            202,
            json!({"matchedSubscriptions":count,"acceptedDeliveries":count}),
        ));
    }
    let key = p.get("subscriptionId").cloned();
    if method == "GET" {
        return Ok((
            200,
            page(app.store.rows("event-subscriptions"), q, "entries")?,
        ));
    }
    if method == "DELETE" {
        let key = key.unwrap();
        app.store.update(|db| {
            let old = table(db, "event-subscriptions")
                .get(&key)
                .ok_or_else(|| Error::new(404, "Subscription not found"))?;
            if !path.contains("/management/") {
                own(caller, s(old, "subscriberSystemName"))?
            }
            table(db, "event-subscriptions").remove(&key);
            for delivery in table(db, "event-outbox").values_mut() {
                if s(delivery, "subscriptionId") == key && s(delivery, "status") == "PENDING" {
                    delivery["status"] = "CANCELLED".into()
                }
            }
            Ok(())
        })?;
        return Ok((200, Value::Null));
    }
    let subscriber = if method == "PUT" {
        s(
            &row(app, "event-subscriptions", key.as_deref().unwrap())?,
            "subscriberSystemName",
        )
        .to_string()
    } else {
        caller.name.clone()
    };
    validate(app, req, &subscriber)?;
    let record=app.store.update(|db|{let id=key.unwrap_or_else(id);let t=table(db,"event-subscriptions");if method=="PUT"&&!t.contains_key(&id){return Err(Error::new(404,"Subscription not found"))}let value=json!({"id":id,"subscriberSystemName":subscriber,"eventType":req["eventType"],"notifyUri":req["notifyUri"],"matchMetadata":req["matchMetadata"]==true,"metadataFilter":req["metadataFilter"],"startsAt":req["startsAt"],"expiresAt":req["expiresAt"],"createdAt":t.get(&id).map(|r|r["createdAt"].clone()).unwrap_or_else(||now().into()),"updatedAt":now()});t.insert(id,value.clone());Ok(value)})?;
    Ok((if method == "PUT" { 200 } else { 201 }, record))
}
pub async fn deliver_once(app: &App) -> Result<()> {
    for delivery in app
        .store
        .rows("event-outbox")
        .into_iter()
        .filter(|r| s(r, "status") == "PENDING")
        .take(16)
    {
        let current = row(app, "event-subscriptions", s(&delivery, "subscriptionId"));
        let result = async {
            let sub = current?;
            if !s(&sub, "expiresAt").is_empty() && expired(s(&sub, "expiresAt")) {
                return Err(Error::denied());
            }
            if !event_authorized(
                app,
                s(&delivery, "provider"),
                s(&delivery, "publisher"),
                s(&delivery["body"], "eventType"),
            )
            .await?
            {
                return Err(Error::denied());
            }
            app.remote
                .call_at(
                    s(&delivery, "provider"),
                    s(&delivery, "origin"),
                    "POST",
                    s(&delivery, "path"),
                    &delivery["body"],
                )
                .await
        }
        .await;
        app.store.update(|db| {
            if let Some(r) = table(db, "event-outbox").get_mut(s(&delivery, "id")) {
                if s(r, "status") != "PENDING" {
                    return Ok(());
                }
                let attempts = integer(r, "attempts", 0) + 1;
                r["attempts"] = attempts.into();
                r["updatedAt"] = now().into();
                r["status"] = if result.is_ok() {
                    "DELIVERED"
                } else if attempts >= 3 {
                    "FAILED"
                } else {
                    "PENDING"
                }
                .into();
            }
            Ok(())
        })?;
    }
    Ok(())
}
