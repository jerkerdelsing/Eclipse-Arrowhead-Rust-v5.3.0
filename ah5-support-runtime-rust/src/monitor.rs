// SPDX-License-Identifier: EPL-2.0
use crate::*;
use arrowhead_messaging_rust as broker;
use axum::http::HeaderMap;
use broker::{amqprs, rumqttc};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

fn subscription(app: &App, name: &str) -> Value {
    row(app,"monitor-subscriptions",name).unwrap_or_else(|_|json!({"enabled":app.config.messaging.as_ref().is_some_and(|c|c.default_subscription=="all"),"revision":0,"observationTypes":["*"]}))
}
fn runtime(app: &App) -> Value {
    app.monitor_runtime
        .lock()
        .expect("monitor runtime mutex")
        .clone()
}
fn set_runtime(app: &App, key: &str, value: Value) {
    if let Ok(mut state) = app.monitor_runtime.lock() {
        state[key] = value;
    }
}
pub fn health(app: &App) -> Value {
    let mut status = runtime(app);
    status["status"] = json!(if status["amqp"]["connected"] == true
        && status["mqtt"]["connected"] == true
    {
        "running"
    } else {
        "degraded"
    });
    status["state"] = status["status"].clone();
    status["system"] = app.config.name.clone().into();
    status["implementation"] = json!("rust");
    status["version"] = json!("5.2.2");
    status["brokerWorkersImplemented"] = json!(true);
    status["amqpConnected"] = json!(status["amqp"]["connected"] == true);
    status["mqttConnected"] = json!(status["mqtt"]["connected"] == true);
    status["defaultSubscription"] = json!(
        app.config
            .messaging
            .as_ref()
            .map(|c| c.default_subscription.as_str())
            .unwrap_or("none")
    );
    status["subscriptions"] = json!(app.store.rows("monitor-subscriptions").len());
    status["storage"]=app.monitor_db.as_ref().and_then(|db|db.counts().ok()).unwrap_or_else(||json!({"stored":app.store.rows("observations").len(),"pending":app.store.rows("monitor-outbox").len()}));
    status["storage"]["retentionDays"] = json!(
        app.config
            .messaging
            .as_ref()
            .map(|c| c.retention_days)
            .unwrap_or(30)
    );
    status["certificateSecurity"] = json!("mutual X.509 TLS 1.2+");
    if status["registration"].is_null() {
        status["registration"] = json!({"registered":false,"instances":[],"error":null});
    }
    if status["lastError"].is_null() {
        status["lastError"] = Value::Null;
    }
    status["storage"]["lastPrunedAt"] = status["lastPrunedAt"].clone();
    status["storage"]["lastPruned"] = status.get("lastPruned").cloned().unwrap_or(json!(0));
    status
}
pub async fn reconcile(app: &App) -> Result<()> {
    let result=app.remote.call("DynamicServiceOrchestration","POST","/serviceorchestration/orchestration/pull",&json!({"serviceRequirement":{"serviceDefinition":"sysMonitor","versions":["1.0.0"],"interfaceTemplateNames":["generic_amqps"],"securityPolicies":["CERT_AUTH"]},"orchestrationFlags":{}})).await?;
    let config = app
        .config
        .messaging
        .as_ref()
        .ok_or_else(|| Error::unavailable("Broker configuration required"))?;
    let cloud = app.config.cloud_suffix.split('.').next().unwrap();
    let mut providers = serde_json::Map::new();
    for service in array(&result, "results") {
        let name = if s(&service, "providerName").is_empty() {
            s(&service["provider"], "name")
        } else {
            s(&service, "providerName")
        };
        if !valid_name(name) {
            continue;
        }
        for interface in array(&service, "interfaces") {
            let properties = &interface["properties"];
            let base = s(properties, "baseRoutingKey");
            let parts = base.split('.').collect::<Vec<_>>();
            if interface["templateName"] != "generic_amqps"
                || interface["policy"] != "CERT_AUTH"
                || parts.len() != 4
                || parts[0] != cloud
                || parts[1] != "sysmonitor"
                || parts[2] != name
                || parts[3].is_empty()
            {
                continue;
            }
            // Orchestration cannot redirect this credential to an unconfigured broker.
            if properties["accessPort"] != config.amqp_port
                || !array(properties, "accessAddresses")
                    .iter()
                    .any(|v| v == &config.amqp_host)
                || properties["exchange"] != "arrowhead"
            {
                continue;
            }
            let types = service["metadata"]["observationTypes"]
                .as_array()
                .cloned()
                .unwrap_or_else(|| array(properties, "operations"));
            if types.iter().any(|v| {
                v.as_str().is_none_or(|t| {
                    t.is_empty() || !t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                })
            }) {
                continue;
            }
            providers.insert(name.to_string(),json!({"providerSystem":name,"serviceInstanceId":service["serviceInstanceId"],"baseRoutingKey":base,"exchange":"arrowhead","observationTypes":types,"broker":config.amqp_host,"port":config.amqp_port,"orchestratedAt":now()}));
        }
    }
    set_runtime(
        app,
        "orchestration",
        json!({"providers":providers,"error":null,"intervalSeconds":30}),
    );
    Ok(())
}
fn providers(app: &App) -> Vec<Value> {
    runtime(app)["orchestration"]["providers"]
        .as_object()
        .map(|m| m.values().cloned().collect())
        .unwrap_or_default()
}
fn desired_bindings(app: &App) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for provider in providers(app) {
        let sub = subscription(app, s(&provider, "providerSystem"));
        if sub["enabled"] == false {
            continue;
        }
        let types = array(&sub, "observationTypes");
        for kind in array(&provider, "observationTypes") {
            if (types.is_empty() || types.iter().any(|v| v == "*" || v == &kind))
                && let Some(kind) = kind.as_str()
            {
                out.insert(format!("{}.{kind}", s(&provider, "baseRoutingKey")));
            }
        }
    }
    out
}
pub async fn worker(app: App, mut stop: tokio::sync::watch::Receiver<bool>) {
    let config = app.config.messaging.clone().expect("configured worker");
    let remote = app.remote.clone();
    let tls: broker::TlsFactory = Arc::new(move |expected| Ok(remote.tls_config(expected)?));
    loop {
        let result =
            tokio::select! {_=stop.changed()=>break,r=monitor_session(&app,&config,&tls)=>r};
        set_runtime(
            &app,
            "amqp",
            json!({"connected":false,"error":"Broker intake session unavailable"}),
        );
        set_runtime(&app, "mqtt", json!({"connected":false}));
        if result.is_err() {
            eprintln!("SysMonitor broker session unavailable; bounded retry")
        } else {
            continue;
        }
        tokio::select! {_=stop.changed()=>break,_=tokio::time::sleep(Duration::from_secs(2))=>{}}
    }
}
async fn monitor_session(
    app: &App,
    config: &broker::Config,
    tls: &broker::TlsFactory,
) -> broker::Result<()> {
    use amqprs::{callbacks::DefaultChannelCallback, channel::*};
    use rumqttc::{AsyncClient, Event, Incoming, MqttOptions, TlsConfiguration, Transport};
    let connection =
        broker::connect(config, "SysMonitor-intake", tls, &app.config.cloud_suffix).await?;
    let channel = connection.open_channel(None).await?;
    channel.register_callback(DefaultChannelCallback).await?;
    let queue = "SysMonitor.observations";
    channel
        .queue_declare(QueueDeclareArguments::new(queue).durable(true).finish())
        .await?;
    let mut options = MqttOptions::new(
        "SysMonitor-native",
        (config.mqtt_host.as_str(), config.mqtt_port),
    );
    options.set_keep_alive(30);
    options.set_max_packet_size(Some(1024 * 1024));
    options.set_transport(Transport::tls_with_config(TlsConfiguration::Rustls(
        Arc::new(tls(&format!(
            "{}.{}",
            config.mqtt_identity, app.config.cloud_suffix
        ))?),
    )));
    let (client, mut eventloop) = AsyncClient::builder(options).capacity(8).build();
    let event = tokio::time::timeout(Duration::from_secs(10), eventloop.poll()).await??;
    if !matches!(event, Event::Incoming(Incoming::ConnAck(_))) {
        return Err("MQTT handshake failed".into());
    }
    set_runtime(
        app,
        "mqtt",
        json!({"connected":true,"broker":config.mqtt_host,"port":config.mqtt_port,"output":format!("arrowhead/{}/sysmonitor/data",app.config.cloud_suffix.split('.').next().unwrap())}),
    );
    let opened = Instant::now();
    let mut last_orchestration = Instant::now() - Duration::from_secs(31);
    let mut applied = app
        .store
        .rows("monitor-bindings")
        .iter()
        .filter_map(|v| v["key"].as_str().map(String::from))
        .collect::<BTreeSet<_>>();
    while opened.elapsed() < Duration::from_secs(55) {
        if last_orchestration.elapsed() >= Duration::from_secs(30) {
            if reconcile(app).await.is_err() {
                set_runtime(
                    app,
                    "orchestration",
                    json!({"providers":{},"error":"Authorized provider orchestration failed"}),
                );
            }
            last_orchestration = Instant::now();
        }
        let desired = desired_bindings(app);
        if desired != applied {
            let intent = desired.union(&applied).cloned().collect::<Vec<_>>();
            app.store.update(|db| {
                let t = table(db, "monitor-bindings");
                for key in &intent {
                    t.insert(key.clone(), json!({"key":key}));
                }
                Ok(())
            })?;
            for key in applied.difference(&desired) {
                channel
                    .queue_unbind(QueueUnbindArguments::new(queue, "arrowhead", key))
                    .await?;
            }
            for key in desired.difference(&applied) {
                channel
                    .queue_bind(QueueBindArguments::new(queue, "arrowhead", key))
                    .await?;
            }
            app.store.update(|db| {
                let t = table(db, "monitor-bindings");
                t.clear();
                for key in &desired {
                    t.insert(key.clone(), json!({"key":key}));
                }
                Ok(())
            })?;
            applied = desired.clone();
        }
        set_runtime(
            app,
            "amqp",
            json!({"connected":true,"broker":config.amqp_host,"port":config.amqp_port,"exchange":"arrowhead","queue":queue,"bindings":applied}),
        );
        for _ in 0..50 {
            let message = tokio::time::timeout(
                Duration::from_secs(5),
                channel.basic_get(BasicGetArguments::new(queue)),
            )
            .await??;
            let Some((delivery, _, bytes)) = message else {
                break;
            };
            let key = delivery.routing_key();
            let result = if bytes.len() > 1024 * 1024 || !desired.contains(key.as_str()) {
                Err(Error::bad("Observation outside authorized binding"))
            } else {
                serde_json::from_slice::<Value>(&bytes)
                    .map_err(Error::from)
                    .and_then(|v| ingest(app, key.as_str(), &v))
            };
            match result {
                Ok(_) => {
                    channel
                        .basic_ack(BasicAckArguments::new(delivery.delivery_tag(), false))
                        .await?
                }
                Err(e) => {
                    channel
                        .basic_reject(BasicRejectArguments::new(
                            delivery.delivery_tag(),
                            e.code >= 500,
                        ))
                        .await?;
                    if e.code >= 500 {
                        return Err("Observation persistence unavailable".into());
                    }
                }
            }
        }
        let pending = if let Some(db) = &app.monitor_db {
            db.pending()?
        } else {
            app.store
                .snapshot()
                .get("monitor-outbox")
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .collect()
        };
        for (id, row) in pending.into_iter().take(50) {
            let mut observation = row["observation"].clone();
            observation["publishedTime"] = now().into();
            let notice = client
                .publish_tracked(
                    s(&row, "topic"),
                    serde_json::to_vec(&observation)?,
                    rumqttc::PublishOptions::at_least_once(),
                )
                .await?;
            let complete = notice.wait_completion_async();
            tokio::pin!(complete);
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {tokio::select! {
                    result=&mut complete=>return result.map_err(|e|Box::new(e) as Box<dyn std::error::Error+Send+Sync>),
                    event=eventloop.poll()=>{event?;}
                }}
            }).await??;
            if let Some(db) = &app.monitor_db {
                db.published(&id)?;
            } else {
                app.store.update(|db| {
                    table(db, "monitor-outbox").remove(&id);
                    Ok(())
                })?;
            }
        }
        if let Ok(event) = tokio::time::timeout(Duration::from_millis(100), eventloop.poll()).await
        {
            event?;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Bound retention by received time; unsent outbox rows remain durable.
        let cutoff = chrono::Utc::now() - chrono::Duration::days(config.retention_days.into());
        if let Some(db) = &app.monitor_db {
            db.prune(config.retention_days)?;
        } else if app.store.rows("observations").len() > 1000 {
            app.store.update(|db| {
                table(db, "observations").retain(|_, v| {
                    chrono::DateTime::parse_from_rfc3339(s(v, "receivedTime"))
                        .is_ok_and(|t| t >= cutoff)
                });
                Ok(())
            })?;
        }
    }
    let _ = client.disconnect().await;
    let _ = connection.close().await;
    Ok(())
}
pub fn ingest(app: &App, routing: &str, raw: &Value) -> Result<Value> {
    let parts = routing.split('.').collect::<Vec<_>>();
    let cloud = app.config.cloud_suffix.split('.').next().unwrap();
    if parts.len() != 5
        || parts[0] != cloud
        || parts[1] != "sysmonitor"
        || !valid_name(parts[2])
        || parts[3].is_empty()
        || parts[4].is_empty()
    {
        return Err(Error::bad("Invalid local telemetry routing key"));
    }
    let subscription = subscription(app, parts[2]);
    if subscription["enabled"] == false {
        return Err(Error::denied());
    }
    if !array(&subscription, "observationTypes")
        .iter()
        .any(|v| v == "*")
        && !selected(&subscription, "observationTypes", parts[4])
    {
        return Err(Error::denied());
    }
    if !(s(raw, "schemaVersion").is_empty()
        || s(raw, "schemaVersion").split('.').next() == Some("1"))
        || raw.get("value").is_none()
    {
        return Err(Error::bad("Schema major 1 and value required"));
    }
    for (key, index) in [
        ("providerSystem", 2),
        ("serviceInstance", 3),
        ("observationType", 4),
    ] {
        if !s(raw, key).is_empty() && s(raw, key) != parts[index] {
            return Err(Error::bad("Routing/payload identity mismatch"));
        }
    }
    let source = s(raw, "sourceTime");
    let time = chrono::DateTime::parse_from_rfc3339(source)
        .map_err(|_| Error::bad("Invalid sourceTime"))?;
    if !source.ends_with('Z') || time.offset().local_minus_utc() != 0 {
        return Err(Error::bad("sourceTime must be UTC Z"));
    }
    if parts[4] == "echo" && !["alive", "degraded", "failed"].contains(&s(&raw["value"], "status"))
    {
        return Err(Error::bad("Invalid echo status"));
    }
    if parts[4] == "power"
        && !["line", "battery", "harvesting"].contains(&s(&raw["value"], "supplyType"))
    {
        return Err(Error::bad("Invalid power supplyType"));
    }
    let observation_id = if s(raw, "observationId").is_empty() {
        digest(format!("{routing}\0{}", serde_json::to_string(raw)?))
    } else {
        s(raw, "observationId").to_owned()
    };
    if observation_id.len() > 256 {
        return Err(Error::bad("observationId too long"));
    }
    let row = json!({"schemaVersion":"1.0","observationId":observation_id,"providerSystem":parts[2],"serviceInstance":parts[3],"observationType":parts[4],"sourceTime":source,"receivedTime":now(),"publishedTime":null,"value":raw["value"],"unit":raw["unit"],"quality":raw.get("quality").cloned().unwrap_or(json!("good")),"pipeline":{"sysMonitor":app.config.name,"revision":1},"metadata":raw.get("metadata").cloned().unwrap_or(json!({}))});
    if let Some(db) = &app.monitor_db {
        return db.append(
            &row,
            &format!(
                "arrowhead/{cloud}/sysmonitor/data/{}/{}",
                parts[4], parts[2]
            ),
        );
    }
    app.store.update(|db|{let key=format!("{}:{observation_id}",parts[2]);if let Some(old)=table(db,"observations").get(&key){if old["sourceTime"]!=row["sourceTime"]||old["value"]!=row["value"]||old["observationType"]!=row["observationType"]||old["serviceInstance"]!=row["serviceInstance"]{return Err(Error::new(409,"Observation ID reused with different content"))}return Ok(old.clone())}let current=table(db,"monitor-subscriptions").get(parts[2]).unwrap_or(&subscription);if current["revision"]!=subscription["revision"]||current["enabled"]==false{return Err(Error::new(409,"Subscription changed during intake"))}
 if table(db,"observations").len()>=100000{return Err(Error::unavailable("History capacity reached; export/retention required"))}table(db,"observations").insert(key.clone(),row.clone());table(db,"monitor-outbox").insert(key,json!({"topic":format!("arrowhead/{cloud}/sysmonitor/data/{}/{}",parts[4],parts[2]),"status":"PENDING","observation":row}));Ok(row)})
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
    headers: &HeaderMap,
) -> Result<(u16, Value)> {
    if path == "/sysmonitor/observations" {
        return Ok((201, ingest(app, s(req, "routingKey"), &req["observation"])?));
    }
    if path.ends_with("/status") {
        return Ok((200, health(app)));
    }
    if path.ends_with("/reconcile") {
        reconcile(app).await?;
        return Ok((
            202,
            json!({"jobId":format!("reconcile-{}",uuid::Uuid::new_v4())}),
        ));
    }
    let default_subscription = app
        .config
        .messaging
        .as_ref()
        .map(|c| c.default_subscription.as_str())
        .unwrap_or("none");
    if path.ends_with("/providers") {
        let list = providers(app)
            .into_iter()
            .map(|mut v| {
                let sub = subscription(app, s(&v, "providerSystem"));
                v["subscription"] = row(app, "monitor-subscriptions", s(&v, "providerSystem"))
                    .unwrap_or(Value::Null);
                v["subscribedTypes"] = if sub["enabled"] == false {
                    json!([])
                } else if array(&sub, "observationTypes").iter().any(|v| v == "*") {
                    v["observationTypes"].clone()
                } else {
                    sub["observationTypes"].clone()
                };
                v["selection"] = json!(if v["subscription"].is_null() {
                    "default"
                } else if sub["enabled"] == false {
                    "subscription (disabled)"
                } else {
                    "subscription"
                });
                v
            })
            .collect::<Vec<_>>();
        return Ok((
            200,
            json!({"defaultSubscription":default_subscription,"list":list}),
        ));
    }
    if path.contains("/subscriptions") {
        if method == "GET" {
            let list = app
                .store
                .rows("monitor-subscriptions")
                .into_iter()
                .map(|mut sub| {
                    let found = providers(app)
                        .into_iter()
                        .find(|v| v["providerSystem"] == sub["providerSystem"]);
                    sub["providerFound"] = json!(found.is_some());
                    sub["unknownTypes"] = json!(
                        array(&sub, "observationTypes")
                            .iter()
                            .filter(|v| v.as_str() != Some("*")
                                && found
                                    .as_ref()
                                    .is_some_and(|p| !array(p, "observationTypes").contains(v)))
                            .cloned()
                            .collect::<Vec<_>>()
                    );
                    sub
                })
                .collect::<Vec<_>>();
            return Ok((
                200,
                json!({"defaultSubscription":default_subscription,"list":list}),
            ));
        }
        let provider = &p["providerSystem"];
        if !valid_name(provider) {
            return Err(Error::bad("Invalid providerSystem"));
        }
        let revision = headers
            .get("if-match")
            .map(|h| {
                h.to_str()
                    .map_err(|_| Error::bad("Invalid If-Match"))?
                    .trim_matches('"')
                    .parse::<u64>()
                    .map_err(|_| Error::bad("Invalid If-Match revision"))
            })
            .transpose()?;
        let value=app.store.update(|db|{
            let t=table(db,"monitor-subscriptions");
            let current=t.get(provider).map(|v|integer(v,"revision",0));
            if method=="DELETE" {
                t.remove(provider).ok_or_else(||Error::new(404,"Subscription not found"))?;
                return Ok(Value::Null)
            }
            if revision.is_some()&&revision!=current {return Err(Error::new(409,"Subscription revision conflict"))}
            if req.get("enabled").is_some()&&!req["enabled"].is_boolean(){return Err(Error::bad("enabled must be boolean"))}
            let types=req.get("observationTypes").cloned().unwrap_or(json!(["*"]));
            let types=types.as_array().ok_or_else(||Error::bad("observationTypes must be an array"))?;
            if types.is_empty()||types.iter().any(|v|v.as_str().is_none_or(|v|v.is_empty()||v.contains(['.','#','/'])||v=="*"&&types.len()!=1)){return Err(Error::bad("Valid observationTypes or [*] required"))}
            let types=types.iter().filter_map(Value::as_str).collect::<BTreeSet<_>>();
            let value=json!({"providerSystem":provider,"observationTypes":types,"enabled":req.get("enabled").cloned().unwrap_or(json!(true)),"revision":current.unwrap_or(0)+1,"updatedAt":now(),"updatedBy":_caller.name});
            t.insert(provider.clone(),value.clone());Ok(value)
        })?;
        return Ok((if method == "DELETE" { 204 } else { 200 }, value));
    }
    let system = p.get("systemName");
    if let Some(db) = &app.monitor_db {
        let retention_days = app
            .config
            .messaging
            .as_ref()
            .map(|c| c.retention_days)
            .unwrap_or(30);
        let Some(system) = system else {
            return Ok((
                200,
                json!({"systems":db.systems()?,"retentionDays":retention_days}),
            ));
        };
        if path.ends_with("/latest") {
            let latest = db.latest(system)?;
            if latest.as_object().is_none_or(|v| v.is_empty()) {
                return Err(Error::new(404, "No observations"));
            }
            return Ok((200, json!({"systemName":system,"latest":latest})));
        }
        let types = array(q, "type")
            .iter()
            .filter_map(Value::as_str)
            .flat_map(|v| v.split(','))
            .filter(|v| !v.is_empty())
            .map(String::from)
            .collect::<Vec<_>>();
        let from = data::first(q, "from");
        let to = data::first(q, "to");
        for bound in [from, to] {
            if !bound.is_empty() {
                chrono::DateTime::parse_from_rfc3339(bound)
                    .map_err(|_| Error::bad("Invalid time bound"))?;
            }
        }
        let observations = db.history(system, &types, from, to, data::count(q, 100)?)?;
        return Ok((
            200,
            json!({"systemName":system,"count":observations.len(),"observations":observations}),
        ));
    }

    let mut rows = app
        .store
        .rows("observations")
        .into_iter()
        .filter(|r| system.is_none_or(|name| s(r, "providerSystem") == name))
        .collect::<Vec<_>>();
    if system.is_none() {
        let systems = rows
            .iter()
            .map(|r| s(r, "providerSystem").to_owned())
            .collect::<BTreeSet<_>>();
        return Ok((200, json!({"systems":systems})));
    }
    let mut filtered = Vec::new();
    for row in rows.drain(..) {
        if !data::first(q, "type").is_empty()
            && data::first(q, "type") != s(&row, "observationType")
        {
            continue;
        }
        if data::in_range(
            s(&row, "sourceTime"),
            data::first(q, "from"),
            data::first(q, "to"),
        )? {
            filtered.push(row)
        }
    }
    filtered.sort_by(|a, b| {
        s(b, "sourceTime")
            .cmp(s(a, "sourceTime"))
            .then(s(a, "observationId").cmp(s(b, "observationId")))
    });
    if path.ends_with("/latest") {
        return Ok((
            200,
            filtered
                .into_iter()
                .next()
                .ok_or_else(|| Error::new(404, "No observations"))?,
        ));
    }
    filtered.truncate(data::count(q, 100)?);
    Ok((200, json!({"count":filtered.len(),"entries":filtered})))
}
