// SPDX-License-Identifier: EPL-2.0
use crate::*;
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::collections::BTreeMap;
pub fn router(app: App) -> Router {
    Router::new().fallback(dispatch).with_state(app)
}
pub fn parameters(pattern: &str, path: &str) -> Option<BTreeMap<String, String>> {
    let a = pattern.split('/').collect::<Vec<_>>();
    let b = path.split('/').collect::<Vec<_>>();
    if a.len() != b.len() {
        return None;
    }
    let mut out = BTreeMap::new();
    for (a, b) in a.into_iter().zip(b) {
        let decoded = percent_encoding::percent_decode_str(b).decode_utf8().ok()?;
        if decoded.contains(['/', '\0', '\r', '\n', '\\']) || decoded == "." || decoded == ".." {
            return None;
        }
        if a.starts_with('{') && a.ends_with('}') {
            if decoded.is_empty() {
                return None;
            }
            out.insert(a[1..a.len() - 1].into(), decoded.into_owned());
        } else if a != decoded {
            return None;
        }
    }
    Some(out)
}
pub fn query(raw: Option<&str>) -> Value {
    let mut out = json!({});
    for (k, v) in url::form_urlencoded::parse(raw.unwrap_or("").as_bytes()) {
        if out.get(k.as_ref()).is_none() {
            out[k.as_ref()] = json!([])
        }
        for v in v.split(',') {
            out[k.as_ref()]
                .as_array_mut()
                .unwrap()
                .push(v.to_string().into())
        }
    }
    out
}
async fn dispatch(State(app): State<App>, request: Request) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_owned();
    let matched = contracts::routes(&app.config.role)
        .into_iter()
        .find_map(|r| {
            if r.method == method {
                parameters(&r.path, &path).map(|p| (r, p))
            } else {
                None
            }
        });
    let origin = matched
        .as_ref()
        .map(|(r, _)| format!("{} {}", r.method, r.path))
        .unwrap_or_else(|| format!("{method} <unmatched>"));
    let result=async {
 let(route,params)=matched.ok_or_else(||Error::new(404,"No such support interface operation"))?;
 let peer=request.extensions().get::<Principal>().cloned().ok_or_else(||Error::new(401,"Verified TLS peer required"))?;
 // Device credentials of the onboarding procedure reach only the onboarding steps (never echo or management).
 if peer.profile==onboarding::DEVICE&&(app.config.role!="onboarding"||route.service!="onboarding"||route.operation=="echo"){return Err(Error::denied())}
 let peer_certificate=request.extensions().get::<onboarding::PeerCertificate>().cloned();
 let caller=if route.access=="certificate"{peer}else{security::authenticate(&app,peer,request.headers().get("authorization").and_then(|h|h.to_str().ok())).await?};
 if route.access=="management"&&!caller.sysop&&!app.config.management_whitelist.contains(&caller.name){return Err(Error::denied())}
 if route.service=="echo"||route.operation=="echo" {return Ok((StatusCode::OK,"Got it!").into_response())}
 if route.access=="identity" {authorize(&app,&caller,&route.service,&route.operation).await?}
 if !route.implemented {return Err(Error::unsupported("Operation not yet ported; no external side effect performed"))}
 let q=query(request.uri().query());let headers=request.headers().clone();let bytes=to_bytes(request.into_body(),1024*1024).await.map_err(|_|Error::new(413,"Request exceeds one MiB"))?;
 let req=if bytes.is_empty(){json!({})}else{serde_json::from_slice::<Value>(&bytes)?};
 if !req.is_object()&&!(req.is_array()&&((app.config.role=="datamanager"&&method=="PUT")||(app.config.role=="gatekeeper"&&method=="POST"&&path.contains("/mgmt/"))||(app.config.role=="gatetunnel"&&path.ends_with("/close_sessions")))){return Err(Error::bad("Expected JSON object"))}
 let (status,value)=if route.service=="generalManagement" {if route.operation=="get-config"{(200,json!({"map":{"implementation":"Rust","version":"5.4.0","system.name":app.config.name,"server.ssl.client-auth":"need","persistence":"atomic-json","qualification":"development"}}))}else{(200,page(app.store.rows("logs"),&req,"entries")?)}}
 else if app.config.role=="onboarding"{onboarding::handle(&app,&method,&path,&params,&q,&req,&caller,peer_certificate.as_ref()).await?}
 else{handle(&app,&method,&path,&params,&q,&req,&caller,&headers).await?};
 if app.config.role=="certificateauthority" && (method=="DELETE" || path.ends_with("/revocations")) {crate::ca::publish_crl(&app)?;}
 let status=StatusCode::from_u16(status).map_err(|_|Error::new(500,"Invalid status"))?;
 if path.contains("/config/raw/"){use base64::Engine;let data=base64::engine::general_purpose::STANDARD.decode(s(&value,"data")).map_err(|_|Error::new(500,"Corrupt configuration"))?;let content=s(&value,"contentType").parse::<axum::http::HeaderValue>().map_err(|_|Error::new(500,"Invalid stored MIME type"))?;return Ok((status,[(axum::http::header::CONTENT_TYPE,content)],data).into_response())}
 if app.config.role=="certificateauthority"&&path.ends_with("/crl") {return Ok((status,[(axum::http::header::CONTENT_TYPE,"application/pkix-crl")],s(&value,"pem").to_owned()).into_response())}
 let mut response=if value.is_null(){status.into_response()}else{(status,Json(value.clone())).into_response()};
 if app.config.role=="sysmonitor"&&let Some(rev)=value["revision"].as_u64(){response.headers_mut().insert("etag",format!("\"{rev}\"").parse().unwrap());}
 Ok(response)
 }.await;
    let mut response = match result {
        Ok(r) => r,
        Err(e) => {
            let status = StatusCode::from_u16(e.code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status,Json(json!({"errorMessage":e.message,"errorCode":e.code,"exceptionType":status.canonical_reason(),"origin":origin,"timestamp":now()}))).into_response()
        }
    };
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert("x-content-type-options", "nosniff".parse().unwrap());
    let _=app.store.update(|db|{let logs=table(db,"logs");if logs.len()>=1000&&let Some(k)=logs.keys().next().cloned(){logs.remove(&k);}logs.insert(format!("{}-{}",now(),id()),json!({"entryDate":now(),"severity":if response.status().is_success(){"INFO"}else{"WARN"},"logger":"rust-support","message":format!("{origin}: {}",response.status().as_u16())}));Ok(())});
    response
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
    headers: &HeaderMap,
) -> Result<(u16, Value)> {
    match app.config.role.as_str() {
        "blacklist" | "configuration" | "timemanager" | "aigym" => {
            basic::handle(app, method, path, p, q, req, caller).await
        }
        "datamanager" => {
            // Only the verified local GateTunnel may assert a remote consumer.
            // Normal callers cannot use this header to bypass historian ownership.
            if let Some(remote) = headers.get("x-arrowhead-remote-consumer") {
                let parts = remote
                    .to_str()
                    .map_err(|_| Error::denied())?
                    .split('|')
                    .collect::<Vec<_>>();
                if caller.name != "GateTunnel"
                    || parts.len() != 3
                    || parts.iter().any(|v| !valid_name(v))
                {
                    return Err(Error::denied());
                }
                let effective = Principal {
                    name: parts[0].into(),
                    sysop: false,
                    profile: "sy".into(),
                };
                data::handle(app, method, path, p, q, req, &effective).await
            } else {
                data::handle(app, method, path, p, q, req, caller).await
            }
        }
        "certificateauthority" => {
            let permit = app
                .identity_workers
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::unavailable("CA worker capacity reached"))?;
            let app = app.clone();
            let method = method.to_string();
            let path = path.to_string();
            let p = p.clone();
            let q = q.clone();
            let req = req.clone();
            let caller = caller.clone();
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                ca::handle(&app, &method, &path, &p, &q, &req, &caller)
            })
            .await
            .map_err(|_| Error::new(500, "CA worker failed"))?
        }
        "eventhandler" => events::handle(app, method, path, p, q, req, caller).await,
        "deviceqosevaluator" => qos::handle(app, method, path, p, q, req, caller).await,
        "plantdescriptionengine" => plant::handle(app, method, path, p, q, req, caller).await,
        "choreographer" => choreography::handle(app, method, path, p, q, req, caller).await,
        "sysmonitor" => monitor::handle(app, method, path, p, q, req, caller, headers).await,
        "onboarding" => onboarding::handle(app, method, path, p, q, req, caller, None).await, // dispatch passes the TLS peer certificate; direct callers have none
        "translationmanager" => translation::handle(app, method, path, p, q, req, caller).await,
        _ => federation::handle(app, method, path, p, q, req, caller).await,
    }
}
pub async fn register(app: &App) -> Result<()> {
    app.remote.call("ServiceRegistry","POST","/serviceregistry/system-discovery/register",&json!({"version":"5.4.0","addresses":[app.config.advertise_address],"metadata":{"implementation":"Rust","qualification":"development"}})).await?;
    let mut registered_ids = Vec::new();
    for service in contracts::services(&app.config.role) {
        let mut properties = json!({"accessAddresses":[app.config.advertise_address],"accessPort":app.config.advertise_port,"basePath":service.base_path,"operations":service.operations});
        if let Some(models) = contracts::data_models(&app.config.role, &service.definition) {
            properties["dataModels"] = models;
        }
        let registered=app.remote.call("ServiceRegistry","POST","/serviceregistry/service-discovery/register",&json!({"systemName":app.config.name,"serviceDefinitionName":service.definition,"version":if matches!(app.config.role.as_str(),"gatekeeper"|"gatetunnel"){"5.2.2"}else{"1.0.0"},"metadata":if service.definition=="blacklistDiscovery"{json!({"implementation":"Rust","qualification":"development","unrestrictedDiscovery":true})}else{json!({"implementation":"Rust","qualification":"development"})},"interfaces":[{"templateName":"generic_https","protocol":"https","policy":"CERT_AUTH","properties":properties}]})).await?;
        registered_ids.push(registered["instanceId"].clone());
    }
    if app.config.role == "sysmonitor"
        && let Some(config) = &app.config.messaging
    {
        app.remote.call("ServiceRegistry","POST","/serviceregistry/service-discovery/register",&json!({"serviceDefinitionName":"sysMonitorData","version":"1.0.0","metadata":{"schemaVersion":"1.0","implementation":"rust"},"interfaces":[{"templateName":"generic_mqtts","protocol":"ssl","policy":"CERT_AUTH","properties":{"accessAddresses":[config.mqtt_host],"accessPort":config.mqtt_port,"baseTopic":format!("arrowhead/{}/sysmonitor/data",app.config.cloud_suffix.split('.').next().unwrap()),"operations":["subscribe"]}}]})).await?;
    }
    if let Ok(mut runtime) = app.monitor_runtime.lock() {
        runtime["registration"] =
            json!({"registered":true,"instances":registered_ids,"error":null});
    }
    Ok(())
}
pub async fn background(app: App, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut broker_jobs = tokio::task::JoinSet::new();
    if app.config.federation.is_some() {
        broker_jobs.spawn(crate::federation::relay::worker(
            app.clone(),
            shutdown.clone(),
        ));
    }
    if app.config.messaging.is_some() {
        if app.config.role == "aigym" {
            broker_jobs.spawn(crate::aigym_mqtt::worker(app.clone(), shutdown.clone()));
        }
        broker_jobs.spawn(crate::telemetry::publisher(app.clone(), shutdown.clone()));
        if app.config.role == "sysmonitor" {
            broker_jobs.spawn(crate::monitor::worker(app.clone(), shutdown.clone()));
        }
    }
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
    let mut ticks = 0u64;
    let mut last_plants = Value::Null;
    loop {
        tokio::select! {_=shutdown.changed()=>break,_=interval.tick()=>{
        if app.config.register&&ticks.is_multiple_of(15)&&let Err(e)=register(&app).await{eprintln!("{} registration unavailable ({})",app.config.name,e.code)}
        if app.config.role=="plantdescriptionengine" {let plants=json!(app.store.snapshot().get("plants"));if plants!=last_plants||ticks.is_multiple_of(15){last_plants=plants;crate::plant_sync::tick(&app).await;}}
        if app.config.role=="certificateauthority"&&ticks.is_multiple_of(30)&&let Err(e)=crate::ca::refresh_crl(&app){eprintln!("CRL publication unavailable ({})",e.code)}
        if app.config.role=="gatetunnel" {crate::federation::tunnel::cleanup(&app);}
        if app.config.role=="eventhandler"&&let Err(e)=events::deliver_once(&app).await{eprintln!("Event outbox unavailable ({})",e.code)}ticks+=1;
        }}
    }
    if app.config.role == "gatetunnel" {
        crate::federation::tunnel::shutdown(&app);
    }
}
