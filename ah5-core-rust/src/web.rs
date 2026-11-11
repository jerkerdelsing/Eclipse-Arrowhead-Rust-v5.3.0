// SPDX-License-Identifier: EPL-2.0
use crate::*;
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
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
        if decoded.contains(['/', '\0', '\r', '\n']) {
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
fn query(raw: Option<&str>) -> Value {
    let mut out = json!({});
    for (k, v) in url::form_urlencoded::parse(raw.unwrap_or("").as_bytes()) {
        if out.get(k.as_ref()).is_none() {
            out[k.as_ref()] = json!([])
        }
        for value in v.split(',') {
            out[k.as_ref()]
                .as_array_mut()
                .unwrap()
                .push(value.to_string().into());
        }
    }
    out
}
async fn dispatch(State(app): State<App>, request: Request) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_owned();
    let available = contracts::routes(&app.config.role);
    let matched = available.into_iter().find_map(|r| {
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
    let result=async{
        let (route,params)=matched.ok_or_else(||Error::new(404,"No such core interface operation"))?;
        let peer=request.extensions().get::<Principal>().cloned().ok_or_else(||Error::new(401,"Verified TLS peer required"))?;
        let authorization=request.headers().get("authorization").and_then(|h|h.to_str().ok());
        // A system has no token until it can discover Authentication. Mark only
        // that tokenless lookup as bootstrap; Registry validates its body before
        // returning the unrestricted identity offer.
        let bootstrap_lookup=app.config.role=="serviceregistry"
            && route.service=="serviceDiscovery"&&route.operation=="lookup"
            && authorization.is_none();
        let caller=if route.access=="certificate"{peer}else if bootstrap_lookup{
            Principal{profile:"bootstrap".into(),..peer}
        }else{security::authenticate(&app,peer,authorization).await?};
        // the bootstrap lookup comes before a system can be checked by name; every other requester is checked (J17)
        if !bootstrap_lookup{security::check_blacklist(&app,&caller).await?;}
        let pde_read=app.config.role=="serviceregistry"&&caller.name=="PlantDescriptionEngine"&&method=="POST"&&["system-query","service-query"].contains(&route.operation.as_str());
        let pde_rules=route.service=="serviceOrchestrationPlantManagement"&&caller.name=="PlantDescriptionEngine";
        if route.access=="management"&&!caller.sysop&&!pde_read&&!pde_rules&&!app.config.management_whitelist.contains(&caller.name){
            let check_only=app.config.role=="consumer-authorization"&&route.operation=="check-policies"&&["Gatekeeper","GateTunnel"].contains(&caller.name.as_str());
            if !check_only||!authorization::granted(&app,json!({"provider":"ConsumerAuthorization","consumer":caller.name,"cloud":"LOCAL","targetType":"SERVICE_DEF","target":"authorizationManagement","scope":"check-policies"})).await? {return Err(Error::denied());}
        }
        if route.service=="echo"{return Ok((StatusCode::OK,"Got it!").into_response())}
        let q=query(request.uri().query());let bytes=to_bytes(request.into_body(),1024*1024).await.map_err(|_|Error::new(413,"Request body exceeds limit"))?;
        let req:Value=if bytes.is_empty(){json!({})}else{let v:Value=serde_json::from_slice(&bytes)?;if !v.is_object(){return Err(Error::bad("Expected one JSON object"))}v};
        let(status,value)=if route.service=="generalManagement"{if route.operation=="get-config"{let mut settings=json!({"implementation":"Rust","version":"5.2.2","system.name":app.config.name,"server.ssl.enabled":"true","server.ssl.client-auth":"need","persistence":"atomic-json"});let keys=array(&q,"keys");if !keys.is_empty(){settings.as_object_mut().unwrap().retain(|k,_|keys.iter().any(|v|v==k));}(200,json!({"map":settings}))}else{(200,page(app.store.rows("logs"),&req,"entries")?)}}
        else{match app.config.role.as_str(){"authentication"=>{let permit=app.identity_workers.clone().try_acquire_owned().map_err(|_|Error::unavailable("Identity worker capacity reached"))?;let app=app.clone();let method=method.clone();let path=path.clone();let caller=caller.clone();let params=params.clone();let q=q.clone();let req=req.clone();tokio::task::spawn_blocking(move||{let _permit=permit;authentication::handle(&app,&method,&path,&params,&q,&req,&caller)}).await.map_err(|_|Error::new(500,"Identity worker failed"))??},"serviceregistry"=>registry::handle(&app,&method,&path,&params,&q,&req,&caller).await?,"consumer-authorization"=>authorization::handle(&app,&method,&path,&params,&q,&req,&caller).await?,_=>orchestration::handle(&app,&method,&path,&params,&q,&req,&caller).await?}};
        let status=StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let text=path.ends_with("/public-key")||path.ends_with("/encryption-key")&&method=="POST"&&!path.contains("/mgmt/")||path.ends_with("/subscribe")&&!path.contains("/mgmt/");
        Ok(if text{(status,value.as_str().unwrap_or("").to_owned()).into_response()}else if value.is_null(){status.into_response()}else{(status,Json(value)).into_response()})
    }.await;
    let mut response = match result {
        Ok(response) => response,
        Err(error) => {
            let status =
                StatusCode::from_u16(error.code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status,Json(json!({"errorMessage":error.message,"errorCode":error.code,"exceptionType":status.canonical_reason(),"origin":origin,"timestamp":now()}))).into_response()
        }
    };
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert("x-content-type-options", "nosniff".parse().unwrap());
    // No credential, path parameter, token or body is written to the audit record.
    let _=app.store.update(|db|{let logs=table(db,"logs");if logs.len()>=1000&& let Some(key)=logs.keys().next().cloned(){logs.remove(&key);}let id=format!("{}-{}",now(),uuid::Uuid::new_v4());logs.insert(id,json!({"entryDate":now(),"severity":if response.status().is_success(){"INFO"}else{"WARN"},"logger":"rust-core","message":format!("{origin}: {}",response.status().as_u16())}));Ok(())});
    response
}
pub async fn register(app: &App) -> Result<()> {
    let request = json!({"version":"5.2.2","addresses":[app.config.advertise_address],"metadata":{"implementation":"Rust"}});
    if app.config.role == "serviceregistry" {
        let caller = Principal {
            name: app.config.name.clone(),
            sysop: true,
            profile: "sy".into(),
        };
        registry::handle(
            app,
            "POST",
            "/serviceregistry/system-discovery/register",
            &BTreeMap::new(),
            &json!({}),
            &request,
            &caller,
        )
        .await?;
        for service in contracts::services(&app.config.role) {
            let request = service_request(app, &service);
            registry::handle(
                app,
                "POST",
                "/serviceregistry/service-discovery/register",
                &BTreeMap::new(),
                &json!({}),
                &request,
                &caller,
            )
            .await?;
        }
    } else {
        app.remote
            .call_certificate(
                "ServiceRegistry",
                "POST",
                "/serviceregistry/system-discovery/register",
                &request,
            )
            .await?;
        for service in contracts::services(&app.config.role) {
            app.remote
                .call_certificate(
                    "ServiceRegistry",
                    "POST",
                    "/serviceregistry/service-discovery/register",
                    &service_request(app, &service),
                )
                .await?;
        }
    }
    Ok(())
}
fn service_request(app: &App, service: &contracts::Service) -> Value {
    let mut metadata = json!({"implementation":"Rust"});
    // Bootstrap services, discoverable under restricted discovery as in the Java
    // reference: identity and orchestration before a token or provider choice,
    // authorization and tokens for other systems' management filters and checks.
    if matches!(
        service.definition.as_str(),
        "identity"
            | "serviceOrchestration"
            | "authorization"
            | "authorizationToken"
            | "deviceDiscovery"
            | "systemDiscovery"
            | "serviceDiscovery"
    ) {
        metadata["unrestrictedDiscovery"] = json!(true);
    }
    let mut operations = service.operations.clone();
    let mut base_path = service.base_path.clone();
    if service.definition == "identity" {
        base_path = "/authentication/identity".into();
        for operation in operations.values_mut() {
            if let Some(path) = operation["path"]
                .as_str()
                .and_then(|p| p.strip_prefix("/identity"))
            {
                operation["path"] = json!(path);
            }
        }
    }
    json!({"systemName":app.config.name,"serviceDefinitionName":service.definition,"version":"1.0.0","metadata":metadata,"interfaces":[{"templateName":"generic_https","protocol":"https","policy":"CERT_AUTH","properties":{"accessAddresses":[app.config.advertise_address],"accessPort":app.config.advertise_port,"basePath":base_path,"operations":operations}}]})
}
pub async fn background(app: App, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut broker_jobs = tokio::task::JoinSet::new();
    if app.config.messaging.is_some() {
        broker_jobs.spawn(crate::telemetry::publisher(app.clone(), shutdown.clone()));
    }
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
    let mut ticks = 0u64;
    loop {
        tokio::select! {_=shutdown.changed()=>break,_=interval.tick()=>{if app.config.register&&ticks.is_multiple_of(15)&& let Err(e)=register(&app).await{eprintln!("{} registration unavailable ({}: {})",app.config.name,e.code,e.message)}
        if app.config.role.starts_with("serviceorchestration")&& let Err(e)=orchestration::push_once(&app).await{eprintln!("Push worker unavailable ({})",e.code)}ticks+=1;}}
    }
}
