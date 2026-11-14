// SPDX-License-Identifier: EPL-2.0
//! Native test application: random-number provider and historian consumer.
use crate::*;
use arrowhead_messaging_rust as broker;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;
const NAME: &str = "RandomDataProducer";
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub name: String,
    pub cloud_suffix: String,
    pub listen: String,
    pub certificate: String,
    pub private_key: String,
    pub ca: String,
    pub crl_file: String,
    pub password_file: String,
    pub state: String,
    pub authentication_url: String,
    pub registry_url: String,
    pub authorization_url: String,
    pub orchestrator_url: String,
    pub advertise_address: String,
    pub advertise_port: u16,
    pub interval_seconds: u64,
    pub intercloud_enabled: bool,
    pub messaging: broker::Config,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.name != NAME
            || self.cloud_suffix.split('.').count() != 4
            || !self.cloud_suffix.ends_with(".arrowhead.eu")
            || self.listen.parse::<std::net::SocketAddr>().is_err()
            || !(1..=3600).contains(&self.interval_seconds)
            || self.advertise_address.is_empty()
            || self.advertise_port == 0
            || self.crl_file.is_empty()
        {
            return Err(Error::bad("Invalid producer identity/listener/interval"));
        }
        self.messaging.validate().map_err(Error::bad)?;
        for raw in [
            &self.authentication_url,
            &self.registry_url,
            &self.authorization_url,
            &self.orchestrator_url,
        ] {
            let u = url::Url::parse(raw).map_err(|_| Error::bad("Invalid producer authority"))?;
            if u.scheme() != "https"
                || u.host_str().is_none()
                || !u.username().is_empty()
                || u.password().is_some()
                || u.path() != "/"
                || u.query().is_some()
                || u.fragment().is_some()
            {
                return Err(Error::bad("Producer requires bare HTTPS authorities"));
            }
        }
        Ok(())
    }
}
#[derive(Clone)]
struct Producer {
    config: Arc<Config>,
    store: Arc<Store>,
    remote: Arc<security::Remote>,
}
fn random_value() -> Result<u64> {
    loop {
        let mut bytes = [0; 8];
        openssl::rand::rand_bytes(&mut bytes)?;
        let value = u64::from_le_bytes(bytes);
        let limit = u64::MAX - u64::MAX % 101;
        if value < limit {
            return Ok(value % 101);
        }
    }
}
impl Producer {
    fn status(&self) -> Value {
        self.store.rows("producer-status").into_iter().next().unwrap_or_else(||json!({"status":"starting","lastValue":null,"lastPublishedAt":null,"publishedCount":0,"lastError":null,"orchestration":{"provider":null,"serviceInstanceId":null,"endpoint":null,"resolvedAt":null},"registration":{"registered":false,"instance":null,"error":null},"interCloud":{"enabled":self.config.intercloud_enabled,"status":if self.config.intercloud_enabled{"starting"}else{"disabled"},"providerCloud":null,"provider":null,"endpoint":null,"lastValue":null,"lastPublishedAt":null,"publishedCount":0,"lastError":null}}))
    }
    fn update(&self, change: impl FnOnce(&mut Value)) -> Result<()> {
        let initial = self.status();
        self.store.update(|db| {
            let value = table(db, "producer-status")
                .entry("state".into())
                .or_insert(initial);
            change(value);
            Ok(())
        })
    }
    async fn register(&self) -> Result<()> {
        self.remote.call("ServiceRegistry","POST","/serviceregistry/system-discovery/register",&json!({"version":"1.0.0","addresses":[self.config.advertise_address],"metadata":{"role":"random-data-producer","implementation":"Rust","authentication":"X.509/mTLS"}})).await?;
        let result=self.remote.call("ServiceRegistry","POST","/serviceregistry/service-discovery/register",&json!({"serviceDefinitionName":"randomNumberProducer","version":"1.0.0","metadata":{"range":"0..100","intervalSeconds":self.config.interval_seconds,"transportSecurity":"mutualTLS","implementation":"Rust"},"interfaces":[{"templateName":"generic_https","protocol":"https","policy":"CERT_AUTH","properties":{"accessAddresses":[self.config.advertise_address],"accessPort":self.config.advertise_port,"basePath":"/random-data-producer","operations":{"latest":{"method":"GET","path":"/latest"}}}}]})).await?;
        self.remote
            .call(
                "ServiceRegistry",
                "POST",
                "/serviceregistry/service-discovery/register",
                &broker::monitor_descriptor(
                    NAME,
                    &self.config.cloud_suffix,
                    &self.config.messaging,
                ),
            )
            .await?;
        self.update(|v| {
            v["registration"] =
                json!({"registered":true,"instance":result["instanceId"],"error":null})
        })
    }
    async fn publish(&self, foreign: bool) -> Result<()> {
        let result=self.remote.call("DynamicServiceOrchestration","POST","/serviceorchestration/orchestration/pull",&json!({"serviceRequirement":{"serviceDefinition":"dataHistorian","operations":["put-data"],"versions":["1.0.0"],"interfaceTemplateNames":["generic_https"],"securityPolicies":["CERT_AUTH"]},"orchestrationFlags":if foreign{json!({"ONLY_INTERCLOUD":true})}else{json!({})}})).await?;
        let results = array(&result, "results");
        let selected = results
            .first()
            .ok_or_else(|| Error::unavailable("No authorized historian provider"))?;
        let interfaces = array(selected, "interfaces");
        let interface = interfaces
            .iter()
            .find(|v| s(v, "protocol") == "https" && s(v, "policy") == "CERT_AUTH")
            .ok_or_else(|| Error::unavailable("No HTTPS/CERT_AUTH historian interface"))?;
        let properties = &interface["properties"];
        let operation = &properties["operations"]["put-data"];
        if operation["method"] != "PUT"
            || s(selected, "providerName") != "DataManager"
            || (s(selected, "cloudIdentitifer") != "LOCAL") != foreign
        {
            return Err(Error::new(502, "Invalid historian orchestration binding"));
        }
        let cloud = self.config.cloud_suffix.split('.').next().unwrap();
        let service = if foreign {
            format!("randomNumberProducerFrom{cloud}")
        } else {
            "randomNumberProducer".into()
        };
        let path = format!(
            "{}/{}",
            s(properties, "basePath").trim_end_matches('/'),
            s(operation, "path").trim_start_matches('/')
        )
        .replace("{systemName}", NAME)
        .replace("{serviceName}", &service);
        if !path.starts_with('/')
            || path.contains(['{', '}', '\\', '#', '\r', '\n'])
            || path.starts_with("//")
        {
            return Err(Error::new(502, "Invalid historian operation path"));
        }
        let mut origin = url::Url::parse("https://placeholder/").unwrap();
        origin
            .set_host(properties["accessAddresses"][0].as_str())
            .map_err(|_| Error::new(502, "Invalid historian address"))?;
        let port = properties["accessPort"]
            .as_u64()
            .filter(|p| *p > 0 && *p <= 65535)
            .ok_or_else(|| Error::new(502, "Invalid historian port"))?;
        origin
            .set_port(Some(port as u16))
            .map_err(|_| Error::new(502, "Invalid historian port"))?;
        let value = random_value()?;
        let timestamp = chrono::Utc::now().timestamp_millis() as f64 / 1000.0;
        let payload = json!([{"bn":if foreign{format!("urn:arrowhead:{cloud}:random-data-producer:")}else{"urn:arrowhead:random-data-producer:".into()},"bt":timestamp,"n":"random-number","u":"1","v":value}]);
        self.remote
            .call_at(
                if foreign { "GateTunnel" } else { "DataManager" },
                origin.as_str(),
                "PUT",
                &path,
                &payload,
            )
            .await?;
        self.update(|status|{
            let status=if foreign{&mut status["interCloud"]}else{status};
            status["status"]="running".into();status["lastValue"]=value.into();status["lastPublishedAt"]=timestamp.into();status["publishedCount"]=(status["publishedCount"].as_u64().unwrap_or(0)+1).into();status["lastError"]=Value::Null;
            if foreign{status["providerCloud"]=selected["cloudIdentitifer"].clone();status["provider"]=selected["providerName"].clone();status["endpoint"]=format!("{}{path}",origin.as_str().trim_end_matches('/')).into();}
            else{status["orchestration"]=json!({"provider":selected["providerName"],"serviceInstanceId":selected["serviceInstanceId"],"endpoint":format!("{}{path}",origin.as_str().trim_end_matches('/')),"resolvedAt":timestamp});}
        })
    }
    async fn publishing(self, foreign: bool, mut stop: tokio::sync::watch::Receiver<bool>) {
        let mut clock = tokio::time::interval(Duration::from_secs(self.config.interval_seconds));
        clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {_=stop.changed()=>break,_=clock.tick()=>{if let Err(e)=self.publish(foreign).await{let _=self.update(|status|{let status=if foreign{&mut status["interCloud"]}else{status};status["status"]="degraded".into();status["lastError"]=format!("Historian publication failed (HTTP {})",e.code).into();});}}}
        }
    }
    async fn monitoring(self, mut stop: tokio::sync::watch::Receiver<bool>) {
        let remote = self.remote.clone();
        let tls: broker::TlsFactory = Arc::new(move |expected| Ok(remote.tls_config(expected)?));
        let mut clock = tokio::time::interval(Duration::from_secs(30));
        loop {
            tokio::select! {_=stop.changed()=>break,_=clock.tick()=>{if let Err(e)=self.register().await{let _=self.update(|status|status["registration"]=json!({"registered":false,"instance":null,"error":format!("Registration unavailable ({})",e.code)}));}let _=broker::publish_monitor(&self.config.messaging,NAME,&self.config.cloud_suffix,&tls,&json!({"sourceTime":now(),"state":self.status()["status"],"implementation":"rust"})).await;}}
        }
    }
}
async fn route(
    axum::extract::State(app): axum::extract::State<Producer>,
    request: axum::extract::Request,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let result=async move {
        let peer=request.extensions().get::<Principal>().cloned().ok_or_else(Error::denied)?;
        if request.method()!=axum::http::Method::GET{return Err(Error::new(404,"Not found"));}
        let path=request.uri().path().to_owned();
        if path=="/random-data-producer/mgmt"{
            let token=request.headers().get("authorization").and_then(|h|h.to_str().ok()).and_then(|h|h.strip_prefix("Bearer IDENTITY-TOKEN//")).filter(|t|!t.is_empty()&&t.len()<=4096&&!t.contains(['/', '?','#','\r','\n'])).map(str::to_owned).ok_or_else(||Error::new(401,"Identity token required"))?;
            let verified=app.remote.call("Authentication","GET",&format!("/authentication/identity/verify/{}",security::encode(&token)),&Value::Null).await?;
            if verified["verified"]!=true||verified["systemName"]!=peer.name{return Err(Error::new(401,"Token/certificate mismatch"));}
            if verified["sysop"]!=true&&peer.name!="LocalCloudManager"{return Err(Error::denied());}
            return Ok((axum::http::StatusCode::OK,axum::Json(json!({"map":{"implementation":"Rust","version":"5.4.0","system.name":NAME,"qualification":"test application"}}))).into_response());
        }
        if path=="/random-data-producer/monitor/echo"{return Ok((axum::http::StatusCode::OK,"Got it!").into_response());}
        if path!="/health"&&path!="/random-data-producer/latest"{return Err(Error::new(404,"Not found"));}
        let status=app.status();let code=if status["status"]=="degraded"{axum::http::StatusCode::SERVICE_UNAVAILABLE}else{axum::http::StatusCode::OK};
        Ok((code,axum::Json(status)).into_response())
    }.await;
    let mut response = match result {
        Ok(response) => response,
        Err(e) => (
            axum::http::StatusCode::from_u16(e.code)
                .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
            axum::Json(json!({"error":e.message})),
        )
            .into_response(),
    };
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
}
pub async fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
    use hyper_util::{
        rt::{TokioExecutor, TokioIo, TokioTimer},
        server::conn::auto::Builder,
        service::TowerToHyperService,
    };
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 3 || args[1] != "--config" {
        return Err("RandomDataProducer --config CONFIG.json".into());
    }
    let config: Config = serde_json::from_slice(&std::fs::read(&args[2])?)?;
    config.validate()?;
    let tls = security::Tls::load_identity(
        NAME,
        &config.cloud_suffix,
        &config.certificate,
        &config.private_key,
        &config.ca,
        Some(&config.crl_file),
    )?;
    let remote = security::Remote::from_identity(
        security::RemoteIdentity {
            name: NAME.into(),
            cloud_suffix: config.cloud_suffix.clone(),
            password_file: config.password_file.clone(),
            authentication_url: config.authentication_url.clone(),
            registry_url: config.registry_url.clone(),
            authorization_url: config.authorization_url.clone(),
            upstreams: BTreeMap::from([(
                "DynamicServiceOrchestration".into(),
                config.orchestrator_url.clone(),
            )]),
        },
        tls.clone(),
    );
    let app = Producer {
        store: Arc::new(Store::open(&config.state)?),
        config: Arc::new(config),
        remote: Arc::new(remote),
    };
    let router = axum::Router::new().fallback(route).with_state(app.clone());
    let listener = tokio::net::TcpListener::bind(&app.config.listen).await?;
    let (stop, rx) = tokio::sync::watch::channel(false);
    let mut jobs = tokio::task::JoinSet::new();
    jobs.spawn(app.clone().publishing(false, rx.clone()));
    if app.config.intercloud_enabled {
        jobs.spawn(app.clone().publishing(true, rx.clone()));
    }
    jobs.spawn(app.clone().monitoring(rx.clone()));
    let limit = Arc::new(tokio::sync::Semaphore::new(64));
    let mut connections = tokio::task::JoinSet::new();
    let shutdown = async {
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM");
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    };
    tokio::pin!(shutdown);
    loop {
        tokio::select! {_=&mut shutdown=>break,_=connections.join_next(),if !connections.is_empty()=>{},accepted=listener.accept()=>{let(stream,_)=accepted?;let Ok(permit)=limit.clone().try_acquire_owned()else{continue};let Ok(server)=tls.server_current()else{continue};let router=router.clone();let suffix=app.config.cloud_suffix.clone();let mut stopping=rx.clone();connections.spawn(async move{let _permit=permit;let acceptor=tokio_rustls::TlsAcceptor::from(server);let handshake=tokio::time::timeout(Duration::from_secs(5),acceptor.accept(stream));let stream=tokio::select!{_=stopping.changed()=>return,result=handshake=>{let Ok(Ok(stream))=result else{return};stream}};let Some(cert)=stream.get_ref().1.peer_certificates().and_then(|c|c.first())else{return};let Ok(peer)=security::peer(cert.as_ref(),&suffix)else{return};let router=router.layer(axum::Extension(peer));let mut builder=Builder::new(TokioExecutor::new());builder.http1().timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(10)).max_buf_size(1024*1024);builder.http2().max_concurrent_streams(16);let connection=builder.serve_connection_with_upgrades(TokioIo::new(stream),TowerToHyperService::new(router));tokio::pin!(connection);tokio::select!{_=&mut connection=>{},_=stopping.changed()=>{},_=tokio::time::sleep(Duration::from_secs(60))=>{}}});}}
    }
    let _ = stop.send(true);
    jobs.abort_all();
    connections.abort_all();
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_random_generator_stays_in_the_reference_range() {
        for _ in 0..1000 {
            assert!(random_value().unwrap() <= 100);
        }
    }
}
