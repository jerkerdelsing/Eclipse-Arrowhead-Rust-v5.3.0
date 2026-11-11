// SPDX-License-Identifier: EPL-2.0
use super::*;
use crate::s as strv;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use openssl::pkey::{PKey, Private};
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::sync::watch;

pub struct Session {
    id: String,
    consumer: String,
    consumer_cloud: String,
    provider: String,
    provider_cloud: String,
    definition: String,
    peer: String,
    target: Value,
    params: Value,
    ephemeral: Option<PKey<Private>>,
    keys: Option<[Vec<u8>; 2]>,
    exchange: Value,
    consumer_key: String,
    replay: crypto::Replay,
    sequence: u64,
    requests: u64,
    created: Instant,
    last_used: Instant,
    created_at: f64,
    port: u16,
}
type Shared = Arc<Mutex<Session>>;
pub struct Runtime {
    providers: Mutex<BTreeMap<String, Shared>>,
    consumers: Mutex<BTreeMap<String, (Shared, watch::Sender<bool>)>>,
    connections: Arc<tokio::sync::Semaphore>,
    requests: Arc<tokio::sync::Semaphore>,
}
impl Default for Runtime {
    fn default() -> Self {
        Self {
            providers: Mutex::new(BTreeMap::new()),
            consumers: Mutex::new(BTreeMap::new()),
            connections: Arc::new(tokio::sync::Semaphore::new(64)),
            requests: Arc::new(tokio::sync::Semaphore::new(16)),
        }
    }
}
impl Session {
    fn expired(&self) -> bool {
        self.created.elapsed() > Duration::from_secs(43200)
            || self.last_used.elapsed() > Duration::from_secs(3600)
    }
    fn summary(&self, side: &str) -> Value {
        json!({"sessionId":self.id,"side":side,"consumer":self.consumer,"consumerCloud":self.consumer_cloud,"provider":self.provider,"providerCloud":self.provider_cloud,"serviceDefinition":self.definition,"requests":self.requests,"createdAt":self.created_at})
    }
}
fn lock<T>(value: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>> {
    value
        .lock()
        .map_err(|_| Error::unavailable("Tunnel runtime unavailable"))
}
fn peer_cloud(peer: &str) -> Result<String> {
    let p = peer.split('.').collect::<Vec<_>>();
    if p.len() != 5 {
        return Err(Error::denied());
    }
    Ok(format!("{}|{}", p[1], p[2]))
}
fn session(app: &App, req: &Value) -> Result<Session> {
    if app.config.federation.is_none() {
        return Err(Error::unsupported("Federation is not configured"));
    }
    required(req, &["consumer", "provider", "serviceDefinition", "peer"])?;
    if !valid_name(strv(req, "consumer"))
        || !valid_name(strv(req, "provider"))
        || !trusted(app, strv(req, "peer"))
    {
        return Err(Error::denied());
    }
    let session_id = req["sessionId"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(id);
    if session_id.is_empty()
        || session_id.len() > 128
        || !session_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Error::bad("Invalid session id"));
    }
    Ok(Session {
        id: session_id,
        consumer: strv(req, "consumer").into(),
        consumer_cloud: strv(req, "consumerCloud").into(),
        provider: strv(req, "provider").into(),
        provider_cloud: strv(req, "providerCloud").into(),
        definition: strv(req, "serviceDefinition").into(),
        peer: strv(req, "peer").into(),
        target: req["target"].clone(),
        params: Value::Null,
        ephemeral: None,
        keys: None,
        exchange: Value::Null,
        consumer_key: String::new(),
        replay: crypto::Replay::default(),
        sequence: 0,
        requests: 0,
        created: Instant::now(),
        last_used: Instant::now(),
        created_at: chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
        port: 0,
    })
}
fn params(s: &Session, consumer: &str, provider: &str, key: &str) -> Value {
    json!({"sessionId":s.id,"consumer":s.consumer,"consumerCloud":s.consumer_cloud,"provider":s.provider,"serviceDefinition":s.definition,"consumerGateTunnel":consumer,"providerGateTunnel":provider,"providerKey":key})
}
pub fn operation_allowed(method: &str, raw: &str, base: &str, operations: &Value) -> bool {
    let path = raw.split('?').next().unwrap_or("");
    let lower = path.to_ascii_lowercase();
    if !raw.starts_with('/')
        || raw.contains(['#', '\\', '\0', '\r', '\n'])
        || path.contains("//")
        || ["%2e", "%2f", "%5c", "%00", "%25"]
            .iter()
            .any(|v| lower.contains(v))
        || path.split('/').any(|p| p == "." || p == "..")
    {
        return false;
    }
    let Some(operations) = operations.as_object() else {
        return false;
    };
    operations.values().any(|op| {
        if !strv(op, "method").eq_ignore_ascii_case(method) {
            return false;
        }
        let pattern = format!(
            "{}/{}",
            base.trim_end_matches('/'),
            strv(op, "path").trim_start_matches('/')
        );
        let a = pattern.trim_matches('/').split('/').collect::<Vec<_>>();
        let b = path.trim_matches('/').split('/').collect::<Vec<_>>();
        // Segment-exact grants: unlike a raw prefix, /put never authorises
        // /putAnything, traversal or an unrelated descendant operation.
        a.len() == b.len()
            && a.iter().zip(&b).all(|(a, b)| {
                if a.starts_with('{') && a.ends_with('}') && !a[1..a.len() - 1].contains(['{', '}'])
                {
                    !b.is_empty()
                } else {
                    a == b
                }
            })
    })
}
async fn registered_target(app: &App, session: &Session) -> Result<()> {
    let response=app.remote.call("ServiceRegistry","POST","/serviceregistry/service-discovery/lookup",&json!({"providerNames":[session.provider],"serviceDefinitionNames":[session.definition],"interfaceTemplateNames":["generic_https"]})).await?;
    for instance in array(&response, "entries") {
        if strv(&instance["provider"], "name") != session.provider {
            continue;
        }
        let Some(properties) = gatekeeper::properties(&instance) else {
            continue;
        };
        if array(properties, "accessAddresses")
            .iter()
            .any(|a| a == &session.target["address"])
            && properties["accessPort"] == session.target["port"]
            && properties["basePath"] == session.target["basePath"]
            && session.target["operations"].as_object().is_some_and(|ops| {
                ops.iter()
                    .all(|(name, op)| properties["operations"][name] == *op)
            })
        {
            return Ok(());
        }
    }
    Err(Error::denied())
}
fn open_provider(app: &App, req: &Value) -> Result<Value> {
    let mut s = session(app, req)?;
    if s.consumer_cloud != peer_cloud(&s.peer)?
        || !s.target["operations"].is_object()
        || s.target["operations"].as_object().unwrap().is_empty()
    {
        return Err(Error::bad(
            "Consumer cloud and negotiated operations required",
        ));
    }
    let address = strv(&s.target, "address");
    if address.is_empty()
        || address.len() > 253
        || !address
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-_:".contains(&c))
        || s.target["port"]
            .as_u64()
            .is_none_or(|p| p == 0 || p > 65535)
        || !strv(&s.target, "basePath").starts_with('/')
    {
        return Err(Error::bad("Invalid provider target"));
    }
    let ephemeral = crypto::ephemeral()?;
    s.params = params(&s, &s.peer, &own_cn(app), &crypto::public(&ephemeral)?);
    s.exchange = crypto::Identity::load(app.config.federation.as_ref().unwrap(), &own_cn(app))?
        .exchange("provider", &s.params)?;
    s.ephemeral = Some(ephemeral);
    let response = json!({"sessionId":s.id,"keyExchange":s.exchange});
    let mut providers = lock(&app.federation.tunnel.providers)?;
    providers.retain(|_, old| old.lock().is_ok_and(|old| !old.expired()));
    if providers.contains_key(&s.id) {
        return Err(Error::new(409, "Session id already allocated"));
    }
    providers.retain(|_, old| {
        old.lock().is_ok_and(|old| {
            !(old.consumer == s.consumer
                && old.consumer_cloud == s.consumer_cloud
                && old.provider == s.provider
                && old.definition == s.definition)
        })
    });
    if providers.len() >= 256 {
        return Err(Error::unavailable("Provider session capacity reached"));
    }
    providers.insert(s.id.clone(), Arc::new(Mutex::new(s)));
    Ok(response)
}
fn open_consumer(app: &App, req: &Value) -> Result<Value> {
    let mut s = session(app, req)?;
    if s.provider_cloud != peer_cloud(&s.peer)? {
        return Err(Error::bad("Provider cloud does not match peer"));
    }
    s.consumer_cloud = cloud(app);
    let exchange = &req["keyExchange"];
    s.params = params(&s, &own_cn(app), &s.peer, strv(exchange, "providerKey"));
    let identity = crypto::Identity::load(app.config.federation.as_ref().unwrap(), &own_cn(app))?;
    identity.verify(exchange, &s.peer, "provider", &s.params)?;
    let ephemeral = crypto::ephemeral()?;
    s.params["consumerKey"] = crypto::public(&ephemeral)?.into();
    s.exchange = identity.exchange("consumer", &s.params)?;
    s.keys = Some(crypto::derive(
        &ephemeral,
        strv(exchange, "providerKey"),
        &s.id,
    )?);
    // Retain the provider exchange for fresh CRL validation on every request.
    s.target = exchange.clone();
    let config = app.config.federation.as_ref().unwrap();
    let mut consumers = lock(&app.federation.tunnel.consumers)?;
    consumers.retain(|_, (old, stop)| {
        let keep = old.lock().is_ok_and(|old| {
            !old.expired()
                && !(old.consumer == s.consumer
                    && old.provider_cloud == s.provider_cloud
                    && old.provider == s.provider
                    && old.definition == s.definition)
        });
        if !keep {
            let _ = stop.send(true);
        }
        keep
    });
    if consumers.contains_key(&s.id) {
        return Err(Error::new(409, "Session id already allocated"));
    }
    let ip = app
        .config
        .listen
        .parse::<std::net::SocketAddr>()
        .map_err(|_| Error::bad("Invalid listen address"))?
        .ip();
    let mut listener = None;
    for port in config.min_port..=config.max_port {
        if let Ok(socket) = std::net::TcpListener::bind((ip, port)) {
            socket.set_nonblocking(true)?;
            listener = Some((port, tokio::net::TcpListener::from_std(socket)?));
            break;
        }
    }
    let (port, listener) =
        listener.ok_or_else(|| Error::unavailable("No tunnel listener ports available"))?;
    s.port = port;
    let response = json!({"address":app.config.advertise_address,"port":port,"sessionId":s.id});
    let (stop, rx) = watch::channel(false);
    let session = Arc::new(Mutex::new(s));
    consumers.insert(session.lock().unwrap().id.clone(), (session.clone(), stop));
    tokio::spawn(serve(app.clone(), session, listener, rx));
    Ok(response)
}
async fn serve(
    app: App,
    session: Shared,
    listener: tokio::net::TcpListener,
    mut stop: watch::Receiver<bool>,
) {
    use hyper_util::{
        rt::{TokioExecutor, TokioIo, TokioTimer},
        server::conn::auto::Builder,
        service::TowerToHyperService,
    };
    let Ok(tls) = security::Tls::load(&app.config) else {
        return;
    };
    let router = axum::Router::new()
        .fallback(forward_http)
        .with_state((app.clone(), session));
    let mut jobs = tokio::task::JoinSet::new();
    let limit = app.federation.tunnel.connections.clone();
    loop {
        tokio::select! {
            _=stop.changed()=>break,
            _=jobs.join_next(),if !jobs.is_empty()=>{},
            accepted=listener.accept()=>{let Ok((stream,_))=accepted else{break};let Ok(permit)=limit.clone().try_acquire_owned()else{continue};let Ok(server)=tls.server_current()else{continue};let router=router.clone();let suffix=app.config.cloud_suffix.clone();let mut stopping=stop.clone();
                jobs.spawn(async move {let _permit=permit;let acceptor=tokio_rustls::TlsAcceptor::from(server);let handshake=tokio::time::timeout(Duration::from_secs(5),acceptor.accept(stream));
                    let stream=tokio::select!{_=stopping.changed()=>return,result=handshake=>{let Ok(Ok(stream))=result else{return};stream}};
                    let Some(cert)=stream.get_ref().1.peer_certificates().and_then(|c|c.first())else{return};let Ok(peer)=security::peer(cert.as_ref(),&suffix)else{return};
                    let router=router.layer(axum::Extension(peer));let mut builder=Builder::new(TokioExecutor::new());builder.http1().timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(10)).max_buf_size(1024*1024);builder.http2().max_concurrent_streams(16);
                    let connection=builder.serve_connection_with_upgrades(TokioIo::new(stream),TowerToHyperService::new(router));tokio::pin!(connection);
                    tokio::select!{_=&mut connection=>{},_=stopping.changed()=>{},_=tokio::time::sleep(Duration::from_secs(60))=>{}}
                });
            }
        }
    }
    jobs.abort_all();
}
async fn forward_http(
    axum::extract::State((app, session)): axum::extract::State<(App, Shared)>,
    request: axum::extract::Request,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let result=async {
        let _permit=app.federation.tunnel.requests.clone().try_acquire_owned().map_err(|_|Error::unavailable("Tunnel request capacity reached"))?;
        let peer=request.extensions().get::<Principal>().cloned().ok_or_else(Error::denied)?;
        let caller=security::authenticate(&app,peer,request.headers().get("authorization").and_then(|h|h.to_str().ok())).await?;
        let (peer,id,keys,exchange,sequence)={let mut s=lock(&session)?;if s.expired(){return Err(Error::new(401,"Tunnel session expired"));}
            if caller.name!=s.consumer{return Err(Error::denied());}
            let identity=crypto::Identity::load(app.config.federation.as_ref().unwrap(),&own_cn(&app))?;identity.verify(&s.target,&s.peer,"provider",&s.params)?;
            s.sequence=s.sequence.checked_add(1).ok_or_else(Error::denied)?;(s.peer.clone(),s.id.clone(),s.keys.as_ref().ok_or_else(Error::denied)?.clone(),s.exchange.clone(),s.sequence)};
        let method=request.method().as_str().to_owned();let path=origin_path(request.uri());let content_type=request.headers().get("content-type").and_then(|h|h.to_str().ok()).unwrap_or("application/json").to_owned();
        let body=axum::body::to_bytes(request.into_body(),1024*1024).await.map_err(|_|Error::new(413,"Tunnel request too large"))?;
        let mut message=crypto::seal(&keys[0],&id,"c2p",sequence,&json!({"method":method,"path":path,"contentType":content_type,"body":B64.encode(body)}))?;
        message["type"]="http-request".into();message["sessionId"]=id.clone().into();message["keyExchange"]=exchange;
        let reply=relay::request(&app,&peer,message).await?;
        let (actual,response)=crypto::open(&keys[1],&id,"p2c",&reply)?;
        if actual!=sequence{return Err(Error::new(401,"Tunnel response sequence mismatch"));}
        let status=response["status"].as_u64().filter(|v|(100..600).contains(v)).ok_or_else(||Error::new(502,"Invalid peer status"))?;
        let bytes=B64.decode(strv(&response,"body")).map_err(|_|Error::new(502,"Invalid peer body"))?;
        if bytes.len()>1024*1024{return Err(Error::new(502,"Peer response too large"));}
        let content=strv(&response,"contentType").parse::<axum::http::HeaderValue>().map_err(|_|Error::new(502,"Invalid peer content type"))?;
        {let mut session=lock(&session)?;session.requests+=1;session.last_used=Instant::now();}
        Ok::<_,Error>((axum::http::StatusCode::from_u16(status as u16).unwrap(),[(axum::http::header::CONTENT_TYPE,content)],bytes).into_response())
    }.await;
    match result {
        Ok(response) => response,
        Err(e) => (
            axum::http::StatusCode::from_u16(e.code).unwrap_or(axum::http::StatusCode::BAD_GATEWAY),
            axum::Json(json!({"error":e.message})),
        )
            .into_response(),
    }
}
fn origin_path(uri: &axum::http::Uri) -> String {
    // HTTP/2 reconstructs scheme/authority in its URI. The AH-GT-1 wire
    // carries only origin-form path/query, as Java RequestURI and Go do.
    uri.path_and_query()
        .map(|v| v.as_str())
        .unwrap_or("/")
        .to_owned()
}
fn answer(status: u16, bytes: &[u8], content: &str) -> Value {
    json!({"status":status,"body":B64.encode(bytes),"contentType":content})
}
async fn execute(app: &App, session: Shared, message: &Value) -> Result<Value> {
    let (provider, target, consumer, foreign, definition) = {
        let s = lock(&session)?;
        if s.expired() {
            return Err(Error::new(401, "Tunnel session expired"));
        }
        (
            s.provider.clone(),
            s.target.clone(),
            s.consumer.clone(),
            s.consumer_cloud.clone(),
            s.definition.clone(),
        )
    };
    let method = strv(message, "method");
    let path = strv(message, "path");
    if !operation_allowed(
        method,
        path,
        strv(&target, "basePath"),
        &target["operations"],
    ) {
        return Ok(answer(
            403,
            b"Operation outside negotiated session",
            "text/plain",
        ));
    }
    // Revalidate the registry binding rather than following an endpoint supplied
    // by a relay message. Only the local Gatekeeper can create this snapshot.
    let snapshot = Session {
        id: String::new(),
        consumer: String::new(),
        consumer_cloud: String::new(),
        provider: provider.clone(),
        provider_cloud: String::new(),
        definition: definition.clone(),
        peer: String::new(),
        target: target.clone(),
        params: Value::Null,
        ephemeral: None,
        keys: None,
        exchange: Value::Null,
        consumer_key: String::new(),
        replay: crypto::Replay::default(),
        sequence: 0,
        requests: 0,
        created: Instant::now(),
        last_used: Instant::now(),
        created_at: 0.0,
        port: 0,
    };
    registered_target(app, &snapshot).await?;
    let operation = target["operations"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(_, op)| {
            operation_allowed(
                method,
                path,
                strv(&target, "basePath"),
                &json!({"operation":op}),
            )
        })
        .map(|(name, _)| name.clone())
        .ok_or_else(Error::denied)?;
    let authorization=app.remote.call("ConsumerAuthorization","POST","/consumerauthorization/authorization/mgmt/check",&json!({"list":[{"provider":provider,"consumer":consumer,"cloud":foreign,"targetType":"SERVICE_DEF","target":definition,"scope":operation}]})).await?;
    if authorization["entries"][0]["granted"] != true {
        return Ok(answer(
            403,
            b"Foreign consumer no longer authorized",
            "text/plain",
        ));
    }
    if strv(message, "body").len() > 1_398_104 {
        return Err(Error::new(413, "Tunnel request too large"));
    }
    let bytes = B64
        .decode(strv(message, "body"))
        .map_err(|_| Error::bad("Invalid tunnel body"))?;
    if bytes.len() > 1024 * 1024 {
        return Err(Error::new(413, "Tunnel request too large"));
    }
    let mut origin = url::Url::parse("https://placeholder/").unwrap();
    origin
        .set_host(Some(strv(&target, "address")))
        .map_err(|_| Error::bad("Invalid provider host"))?;
    origin
        .set_port(Some(target["port"].as_u64().unwrap() as u16))
        .map_err(|_| Error::bad("Invalid provider port"))?;
    let endpoint = format!("{}{path}", origin.as_str().trim_end_matches('/'));
    let token = app.remote.own_token().await?;
    let client = app.remote.provider_client(&provider)?;
    let mut response = client
        .request(
            method
                .parse()
                .map_err(|_| Error::bad("Invalid tunnel method"))?,
            endpoint,
        )
        .header("Authorization", format!("Bearer IDENTITY-TOKEN//{token}"))
        .header(
            "X-Arrowhead-Remote-Consumer",
            format!("{consumer}|{foreign}"),
        )
        .header("Content-Type", strv(message, "contentType"))
        .body(bytes)
        .send()
        .await
        .map_err(|_| Error::new(502, "Provider call unavailable"))?;
    let status = response.status().as_u16();
    let content = response
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("application/json")
        .to_owned();
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| Error::new(502, "Provider response unavailable"))?
    {
        if bytes.len() + chunk.len() > 1024 * 1024 {
            return Err(Error::new(502, "Provider response too large"));
        }
        bytes.extend_from_slice(&chunk);
    }
    {
        let mut s = lock(&session)?;
        s.requests += 1;
        s.last_used = Instant::now();
    }
    Ok(answer(status, &bytes, &content))
}
pub async fn incoming(app: &App, peer: &str, message: &Value) -> Result<Value> {
    let _permit = app
        .federation
        .tunnel
        .requests
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::unavailable("Tunnel request capacity reached"))?;
    let session = lock(&app.federation.tunnel.providers)?
        .get(strv(message, "sessionId"))
        .cloned()
        .ok_or_else(Error::denied)?;
    let (keys, id, sequence, content) = {
        let mut s = lock(&session)?;
        if s.peer != peer
            || s.expired()
            || strv(message, "type") != "http-request"
            || message["ciphertext"].is_null()
        {
            return Err(Error::denied());
        }
        let exchange = &message["keyExchange"];
        let mut params = s.params.clone();
        params["consumerKey"] = exchange["consumerKey"].clone();
        crypto::Identity::load(app.config.federation.as_ref().unwrap(), &own_cn(app))?
            .verify(exchange, peer, "consumer", &params)?;
        if s.keys.is_none() {
            let ephemeral = s.ephemeral.take().ok_or_else(Error::denied)?;
            s.keys = Some(crypto::derive(
                &ephemeral,
                strv(exchange, "consumerKey"),
                &s.id,
            )?);
            s.consumer_key = strv(exchange, "consumerKey").into();
        } else if s.consumer_key != strv(exchange, "consumerKey") {
            return Err(Error::denied());
        }
        let keys = s.keys.as_ref().unwrap().clone();
        let (sequence, content) = crypto::open(&keys[0], &s.id, "c2p", message)?;
        if !s.replay.accept(sequence) {
            return Err(Error::new(401, "Replayed tunnel request"));
        }
        (keys, s.id.clone(), sequence, content)
    };
    let response = execute(app, session, &content)
        .await
        .unwrap_or_else(|e| answer(e.code, b"Provider operation refused", "text/plain"));
    crypto::seal(&keys[1], &id, "p2c", sequence, &response)
}
pub fn cleanup(app: &App) {
    if let Ok(mut providers) = app.federation.tunnel.providers.lock() {
        providers.retain(|_, s| s.lock().is_ok_and(|s| !s.expired()));
    }
    if let Ok(mut consumers) = app.federation.tunnel.consumers.lock() {
        consumers.retain(|_, (s, stop)| {
            let keep = s.lock().is_ok_and(|s| !s.expired());
            if !keep {
                let _ = stop.send(true);
            }
            keep
        });
    }
}
pub fn shutdown(app: &App) {
    if let Ok(mut consumers) = app.federation.tunnel.consumers.lock() {
        for (_, (_, stop)) in std::mem::take(&mut *consumers) {
            let _ = stop.send(true);
        }
    }
    if let Ok(mut providers) = app.federation.tunnel.providers.lock() {
        providers.clear();
    }
}
pub async fn handle(
    app: &App,
    method: &str,
    path: &str,
    req: &Value,
    caller: &Principal,
) -> Result<(u16, Value)> {
    if path.ends_with("/publickey") {
        let certificate = openssl::x509::X509::from_pem(&std::fs::read(&app.config.certificate)?)?;
        let key = certificate.public_key()?;
        return Ok((
            200,
            json!({"algorithm":if key.id()==openssl::pkey::Id::RSA{"RSA"}else{"EC"},"format":"X.509","publicKey":B64.encode(key.public_key_to_der()?)}),
        ));
    }
    cleanup(app);
    if path.ends_with("/mgmt/status") {
        let mut sessions = Vec::new();
        for s in lock(&app.federation.tunnel.providers)?.values() {
            sessions.push(lock(s)?.summary("provider"));
        }
        for (s, _) in lock(&app.federation.tunnel.consumers)?.values() {
            sessions.push(lock(s)?.summary("consumer"));
        }
        return Ok((
            200,
            json!({"relay":relay::status(app),"interCloud":{"sessions":sessions,"providerSessions":lock(&app.federation.tunnel.providers)?.len(),"consumerSessions":lock(&app.federation.tunnel.consumers)?.len()}}),
        ));
    }
    if method == "GET" {
        let rows = app.store.rows("tunnel-controls");
        return Ok((200, json!({"entries":rows,"count":rows.len()})));
    }
    if path.contains("/intercloud/") {
        if caller.name != "Gatekeeper" {
            return Err(Error::denied());
        }
        return Ok((
            201,
            if path.ends_with("/provider") {
                open_provider(app, req)?
            } else {
                open_consumer(app, req)?
            },
        ));
    }
    if app.config.federation.is_none() {
        return Err(Error::unsupported("Federation is not configured"));
    }
    if path.ends_with("/connect_provider") {
        for field in [
            "consumer",
            "provider",
            "consumerCloud",
            "providerCloud",
            "relay",
            "serviceDefinition",
        ] {
            if req[field].is_null() || req[field].as_str().is_some_and(str::is_empty) {
                return Err(Error::bad(format!("{field} required")));
            }
        }
        let record = app.store.update(|db| {
            let t = table(db, "tunnel-controls");
            let used = t
                .values()
                .filter_map(|v| v["tunnelPort"].as_u64())
                .collect::<std::collections::BTreeSet<_>>();
            let port = (8000..=8099)
                .find(|p| !used.contains(p))
                .ok_or_else(|| Error::unavailable("No control ports available"))?;
            let mut record = req.clone();
            record["sessionId"] = id().into();
            record["queueId"] = req
                .get("queueId")
                .cloned()
                .unwrap_or_else(|| format!("gatetunnel.{}", id()).into());
            if t.values().any(|r| r["queueId"] == record["queueId"]) {
                return Err(Error::new(409, "Queue already allocated"));
            }
            record["peerName"] = req
                .get("peerName")
                .cloned()
                .unwrap_or_else(|| format!("GateTunnel-{}", id()).into());
            record["tunnelPort"] = port.into();
            record["state"] = "PROVIDER_READY".into();
            record["sessionStartedAt"] =
                (chrono::Utc::now().timestamp_millis() as f64 / 1000.0).into();
            t.insert(strv(&record, "sessionId").into(), record.clone());
            Ok(record)
        })?;
        return Ok((
            201,
            json!({"sessionId":record["sessionId"],"queueId":record["queueId"],"peerName":record["peerName"],"serverPort":record["tunnelPort"],"state":record["state"]}),
        ));
    }
    if path.ends_with("/connect_consumer") {
        required(req, &["queueId"])?;
        let record = app.store.update(|db| {
            let r = table(db, "tunnel-controls")
                .values_mut()
                .find(|v| v["queueId"] == req["queueId"] && v["state"] != "CLOSED")
                .ok_or_else(|| Error::new(404, "Session not found"))?;
            r["state"] = "ACTIVE".into();
            Ok(r.clone())
        })?;
        return Ok((
            201,
            json!({"sessionId":record["sessionId"],"serverPort":record["tunnelPort"],"state":record["state"]}),
        ));
    }
    let close = |session: &str, port: Option<u64>| -> Result<bool> {
        let mut changed = app.store.update(|db| {
            let mut changed = false;
            for value in table(db, "tunnel-controls").values_mut() {
                if value["state"] != "CLOSED"
                    && (if !session.is_empty() {
                        strv(value, "sessionId") == session
                    } else {
                        port.is_some() && value["tunnelPort"].as_u64() == port
                    })
                {
                    value["state"] = "CLOSED".into();
                    changed = true;
                }
            }
            Ok(changed)
        })?;
        if !session.is_empty() {
            changed |= lock(&app.federation.tunnel.providers)?
                .remove(session)
                .is_some();
            if let Some((_, stop)) = lock(&app.federation.tunnel.consumers)?.remove(session) {
                let _ = stop.send(true);
                changed = true;
            }
        }
        Ok(changed)
    };
    if path.ends_with("/close_sessions") {
        let ports = req
            .as_array()
            .cloned()
            .unwrap_or_else(|| array(req, "ports"));
        let mut errors = Vec::new();
        for port in ports {
            if !close("", port.as_u64())? {
                errors.push(json!({"port":port,"error":"Active session not found"}));
            }
        }
        return Ok((200, errors.into()));
    }
    let changed = close(strv(req, "sessionId"), req["tunnelPort"].as_u64())?;
    Ok((if changed { 200 } else { 404 }, json!({"closed":changed})))
}
#[cfg(test)]
mod wire_tests {
    #[test]
    fn http2_uri_is_forwarded_as_origin_form_with_query() {
        let uri =
            "https://gatetunnel:8200/datamanager/data-historian/systems/A/services/B/data?count=2"
                .parse()
                .unwrap();
        assert_eq!(
            super::origin_path(&uri),
            "/datamanager/data-historian/systems/A/services/B/data?count=2"
        );
    }
}
