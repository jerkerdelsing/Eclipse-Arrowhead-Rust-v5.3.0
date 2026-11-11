// SPDX-License-Identifier: EPL-2.0
use super::*;
use arrowhead_messaging_rust::rumqttc::{
    self, AsyncClient, Event, Incoming, MqttOptions, QoS, TlsConfiguration, Transport,
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
};
use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

// Preserve strict MQTT protocol reconciliation across credential reconnects.
// This is a protocol checkpoint, not a durable application request outbox.
#[derive(Clone)]
struct ProtocolStore {
    store: Arc<Store>,
}
type CheckpointFuture<'a, T> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = std::result::Result<T, rumqttc::SessionStoreError>>
            + Send
            + 'a,
    >,
>;
impl std::fmt::Debug for ProtocolStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeRelayProtocolStore")
    }
}
fn checkpoint_key(key: &rumqttc::SessionStoreKey) -> String {
    digest(format!("{}\n{}", key.scope(), key.client_id()).as_bytes())
}
impl rumqttc::SessionStore for ProtocolStore {
    fn load<'a>(
        &'a self,
        key: &'a rumqttc::SessionStoreKey,
    ) -> CheckpointFuture<'a, Option<rumqttc::PersistedSession>> {
        Box::pin(async move {
            let db = self.store.snapshot();
            let Some(row) = db
                .get("relay-protocol")
                .and_then(|t| t.get(&checkpoint_key(key)))
            else {
                return Ok(None);
            };
            let encoded = s(row, "checkpoint");
            if encoded.len() > 24 * 1024 * 1024 {
                return Err(std::io::Error::other("Relay checkpoint exceeds limit").into());
            }
            let bytes = B64.decode(encoded)?;
            Ok(Some(rumqttc::PersistedSession::decode(&bytes)?))
        })
    }
    fn save<'a>(
        &'a self,
        key: &'a rumqttc::SessionStoreKey,
        session: &'a rumqttc::PersistedSession,
    ) -> CheckpointFuture<'a, ()> {
        Box::pin(async move {
            let bytes = session.encode()?;
            if bytes.len() > 16 * 1024 * 1024 {
                return Err(std::io::Error::other("Relay checkpoint exceeds limit").into());
            }
            let encoded = B64.encode(bytes);
            let key = checkpoint_key(key);
            let store = self.store.clone();
            tokio::task::spawn_blocking(move || {
                store.update(|db| {
                    table(db, "relay-protocol").insert(key, json!({"checkpoint":encoded}));
                    Ok(())
                })
            })
            .await??;
            Ok(())
        })
    }
    fn clear<'a>(&'a self, key: &'a rumqttc::SessionStoreKey) -> CheckpointFuture<'a, ()> {
        Box::pin(async move {
            let key = checkpoint_key(key);
            let store = self.store.clone();
            tokio::task::spawn_blocking(move || {
                store.update(|db| {
                    table(db, "relay-protocol").remove(&key);
                    Ok(())
                })
            })
            .await??;
            Ok(())
        })
    }
}

struct Pending {
    peer: String,
    sender: oneshot::Sender<Result<Value>>,
    sent: bool,
}
struct Seen {
    expires: Instant,
    digest: String,
    reply: Option<Value>,
}
#[derive(Default)]
pub struct Runtime {
    client: Mutex<Option<AsyncClient>>,
    pending: Mutex<BTreeMap<String, Pending>>,
    seen: Mutex<BTreeMap<String, Seen>>,
    connected: AtomicBool,
    ready: tokio::sync::Notify,
}
impl Runtime {
    fn pause(&self) {
        self.connected.store(false, Ordering::Release);
        if let Ok(mut client) = self.client.lock() {
            *client = None;
        }
    }
    fn disconnect(&self) {
        self.pause();
        if let Ok(mut pending) = self.pending.lock() {
            let sent = pending
                .iter()
                .filter(|(_, p)| p.sent)
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>();
            for id in sent {
                if let Some(p) = pending.remove(&id) {
                    let _ = p
                        .sender
                        .send(Err(Error::unavailable("Relay connection interrupted")));
                }
            }
        }
    }
    fn in_flight(&self) -> bool {
        self.pending
            .lock()
            .map(|p| p.values().any(|p| p.sent))
            .unwrap_or(true)
    }
}
async fn connected_client(runtime: &Runtime, correlation: Option<&str>) -> Result<AsyncClient> {
    loop {
        let ready = runtime.ready.notified();
        tokio::pin!(ready);
        ready.as_mut().enable();
        {
            let client = runtime
                .client
                .lock()
                .map_err(|_| Error::unavailable("Relay runtime unavailable"))?;
            if let Some(client) = client.as_ref() {
                // Mark it while holding the client lock, before pause can
                // decide that rotation has no in-flight requests to drain.
                if let Some(id) = correlation {
                    runtime
                        .pending
                        .lock()
                        .map_err(|_| Error::unavailable("Relay runtime unavailable"))?
                        .get_mut(id)
                        .ok_or_else(|| Error::unavailable("Relay request cancelled"))?
                        .sent = true;
                }
                return Ok(client.clone());
            }
        }
        ready.await;
    }
}
pub fn status(app: &App) -> Value {
    json!({"configured":app.config.federation.is_some(),"connected":app.federation.relay.connected.load(Ordering::Acquire),"profile":"ah-gt-1","endToEndEncrypted":true,"broker":app.config.federation.as_ref().map(|c|format!("{}:{}",c.host,c.port)),"inbox":format!("arrowhead/relay/{}/{}/in/#",app.config.cloud_suffix.split('.').next().unwrap(),app.config.role)})
}
#[derive(Debug)]
struct Pinned {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    expected: String,
}
impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server: &ServerName<'_>,
        ocsp: &[u8],
        time: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let verified = self
            .inner
            .verify_server_cert(leaf, intermediates, server, ocsp, time)?;
        let cert = openssl::x509::X509::from_der(leaf.as_ref())
            .map_err(|_| rustls::Error::General("Malformed relay certificate".into()))?;
        let names = cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .collect::<Vec<_>>();
        if names.len() != 1 || names[0].data().to_string().ok().as_deref() != Some(&self.expected) {
            return Err(rustls::Error::General("Unexpected relay identity".into()));
        }
        Ok(verified)
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(m, c, d)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
fn tls(config: &Config) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&std::fs::read(&config.ca)?) {
        roots
            .add(cert.map_err(|_| Error::bad("Invalid relay root"))?)
            .map_err(|_| Error::bad("Invalid relay root"))?;
    }
    let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| Error::bad("Invalid relay verifier"))?;
    let chain = CertificateDer::pem_slice_iter(&std::fs::read(&config.certificate)?)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Error::bad("Invalid relay chain"))?;
    let key = PrivateKeyDer::from_pem_slice(&config::secret(&config.private_key)?)
        .map_err(|_| Error::bad("Invalid relay key"))?;
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            inner: verifier,
            expected: config.relay_common_name.clone(),
        }))
        .with_client_auth_cert(chain, key)
        .map_err(|_| Error::bad("Relay credential mismatch"))?;
    tls.resumption = rustls::client::Resumption::disabled();
    Ok(tls)
}
async fn send(app: &App, sender: &AsyncClient, target: &str, mut message: Value) -> Result<()> {
    if !message.is_object() {
        return Err(Error::bad("Relay object required"));
    }
    if s(&message, "id").is_empty() {
        message["id"] = id().into();
    }
    let payload = serde_json::to_vec(&message)?;
    if payload.len() > 2 * 1024 * 1024 {
        return Err(Error::new(413, "Relay message exceeds limit"));
    }
    let topic = format!(
        "arrowhead/relay/{target}/{}/in/{}/{}",
        app.config.role,
        own_cn(app),
        s(&message, "id")
    );
    let notice = sender
        .publish_tracked(topic, payload, rumqttc::PublishOptions::at_least_once())
        .await
        .map_err(|_| Error::unavailable("Relay publisher unavailable"))?;
    tokio::time::timeout(Duration::from_secs(10), notice.wait_completion_async())
        .await
        .map_err(|_| Error::new(504, "Relay publish timeout"))?
        .map_err(|_| Error::new(502, "Relay publish refused"))?;
    Ok(())
}
struct PendingGuard {
    app: App,
    id: String,
}
impl Drop for PendingGuard {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.app.federation.relay.pending.lock() {
            pending.remove(&self.id);
        }
    }
}
pub async fn request(app: &App, expected: &str, mut message: Value) -> Result<Value> {
    if !trusted(app, expected) {
        return Err(Error::denied());
    }
    let correlation = id();
    let (sender, receiver) = oneshot::channel();
    {
        let mut pending = app
            .federation
            .relay
            .pending
            .lock()
            .map_err(|_| Error::unavailable("Relay runtime unavailable"))?;
        if pending.len() >= 128 {
            return Err(Error::unavailable("Relay request capacity reached"));
        }
        pending.insert(
            correlation.clone(),
            Pending {
                peer: expected.into(),
                sender,
                sent: false,
            },
        );
    }
    let _guard = PendingGuard {
        app: app.clone(),
        id: correlation.clone(),
    };
    message["correlationId"] = correlation.into();
    let target = expected.split('.').nth(1).ok_or_else(Error::denied)?;
    tokio::time::timeout(Duration::from_secs(15), async {
        // Waiting is bounded by the same 128-slot request table and overall
        // deadline. Never retry a request after it may have been published.
        let client = connected_client(&app.federation.relay, Some(&_guard.id)).await?;
        if !trusted(app, expected) {
            return Err(Error::denied());
        }
        send(app, &client, target, message).await?;
        receiver
            .await
            .map_err(|_| Error::unavailable("Relay connection interrupted"))?
    })
    .await
    .map_err(|_| Error::new(504, "Relay request timeout"))?
}
fn disconnect(app: &App) {
    app.federation.relay.disconnect();
}
async fn receive(
    app: App,
    client: AsyncClient,
    topic: Vec<u8>,
    data: Vec<u8>,
    retained: bool,
) -> Result<()> {
    if retained || data.len() > 2 * 1024 * 1024 {
        return Ok(());
    }
    let topic = std::str::from_utf8(&topic).map_err(|_| Error::bad("Invalid relay topic"))?;
    let parts = topic.split('/').collect::<Vec<_>>();
    let own = app.config.cloud_suffix.split('.').next().unwrap();
    if parts.len() != 7
        || parts[0] != "arrowhead"
        || parts[1] != "relay"
        || parts[2] != own
        || parts[3] != app.config.role
        || parts[4] != "in"
        || !trusted(&app, parts[5])
    {
        return Ok(());
    }
    let message: Value = serde_json::from_slice(&data)?;
    if !message.is_object()
        || s(&message, "id") != parts[6]
        || parts[6].len() > 128
        || parts[6].is_empty()
    {
        return Ok(());
    }
    if s(&message, "type") == "reply" {
        let mut pending = app
            .federation
            .relay
            .pending
            .lock()
            .map_err(|_| Error::unavailable("Relay runtime unavailable"))?;
        if pending
            .get(s(&message, "correlationId"))
            .is_some_and(|p| p.peer == parts[5])
            && let Some(waiter) = pending.remove(s(&message, "correlationId"))
        {
            let _ = waiter.sender.send(Ok(message));
        }
        return Ok(());
    }
    if s(&message, "correlationId").is_empty() || s(&message, "correlationId").len() > 128 {
        return Ok(());
    }
    let key = format!("{}/{}", parts[5], parts[6]);
    let digest = digest(&data);
    let cached = {
        let mut seen = app
            .federation
            .relay
            .seen
            .lock()
            .map_err(|_| Error::unavailable("Relay runtime unavailable"))?;
        seen.retain(|_, v| v.expires > Instant::now());
        if let Some(previous) = seen.get(&key) {
            if previous.digest != digest {
                return Ok(());
            }
            if let Some(reply) = &previous.reply {
                Some(reply.clone())
            } else {
                return Ok(());
            }
        } else {
            if seen.len() >= 4096 {
                return Ok(());
            }
            seen.insert(
                key.clone(),
                Seen {
                    expires: Instant::now() + Duration::from_secs(120),
                    digest,
                    reply: None,
                },
            );
            None
        }
    };
    let reply = if let Some(reply) = cached {
        reply
    } else {
        let mut result=tokio::time::timeout(Duration::from_secs(12),super::incoming(&app,parts[5],&message)).await.ok().and_then(std::result::Result::ok).unwrap_or_else(||json!({"accepted":false,"error":"Relay operation refused","reason":"Relay operation refused"}));
        result["id"] = id().into();
        result["type"] = "reply".into();
        result["correlationId"] = message["correlationId"].clone();
        if let Ok(mut seen) = app.federation.relay.seen.lock()
            && let Some(seen) = seen.get_mut(&key)
        {
            seen.reply = Some(result.clone());
        }
        result
    };
    send(&app, &client, parts[5].split('.').nth(1).unwrap(), reply).await
}
pub async fn worker(app: App, mut stop: tokio::sync::watch::Receiver<bool>) {
    let Some(config) = app.config.federation.as_ref() else {
        return;
    };
    loop {
        let result = async {
            crypto::Identity::load(config, &own_cn(&app))?;
            let mut options = MqttOptions::new(
                format!("{}-rust-v1", own_cn(&app)),
                (config.host.as_str(), config.port),
            );
            options.set_transport(Transport::tls_with_config(TlsConfiguration::Rustls(
                Arc::new(tls(config)?),
            )));
            options.set_keep_alive(30);
            // Preserve broker-queued QoS1 messages across the short, mandatory
            // credential revalidation reconnect. Message/sequence replay guards
            // still apply; no expired or revoked credentials are retained.
            options.set_clean_start(false);
            options.set_session_expiry_interval(Some(120));
            options.set_session_store_scope(format!(
                "{}:{}:{}",
                config.host,
                config.port,
                own_cn(&app)
            ));
            options.set_session_store(ProtocolStore {
                store: app.store.clone(),
            });
            options.set_receive_maximum(Some(16));
            options.set_max_packet_size(Some(2 * 1024 * 1024));
            let (client, mut events) = AsyncClient::builder(options).capacity(64).build();
            let mut jobs = tokio::task::JoinSet::new();
            let deadline = tokio::time::sleep(Duration::from_secs(55));
            tokio::pin!(deadline);
            let hard_deadline = tokio::time::sleep(Duration::from_secs(60));
            tokio::pin!(hard_deadline);
            let mut drain_check = tokio::time::interval(Duration::from_millis(100));
            let mut draining = false;
            loop {
                tokio::select! {
                    _=stop.changed()=>{jobs.abort_all();return Ok::<bool,Error>(false);},
                    _=&mut deadline,if !draining=>{app.federation.relay.pause();draining=true;},
                    _=&mut hard_deadline=>{jobs.abort_all();return Ok(true);},
                    _=drain_check.tick(),if draining=>{if jobs.is_empty()&&!app.federation.relay.in_flight(){return Ok(true);}},
                    _=jobs.join_next(),if !jobs.is_empty()=>{},
                    event=events.poll()=>match event.map_err(|_|Error::unavailable("Relay connection unavailable"))? {
                        Event::Incoming(Incoming::ConnAck(_))=>{client.subscribe(format!("arrowhead/relay/{}/{}/in/#",app.config.cloud_suffix.split('.').next().unwrap(),app.config.role),QoS::AtLeastOnce).await.map_err(|_|Error::unavailable("Relay subscription unavailable"))?;},
                        Event::Incoming(Incoming::SubAck(ack))=>{if ack.return_codes.iter().any(|v|!matches!(v,rumqttc::mqttbytes::v5::SubscribeReasonCode::Success(_))){return Err(Error::denied());}
                            if !draining{*app.federation.relay.client.lock().map_err(|_|Error::unavailable("Relay runtime unavailable"))?=Some(client.clone());app.federation.relay.connected.store(true,Ordering::Release);app.federation.relay.ready.notify_waiters();}},
                        Event::Incoming(Incoming::Publish(message)) if jobs.len()<32=>{jobs.spawn(receive(app.clone(),client.clone(),message.topic.to_vec(),message.payload.to_vec(),message.retain));},
                        _=>{}
                    }
                }
            }
        };
        let scheduled = result.await.is_ok_and(|scheduled| scheduled);
        disconnect(&app);
        if *stop.borrow() {
            break;
        }
        if !scheduled {
            tokio::select! {_=stop.changed()=>break,_=tokio::time::sleep(Duration::from_secs(2))=>{}}
        }
    }
    disconnect(&app);
}
#[cfg(test)]
mod tests {
    use super::*;
    use rumqttc::SessionStore;
    #[tokio::test]
    async fn protocol_checkpoint_roundtrips_and_is_scoped_and_fail_closed() {
        let store = ProtocolStore {
            store: Arc::new(Store::memory()),
        };
        let key = rumqttc::SessionStoreKey::new("broker", "client");
        let session = rumqttc::PersistedSession {
            format_version: 1,
            client_id: "client".into(),
            clean_start: false,
            session_expiry_interval: Some(120),
            outgoing_inflight_upper_limit: None,
            ack_mode: rumqttc::PersistedAckMode::Automatic,
            last_pkid: 0,
            last_puback: 0,
            replay: vec![],
            incoming_qos2: vec![],
        };
        store.save(&key, &session).await.unwrap();
        assert_eq!(store.load(&key).await.unwrap(), Some(session));
        assert!(
            store
                .load(&rumqttc::SessionStoreKey::new("other", "client"))
                .await
                .unwrap()
                .is_none()
        );
        store
            .store
            .update(|db| {
                table(db, "relay-protocol")
                    .get_mut(&checkpoint_key(&key))
                    .unwrap()["checkpoint"] = "not-valid-base64".into();
                Ok(())
            })
            .unwrap();
        assert!(store.load(&key).await.is_err());
        store.clear(&key).await.unwrap();
        assert!(store.load(&key).await.unwrap().is_none());
    }
    #[test]
    fn disconnect_does_not_fail_a_request_that_was_never_sent() {
        let runtime = Runtime::default();
        let (a, mut sent) = oneshot::channel();
        let (b, mut unsent) = oneshot::channel();
        runtime.pending.lock().unwrap().insert(
            "a".into(),
            Pending {
                peer: "peer".into(),
                sender: a,
                sent: true,
            },
        );
        runtime.pending.lock().unwrap().insert(
            "b".into(),
            Pending {
                peer: "peer".into(),
                sender: b,
                sent: false,
            },
        );
        assert!(runtime.in_flight());
        runtime.disconnect();
        assert!(sent.try_recv().unwrap().is_err());
        assert!(matches!(
            unsent.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert!(!runtime.in_flight());
        assert_eq!(runtime.pending.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn unsent_request_waits_for_connection_without_network_polling() {
        let runtime = Runtime::default();
        let wait = connected_client(&runtime, None);
        tokio::pin!(wait);
        assert!(
            tokio::time::timeout(Duration::from_millis(5), &mut wait)
                .await
                .is_err()
        );
        let (client, _) = AsyncClient::builder(MqttOptions::new("test", ("localhost", 8883)))
            .capacity(1)
            .build();
        *runtime.client.lock().unwrap() = Some(client);
        runtime.ready.notify_waiters();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), wait)
                .await
                .unwrap()
                .is_ok()
        );
    }
}
