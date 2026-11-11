// SPDX-License-Identifier: EPL-2.0
//! Shared native AMQP/MQTT clients for the Arrowhead cloud.
use amqprs::{
    Ack, BasicProperties, Cancel, CloseChannel, Nack, Return,
    callbacks::{ChannelCallback, DefaultConnectionCallback},
    channel::{BasicPublishArguments, Channel, ConfirmSelectArguments},
    connection::{Connection, OpenConnectionArguments},
    security::SecurityCredentials,
    tls::TlsAdaptor,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub type TlsFactory = Arc<dyn Fn(&str) -> Result<rustls::ClientConfig> + Send + Sync>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub amqp_host: String,
    pub amqp_port: u16,
    pub amqp_identity: String,
    pub mqtt_host: String,
    pub mqtt_port: u16,
    pub mqtt_identity: String,
    #[serde(default = "interval")]
    pub interval_seconds: u64,
    #[serde(default = "all")]
    pub default_subscription: String,
    #[serde(default = "retention")]
    pub retention_days: u32,
}
fn interval() -> u64 {
    30
}
fn all() -> String {
    "all".into()
}
fn retention() -> u32 {
    30
}
impl Config {
    pub fn validate(&self) -> std::result::Result<(), String> {
        for host in [&self.amqp_host, &self.mqtt_host] {
            if host.is_empty()
                || host.len() > 253
                || !host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
            {
                return Err("Broker host must be an explicit DNS name or IPv4 address".into());
            }
        }
        for identity in [&self.amqp_identity, &self.mqtt_identity] {
            if identity.is_empty() || !identity.bytes().all(|b| b.is_ascii_alphanumeric()) {
                return Err("Invalid broker identity".into());
            }
        }
        if self.amqp_port == 0
            || self.mqtt_port == 0
            || !(5..=3600).contains(&self.interval_seconds)
            || !["all", "none"].contains(&self.default_subscription.as_str())
            || !(1..=3650).contains(&self.retention_days)
        {
            return Err("Invalid broker configuration".into());
        }
        Ok(())
    }
}
struct Confirms(mpsc::Sender<(u64, bool, bool)>);
#[async_trait]
impl ChannelCallback for Confirms {
    async fn close(
        &mut self,
        _: &Channel,
        _: CloseChannel,
    ) -> std::result::Result<(), amqprs::error::Error> {
        Ok(())
    }
    async fn cancel(
        &mut self,
        _: &Channel,
        _: Cancel,
    ) -> std::result::Result<(), amqprs::error::Error> {
        Ok(())
    }
    async fn flow(
        &mut self,
        _: &Channel,
        active: bool,
    ) -> std::result::Result<bool, amqprs::error::Error> {
        Ok(active)
    }
    async fn publish_ack(&mut self, _: &Channel, ack: Ack) {
        let _ = self.0.try_send((ack.delivery_tag(), ack.mutiple(), true));
    }
    async fn publish_nack(&mut self, _: &Channel, nack: Nack) {
        let _ = self
            .0
            .try_send((nack.delivery_tag(), nack.multiple(), false));
    }
    async fn publish_return(&mut self, _: &Channel, _: Return, _: BasicProperties, _: Vec<u8>) {
        let _ = self.0.try_send((0, true, false));
    }
}
pub async fn connect(
    config: &Config,
    name: &str,
    tls: &TlsFactory,
    suffix: &str,
) -> Result<Connection> {
    let mut client_config = tls(&format!("{}.{}", config.amqp_identity, suffix))?;
    client_config.alpn_protocols.clear();
    let adapter = TlsAdaptor::new(
        tokio_rustls::TlsConnector::from(Arc::new(client_config)),
        config.amqp_host.clone(),
    );
    let args = OpenConnectionArguments::default()
        .host(&config.amqp_host)
        .port(config.amqp_port)
        .credentials(SecurityCredentials::new_external())
        .heartbeat(30)
        .connection_name(name)
        .tls_adaptor(adapter)
        .finish();
    let connection =
        tokio::time::timeout(Duration::from_secs(10), Connection::open(&args)).await??;
    connection
        .register_callback(DefaultConnectionCallback)
        .await?;
    Ok(connection)
}
pub struct Publisher {
    connection: Connection,
    channel: Channel,
    confirms: mpsc::Receiver<(u64, bool, bool)>,
    sequence: u64,
    opened: Instant,
}
impl Publisher {
    pub async fn open(config: &Config, name: &str, tls: &TlsFactory, suffix: &str) -> Result<Self> {
        let connection = connect(config, name, tls, suffix).await?;
        let channel = connection.open_channel(None).await?;
        let (tx, rx) = mpsc::channel(8);
        channel.register_callback(Confirms(tx)).await?;
        channel
            .confirm_select(ConfirmSelectArguments::default())
            .await?;
        Ok(Self {
            connection,
            channel,
            confirms: rx,
            sequence: 0,
            opened: Instant::now(),
        })
    }
    pub fn usable(&self) -> bool {
        self.connection.is_open()
            && self.channel.is_open()
            && self.opened.elapsed() < Duration::from_secs(55)
    }
    pub async fn publish(&mut self, routing: &str, payload: &Value) -> Result<()> {
        let bytes = serde_json::to_vec(payload)?;
        if bytes.len() > 1024 * 1024 || routing.len() > 255 {
            return Err("Observation exceeds contract bounds".into());
        }
        self.sequence += 1;
        let properties = BasicProperties::default()
            .with_content_type("application/json")
            .with_delivery_mode(2)
            .with_message_id(payload["observationId"].as_str().unwrap_or(""))
            .finish();
        let expected = self.sequence;
        tokio::time::timeout(Duration::from_secs(10), async {
            self.channel
                .basic_publish(
                    properties,
                    bytes,
                    BasicPublishArguments::new("arrowhead", routing),
                )
                .await?;
            loop {
                let (tag, multiple, accepted) = self
                    .confirms
                    .recv()
                    .await
                    .ok_or("AMQP confirm channel closed")?;
                if tag == expected || multiple && tag >= expected || tag == 0 {
                    if accepted {
                        return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
                    }
                    return Err("AMQP publish not confirmed".into());
                }
            }
        })
        .await??;
        Ok(())
    }
    pub async fn close(self) {
        let _ = self.connection.close().await;
    }
}
pub fn observations(name: &str, cloud: &str, status: &Value) -> Vec<(String, Value)> {
    ["echo","power","status"].into_iter().map(|kind| {
        let value=match kind {"echo"=>json!({"status":"alive"}),"power"=>json!({"supplyType":"line","state":"available"}),_=>status.clone()};
        (format!("{cloud}.sysmonitor.{name}.{name}.{kind}"),json!({"schemaVersion":"1.0","observationId":uuid::Uuid::new_v4().to_string(),"providerSystem":name,"serviceInstance":name,"observationType":kind,"sourceTime":status["sourceTime"],"value":value,"unit":if kind=="echo"{Value::Null}else{json!("1")},"quality":"good","metadata":{"implementation":"rust","publisherMode":"native","arrowheadVersion":"5.2.2"}}))
    }).collect()
}
pub async fn publish_monitor(
    config: &Config,
    name: &str,
    suffix: &str,
    tls: &TlsFactory,
    status: &Value,
) -> Result<()> {
    let mut publisher = Publisher::open(config, name, tls, suffix).await?;
    for (routing, observation) in observations(
        name,
        suffix.split('.').next().ok_or("Missing cloud")?,
        status,
    ) {
        publisher.publish(&routing, &observation).await?;
    }
    publisher.close().await;
    Ok(())
}
pub use amqprs;
pub use rumqttc;

pub fn monitor_descriptor(name: &str, suffix: &str, config: &Config) -> Value {
    let cloud = suffix.split('.').next().unwrap_or("");
    json!({"serviceDefinitionName":"sysMonitor","version":"1.0.0","metadata":{"schemaVersion":"1.0","observationTypes":["echo","power","status"],"implementation":"rust"},"interfaces":[{"templateName":"generic_amqps","protocol":"amqps","policy":"CERT_AUTH","properties":{"accessAddresses":[config.amqp_host],"accessPort":config.amqp_port,"baseRoutingKey":format!("{cloud}.sysmonitor.{name}.{name}"),"exchange":"arrowhead","operations":["echo","power","status"]}}]})
}
