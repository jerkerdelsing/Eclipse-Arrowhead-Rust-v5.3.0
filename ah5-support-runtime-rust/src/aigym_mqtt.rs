// SPDX-License-Identifier: EPL-2.0
use crate::*;
use arrowhead_messaging_rust::rumqttc::{
    AsyncClient, Event, Incoming, MqttOptions, QoS, TlsConfiguration, Transport,
};
use std::time::{Duration, Instant};
const REQUEST_CAPACITY: usize = 8;
fn options(host: &str, port: u16) -> MqttOptions {
    let mut options = MqttOptions::new("AIGym-native", (host, port));
    // The event loop yields its buffered incoming messages before draining
    // outgoing requests. Do not let a QoS-1 burst fill the ACK request channel
    // while this same task is responsible for polling that channel.
    options.set_receive_maximum(Some(4));
    options
}
pub fn receive(app: &App, topic: &str, bytes: &[u8]) -> Result<()> {
    if bytes.len() > 1024 * 1024 {
        return Err(Error::bad("Observation exceeds one MiB"));
    }
    let parts = topic.split('/').collect::<Vec<_>>();
    let cloud = app.config.cloud_suffix.split('.').next().unwrap();
    if parts.len() != 6
        || parts[0] != "arrowhead"
        || parts[1] != cloud
        || parts[2] != "sysmonitor"
        || parts[3] != "data"
    {
        return Err(Error::bad("Foreign telemetry topic"));
    }
    let value: Value = serde_json::from_slice(bytes)?;
    if value["providerSystem"] != parts[5]
        || value["observationType"] != parts[4]
        || s(&value, "observationId").is_empty()
        || !s(&value, "schemaVersion").starts_with("1.")
    {
        return Err(Error::bad("Telemetry topic/payload mismatch"));
    }
    chrono::DateTime::parse_from_rfc3339(s(&value, "sourceTime"))
        .map_err(|_| Error::bad("Invalid observation time"))?;
    app.store.update(|db| {
        let table = table(db, "ai-observations");
        let id = s(&value, "observationId");
        if let Some(previous) = table.get(id) {
            if previous != &value {
                return Err(Error::new(409, "Observation ID conflict"));
            }
            return Ok(());
        }
        if table.len() >= 1000
            && let Some(old) = table
                .iter()
                .min_by_key(|(_, v)| s(v, "sourceTime"))
                .map(|(k, _)| k.clone())
        {
            table.remove(&old);
        }
        table.insert(id.to_string(), value);
        Ok(())
    })
}
pub async fn worker(app: App, mut stop: tokio::sync::watch::Receiver<bool>) {
    let config = app.config.messaging.as_ref().expect("configured worker");
    loop {
        let result = async {
            let mut options = options(&config.mqtt_host, config.mqtt_port);
            options.set_transport(Transport::tls_with_config(TlsConfiguration::Rustls(
                Arc::new(app.remote.tls_config(&format!(
                    "{}.{}",
                    config.mqtt_identity, app.config.cloud_suffix
                ))?),
            )));
            options.set_keep_alive(30);
            options.set_max_packet_size(Some(1024 * 1024));
            options.set_ack_mode(arrowhead_messaging_rust::rumqttc::AckMode::Manual);
            let (client, mut events) = AsyncClient::builder(options)
                .capacity(REQUEST_CAPACITY)
                .build();
            let started = Instant::now();
            let cloud = app.config.cloud_suffix.split('.').next().unwrap();
            loop {
                if started.elapsed() >= Duration::from_secs(55) {
                    let _ = client.try_disconnect();
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
                }
                let event = match tokio::time::timeout(Duration::from_secs(10), events.poll()).await
                {
                    Ok(result) => result?,
                    Err(_) => continue,
                };
                match event {
                    Event::Incoming(Incoming::ConnAck(_)) => {
                        client
                            .subscribe(
                                format!("arrowhead/{cloud}/sysmonitor/data/+/+"),
                                QoS::AtLeastOnce,
                            )
                            .await?;
                        *app.monitor_runtime
                            .lock()
                            .map_err(|_| "Runtime state lock")? = json!({"mqttConnected":true});
                    }
                    Event::Incoming(Incoming::Publish(message)) => {
                        match std::str::from_utf8(&message.topic)
                            .map_err(|_| Error::bad("Invalid topic encoding"))
                            .and_then(|topic| receive(&app, topic, &message.payload))
                        {
                            Ok(()) => client.try_ack(&message)?,
                            Err(e) if e.code < 500 => client.try_ack(&message)?,
                            Err(e) => return Err(e.into()),
                        }
                    }
                    _ => {}
                }
            }
        };
        tokio::select! {_=stop.changed()=>break,_=result=>{}}
        if let Ok(mut runtime) = app.monitor_runtime.lock() {
            *runtime = json!({"mqttConnected":false});
        }
        tokio::select! {_=stop.changed()=>break,_=tokio::time::sleep(Duration::from_secs(2))=>{}}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrowhead_messaging_rust::rumqttc::mqttbytes::v5::Publish;
    #[test]
    fn qos1_window_cannot_fill_ack_queue_and_overflow_does_not_wait() {
        let options = options("localhost", 8883);
        assert!(usize::from(options.receive_maximum().unwrap()) < REQUEST_CAPACITY);
        let (client, _events) = AsyncClient::builder(options)
            .capacity(REQUEST_CAPACITY)
            .build();
        for id in 1..=REQUEST_CAPACITY {
            let mut message = Publish::new("bounded/test", QoS::AtLeastOnce, vec![1], None);
            message.pkid = id as u16;
            client.try_ack(&message).unwrap();
        }
        let mut overflow = Publish::new("bounded/test", QoS::AtLeastOnce, vec![1], None);
        overflow.pkid = 99;
        assert!(client.try_ack(&overflow).is_err());
    }
}
