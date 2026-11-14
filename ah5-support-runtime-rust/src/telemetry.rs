// SPDX-License-Identifier: EPL-2.0
use crate::*;
use arrowhead_messaging_rust as broker;
use std::time::Duration;
pub async fn publisher(app: App, mut stop: tokio::sync::watch::Receiver<bool>) {
    let Some(config) = app.config.messaging.clone() else {
        return;
    };
    let remote = app.remote.clone();
    let tls: broker::TlsFactory = Arc::new(move |expected| Ok(remote.tls_config(expected)?));
    let mut clock = tokio::time::interval(Duration::from_secs(config.interval_seconds));
    loop {
        tokio::select! {_=stop.changed()=>break,_=clock.tick()=>{
            let result=async {
                app.remote.call("ServiceRegistry","POST","/serviceregistry/service-discovery/register",&broker::monitor_descriptor(&app.config.name,&app.config.cloud_suffix,&config)).await?;
                let mut status=json!({"state":"running","sourceTime":now(),"implementation":"rust","version":"5.4.0"});
                if app.config.role=="plantdescriptionengine" {status["synchronization"]=app.store.snapshot().get("pdeSync").and_then(|t|t.get("state")).cloned().unwrap_or(Value::Null);if status["synchronization"]["ok"]!=true{status["state"]="degraded".into();}}
                broker::publish_monitor(&config,&app.config.name,&app.config.cloud_suffix,&tls,&status).await.map_err(|_|Error::unavailable("AMQP monitor publication failed"))?;
                Ok::<_,Error>(())
            }.await;
            if let Err(e)=result {eprintln!("{} monitor publication unavailable ({})",app.config.name,e.code)}
        }}
    }
}
