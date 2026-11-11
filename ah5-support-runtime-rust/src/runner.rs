// SPDX-License-Identifier: EPL-2.0
use crate::{App, Config, Store, security, web};
use axum::Extension;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use std::{sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, watch},
    task::JoinSet,
};

pub async fn run(forced_role: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let all = std::env::args().collect::<Vec<_>>();
    let port = crate::listen::port_argument(&all[1..])?;
    let args = crate::listen::without_port_argument(&all);
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "arrowhead-support --config CONFIG.json [--server.port N]\nNative mutual-TLS Arrowhead support runtime. Configuration selects one of fifteen roles. Listening port: --server.port N > SERVER_PORT > \"listen\" in CONFIG.json > role default."
        );
        return Ok(());
    }
    let path = if args.len() == 3 && args[1] == "--config" {
        &args[2]
    } else {
        return Err("Usage: arrowhead-support --config CONFIG.json [--server.port N]".into());
    };
    let mut config = Config::load(path)?;
    if let Some(port) = port {
        config.listen = crate::listen::with_port(&config.listen, port)?;
    }
    if forced_role.is_some_and(|r| r != config.role) {
        return Err("Configuration role does not match executable".into());
    }
    let tls = security::Tls::load(&config)?;
    let store = Store::open(&config.state)?;
    let app = App::new(config.clone(), store, tls.clone())?;
    if let Some(federation) = &config.federation {
        crate::federation::crypto::Identity::load(federation, &crate::federation::own_cn(&app))?;
    }
    if config.role == "datamanager" {
        // before anything clones the state: a historian stored without retention may not fit twice in memory
        let removed = app.store.prune(|db| {
            crate::data::prune_senml(db, config.retention_days, config.max_senml_records)
        })?;
        if removed > 0 {
            eprintln!("DataManager retention removed {removed} dataHistorian records");
        }
    }
    crate::ca::validate_signer(&config)?;
    if config.role == "certificateauthority" {
        crate::ca::publish_crl(&app)?;
    }
    // only when a job was interrupted: `update` copies the whole state (a large historian twice in memory)
    let interrupted = ["sessions", "bridges"].iter().any(|bucket| {
        !app.store
            .select(bucket, |job| {
                ["STARTING", "RUNNING", "NEGOTIATING", "ABORTING"]
                    .contains(&crate::s(job, "status"))
            })
            .is_empty()
    });
    if interrupted {
        app.store.update(|db| {
            for bucket in ["sessions", "bridges"] {
                for job in crate::table(db, bucket).values_mut() {
                    if ["STARTING", "RUNNING", "NEGOTIATING", "ABORTING"]
                        .contains(&crate::s(job, "status"))
                    {
                        job["status"] = "ERROR".into();
                        job["message"] =
                            "Interrupted by restart; remote effects require reconciliation".into();
                    }
                }
            }
            Ok(())
        })?;
    }
    let listener = TcpListener::bind(&config.listen).await?;
    let router = web::router(app.clone());
    let capacity = Arc::new(Semaphore::new(128));
    let mut connections = JoinSet::new();
    let (tx, rx) = watch::channel(false);
    let mut worker = tokio::spawn(web::background(app, rx.clone()));
    eprintln!(
        "{} Rust support listening on {} (mandatory mutual TLS)",
        config.name,
        listener.local_addr()?
    );
    let signal = async {
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM handler");
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    };
    tokio::pin!(signal);
    loop {
        tokio::select! {
            _=&mut signal=>break,
            accepted=listener.accept()=>{
                let(stream,remote)=accepted?;
                let Ok(permit)=capacity.clone().try_acquire_owned()else{drop(stream);continue};
                let Ok(server)=tls.server_current() else { eprintln!("TLS material unavailable; rejecting connection"); continue };let acceptor=tokio_rustls::TlsAcceptor::from(server);let router=router.clone();let suffix=config.cloud_suffix.clone();let role=config.role.clone();let mut stopping=rx.clone();
                connections.spawn(async move {
                    let _permit=permit;
                    let handshake=tokio::time::timeout(Duration::from_secs(5),acceptor.accept(stream));
                    let stream=tokio::select! {_=stopping.changed()=>return,result=handshake=>{let Ok(Ok(stream))=result else{return};stream}};
                    let Some(cert)=stream.get_ref().1.peer_certificates().and_then(|c|c.first())else{return};
                    let Ok(peer)=crate::onboarding::admit(&role,cert.as_ref(),&suffix)else{return};
                    let app=if role=="onboarding"{router.layer(Extension(crate::onboarding::PeerCertificate{der:std::sync::Arc::new(cert.as_ref().to_vec()),address:remote.ip().to_canonical().to_string()}))}else{router};
                    let app=app.layer(Extension(peer));let mut builder=Builder::new(TokioExecutor::new());
                    builder.http1().timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(10)).max_buf_size(1024*1024);
                    builder.http2().max_concurrent_streams(16);
                    let connection=builder.serve_connection_with_upgrades(TokioIo::new(stream),TowerToHyperService::new(app));
                    tokio::pin!(connection);
                    tokio::select! {
                        _=&mut connection=>{},
                        _=stopping.changed()=>{
                            connection.as_mut().graceful_shutdown();
                            let _=tokio::time::timeout(Duration::from_secs(10),&mut connection).await;
                        },
                        _=tokio::time::sleep(Duration::from_secs(60))=>{
                            connection.as_mut().graceful_shutdown();
                            let _=tokio::time::timeout(Duration::from_secs(5),&mut connection).await;
                        }
                    }
                });
            },
            _=connections.join_next(),if !connections.is_empty()=>{}
        }
    }
    drop(listener);
    let _ = tx.send(true);
    if tokio::time::timeout(Duration::from_secs(30), &mut worker)
        .await
        .is_err()
    {
        worker.abort();
        let _ = worker.await;
    }
    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(10), drain)
        .await
        .is_err()
    {
        connections.abort_all();
    }
    Ok(())
}
