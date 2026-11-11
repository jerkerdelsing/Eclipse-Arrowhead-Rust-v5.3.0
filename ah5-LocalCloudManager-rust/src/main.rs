use arrowhead_localcloudmanager_rust::{api, registry, state};

use std::{net::SocketAddr, sync::Arc};
use tower_http::{
    catch_panic::CatchPanicLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h") {
        println!(
            "LocalCloudManager (Rust): environment configuration; default http://127.0.0.1:8480/. Legacy development transport, no native TLS or sysMonitor publisher. See README.md."
        );
        return Ok(());
    }
    if !args.is_empty() {
        return Err("Unknown argument; use --help".into());
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "arrowhead_core_systems=info,tower_http=info".into()),
        )
        .init();
    let mut config = api::Config::from_env_with_default_role("localcloudmanager")?;
    if config.role != "localcloudmanager" {
        return Err("This executable only runs the localcloudmanager role".into());
    }
    // Keep the inherited HTTP transport off non-loopback interfaces by default.
    if std::env::var_os("LISTEN_ADDRESS").is_none() {
        config.listen_address = format!("127.0.0.1:{}", config.port)
    }
    let config = Arc::new(config);
    let store = Arc::new(state::Store::load(&config.data_file).await?);
    let app = api::router(config.clone(), store)
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(TraceLayer::new_for_http())
        .layer(CatchPanicLayer::new());
    let address: SocketAddr = config.listen_address.parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(role=%config.role, system=%config.system_name, %address, "Arrowhead Rust core system ready");
    tokio::spawn(registry::registration_loop(config));
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
