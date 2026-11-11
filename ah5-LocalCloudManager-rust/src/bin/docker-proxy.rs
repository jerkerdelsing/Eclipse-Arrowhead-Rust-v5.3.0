#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    arrowhead_localcloudmanager_rust::docker_proxy::run().await
}
