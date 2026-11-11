#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    arrowhead_support_rust::runner::run(Some("gatetunnel")).await
}
