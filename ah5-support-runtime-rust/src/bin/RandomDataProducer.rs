#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    arrowhead_support_rust::producer::run().await
}
