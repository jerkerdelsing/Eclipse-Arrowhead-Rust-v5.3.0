// SPDX-License-Identifier: EPL-2.0
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    arrowhead_core_rust::runner::run(Some("serviceorchestration-dynamic")).await
}
