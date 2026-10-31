use std::sync::Arc;

use scrapelens_mcp::live::RealBackend;

#[tokio::main]
async fn main() {
    let config = match scrapelens_mcp::cli::parse_args(std::env::args().skip(1).collect()) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };
    let code = scrapelens_mcp::app::run(config, Arc::new(RealBackend)).await;
    std::process::exit(code);
}
