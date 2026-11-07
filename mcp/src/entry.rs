//! The MCP server's command-line entry, shared by the `scrapelens-mcp` binary and the App's
//! `scrapelens mcp` subcommand. Both run exactly this code: same hardening, same flags, same server.

use std::sync::Arc;

use crate::live::RealBackend;

/// The server's version. It is the App's version: the crate and the App share one number, and the
/// App's tests check that they match.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Runs the server with the arguments after the program name (or after `mcp`, for the App) and
/// returns the process exit code. stdout carries only the protocol; diagnostics go to stderr.
pub fn run(args: Vec<String>) -> i32 {
    crate::harden::harden_process();
    let config = match crate::cli::parse_args(args) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("scrapelens mcp: cannot start the runtime: {error}");
            return 1;
        }
    };
    runtime.block_on(crate::app::run(config, Arc::new(RealBackend)))
}
