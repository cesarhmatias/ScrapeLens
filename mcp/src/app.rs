//! Server lifecycle: stdio, signals and shutdown of captures.

use std::sync::Arc;

use rmcp::ServiceExt;

use crate::config::Config;
use crate::live::CaptureBackend;
use crate::registry::Ctx;
use crate::server::ScrapeLensServer;

/// Waits for SIGINT/SIGTERM (on Windows, only Ctrl-C).
async fn termination() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) {
            (Ok(mut term), Ok(mut int)) => {
                tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
            }
            _ => std::future::pending::<()>().await,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Serves MCP over stdio until stdin closes or a signal arrives; then gracefully
/// stops all active captures.
/// Returns the exit code; the caller must exit with `std::process::exit`,
/// because the blocked stdin read keeps the runtime from terminating on its own
/// when the exit comes from a signal.
pub async fn run(config: Config, backend: Arc<dyn CaptureBackend>) -> i32 {
    // stdout is the JSON-RPC channel: all diagnostics go to stderr.
    eprintln!(
        "scrapelens-mcp: sessions in {} (reveal {}, capture without confirmation {}, sensitive export without confirmation {})",
        config.sessions_dir.display(),
        if config.allow_reveal {
            "allowed"
        } else {
            "disabled"
        },
        if config.allow_unconfirmed_capture {
            "allowed"
        } else {
            "disabled"
        },
        if config.allow_sensitive_export {
            "allowed"
        } else {
            "disabled"
        }
    );
    let server = ScrapeLensServer::new(Ctx::new(config), backend);
    server.startup();
    let service = match server.clone().serve(rmcp::transport::stdio()).await {
        Ok(service) => service,
        Err(error) => {
            eprintln!("scrapelens-mcp: failed to start: {error}");
            return 1;
        }
    };
    let mut failed = false;
    tokio::select! {
        result = service.waiting() => {
            if let Err(error) = result {
                eprintln!("scrapelens-mcp: stopped with error: {error}");
                failed = true;
            }
        }
        () = termination() => {
            eprintln!("scrapelens-mcp: signal received; shutting down");
        }
    }
    let stopped = server.shutdown_captures().await;
    if stopped > 0 {
        eprintln!("scrapelens-mcp: {stopped} capture(s) stopped on exit");
    }
    i32::from(failed)
}
