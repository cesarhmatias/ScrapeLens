//! Ciclo de vida do servidor: stdio, sinais e encerramento das capturas.

use std::sync::Arc;

use rmcp::ServiceExt;

use crate::config::Config;
use crate::live::CaptureBackend;
use crate::registry::Ctx;
use crate::server::ScrapeLensServer;

/// Espera SIGINT/SIGTERM (no Windows, só Ctrl-C).
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

/// Serve MCP por stdio até o stdin fechar ou um sinal chegar; então para todas
/// as capturas ativas de forma graciosa.
/// Devolve o código de saída; o chamador deve sair com `std::process::exit`,
/// porque a leitura bloqueada do stdin impede o runtime de terminar sozinho
/// quando a saída vem de um sinal.
pub async fn run(config: Config, backend: Arc<dyn CaptureBackend>) -> i32 {
    // stdout é o canal JSON-RPC: tudo que for diagnóstico vai para stderr.
    eprintln!(
        "scrapelens-mcp: sessões em {} (reveal {}, captura sem confirmação {})",
        config.sessions_dir.display(),
        if config.allow_reveal {
            "permitido"
        } else {
            "desligado"
        },
        if config.allow_unconfirmed_capture {
            "permitida"
        } else {
            "desligada"
        }
    );
    let server = ScrapeLensServer::new(Ctx::new(config), backend);
    let service = match server.clone().serve(rmcp::transport::stdio()).await {
        Ok(service) => service,
        Err(error) => {
            eprintln!("scrapelens-mcp: falha ao iniciar: {error}");
            return 1;
        }
    };
    let mut failed = false;
    tokio::select! {
        result = service.waiting() => {
            if let Err(error) = result {
                eprintln!("scrapelens-mcp: encerrado com erro: {error}");
                failed = true;
            }
        }
        () = termination() => {
            eprintln!("scrapelens-mcp: sinal recebido; encerrando");
        }
    }
    let stopped = server.shutdown_captures().await;
    if stopped > 0 {
        eprintln!("scrapelens-mcp: {stopped} captura(s) encerrada(s) ao sair");
    }
    i32::from(failed)
}
