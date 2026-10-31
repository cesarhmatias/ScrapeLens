use std::path::PathBuf;
use std::process::ExitCode;

use rmcp::ServiceExt;
use scrapelens_mcp::config::DEFAULT_MAX_IMPORT_BYTES;
use scrapelens_mcp::server::ScrapeLensServer;
use scrapelens_mcp::{Config, Ctx};

const USAGE: &str = "uso: scrapelens-mcp --sessions-dir <dir> [--out-dir <dir>] [--extra-sessions-dir <dir>]... [--allow-reveal] [--max-import-bytes <n>]";

fn parse_args(args: Vec<String>) -> Result<Config, String> {
    let mut sessions: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut extras: Vec<PathBuf> = Vec::new();
    let mut allow_reveal = false;
    let mut max_import = DEFAULT_MAX_IMPORT_BYTES;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        let mut value = |name: &str| iter.next().ok_or_else(|| format!("{name} exige um valor"));
        match arg.as_str() {
            "--sessions-dir" => sessions = Some(PathBuf::from(value("--sessions-dir")?)),
            "--out-dir" => out = Some(PathBuf::from(value("--out-dir")?)),
            "--extra-sessions-dir" => extras.push(PathBuf::from(value("--extra-sessions-dir")?)),
            "--max-import-bytes" => {
                max_import = value("--max-import-bytes")?
                    .parse()
                    .map_err(|_| "--max-import-bytes: número inválido".to_string())?
            }
            "--allow-reveal" => allow_reveal = true,
            "--help" | "-h" => return Err(USAGE.to_string()),
            other => return Err(format!("argumento desconhecido: {other}\n{USAGE}")),
        }
    }
    let sessions = sessions.ok_or_else(|| format!("--sessions-dir é obrigatório\n{USAGE}"))?;
    Config::new(&sessions, out.as_deref(), &extras, allow_reveal, max_import)
        .map_err(|error| error.to_string())
}

#[tokio::main]
async fn main() -> ExitCode {
    // stdout é o canal JSON-RPC: tudo que for diagnóstico vai para stderr.
    let config = match parse_args(std::env::args().skip(1).collect()) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    eprintln!(
        "scrapelens-mcp: sessões em {} (reveal {})",
        config.sessions_dir.display(),
        if config.allow_reveal {
            "permitido"
        } else {
            "desligado"
        }
    );
    let server = ScrapeLensServer::new(Ctx::new(config));
    let service = match server.serve(rmcp::transport::stdio()).await {
        Ok(service) => service,
        Err(error) => {
            eprintln!("scrapelens-mcp: falha ao iniciar: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = service.waiting().await {
        eprintln!("scrapelens-mcp: encerrado com erro: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
