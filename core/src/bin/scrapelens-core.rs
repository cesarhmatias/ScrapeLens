//! CLI mínimo do core. Sem rede, sem telemetria; só lê/grava arquivos locais.
//!
//! Uso:
//!   scrapelens-core inspect <sessao>
//!   scrapelens-core import-har <har> --out <sessao> [--label <rótulo>]...
//!   scrapelens-core import-netlog <netlog> --out <sessao> [--label <rótulo>]...
//!   scrapelens-core import-capture <cdp.jsonl> <netlog.json> --out <sessao> [--bodies <cdp-bodies.jsonl>] [--label <rótulo>]...
//!   scrapelens-core search <sessao> <texto> [--scope url|requestHeaders|responseHeaders|cookies|requestBody|responseBody]... [--case-sensitive]
//!   scrapelens-core export-curl <sessao> <requestId> [--out arquivo]
//!   scrapelens-core export-python <sessao> <requestId> [--out arquivo]
//!   scrapelens-core sanitize <sessao> <saida>
//!   scrapelens-core diff <sessao> <requestIdA> <requestIdB>

use std::path::PathBuf;
use std::process::ExitCode;

use scrapelens_core::correlate::CorrelationOptions;
use scrapelens_core::diff::{diff_requests, DiffOptions};
use scrapelens_core::export::{curl, python, sanitize};
use scrapelens_core::parse::{import_capture_labeled, import_har, import_netlog, ImportedSession};
use scrapelens_core::store;

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("erro: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(mut args: Vec<String>) -> Result<(), String> {
    if args.is_empty() {
        return Err(usage());
    }
    let command = args.remove(0);
    match command.as_str() {
        "inspect" => {
            let path = one_path(&args)?;
            let imported = scrapelens_core::import_session_dir(&path).map_err(|e| e.to_string())?;
            print_json(&serde_json::json!({
                "session": imported.bundle.session,
                "report": imported.report,
            }))
        }
        "import-har" => {
            let (path, out) = input_and_out(&args)?;
            let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let mut imported = import_har(&bytes).map_err(|e| e.to_string())?;
            add_labels(&mut imported, &cli_labels(&args)?);
            write_imported(&imported, &out)
        }
        "import-netlog" => {
            let (path, out) = input_and_out(&args)?;
            let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let mut imported = import_netlog(&bytes).map_err(|e| e.to_string())?;
            add_labels(&mut imported, &cli_labels(&args)?);
            write_imported(&imported, &out)
        }
        "import-capture" => {
            if args.len() < 4 {
                return Err(usage());
            }
            let cdp_path = PathBuf::from(&args[0]);
            let netlog_path = PathBuf::from(&args[1]);
            let out = PathBuf::from(
                args.iter()
                    .position(|arg| arg == "--out")
                    .and_then(|index| args.get(index + 1))
                    .ok_or_else(|| "--out <sessao> é obrigatório".to_string())?,
            );
            let cdp =
                std::fs::read(&cdp_path).map_err(|e| format!("{}: {e}", cdp_path.display()))?;
            let netlog = std::fs::read(&netlog_path)
                .map_err(|e| format!("{}: {e}", netlog_path.display()))?;
            let bodies_path = match args.iter().position(|arg| arg == "--bodies") {
                Some(index) => Some(PathBuf::from(
                    args.get(index + 1)
                        .ok_or_else(|| "--bodies exige um caminho".to_string())?,
                )),
                None => scrapelens_core::parse::cdp_bodies::sibling_candidates(&cdp_path)
                    .into_iter()
                    .find(|candidate| candidate.is_file()),
            };
            let bodies = match &bodies_path {
                Some(path) => {
                    Some(std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?)
                }
                None => None,
            };
            let imported = import_capture_labeled(
                &cdp,
                &netlog,
                bodies.as_deref(),
                &cli_labels(&args)?,
                CorrelationOptions::default(),
            )
            .map_err(|e| e.to_string())?;
            write_imported(&imported, &out)
        }
        "search" => search_command(&args),
        "export-curl" => export_request(&args, true),
        "export-python" => export_request(&args, false),
        "sanitize" => {
            if args.len() != 2 {
                return Err(usage());
            }
            let input = PathBuf::from(&args[0]);
            let output = PathBuf::from(&args[1]);
            let imported =
                scrapelens_core::import_session_dir(&input).map_err(|e| e.to_string())?;
            let export =
                sanitize::sanitize_bundle(&imported.bundle, &sanitize::SanitizeOptions::default());
            export.write_to(&output).map_err(|e| e.to_string())?;
            print_json(&serde_json::json!({
                "output": output.display().to_string(),
                "redactions": export.redactions,
                "omittedAttachments": export.omitted_attachments,
                "warnings": export.warnings,
            }))
        }
        "diff" => {
            if args.len() != 3 {
                return Err(usage());
            }
            let path = PathBuf::from(&args[0]);
            let imported = scrapelens_core::import_session_dir(&path).map_err(|e| e.to_string())?;
            let a = imported
                .bundle
                .session
                .find_request(&args[1])
                .ok_or_else(|| format!("requisição {} não encontrada", args[1]))?;
            let b = imported
                .bundle
                .session
                .find_request(&args[2])
                .ok_or_else(|| format!("requisição {} não encontrada", args[2]))?;
            let diff = diff_requests(a, b, &DiffOptions::default());
            print_json(&diff)
        }
        "help" | "--help" | "-h" => {
            println!("{}", usage());
            Ok(())
        }
        other => Err(format!("comando desconhecido: {other}\n\n{}", usage())),
    }
}

fn search_command(args: &[String]) -> Result<(), String> {
    use scrapelens_core::search::{Scope, SearchQuery};
    if args.len() < 2 {
        return Err(usage());
    }
    let (lazy, _report) = scrapelens_core::open_session_dir_lazy(&PathBuf::from(&args[0]))
        .map_err(|e| e.to_string())?;
    let mut query = SearchQuery::new(args[1].clone());
    let mut rest = args[2..].iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--case-sensitive" => query.case_sensitive = true,
            "--scope" => {
                let value = rest
                    .next()
                    .ok_or_else(|| "--scope exige um valor".to_string())?;
                query.scopes.push(
                    Scope::parse(value).ok_or_else(|| format!("escopo desconhecido: {value}"))?,
                );
            }
            other => return Err(format!("argumento desconhecido: {other}\n\n{}", usage())),
        }
    }
    print_json(&scrapelens_core::search::search_lazy(&lazy, &query))
}

fn export_request(args: &[String], is_curl: bool) -> Result<(), String> {
    if args.len() < 2 {
        return Err(usage());
    }
    let path = PathBuf::from(&args[0]);
    let request_id = &args[1];
    let imported = scrapelens_core::import_session_dir(&path).map_err(|e| e.to_string())?;
    let request = imported
        .bundle
        .session
        .find_request(request_id)
        .ok_or_else(|| format!("requisição {request_id} não encontrada"))?;
    let body = scrapelens_core::export::request_body_bytes(&imported.bundle, request);
    let options = scrapelens_core::export::ExportOptions::default();
    let output = if is_curl {
        curl::to_curl(request, body, &options).map_err(|e| e.to_string())?
    } else {
        python::to_python(request, body, &options).map_err(|e| e.to_string())?
    };
    for warning in &output.warnings {
        eprintln!("aviso [{}]: {}", warning.code, warning.message);
    }
    match args.iter().position(|arg| arg == "--out") {
        Some(index) => {
            let out = args
                .get(index + 1)
                .ok_or_else(|| "--out exige um caminho".to_string())?;
            std::fs::write(out, output.text).map_err(|e| format!("{out}: {e}"))?;
            println!("{out}");
            Ok(())
        }
        None => {
            print!("{}", output.text);
            Ok(())
        }
    }
}

/// Rótulos de `--label <rótulo>` (repetível).
fn cli_labels(args: &[String]) -> Result<Vec<String>, String> {
    let mut labels = Vec::new();
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--label" {
            let value = args
                .get(index + 1)
                .ok_or_else(|| "--label exige um valor".to_string())?;
            labels.push(value.clone());
            index += 1;
        }
        index += 1;
    }
    Ok(labels)
}

fn add_labels(imported: &mut ImportedSession, labels: &[String]) {
    for label in labels {
        if !imported.bundle.session.session.labels.contains(label) {
            imported.bundle.session.session.labels.push(label.clone());
        }
    }
}

fn write_imported(imported: &ImportedSession, out: &std::path::Path) -> Result<(), String> {
    store::write_session_dir(&imported.bundle, out).map_err(|e| e.to_string())?;
    print_json(&serde_json::json!({
        "output": out.display().to_string(),
        "requests": imported.bundle.session.requests.len(),
        "warnings": imported.report.warnings.len(),
    }))
}

fn one_path(args: &[String]) -> Result<PathBuf, String> {
    if args.len() != 1 {
        return Err(usage());
    }
    Ok(PathBuf::from(&args[0]))
}

fn input_and_out(args: &[String]) -> Result<(PathBuf, PathBuf), String> {
    let path = args.first().ok_or_else(|| usage())?;
    let index = args
        .iter()
        .position(|arg| arg == "--out")
        .ok_or_else(|| "--out <sessao> é obrigatório".to_string())?;
    let out = args
        .get(index + 1)
        .ok_or_else(|| "--out exige um caminho".to_string())?;
    Ok((PathBuf::from(path), PathBuf::from(out)))
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    println!("{text}");
    Ok(())
}

fn usage() -> String {
    "uso:
  scrapelens-core inspect <sessao>
  scrapelens-core import-har <har> --out <sessao> [--label <rótulo>]...
  scrapelens-core import-netlog <netlog> --out <sessao> [--label <rótulo>]...
  scrapelens-core import-capture <cdp.jsonl> <netlog.json> --out <sessao> [--bodies <cdp-bodies.jsonl>] [--label <rótulo>]...
  scrapelens-core search <sessao> <texto> [--scope <escopo>]... [--case-sensitive]
  scrapelens-core export-curl <sessao> <requestId> [--out arquivo]
  scrapelens-core export-python <sessao> <requestId> [--out arquivo]
  scrapelens-core sanitize <sessao> <saida>
  scrapelens-core diff <sessao> <requestIdA> <requestIdB>"
        .to_string()
}
