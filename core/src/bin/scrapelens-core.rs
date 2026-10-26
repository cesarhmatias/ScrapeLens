//! CLI mínimo do core. Sem rede, sem telemetria; só lê/grava arquivos locais.
//!
//! Uso:
//!   scrapelens-core inspect <sessao>
//!   scrapelens-core import-har <har> --out <sessao>
//!   scrapelens-core import-netlog <netlog> --out <sessao>
//!   scrapelens-core import-capture <cdp.jsonl> <netlog.json> --out <sessao>
//!   scrapelens-core export-curl <sessao> <requestId> [--out arquivo]
//!   scrapelens-core export-python <sessao> <requestId> [--out arquivo]
//!   scrapelens-core sanitize <sessao> <saida>
//!   scrapelens-core diff <sessao> <requestIdA> <requestIdB>

use std::path::PathBuf;
use std::process::ExitCode;

use scrapelens_core::correlate::CorrelationOptions;
use scrapelens_core::diff::{diff_requests, DiffOptions};
use scrapelens_core::export::{curl, python, sanitize};
use scrapelens_core::parse::{import_capture, import_har, import_netlog, ImportedSession};
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
            let imported = import_har(&bytes).map_err(|e| e.to_string())?;
            write_imported(&imported, &out)
        }
        "import-netlog" => {
            let (path, out) = input_and_out(&args)?;
            let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let imported = import_netlog(&bytes).map_err(|e| e.to_string())?;
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
            let imported = import_capture(&cdp, &netlog, CorrelationOptions::default())
                .map_err(|e| e.to_string())?;
            write_imported(&imported, &out)
        }
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
    let body = request
        .request_body
        .attachment
        .as_deref()
        .and_then(|name| imported.bundle.attachment(name));
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
  scrapelens-core import-har <har> --out <sessao>
  scrapelens-core import-netlog <netlog> --out <sessao>
  scrapelens-core import-capture <cdp.jsonl> <netlog.json> --out <sessao>
  scrapelens-core export-curl <sessao> <requestId> [--out arquivo]
  scrapelens-core export-python <sessao> <requestId> [--out arquivo]
  scrapelens-core sanitize <sessao> <saida>
  scrapelens-core diff <sessao> <requestIdA> <requestIdB>"
        .to_string()
}
