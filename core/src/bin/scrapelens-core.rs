//! CLI mínimo do core. Sem rede, sem telemetria; só lê/grava arquivos locais.
//!
//! Uso:
//!   scrapelens-core inspect <sessao>
//!   scrapelens-core import-har <har> --out <sessao> [--label <rótulo>]...
//!   scrapelens-core import-trace <trace.json> --out <sessao> [--label <rótulo>]...
//!   scrapelens-core import-netlog <netlog> --out <sessao> [--label <rótulo>]...
//!   scrapelens-core import-capture <cdp.jsonl> <netlog.json> --out <sessao> [--bodies <cdp-bodies.jsonl>] [--label <rótulo>]...
//!   scrapelens-core search <sessao> <texto> [--scope url|requestHeaders|responseHeaders|cookies|requestBody|responseBody]... [--case-sensitive]
//!   scrapelens-core origins <sessao> <requestId>
//!   scrapelens-core chain <sessao> <requestId>
//!   scrapelens-core timeline <sessao>
//!   scrapelens-core validate <captura> <sessao-trace> [--map-origin <origem-captura>=<origem-trace>]
//!   scrapelens-core assess <sessao> [requestId] [--rules regras.json]
//!   scrapelens-core export-priming <sessao> <requestId> [--out arquivo] [--allow-incomplete] [--allow-origin <origin>] [--allow-literal-body]
//!   scrapelens-core compare <sessaoA> <sessaoB> [--a-range de:ate] [--b-range de:ate] [--all] [--map-origin <origem-A>=<origem-B>]
//!   scrapelens-core export-curl <sessao> <requestId> [--out arquivo] [--with-origins]
//!   scrapelens-core export-python <sessao> <requestId> [--out arquivo] [--with-origins]
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
            // Struct emprestada + escrita em fluxo: sem `json!` (que copia a sessão num DOM) e
            // sem a `String` gigante (docs/18 §4.2). A ordem e o formato são os de antes.
            print_json(&Inspect {
                session: &imported.bundle.session,
                report: &imported.report,
            })
        }
        "import-har" => {
            let (path, out) = input_and_out(&args)?;
            let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let mut imported = import_har(&bytes).map_err(|e| e.to_string())?;
            add_labels(&mut imported, &cli_labels(&args)?);
            write_imported(&imported, &out)
        }
        "import-trace" => {
            let (path, out) = input_and_out(&args)?;
            let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let mut imported =
                scrapelens_core::parse::import_trace(&bytes).map_err(|e| e.to_string())?;
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
        "origins" | "chain" => flow_command(&command, &args),
        "compare" => compare_command(&args),
        "assess" => assess_command(&args),
        "validate" => validate_command(&args),
        "timeline" => {
            if args.len() != 1 {
                return Err(usage());
            }
            let (lazy, _) = scrapelens_core::open_session_dir_lazy(&PathBuf::from(&args[0]))
                .map_err(|e| e.to_string())?;
            let source = scrapelens_core::search::LazyBodies(&lazy);
            let result = scrapelens_core::timeline::timeline(
                &lazy.session,
                &source,
                &scrapelens_core::timeline::TimelineOptions::default(),
            );
            print_json(&result)
        }
        "export-priming" => export_priming_command(&args),
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
            // Consome o bundle (sem a cópia da sessão; docs/18 P7).
            let export = sanitize::sanitize_bundle_owned(
                imported.bundle,
                &sanitize::SanitizeOptions::default(),
            );
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

fn compare_command(args: &[String]) -> Result<(), String> {
    use scrapelens_core::compare::{compare_sessions, CompareOptions};
    if args.len() < 2 {
        return Err(usage());
    }
    let mut options = CompareOptions::default();
    let mut rest = args[2..].iter();
    while let Some(arg) = rest.next() {
        let mut range = |name: &str| -> Result<scrapelens_core::compare::RequestRange, String> {
            let value = rest.next().ok_or_else(|| {
                format!("{name} exige um valor (ex.: 10:50 ou har-0010:har-0050)")
            })?;
            scrapelens_core::compare::RequestRange::parse(value)
                .ok_or_else(|| format!("{name}: faixa inválida {value:?}"))
        };
        match arg.as_str() {
            "--all" => options.include_all = true,
            "--a-range" => options.a_range = Some(range("--a-range")?),
            "--b-range" => options.b_range = Some(range("--b-range")?),
            "--map-origin" => {
                let value = rest.next().ok_or_else(|| {
                    "--map-origin exige <origem-captura>=<origem-trace>".to_string()
                })?;
                options.map_origin = Some(
                    scrapelens_core::compare::OriginMap::parse(value)
                        .ok_or_else(|| format!("--map-origin inválido: {value:?}"))?,
                );
            }
            other => return Err(format!("argumento desconhecido: {other}\n\n{}", usage())),
        }
    }
    let (a, _) = scrapelens_core::open_session_dir_lazy(&PathBuf::from(&args[0]))
        .map_err(|e| e.to_string())?;
    let (b, _) = scrapelens_core::open_session_dir_lazy(&PathBuf::from(&args[1]))
        .map_err(|e| e.to_string())?;
    let result = compare_sessions(
        &a.session,
        &scrapelens_core::search::LazyBodies(&a),
        &b.session,
        &scrapelens_core::search::LazyBodies(&b),
        &options,
    );
    print_json(&result)
}

fn validate_command(args: &[String]) -> Result<(), String> {
    use scrapelens_core::validate::{validate, ValidateOptions};
    if args.len() < 2 {
        return Err(usage());
    }
    let mut options = ValidateOptions::default();
    let mut rest = args[2..].iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--map-origin" => {
                let value = rest.next().ok_or_else(|| {
                    "--map-origin exige <origem-captura>=<origem-trace>".to_string()
                })?;
                options.compare.map_origin = Some(
                    scrapelens_core::compare::OriginMap::parse(value)
                        .ok_or_else(|| format!("--map-origin inválido: {value:?}"))?,
                );
            }
            other => return Err(format!("argumento desconhecido: {other}\n\n{}", usage())),
        }
    }
    let (a, _) = scrapelens_core::open_session_dir_lazy(&PathBuf::from(&args[0]))
        .map_err(|e| e.to_string())?;
    let (b, _) = scrapelens_core::open_session_dir_lazy(&PathBuf::from(&args[1]))
        .map_err(|e| e.to_string())?;
    let result = validate(
        &a.session,
        &scrapelens_core::search::LazyBodies(&a),
        &b.session,
        &scrapelens_core::search::LazyBodies(&b),
        &options,
    );
    print_json(&result)?;
    eprintln!("{}", result.summary);
    Ok(())
}

fn flow_command(command: &str, args: &[String]) -> Result<(), String> {
    use scrapelens_core::flow::{priming_chain, value_origins, FlowOptions};
    if args.len() != 2 {
        return Err(usage());
    }
    let (lazy, _report) = scrapelens_core::open_session_dir_lazy(&PathBuf::from(&args[0]))
        .map_err(|e| e.to_string())?;
    let source = scrapelens_core::search::LazyBodies(&lazy);
    let options = FlowOptions::default();
    if command == "origins" {
        let found =
            value_origins(&lazy.session, &source, &args[1], &options).map_err(|e| e.to_string())?;
        print_json(&found)
    } else {
        let chain =
            priming_chain(&lazy.session, &source, &args[1], &options).map_err(|e| e.to_string())?;
        print_json(&chain)
    }
}

/// `export-priming <sessao> <requestId> [--out f] [--allow-incomplete] [--allow-origin o]...`: gera
/// o script, sem executá-lo.
fn export_priming_command(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err(usage());
    }
    let (lazy, _report) = scrapelens_core::open_session_dir_lazy(&PathBuf::from(&args[0]))
        .map_err(|e| e.to_string())?;
    let source = scrapelens_core::search::LazyBodies(&lazy);
    let options = scrapelens_core::export::priming::PrimingOptions {
        allow_incomplete: args.iter().any(|arg| arg == "--allow-incomplete"),
        allow_literal_body: args.iter().any(|arg| arg == "--allow-literal-body"),
        allow_origins: args
            .windows(2)
            .filter(|w| w[0] == "--allow-origin")
            .map(|w| w[1].clone())
            .collect(),
        ..Default::default()
    };
    let output =
        scrapelens_core::export::priming::to_python(&lazy.session, &source, &args[1], &options)
            .map_err(|e| e.to_string())?;
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
        }
        None => print!("{}", output.text),
    }
    Ok(())
}

/// `assess <sessao> [requestId] [--rules f.json]`. Sem `--rules`, usa
/// `<sessao>/assess-rules.json` se existir; senão as regras padrão.
fn assess_command(args: &[String]) -> Result<(), String> {
    use scrapelens_core::assess::{assess_session, AssessRules};
    let mut positional: Vec<&String> = Vec::new();
    let mut rules_path: Option<PathBuf> = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg == "--rules" {
            let value = rest
                .next()
                .ok_or_else(|| "--rules exige um caminho".to_string())?;
            rules_path = Some(PathBuf::from(value));
        } else if arg.starts_with("--") {
            return Err(format!("argumento desconhecido: {arg}\n\n{}", usage()));
        } else {
            positional.push(arg);
        }
    }
    if positional.is_empty() || positional.len() > 2 {
        return Err(usage());
    }
    let dir = PathBuf::from(positional[0]);
    let rules_path = rules_path.or_else(|| {
        let default = dir.join("assess-rules.json");
        default.is_file().then_some(default)
    });
    let rules = match &rules_path {
        Some(path) => {
            let text =
                std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            AssessRules::from_json(&text)?
        }
        None => AssessRules::default(),
    };
    let warnings = rules.warnings();
    for warning in &warnings {
        eprintln!("aviso: {warning}");
    }
    let (lazy, _report) =
        scrapelens_core::open_session_dir_lazy(&dir).map_err(|e| e.to_string())?;
    let source = scrapelens_core::search::LazyBodies(&lazy);
    let mut outcomes = assess_session(&lazy.session, &source, &rules);
    if let Some(id) = positional.get(1) {
        outcomes.retain(|outcome| &outcome.request_id == *id);
        if outcomes.is_empty() {
            return Err(format!("requisição {id} não encontrada"));
        }
    }
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for outcome in &outcomes {
        *counts
            .entry(outcome.verdict_kind.count_key().to_string())
            .or_default() += 1;
    }
    print_json(&AssessOutput {
        schema: "scrapelens.assess/1",
        rules: rules_path
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "default".into()),
        counts,
        warnings: &warnings,
        outcomes: &outcomes,
    })
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
    let origins = if args.iter().any(|arg| arg == "--with-origins") {
        Some(
            scrapelens_core::flow::value_origins(
                &imported.bundle.session,
                &imported.bundle,
                request_id,
                &scrapelens_core::flow::FlowOptions::default(),
            )
            .map_err(|e| e.to_string())?,
        )
    } else {
        None
    };
    let output = if is_curl {
        curl::to_curl_with_origins(request, body, &options, origins.as_ref())
            .map_err(|e| e.to_string())?
    } else {
        python::to_python_with_origins(request, body, &options, origins.as_ref())
            .map_err(|e| e.to_string())?
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
    let path = args.first().ok_or_else(usage)?;
    let index = args
        .iter()
        .position(|arg| arg == "--out")
        .ok_or_else(|| "--out <sessao> é obrigatório".to_string())?;
    let out = args
        .get(index + 1)
        .ok_or_else(|| "--out exige um caminho".to_string())?;
    Ok((PathBuf::from(path), PathBuf::from(out)))
}

/// Saída de `inspect` (mesma ordem de campos do antigo `json!`).
#[derive(serde::Serialize)]
struct Inspect<'a> {
    session: &'a scrapelens_core::SessionV1,
    report: &'a scrapelens_core::ImportReport,
}

/// Saída de `assess` (mesma ordem de campos do antigo `json!`).
#[derive(serde::Serialize)]
struct AssessOutput<'a, W: serde::Serialize, O: serde::Serialize> {
    schema: &'static str,
    rules: String,
    counts: std::collections::BTreeMap<String, usize>,
    warnings: &'a W,
    outcomes: &'a O,
}

/// JSON identado direto no stdout, sem montar a `String` inteira.
fn print_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    serde_json::to_writer_pretty(&mut out, value).map_err(|e| e.to_string())?;
    out.write_all(b"\n").map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())
}

fn usage() -> String {
    "uso:
  scrapelens-core inspect <sessao>
  scrapelens-core import-har <har> --out <sessao> [--label <rótulo>]...
  scrapelens-core import-trace <trace.json> --out <sessao> [--label <rótulo>]...
  scrapelens-core import-netlog <netlog> --out <sessao> [--label <rótulo>]...
  scrapelens-core import-capture <cdp.jsonl> <netlog.json> --out <sessao> [--bodies <cdp-bodies.jsonl>] [--label <rótulo>]...
  scrapelens-core search <sessao> <texto> [--scope <escopo>]... [--case-sensitive]
  scrapelens-core origins <sessao> <requestId>
  scrapelens-core chain <sessao> <requestId>
  scrapelens-core timeline <sessao>
  scrapelens-core validate <captura> <sessao-trace> [--map-origin <origem-captura>=<origem-trace>]
  scrapelens-core assess <sessao> [requestId] [--rules regras.json]
  scrapelens-core export-priming <sessao> <requestId> [--out arquivo] [--allow-incomplete] [--allow-origin <origin>] [--allow-literal-body]
  scrapelens-core compare <sessaoA> <sessaoB> [--a-range de:ate] [--b-range de:ate] [--all] [--map-origin <origem-A>=<origem-B>]
  scrapelens-core export-curl <sessao> <requestId> [--out arquivo] [--with-origins]
  scrapelens-core export-python <sessao> <requestId> [--out arquivo] [--with-origins]
  scrapelens-core sanitize <sessao> <saida>
  scrapelens-core diff <sessao> <requestIdA> <requestIdB>"
        .to_string()
}
