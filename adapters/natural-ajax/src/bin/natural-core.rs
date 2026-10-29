//! Wrapper do CLI do core com o adaptador Natural registrado.
//!
//! `export-priming` roda aqui, com o adaptador e o codificador Python; qualquer
//! outro subcomando é repassado ao `scrapelens-core` (caminho em
//! `SCRAPELENS_CORE_BIN`, senão `../../core/target/release/scrapelens-core`
//! relativo a este crate, senão o do PATH). O adaptador só vale com `--adapter natural-ajax`;
//! sem a flag, o script sai pelo caminho por trechos (controle).

use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::sync::Arc;

use scrapelens_core::adapter::AdapterRegistry;
use scrapelens_core::export::priming::{to_python, AdapterEncoder, PrimingOptions};
use scrapelens_natural_ajax::{
    NaturalAjax, ADAPTER_ID, PYTHON_DECODER, PYTHON_ENCODER, PYTHON_FUNCTION,
};

/// Procura `name` no PATH (quando não é caminho).
fn resolve_in_path(path: PathBuf) -> Option<PathBuf> {
    if path.components().count() > 1 {
        return path.is_file().then_some(path);
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(&path))
            .find(|candidate| candidate.is_file())
    })
}

/// O `scrapelens-core` que recebe os subcomandos repassados. Nunca devolve o
/// próprio wrapper (variável de ambiente, vizinho ou PATH que resolvam para
/// ele), o que geraria recursão infinita de processos.
fn core_binary() -> Result<PathBuf, String> {
    let me = std::env::current_exe().and_then(|p| p.canonicalize()).ok();
    let is_me = |path: &PathBuf| path.canonicalize().ok().is_some_and(|p| Some(p) == me);
    if let Some(path) = std::env::var_os("SCRAPELENS_CORE_BIN").filter(|v| !v.is_empty()) {
        let path = PathBuf::from(path);
        if !is_me(&path) {
            return Ok(path);
        }
    }
    let sibling =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../core/target/release/scrapelens-core");
    if sibling.is_file() && !is_me(&sibling) {
        return Ok(sibling);
    }
    match resolve_in_path(PathBuf::from("scrapelens-core")) {
        Some(found) if !is_me(&found) => Ok(found),
        Some(_) => Err(
            "o scrapelens-core encontrado é este próprio wrapper; defina SCRAPELENS_CORE_BIN"
                .into(),
        ),
        None => Err("scrapelens-core não encontrado; defina SCRAPELENS_CORE_BIN".into()),
    }
}

/// `--adapter <id>`: só `natural-ajax` existe aqui.
fn check_adapter_flag(args: &[String]) -> Result<(), String> {
    if let Some(index) = args.iter().position(|a| a == "--adapter") {
        match args.get(index + 1).map(String::as_str) {
            Some(ADAPTER_ID) => {}
            Some(other) => {
                return Err(format!(
                    "adaptador desconhecido: {other} (disponível: {ADAPTER_ID})"
                ))
            }
            None => return Err("--adapter exige um id".into()),
        }
    }
    Ok(())
}

/// `adapter-roundtrip <sessao> [--adapter natural-ajax]`: `encode(decode(x)) == x`
/// em todos os campos `XML` de requisição da sessão. Só agregados, sem valores.
fn adapter_roundtrip(args: &[String]) -> Result<(), String> {
    use scrapelens_core::adapter::{AdapterContext, ProtocolAdapter};
    use scrapelens_natural_ajax::grammar::{self, Op};
    check_adapter_flag(args)?;
    let dir = args.first().ok_or(
        "uso: natural-core adapter-roundtrip <sessao> [--adapter natural-ajax] [--lenient-parts]",
    )?;
    let (lazy, _report) =
        scrapelens_core::open_session_dir_lazy(&PathBuf::from(dir)).map_err(|e| e.to_string())?;
    let source = scrapelens_core::search::LazyBodies(&lazy);
    let adapter = NaturalAjax;
    let (mut xml, mut fields, mut unclaimed, mut divergences) = (0usize, 0usize, 0usize, 0usize);
    let mut kinds: std::collections::BTreeMap<String, usize> = Default::default();
    for request in &lazy.session.requests {
        let Some(attachment) = request.request_body.attachment.as_deref() else {
            continue;
        };
        let Some(loaded) = scrapelens_core::search::BodySource::load(&source, attachment) else {
            continue;
        };
        let body = String::from_utf8_lossy(&loaded.bytes).into_owned();
        for value in scrapelens_natural_ajax::extract::form_values(&body, "XML") {
            xml += 1;
            let ctx = AdapterContext {
                url: &request.url,
                method: &request.method,
                request: true,
                media: None,
            };
            if !adapter.detect("XML", &value, &ctx) {
                unclaimed += 1;
                continue;
            }
            if let Ok(items) = grammar::parse(&value) {
                fields += items
                    .iter()
                    .map(|i| match &i.op {
                        Op::Head { .. } => 8,
                        Op::Lit { .. } | Op::Ref { .. } | Op::Dict { .. } => 2,
                        _ => 1,
                    })
                    .sum::<usize>();
            }
            let round_trip = adapter
                .decode(&value)
                .and_then(|d| adapter.encode(&d))
                .map_err(|_| "erro".to_string());
            match round_trip {
                Ok(encoded) if encoded == value => {}
                Ok(_) => {
                    divergences += 1;
                    *kinds.entry("saida-diferente".into()).or_default() += 1;
                }
                Err(kind) => {
                    divergences += 1;
                    *kinds.entry(kind).or_default() += 1;
                }
            }
        }
    }
    println!(
        "{}",
        serde_json::json!({
            "adapter": ADAPTER_ID,
            "xml": xml,
            "fields": fields,
            "unclaimed": unclaimed,
            "divergences": divergences,
            "divergenceKinds": kinds,
        })
    );
    Ok(())
}

fn registry(args: &[String]) -> Result<AdapterRegistry, String> {
    check_adapter_flag(args)?;
    if args.iter().any(|a| a == "--adapter") && !args.iter().any(|a| a == "--sem-adaptador") {
        Ok(AdapterRegistry::new().with(Arc::new(NaturalAjax)))
    } else {
        Ok(AdapterRegistry::new())
    }
}

/// Argumentos sem `--adapter <id>` e `--sem-adaptador`.
fn strip_adapter_flags(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--adapter" => {
                it.next();
            }
            "--sem-adaptador" => {}
            _ => out.push(a.clone()),
        }
    }
    out
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|e| e.to_string())?
    );
    Ok(())
}

/// `origins`/`chain <sessao> <requestId>` com o adaptador registrado.
fn flow_command(command: &str, args: &[String]) -> Result<(), String> {
    use scrapelens_core::flow::{priming_chain, value_origins, FlowOptions};
    let options = FlowOptions {
        adapters: registry(args)?,
        ..FlowOptions::default()
    };
    let args = strip_adapter_flags(args);
    if args.len() != 2 {
        return Err(format!(
            "uso: natural-core {command} <sessao> <requestId> [--adapter natural-ajax]"
        ));
    }
    let (lazy, _) = scrapelens_core::open_session_dir_lazy(&PathBuf::from(&args[0]))
        .map_err(|e| e.to_string())?;
    let source = scrapelens_core::search::LazyBodies(&lazy);
    if command == "origins" {
        print_json(
            &value_origins(&lazy.session, &source, &args[1], &options)
                .map_err(|e| e.to_string())?,
        )
    } else {
        print_json(
            &priming_chain(&lazy.session, &source, &args[1], &options)
                .map_err(|e| e.to_string())?,
        )
    }
}

/// `compare <A> <B> [--all] [--a-range r] [--b-range r]` com o adaptador.
fn compare_command(args: &[String]) -> Result<(), String> {
    use scrapelens_core::compare::{compare_sessions, CompareOptions, RequestRange};
    let mut options = CompareOptions {
        flow: scrapelens_core::flow::FlowOptions {
            adapters: registry(args)?,
            ..Default::default()
        },
        ..Default::default()
    };
    let args = strip_adapter_flags(args);
    if args.len() < 2 {
        return Err("uso: natural-core compare <sessaoA> <sessaoB> [--all] [--a-range r] [--b-range r] [--adapter natural-ajax]".into());
    }
    let mut rest = args[2..].iter();
    while let Some(arg) = rest.next() {
        let mut range = |name: &str| -> Result<RequestRange, String> {
            let value = rest
                .next()
                .ok_or_else(|| format!("{name} exige um valor"))?;
            RequestRange::parse(value).ok_or_else(|| format!("{name}: faixa inválida {value:?}"))
        };
        match arg.as_str() {
            "--all" => options.include_all = true,
            "--a-range" => options.a_range = Some(range("--a-range")?),
            "--b-range" => options.b_range = Some(range("--b-range")?),
            other => return Err(format!("argumento desconhecido: {other}")),
        }
    }
    let (a, _) = scrapelens_core::open_session_dir_lazy(&PathBuf::from(&args[0]))
        .map_err(|e| e.to_string())?;
    let (b, _) = scrapelens_core::open_session_dir_lazy(&PathBuf::from(&args[1]))
        .map_err(|e| e.to_string())?;
    print_json(&compare_sessions(
        &a.session,
        &scrapelens_core::search::LazyBodies(&a),
        &b.session,
        &scrapelens_core::search::LazyBodies(&b),
        &options,
    ))
}

fn export_priming(args: &[String]) -> Result<(), String> {
    check_adapter_flag(args)?;
    if args.len() < 2 {
        return Err("uso: natural-core export-priming <sessao> <requestId> [--out f] [--allow-incomplete] [--allow-origin o] [--allow-literal-body] [--adapter natural-ajax] [--lenient-parts]".into());
    }
    let (lazy, _report) = scrapelens_core::open_session_dir_lazy(&PathBuf::from(&args[0]))
        .map_err(|e| e.to_string())?;
    let source = scrapelens_core::search::LazyBodies(&lazy);
    let mut options = PrimingOptions {
        allow_incomplete: args.iter().any(|a| a == "--allow-incomplete"),
        allow_literal_body: args.iter().any(|a| a == "--allow-literal-body"),
        lenient_parts: args.iter().any(|a| a == "--lenient-parts"),
        allow_origins: args
            .windows(2)
            .filter(|w| w[0] == "--allow-origin")
            .map(|w| w[1].clone())
            .collect(),
        ..Default::default()
    };
    if args.iter().any(|a| a == "--adapter") && !args.iter().any(|a| a == "--sem-adaptador") {
        options.flow.adapters = AdapterRegistry::new().with(Arc::new(NaturalAjax));
        options.adapter_encoders.push(AdapterEncoder {
            adapter_id: ADAPTER_ID.to_string(),
            function: PYTHON_FUNCTION.to_string(),
            decoder: PYTHON_DECODER.to_string(),
            source: PYTHON_ENCODER.to_string(),
        });
    }
    let output =
        to_python(&lazy.session, &source, &args[1], &options).map_err(|e| e.to_string())?;
    for warning in &output.warnings {
        eprintln!("aviso [{}]: {}", warning.code, warning.message);
    }
    match args.iter().position(|a| a == "--out") {
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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(command @ ("origins" | "chain" | "compare")) = args.first().map(String::as_str) {
        let result = if command == "compare" {
            compare_command(&args[1..])
        } else {
            flow_command(command, &args[1..])
        };
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("erro: {message}");
                ExitCode::from(1)
            }
        };
    }
    if args.first().map(String::as_str) == Some("adapter-roundtrip") {
        return match adapter_roundtrip(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("erro: {message}");
                ExitCode::from(1)
            }
        };
    }
    if args.first().map(String::as_str) == Some("export-priming") {
        return match export_priming(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("erro: {message}");
                ExitCode::from(1)
            }
        };
    }
    // Profundidade de re-execução: o repasse ao core acontece no máximo uma vez.
    let depth: u32 = std::env::var("NATURAL_CORE_DEPTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if depth >= 1 {
        eprintln!("erro: recursão de re-execução recusada (NATURAL_CORE_DEPTH={depth})");
        return ExitCode::from(1);
    }
    let core = match core_binary() {
        Ok(core) => core,
        Err(message) => {
            eprintln!("erro: {message}");
            return ExitCode::from(1);
        }
    };
    match Command::new(core)
        .env("NATURAL_CORE_DEPTH", (depth + 1).to_string())
        .args(&args)
        .status()
    {
        Ok(status) => ExitCode::from(status.code().unwrap_or(1) as u8),
        Err(e) => {
            eprintln!("erro: não consegui executar o scrapelens-core: {e}");
            ExitCode::from(1)
        }
    }
}
