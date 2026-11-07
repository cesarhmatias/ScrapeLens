//! Wrapper around the core CLI with the Natural adapter registered.
//!
//! `export-priming` runs here, with the adapter and the Python encoder; any
//! other subcommand is passed through to `scrapelens-core` (path in
//! `SCRAPELENS_CORE_BIN`, otherwise `../../target/release/scrapelens-core`
//! relative to this crate, otherwise the one on PATH). The adapter only applies with `--adapter natural-ajax`;
//! without the flag, the script takes the snippet path (control).

use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::sync::Arc;

use scrapelens_core::adapter::AdapterRegistry;
use scrapelens_core::export::priming::{to_python, AdapterEncoder, PrimingOptions};
use scrapelens_natural_ajax::{
    NaturalAjax, ADAPTER_ID, PYTHON_DECODER, PYTHON_ENCODER, PYTHON_FUNCTION,
};

/// Looks up `name` in PATH (when it is not a path).
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

/// The `scrapelens-core` that receives the passed-through subcommands. Never
/// returns the wrapper itself (an env var, a neighbour or PATH resolving to it),
/// which would cause infinite process recursion.
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
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release/scrapelens-core");
    if sibling.is_file() && !is_me(&sibling) {
        return Ok(sibling);
    }
    match resolve_in_path(PathBuf::from("scrapelens-core")) {
        Some(found) if !is_me(&found) => Ok(found),
        Some(_) => Err(
            "the scrapelens-core found is this wrapper itself; set SCRAPELENS_CORE_BIN"
                .into(),
        ),
        None => Err("scrapelens-core not found; set SCRAPELENS_CORE_BIN".into()),
    }
}

/// `--adapter <id>`: only `natural-ajax` exists here.
fn check_adapter_flag(args: &[String]) -> Result<(), String> {
    if let Some(index) = args.iter().position(|a| a == "--adapter") {
        match args.get(index + 1).map(String::as_str) {
            Some(ADAPTER_ID) => {}
            Some(other) => {
                return Err(format!(
                    "unknown adapter: {other} (available: {ADAPTER_ID})"
                ))
            }
            None => return Err("--adapter requires an id".into()),
        }
    }
    Ok(())
}

/// `adapter-roundtrip <session> [--adapter natural-ajax]`: `encode(decode(x)) == x`
/// on all request `XML` fields of the session. Aggregates only, no values.
fn adapter_roundtrip(args: &[String]) -> Result<(), String> {
    use scrapelens_core::adapter::{AdapterContext, ProtocolAdapter};
    use scrapelens_natural_ajax::grammar::{self, Op};
    check_adapter_flag(args)?;
    let dir = args.first().ok_or(
        "usage: natural-core adapter-roundtrip <session> [--adapter natural-ajax] [--lenient-parts]",
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

/// Arguments without `--adapter <id>` and `--sem-adaptador`.
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

/// `origins`/`chain <session> <requestId>` with the adapter registered.
fn flow_command(command: &str, args: &[String]) -> Result<(), String> {
    use scrapelens_core::flow::{priming_chain, value_origins, FlowOptions};
    let options = FlowOptions {
        adapters: registry(args)?,
        ..FlowOptions::default()
    };
    let args = strip_adapter_flags(args);
    if args.len() != 2 {
        return Err(format!(
            "usage: natural-core {command} <session> <requestId> [--adapter natural-ajax]"
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

/// `validate <capture> <trace> [--map-origin a=b] [--adapter natural-ajax]`.
fn validate_command(args: &[String]) -> Result<(), String> {
    use scrapelens_core::validate::{validate, ValidateOptions};
    let mut options = ValidateOptions::default();
    options.compare.flow.adapters = registry(args)?;
    let args = strip_adapter_flags(args);
    if args.len() < 2 {
        return Err("usage: natural-core validate <capture> <session-trace> [--map-origin a=b] [--adapter natural-ajax]".into());
    }
    let mut rest = args[2..].iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--map-origin" => {
                let value = rest.next().ok_or_else(|| {
                    "--map-origin requires <capture-origin>=<trace-origin>".to_string()
                })?;
                options.compare.map_origin = Some(
                    scrapelens_core::compare::OriginMap::parse(value)
                        .ok_or_else(|| format!("invalid --map-origin: {value:?}"))?,
                );
            }
            other => return Err(format!("unknown argument: {other}")),
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

/// `timeline <session> [--adapter natural-ajax]`: timeline with `event @ page`
/// labels when the adapter is registered.
fn timeline_command(args: &[String]) -> Result<(), String> {
    use scrapelens_core::timeline::{timeline, TimelineOptions};
    let options = TimelineOptions {
        flow: scrapelens_core::flow::FlowOptions {
            adapters: registry(args)?,
            ..Default::default()
        },
        ..Default::default()
    };
    let args = strip_adapter_flags(args);
    if args.len() != 1 {
        return Err("usage: natural-core timeline <session> [--adapter natural-ajax]".into());
    }
    let (lazy, _) = scrapelens_core::open_session_dir_lazy(&PathBuf::from(&args[0]))
        .map_err(|e| e.to_string())?;
    let source = scrapelens_core::search::LazyBodies(&lazy);
    print_json(&timeline(&lazy.session, &source, &options))
}

/// `compare <A> <B> [--all] [--a-range r] [--b-range r]` with the adapter.
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
        return Err("usage: natural-core compare <sessionA> <sessionB> [--all] [--a-range r] [--b-range r] [--adapter natural-ajax]".into());
    }
    let mut rest = args[2..].iter();
    while let Some(arg) = rest.next() {
        let mut range = |name: &str| -> Result<RequestRange, String> {
            let value = rest
                .next()
                .ok_or_else(|| format!("{name} requires a value"))?;
            RequestRange::parse(value).ok_or_else(|| format!("{name}: invalid range {value:?}"))
        };
        match arg.as_str() {
            "--all" => options.include_all = true,
            "--a-range" => options.a_range = Some(range("--a-range")?),
            "--b-range" => options.b_range = Some(range("--b-range")?),
            other => return Err(format!("unknown argument: {other}")),
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
        return Err("usage: natural-core export-priming <session> <requestId> [--out f] [--allow-incomplete] [--allow-origin o] [--allow-literal-body] [--adapter natural-ajax] [--lenient-parts]".into());
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
        eprintln!("warning [{}]: {}", warning.code, warning.message);
    }
    match args.iter().position(|a| a == "--out") {
        Some(index) => {
            let out = args
                .get(index + 1)
                .ok_or_else(|| "--out requires a path".to_string())?;
            std::fs::write(out, output.text).map_err(|e| format!("{out}: {e}"))?;
            println!("{out}");
        }
        None => print!("{}", output.text),
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(command @ ("origins" | "chain" | "compare" | "timeline" | "validate")) =
        args.first().map(String::as_str)
    {
        let result = if command == "validate" {
            validate_command(&args[1..])
        } else if command == "timeline" {
            timeline_command(&args[1..])
        } else if command == "compare" {
            compare_command(&args[1..])
        } else {
            flow_command(command, &args[1..])
        };
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("error: {message}");
                ExitCode::from(1)
            }
        };
    }
    if args.first().map(String::as_str) == Some("adapter-roundtrip") {
        return match adapter_roundtrip(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("error: {message}");
                ExitCode::from(1)
            }
        };
    }
    if args.first().map(String::as_str) == Some("export-priming") {
        return match export_priming(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("error: {message}");
                ExitCode::from(1)
            }
        };
    }
    // Re-execution depth: the pass-through to the core happens at most once.
    let depth: u32 = std::env::var("NATURAL_CORE_DEPTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if depth >= 1 {
        eprintln!("error: re-execution recursion refused (NATURAL_CORE_DEPTH={depth})");
        return ExitCode::from(1);
    }
    let core = match core_binary() {
        Ok(core) => core,
        Err(message) => {
            eprintln!("error: {message}");
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
            eprintln!("error: could not run scrapelens-core: {e}");
            ExitCode::from(1)
        }
    }
}
