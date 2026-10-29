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

fn core_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("SCRAPELENS_CORE_BIN") {
        return PathBuf::from(path);
    }
    let sibling =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../core/target/release/scrapelens-core");
    if sibling.is_file() {
        sibling
    } else {
        PathBuf::from("scrapelens-core")
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
    let dir = args
        .first()
        .ok_or("uso: natural-core adapter-roundtrip <sessao> [--adapter natural-ajax]")?;
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

fn export_priming(args: &[String]) -> Result<(), String> {
    check_adapter_flag(args)?;
    if args.len() < 2 {
        return Err("uso: natural-core export-priming <sessao> <requestId> [--out f] [--allow-incomplete] [--allow-origin o] [--allow-literal-body] [--adapter natural-ajax]".into());
    }
    let (lazy, _report) = scrapelens_core::open_session_dir_lazy(&PathBuf::from(&args[0]))
        .map_err(|e| e.to_string())?;
    let source = scrapelens_core::search::LazyBodies(&lazy);
    let mut options = PrimingOptions {
        allow_incomplete: args.iter().any(|a| a == "--allow-incomplete"),
        allow_literal_body: args.iter().any(|a| a == "--allow-literal-body"),
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
    match Command::new(core_binary()).args(&args).status() {
        Ok(status) => ExitCode::from(status.code().unwrap_or(1) as u8),
        Err(e) => {
            eprintln!("erro: não consegui executar o scrapelens-core: {e}");
            ExitCode::from(1)
        }
    }
}
