//! Wrapper do CLI do core com o adaptador Natural registrado.
//!
//! `export-priming` roda aqui, com o adaptador e o codificador Python; qualquer
//! outro subcomando é repassado ao `scrapelens-core` (caminho em
//! `SCRAPELENS_CORE_BIN`, senão `../../core/target/release/scrapelens-core`
//! relativo a este crate, senão o do PATH). Use `--sem-adaptador` para gerar
//! o script pelo caminho por trechos (controle).

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

fn export_priming(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("uso: natural-core export-priming <sessao> <requestId> [--out f] [--allow-incomplete] [--allow-origin o] [--allow-literal-body] [--sem-adaptador]".into());
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
    if !args.iter().any(|a| a == "--sem-adaptador") {
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
