//! Argumentos de linha de comando.

use std::path::PathBuf;

use crate::config::{Config, DEFAULT_MAX_IMPORT_BYTES};

pub const USAGE: &str = "uso: scrapelens-mcp --sessions-dir <dir> [--out-dir <dir>] [--extra-sessions-dir <dir>]... [--allow-reveal] [--allow-unconfirmed-capture] [--max-import-bytes <n>]";

pub fn parse_args(args: Vec<String>) -> Result<Config, String> {
    let mut sessions: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut extras: Vec<PathBuf> = Vec::new();
    let mut allow_reveal = false;
    let mut allow_unconfirmed = false;
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
            "--allow-unconfirmed-capture" => allow_unconfirmed = true,
            "--help" | "-h" => return Err(USAGE.to_string()),
            other => return Err(format!("argumento desconhecido: {other}\n{USAGE}")),
        }
    }
    let sessions = sessions.ok_or_else(|| format!("--sessions-dir é obrigatório\n{USAGE}"))?;
    let mut config = Config::new(&sessions, out.as_deref(), &extras, allow_reveal, max_import)
        .map_err(|error| error.to_string())?;
    config.allow_unconfirmed_capture = allow_unconfirmed;
    Ok(config)
}
