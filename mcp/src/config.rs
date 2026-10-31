//! Configuração e limites de diretório do servidor.

use std::path::{Path, PathBuf};

use scrapelens_core::store::ensure_private_dir;

use crate::error::ToolError;

pub const DEFAULT_MAX_IMPORT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Config {
    /// Onde `import_session` grava e de onde `list_sessions` lê (canônico).
    pub sessions_dir: PathBuf,
    /// Onde vão os arquivos de corpos grandes (canônico).
    pub out_dir: PathBuf,
    /// Diretórios de sessões só para leitura (canônicos).
    pub extra_dirs: Vec<PathBuf>,
    pub allow_reveal: bool,
    pub max_import_bytes: u64,
}

impl Config {
    pub fn new(
        sessions_dir: &Path,
        out_dir: Option<&Path>,
        extra_dirs: &[PathBuf],
        allow_reveal: bool,
        max_import_bytes: u64,
    ) -> Result<Self, ToolError> {
        let io = |path: &Path, error: std::io::Error| {
            ToolError::new("io", format!("{}: {error}", path.display()))
        };
        ensure_private_dir(sessions_dir)?;
        let sessions_dir = sessions_dir
            .canonicalize()
            .map_err(|error| io(sessions_dir, error))?;
        let out_dir = match out_dir {
            Some(path) => path.to_path_buf(),
            None => sessions_dir.join(".mcp-out"),
        };
        ensure_private_dir(&out_dir)?;
        let out_dir = out_dir
            .canonicalize()
            .map_err(|error| io(&out_dir, error))?;
        let mut extras = Vec::new();
        for dir in extra_dirs {
            extras.push(dir.canonicalize().map_err(|error| io(dir, error))?);
        }
        Ok(Self {
            sessions_dir,
            out_dir,
            extra_dirs: extras,
            allow_reveal,
            max_import_bytes,
        })
    }
}

/// Nome seguro de um único componente de caminho (handle de sessão, `name`).
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

/// Converte texto livre em um nome seguro.
pub fn slug(text: &str) -> String {
    let mut out: String = text
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-') {
                ch
            } else {
                '-'
            }
        })
        .collect();
    out.truncate(64);
    let out = out.trim_matches(['-', '.']).to_string();
    if out.is_empty() {
        "sessao".to_string()
    } else {
        out
    }
}

/// `true` se `child` (já canônico) está dentro de `root` (canônico).
pub fn is_within(root: &Path, child: &Path) -> bool {
    child.starts_with(root)
}
