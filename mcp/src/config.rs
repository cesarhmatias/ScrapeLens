//! Server configuration and directory limits.

use std::path::{Path, PathBuf};

use scrapelens_core::store::ensure_private_dir;

use crate::error::ToolError;

pub const DEFAULT_MAX_IMPORT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Config {
    /// Where `import_session` writes and `list_sessions` reads from (canonical).
    pub sessions_dir: PathBuf,
    /// Where large body files go (canonical).
    pub out_dir: PathBuf,
    /// Read-only session directories (canonical).
    pub extra_dirs: Vec<PathBuf>,
    pub allow_reveal: bool,
    /// Accepts `start_capture` without elicitation when the client does not support it.
    pub allow_unconfirmed_capture: bool,
    /// Accepts `include_sensitive` without elicitation when the client does not support it.
    pub allow_sensitive_export: bool,
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
            allow_unconfirmed_capture: false,
            allow_sensitive_export: false,
            max_import_bytes,
        })
    }
}

/// Safe name for a single path component (session handle, `name`).
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

/// Converts free text into a safe name.
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
        "session".to_string()
    } else {
        out
    }
}

/// `true` if `child` (already canonical) is inside `root` (canonical).
pub fn is_within(root: &Path, child: &Path) -> bool {
    child.starts_with(root)
}
