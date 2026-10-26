//! Detecção e seleção manual do Chrome externo. O ScrapeLens nunca usa o
//! perfil pessoal: o launcher do core/ abre um perfil dedicado. Aqui só
//! localizamos/validamos o binário.

use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChromeInfo {
    pub found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub source: String,
    pub candidates: Vec<String>,
}

fn home_candidates() -> Vec<PathBuf> {
    let mut list = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        list.push(
            PathBuf::from(&home)
                .join("Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        );
        list.push(
            PathBuf::from(&home).join("Applications/Chromium.app/Contents/MacOS/Chromium"),
        );
    }
    list
}

pub fn candidates() -> Vec<String> {
    let mut paths = vec![
        PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        PathBuf::from("/Applications/Chromium.app/Contents/MacOS/Chromium"),
        PathBuf::from("/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary"),
    ];
    paths.extend(home_candidates());
    paths
        .into_iter()
        .map(|path| path.display().to_string())
        .collect()
}

/// Normaliza o que o usuário escolheu no diálogo: aceita `.app`, o diretório
/// `Contents/MacOS` ou o binário direto.
pub fn normalize_binary_path(chosen: &Path) -> Option<PathBuf> {
    let chosen = chosen.to_path_buf();
    if chosen.is_file() {
        return Some(chosen);
    }
    if chosen.extension().and_then(|ext| ext.to_str()) == Some("app") {
        let inner = chosen.join("Contents/MacOS/Google Chrome");
        if inner.is_file() {
            return Some(inner);
        }
        let chromium = chosen.join("Contents/MacOS/Chromium");
        if chromium.is_file() {
            return Some(chromium);
        }
    }
    if chosen.is_dir() {
        for name in ["Google Chrome", "Chromium", "Google Chrome Canary"] {
            let candidate = chosen.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        let in_macos = chosen.join("Contents/MacOS/Google Chrome");
        if in_macos.is_file() {
            return Some(in_macos);
        }
    }
    None
}

pub fn detect(saved: Option<&Path>) -> ChromeInfo {
    if let Some(path) = saved {
        if path.is_file() {
            return ChromeInfo {
                found: true,
                path: Some(path.display().to_string()),
                source: "manual".to_string(),
                candidates: candidates(),
            };
        }
    }
    for candidate in candidates() {
        let path = PathBuf::from(&candidate);
        if path.is_file() {
            return ChromeInfo {
                found: true,
                path: Some(candidate),
                source: "detected".to_string(),
                candidates: candidates(),
            };
        }
    }
    ChromeInfo {
        found: false,
        path: None,
        source: "none".to_string(),
        candidates: candidates(),
    }
}
