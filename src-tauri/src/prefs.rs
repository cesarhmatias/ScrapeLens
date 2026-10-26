//! Preferências locais do shell (por enquanto: caminho manual do Chrome).
//! Ficam em `app_config_dir()/preferences.json`; nada sai da máquina.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Preferences {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chrome_path: Option<String>,
}

fn config_file(app: &AppHandle) -> Option<PathBuf> {
    app.path()
        .app_config_dir()
        .ok()
        .map(|dir| dir.join("preferences.json"))
}

fn read(app: &AppHandle) -> Preferences {
    let Some(file) = config_file(app) else {
        return Preferences::default();
    };
    fs::read_to_string(file)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

pub fn load_chrome_path(app: &AppHandle) -> Option<PathBuf> {
    read(app)
        .chrome_path
        .map(PathBuf::from)
        .filter(|path| path.is_file())
}

pub fn save_chrome_path(app: &AppHandle, path: &Path) -> Result<(), String> {
    let Some(file) = config_file(app) else {
        return Err("sem diretório de configuração do app".to_string());
    };
    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("não foi possível criar {parent:?}: {error}"))?;
    }
    let preferences = Preferences {
        chrome_path: Some(path.display().to_string()),
    };
    let text = serde_json::to_string_pretty(&preferences)
        .map_err(|error| format!("falha ao serializar preferências: {error}"))?;
    fs::write(&file, text).map_err(|error| format!("falha ao gravar {file:?}: {error}"))
}
