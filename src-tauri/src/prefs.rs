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
    /// URL inicial da captura ao vivo (`http`/`https`); ausente = usar env ou em branco.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capture_start_url: Option<String>,
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
    read_nofollow(&file)
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
    let mut preferences = read(app);
    preferences.chrome_path = Some(path.display().to_string());
    write_prefs(file, &preferences)
}

pub fn load_capture_start_url(app: &AppHandle) -> Option<String> {
    read(app)
        .capture_start_url
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub fn save_capture_start_url(app: &AppHandle, url: Option<&str>) -> Result<(), String> {
    let Some(file) = config_file(app) else {
        return Err("sem diretório de configuração do app".to_string());
    };
    let mut preferences = read(app);
    preferences.capture_start_url = match url.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => Some(crate::cli::persistable_url(value)?),
        None => None,
    };
    write_prefs(file, &preferences)
}

fn write_prefs(file: PathBuf, preferences: &Preferences) -> Result<(), String> {
    let text = serde_json::to_string_pretty(preferences)
        .map_err(|error| format!("falha ao serializar preferências: {error}"))?;
    write_private_atomic(&file, text.as_bytes())
}

/// Lê sem seguir symlink (O_NOFOLLOW) e só arquivo regular.
fn read_nofollow(file: &Path) -> Option<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut handle = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(file)
        .ok()?;
    if !handle.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    handle.by_ref().take(1024 * 1024).read_to_string(&mut text).ok()?;
    Some(text)
}

/// Diretório 0700 (recusa symlink), temporário `create_new` + O_NOFOLLOW 0600,
/// fsync e `rename` sobre o destino (que não pode ser symlink).
pub(crate) fn write_private_atomic(file: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    let parent = file.parent().ok_or("destino sem diretório")?;
    match fs::symlink_metadata(parent) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(format!("diretório de configuração é symlink: {}", parent.display()));
        }
        Ok(meta) if !meta.is_dir() => {
            return Err(format!("não é um diretório: {}", parent.display()));
        }
        Ok(_) => {}
        Err(_) => fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|error| format!("não foi possível criar {}: {error}", parent.display()))?,
    }
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("não foi possível proteger {}: {error}", parent.display()))?;
    if let Ok(meta) = fs::symlink_metadata(file) {
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(format!("{} não é um arquivo regular (symlink recusado)", file.display()));
        }
    }
    let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("prefs");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = parent.join(format!(".{name}.{}.{nonce}.tmp", std::process::id()));
    let result = (|| {
        let mut handle = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
            .map_err(|error| format!("falha ao criar {}: {error}", tmp.display()))?;
        handle
            .write_all(bytes)
            .and_then(|_| handle.sync_all())
            .map_err(|error| format!("falha ao gravar {}: {error}", tmp.display()))?;
        fs::rename(&tmp, file).map_err(|error| format!("falha ao gravar {}: {error}", file.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn base() -> PathBuf {
        let dir = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("scrapelens-prefs-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn private_write_uses_0700_dir_0600_file_and_refuses_symlink() {
        let root = base();
        let dir = root.join("cfg");
        let file = dir.join("preferences.json");
        write_private_atomic(&file, b"{\"a\":1}").unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(read_nofollow(&file).unwrap(), "{\"a\":1}");
        // sem temporários sobrando
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);

        let victim = root.join("victim.txt");
        fs::write(&victim, b"orig").unwrap();
        let linked = dir.join("linked.json");
        symlink(&victim, &linked).unwrap();
        assert!(write_private_atomic(&linked, b"x").is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"orig");
        assert!(read_nofollow(&linked).is_none());

        let link_dir = root.join("cfg-link");
        symlink(&dir, &link_dir).unwrap();
        assert!(write_private_atomic(&link_dir.join("p.json"), b"x").is_err());
        let _ = fs::remove_dir_all(&root);
    }
}
