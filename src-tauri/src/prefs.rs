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
    read_and_scrub(&file)
}

/// Lê as preferências e limpa o legado (A9-B3): a URL inicial passa por
/// `persistable_url` (sem userinfo, query, fragmento e com caminho sanitizado);
/// URL inválida é descartada. Se algo mudou ou o arquivo não é 0600, regrava.
fn read_and_scrub(file: &Path) -> Preferences {
    let Some((text, mode)) = read_nofollow(file) else {
        return Preferences::default();
    };
    let Ok(mut preferences) = serde_json::from_str::<Preferences>(&text) else {
        return Preferences::default();
    };
    let changed = normalize(&mut preferences);
    if changed || mode & 0o077 != 0 {
        let _ = write_prefs(file.to_path_buf(), &preferences);
    }
    preferences
}

/// Normaliza o que vai para o disco; devolve `true` se mudou algo.
fn normalize(preferences: &mut Preferences) -> bool {
    let before = preferences.capture_start_url.clone();
    preferences.capture_start_url = before
        .as_deref()
        .and_then(|value| crate::cli::persistable_url(value).ok());
    preferences.capture_start_url != before
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
    let mut preferences = read_and_scrub(&file);
    preferences.chrome_path = Some(path.display().to_string());
    normalize(&mut preferences);
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
    let mut preferences = read_and_scrub(&file);
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

/// Lê sem seguir symlink (O_NOFOLLOW) e só arquivo regular; devolve o texto e o modo.
fn read_nofollow(file: &Path) -> Option<(String, u32)> {
    use std::io::Read;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut handle = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(file)
        .ok()?;
    let meta = handle.metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    let mut text = String::new();
    handle.by_ref().take(1024 * 1024).read_to_string(&mut text).ok()?;
    Some((text, meta.permissions().mode() & 0o777))
}

/// Nenhum componente do caminho (ancestrais inclusive) pode ser symlink (A9-B7).
fn refuse_symlinked_components(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        if let Ok(meta) = fs::symlink_metadata(&current) {
            if meta.file_type().is_symlink() {
                return Err(format!("componente symlink recusado: {}", current.display()));
            }
        }
    }
    Ok(())
}

/// Diretório 0700 (recusa symlink), temporário `create_new` + O_NOFOLLOW 0600,
/// fsync e `rename` sobre o destino (que não pode ser symlink).
pub(crate) fn write_private_atomic(file: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    let parent = file.parent().ok_or("destino sem diretório")?;
    if !file.is_absolute() {
        return Err(format!("caminho de preferências não absoluto: {}", file.display()));
    }
    refuse_symlinked_components(parent)?;
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
        fs::rename(&tmp, file).map_err(|error| format!("falha ao gravar {}: {error}", file.display()))?;
        // fsync do diretório: o rename sobrevive a queda de energia.
        fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|error| format!("falha no fsync de {}: {error}", parent.display()))
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
        assert_eq!(read_nofollow(&file).unwrap(), ("{\"a\":1}".to_string(), 0o600));
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

    #[test]
    fn write_refuses_symlinked_ancestor() {
        let root = base();
        fs::create_dir_all(root.join("real/cfg")).unwrap();
        symlink(root.join("real"), root.join("alias")).unwrap();
        assert!(write_private_atomic(&root.join("alias/cfg/p.json"), b"x").unwrap_err().contains("symlink"));
        assert!(!root.join("real/cfg/p.json").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn legacy_prefs_secret_is_scrubbed_on_first_read_and_chrome_save() {
        let root = base();
        fs::create_dir_all(&root).unwrap();
        let file = root.join("preferences.json");
        fs::write(&file, r#"{"chromePath":"/x","captureStartUrl":"https://u:pw@h/p;jsessionid=J1?token=SECRET#frag"}"#).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        let prefs = read_and_scrub(&file);
        assert_eq!(prefs.capture_start_url, None, "userinfo invalida a URL legada");
        let text = fs::read_to_string(&file).unwrap();
        for secret in ["pw", "SECRET", "frag", "J1"] {
            assert!(!text.contains(secret), "{text}");
        }
        assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);

        fs::write(&file, r#"{"captureStartUrl":"https://h/p;jsessionid=J2?token=S2#f"}"#).unwrap();
        let mut prefs = read_and_scrub(&file);
        let kept = prefs.capture_start_url.clone().unwrap();
        assert!(kept.starts_with("https://h/") && !kept.contains("J2") && !kept.contains('?'), "{kept}");
        prefs.chrome_path = Some("/y".into());
        normalize(&mut prefs);
        write_prefs(file.clone(), &prefs).unwrap();
        let text = fs::read_to_string(&file).unwrap();
        assert!(!text.contains("J2") && !text.contains("S2"), "{text}");
        let _ = fs::remove_dir_all(&root);
    }
}
