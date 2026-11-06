//! Local shell preferences (for now: manual Chrome path).
//! Stored in `app_config_dir()/preferences.json`; nothing leaves the machine.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Preferences {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chrome_path: Option<String>,
    /// Initial live-capture URL (`http`/`https`); absent = use env or blank.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capture_start_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capture_cookie_source: Option<String>,
    /// Proxy server only, as `scheme://host:port`. Credentials are never written here:
    /// they stay in memory until the app closes (see `capture_proxy`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capture_proxy: Option<String>,
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

/// Reads the preferences and scrubs legacy data (A9-B3): the initial URL goes through
/// `persistable_url` (no userinfo, query or fragment, and with a sanitized path);
/// an invalid URL is discarded. If anything changed or the file is not 0600, it is rewritten.
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

/// Normalizes what goes to disk; returns `true` if anything changed.
fn normalize(preferences: &mut Preferences) -> bool {
    let before = preferences.capture_start_url.clone();
    preferences.capture_start_url = before
        .as_deref()
        .and_then(|value| crate::cli::persistable_url(value).ok());
    let before_proxy = preferences.capture_proxy.clone();
    // Whatever is on disk is reduced to the server address: a password never survives a rewrite.
    preferences.capture_proxy = before_proxy
        .as_deref()
        .and_then(|value| scrapelens_capture::proxy::ProxyLink::parse(value).ok())
        .map(|link| link.server_url());
    preferences.capture_start_url != before || preferences.capture_proxy != before_proxy
}

/// The saved proxy server (`scheme://host:port`), without credentials.
pub fn load_capture_proxy(app: &AppHandle) -> Option<String> {
    config_file(app).and_then(|file| load_capture_proxy_at(&file))
}

pub fn save_capture_proxy(app: &AppHandle, server: Option<&str>) -> Result<(), String> {
    let file = config_file(app).ok_or("no app configuration directory")?;
    save_capture_proxy_at(file, server)
}

/// Writes the proxy server to `file`. Any userinfo in `server` is dropped before writing.
pub(crate) fn save_capture_proxy_at(file: PathBuf, server: Option<&str>) -> Result<(), String> {
    let mut preferences = read_and_scrub(&file);
    preferences.capture_proxy = match server.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => Some(
            scrapelens_capture::proxy::ProxyLink::parse(value)
                .map_err(|error| error.to_string())?
                .server_url(),
        ),
        None => None,
    };
    write_prefs(file, &preferences)
}

/// Reads the saved proxy server from `file` (scrubbed on the way).
pub(crate) fn load_capture_proxy_at(file: &Path) -> Option<String> {
    read_and_scrub(file).capture_proxy.filter(|value| !value.is_empty())
}

pub fn load_chrome_path(app: &AppHandle) -> Option<PathBuf> {
    read(app)
        .chrome_path
        .map(PathBuf::from)
        .filter(|path| path.is_file())
}

pub fn save_chrome_path(app: &AppHandle, path: &Path) -> Result<(), String> {
    let Some(file) = config_file(app) else {
        return Err("no app configuration directory".to_string());
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
        return Err("no app configuration directory".to_string());
    };
    let mut preferences = read_and_scrub(&file);
    preferences.capture_start_url = match url.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => Some(crate::cli::persistable_url(value)?),
        None => None,
    };
    write_prefs(file, &preferences)
}

pub fn load_capture_cookie_source(app: &AppHandle) -> Option<String> {
    read(app).capture_cookie_source.filter(|value| !value.is_empty())
}

pub fn save_capture_cookie_source(app: &AppHandle, source: Option<&str>) -> Result<(), String> {
    let file = config_file(app).ok_or("no app configuration directory")?;
    let mut preferences = read_and_scrub(&file);
    preferences.capture_cookie_source = source.filter(|value| !value.is_empty()).map(str::to_owned);
    write_prefs(file, &preferences)
}

fn write_prefs(file: PathBuf, preferences: &Preferences) -> Result<(), String> {
    let text = serde_json::to_string_pretty(preferences)
        .map_err(|error| format!("failed to serialize preferences: {error}"))?;
    write_private_atomic(&file, text.as_bytes())
}

/// Reads without following symlinks (O_NOFOLLOW) and only regular files; returns the text and the mode.
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

/// No path component (ancestors included) may be a symlink (A9-B7).
fn refuse_symlinked_components(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        if let Ok(meta) = fs::symlink_metadata(&current) {
            if meta.file_type().is_symlink() {
                return Err(format!("symlink component refused: {}", current.display()));
            }
        }
    }
    Ok(())
}

/// 0700 directory (refuses symlink), temporary file via `create_new` + O_NOFOLLOW 0600,
/// fsync and `rename` over the destination (which cannot be a symlink).
pub(crate) fn write_private_atomic(file: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    let parent = file.parent().ok_or("destination has no directory")?;
    if !file.is_absolute() {
        return Err(format!("preferences path is not absolute: {}", file.display()));
    }
    refuse_symlinked_components(parent)?;
    match fs::symlink_metadata(parent) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(format!("configuration directory is a symlink: {}", parent.display()));
        }
        Ok(meta) if !meta.is_dir() => {
            return Err(format!("not a directory: {}", parent.display()));
        }
        Ok(_) => {}
        Err(_) => fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|error| format!("could not create {}: {error}", parent.display()))?,
    }
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("could not protect {}: {error}", parent.display()))?;
    if let Ok(meta) = fs::symlink_metadata(file) {
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(format!("{} is not a regular file (symlink refused)", file.display()));
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
            .map_err(|error| format!("failed to create {}: {error}", tmp.display()))?;
        handle
            .write_all(bytes)
            .and_then(|_| handle.sync_all())
            .map_err(|error| format!("failed to write {}: {error}", tmp.display()))?;
        fs::rename(&tmp, file).map_err(|error| format!("failed to write {}: {error}", file.display()))?;
        // fsync the directory: the rename survives a power loss.
        fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|error| format!("fsync failed for {}: {error}", parent.display()))
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
    fn cookie_source_roundtrip_preserves_other_preferences_and_legacy_defaults() {
        let mut prefs: Preferences = serde_json::from_str(r#"{"chromePath":"/browser","captureStartUrl":"https://example.org"}"#).unwrap();
        assert!(prefs.capture_cookie_source.is_none());
        prefs.capture_cookie_source = Some("chrome:Default".into());
        let root = base();
        let file = root.join("preferences.json");
        write_prefs(file.clone(), &prefs).unwrap();
        let restored = read_and_scrub(&file);
        assert_eq!(restored.capture_cookie_source.as_deref(), Some("chrome:Default"));
        assert_eq!(restored.chrome_path.as_deref(), Some("/browser"));
        assert_eq!(restored.capture_start_url.as_deref(), Some("https://example.org"));
        prefs.capture_cookie_source = None;
        write_prefs(file.clone(), &prefs).unwrap();
        assert!(!fs::read_to_string(&file).unwrap().contains("captureCookieSource"));
        fs::remove_dir_all(root).unwrap();
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
        // no leftover temporary files
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
        assert_eq!(prefs.capture_start_url, None, "userinfo invalidates the legacy URL");
        let text = fs::read_to_string(&file).unwrap();
        for secret in ["pw", "SECRET", "frag", "J1"] {
            assert!(!text.contains(secret), "{text}");
        }
        assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);

        fs::write(&file, r#"{"captureStartUrl":"https://h/p;jsessionid=J2?token=S2#f"}"#).unwrap();
        let mut prefs = read_and_scrub(&file);
        assert_eq!(prefs.capture_start_url.as_deref(), Some("https://h"));
        prefs.chrome_path = Some("/y".into());
        normalize(&mut prefs);
        write_prefs(file.clone(), &prefs).unwrap();
        let text = fs::read_to_string(&file).unwrap();
        assert!(!text.contains("J2") && !text.contains("S2"), "{text}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn proxy_is_saved_as_server_address_only() {
        let dir = base();
        let file = dir.join("preferences.json");
        save_capture_proxy_at(file.clone(), Some("http://reader:TopSecret-9@proxy.example:8080")).unwrap();
        let text = fs::read_to_string(&file).unwrap();
        assert!(text.contains("http://proxy.example:8080"), "{text}");
        assert!(!text.contains("TopSecret-9"), "the password must never reach the preferences file");
        assert!(!text.contains("reader"), "the username must never reach the preferences file");
        assert_eq!(load_capture_proxy_at(&file).as_deref(), Some("http://proxy.example:8080"));
        save_capture_proxy_at(file.clone(), None).unwrap();
        assert_eq!(load_capture_proxy_at(&file), None);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_legacy_file_with_credentials_is_scrubbed_on_read() {
        let dir = base();
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("preferences.json");
        fs::write(
            &file,
            r#"{"captureProxy":"socks5://reader:LegacySecret-7@10.0.0.5:1080"}"#,
        )
        .unwrap();
        assert_eq!(load_capture_proxy_at(&file).as_deref(), Some("socks5://10.0.0.5:1080"));
        let text = fs::read_to_string(&file).unwrap();
        assert!(!text.contains("LegacySecret-7"), "rewritten without the password: {text}");
        assert!(!text.contains("reader"), "rewritten without the username: {text}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_invalid_saved_proxy_is_dropped() {
        let dir = base();
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("preferences.json");
        fs::write(&file, r#"{"captureProxy":"socks4://old.example:1080"}"#).unwrap();
        assert_eq!(load_capture_proxy_at(&file), None);
        fs::remove_dir_all(&dir).ok();
    }
}
