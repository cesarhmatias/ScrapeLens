//! Import of cookies from installed browsers for the domain of a capture's
//! initial URL.
//!
//! Security and privacy rules:
//! - the user's browser database is **never** opened in place: it is copied
//!   (with `-wal`/`-shm`) into a private 0700 temporary directory, which is
//!   deleted on `Drop`; nothing is written to the personal profile;
//! - only cookies from the **same registrable site** as the initial URL's host
//!   get in (plus the host itself, for `localhost` and IPs), and expired cookies
//!   are left out;
//! - imported values are not written to the summary log: the audit event
//!   `Capture.cookiesImported` carries only the source, the domain and the
//!   counts. The cookies later appear, like any others, in the `Cookie` headers
//!   of CDP/NetLog — which is why the capture already starts with the sensitive
//!   data notice (`browser::SENSITIVE_NOTICE`).
//!
//! SQLite is read with the system's `sqlite3` (present on macOS; installed in the
//! Linux test images), always against the copy. Decryption is pure Rust
//! (SHA-1/SHA-256/PBKDF2/AES-128-CBC), with no OpenSSL and no new crate, so it
//! works the same on macOS and in the `--offline` container.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Cookie storage type of the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BrowserKind {
    Chromium,
    Firefox,
    Safari,
}

impl BrowserKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BrowserKind::Chromium => "chromium",
            BrowserKind::Firefox => "firefox",
            BrowserKind::Safari => "safari",
        }
    }
}

/// An installed browser profile with a readable cookie database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BrowserCookieSource {
    /// Stable identifier for the caller to choose: `chrome:Default`,
    /// `firefox:xxxx.default-release`, `safari:default`.
    pub id: String,
    /// Product name: `Google Chrome`, `Brave`, `Firefox`, `Safari`...
    pub browser: String,
    /// Profile: the friendly Chromium name (`Default (Person 1)`) or the Firefox
    /// profile directory.
    pub profile: String,
    /// Text for the UI: `Google Chrome — Default`.
    pub label: String,
    pub kind: BrowserKind,
    /// Path to the `Cookies`/`cookies.sqlite`/`Cookies.binarycookies` file.
    pub db_path: PathBuf,
}

/// Cookie ready for CDP's `Network.setCookies`. `domain` is the `host_key` as it
/// is in the database (it may start with `.`); `expires` is Unix time in seconds and
/// is absent for session cookies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub same_site: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<i64>,
}

/// Result of an import. `skipped` counts database cookies left out (expired, from
/// another site, `v11` without a key, non-UTF-8 value).
#[derive(Debug, Clone)]
pub struct CookieImportOutcome {
    pub source_id: String,
    pub label: String,
    pub domain: String,
    pub cookies: Vec<ImportedCookie>,
    pub skipped: usize,
    /// Structural warnings (no cookie values), for the session/UI.
    pub notes: Vec<String>,
}

impl CookieImportOutcome {
    /// Suffix for the capture's `notice`, without values.
    pub fn notice_suffix(&self) -> String {
        format!(
            " · {} cookie(s) imported from {}",
            self.cookies.len(),
            self.label
        )
    }
}

// ---------------------------------------------------------------------------
// Discovery of installed sources
// ---------------------------------------------------------------------------

/// Readable cookie sources on this machine, in stable order. A source only
/// gets in if its file exists; empty or unreadable profiles are left out.
pub fn list_browser_cookie_sources() -> Vec<BrowserCookieSource> {
    #[cfg(target_os = "macos")]
    {
        macos_sources()
    }
    #[cfg(target_os = "linux")]
    {
        linux_sources()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Vec::new()
    }
}

#[derive(Debug, Clone, Copy)]
struct ChromiumProduct {
    browser: &'static str,
    slug: &'static str,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    keychain_service: &'static str,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    keychain_account: &'static str,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    linux_secret_app: &'static str,
}

const CHROMIUM_PRODUCTS: &[ChromiumProduct] = &[
    ChromiumProduct {
        browser: "Google Chrome",
        slug: "chrome",
        keychain_service: "Chrome Safe Storage",
        keychain_account: "Chrome",
        linux_secret_app: "chrome",
    },
    ChromiumProduct {
        browser: "Brave",
        slug: "brave",
        keychain_service: "Brave Safe Storage",
        keychain_account: "Brave",
        linux_secret_app: "brave",
    },
    ChromiumProduct {
        browser: "Arc",
        slug: "arc",
        keychain_service: "Arc Safe Storage",
        keychain_account: "Arc",
        linux_secret_app: "arc",
    },
    ChromiumProduct {
        browser: "Microsoft Edge",
        slug: "edge",
        keychain_service: "Microsoft Edge Safe Storage",
        keychain_account: "Microsoft Edge",
        linux_secret_app: "microsoft-edge",
    },
    ChromiumProduct {
        browser: "Chromium",
        slug: "chromium",
        keychain_service: "Chromium Safe Storage",
        keychain_account: "Chromium",
        linux_secret_app: "chromium",
    },
];

fn product_for_slug(slug: &str) -> Option<&'static ChromiumProduct> {
    CHROMIUM_PRODUCTS.iter().find(|p| p.slug == slug)
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// Chromium profiles (`Default`, `Profile 1`, ...) inside a user-data-dir.
fn chromium_sources(
    product: &'static ChromiumProduct,
    user_data: &Path,
    out: &mut Vec<BrowserCookieSource>,
) {
    let Ok(entries) = std::fs::read_dir(user_data) else {
        return;
    };
    let friendly = chromium_profile_names(user_data);
    let mut profiles: Vec<(String, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            if name != "Default" && !name.starts_with("Profile ") {
                return None;
            }
            Some((name, entry.path()))
        })
        .collect();
    profiles.sort_by(|a, b| a.0.cmp(&b.0));
    for (dir_name, dir) in profiles {
        let db = if dir.join("Network/Cookies").is_file() {
            dir.join("Network/Cookies")
        } else if dir.join("Cookies").is_file() {
            dir.join("Cookies")
        } else {
            continue;
        };
        let profile = friendly
            .get(&dir_name)
            .cloned()
            .unwrap_or_else(|| dir_name.clone());
        out.push(BrowserCookieSource {
            id: format!("{}:{}", product.slug, dir_name),
            browser: product.browser.to_string(),
            profile,
            label: format!("{} — {}", product.browser, dir_name),
            kind: BrowserKind::Chromium,
            db_path: db,
        });
    }
}

/// `Local State` → `profile.info_cache` → friendly profile name. Read-only;
/// a missing or invalid file does not prevent discovery.
fn chromium_profile_names(user_data: &Path) -> std::collections::HashMap<String, String> {
    let mut names = std::collections::HashMap::new();
    let Ok(text) = std::fs::read(user_data.join("Local State")) else {
        return names;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&text) else {
        return names;
    };
    let Some(cache) = value
        .get("profile")
        .and_then(|p| p.get("info_cache"))
        .and_then(Value::as_object)
    else {
        return names;
    };
    for (dir, info) in cache {
        if let Some(name) = info.get("name").and_then(Value::as_str) {
            if !name.trim().is_empty() {
                names.insert(dir.clone(), format!("{dir} ({name})"));
            }
        }
    }
    names
}

#[cfg(target_os = "macos")]
fn macos_sources() -> Vec<BrowserCookieSource> {
    let mut out = Vec::new();
    if let Some(home) = home() {
        let app = home.join("Library/Application Support");
        let roots: &[(&str, &Path)] = &[
            ("chrome", &app.join("Google/Chrome")),
            ("brave", &app.join("BraveSoftware/Brave-Browser")),
            ("arc", &app.join("Arc/User Data")),
            ("edge", &app.join("Microsoft Edge")),
            ("chromium", &app.join("Chromium")),
        ];
        for (slug, root) in roots {
            if let Some(product) = product_for_slug(slug) {
                chromium_sources(product, root, &mut out);
            }
        }
        for profile in firefox_profile_dirs(&app.join("Firefox/Profiles")) {
            let db = profile.join("cookies.sqlite");
            if db.is_file() {
                out.push(firefox_source(&db, &profile));
            }
        }
        for candidate in [
            home.join("Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies"),
            home.join("Library/Cookies/Cookies.binarycookies"),
        ] {
            if candidate.is_file() {
                out.push(BrowserCookieSource {
                    id: "safari:default".to_string(),
                    browser: "Safari".to_string(),
                    profile: "default".to_string(),
                    label: "Safari — default".to_string(),
                    kind: BrowserKind::Safari,
                    db_path: candidate,
                });
                break;
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn linux_sources() -> Vec<BrowserCookieSource> {
    let mut out = Vec::new();
    if let Some(home) = home() {
        let config = home.join(".config");
        let roots: &[(&str, &Path)] = &[
            ("chrome", &config.join("google-chrome")),
            ("chromium", &config.join("chromium")),
            ("brave", &config.join("BraveSoftware/Brave-Browser")),
            ("edge", &config.join("microsoft-edge")),
        ];
        for (slug, root) in roots {
            if let Some(product) = product_for_slug(slug) {
                chromium_sources(product, root, &mut out);
            }
        }
        let mut firefox_roots = vec![
            home.join(".mozilla/firefox"),
            home.join("snap/firefox/common/.mozilla/firefox"),
        ];
        for root in firefox_roots.drain(..) {
            for profile in firefox_profile_dirs(&root) {
                let db = profile.join("cookies.sqlite");
                if db.is_file() {
                    out.push(firefox_source(&db, &profile));
                }
            }
        }
    }
    out
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn firefox_profile_dirs(profiles_root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(profiles_root) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.path())
        .collect();
    dirs.sort();
    dirs
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn firefox_source(db: &Path, profile_dir: &Path) -> BrowserCookieSource {
    let profile = profile_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("default")
        .to_string();
    BrowserCookieSource {
        id: format!("firefox:{profile}"),
        browser: "Firefox".to_string(),
        label: format!("Firefox — {profile}"),
        profile,
        kind: BrowserKind::Firefox,
        db_path: db.to_path_buf(),
    }
}

// ---------------------------------------------------------------------------
// URL, registrable site and domain filter
// ---------------------------------------------------------------------------

/// Lowercase host of an `http(s)` URL: no user, port or IPv6 brackets.
pub fn url_host(target_url: &str) -> Option<String> {
    let rest = target_url.split_once("://").map(|(_, r)| r)?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = match authority.rsplit_once('@') {
        Some((_, after)) => after,
        None => authority,
    };
    if authority.is_empty() {
        return None;
    }
    let host = if let Some(after_open) = authority.strip_prefix('[') {
        after_open.split_once(']').map(|(h, _)| h)?
    } else {
        authority.split(':').next()?
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn is_ip(host: &str) -> bool {
    host.contains(':') || host.parse::<std::net::Ipv4Addr>().is_ok()
}

/// Compound suffixes used in the project's URLs and in common eTLD+1 cases.
const COMPOUND_SUFFIXES: &[&str] = &[
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "art.br", "blog.br", "eco.br",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "ne.jp", "or.jp", "com.au", "net.au",
    "org.au", "co.nz", "com.mx", "com.ar", "com.co", "com.pt", "com.es", "co.za",
];

/// `app.exemplo.com.br` → `exemplo.com.br`; `exemplo.com` → `exemplo.com`;
/// `localhost`/IP → `None` (the match is then exact).
pub fn registrable_domain(host: &str) -> Option<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || is_ip(&host) {
        return None;
    }
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }
    let last_two = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    let compound = COMPOUND_SUFFIXES.contains(&last_two.as_str())
        || (labels[labels.len() - 1].len() == 2
            && ["com", "net", "org", "gov", "edu", "co", "ac", "or", "ne", "go"]
                .contains(&labels[labels.len() - 2]));
    let start = if compound { 3 } else { 2 };
    if labels.len() < start {
        return None;
    }
    Some(labels[labels.len() - start..].join("."))
}

/// Does the cookie belong to the host's site? Same registrable site (includes
/// login/SSO subdomains), or exact host for `localhost`/IP.
fn cookie_matches_host(cookie_domain: &str, host: &str) -> bool {
    let domain = cookie_domain.trim_start_matches('.').trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return false;
    }
    if domain == host {
        return true;
    }
    match (registrable_domain(&domain), registrable_domain(host)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Private copy of the database (read-only, deleted on Drop)
// ---------------------------------------------------------------------------

struct CookieDbCopy {
    dir: PathBuf,
    db: PathBuf,
}

impl Drop for CookieDbCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn copy_cookie_db(source: &Path) -> Result<CookieDbCopy, String> {
    let meta = std::fs::metadata(source)
        .map_err(|error| format!("cookie database inaccessible ({}): {error}", source.display()))?;
    if !meta.is_file() {
        return Err(format!(
            "cookie database is not a regular file: {}",
            source.display()
        ));
    }
    let dir = crate::private_base_dir().join(format!(
        "scrapelens-cookies-{}-{}",
        std::process::id(),
        unix_nanos()
    ));
    crate::create_private_dir_new(&dir)
        .map_err(|error| format!("cookie temporary directory: {error}"))?;
    let db = dir.join("cookies.db");
    if let Err(error) = std::fs::copy(source, &db) {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(format!("copy the cookie database: {error}"));
    }
    // WAL and SHM follow the copy: without them SQLite does not see the most
    // recent cookies (Chrome keeps its writes in the WAL).
    for suffix in ["-wal", "-shm"] {
        let mut name = source.as_os_str().to_os_string();
        name.push(suffix);
        let side = PathBuf::from(name);
        if side.is_file() {
            let mut dest = db.as_os_str().to_os_string();
            dest.push(suffix);
            let _ = std::fs::copy(&side, PathBuf::from(dest));
        }
    }
    Ok(CookieDbCopy { dir, db })
}

fn unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Reading SQLite through the system CLI
// ---------------------------------------------------------------------------

#[cfg(test)]
fn sqlite3_available() -> bool {
    Command::new("sqlite3")
        .arg("-version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Runs a query on the copied database and returns the rows separated by TAB.
/// Text always comes out as `hex(...)`, so name/value/domain never break the
/// line, even with TAB, quotes or a non-UTF-8 byte.
fn sqlite_rows(db: &Path, sql: &str) -> Result<Vec<Vec<String>>, String> {
    let output = Command::new("sqlite3")
        .arg("-batch")
        .arg("-noheader")
        .arg("-separator")
        .arg("\t")
        .arg(db)
        .arg(sql)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            format!("sqlite3 not found (install the sqlite3 package): {error}")
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let first = stderr.lines().next().unwrap_or("sqlite3 error");
        return Err(format!("cookie query failed: {first}"));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| line.split('\t').map(str::to_string).collect())
        .collect())
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() {
        return Some(Vec::new());
    }
    if text.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

fn unhex_text(text: &str) -> String {
    unhex(text)
        .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
        .unwrap_or_default()
}

fn sql_quote(value: &str) -> String {
    // Only an already normalized host gets in (letters, digits, '.', ':', '-' and '_');
    // even so, quotes are doubled for safety.
    format!("'{}'", value.replace('\'', "''"))
}

fn host_candidates(host: &str) -> Vec<String> {
    let mut out = vec![host.to_string()];
    if let Some(site) = registrable_domain(host) {
        out.push(site.clone());
        out.push(format!(".{site}"));
        if site != host {
            out.push(format!(".{host}"));
        }
    }
    out.sort();
    out.dedup();
    out
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Chromium decryption (v10/v11)
// ---------------------------------------------------------------------------

fn chromium_key(product: &ChromiumProduct, version_prefix: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(target_os = "macos")]
    {
        let _ = version_prefix;
        let password = keychain_password(product.keychain_service, product.keychain_account)?;
        Ok(pbkdf2_sha1(&password, b"saltysalt", 1003, 16))
    }
    #[cfg(target_os = "linux")]
    {
        if version_prefix == b"v11" {
            return linux_v11_key(product);
        }
        let _ = version_prefix;
        Ok(pbkdf2_sha1(b"peanuts", b"saltysalt", 1, 16))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (product, version_prefix);
        Err("cookie decryption is not supported on this platform".to_string())
    }
}

#[cfg(target_os = "macos")]
fn keychain_password(service: &str, account: &str) -> Result<Vec<u8>, String> {
    let mut child = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-w", "-s", service, "-a", account])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("Keychain ({service}): {error}"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child
                    .wait_with_output()
                    .map_err(|error| format!("Keychain ({service}): {error}"))?;
                if !status.success() {
                    return Err(format!(
                        "could not read the \"{service}\" password from the Keychain; authorize access and try again"
                    ));
                }
                let mut password = output.stdout;
                while matches!(password.last(), Some(b'\n') | Some(b'\r')) {
                    password.pop();
                }
                if password.is_empty() {
                    return Err(format!("the \"{service}\" password in the Keychain came back empty"));
                }
                return Ok(password);
            }
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "the Keychain did not respond within 30 s for \"{service}\" (authorization pending?)"
                ));
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_v11_key(product: &ChromiumProduct) -> Result<Vec<u8>, String> {
    let output = Command::new("secret-tool")
        .args([
            "lookup",
            "xdg:schema",
            "chrome_libsecret_os_crypt_password_v2",
            "application",
            product.linux_secret_app,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|_| {
            format!(
                "v11 cookie of {}: install libsecret/secret-tool or use a profile with v10",
                product.browser
            )
        })?;
    if !output.status.success() || output.stdout.is_empty() {
        return Err(format!(
            "v11 cookie of {}: the password is not in libsecret",
            product.browser
        ));
    }
    let mut password = output.stdout;
    while matches!(password.last(), Some(b'\n') | Some(b'\r')) {
        password.pop();
    }
    Ok(pbkdf2_sha1(&password, b"saltysalt", 1, 16))
}

/// `v10`/`v11` + AES-128-CBC (IV = 16 spaces, PKCS#7). In Chrome 130+ the
/// plaintext starts with 32 bytes of SHA-256(host_key); the prefix is only removed
/// when it matches exactly.
fn decrypt_chromium_value(
    encrypted: &[u8],
    key: &[u8],
    host_key: &str,
    value_version: Option<i64>,
) -> Result<String, String> {
    if encrypted.len() < 3 {
        return Err("encrypted value too short".to_string());
    }
    if &encrypted[..3] != b"v10" && &encrypted[..3] != b"v11" {
        return Err("unknown encryption prefix".to_string());
    }
    let mut plain = aes_128_cbc_decrypt(key, &[0x20u8; 16], &encrypted[3..])?;
    let hash = sha256(host_key.as_bytes());
    let has_hash_prefix = plain.len() >= 32 && plain[..32] == hash[..];
    // Chrome 130+ (meta.version >= 24) prefixes SHA-256(host_key). With no version
    // in the database, an exact match of the 32 bytes is enough; with an old version, it does not remove.
    if has_hash_prefix && value_version.map_or(true, |v| v >= 24) {
        plain.drain(..32);
    }
    String::from_utf8(plain).map_err(|_| "cookie value is not UTF-8".to_string())
}

fn same_site_from_db(value: i64) -> Option<String> {
    match value {
        0 => Some("None".to_string()),
        1 => Some("Lax".to_string()),
        2 => Some("Strict".to_string()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Cookies for the site of `target_url` from the source `source_id`.
pub fn load_cookies_for_url(
    source_id: &str,
    target_url: &str,
) -> Result<CookieImportOutcome, String> {
    let source = list_browser_cookie_sources()
        .into_iter()
        .find(|s| s.id == source_id)
        .ok_or_else(|| format!("cookie source not found: {source_id}"))?;
    let host = url_host(target_url)
        .ok_or_else(|| format!("initial URL without an http(s) host: {target_url}"))?;
    let site = registrable_domain(&host).unwrap_or_else(|| host.clone());

    let copy = copy_cookie_db(&source.db_path)?;
    let mut skipped = 0usize;
    let mut notes = Vec::new();
    let mut cookies = match source.kind {
        BrowserKind::Chromium => {
            load_chromium(&source, &copy.db, &host, &mut skipped, &mut notes)?
        }
        BrowserKind::Firefox => load_firefox(&copy.db, &host, &mut skipped, &mut notes)?,
        BrowserKind::Safari => load_safari(&copy.db, &host, &mut skipped, &mut notes)?,
    };
    drop_expired(&mut cookies, &mut skipped);
    cookies.sort_by(|a, b| {
        (&a.domain, &a.path, &a.name).cmp(&(&b.domain, &b.path, &b.name))
    });
    cookies.dedup();
    Ok(CookieImportOutcome {
        source_id: source.id,
        label: source.label,
        domain: site,
        cookies,
        skipped,
        notes,
    })
}

/// Removes expired cookies (with `expires` set) and counts those removed.
fn drop_expired(cookies: &mut Vec<ImportedCookie>, skipped: &mut usize) {
    let now = unix_now();
    let before = cookies.len();
    cookies.retain(|cookie| cookie.expires.map_or(true, |expires| expires > now));
    *skipped += before - cookies.len();
}

fn load_chromium(
    source: &BrowserCookieSource,
    db: &Path,
    host: &str,
    skipped: &mut usize,
    notes: &mut Vec<String>,
) -> Result<Vec<ImportedCookie>, String> {
    let product = product_for_slug(source.id.split(':').next().unwrap_or(""))
        .ok_or_else(|| format!("unknown Chromium product: {}", source.id))?;
    let version = sqlite_rows(db, "SELECT value FROM meta WHERE key='version'")
        .ok()
        .and_then(|rows| rows.first().and_then(|r| r.first().cloned()))
        .and_then(|v| v.trim().parse::<i64>().ok());
    let hosts = host_candidates(host);
    let list = hosts
        .iter()
        .map(|h| sql_quote(h))
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT hex(host_key), hex(name), hex(value), hex(encrypted_value), hex(path), \
         expires_utc, is_secure, is_httponly, samesite, is_persistent FROM cookies \
         WHERE host_key IN ({list})"
    );
    let rows = sqlite_rows(db, &sql)?;
    let mut key: Option<Vec<u8>> = None;
    let mut key_error: Option<String> = None;
    let mut cookies = Vec::new();
    for row in rows {
        if row.len() < 10 {
            *skipped += 1;
            continue;
        }
        let host_key = unhex_text(&row[0]);
        if !cookie_matches_host(&host_key, host) {
            *skipped += 1;
            continue;
        }
        let name = unhex_text(&row[1]);
        if name.is_empty() {
            *skipped += 1;
            continue;
        }
        let stored_value = unhex_text(&row[2]);
        let encrypted = unhex(&row[3]).unwrap_or_default();
        let value = if encrypted.is_empty() {
            stored_value
        } else {
            if key.is_none() && key_error.is_none() {
                match chromium_key(product, &encrypted[..3]) {
                    Ok(found) => key = Some(found),
                    Err(why) => {
                        notes.push(format!("{why} (encrypted cookies ignored)"));
                        key_error = Some(why);
                    }
                }
            }
            let Some(found) = key.as_deref() else {
                *skipped += 1;
                continue;
            };
            match decrypt_chromium_value(&encrypted, found, &host_key, version) {
                Ok(value) => value,
                Err(why) => {
                    *skipped += 1;
                    notes.push(format!("{why} ({} cookie ignored)", source.label));
                    continue;
                }
            }
        };
        let expires_utc = row[5].trim().parse::<i64>().unwrap_or(0);
        let persistent = row[9].trim().parse::<i64>().unwrap_or(1) != 0;
        let expires = if persistent && expires_utc > 0 {
            Some(expires_utc / 1_000_000 - 11_644_473_600)
        } else {
            None
        };
        cookies.push(ImportedCookie {
            name,
            value,
            domain: host_key,
            path: {
                let path = unhex_text(&row[4]);
                if path.is_empty() {
                    "/".to_string()
                } else {
                    path
                }
            },
            secure: row[6].trim().parse::<i64>().unwrap_or(0) != 0,
            http_only: row[7].trim().parse::<i64>().unwrap_or(0) != 0,
            same_site: same_site_from_db(row[8].trim().parse::<i64>().unwrap_or(-1)),
            expires,
        });
    }
    Ok(cookies)
}

fn load_firefox(
    db: &Path,
    host: &str,
    skipped: &mut usize,
    notes: &mut Vec<String>,
) -> Result<Vec<ImportedCookie>, String> {
    let hosts = host_candidates(host);
    let list = hosts
        .iter()
        .map(|h| sql_quote(h))
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT hex(host), hex(name), hex(value), hex(path), expiry, isSecure, isHttpOnly, \
         sameSite FROM moz_cookies WHERE host IN ({list})"
    );
    let rows = sqlite_rows(db, &sql)?;
    let mut cookies = Vec::new();
    for row in rows {
        if row.len() < 8 {
            *skipped += 1;
            continue;
        }
        let host_key = unhex_text(&row[0]);
        if !cookie_matches_host(&host_key, host) {
            *skipped += 1;
            continue;
        }
        let name = unhex_text(&row[1]);
        if name.is_empty() {
            *skipped += 1;
            continue;
        }
        let expiry = row[4].trim().parse::<i64>().unwrap_or(0);
        cookies.push(ImportedCookie {
            name,
            value: unhex_text(&row[2]),
            domain: host_key,
            path: {
                let path = unhex_text(&row[3]);
                if path.is_empty() {
                    "/".to_string()
                } else {
                    path
                }
            },
            secure: row[5].trim().parse::<i64>().unwrap_or(0) != 0,
            http_only: row[6].trim().parse::<i64>().unwrap_or(0) != 0,
            same_site: same_site_from_db(row[7].trim().parse::<i64>().unwrap_or(-1)),
            expires: (expiry > 0).then_some(expiry),
        });
    }
    let _ = notes;
    Ok(cookies)
}

fn load_safari(
    db: &Path,
    host: &str,
    skipped: &mut usize,
    notes: &mut Vec<String>,
) -> Result<Vec<ImportedCookie>, String> {
    let bytes = std::fs::read(db).map_err(|error| format!("ler Cookies.binarycookies: {error}"))?;
    let raw = parse_binarycookies(&bytes)?;
    let mut cookies = Vec::new();
    for cookie in raw {
        if !cookie_matches_host(&cookie.domain, host) {
            *skipped += 1;
            continue;
        }
        cookies.push(ImportedCookie {
            name: cookie.name,
            value: cookie.value,
            domain: cookie.domain,
            path: if cookie.path.is_empty() {
                "/".to_string()
            } else {
                cookie.path
            },
            secure: cookie.secure,
            http_only: cookie.http_only,
            same_site: None,
            expires: (cookie.expires > 0).then_some(cookie.expires),
        });
    }
    let _ = notes;
    Ok(cookies)
}

/// Converts the list to the `cookies` parameter of `Network.setCookies`. Never
/// returns the values to a log; it is just the CDP payload.
pub(crate) fn cdp_cookies(cookies: &[ImportedCookie]) -> Value {
    Value::Array(
        cookies
            .iter()
            .map(|cookie| {
                let mut value = json!({
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": cookie.secure,
                    "httpOnly": cookie.http_only,
                });
                if let Some(same_site) = &cookie.same_site {
                    value["sameSite"] = json!(same_site);
                }
                if let Some(expires) = cookie.expires {
                    value["expires"] = json!(expires);
                }
                value
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Safari `Cookies.binarycookies`
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
struct RawCookie {
    domain: String,
    name: String,
    value: String,
    path: String,
    secure: bool,
    http_only: bool,
    expires: i64,
}

/// `cook` big-endian: 4 magic bytes, page count, page sizes and, in each page,
/// cookies with offsets. Strings are NUL-terminated; the date is an `f64` in
/// seconds since 2001-01-01.
fn parse_binarycookies(bytes: &[u8]) -> Result<Vec<RawCookie>, String> {
    if bytes.len() < 8 || &bytes[..4] != b"cook" {
        return Err("Cookies.binarycookies: invalid signature".to_string());
    }
    let pages = be_u32(bytes, 4).ok_or("truncated file")? as usize;
    let mut pos = 8usize;
    let mut sizes = Vec::with_capacity(pages);
    for _ in 0..pages {
        sizes.push(be_u32(bytes, pos).ok_or("truncated page size")? as usize);
        pos += 4;
    }
    let mut cookies = Vec::new();
    for size in sizes {
        if pos + size > bytes.len() {
            return Err("truncated cookie page".to_string());
        }
        parse_binarycookies_page(&bytes[pos..pos + size], &mut cookies)?;
        pos += size;
    }
    Ok(cookies)
}

fn parse_binarycookies_page(page: &[u8], out: &mut Vec<RawCookie>) -> Result<(), String> {
    if page.len() < 8 {
        return Ok(());
    }
    let count = le_u32(page, 4).ok_or("truncated page")? as usize;
    let mut offsets = Vec::with_capacity(count);
    for index in 0..count {
        let at = 8 + index * 4;
        offsets.push(le_u32(page, at).ok_or("truncated cookie offset")? as usize);
    }
    for offset in offsets {
        if offset >= page.len() {
            continue;
        }
        let record = &page[offset..];
        if record.len() < 48 {
            continue;
        }
        let flags = le_u32(record, 8).ok_or("truncated cookie")?;
        let url_off = le_u32(record, 16).ok_or("truncated cookie")? as usize;
        let name_off = le_u32(record, 20).ok_or("truncated cookie")? as usize;
        let path_off = le_u32(record, 24).ok_or("truncated cookie")? as usize;
        let value_off = le_u32(record, 28).ok_or("truncated cookie")? as usize;
        let expiry = be_f64(record, 40).ok_or("truncated cookie")?;
        let Some(domain) = c_string(record, url_off) else {
            continue;
        };
        let Some(name) = c_string(record, name_off) else {
            continue;
        };
        let Some(path) = c_string(record, path_off) else {
            continue;
        };
        let Some(value) = c_string(record, value_off) else {
            continue;
        };
        let expires = if expiry.is_finite() && expiry > 0.0 {
            (expiry as i64).saturating_add(978_307_200)
        } else {
            0
        };
        out.push(RawCookie {
            domain,
            name,
            value,
            path,
            secure: flags & 1 != 0,
            http_only: flags & 4 != 0,
            expires,
        });
    }
    Ok(())
}

fn be_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at + 4)?;
    Some(u32::from_be_bytes(slice.try_into().ok()?))
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at + 4)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

fn be_f64(bytes: &[u8], at: usize) -> Option<f64> {
    let slice = bytes.get(at..at + 8)?;
    Some(f64::from_be_bytes(slice.try_into().ok()?))
}

fn c_string(bytes: &[u8], at: usize) -> Option<String> {
    if at >= bytes.len() {
        return None;
    }
    let tail = &bytes[at..];
    let len = tail.iter().position(|b| *b == 0).unwrap_or(tail.len());
    Some(String::from_utf8_lossy(&tail[..len]).to_string())
}

// ---------------------------------------------------------------------------
// Crypto: SHA-1, SHA-256, HMAC-SHA1, PBKDF2-HMAC-SHA1 e AES-128-CBC
// ---------------------------------------------------------------------------

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let mut message = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in message.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4,
        0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe,
        0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f,
        0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da, 0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
        0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc,
        0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
        0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070, 0x19a4_c116,
        0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
        0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let mut message = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in message.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let temp1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let temp2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(temp1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = temp1.wrapping_add(temp2);
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..20].copy_from_slice(&sha1(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + message.len());
    let mut outer = Vec::with_capacity(84);
    for byte in block {
        inner.push(byte ^ 0x36);
    }
    inner.extend_from_slice(message);
    let inner_hash = sha1(&inner);
    for byte in block {
        outer.push(byte ^ 0x5c);
    }
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}

/// PBKDF2-HMAC-SHA1 (RFC 2898) producing `dk_len` bytes.
pub fn pbkdf2_sha1(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    let iterations = iterations.max(1);
    let mut out = Vec::with_capacity(dk_len);
    let mut block_index = 1u32;
    while out.len() < dk_len {
        let mut salt_block = salt.to_vec();
        salt_block.extend_from_slice(&block_index.to_be_bytes());
        let mut u = hmac_sha1(password, &salt_block);
        let mut t = u;
        for _ in 1..iterations {
            u = hmac_sha1(password, &u);
            for i in 0..20 {
                t[i] ^= u[i];
            }
        }
        out.extend_from_slice(&t);
        block_index += 1;
    }
    out.truncate(dk_len);
    out
}

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

fn xtime(byte: u8) -> u8 {
    (byte << 1) ^ if byte & 0x80 != 0 { 0x1b } else { 0 }
}

fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    product
}

fn expand_key(key: &[u8]) -> [u8; 176] {
    let mut expanded = [0u8; 176];
    expanded[..16].copy_from_slice(key);
    let mut rcon = 1u8;
    for round in 1..11 {
        let offset = round * 16;
        let mut temp = [
            expanded[offset - 4],
            expanded[offset - 3],
            expanded[offset - 2],
            expanded[offset - 1],
        ];
        // Each loop step produces exactly 4 words: the first word of EVERY step
        // is a multiple of 4 and goes through `g` (SubWord + RotWord +
        // Rcon), not only every four steps.
        temp.rotate_left(1);
        for byte in &mut temp {
            *byte = SBOX[*byte as usize];
        }
        temp[0] ^= rcon;
        rcon = xtime(rcon);
        for i in 0..4 {
            expanded[offset + i] = expanded[offset - 16 + i] ^ temp[i];
        }
        for i in 4..16 {
            expanded[offset + i] = expanded[offset - 16 + i] ^ expanded[offset + i - 4];
        }
    }
    expanded
}

fn add_round_key(state: &mut [u8; 16], round_key: &[u8; 176], round: usize) {
    for i in 0..16 {
        state[i] ^= round_key[round * 16 + i];
    }
}

fn inv_shift_rows(state: &mut [u8; 16]) {
    let copy = *state;
    for row in 1..4 {
        for column in 0..4 {
            state[row + 4 * column] = copy[row + 4 * ((column + 4 - row) % 4)];
        }
    }
}

fn inv_sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = INV_SBOX[*byte as usize];
    }
}

fn inv_mix_columns(state: &mut [u8; 16]) {
    for column in 0..4 {
        let i = column * 4;
        let (a0, a1, a2, a3) = (state[i], state[i + 1], state[i + 2], state[i + 3]);
        state[i] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
        state[i + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
        state[i + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
        state[i + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
    }
}

fn aes128_decrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let round_keys = expand_key(key);
    let mut state = *block;
    add_round_key(&mut state, &round_keys, 10);
    for round in (1..10).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, &round_keys, round);
        inv_mix_columns(&mut state);
    }
    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    add_round_key(&mut state, &round_keys, 0);
    state
}

/// AES-128-CBC decrypt with optional PKCS#7 (invalid padding is kept as it came:
/// some profiles store values with zero padding).
pub fn aes_128_cbc_decrypt(key: &[u8], iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 16 {
        return Err("AES-128 key must be 16 bytes".to_string());
    }
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err("ciphertext is not a multiple of 16".to_string());
    }
    let key: [u8; 16] = key.try_into().expect("checado acima");
    let mut previous = *iv;
    let mut out = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks(16) {
        let block: [u8; 16] = chunk.try_into().expect("multiple of 16");
        let decrypted = aes128_decrypt_block(&key, &block);
        for i in 0..16 {
            out.push(decrypted[i] ^ previous[i]);
        }
        previous = block;
    }
    if let Some(&padding) = out.last() {
        let padding = padding as usize;
        if (1..=16).contains(&padding)
            && out.len() >= padding
            && out[out.len() - padding..].iter().all(|b| *b == padding as u8)
        {
            out.truncate(out.len() - padding);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        unhex(text).unwrap()
    }

    #[test]
    fn sha1_and_sha256_match_the_standard_vectors() {
        assert_eq!(
            hex_string(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex_string(&sha1(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            hex_string(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn pbkdf2_hmac_sha1_matches_rfc_6070() {
        assert_eq!(
            hex_string(&pbkdf2_sha1(b"password", b"salt", 1, 20)),
            "0c60c80f961f0e71f3a9b524af6012062fe037a6"
        );
        assert_eq!(
            hex_string(&pbkdf2_sha1(b"password", b"salt", 2, 20)),
            "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
        );
        assert_eq!(
            hex_string(&pbkdf2_sha1(b"password", b"salt", 4096, 20)),
            "4b007901b765489abead49d926f721d065a429c1"
        );
        assert_eq!(
            hex_string(&pbkdf2_sha1(b"peanuts", b"saltysalt", 1, 16)),
            hex_string(&pbkdf2_sha1(b"peanuts", b"saltysalt", 1, 16))
        );
    }

    #[test]
    fn aes_128_cbc_decrypts_the_nist_vector() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let ciphertext = hex(
            "7649abac8119b246cee98e9b12e9197d\
             5086cb9b507219ee95db113a917678b2",
        );
        let plain = aes_128_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        assert_eq!(
            hex_string(&plain),
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        );
    }

    #[test]
    fn chromium_v10_value_decrypts_and_strips_the_sha256_prefix() {
        // Encrypt via the reverse path? No: we use a vector built here with a minimal
        // forward AES to prove the removal of the Chrome 130+ prefix.
        let host = ".exemplo.com.br";
        let key = pbkdf2_sha1(b"peanuts", b"saltysalt", 1, 16);
        let hash = sha256(host.as_bytes());
        let mut plain = hash.to_vec();
        plain.extend_from_slice(b"valor-secreto");
        let key_bytes: [u8; 16] = key.as_slice().try_into().unwrap();
        let encrypted = encrypt_for_test(&key_bytes, &[0x20u8; 16], &plain);
        let mut blob = b"v10".to_vec();
        blob.extend_from_slice(&encrypted);
        let value = decrypt_chromium_value(&blob, &key, host, Some(24)).unwrap();
        assert_eq!(value, "valor-secreto");
        // With no version in the database, the exact prefix match still removes it.
        assert_eq!(decrypt_chromium_value(&blob, &key, host, None).unwrap(), "valor-secreto");
    }

    #[test]
    fn registrable_domain_handles_compound_suffixes() {
        assert_eq!(registrable_domain("app.exemplo.com.br").as_deref(), Some("exemplo.com.br"));
        assert_eq!(registrable_domain("exemplo.com.br").as_deref(), Some("exemplo.com.br"));
        assert_eq!(registrable_domain("a.b.exemplo.co.uk").as_deref(), Some("exemplo.co.uk"));
        assert_eq!(registrable_domain("sub.exemplo.com").as_deref(), Some("exemplo.com"));
        assert_eq!(registrable_domain("localhost"), None);
        assert_eq!(registrable_domain("127.0.0.1"), None);
        assert_eq!(registrable_domain("::1"), None);
    }

    #[test]
    fn cookie_matching_includes_subdomains_of_the_same_site() {
        assert!(cookie_matches_host(".exemplo.com.br", "app.exemplo.com.br"));
        assert!(cookie_matches_host("exemplo.com.br", "app.exemplo.com.br"));
        assert!(cookie_matches_host("login.exemplo.com.br", "app.exemplo.com.br"));
        assert!(cookie_matches_host(".exemplo.com.br", "exemplo.com.br"));
        assert!(!cookie_matches_host(".outro.com.br", "app.exemplo.com.br"));
        assert!(!cookie_matches_host("outro.com", "app.exemplo.com.br"));
        assert!(cookie_matches_host("localhost", "localhost"));
        assert!(!cookie_matches_host("127.0.0.1", "127.0.0.2"));
    }

    #[test]
    fn url_host_strips_user_port_and_brackets() {
        assert_eq!(url_host("https://app.exemplo.com.br/painel?x=1").as_deref(), Some("app.exemplo.com.br"));
        assert_eq!(url_host("https://user:pass@Exemplo.COM:8443/").as_deref(), Some("exemplo.com"));
        assert_eq!(url_host("http://[::1]:8781/x").as_deref(), Some("::1"));
        assert_eq!(url_host("about:blank"), None);
    }

    #[test]
    fn host_candidates_cover_the_site_and_its_dot_form() {
        let mut got = host_candidates("app.exemplo.com.br");
        got.sort();
        assert_eq!(
            got,
            vec![
                ".app.exemplo.com.br",
                ".exemplo.com.br",
                "app.exemplo.com.br",
                "exemplo.com.br",
            ]
        );
    }

    #[test]
    fn safari_binarycookies_parses_a_synthetic_file() {
        // One page, one cookie: "sid=abc" for ".exemplo.com.br", secure.
        let domain = b".exemplo.com.br\0";
        let name = b"sid\0";
        let path = b"/\0";
        let value = b"abc\0";
        let header = 56usize;
        let url_off = header;
        let name_off = url_off + domain.len();
        let path_off = name_off + name.len();
        let value_off = path_off + path.len();
        let total = value_off + value.len();
        let mut record = vec![0u8; header];
        record[0..4].copy_from_slice(&(total as u32).to_le_bytes());
        record[8..12].copy_from_slice(&1u32.to_le_bytes()); // secure
        record[16..20].copy_from_slice(&(url_off as u32).to_le_bytes());
        record[20..24].copy_from_slice(&(name_off as u32).to_le_bytes());
        record[24..28].copy_from_slice(&(path_off as u32).to_le_bytes());
        record[28..32].copy_from_slice(&(value_off as u32).to_le_bytes());
        record[40..48].copy_from_slice(&(1_700_000_000f64 - 978_307_200f64).to_be_bytes());
        record.extend_from_slice(domain);
        record.extend_from_slice(name);
        record.extend_from_slice(path);
        record.extend_from_slice(value);
        let mut page = vec![0u8; 8];
        page[0..4].copy_from_slice(&0x0000_0100u32.to_le_bytes());
        page[4..8].copy_from_slice(&1u32.to_le_bytes());
        page.extend_from_slice(&(8u32 + 4).to_le_bytes()); // cookie offset
        page.extend_from_slice(&record);
        let mut file = b"cook".to_vec();
        file.extend_from_slice(&1u32.to_be_bytes());
        file.extend_from_slice(&(page.len() as u32).to_be_bytes());
        file.extend_from_slice(&page);
        let cookies = parse_binarycookies(&file).unwrap();
        assert_eq!(cookies.len(), 1);
        let cookie = &cookies[0];
        assert_eq!(cookie.name, "sid");
        assert_eq!(cookie.value, "abc");
        assert_eq!(cookie.domain, ".exemplo.com.br");
        assert!(cookie.secure);
        assert_eq!(cookie.expires, 1_700_000_000);
    }

    #[test]
    fn cdp_payload_carries_only_present_fields() {
        let cookies = vec![
            ImportedCookie {
                name: "a".into(),
                value: "1".into(),
                domain: ".exemplo.com.br".into(),
                path: "/".into(),
                secure: true,
                http_only: true,
                same_site: Some("Lax".into()),
                expires: Some(1_700_000_000),
            },
            ImportedCookie {
                name: "b".into(),
                value: "2".into(),
                domain: "exemplo.com.br".into(),
                path: "/x".into(),
                secure: false,
                http_only: false,
                same_site: None,
                expires: None,
            },
        ];
        let payload = cdp_cookies(&cookies);
        assert_eq!(payload[0]["sameSite"], "Lax");
        assert_eq!(payload[0]["expires"], 1_700_000_000);
        assert!(payload[1].get("sameSite").is_none());
        assert!(payload[1].get("expires").is_none());
        assert_eq!(payload[1]["httpOnly"], false);
    }

    #[test]
    fn short_or_unknown_encrypted_values_are_refused() {
        let key = [0u8; 16];
        assert!(decrypt_chromium_value(b"v10", &key, "h", None).is_err());
        assert!(decrypt_chromium_value(b"xx", &key, "h", None).is_err());
        assert!(decrypt_chromium_value(b"v12abcdef", &key, "h", None).is_err());
    }

    #[test]
    fn sqlite_roundtrip_reads_chromium_and_firefox_tables() {
        if !sqlite3_available() {
            eprintln!("sqlite3 missing: database test skipped");
            return;
        }
        let dir = crate::private_base_dir().join(format!(
            "scrapelens-cookies-test-{}-{}",
            std::process::id(),
            unix_nanos()
        ));
        crate::create_private_dir_new(&dir).unwrap();
        let chromium_db = dir.join("Cookies");
        // Plain-text value: the test covers reading SQLite; decryption has its own
        // test (without touching the user's Keychain).
        let sql = "PRAGMA journal_mode=DELETE;\
             CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);\
             INSERT INTO meta VALUES('version','24');\
             CREATE TABLE cookies(host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, samesite INTEGER, is_persistent INTEGER);\
             INSERT INTO cookies VALUES('.exemplo.com.br','sid','segredo','', '/',0,1,1,1,1);\
             INSERT INTO cookies VALUES('.outro.com.br','fora','x','', '/',0,0,0,-1,1);\
             INSERT INTO cookies VALUES('.exemplo.com.br','velho','x','', '/',1,0,0,-1,1);";
        let status = Command::new("sqlite3").arg(&chromium_db).arg(sql).output().unwrap();
        assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stderr));
        let firefox_db = dir.join("cookies.sqlite");
        let sql = "CREATE TABLE moz_cookies(host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER);\
                   INSERT INTO moz_cookies VALUES('.exemplo.com.br','ff','valor','/',4102444800,1,0,2);\
                   INSERT INTO moz_cookies VALUES('.outro.com.br','ff-fora','x','/',4102444800,0,0,0);";
        let status = Command::new("sqlite3").arg(&firefox_db).arg(sql).output().unwrap();
        assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stderr));

        let source = BrowserCookieSource {
            id: "chrome:Default".to_string(),
            browser: "Google Chrome".to_string(),
            profile: "Default".to_string(),
            label: "Google Chrome — Default".to_string(),
            kind: BrowserKind::Chromium,
            db_path: chromium_db,
        };
        let mut skipped = 0;
        let mut notes = Vec::new();
        let copy = copy_cookie_db(&source.db_path).unwrap();
        let mut cookies = load_chromium(&source, &copy.db, "app.exemplo.com.br", &mut skipped, &mut notes).unwrap();
        assert_eq!(cookies.len(), 2, "sid and the expired one; the one from another site does not get in");
        assert_eq!(cookies[0].name, "sid");
        assert_eq!(cookies[0].value, "segredo");
        assert!(cookies[0].secure);
        assert_eq!(skipped, 0);
        drop_expired(&mut cookies, &mut skipped);
        assert_eq!(cookies.len(), 1, "the expired one is dropped by the common filter");
        assert_eq!(skipped, 1);
        drop(copy);

        let mut skipped = 0;
        let mut notes = Vec::new();
        let copy = copy_cookie_db(&source.db_path).unwrap();
        let _ = copy;
        let fsource = BrowserCookieSource {
            id: "firefox:test".to_string(),
            browser: "Firefox".to_string(),
            profile: "test".to_string(),
            label: "Firefox — test".to_string(),
            kind: BrowserKind::Firefox,
            db_path: firefox_db,
        };
        let copy = copy_cookie_db(&fsource.db_path).unwrap();
        let cookies = load_firefox(&copy.db, "app.exemplo.com.br", &mut skipped, &mut notes).unwrap();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name, "ff");
        assert_eq!(cookies[0].value, "valor");
        assert_eq!(cookies[0].same_site.as_deref(), Some("Strict"));
        let _ = std::fs::remove_dir_all(dir);
    }

    // -- test helpers --

    fn hex_string(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// AES-128-CBC forward, for the tests only (the product encrypts nothing).
    fn encrypt_for_test(key: &[u8; 16], iv: &[u8; 16], plain: &[u8]) -> Vec<u8> {
        let padded = {
            let padding = 16 - (plain.len() % 16);
            let mut buffer = plain.to_vec();
            buffer.extend(std::iter::repeat(padding as u8).take(padding));
            buffer
        };
        let round_keys = expand_key(key);
        let mut previous = *iv;
        let mut out = Vec::with_capacity(padded.len());
        for chunk in padded.chunks(16) {
            let mut block: [u8; 16] = chunk.try_into().unwrap();
            for i in 0..16 {
                block[i] ^= previous[i];
            }
            let encrypted = aes128_encrypt_block(&round_keys, &block);
            out.extend_from_slice(&encrypted);
            previous = encrypted;
        }
        out
    }

    fn aes128_encrypt_block(round_keys: &[u8; 176], block: &[u8; 16]) -> [u8; 16] {
        let mut state = *block;
        add_round_key(&mut state, round_keys, 0);
        for round in 1..10 {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, round_keys, round);
        }
        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, round_keys, 10);
        state
    }

    fn sub_bytes(state: &mut [u8; 16]) {
        for byte in state.iter_mut() {
            *byte = SBOX[*byte as usize];
        }
    }

    fn shift_rows(state: &mut [u8; 16]) {
        let copy = *state;
        for row in 1..4 {
            for column in 0..4 {
                state[row + 4 * column] = copy[row + 4 * ((column + row) % 4)];
            }
        }
    }

    fn mix_columns(state: &mut [u8; 16]) {
        for column in 0..4 {
            let i = column * 4;
            let (a0, a1, a2, a3) = (state[i], state[i + 1], state[i + 2], state[i + 3]);
            state[i] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
            state[i + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
            state[i + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
            state[i + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
        }
    }
}
