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
use zeroize::Zeroize;

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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl std::fmt::Debug for ImportedCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedCookie")
            .field("name", &self.name)
            .field("value", &"***")
            .field("domain", &self.domain)
            .field("path", &self.path)
            .field("secure", &self.secure)
            .field("http_only", &self.http_only)
            .field("same_site", &self.same_site)
            .field("expires", &self.expires)
            .finish()
    }
}

impl Drop for ImportedCookie {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Result of an import. `skipped` counts database cookies left out on purpose (expired,
/// from another site, not a cookie). `undecryptable` counts encrypted cookies of the site
/// that could not be read, and `undecryptable_reason` says why (no cookie values).
#[derive(Debug, Clone)]
pub struct CookieImportOutcome {
    pub source_id: String,
    pub label: String,
    pub domain: String,
    pub cookies: Vec<ImportedCookie>,
    pub skipped: usize,
    pub undecryptable: usize,
    pub undecryptable_reason: Option<String>,
    /// Structural warnings (no cookie values), for the session/UI.
    pub notes: Vec<String>,
}

impl CookieImportOutcome {
    /// Suffix for the capture's `notice`, without values.
    pub fn notice_suffix(&self) -> String {
        let mut text = format!(
            " · {} cookie(s) imported from {}",
            self.cookies.len(),
            self.label
        );
        if self.undecryptable > 0 {
            text.push_str(&format!(
                "; {} cookie(s) could not be decrypted: {}",
                self.undecryptable,
                self.undecryptable_reason.as_deref().unwrap_or("unknown reason")
            ));
        }
        text
    }
}

/// Counts and reasons collected while reading one database. Passed down to the loaders.
#[derive(Debug, Default)]
struct ImportTally {
    skipped: usize,
    undecryptable: usize,
    /// Reason → number of cookies it applies to (sorted, so the text is stable).
    reasons: std::collections::BTreeMap<String, usize>,
    notes: Vec<String>,
}

impl ImportTally {
    fn undecryptable(&mut self, reason: String) {
        self.undecryptable += 1;
        *self.reasons.entry(reason).or_insert(0) += 1;
    }

    /// `reason (n); other reason (m)`, or `None` when every cookie was read.
    fn reason_text(&self) -> Option<String> {
        if self.reasons.is_empty() {
            return None;
        }
        Some(
            self.reasons
                .iter()
                .map(|(reason, count)| format!("{reason} ({count})"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    fn first_reason(&self) -> Option<String> {
        self.reasons.keys().next().cloned()
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

/// Product slug of a source id: `chrome:Default` and `chrome+flatpak:Default` both give `chrome`.
fn product_slug(source_id: &str) -> &str {
    let head = source_id.split(':').next().unwrap_or("");
    head.split('+').next().unwrap_or("")
}

/// Packaging variant of a source: a Flatpak or Snap copy of a browser keeps its own
/// id (`chrome+flatpak:Default`) and label, so it never collides with a native install.
fn variant_id(variant: &str) -> String {
    if variant.is_empty() {
        String::new()
    } else {
        format!("+{variant}")
    }
}

fn variant_label(variant: &str) -> &'static str {
    match variant {
        "flatpak" => " (Flatpak)",
        "snap" => " (Snap)",
        _ => "",
    }
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// Chromium profiles (`Default`, `Profile 1`, ...) inside a user-data-dir.
fn chromium_sources(
    product: &'static ChromiumProduct,
    variant: &str,
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
        let suffix = variant_label(variant);
        out.push(BrowserCookieSource {
            id: format!("{}{}:{}", product.slug, variant_id(variant), dir_name),
            browser: product.browser.to_string(),
            profile,
            label: format!("{}{} — {}", product.browser, suffix, dir_name),
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
                chromium_sources(product, "", root, &mut out);
            }
        }
        for profile in firefox_profile_dirs(&app.join("Firefox/Profiles")) {
            let db = profile.join("cookies.sqlite");
            if db.is_file() {
                out.push(firefox_source(&db, &profile, ""));
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
    match home() {
        Some(home) => linux_sources_in(&home),
        None => Vec::new(),
    }
}

/// Linux profile discovery under `home`: native installs, Flatpak and Snap packages.
/// Flatpak and Snap keep their data under their own roots and are checked separately.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_sources_in(home: &Path) -> Vec<BrowserCookieSource> {
    let mut out = Vec::new();
    let config = home.join(".config");
    let chromium_roots: &[(&str, &str, PathBuf)] = &[
        ("chrome", "", config.join("google-chrome")),
        ("chromium", "", config.join("chromium")),
        ("brave", "", config.join("BraveSoftware/Brave-Browser")),
        ("edge", "", config.join("microsoft-edge")),
        ("chrome", "flatpak", home.join(".var/app/com.google.Chrome/config/google-chrome")),
        ("chromium", "flatpak", home.join(".var/app/org.chromium.Chromium/config/chromium")),
        ("brave", "flatpak", home.join(".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser")),
        ("edge", "flatpak", home.join(".var/app/com.microsoft.Edge/config/microsoft-edge")),
        ("chromium", "snap", home.join("snap/chromium/common/chromium")),
    ];
    for (slug, variant, root) in chromium_roots {
        if let Some(product) = product_for_slug(slug) {
            chromium_sources(product, variant, root, &mut out);
        }
    }
    let firefox_roots: &[(&str, PathBuf)] = &[
        ("", home.join(".mozilla/firefox")),
        ("snap", home.join("snap/firefox/common/.mozilla/firefox")),
        ("flatpak", home.join(".var/app/org.mozilla.firefox/.mozilla/firefox")),
    ];
    for (variant, root) in firefox_roots {
        for profile in firefox_profile_dirs(root) {
            let db = profile.join("cookies.sqlite");
            if db.is_file() {
                out.push(firefox_source(&db, &profile, variant));
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
fn firefox_source(db: &Path, profile_dir: &Path, variant: &str) -> BrowserCookieSource {
    let profile = profile_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("default")
        .to_string();
    BrowserCookieSource {
        id: format!("firefox{}:{profile}", variant_id(variant)),
        browser: "Firefox".to_string(),
        label: format!("Firefox{} — {profile}", variant_label(variant)),
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

/// `app.example.com.br` → `example.com.br`; `example.com` → `example.com`;
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
    /// Problems copying the sidecar files (WAL, shared memory, journal): the copy may be stale.
    notes: Vec<String>,
}

impl Drop for CookieDbCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Name prefix of a private copy: `scrapelens-cookies-<pid>-<nanos>`.
const COPY_PREFIX: &str = "scrapelens-cookies-";
/// A copy this old is removed even if its process id is taken (pid reuse after a reboot).
const STALE_COPY_AGE: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

fn copy_cookie_db(source: &Path) -> Result<CookieDbCopy, String> {
    copy_cookie_db_in(source, &crate::private_base_dir())
}

fn copy_cookie_db_in(source: &Path, base: &Path) -> Result<CookieDbCopy, String> {
    let meta = std::fs::metadata(source)
        .map_err(|error| format!("cookie database inaccessible ({}): {error}", source.display()))?;
    if !meta.is_file() {
        return Err(format!(
            "cookie database is not a regular file: {}",
            source.display()
        ));
    }
    sweep_stale_copies(base);
    let dir = base.join(format!(
        "{COPY_PREFIX}{}-{}",
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
    // WAL, SHM and the rollback journal follow the copy: without them SQLite does not
    // see the most recent cookies (Chrome keeps its writes in the WAL), and a copy taken
    // in the middle of a transaction is only consistent with its hot journal.
    let mut notes = Vec::new();
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = source.as_os_str().to_os_string();
        name.push(suffix);
        let side = PathBuf::from(name);
        if side.is_file() {
            let mut dest = db.as_os_str().to_os_string();
            dest.push(suffix);
            if let Err(error) = std::fs::copy(&side, PathBuf::from(dest)) {
                notes.push(format!(
                    "could not copy the {suffix} file next to the cookie database ({error}); the most recent cookies may be missing"
                ));
            }
        }
    }
    Ok(CookieDbCopy { dir, db, notes })
}

/// Removes private copies left behind by an import that was killed, crashed or cut off by
/// a reboot. Only directories of this user, with the copy's name, mode 0700 and not a
/// symlink are touched, and only when their process is gone or they are over a day old.
/// A running import's copy (this process included) is never removed.
fn sweep_stale_copies(base: &Path) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };
    // SAFETY: getuid has no failure mode and no arguments.
    let me = unsafe { libc::getuid() };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(rest) = name.strip_prefix(COPY_PREFIX) else { continue };
        let Some(pid) = rest.split('-').next().and_then(|p| p.parse::<i32>().ok()) else {
            continue;
        };
        if pid <= 0 {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
        if !meta.is_dir() || meta.file_type().is_symlink() {
            continue;
        }
        if meta.uid() != me || meta.permissions().mode() & 0o777 != 0o700 {
            continue;
        }
        let old = meta
            .modified()
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age > STALE_COPY_AGE);
        if !old && process_alive(pid) {
            continue;
        }
        let _ = std::fs::remove_dir_all(&path);
    }
}

/// Whether a process id belongs to a live process (or one we may not signal).
fn process_alive(pid: i32) -> bool {
    // SAFETY: signal 0 only checks that the process exists; it sends nothing.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
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
    helper_command("sqlite3")
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
/// Runs an external helper (`sqlite3`, `secret-tool`) with the environment it expects.
/// Inside an AppImage the launcher puts the AppImage's own libraries in
/// `LD_LIBRARY_PATH`; a system helper then loads those and fails (for example
/// `undefined symbol: sqlite3_error_offset`). The helper gets the system libraries.
#[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
fn helper_command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(program);
    #[cfg(target_os = "linux")]
    command.env_remove("LD_LIBRARY_PATH");
    command
}

/// Linux system libraries loaded at run time (`dlopen`), so the import needs no helper
/// command: the SQLite library that WebKit already uses for the App, and the libsecret
/// client that Chrome already links for its cookie key. An AppImage's environment and
/// a missing `sqlite3` or `secret-tool` package cannot break it. `None` means the
/// library is not there, and the caller falls back to the command.
#[cfg(target_os = "linux")]
mod native {
    use std::ffi::{c_char, c_int, c_void, CStr, CString};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::sync::OnceLock;

    const SQLITE_OK: c_int = 0;
    const SQLITE_ROW: c_int = 100;
    const SQLITE_DONE: c_int = 101;
    const SQLITE_OPEN_READWRITE: c_int = 0x2;

    type OpenV2 = unsafe extern "C" fn(*const c_char, *mut *mut c_void, c_int, *const c_char) -> c_int;
    type PrepareV2 = unsafe extern "C" fn(*mut c_void, *const c_char, c_int, *mut *mut c_void, *mut *const c_char) -> c_int;
    type Step = unsafe extern "C" fn(*mut c_void) -> c_int;
    type ColumnCount = unsafe extern "C" fn(*mut c_void) -> c_int;
    type ColumnText = unsafe extern "C" fn(*mut c_void, c_int) -> *const c_char;
    type Finalize = unsafe extern "C" fn(*mut c_void) -> c_int;
    type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
    type ErrMsg = unsafe extern "C" fn(*mut c_void) -> *const c_char;

    struct Sqlite {
        open_v2: OpenV2,
        prepare_v2: PrepareV2,
        step: Step,
        column_count: ColumnCount,
        column_text: ColumnText,
        finalize: Finalize,
        close: Close,
        errmsg: ErrMsg,
    }

    /// Opens a shared library by name, or `None` when it is not installed.
    fn open_library(name: &str) -> Option<usize> {
        let name = CString::new(name).ok()?;
        // SAFETY: a plain dlopen of a system library; the handle is kept for the process lifetime.
        let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        (!handle.is_null()).then_some(handle as usize)
    }

    /// The address of a symbol in a library opened by `open_library`.
    fn symbol(handle: usize, name: &str) -> Option<*mut c_void> {
        let name = CString::new(name).ok()?;
        // SAFETY: `handle` came from dlopen; a missing symbol yields NULL, which is checked.
        let address = unsafe { libc::dlsym(handle as *mut c_void, name.as_ptr()) };
        (!address.is_null()).then_some(address)
    }

    fn sqlite_api() -> Option<&'static Sqlite> {
        static API: OnceLock<Option<Sqlite>> = OnceLock::new();
        API.get_or_init(|| {
            let handle = open_library("libsqlite3.so.0")?;
            // SAFETY: each address is the documented SQLite C API function with this signature.
            unsafe {
                Some(Sqlite {
                    open_v2: std::mem::transmute::<*mut c_void, OpenV2>(symbol(handle, "sqlite3_open_v2")?),
                    prepare_v2: std::mem::transmute::<*mut c_void, PrepareV2>(symbol(handle, "sqlite3_prepare_v2")?),
                    step: std::mem::transmute::<*mut c_void, Step>(symbol(handle, "sqlite3_step")?),
                    column_count: std::mem::transmute::<*mut c_void, ColumnCount>(symbol(handle, "sqlite3_column_count")?),
                    column_text: std::mem::transmute::<*mut c_void, ColumnText>(symbol(handle, "sqlite3_column_text")?),
                    finalize: std::mem::transmute::<*mut c_void, Finalize>(symbol(handle, "sqlite3_finalize")?),
                    close: std::mem::transmute::<*mut c_void, Close>(symbol(handle, "sqlite3_close")?),
                    errmsg: std::mem::transmute::<*mut c_void, ErrMsg>(symbol(handle, "sqlite3_errmsg")?),
                })
            }
        })
        .as_ref()
    }

    /// Rows of one query on a database file, every column as text (NULL is empty), the
    /// same values the `sqlite3` command prints. `None` when SQLite is not available.
    pub(super) fn sqlite_query(db: &Path, sql: &str) -> Option<Result<Vec<Vec<String>>, String>> {
        let api = sqlite_api()?;
        let path = CString::new(db.as_os_str().as_bytes()).ok()?;
        let sql = CString::new(sql).ok()?;
        // SAFETY: every pointer is either from SQLite (checked for NULL before use) or
        // from a CString that outlives the call; statements and the handle are released on every path.
        unsafe {
            let mut handle: *mut c_void = std::ptr::null_mut();
            let opened = (api.open_v2)(path.as_ptr(), &mut handle, SQLITE_OPEN_READWRITE, std::ptr::null());
            if opened != SQLITE_OK {
                let why = last_error(api, handle);
                (api.close)(handle);
                return Some(Err(format!("cookie database could not be opened: {why}")));
            }
            let mut stmt: *mut c_void = std::ptr::null_mut();
            let prepared = (api.prepare_v2)(handle, sql.as_ptr(), -1, &mut stmt, std::ptr::null_mut());
            if prepared != SQLITE_OK || stmt.is_null() {
                let why = last_error(api, handle);
                (api.close)(handle);
                return Some(Err(format!("cookie query failed: {why}")));
            }
            let mut rows = Vec::new();
            let mut failure = None;
            loop {
                match (api.step)(stmt) {
                    SQLITE_ROW => {
                        let columns = (api.column_count)(stmt);
                        let mut row = Vec::with_capacity(columns.max(0) as usize);
                        for column in 0..columns {
                            let text = (api.column_text)(stmt, column);
                            row.push(if text.is_null() {
                                String::new()
                            } else {
                                CStr::from_ptr(text).to_string_lossy().into_owned()
                            });
                        }
                        rows.push(row);
                    }
                    SQLITE_DONE => break,
                    _ => {
                        failure = Some(last_error(api, handle));
                        break;
                    }
                }
            }
            (api.finalize)(stmt);
            (api.close)(handle);
            Some(match failure {
                Some(why) => Err(format!("cookie query failed: {why}")),
                None => Ok(rows),
            })
        }
    }

    /// SAFETY: `handle` must be a SQLite connection or NULL.
    unsafe fn last_error(api: &Sqlite, handle: *mut c_void) -> String {
        if handle.is_null() {
            return "unknown error".to_string();
        }
        let text = (api.errmsg)(handle);
        if text.is_null() {
            "unknown error".to_string()
        } else {
            CStr::from_ptr(text).to_string_lossy().into_owned()
        }
    }

    /// Secret Service lookup of the browser's cookie key, through libsecret. The caller
    /// decides what an empty result means. `None` when libsecret is not installed.
    pub(super) fn secret_lookup(application: &str) -> Option<Result<Vec<u8>, String>> {
        type HashFn = unsafe extern "C" fn(*const c_void) -> u32;
        type EqualFn = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;
        type NewTable = unsafe extern "C" fn(HashFn, EqualFn, Option<unsafe extern "C" fn(*mut c_void)>, Option<unsafe extern "C" fn(*mut c_void)>) -> *mut c_void;
        type Insert = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> c_int;
        type Unref = unsafe extern "C" fn(*mut c_void);
        type Dup = unsafe extern "C" fn(*const c_char) -> *mut c_char;
        type Free = unsafe extern "C" fn(*mut c_void);
        type Lookup = unsafe extern "C" fn(*const c_void, *mut c_void, *mut c_void, *mut *mut c_void) -> *mut c_char;
        type PasswordFree = unsafe extern "C" fn(*mut c_char);
        type ErrorFree = unsafe extern "C" fn(*mut c_void);

        static LIB: OnceLock<Option<(usize, usize)>> = OnceLock::new();
        let (secret, glib) = LIB.get_or_init(|| Some((open_library("libsecret-1.so.0")?, open_library("libglib-2.0.so.0")?)))
            .as_ref()
            .copied()?;
        // SAFETY: each symbol is the documented libsecret / GLib function with the signature
        // declared above; every pointer handed in is valid for the call and released after it.
        unsafe {
            let lookup: Lookup = std::mem::transmute(symbol(secret, "secret_password_lookupv_sync")?);
            let password_free: PasswordFree = std::mem::transmute(symbol(secret, "secret_password_free")?);
            let new_table: NewTable = std::mem::transmute(symbol(glib, "g_hash_table_new_full")?);
            let insert: Insert = std::mem::transmute(symbol(glib, "g_hash_table_insert")?);
            let unref: Unref = std::mem::transmute(symbol(glib, "g_hash_table_unref")?);
            let dup: Dup = std::mem::transmute(symbol(glib, "g_strdup")?);
            let free: Free = std::mem::transmute(symbol(glib, "g_free")?);
            let error_free: ErrorFree = std::mem::transmute(symbol(glib, "g_error_free")?);
            let str_hash: HashFn = std::mem::transmute(symbol(glib, "g_str_hash")?);
            let str_equal: EqualFn = std::mem::transmute(symbol(glib, "g_str_equal")?);

            let table = new_table(str_hash, str_equal, Some(free), Some(free));
            for (key, value) in [("xdg:schema", "chrome_libsecret_os_crypt_password_v2"), ("application", application)] {
                let key = CString::new(key).ok()?;
                let value = CString::new(value).ok()?;
                insert(table, dup(key.as_ptr()) as *mut c_void, dup(value.as_ptr()) as *mut c_void);
            }
            let mut error: *mut c_void = std::ptr::null_mut();
            let password = lookup(std::ptr::null(), table, std::ptr::null_mut(), &mut error);
            unref(table);
            if !error.is_null() {
                // GError: domain (u32), code (i32), message (pointer) on 64-bit Linux.
                let message_ptr = *((error as *const u8).add(8) as *const *const c_char);
                let message = if message_ptr.is_null() {
                    "unknown error".to_string()
                } else {
                    CStr::from_ptr(message_ptr).to_string_lossy().into_owned()
                };
                error_free(error);
                return Some(Err(message));
            }
            if password.is_null() {
                return Some(Ok(Vec::new()));
            }
            let bytes = CStr::from_ptr(password).to_bytes().to_vec();
            password_free(password);
            Some(Ok(bytes))
        }
    }
}

fn sqlite_rows(db: &Path, sql: &str) -> Result<Vec<Vec<String>>, String> {
    #[cfg(target_os = "linux")]
    if let Some(result) = native::sqlite_query(db, sql) {
        return result;
    }
    sqlite_cli_rows(db, sql)
}

/// The `sqlite3` command, for systems where SQLite cannot be loaded as a library.
fn sqlite_cli_rows(db: &Path, sql: &str) -> Result<Vec<Vec<String>>, String> {
    let output = helper_command("sqlite3")
        .arg("-batch")
        .arg("-noheader")
        .arg("-separator")
        .arg("\t")
        .arg(db)
        .arg(sql)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                "the sqlite3 command is not installed; the cookie import needs it (Debian/Ubuntu package `sqlite3`)".to_string()
            } else {
                format!("the sqlite3 command could not run: {error}")
            }
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

/// The candidate keys for a value prefix, in the order they are tried. Each candidate is a
/// key, or the reason it could not be had. A value takes the first candidate that decrypts it.
fn chromium_keys(product: &ChromiumProduct, version_prefix: &[u8]) -> Vec<Result<Vec<u8>, String>> {
    #[cfg(target_os = "macos")]
    {
        let _ = version_prefix;
        let key = keychain_password(product.keychain_service, product.keychain_account)
            .map(|password| pbkdf2_sha1(&password[..], b"saltysalt", 1003, 16));
        vec![key]
    }
    #[cfg(target_os = "linux")]
    {
        if version_prefix == b"v11" {
            return linux_v11_keys(product);
        }
        let _ = version_prefix;
        vec![Ok(pbkdf2_sha1(b"peanuts", b"saltysalt", 1, 16))]
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (product, version_prefix);
        vec![Err("cookie decryption is not supported on this platform".to_string())]
    }
}

#[cfg(target_os = "macos")]
fn keychain_password(service: &str, account: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
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
                return Ok(zeroize::Zeroizing::new(password));
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

/// How long the browser's key may take to come back from the keyring. A locked keyring
/// waits for the user to unlock it; past this the import reports it instead of waiting.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const KEYRING_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);

/// The error for a keyring that is locked, or whose unlock prompt was not answered.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn keyring_locked_error(browser: &str) -> String {
    format!("v11 cookie of {browser}: keyring is locked: unlock it and try again")
}

/// Outcome of a call bounded in time.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum Bounded<T> {
    Done(T),
    TimedOut,
    Failed,
}

/// Runs `work` on a throwaway thread and waits at most `deadline` for its result. A call
/// that does not finish is left behind on its own thread; the capture never waits for it.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn bounded<T: Send + 'static>(
    deadline: std::time::Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Bounded<T> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(work());
    });
    match receiver.recv_timeout(deadline) {
        Ok(value) => Bounded::Done(value),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Bounded::TimedOut,
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Bounded::Failed,
    }
}

/// Keyring item names a browser's cookie key may be stored under, in the order tried: its
/// own name first, then the names other Chromium builds use. Microsoft Edge writes
/// `application=chromium` (label "Chromium Safe Storage"). A key is only used when it
/// decrypts a value (see `decrypt_chromium_value`), so a wrong name cannot give garbage.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_secret_applications(product: &ChromiumProduct) -> Vec<&'static str> {
    let mut names = vec![product.linux_secret_app];
    for other in ["chromium", "chrome"] {
        if !names.contains(&other) {
            names.push(other);
        }
    }
    names
}

/// The candidate v11 keys: one per keyring name, from libsecret (one bounded call for all
/// names) or, when libsecret is not installed, from `secret-tool` under the same deadline.
#[cfg(target_os = "linux")]
fn linux_v11_keys(product: &ChromiumProduct) -> Vec<Result<Vec<u8>, String>> {
    let names = linux_secret_applications(product);
    let lookups = names.clone();
    match bounded(KEYRING_DEADLINE, move || {
        lookups
            .iter()
            .map(|application| native::secret_lookup(application))
            .collect::<Vec<_>>()
    }) {
        Bounded::TimedOut => vec![Err(keyring_locked_error(product.browser))],
        Bounded::Failed => vec![Err(format!(
            "v11 cookie of {}: the keyring lookup failed; try again",
            product.browser
        ))],
        Bounded::Done(results) => {
            // One deadline for every secret-tool name. The closure runs only when
            // libsecret is absent for all of them.
            let until = std::time::Instant::now() + KEYRING_DEADLINE;
            linux_v11_keys_from(product, results, |application| {
                secret_tool_password(Path::new("secret-tool"), product.browser, application, until)
            })
        }
    }
}

/// Turns finished keyring lookups into candidate keys. `library` has one entry per
/// keyring name: `None` means libsecret is not installed. When every entry is `None`,
/// `secret_tool` supplies the password or the reason. Tests pass those results in,
/// so a machine keyring cannot change the message.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_v11_keys_from(
    product: &ChromiumProduct,
    library: Vec<Option<Result<Vec<u8>, String>>>,
    mut secret_tool: impl FnMut(&str) -> Result<Vec<u8>, String>,
) -> Vec<Result<Vec<u8>, String>> {
    if library.iter().all(Option::is_none) {
        return linux_secret_applications(product)
            .into_iter()
            .map(|application| {
                secret_tool(application).and_then(|password| browser_key_from_password(product, password))
            })
            .collect();
    }
    library
        .into_iter()
        .map(|result| match result {
            None => Err(format!(
                "v11 cookie of {}: the keyring is not available; try again",
                product.browser
            )),
            Some(Ok(password)) => browser_key_from_password(product, password),
            Some(Err(why)) => Err(keyring_error(product.browser, &why)),
        })
        .collect()
}

/// Maps a keyring error text to the message the user acts on: a locked keyring asks for
/// an unlock; any other error is reported with its text.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn keyring_error(browser: &str, why: &str) -> String {
    let lowered = why.to_ascii_lowercase();
    if lowered.contains("lock") || lowered.contains("prompt") || lowered.contains("unlock") {
        return keyring_locked_error(browser);
    }
    format!(
        "v11 cookie of {browser}: the keyring did not return the browser password ({why}); unlock the keyring and try again"
    )
}

/// The browser's keyring password to the cookie key (PBKDF2 with one iteration, as
/// Chromium derives it on Linux).
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn browser_key_from_password(product: &ChromiumProduct, password: Vec<u8>) -> Result<Vec<u8>, String> {
    let password = zeroize::Zeroizing::new(password);
    if password.is_empty() {
        // The Secret Service answers an empty result for a locked collection too (it does
        // not prompt), so the two cases share the message that fixes both.
        return Err(format!(
            "v11 cookie of {}: keyring is locked or has no entry for this browser: unlock it and try again",
            product.browser
        ));
    }
    Ok(pbkdf2_sha1(&password[..], b"saltysalt", 1, 16))
}

/// A failure to start `secret-tool`. `NotFound` names the package to install; anything
/// else keeps the operating-system text.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn secret_tool_command_error(browser: &str, error: &std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::NotFound {
        format!(
            "v11 cookie of {browser}: the secret-tool command is not installed; install it (Debian/Ubuntu package `libsecret-tools`)"
        )
    } else {
        format!("v11 cookie of {browser}: secret-tool could not run: {error}")
    }
}

/// The `secret-tool` command for one keyring name, bounded by `until`. A locked keyring makes
/// it wait for the prompt: past the deadline the process is killed and the locked message is
/// returned.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn secret_tool_password(
    program: &Path,
    browser: &str,
    application: &str,
    until: std::time::Instant,
) -> Result<Vec<u8>, String> {
    let mut child = helper_command(program)
        .args([
            "lookup",
            "xdg:schema",
            "chrome_libsecret_os_crypt_password_v2",
            "application",
            application,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| secret_tool_command_error(browser, &error))?;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < until => {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(keyring_locked_error(browser));
            }
            Err(error) => {
                return Err(format!("v11 cookie of {browser}: secret-tool could not be waited for: {error}"));
            }
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("v11 cookie of {browser}: secret-tool output: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let first = stderr.lines().next().unwrap_or("").trim();
        return Err(keyring_error(
            browser,
            if first.is_empty() { "no entry found" } else { first },
        ));
    }
    let mut password = output.stdout;
    while matches!(password.last(), Some(b'\n') | Some(b'\r')) {
        password.pop();
    }
    Ok(password)
}

/// The error for a key that does not decrypt a value. A wrong key never yields a value.
const WRONG_KEY: &str = "the key does not decrypt this value";

/// Removes PKCS#7 padding; `None` when the padding is not valid (a wrong key almost always
/// leaves invalid padding).
fn pkcs7_unpad(data: &[u8]) -> Option<Vec<u8>> {
    let padding = *data.last()? as usize;
    if !(1..=16).contains(&padding) || data.len() < padding {
        return None;
    }
    if data[data.len() - padding..].iter().any(|b| *b as usize != padding) {
        return None;
    }
    Some(data[..data.len() - padding].to_vec())
}

/// `v10`/`v11` + AES-128-CBC (IV = 16 spaces, PKCS#7). In Chrome 130+ (`meta.version >= 24`)
/// the plaintext starts with 32 bytes of SHA-256(host_key), and a key that does not produce
/// that prefix does not decrypt the value. Padding and UTF-8 are checked for every version.
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
    let padded = aes_128_cbc_decrypt(key, &[0x20u8; 16], &encrypted[3..])?;
    let mut plain = pkcs7_unpad(&padded).ok_or_else(|| WRONG_KEY.to_string())?;
    let hash = sha256(host_key.as_bytes());
    let has_hash_prefix = plain.len() >= 32 && plain[..32] == hash[..];
    if value_version.is_some_and(|v| v >= 24) {
        if !has_hash_prefix {
            return Err(WRONG_KEY.to_string());
        }
        plain.drain(..32);
    } else if has_hash_prefix && value_version.is_none() {
        // No version in the database: the exact 32-byte prefix is removed, as before.
        plain.drain(..32);
    }
    String::from_utf8(plain).map_err(|_| WRONG_KEY.to_string())
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
    let mut tally = ImportTally {
        notes: copy.notes.clone(),
        ..ImportTally::default()
    };
    let mut cookies = match source.kind {
        BrowserKind::Chromium => load_chromium(&source, &copy.db, &host, &mut tally)?,
        BrowserKind::Firefox => load_firefox(&copy.db, &host, &mut tally)?,
        BrowserKind::Safari => load_safari(&copy.db, &host, &mut tally)?,
    };
    drop_expired(&mut cookies, &mut tally.skipped);
    cookies.sort_by(|a, b| {
        (&a.domain, &a.path, &a.name).cmp(&(&b.domain, &b.path, &b.name))
    });
    cookies.dedup();
    Ok(CookieImportOutcome {
        source_id: source.id,
        label: source.label,
        domain: site,
        cookies,
        skipped: tally.skipped,
        undecryptable: tally.undecryptable,
        undecryptable_reason: tally.reason_text(),
        notes: tally.notes,
    })
}

/// Removes expired cookies (with `expires` set) and counts those removed.
fn drop_expired(cookies: &mut Vec<ImportedCookie>, skipped: &mut usize) {
    let now = unix_now();
    let before = cookies.len();
    cookies.retain(|cookie| cookie.expires.map_or(true, |expires| expires > now));
    *skipped += before - cookies.len();
}

type CachedKey = Result<zeroize::Zeroizing<Vec<u8>>, String>;

/// Keys derived for one import. Drop, and [`KeyCache::clear`], zero the bytes.
#[derive(Default)]
struct KeyCache {
    keys: std::collections::HashMap<Vec<u8>, Vec<CachedKey>>,
}

impl KeyCache {
    fn candidates(
        &mut self,
        prefix: &[u8],
        key_for: &mut impl FnMut(&[u8]) -> Vec<Result<Vec<u8>, String>>,
    ) -> &[CachedKey] {
        if !self.keys.contains_key(prefix) {
            let filled = key_for(prefix)
                .into_iter()
                .map(|item| item.map(zeroize::Zeroizing::new))
                .collect();
            self.keys.insert(prefix.to_vec(), filled);
        }
        &self.keys[prefix]
    }

    fn clear(&mut self) {
        for group in self.keys.values_mut() {
            for key in group.iter_mut().flatten() {
                (*key).zeroize();
            }
        }
        self.keys.clear();
        #[cfg(test)]
        KEY_CACHE_CLEARED.with(|flag| flag.set(true));
    }
}

impl Drop for KeyCache {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
thread_local! {
    static KEY_CACHE_CLEARED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Decrypts one encrypted value. The key comes from the value's own prefix (`v10` or
/// `v11`) and is cached per prefix, so a profile that mixes both versions keeps each
/// value readable. A key that cannot be had fails only the values it covers.
fn decrypt_row(
    encrypted: &[u8],
    host_key: &str,
    version: Option<i64>,
    keys: &mut KeyCache,
    key_for: &mut impl FnMut(&[u8]) -> Vec<Result<Vec<u8>, String>>,
) -> Result<String, String> {
    if encrypted.len() < 3 {
        return Err("encrypted value is too short to decrypt".to_string());
    }
    let prefix = encrypted[..3].to_vec();
    if prefix.as_slice() != b"v10" && prefix.as_slice() != b"v11" {
        return Err("unknown encryption prefix".to_string());
    }
    let candidates = keys.candidates(&prefix, key_for);
    let mut tried = false;
    let mut first_missing: Option<String> = None;
    for candidate in candidates {
        match candidate {
            Ok(key) => {
                tried = true;
                if let Ok(value) = decrypt_chromium_value(encrypted, &key[..], host_key, version) {
                    return Ok(value);
                }
            }
            Err(why) => {
                if first_missing.is_none() {
                    first_missing = Some(why.clone());
                }
            }
        }
    }
    if tried {
        Err("could not decrypt: none of the keys this browser has decrypts the value".to_string())
    } else {
        Err(first_missing.unwrap_or_else(|| "no key for this browser".to_string()))
    }
}

/// Reads the rows of a Chromium `cookies` table for `host`, decrypting what can be read.
/// Rows of other sites are skipped; encrypted rows that cannot be read are counted in the
/// tally with the reason. `key_for` gives the key for a value prefix (it is called once
/// per prefix).
fn read_chromium_rows(
    rows: &[Vec<String>],
    host: &str,
    version: Option<i64>,
    tally: &mut ImportTally,
    mut key_for: impl FnMut(&[u8]) -> Vec<Result<Vec<u8>, String>>,
) -> Vec<ImportedCookie> {
    let mut keys = KeyCache::default();
    let mut cookies = Vec::new();
    for row in rows {
        if row.len() < 10 {
            tally.skipped += 1;
            continue;
        }
        let host_key = unhex_text(&row[0]);
        if !cookie_matches_host(&host_key, host) {
            tally.skipped += 1;
            continue;
        }
        let name = unhex_text(&row[1]);
        if name.is_empty() {
            tally.skipped += 1;
            continue;
        }
        let stored_value = unhex_text(&row[2]);
        let encrypted = unhex(&row[3]).unwrap_or_default();
        let value = if encrypted.is_empty() {
            stored_value
        } else {
            match decrypt_row(&encrypted, &host_key, version, &mut keys, &mut key_for) {
                Ok(value) => value,
                Err(why) => {
                    tally.undecryptable(why);
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
    keys.clear();
    cookies
}

/// When the site had encrypted cookies and none could be read, the import fails with the
/// reason (the caller shows it), instead of importing zero cookies without one.
fn finish_chromium(
    cookies: Vec<ImportedCookie>,
    tally: &ImportTally,
) -> Result<Vec<ImportedCookie>, String> {
    if cookies.is_empty() {
        if let Some(why) = tally.first_reason() {
            return Err(why);
        }
    }
    Ok(cookies)
}

fn load_chromium(
    source: &BrowserCookieSource,
    db: &Path,
    host: &str,
    tally: &mut ImportTally,
) -> Result<Vec<ImportedCookie>, String> {
    let product = product_for_slug(product_slug(&source.id))
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
    let cookies = read_chromium_rows(&rows, host, version, tally, |prefix| {
        chromium_keys(product, prefix)
    });
    finish_chromium(cookies, tally)
}

fn load_firefox(
    db: &Path,
    host: &str,
    tally: &mut ImportTally,
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
            tally.skipped += 1;
            continue;
        }
        let host_key = unhex_text(&row[0]);
        if !cookie_matches_host(&host_key, host) {
            tally.skipped += 1;
            continue;
        }
        let name = unhex_text(&row[1]);
        if name.is_empty() {
            tally.skipped += 1;
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
    Ok(cookies)
}

fn load_safari(
    db: &Path,
    host: &str,
    tally: &mut ImportTally,
) -> Result<Vec<ImportedCookie>, String> {
    let bytes = std::fs::read(db).map_err(|error| format!("ler Cookies.binarycookies: {error}"))?;
    let raw = parse_binarycookies(&bytes)?;
    let mut cookies = Vec::new();
    for cookie in raw {
        if !cookie_matches_host(&cookie.domain, host) {
            tally.skipped += 1;
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
// Crypto: SHA-1, SHA-256, PBKDF2-HMAC-SHA1 and AES-128-CBC (RustCrypto).
// HMAC stays inside the `pbkdf2` crate. Decrypt returns the raw block bytes;
// `pkcs7_unpad` still checks the padding.
// ---------------------------------------------------------------------------

#[cfg(test)]
fn sha1(data: &[u8]) -> [u8; 20] {
    use sha1::Digest;
    let digest = sha1::Sha1::digest(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest);
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// PBKDF2-HMAC-SHA1 (RFC 2898) producing `dk_len` bytes.
pub fn pbkdf2_sha1(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    let iterations = iterations.max(1);
    let mut out = vec![0u8; dk_len];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, salt, iterations, &mut out);
    out
}

/// AES-128-CBC decrypt, raw: no padding is removed here (see `pkcs7_unpad`).
pub fn aes_128_cbc_decrypt(key: &[u8], iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    use cipher::block_padding::NoPadding;
    use cipher::{BlockDecryptMut, KeyIvInit};
    if key.len() != 16 {
        return Err("AES-128 key must be 16 bytes".to_string());
    }
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err("ciphertext is not a multiple of 16".to_string());
    }
    let mut buffer = ciphertext.to_vec();
    let decryptor = cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
        .map_err(|_| "AES-128 key must be 16 bytes".to_string())?;
    let plain = decryptor
        .decrypt_padded_mut::<NoPadding>(&mut buffer)
        .map_err(|_| "ciphertext is not a multiple of 16".to_string())?;
    Ok(plain.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic Chromium database (plain values, no key needed), committed in the
    /// repository so the Linux native reader is tested where the `sqlite3` command is absent.
    #[cfg(target_os = "linux")]
    #[test]
    fn native_sqlite_reads_the_chromium_fixture_without_the_sqlite3_command() {
        let dir = std::env::temp_dir().join(format!("scrapelens-native-test-{}-{}", std::process::id(), unix_nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("Cookies");
        std::fs::write(&source, include_bytes!("../fixtures/chromium-cookies-synthetic.sqlite")).unwrap();
        let copy = copy_cookie_db(&source).unwrap();
        let rows = native::sqlite_query(&copy.db, "SELECT host_key, name FROM cookies ORDER BY host_key")
            .expect("libsqlite3 is installed wherever WebKit is")
            .unwrap();
        assert_eq!(
            rows,
            vec![
                vec![".other.test".to_string(), "x".to_string()],
                vec!["127.0.0.1".to_string(), "sid".to_string()],
            ]
        );
        let source_info = BrowserCookieSource {
            id: "chromium:Default".to_string(),
            browser: "Chromium".to_string(),
            profile: "Default".to_string(),
            label: "Chromium — Default".to_string(),
            kind: BrowserKind::Chromium,
            db_path: source.clone(),
        };
        let mut tally = ImportTally::default();
        let cookies = load_chromium(&source_info, &copy.db, "127.0.0.1", &mut tally).unwrap();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name, "sid");
        assert_eq!(cookies[0].value, "synthetic-plain");
        drop(copy);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn copy_cookie_db_copies_the_rollback_journal_next_to_the_database() {
        let dir = std::env::temp_dir().join(format!("scrapelens-copy-test-{}-{}", std::process::id(), unix_nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("Cookies");
        std::fs::write(&source, b"db").unwrap();
        std::fs::write(dir.join("Cookies-journal"), b"hot").unwrap();
        std::fs::write(dir.join("Cookies-wal"), b"wal").unwrap();
        let copy = copy_cookie_db(&source).unwrap();
        assert_eq!(std::fs::read(copy.db.with_file_name("cookies.db-journal")).unwrap(), b"hot");
        assert_eq!(std::fs::read(copy.db.with_file_name("cookies.db-wal")).unwrap(), b"wal");
        let copy_dir = copy.dir.clone();
        drop(copy);
        assert!(!copy_dir.exists(), "the private copy is removed on drop");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn linux_discovery_finds_flatpak_and_snap_profiles_with_their_own_ids() {
        let home = std::env::temp_dir().join(format!("scrapelens-home-test-{}-{}", std::process::id(), unix_nanos()));
        for dir in [
            ".config/google-chrome/Default",
            ".var/app/com.google.Chrome/config/google-chrome/Default/Network",
            "snap/chromium/common/chromium/Default",
            ".var/app/org.mozilla.firefox/.mozilla/firefox/abcd.default",
        ] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        std::fs::write(home.join(".config/google-chrome/Default/Cookies"), b"").unwrap();
        std::fs::write(home.join(".var/app/com.google.Chrome/config/google-chrome/Default/Network/Cookies"), b"").unwrap();
        std::fs::write(home.join("snap/chromium/common/chromium/Default/Cookies"), b"").unwrap();
        std::fs::write(home.join(".var/app/org.mozilla.firefox/.mozilla/firefox/abcd.default/cookies.sqlite"), b"").unwrap();

        let sources = linux_sources_in(&home);
        let ids: Vec<&str> = sources.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"chrome:Default"), "{ids:?}");
        assert!(ids.contains(&"chrome+flatpak:Default"), "{ids:?}");
        assert!(ids.contains(&"chromium+snap:Default"), "{ids:?}");
        assert!(ids.contains(&"firefox+flatpak:abcd.default"), "{ids:?}");
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), ids.len(), "ids must be unique: {ids:?}");
        let flatpak = sources.iter().find(|s| s.id == "chrome+flatpak:Default").unwrap();
        assert_eq!(flatpak.label, "Google Chrome (Flatpak) — Default");
        assert!(flatpak.db_path.ends_with("Network/Cookies"));
        // The product lookup accepts the variant id.
        assert_eq!(product_slug("chrome+flatpak:Default"), "chrome");
        assert_eq!(product_slug("chrome:Default"), "chrome");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn missing_secret_tool_says_which_package_to_install() {
        // Injected lookups: libsecret is absent, and starting secret-tool fails with
        // NotFound. No process is spawned, and a keyring on the machine cannot answer.
        let product = CHROMIUM_PRODUCTS.iter().find(|p| p.slug == "chromium").unwrap();
        let missing = std::io::Error::new(std::io::ErrorKind::NotFound, "injected missing command");
        let names = linux_secret_applications(product);
        let error = linux_v11_keys_from(product, vec![None; names.len()], |_| {
            Err(secret_tool_command_error(product.browser, &missing))
        })
        .into_iter()
        .next()
        .unwrap()
        .unwrap_err();
        assert!(error.contains("libsecret-tools"), "{error}");
        assert!(error.contains("Chromium"), "{error}");
        assert!(!error.contains("no entry found"), "{error}");
    }

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
        let host = ".example.com.br";
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
        assert_eq!(registrable_domain("app.example.com.br").as_deref(), Some("example.com.br"));
        assert_eq!(registrable_domain("example.com.br").as_deref(), Some("example.com.br"));
        assert_eq!(registrable_domain("a.b.example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(registrable_domain("sub.example.com").as_deref(), Some("example.com"));
        assert_eq!(registrable_domain("localhost"), None);
        assert_eq!(registrable_domain("127.0.0.1"), None);
        assert_eq!(registrable_domain("::1"), None);
    }

    #[test]
    fn cookie_matching_includes_subdomains_of_the_same_site() {
        assert!(cookie_matches_host(".example.com.br", "app.example.com.br"));
        assert!(cookie_matches_host("example.com.br", "app.example.com.br"));
        assert!(cookie_matches_host("login.example.com.br", "app.example.com.br"));
        assert!(cookie_matches_host(".example.com.br", "example.com.br"));
        assert!(!cookie_matches_host(".other.com.br", "app.example.com.br"));
        assert!(!cookie_matches_host("other.com", "app.example.com.br"));
        assert!(cookie_matches_host("localhost", "localhost"));
        assert!(!cookie_matches_host("127.0.0.1", "127.0.0.2"));
    }

    #[test]
    fn url_host_strips_user_port_and_brackets() {
        assert_eq!(url_host("https://app.example.com.br/painel?x=1").as_deref(), Some("app.example.com.br"));
        assert_eq!(url_host("https://user:pass@Example.COM:8443/").as_deref(), Some("example.com"));
        assert_eq!(url_host("http://[::1]:8781/x").as_deref(), Some("::1"));
        assert_eq!(url_host("about:blank"), None);
    }

    #[test]
    fn host_candidates_cover_the_site_and_its_dot_form() {
        let mut got = host_candidates("app.example.com.br");
        got.sort();
        assert_eq!(
            got,
            vec![
                ".app.example.com.br",
                ".example.com.br",
                "app.example.com.br",
                "example.com.br",
            ]
        );
    }

    #[test]
    fn safari_binarycookies_parses_a_synthetic_file() {
        // One page, one cookie: "sid=abc" for ".example.com.br", secure.
        let domain = b".example.com.br\0";
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
        assert_eq!(cookie.domain, ".example.com.br");
        assert!(cookie.secure);
        assert_eq!(cookie.expires, 1_700_000_000);
    }

    #[test]
    fn cdp_payload_carries_only_present_fields() {
        let cookies = vec![
            ImportedCookie {
                name: "a".into(),
                value: "1".into(),
                domain: ".example.com.br".into(),
                path: "/".into(),
                secure: true,
                http_only: true,
                same_site: Some("Lax".into()),
                expires: Some(1_700_000_000),
            },
            ImportedCookie {
                name: "b".into(),
                value: "2".into(),
                domain: "example.com.br".into(),
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
    fn debug_hides_cookie_and_proxy_secrets() {
        let cookie = ImportedCookie {
            name: "sid".into(),
            value: "cookie-secret-value".into(),
            domain: ".example.com.br".into(),
            path: "/".into(),
            secure: true,
            http_only: true,
            same_site: None,
            expires: None,
        };
        let shown = format!("{cookie:?}");
        assert!(!shown.contains("cookie-secret-value"), "{shown}");
        assert!(shown.contains("sid"), "{shown}");
        let json = serde_json::to_string(&cookie).unwrap();
        assert!(json.contains("cookie-secret-value"), "{json}");
        let config = crate::CaptureConfig {
            chrome: PathBuf::from("chrome"),
            session_dir: PathBuf::from("session"),
            start_url: "https://example.com.br/".into(),
            headless: true,
            ignore_cert: false,
            network: crate::NetworkMode::Open,
            cookie_source: None,
            initial_cookies: vec![cookie],
            proxy: Some(
                crate::proxy::ProxyLink::parse("http://user:proxy-secret-value@127.0.0.1:9").unwrap(),
            ),
            test_proxy_bypass_loopback: false,
        };
        let shown = format!("{config:?}");
        assert!(!shown.contains("cookie-secret-value"), "{shown}");
        assert!(!shown.contains("proxy-secret-value"), "{shown}");
        assert!(!shown.contains("user:proxy"), "{shown}");
    }

    #[test]
    fn the_key_cache_is_cleared_after_the_rows_are_read() {
        KEY_CACHE_CLEARED.with(|flag| flag.set(false));
        let key = pbkdf2_sha1(b"peanuts", b"saltysalt", 1, 16);
        let rows = vec![chromium_row(
            ".example.com.br",
            "sid",
            "",
            &encrypted_value(b"v10", &key, "secret-value"),
        )];
        let mut tally = ImportTally::default();
        let cookies = read_chromium_rows(&rows, "app.example.com.br", None, &mut tally, |_| {
            vec![Ok(key.clone())]
        });
        assert_eq!(cookies[0].value, "secret-value");
        assert!(KEY_CACHE_CLEARED.with(|flag| flag.get()));
        let mut cache = KeyCache::default();
        cache
            .keys
            .insert(b"v10".to_vec(), vec![Ok(zeroize::Zeroizing::new(key))]);
        cache.clear();
        assert!(cache.keys.is_empty());
    }

    #[test]
    fn short_or_unknown_encrypted_values_are_refused() {
        let key = [0u8; 16];
        assert!(decrypt_chromium_value(b"v10", &key, "h", None).is_err());
        assert!(decrypt_chromium_value(b"xx", &key, "h", None).is_err());
        assert!(decrypt_chromium_value(b"v12abcdef", &key, "h", None).is_err());
    }

    /// One `cookies` row in the order `read_chromium_rows` expects.
    fn chromium_row(host_key: &str, name: &str, value: &str, encrypted: &[u8]) -> Vec<String> {
        vec![
            hex_string(host_key.as_bytes()),
            hex_string(name.as_bytes()),
            hex_string(value.as_bytes()),
            hex_string(encrypted),
            hex_string(b"/"),
            "0".into(),
            "0".into(),
            "0".into(),
            "-1".into(),
            "1".into(),
        ]
    }

    /// `v10`/`v11` + AES-128-CBC of `plain`, as the browser writes it (test data only).
    fn encrypted_value(prefix: &[u8; 3], key: &[u8], plain: &str) -> Vec<u8> {
        let key: [u8; 16] = key.try_into().unwrap();
        let mut out = prefix.to_vec();
        out.extend(encrypt_for_test(&key, &[0x20u8; 16], plain.as_bytes()));
        out
    }

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "scrapelens-{label}-{}-{}",
            std::process::id(),
            unix_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn each_row_is_decrypted_with_the_key_of_its_own_version() {
        // A profile that migrated to the keyring mixes `v11` and `v10` rows. The first row
        // is `v11`: the later `v10` rows must still decrypt with their own key.
        let v10_key = pbkdf2_sha1(b"peanuts", b"saltysalt", 1, 16);
        let v11_key = pbkdf2_sha1(b"keyring password", b"saltysalt", 1, 16);
        let rows = vec![
            chromium_row(".example.com.br", "a", "", &encrypted_value(b"v11", &v11_key, "from-v11")),
            chromium_row(".example.com.br", "b", "", &encrypted_value(b"v10", &v10_key, "from-v10-1")),
            chromium_row(".example.com.br", "c", "", &encrypted_value(b"v10", &v10_key, "from-v10-2")),
        ];
        let lookups = std::cell::Cell::new(0);
        let mut tally = ImportTally::default();
        let cookies = read_chromium_rows(&rows, "app.example.com.br", None, &mut tally, |prefix| {
            lookups.set(lookups.get() + 1);
            if prefix == b"v10" {
                vec![Ok(v10_key.clone())]
            } else {
                vec![Ok(v11_key.clone())]
            }
        });
        let values: Vec<(&str, &str)> = cookies.iter().map(|c| (c.name.as_str(), c.value.as_str())).collect();
        assert_eq!(values, vec![("a", "from-v11"), ("b", "from-v10-1"), ("c", "from-v10-2")]);
        assert_eq!(tally.undecryptable, 0);
        assert_eq!(lookups.get(), 2, "one key lookup per version, not one per row");
    }

    #[test]
    fn a_locked_v11_key_still_imports_the_readable_v10_cookies_and_reports_the_rest() {
        let v10_key = pbkdf2_sha1(b"peanuts", b"saltysalt", 1, 16);
        let rows = vec![
            chromium_row(".example.com.br", "login", "", &encrypted_value(b"v11", &[1u8; 16], "x")),
            chromium_row(".example.com.br", "plain", "", &encrypted_value(b"v10", &v10_key, "readable")),
            chromium_row(".example.com.br", "more", "", &encrypted_value(b"v11", &[1u8; 16], "y")),
        ];
        let mut tally = ImportTally::default();
        let cookies = read_chromium_rows(&rows, "app.example.com.br", None, &mut tally, |prefix| {
            if prefix == b"v10" {
                vec![Ok(v10_key.clone())]
            } else {
                vec![Err(keyring_locked_error("Chromium"))]
            }
        });
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].value, "readable");
        assert_eq!(tally.undecryptable, 2);
        assert_eq!(
            tally.reason_text().as_deref(),
            Some("v11 cookie of Chromium: keyring is locked: unlock it and try again (2)")
        );
        assert!(finish_chromium(cookies, &tally).is_ok(), "readable cookies are still returned");
    }

    #[test]
    fn short_or_unknown_encrypted_values_are_counted_without_a_panic() {
        // A one- or two-byte value used to index past its end; it must be counted instead.
        let rows = vec![
            chromium_row(".example.com.br", "one", "", &[0x01]),
            chromium_row(".example.com.br", "two", "", &[0x01, 0x02]),
            chromium_row(".example.com.br", "three", "", b"v12abcdefghijklmnop"),
        ];
        let mut tally = ImportTally::default();
        let cookies = read_chromium_rows(&rows, "app.example.com.br", None, &mut tally, |_| {
            vec![Err("no key is expected for these values".to_string())]
        });
        assert!(cookies.is_empty());
        assert_eq!(tally.undecryptable, 3);
        let error = finish_chromium(cookies, &tally).unwrap_err();
        assert!(error.contains("too short"), "{error}");
    }

    #[test]
    fn nothing_readable_because_the_keyring_is_locked_fails_with_the_reason() {
        // Also the macOS-visible rule: encrypted cookies exist, none can be read, so the
        // import fails with the reason instead of importing zero cookies silently.
        let rows = vec![chromium_row(".example.com.br", "login", "", &encrypted_value(b"v11", &[1u8; 16], "x"))];
        let mut tally = ImportTally::default();
        let cookies = read_chromium_rows(&rows, "app.example.com.br", None, &mut tally, |_| {
            vec![Err(keyring_locked_error("Chromium"))]
        });
        let error = finish_chromium(cookies, &tally).unwrap_err();
        assert_eq!(error, "v11 cookie of Chromium: keyring is locked: unlock it and try again");
    }

    #[test]
    fn a_site_without_encrypted_cookies_imports_nothing_without_an_error() {
        let rows = vec![chromium_row(".other.test", "x", "y", b"")];
        let mut tally = ImportTally::default();
        let cookies = read_chromium_rows(&rows, "app.example.com.br", None, &mut tally, |_| {
            panic!("no key is needed")
        });
        assert!(finish_chromium(cookies, &tally).unwrap().is_empty());
        assert_eq!(tally.undecryptable, 0);
    }

    #[test]
    fn the_notice_says_how_many_cookies_could_not_be_decrypted_and_why() {
        let outcome = CookieImportOutcome {
            source_id: "chromium:Default".into(),
            label: "Chromium — Default".into(),
            domain: "example.com.br".into(),
            cookies: Vec::new(),
            skipped: 0,
            undecryptable: 2,
            undecryptable_reason: Some("v11 cookie of Chromium: keyring is locked: unlock it and try again (2)".into()),
            notes: Vec::new(),
        };
        let text = outcome.notice_suffix();
        assert!(text.contains("2 cookie(s) could not be decrypted"), "{text}");
        assert!(text.contains("keyring is locked: unlock it and try again"), "{text}");
    }

    #[test]
    fn bounded_calls_give_up_at_the_deadline_and_quick_results_come_back() {
        assert!(matches!(bounded(std::time::Duration::from_secs(5), || 7), Bounded::Done(7)));
        let started = std::time::Instant::now();
        let outcome = bounded(std::time::Duration::from_millis(150), || {
            std::thread::sleep(std::time::Duration::from_secs(3));
            1
        });
        assert!(matches!(outcome, Bounded::TimedOut));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn a_secret_tool_waiting_for_an_unlock_is_stopped_at_the_deadline() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("secret-tool-test");
        let script = dir.join("secret-tool");
        std::fs::write(&script, "#!/bin/sh\nsleep 30\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let started = std::time::Instant::now();
        let until = std::time::Instant::now() + std::time::Duration::from_millis(300);
        let error = secret_tool_password(&script, "Chromium", "chromium", until).unwrap_err();
        assert_eq!(error, keyring_locked_error("Chromium"));
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn stale_copies_of_gone_processes_are_removed_and_live_ones_are_kept() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let base = temp_dir("sweep-test");
        let dead_pid = {
            let mut child = Command::new("true").spawn().unwrap();
            let pid = child.id() as i32;
            child.wait().unwrap();
            pid
        };
        let make = |name: String, mode: u32| {
            let dir = base.join(name);
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            dir
        };
        let stale = make(format!("{COPY_PREFIX}{dead_pid}-1"), 0o700);
        std::fs::write(stale.join("cookies.db"), b"x").unwrap();
        let live = make(format!("{COPY_PREFIX}{}-2", std::process::id()), 0o700);
        let loose = make(format!("{COPY_PREFIX}{dead_pid}-4"), 0o755);
        let target = base.join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        let link = base.join(format!("{COPY_PREFIX}{dead_pid}-3"));
        symlink(&target, &link).unwrap();

        sweep_stale_copies(&base);

        assert!(!stale.exists(), "the copy of a process that is gone is removed");
        assert!(live.exists(), "the copy of a running process (this one) is kept");
        assert!(loose.exists(), "a directory that is not mode 0700 is not removed");
        assert!(link.symlink_metadata().is_ok(), "a symlink is not followed or removed");
        assert!(target.exists(), "the symlink target is untouched");
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[test]
    fn a_sidecar_that_cannot_be_copied_is_reported_as_a_note() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid has no failure mode and no arguments.
        if unsafe { libc::geteuid() } == 0 {
            // Root can read a file whatever its mode, so the copy cannot fail: explicit skip.
            eprintln!("skipped: run the tests as a normal user to exercise an unreadable sidecar");
            return;
        }
        let base = temp_dir("sidecar-test");
        let source = base.join("Cookies");
        std::fs::write(&source, b"db").unwrap();
        let wal = base.join("Cookies-wal");
        std::fs::write(&wal, b"wal").unwrap();
        std::fs::set_permissions(&wal, std::fs::Permissions::from_mode(0o000)).unwrap();
        let copy = copy_cookie_db_in(&source, &base).unwrap();
        assert!(
            copy.notes.iter().any(|note| note.contains("-wal")),
            "the stale-copy risk must be visible: {:?}",
            copy.notes
        );
        drop(copy);
        let _ = std::fs::remove_dir_all(base);
    }

    /// The value of a row encrypted with `key` for `host_key`, the way Chrome 130+ writes it:
    /// the 32-byte SHA-256(host_key) prefix, then the value.
    fn encrypted_value_with_host_hash(prefix: &[u8; 3], key: &[u8], host_key: &str, plain: &str) -> Vec<u8> {
        let mut body = sha256(host_key.as_bytes()).to_vec();
        body.extend_from_slice(plain.as_bytes());
        let key: [u8; 16] = key.try_into().unwrap();
        let mut out = prefix.to_vec();
        out.extend(encrypt_for_test(&key, &[0x20u8; 16], &body));
        out
    }

    #[test]
    fn a_candidate_key_that_does_not_decrypt_is_skipped_for_the_next_one() {
        // The first keyring candidate is another application's key: the value must come
        // from the second candidate, never from the wrong one.
        let wrong = pbkdf2_sha1(b"another application", b"saltysalt", 1, 16);
        let right = pbkdf2_sha1(b"keyring password", b"saltysalt", 1, 16);
        let rows = vec![chromium_row(
            ".example.com.br",
            "sid",
            "",
            &encrypted_value_with_host_hash(b"v11", &right, ".example.com.br", "secret-value"),
        )];
        let mut tally = ImportTally::default();
        let cookies = read_chromium_rows(&rows, "app.example.com.br", Some(24), &mut tally, |_| {
            vec![Ok(wrong.clone()), Ok(right.clone())]
        });
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].value, "secret-value");
        assert_eq!(tally.undecryptable, 0);
    }

    #[test]
    fn a_wrong_key_never_yields_a_value() {
        // Chrome 130+ writes the host hash: no candidate produces it, so the cookie is not
        // imported and is counted with the reason.
        let wrong = pbkdf2_sha1(b"another application", b"saltysalt", 1, 16);
        let right = pbkdf2_sha1(b"keyring password", b"saltysalt", 1, 16);
        let rows = vec![chromium_row(
            ".example.com.br",
            "sid",
            "",
            &encrypted_value_with_host_hash(b"v11", &right, ".example.com.br", "secret-value"),
        )];
        let mut tally = ImportTally::default();
        let cookies = read_chromium_rows(&rows, "app.example.com.br", Some(24), &mut tally, |_| {
            vec![Ok(wrong.clone())]
        });
        assert!(cookies.is_empty(), "a value decrypted with the wrong key must not be imported");
        assert_eq!(tally.undecryptable, 1);
        assert_eq!(
            tally.reason_text().as_deref(),
            Some("could not decrypt: none of the keys this browser has decrypts the value (1)")
        );
    }

    #[test]
    fn version_24_values_need_the_host_hash_and_valid_padding() {
        let key = pbkdf2_sha1(b"keyring password", b"saltysalt", 1, 16);
        // With the prefix: decrypts.
        let good = encrypted_value_with_host_hash(b"v11", &key, ".example.com.br", "ok");
        assert_eq!(decrypt_chromium_value(&good, &key, ".example.com.br", Some(24)).unwrap(), "ok");
        // Without the prefix at version 24: refused, not returned as garbage.
        let bare = encrypted_value(b"v11", &key, "ok");
        assert!(decrypt_chromium_value(&bare, &key, ".example.com.br", Some(24)).is_err());
        // Without the prefix at an old version: the value is returned as written.
        assert_eq!(decrypt_chromium_value(&bare, &key, ".example.com.br", Some(20)).unwrap(), "ok");
        // Bad padding (a value that does not end in valid PKCS#7): refused.
        let mut bad_padding = encrypted_value(b"v11", &key, "AAAAAAAAAAAAAAA");
        let last = bad_padding.len() - 1;
        bad_padding[last] ^= 0x01; // corrupt the last ciphertext block: padding no longer valid
        assert!(decrypt_chromium_value(&bad_padding, &key, ".example.com.br", None).is_err());
    }

    #[test]
    fn pkcs7_unpad_accepts_only_valid_padding() {
        assert_eq!(pkcs7_unpad(b"abc\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d"), Some(b"abc".to_vec()));
        assert_eq!(pkcs7_unpad(b"abcdefghijklmnop"), None, "last byte 'p' is not a padding length");
        assert_eq!(pkcs7_unpad(b"abc\x02\x03"), None, "padding bytes must all match");
        assert_eq!(pkcs7_unpad(b""), None);
        assert_eq!(pkcs7_unpad(b"\x00"), None, "a zero padding length is invalid");
    }

    #[test]
    fn linux_candidates_are_the_browsers_own_name_then_the_chromium_names() {
        let names = |slug: &str| {
            let product = CHROMIUM_PRODUCTS.iter().find(|p| p.slug == slug).unwrap();
            linux_secret_applications(product)
        };
        // Edge stores its key as application=chromium (label "Chromium Safe Storage").
        assert_eq!(names("edge"), vec!["microsoft-edge", "chromium", "chrome"]);
        assert_eq!(names("brave"), vec!["brave", "chromium", "chrome"]);
        assert_eq!(names("chrome"), vec!["chrome", "chromium"]);
        assert_eq!(names("chromium"), vec!["chromium", "chrome"]);
    }


    #[test]
    fn sqlite_roundtrip_reads_chromium_and_firefox_tables() {
        // Builds the fixtures with the `sqlite3` command. A minimal image has no such
        // binary; the committed-fixture test covers reading there. Skip, and say why,
        // instead of failing the suite.
        if !sqlite3_available() {
            eprintln!("skipped: the sqlite3 command is not installed; install the sqlite3 package to build this test's databases");
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
             INSERT INTO cookies VALUES('.example.com.br','sid','segredo','', '/',0,1,1,1,1);\
             INSERT INTO cookies VALUES('.other.com.br','outside','x','', '/',0,0,0,-1,1);\
             INSERT INTO cookies VALUES('.example.com.br','velho','x','', '/',1,0,0,-1,1);";
        let status = Command::new("sqlite3").arg(&chromium_db).arg(sql).output().unwrap();
        assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stderr));
        let firefox_db = dir.join("cookies.sqlite");
        let sql = "CREATE TABLE moz_cookies(host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER);\
                   INSERT INTO moz_cookies VALUES('.example.com.br','ff','valor','/',4102444800,1,0,2);\
                   INSERT INTO moz_cookies VALUES('.other.com.br','ff-outside','x','/',4102444800,0,0,0);";
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
        let mut tally = ImportTally::default();
        let copy = copy_cookie_db(&source.db_path).unwrap();
        let mut cookies = load_chromium(&source, &copy.db, "app.example.com.br", &mut tally).unwrap();
        assert_eq!(cookies.len(), 2, "sid and the expired one; the one from another site does not get in");
        assert_eq!(cookies[0].name, "sid");
        assert_eq!(cookies[0].value, "segredo");
        assert!(cookies[0].secure);
        assert_eq!(tally.skipped, 0);
        drop_expired(&mut cookies, &mut tally.skipped);
        assert_eq!(cookies.len(), 1, "the expired one is dropped by the common filter");
        assert_eq!(tally.skipped, 1);
        drop(copy);

        let mut tally = ImportTally::default();
        let fsource = BrowserCookieSource {
            id: "firefox:test".to_string(),
            browser: "Firefox".to_string(),
            profile: "test".to_string(),
            label: "Firefox — test".to_string(),
            kind: BrowserKind::Firefox,
            db_path: firefox_db,
        };
        let copy = copy_cookie_db(&fsource.db_path).unwrap();
        let cookies = load_firefox(&copy.db, "app.example.com.br", &mut tally).unwrap();
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
        use cipher::block_padding::Pkcs7;
        use cipher::{BlockEncryptMut, KeyIvInit};
        let mut buffer = vec![0u8; plain.len() + 16];
        buffer[..plain.len()].copy_from_slice(plain);
        let encryptor = cbc::Encryptor::<aes::Aes128>::new_from_slices(key, iv)
            .expect("key and iv are 16 bytes");
        let encrypted = encryptor
            .encrypt_padded_mut::<Pkcs7>(&mut buffer, plain.len())
            .expect("buffer holds one extra block");
        encrypted.to_vec()
    }
}
