//! Detection and manual selection of the external Chrome. ScrapeLens never uses
//! the personal profile: the launcher in core/ opens a dedicated profile. Here we
//! only locate and validate the binary.

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

#[cfg(target_os = "macos")]
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

#[cfg(not(target_os = "macos"))]
fn home_candidates() -> Vec<PathBuf> {
    Vec::new()
}

/// Where to look for the browser, from preferred to alternative. On Linux, stable
/// Google Chrome comes first; Chromium is the alternative (and the only browser
/// possible on arm64, where stable Chrome has no build) and is MARKED as such
/// (`BrowserKind::Chromium`). Prefers the real binary (`/opt/google/chrome/chrome`,
/// `/usr/lib/chromium/chromium`, `/usr/lib64/chromium-browser/chromium-browser`)
/// over the `google-chrome`/`chromium` script that only calls it. On Fedora the
/// `/usr/bin/chromium-browser` link resolves to `chromium-browser.sh`, so the ELF
/// beside that script is listed first.
pub fn candidates() -> Vec<String> {
    let mut paths: Vec<PathBuf> = if cfg!(target_os = "macos") {
        vec![
            PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            PathBuf::from("/Applications/Chromium.app/Contents/MacOS/Chromium"),
            PathBuf::from("/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary"),
        ]
    } else {
        [
            "/opt/google/chrome/chrome",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/google-chrome",
            "/opt/google/chrome/google-chrome",
            "/usr/lib/chromium/chromium",
            "/usr/lib/chromium-browser/chromium-browser",
            "/usr/lib64/chromium-browser/chromium-browser",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
        ]
        .iter()
        .map(PathBuf::from)
        .collect()
    };
    paths.extend(home_candidates());
    paths
        .into_iter()
        .map(|path| path.display().to_string())
        .collect()
}

/// Normalizes what the user picked in the dialog: accepts `.app`, the
/// `Contents/MacOS` directory or the binary itself.
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

// ---------------------------------------------------------------------------
// Strict validation of the CONTROLLED CAPTURE browser (docs/16b §2.1)
// ---------------------------------------------------------------------------

/// Bundle identifier and Google Team ID for stable Chrome.
#[cfg(target_os = "macos")]
const CHROME_BUNDLE_ID: &str = "com.google.Chrome";
#[cfg(target_os = "macos")]
const CHROME_TEAM_ID: &str = "EQHXZ8M8AV";
/// Code requirement that stable Chrome must satisfy.
pub const CHROME_REQUIREMENT: &str = "anchor apple generic and identifier \"com.google.Chrome\" and certificate leaf[subject.OU] = \"EQHXZ8M8AV\"";

/// Which browser it is. Chromium is accepted on Linux as an alternative (on arm64
/// it is the only one, since stable Chrome has no build) and is MARKED in the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BrowserKind {
    GoogleChrome,
    Chromium,
}

impl BrowserKind {
    pub fn label(self) -> &'static str {
        match self {
            BrowserKind::GoogleChrome => "Google Chrome",
            BrowserKind::Chromium => "Chromium",
        }
    }

    /// By executable name (for the common capture's `run()`, which only has the path).
    pub fn from_path(path: &Path) -> BrowserKind {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if name.contains("chromium") {
            BrowserKind::Chromium
        } else {
            BrowserKind::GoogleChrome
        }
    }
}

/// Chrome accepted for the controlled capture. On macOS it is read without running
/// the binary; on Linux `--version` only runs after the owner and permission checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedChrome {
    /// Executable binary, with symlinks resolved.
    pub binary: PathBuf,
    /// macOS: the `.app`. Linux: the binary's directory.
    pub app: PathBuf,
    /// macOS: `CFBundleShortVersionString`. Linux: the version from `--version`.
    pub version: String,
    /// macOS: the Google Team ID. Linux: empty (there is no code signature).
    pub team_id: String,
    pub kind: BrowserKind,
    /// Linux: the package that owns the binary (`dpkg -S` or `rpm -qf`), when the
    /// system can tell. Informational: validation does not depend on it.
    pub package: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChromeError {
    NotFound(String),
    /// Not the binary inside a `.app` (e.g. `/bin/echo`, a script).
    NotABundle(String),
    /// The path has a control character (line break, NUL, TAB...) or is not UTF-8:
    /// it is never a legitimate Chrome and it misleads whoever parses text.
    UnsafePath(String),
    /// Bundle of another product (not stable Chrome).
    UnexpectedBundle(String),
    NoVersion,
    BadSignature(String),
    /// Linux: the binary or a directory above it is not owned by root, or is
    /// writable by other users / the current user (docs/21-linux.md §3).
    Untrusted(String),
    UnsupportedPlatform,
}

impl ChromeError {
    pub fn code(&self) -> &'static str {
        "browser_invalid"
    }
}

impl std::fmt::Display for ChromeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChromeError::NotFound(p) => write!(f, "browser not found: {p}"),
            ChromeError::NotABundle(why) => write!(
                f,
                "only the installed stable Chrome is accepted (on macOS a Google .app; on Linux the binary from the Chrome package, or from Chromium); this path is not one: {why}"
            ),
            ChromeError::Untrusted(why) => write!(
                f,
                "the browser is not trusted (it must belong to root and be out of the user's reach): {why}"
            ),
            ChromeError::UnsafePath(shown) => write!(
                f,
                "the browser path has a control character or is not UTF-8 and was refused: {shown}"
            ),
            ChromeError::UnexpectedBundle(id) => write!(
                f,
                "the product is {id:?}, not stable Chrome (macOS: com.google.Chrome; Linux: Google Chrome <version> or Chromium)"
            ),
            ChromeError::NoVersion => write!(f, "the browser's Info.plist does not report a version"),
            ChromeError::BadSignature(why) => {
                write!(f, "the browser's signature does not match Google's: {why}")
            }
            ChromeError::UnsupportedPlatform => write!(
                f,
                "validation of the controlled-capture browser only exists for macOS and Linux in this version"
            ),
        }
    }
}

impl std::error::Error for ChromeError {}

/// Accepts only the **stable Google Chrome**: the binary must be at
/// `<X>.app/Contents/MacOS/<CFBundleExecutable>`, the `Info.plist` must have the
/// identifier `com.google.Chrome` and a version, and the code signature must
/// satisfy the explicit requirement [`CHROME_REQUIREMENT`] in
/// `codesign --verify --deep` (the exit code decides; nothing from the text
/// output is interpreted). Nothing is executed: only the system's `plutil` and
/// `codesign`, by absolute path, read the bundle. Refuses `/bin/echo`, scripts,
/// fake `.app`s (even with a lying `Info.plist`), paths with control characters,
/// and copies of Chrome with a swapped Helper/framework (`--deep` covers the
/// nested ones). No `--strict`: the installed Chrome has Finder attributes that
/// it rejects. The result is not cached: each call re-verifies.
///
/// The returned `binary` is the validated canonical path and is exactly what must
/// be executed. A window remains between this check and the `exec` (a process of
/// the same user with write access to the bundle could swap a file afterwards):
/// `/Applications` belongs to the admin group, and a copy in a user folder belongs
/// to the user, who could already run anything. Documented in docs/16b §2.1.
pub fn validate_chrome(chosen: &Path) -> Result<ValidatedChrome, ChromeError> {
    #[cfg(target_os = "macos")]
    {
        validate_chrome_macos(chosen)
    }
    #[cfg(target_os = "linux")]
    {
        validate_chrome_linux(chosen, 0)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = chosen;
        Err(ChromeError::UnsupportedPlatform)
    }
}

/// Resolves stable Chrome for the controlled capture: the `explicit` one (if any)
/// is validated and never replaced; without it, the first installed candidate
/// that passes [`validate_chrome`]. This is what the MCP server must call to
/// choose and show the browser in the confirmation.
pub fn resolve_stable_chrome(explicit: Option<&Path>) -> Result<ValidatedChrome, ChromeError> {
    if let Some(path) = explicit {
        return validate_chrome(path);
    }
    let mut last = ChromeError::NotFound("installed stable Chrome".to_string());
    for candidate in candidates() {
        match validate_chrome(Path::new(&candidate)) {
            Ok(found) => return Ok(found),
            Err(ChromeError::NotFound(_)) => {}
            Err(other) => last = other,
        }
    }
    Err(last)
}

/// Refuses a path that is not UTF-8 or has a control character (`\n`, `\r`,
/// TAB, NUL, DEL, C1). Applies to both the given path and the canonical one.
fn reject_unsafe_path(path: &Path) -> Result<(), ChromeError> {
    match path.to_str() {
        Some(text) if !text.chars().any(char::is_control) => Ok(()),
        _ => Err(ChromeError::UnsafePath(
            path.to_string_lossy().escape_debug().to_string(),
        )),
    }
}

#[cfg(target_os = "macos")]
fn validate_chrome_macos(chosen: &Path) -> Result<ValidatedChrome, ChromeError> {
    use std::process::Command;

    reject_unsafe_path(chosen)?;
    let resolved = std::fs::canonicalize(chosen)
        .map_err(|_| ChromeError::NotFound(chosen.display().to_string()))?;
    reject_unsafe_path(&resolved)?;
    // Accepts the `.app`, the binary inside it, or the `Contents/MacOS` directory.
    let binary = if resolved.extension().and_then(|e| e.to_str()) == Some("app") {
        None
    } else {
        Some(resolved.clone())
    };
    let app = match &binary {
        None => resolved.clone(),
        Some(b) => b
            .ancestors()
            .find(|a| a.extension().and_then(|e| e.to_str()) == Some("app"))
            .map(Path::to_path_buf)
            .ok_or_else(|| ChromeError::NotABundle(format!("{} is not inside a .app", b.display())))?,
    };
    let plist = app.join("Contents/Info.plist");
    let output = Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-", "--"])
        .arg(&plist)
        .output()
        .map_err(|e| ChromeError::NotABundle(format!("plutil: {e}")))?;
    if !output.status.success() {
        return Err(ChromeError::NotABundle(format!("no readable Info.plist in {}", app.display())));
    }
    let info: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| ChromeError::NotABundle("invalid Info.plist".to_string()))?;
    let text = |key: &str| info.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let id = text("CFBundleIdentifier");
    if id != CHROME_BUNDLE_ID {
        return Err(ChromeError::UnexpectedBundle(id));
    }
    let executable = text("CFBundleExecutable");
    let expected = app.join("Contents/MacOS").join(&executable);
    if executable.is_empty() || executable.contains('/') {
        return Err(ChromeError::NotABundle("invalid CFBundleExecutable".to_string()));
    }
    let binary = match binary {
        Some(b) if b == expected => b,
        Some(b) => {
            return Err(ChromeError::NotABundle(format!(
                "{} is not the bundle's executable ({})",
                b.display(),
                expected.display()
            )))
        }
        None => expected,
    };
    if !binary.is_file() {
        return Err(ChromeError::NotFound(binary.display().to_string()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&binary).map(|m| m.permissions().mode()).unwrap_or(0);
        if mode & 0o111 == 0 {
            return Err(ChromeError::NotABundle("the binary is not executable".to_string()));
        }
    }
    let version = text("CFBundleShortVersionString");
    if version.trim().is_empty() {
        return Err(ChromeError::NoVersion);
    }
    // Signature: explicit requirement, with the exit code as the only verdict.
    // `--deep` also verifies the nested bundles (Helpers, frameworks). The
    // requirement anchors to Apple's CA and requires Google's identifier and
    // Team ID in the leaf certificate, so an ad hoc signed bundle or one signed
    // by another certificate does not satisfy it. None of the text output is read.
    let verify = Command::new("/usr/bin/codesign")
        .args(["--verify", "--deep"])
        .arg(format!("-R={CHROME_REQUIREMENT}"))
        .arg("--")
        .arg(&app)
        .output()
        .map_err(|e| ChromeError::BadSignature(format!("codesign: {e}")))?;
    if !verify.status.success() {
        let stderr = String::from_utf8_lossy(&verify.stderr);
        // Show only the first line and no control characters: the message goes to the agent.
        let why: String = stderr
            .lines()
            .next()
            .unwrap_or("invalid signature")
            .chars()
            .filter(|c| !c.is_control())
            .take(200)
            .collect();
        return Err(ChromeError::BadSignature(format!(
            "does not satisfy Google's requirement ({CHROME_BUNDLE_ID} / {CHROME_TEAM_ID}): {why}"
        )));
    }
    let team_id = CHROME_TEAM_ID.to_string();
    Ok(ValidatedChrome {
        binary,
        app,
        version,
        team_id,
        kind: BrowserKind::GoogleChrome,
        package: None,
    })
}

// ---------------------------------------------------------------------------
// Linux: validation equivalent to the macOS code signature (docs/21-linux.md §3)
// ---------------------------------------------------------------------------

/// Accepts the stable Google Chrome (or Chromium, marked) installed on the system.
/// There is no `codesign` on Linux; the equivalent this module checks, WITHOUT
/// running anything until the end of the checks:
///
/// 1. the path (given and canonical) has no control character and is not non-UTF-8;
/// 2. the path is resolved to the canonical one (symlinks from `/usr/bin/google-chrome-stable`
///    → `/etc/alternatives/...` → `/opt/google/chrome/google-chrome`) and, if it lands on a
///    script (`#!`), only accepts a known wrapper name (`google-chrome`,
///    `google-chrome-stable`, `chromium`, `chromium-browser`, Fedora's
///    `chromium-browser.sh`) and swaps it for the real binary beside it
///    (`chrome`, `/usr/lib/chromium/chromium`, or `chromium-browser` next to the
///    `.sh`); what runs is an **ELF**;
/// 3. the binary is a regular file, **owned by `trusted_uid`** (root), executable, **with no
///    write for group/others**, and **each directory above it, up to `/`**, is owned by the same
///    owner and has no write for group/others; when the current user is not that owner,
///    `access(W_OK)` must fail for the file and for each directory (covers ACLs and
///    read-only mounts the other way around: the user cannot write). The type is checked
///    on the open descriptor with `O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC`: FIFOs, sockets
///    and devices are refused without blocking (a FIFO with no writer would block `open`);
/// 4. ONLY AFTER that does `<binary> --version` run (clean environment, 10 s limit): the
///    product and the version come from it (`Google Chrome 156...`, `Chromium 126...`);
/// 5. the owning package (`dpkg -S` or `rpm -qf`) is queried and recorded, but
///    validation does not depend on it.
///
/// A window remains between the check and the `exec` (TOCTOU), as on macOS: the binary and
/// the directories belong to root and are out of the user's reach, so only root can exploit it.
#[cfg(target_os = "linux")]
pub(crate) fn validate_chrome_linux(
    chosen: &Path,
    trusted_uid: u32,
) -> Result<ValidatedChrome, ChromeError> {
    validate_chrome_linux_from(chosen, trusted_uid, Path::new("/"))
}

/// Like [`validate_chrome_linux`], but the directories are checked only up to `anchor`
/// (inclusive; `/` in production). It exists so tests can build their own tree
/// without requiring `/tmp` to be owned by root.
#[cfg(target_os = "linux")]
pub(crate) fn validate_chrome_linux_from(
    chosen: &Path,
    trusted_uid: u32,
    anchor: &Path,
) -> Result<ValidatedChrome, ChromeError> {
    use std::os::unix::fs::MetadataExt;

    reject_unsafe_path(chosen)?;
    let resolved = std::fs::canonicalize(chosen)
        .map_err(|_| ChromeError::NotFound(chosen.display().to_string()))?;
    reject_unsafe_path(&resolved)?;
    let binary = linux_real_binary(&resolved)?;
    reject_unsafe_path(&binary)?;
    // Only an executable with a browser name runs `--version` (never an arbitrary
    // binary the agent points to).
    let name = binary.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if !["chrome", "chromium", "chromium-browser"].contains(&name) {
        return Err(ChromeError::NotABundle(format!(
            "{} does not have a browser name (chrome, chromium or chromium-browser)",
            binary.display()
        )));
    }

    // 3. owner, mode and directories above.
    let meta = std::fs::symlink_metadata(&binary)
        .map_err(|_| ChromeError::NotFound(binary.display().to_string()))?;
    if !meta.file_type().is_file() {
        return Err(ChromeError::NotABundle(format!("{} is not a regular file", binary.display())));
    }
    if meta.uid() != trusted_uid {
        return Err(ChromeError::Untrusted(format!(
            "{} is owned by user {} (expected {trusted_uid})",
            binary.display(),
            meta.uid()
        )));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(ChromeError::Untrusted(format!(
            "{} is writable by group or others (mode {:o})",
            binary.display(),
            meta.mode() & 0o7777
        )));
    }
    if meta.mode() & 0o111 == 0 {
        return Err(ChromeError::NotABundle(format!("{} is not executable", binary.display())));
    }
    // SAFETY: `geteuid` has no preconditions.
    let euid = unsafe { libc::geteuid() };
    let user_must_not_write = euid != trusted_uid && euid != 0;
    if user_must_not_write && linux_can_write(&binary) {
        return Err(ChromeError::Untrusted(format!("the current user can write to {}", binary.display())));
    }
    for dir in binary.ancestors().skip(1) {
        if !dir.starts_with(anchor) {
            break;
        }
        let dir_meta = std::fs::symlink_metadata(dir)
            .map_err(|e| ChromeError::Untrusted(format!("{}: {e}", dir.display())))?;
        if !dir_meta.file_type().is_dir() {
            return Err(ChromeError::Untrusted(format!("{} is not a directory", dir.display())));
        }
        if dir_meta.uid() != trusted_uid {
            return Err(ChromeError::Untrusted(format!(
                "the directory {} is owned by user {} (expected {trusted_uid})",
                dir.display(),
                dir_meta.uid()
            )));
        }
        if dir_meta.mode() & 0o022 != 0 {
            return Err(ChromeError::Untrusted(format!(
                "the directory {} is writable by group or others (mode {:o})",
                dir.display(),
                dir_meta.mode() & 0o7777
            )));
        }
        if user_must_not_write && linux_can_write(dir) {
            return Err(ChromeError::Untrusted(format!("the current user can write to {}", dir.display())));
        }
    }

    // 4. Only now does the binary run, and only with `--version`.
    let (kind, version) = linux_version(&binary)?;
    // 5. Owning package (informational).
    let package = linux_owning_package(&binary);
    let app = binary.parent().map(Path::to_path_buf).unwrap_or_else(|| binary.clone());
    Ok(ValidatedChrome {
        binary,
        app,
        version,
        team_id: String::new(),
        kind,
        package,
    })
}

#[cfg(target_os = "linux")]
fn linux_can_write(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    match std::ffi::CString::new(path.as_os_str().as_bytes()) {
        // SAFETY: `access` only reads the NUL-terminated path.
        Ok(c) => unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 },
        Err(_) => true,
    }
}

/// Opens the path read-only, without following symlinks and without blocking, and
/// requires the **open** descriptor to be a regular file. A FIFO, socket or device is
/// refused right away: opening a FIFO with no writer would block forever and the
/// 10 s limit of `--version` would never take effect (finding from review round 14).
#[cfg(target_os = "linux")]
fn linux_open_regular(path: &Path) -> Result<std::fs::File, ChromeError> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::FromRawFd;

    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| ChromeError::UnsafePath(path.display().to_string()))?;
    // SAFETY: `c` is NUL-terminated and the flags are valid; the returned descriptor is
    // ours and becomes owned by the `File`.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(ChromeError::NotFound(path.display().to_string()));
    }
    // SAFETY: `fd` was just opened here and is not used anywhere else.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let meta = file
        .metadata()
        .map_err(|_| ChromeError::NotFound(path.display().to_string()))?;
    if !meta.file_type().is_file() {
        return Err(ChromeError::NotABundle(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    Ok(file)
}

/// The first bytes of the file: `\x7fELF` or `#!`.
#[cfg(target_os = "linux")]
fn linux_head(path: &Path) -> Result<[u8; 4], ChromeError> {
    use std::io::Read;
    let mut head = [0u8; 4];
    let mut file = linux_open_regular(path)?;
    let mut read = 0;
    while read < head.len() {
        match file.read(&mut head[read..]) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ChromeError::NotFound(path.display().to_string())),
        }
    }
    Ok(head)
}

/// The ELF executable to run: the path itself if it is ELF; if it is the script that
/// only calls the binary (`google-chrome`, `chromium`), the real binary beside it.
#[cfg(target_os = "linux")]
fn linux_real_binary(resolved: &Path) -> Result<PathBuf, ChromeError> {
    let head = linux_head(resolved)?;
    if head == *b"\x7fELF" {
        return Ok(resolved.to_path_buf());
    }
    if &head[..2] == b"#!" {
        // The script only counts if it is the KNOWN wrapper of the package: `google-chrome`
        // and `google-chrome-stable` beside the real `chrome` (`/opt/google/chrome/`),
        // or Debian/Ubuntu's `chromium` (`/usr/bin/chromium` →
        // `/usr/lib/chromium/chromium`). A script with an arbitrary name is never swapped
        // for a binary from elsewhere (finding from review round 14).
        let name = resolved.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let mapped = match (name, resolved.to_str()) {
            ("chromium", Some("/usr/bin/chromium")) => Some(PathBuf::from("/usr/lib/chromium/chromium")),
            ("chromium-browser", Some("/usr/bin/chromium-browser")) => {
                Some(PathBuf::from("/usr/lib/chromium-browser/chromium-browser"))
            }
            // Fedora: /usr/bin/chromium-browser → /usr/lib64/chromium-browser/chromium-browser.sh
            // The ELF is the sibling, not a binary elsewhere.
            ("chromium-browser.sh", _) => {
                resolved.parent().map(|dir| dir.join("chromium-browser"))
            }
            ("google-chrome" | "google-chrome-stable", _) => {
                resolved.parent().map(|dir| dir.join("chrome"))
            }
            _ => None,
        };
        if let Some(real) = mapped.and_then(|m| std::fs::canonicalize(m).ok()) {
            if linux_head(&real).map(|h| h == *b"\x7fELF").unwrap_or(false) {
                return Ok(real);
            }
        }
        return Err(ChromeError::NotABundle(format!(
            "{} is a script and there is no ELF browser binary beside it",
            resolved.display()
        )));
    }
    Err(ChromeError::NotABundle(format!("{} is not an ELF binary", resolved.display())))
}

/// `<binary> --version` with a clean environment and a 10 s limit. Returns the product and
/// the version; refuses any product that is not stable Google Chrome or Chromium.
#[cfg(target_os = "linux")]
fn linux_version(binary: &Path) -> Result<(BrowserKind, String), ChromeError> {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let mut child = Command::new(binary)
        .arg("--version")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| ChromeError::NotABundle(format!("{}: {e}", binary.display())))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ChromeError::NoVersion);
            }
        }
    }
    let mut text = String::new();
    if let Some(mut out) = child.stdout.take() {
        use std::io::Read;
        let _ = out.by_ref().take(4096).read_to_string(&mut text);
    }
    parse_linux_version(text.lines().next().unwrap_or(""))
}

/// `Google Chrome 156.0.7778.56`, `Chromium 126.0.6478.182 built on Debian…`.
/// Stable Chrome has only the number after the name (Beta/Dev/for Testing carry more
/// words and are refused).
#[cfg(target_os = "linux")]
pub(crate) fn parse_linux_version(line: &str) -> Result<(BrowserKind, String), ChromeError> {
    let line = line.trim();
    let numeric = |v: &str| !v.is_empty() && v.chars().all(|c| c.is_ascii_digit() || c == '.') && v.contains('.');
    if let Some(rest) = line.strip_prefix("Google Chrome ") {
        let mut words = rest.split_whitespace();
        let version = words.next().unwrap_or("");
        if numeric(version) && words.next().is_none() {
            return Ok((BrowserKind::GoogleChrome, version.to_string()));
        }
        return Err(ChromeError::UnexpectedBundle(format!(
            "{line:?} (only stable Chrome is accepted, not Beta, Dev or for Testing)"
        )));
    }
    if let Some(rest) = line.strip_prefix("Chromium ") {
        let version = rest.split_whitespace().next().unwrap_or("");
        if numeric(version) {
            return Ok((BrowserKind::Chromium, version.to_string()));
        }
    }
    Err(ChromeError::UnexpectedBundle(format!("{line:?}")))
}

/// Package that owns the file (`dpkg -S`, then `rpm -qf`), or `None`. Informational.
#[cfg(target_os = "linux")]
fn linux_owning_package(binary: &Path) -> Option<String> {
    use std::process::{Command, Stdio};
    let run = |tool: &str, args: &[&str]| -> Option<String> {
        if !Path::new(tool).is_file() {
            return None;
        }
        let output = Command::new(tool)
            .args(args)
            .arg(binary)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        output.status.success().then(|| String::from_utf8_lossy(&output.stdout).to_string())
    };
    if let Some(out) = run("/usr/bin/dpkg", &["-S"]) {
        // `google-chrome-stable: /opt/google/chrome/chrome` (or `pkg:arch: path`).
        let first = out.lines().next()?;
        let package = first.rsplit_once(": ").map(|(p, _)| p.trim())?;
        return (!package.is_empty()).then(|| package.to_string());
    }
    let out = run("/usr/bin/rpm", &["-qf"])?;
    let package = out.lines().next()?.trim();
    (!package.is_empty()).then(|| package.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // macOS only: a `.app` bundle is a macOS concept; on Linux the same paths are not bundles.
    #[cfg(target_os = "macos")]
    #[test]
    fn normalizes_an_app_bundle_to_its_binary() {
        let root = std::env::temp_dir().join(format!(
            "scrapelens-chrome-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let binary = root.join("Google Chrome.app/Contents/MacOS/Google Chrome");
        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        std::fs::write(&binary, b"fake").unwrap();
        let app_bundle = root.join("Google Chrome.app");
        assert_eq!(normalize_binary_path(&app_bundle), Some(binary));
        assert!(detect(Some(app_bundle.as_path())).found);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn missing_chrome_is_reported_with_candidates() {
        let info = detect(Some(Path::new("/caminho/inexistente/Google Chrome")));
        // Chrome exists on this machine; the test accepts both states and only
        // requires the decision to be consistent with the disk.
        if let Some(path) = &info.path {
            assert!(Path::new(path).is_file());
            assert!(info.found);
        } else {
            assert!(!info.found);
            assert!(!info.candidates.is_empty());
        }
    }

    #[cfg(target_os = "macos")]
    trait TapCreate {
        fn tap_create(self) -> PathBuf;
    }
    #[cfg(target_os = "macos")]
    impl TapCreate for PathBuf {
        fn tap_create(self) -> PathBuf {
            std::fs::create_dir_all(&self).unwrap();
            self
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "scrapelens-vc-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn validate_refuses_bin_echo_and_other_system_binaries() {
        for path in ["/bin/echo", "/bin/sh", "/usr/bin/true"] {
            let err = validate_chrome(Path::new(path)).unwrap_err();
            assert_eq!(err.code(), "browser_invalid");
            if cfg!(target_os = "macos") {
                assert!(matches!(err, ChromeError::NotABundle(_)), "{path}: {err:?}");
                assert!(err.to_string().contains("stable Chrome"), "{err}");
            }
        }
    }

    #[test]
    fn validate_refuses_missing_paths_and_fake_scripts() {
        let err = validate_chrome(Path::new("/does/not/exist/Google Chrome")).unwrap_err();
        if cfg!(target_os = "macos") {
            assert!(matches!(err, ChromeError::NotFound(_)), "{err:?}");
        }
        let dir = scratch("script");
        let script = dir.join("chrome");
        std::fs::write(&script, "#!/bin/sh\necho Google Chrome 156.0.0.0\n").unwrap();
        #[cfg(unix)]
        make_executable(&script);
        let err = validate_chrome(&script).unwrap_err();
        assert_eq!(err.code(), "browser_invalid");
        if cfg!(target_os = "macos") {
            assert!(matches!(err, ChromeError::NotABundle(_)), "{err:?}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    // ---- Linux (docs/21-linux.md §3) -------------------------------------

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use std::os::unix::fs::{symlink, PermissionsExt};

        fn euid() -> u32 {
            // SAFETY: `geteuid` has no preconditions.
            unsafe { libc::geteuid() }
        }

        /// Test tree: `<root>/opt/chrome/chrome` (copy of a real ELF, mode 0755)
        /// with 0755 directories, all owned by the current user.
        fn tree(tag: &str) -> (PathBuf, PathBuf) {
            let root = scratch(tag);
            let dir = root.join("opt/chrome");
            std::fs::create_dir_all(&dir).unwrap();
            for d in [root.join("opt"), dir.clone()] {
                std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let binary = dir.join("chrome");
            std::fs::copy("/bin/true", &binary).unwrap();
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
            (root, binary)
        }

        #[test]
        fn parses_the_version_line_of_each_product_and_refuses_the_others() {
            let (kind, version) = parse_linux_version("Google Chrome 156.0.7778.56 ").unwrap();
            assert_eq!((kind, version.as_str()), (BrowserKind::GoogleChrome, "156.0.7778.56"));
            let (kind, version) =
                parse_linux_version("Chromium 126.0.6478.182 built on Debian GNU/Linux 12 (bookworm), running on Debian GNU/Linux 12 (bookworm)").unwrap();
            assert_eq!((kind, version.as_str()), (BrowserKind::Chromium, "126.0.6478.182"));
            for bad in [
                "Google Chrome 157.0.1.2 beta",
                "Google Chrome 157.0.1.2 dev",
                "Google Chrome for Testing 156.0.1.2",
                "Chromium",
                "true (GNU coreutils) 9.4",
                "",
            ] {
                assert!(parse_linux_version(bad).is_err(), "{bad:?}");
            }
        }

        #[test]
        fn candidates_list_chrome_before_chromium_and_the_real_binary_before_the_script() {
            let list = candidates();
            let pos = |needle: &str| list.iter().position(|c| c == needle).unwrap_or_else(|| panic!("{needle}"));
            assert!(pos("/opt/google/chrome/chrome") < pos("/usr/bin/google-chrome-stable"));
            assert!(pos("/usr/bin/google-chrome-stable") < pos("/usr/lib/chromium/chromium"));
            assert!(pos("/usr/lib/chromium/chromium") < pos("/usr/bin/chromium"));
            assert!(
                pos("/usr/lib64/chromium-browser/chromium-browser")
                    < pos("/usr/bin/chromium-browser")
            );
        }

        /// Fedora 41: `/usr/bin/chromium-browser` canonicalizes to
        /// `chromium-browser.sh`. The script is not run; the ELF beside it is.
        #[test]
        fn fedora_chromium_browser_script_maps_to_the_elf_beside_it() {
            let root = scratch("lx-fedora");
            let dir = root.join("usr/lib64/chromium-browser");
            std::fs::create_dir_all(&dir).unwrap();
            let elf = dir.join("chromium-browser");
            std::fs::copy("/bin/true", &elf).unwrap();
            make_executable(&elf);
            let marker = root.join("rodou");
            let script = dir.join("chromium-browser.sh");
            std::fs::write(&script, format!("#!/bin/sh\ntouch {}\n", marker.display())).unwrap();
            make_executable(&script);
            let link_dir = root.join("usr/bin");
            std::fs::create_dir_all(&link_dir).unwrap();
            let link = link_dir.join("chromium-browser");
            symlink(&script, &link).unwrap();
            let resolved = std::fs::canonicalize(&link).unwrap();
            assert!(resolved.ends_with("chromium-browser.sh"), "{resolved:?}");
            assert_eq!(
                linux_real_binary(&resolved).unwrap(),
                std::fs::canonicalize(&elf).unwrap()
            );
            assert!(!marker.exists(), "the wrapper script must not have run");
            let _ = std::fs::remove_dir_all(root);
        }

        #[test]
        fn a_regular_trusted_elf_passes_every_check_and_only_then_runs_version() {
            let (root, binary) = tree("lx-ok");
            // The ELF is coreutils' `true`: it passes owner/mode/directories and ONLY THEN
            // runs `--version`, whose output is not a browser's.
            let err = validate_chrome_linux_from(&binary, euid(), &root).unwrap_err();
            assert!(matches!(err, ChromeError::UnexpectedBundle(_)), "{err:?}");
            let _ = std::fs::remove_dir_all(root);
        }

        #[test]
        fn a_binary_writable_by_group_or_others_is_refused_before_anything_runs() {
            let (root, binary) = tree("lx-w");
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o775)).unwrap();
            let err = validate_chrome_linux_from(&binary, euid(), &root).unwrap_err();
            assert!(matches!(err, ChromeError::Untrusted(ref w) if w.contains("writable")), "{err:?}");
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o757)).unwrap();
            assert!(matches!(validate_chrome_linux_from(&binary, euid(), &root).unwrap_err(), ChromeError::Untrusted(_)));
            let _ = std::fs::remove_dir_all(root);
        }

        #[test]
        fn a_writable_directory_above_the_binary_is_refused() {
            let (root, binary) = tree("lx-dir");
            std::fs::set_permissions(root.join("opt"), std::fs::Permissions::from_mode(0o777)).unwrap();
            let err = validate_chrome_linux_from(&binary, euid(), &root).unwrap_err();
            assert!(matches!(err, ChromeError::Untrusted(ref w) if w.contains("directory")), "{err:?}");
            std::fs::set_permissions(root.join("opt"), std::fs::Permissions::from_mode(0o755)).unwrap();
            let _ = std::fs::remove_dir_all(root);
        }

        #[test]
        fn a_file_owned_by_someone_else_is_refused() {
            let (root, binary) = tree("lx-uid");
            // The "trusted owner" is another uid: the current user's uid no longer applies.
            let err = validate_chrome_linux_from(&binary, euid() + 1, &root).unwrap_err();
            assert!(matches!(err, ChromeError::Untrusted(ref w) if w.contains("is owned by user")), "{err:?}");
            let _ = std::fs::remove_dir_all(root);
        }

        #[test]
        fn scripts_and_non_browser_names_are_refused_without_running() {
            let (root, binary) = tree("lx-script");
            let marker = root.join("rodou");
            let script = root.join("opt/chrome/google-chrome");
            std::fs::write(&script, format!("#!/bin/sh\ntouch {}\n", marker.display())).unwrap();
            make_executable(&script);
            // The script is dropped from the path: swapped for the ELF `chrome` binary beside it.
            assert_eq!(linux_real_binary(&std::fs::canonicalize(&script).unwrap()).unwrap(), std::fs::canonicalize(&binary).unwrap());
            // A script without an ELF sibling is refused.
            let alone = root.join("solto");
            std::fs::create_dir_all(&alone).unwrap();
            let lonely = alone.join("chrome");
            std::fs::write(&lonely, "#!/bin/sh\ntouch rodou\n").unwrap();
            make_executable(&lonely);
            assert!(matches!(linux_real_binary(&lonely).unwrap_err(), ChromeError::NotABundle(_)));
            // An ELF with a name that is not a browser's never runs.
            let other = root.join("opt/chrome/ls");
            std::fs::copy("/bin/true", &other).unwrap();
            make_executable(&other);
            let err = validate_chrome_linux_from(&other, euid(), &root).unwrap_err();
            assert!(matches!(err, ChromeError::NotABundle(ref w) if w.contains("browser name")), "{err:?}");
            // A script with an arbitrary name is NOT swapped for the `chrome` beside it
            // (only known wrapper names, finding from review round 14).
            let arbitrary = root.join("opt/chrome/run-chrome");
            std::fs::write(&arbitrary, "#!/bin/sh\ntouch rodou\n").unwrap();
            make_executable(&arbitrary);
            let err = linux_real_binary(&std::fs::canonicalize(&arbitrary).unwrap()).unwrap_err();
            assert!(matches!(err, ChromeError::NotABundle(ref w) if w.contains("script")), "{err:?}");
            assert!(!marker.exists(), "the script must not have run");
            let _ = std::fs::remove_dir_all(root);
        }

        /// A FIFO pointed at as a browser is refused **immediately**: with no writer,
        /// a blocking `open` would hang before the `linux_version` limit.
        #[test]
        fn a_fifo_is_refused_immediately_without_blocking() {
            use std::sync::mpsc;
            use std::time::Duration;

            let root = scratch("lx-fifo");
            let fifo = root.join("chrome");
            let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
            // SAFETY: `c` is NUL-terminated and the FIFO is created inside the test folder.
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o755) }, 0);
            let (tx, rx) = mpsc::channel();
            let (fifo, root_clone) = (fifo.clone(), root.clone());
            std::thread::spawn(move || {
                let result = validate_chrome_linux_from(&fifo, euid(), &root_clone)
                    .map(|_| String::from("aceitou"))
                    .unwrap_or_else(|e| e.to_string());
                let _ = tx.send(result);
            });
            // No writer on the FIFO: if `open` blocked, nothing would arrive here.
            let got = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("validation must not block on a FIFO");
            assert!(got.contains("is not a regular file"), "{got}");
            let _ = std::fs::remove_dir_all(root);
        }

        #[test]
        fn a_symlink_is_resolved_to_the_canonical_binary() {
            let (root, binary) = tree("lx-link");
            let link = root.join("google-chrome-stable");
            symlink(&binary, &link).unwrap();
            // The link resolves to the canonical one; validation runs on the canonical one.
            let err = validate_chrome_linux_from(&link, euid(), &root).unwrap_err();
            assert!(matches!(err, ChromeError::UnexpectedBundle(_)), "{err:?}");
            assert_eq!(std::fs::canonicalize(&link).unwrap(), std::fs::canonicalize(&binary).unwrap());
            let _ = std::fs::remove_dir_all(root);
        }

        #[test]
        fn control_characters_in_the_path_are_refused() {
            let err = validate_chrome_linux_from(Path::new("/opt/g\noogle/chrome"), 0, Path::new("/")).unwrap_err();
            assert!(matches!(err, ChromeError::UnsafePath(_)), "{err:?}");
        }

        /// This machine's REAL browser (in the test container, the official package):
        /// passes validation, with product, version and owning package.
        #[test]
        fn the_installed_browser_passes_when_present() {
            let Ok(found) = resolve_stable_chrome(None) else {
                eprintln!("no browser installed: test skipped");
                return;
            };
            assert!(found.binary.is_absolute() && found.binary.is_file());
            assert!(found.version.chars().next().unwrap().is_ascii_digit(), "{}", found.version);
            assert!(found.team_id.is_empty());
            println!("{:?} {} {} pacote={:?}", found.kind, found.version, found.binary.display(), found.package);
            if cfg!(target_arch = "aarch64") {
                assert_eq!(found.kind, BrowserKind::Chromium, "only Chromium exists on arm64");
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn validate_refuses_a_fake_app_that_lies_in_its_info_plist() {
        // `Info.plist` says com.google.Chrome and gives a version, the executable is a script:
        // the (nonexistent) signature does not match.
        let dir = scratch("fakeapp");
        let app = dir.join("Google Chrome.app");
        std::fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
        std::fs::write(
            app.join("Contents/Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.google.Chrome</string>
<key>CFBundleExecutable</key><string>Google Chrome</string>
<key>CFBundleShortVersionString</key><string>156.0.8078.74</string>
</dict></plist>"#,
        )
        .unwrap();
        let exe = app.join("Contents/MacOS/Google Chrome");
        std::fs::write(&exe, "#!/bin/sh\ntouch /tmp/sl-fake-chrome-ran\n").unwrap();
        make_executable(&exe);
        for chosen in [&app, &exe] {
            let err = validate_chrome(chosen).unwrap_err();
            assert!(matches!(err, ChromeError::BadSignature(_)), "{err:?}");
            assert!(err.to_string().contains("signature"), "{err}");
        }
        assert!(!Path::new("/tmp/sl-fake-chrome-ran").exists(), "the fake script must not have run");
        // Bundle of another product.
        std::fs::write(
            app.join("Contents/Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>org.example.Other</string></dict></plist>"#,
        )
        .unwrap();
        let err = validate_chrome(&app).unwrap_err();
        assert!(matches!(err, ChromeError::UnexpectedBundle(ref id) if id == "org.example.Other"), "{err:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Builds a minimal `.app` with Chrome's `Info.plist` and an executable
    /// copied from `/usr/bin/true`, signed AD HOC with Chrome's identifier.
    #[cfg(target_os = "macos")]
    fn adhoc_chrome_bundle(dir: &Path) -> PathBuf {
        let app = dir.join("Google Chrome.app");
        std::fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
        std::fs::write(
            app.join("Contents/Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.google.Chrome</string>
<key>CFBundleExecutable</key><string>Google Chrome</string>
<key>CFBundleShortVersionString</key><string>156.0.8078.74</string>
</dict></plist>"#,
        )
        .unwrap();
        let exe = app.join("Contents/MacOS/Google Chrome");
        std::fs::copy("/usr/bin/true", &exe).unwrap();
        make_executable(&exe);
        let signed = std::process::Command::new("/usr/bin/codesign")
            .args(["--force", "-s", "-", "--identifier", "com.google.Chrome"])
            .arg(&app)
            .output()
            .unwrap();
        assert!(signed.status.success(), "{}", String::from_utf8_lossy(&signed.stderr));
        app
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn r1_adhoc_bundle_claiming_the_chrome_identity_is_refused() {
        // Signed (valid seal) and with Chrome's identifier, but ad hoc: the
        // requirement demands the Apple anchor and Google's Team ID in the certificate.
        let dir = scratch("adhoc");
        let app = adhoc_chrome_bundle(&dir);
        for chosen in [app.clone(), app.join("Contents/MacOS/Google Chrome")] {
            let err = validate_chrome(&chosen).unwrap_err();
            assert!(matches!(err, ChromeError::BadSignature(_)), "{err:?}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn r1_newline_in_the_path_cannot_forge_the_signature_fields() {
        // Review PoC: the directory name injects fake `Identifier=` and
        // `TeamIdentifier=` lines. Now the path is refused before any
        // read, and the result never depends on codesign's text output.
        let base = scratch("inj");
        let evil = base.join(
            "inj\nIdentifier=com.google.Chrome\nTeamIdentifier=EQHXZ8M8AV\nx",
        );
        std::fs::create_dir_all(&evil).unwrap();
        let app = adhoc_chrome_bundle(&evil);
        for chosen in [app.clone(), app.join("Contents/MacOS/Google Chrome")] {
            let err = validate_chrome(&chosen).unwrap_err();
            assert!(matches!(err, ChromeError::UnsafePath(_)), "{err:?}");
            assert_eq!(err.code(), "browser_invalid");
            assert!(!err.to_string().contains('\n'), "the message must not carry the line break");
        }
        // The other controls too: TAB, CR, NUL (this one never even reaches the system).
        for bad in ["a\tb", "a\rb", "a\u{7f}b", "a\u{85}b"] {
            let err = validate_chrome(Path::new(&format!("/Applications/{bad}.app"))).unwrap_err();
            assert!(matches!(err, ChromeError::UnsafePath(_)), "{bad:?}: {err:?}");
        }
        // Even an ad hoc bundle at a clean path is still refused (BadSignature).
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn r2_a_signed_copy_with_a_swapped_helper_is_refused() {
        let real = Path::new("/Applications/Google Chrome.app");
        if !real.is_dir() {
            eprintln!("Chrome not installed: test skipped");
            return;
        }
        let dir = scratch("helper");
        let copy = dir.join("Google Chrome.app");
        // `cp -c` clones on APFS (instant, no data copied). Without a clone, skip.
        let cloned = std::process::Command::new("/bin/cp")
            .arg("-cR")
            .arg(real)
            .arg(&copy)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !cloned {
            eprintln!("clonefile unavailable: test skipped");
            let _ = std::fs::remove_dir_all(dir);
            return;
        }
        // Control: the intact copy is still valid (Google's signature).
        let control = validate_chrome(&copy).expect("the intact copy satisfies the requirement");
        assert_eq!(control.team_id, "EQHXZ8M8AV");
        // Swap the Helper executable for a script that would leave a marker.
        let versions = copy.join("Contents/Frameworks/Google Chrome Framework.framework/Versions");
        let version = std::fs::read_dir(&versions)
            .unwrap()
            .filter_map(Result::ok)
            .find(|e| e.file_name() != "Current" && e.path().join("Helpers").is_dir())
            .expect("framework version directory")
            .path();
        let helper = version.join("Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper");
        assert!(helper.is_file(), "{}", helper.display());
        let marker = dir.join("helper-ran");
        std::fs::remove_file(&helper).unwrap();
        std::fs::write(&helper, format!("#!/bin/sh\ntouch {}\n", marker.display())).unwrap();
        make_executable(&helper);
        let err = validate_chrome(&copy).unwrap_err();
        assert!(matches!(err, ChromeError::BadSignature(_)), "{err:?}");
        // And also through the main binary.
        let err = validate_chrome(&copy.join("Contents/MacOS/Google Chrome")).unwrap_err();
        assert!(matches!(err, ChromeError::BadSignature(_)), "{err:?}");
        assert!(!marker.exists(), "the swapped Helper must not have run");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn r11_validation_is_not_cached_and_returns_the_canonical_path() {
        let real = Path::new("/Applications/Google Chrome.app");
        if !real.is_dir() {
            return;
        }
        let dir = scratch("canon");
        let link = dir.join("atalho");
        std::os::unix::fs::symlink(real, &link).unwrap();
        let first = validate_chrome(&link).unwrap();
        // What gets executed is the canonical path, not the given shortcut.
        assert_eq!(first.binary, std::fs::canonicalize(&first.binary).unwrap());
        assert!(!first.binary.starts_with(&dir));
        // Swap the shortcut's target for a fake bundle: the next call redoes the
        // full check and refuses (no cache between calls).
        let fake = adhoc_chrome_bundle(&dir.join("falso").tap_create());
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&fake, &link).unwrap();
        assert!(matches!(validate_chrome(&link).unwrap_err(), ChromeError::BadSignature(_)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn validate_accepts_the_installed_chrome_and_reads_its_version() {
        let app = Path::new("/Applications/Google Chrome.app");
        if !app.is_dir() {
            eprintln!("Chrome not installed: test skipped");
            return;
        }
        let ok = validate_chrome(app).expect("installed Chrome");
        assert!(ok.binary.ends_with("Contents/MacOS/Google Chrome"));
        assert_eq!(ok.team_id, "EQHXZ8M8AV");
        assert!(ok.version.chars().next().unwrap().is_ascii_digit(), "{}", ok.version);
        // The direct binary and a symlink to it resolve to the same bundle.
        assert_eq!(validate_chrome(&ok.binary).unwrap(), ok);
        let dir = scratch("link");
        let link = dir.join("meu-chrome");
        std::os::unix::fs::symlink(&ok.binary, &link).unwrap();
        assert_eq!(validate_chrome(&link).unwrap(), ok);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn resolve_stable_chrome_never_substitutes_an_explicit_path() {
        let err = resolve_stable_chrome(Some(Path::new("/bin/echo"))).unwrap_err();
        assert_eq!(err.code(), "browser_invalid");
        #[cfg(target_os = "macos")]
        if Path::new("/Applications/Google Chrome.app").is_dir() {
            // Without an explicit path, finds the installed Chrome and validates it.
            let found = resolve_stable_chrome(None).expect("installed Chrome");
            assert!(found.binary.ends_with("Contents/MacOS/Google Chrome"));
        }
    }
}
