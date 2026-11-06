//! Which programs may be chosen as the browser, without running the file.
//!
//! Accepted: Google Chrome (stable, Beta, Dev, Canary and Chrome for Testing),
//! Chromium, Brave, Microsoft Edge and Arc. CloakBrowser is not accepted.
//! macOS reads `Info.plist` through `/usr/bin/plutil`. Linux reads the file
//! header, the name, and, for a launcher script, the owner and mode. Nothing
//! here executes the path.
//!
//! This is not [`crate::chrome::validate_chrome`]. That check stays stricter
//! and is what the MCP controlled capture uses for `binary_path`.

use std::path::{Path, PathBuf};

/// macOS bundle identifiers of the accepted browsers.
pub const MAC_BUNDLE_IDS: &[&str] = &[
    "com.google.Chrome",
    "com.google.Chrome.beta",
    "com.google.Chrome.dev",
    "com.google.Chrome.canary",
    "com.google.chrome.for.testing",
    "org.chromium.Chromium",
    "com.brave.Browser",
    "com.microsoft.edgemac",
    "company.thebrowser.Browser",
];

/// Linux executable names of the accepted browsers (the real binaries, not launchers).
pub const LINUX_BINARY_NAMES: &[&str] = &[
    "chrome",
    "chromium",
    "chromium-browser",
    "brave",
    "brave-browser",
    "msedge",
    "microsoft-edge",
];

/// Launcher script names a package may install. Accepted only in [`LINUX_LAUNCHER_DIRS`],
/// owned by root, and not writable by group or others. The same name in a user folder is refused.
pub const LINUX_LAUNCHER_NAMES: &[&str] = &[
    "google-chrome",
    "google-chrome-stable",
    "google-chrome-beta",
    "google-chrome-unstable",
    "chromium",
    "chromium-browser",
    "brave-browser",
    "brave-browser-stable",
    "brave",
    "msedge",
    "microsoft-edge",
    "microsoft-edge-stable",
    "chromium-browser.sh",
];

/// System directories in which a launcher script may sit (the directory of the resolved file).
pub const LINUX_LAUNCHER_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/local/bin",
    "/usr/lib/chromium",
    "/usr/lib/chromium-browser",
    "/usr/lib64/chromium",
    "/usr/lib64/chromium-browser",
    "/opt/google/chrome",
    "/opt/google/chrome-beta",
    "/opt/google/chrome-unstable",
    "/opt/brave.com/brave",
    "/opt/microsoft/msedge",
];

#[cfg(target_os = "linux")]
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Why a path is not an accepted browser. The text is safe to show to an agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserFamilyError {
    message: String,
}

impl BrowserFamilyError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for BrowserFamilyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for BrowserFamilyError {}

/// Returns the path when it is an accepted browser. Does not run the file.
pub fn accept_browser(path: &Path) -> Result<PathBuf, BrowserFamilyError> {
    match path.to_str() {
        Some(text) if !text.chars().any(char::is_control) => {}
        _ => {
            return Err(BrowserFamilyError::new(
                "the browser path has a control character or is not UTF-8 and was refused",
            ));
        }
    }
    #[cfg(target_os = "macos")]
    {
        accept_mac(path)
    }
    #[cfg(target_os = "linux")]
    {
        accept_linux(path)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = path;
        Err(BrowserFamilyError::new(
            "browser selection is only available on macOS and Linux",
        ))
    }
}

#[cfg(target_os = "macos")]
const MAC_HINT: &str = "Choose Google Chrome.app, Chromium.app, Brave Browser.app, Microsoft Edge.app or Arc.app. Other files, shells and scripts are not accepted.";

#[cfg(target_os = "linux")]
const LINUX_HINT: &str = "Choose the browser executable, for example /opt/google/chrome/chrome or /usr/lib/chromium/chromium. Launcher scripts in a user folder, shells and other programs are not accepted.";

#[cfg(target_os = "macos")]
fn accept_mac(path: &Path) -> Result<PathBuf, BrowserFamilyError> {
    use std::path::Component;

    let inside = path.components().collect::<Vec<_>>();
    let macos_at = inside.windows(2).position(|pair| {
        matches!(
            pair,
            [Component::Normal(a), Component::Normal(b)] if *a == "Contents" && *b == "MacOS"
        )
    });
    let Some(index) = macos_at else {
        return Err(BrowserFamilyError::new(format!(
            "not a browser application: {}. {MAC_HINT}",
            path.display()
        )));
    };
    let bundle: PathBuf = inside[..index].iter().collect();
    if bundle.extension().and_then(|ext| ext.to_str()) != Some("app") {
        return Err(BrowserFamilyError::new(format!(
            "not a browser application: {}. {MAC_HINT}",
            path.display()
        )));
    }
    let executable = inside.get(index + 2).and_then(|component| match component {
        Component::Normal(name) => name.to_str(),
        _ => None,
    });
    let Some(executable) = executable else {
        return Err(BrowserFamilyError::new(format!(
            "not a browser application: {}. {MAC_HINT}",
            path.display()
        )));
    };
    let meta = std::fs::symlink_metadata(path).map_err(|error| {
        BrowserFamilyError::new(format!("cannot read {}: {error}", path.display()))
    })?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(BrowserFamilyError::new(format!(
            "not a browser executable: {}. {MAC_HINT}",
            path.display()
        )));
    }
    let info = plist_text(&bundle.join("Contents/Info.plist"))?;
    let bundle_id = info.get("CFBundleIdentifier").cloned().unwrap_or_default();
    if bundle_id.to_ascii_lowercase().contains("cloak")
        || !MAC_BUNDLE_IDS.contains(&bundle_id.as_str())
    {
        return Err(BrowserFamilyError::new(format!(
            "{} is not a supported browser ({}). CloakBrowser is not accepted. {MAC_HINT}",
            bundle.display(),
            if bundle_id.is_empty() {
                "no bundle identifier".to_string()
            } else {
                bundle_id
            }
        )));
    }
    if info.get("CFBundleExecutable").map(String::as_str) != Some(executable) {
        return Err(BrowserFamilyError::new(format!(
            "{} is not the browser's own executable. {MAC_HINT}",
            path.display()
        )));
    }
    Ok(path.to_path_buf())
}

#[cfg(target_os = "macos")]
fn plist_text(
    plist: &Path,
) -> Result<std::collections::HashMap<String, String>, BrowserFamilyError> {
    let output = std::process::Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-", "--"])
        .arg(plist)
        .output()
        .map_err(|error| {
            BrowserFamilyError::new(format!("cannot read the bundle's Info.plist: {error}"))
        })?;
    if !output.status.success() {
        return Err(BrowserFamilyError::new(format!(
            "cannot read the bundle's Info.plist: {}",
            plist.display()
        )));
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| BrowserFamilyError::new("the bundle's Info.plist is not readable"))?;
    let mut keys = std::collections::HashMap::new();
    for key in ["CFBundleIdentifier", "CFBundleExecutable"] {
        if let Some(text) = value.get(key).and_then(|item| item.as_str()) {
            keys.insert(key.to_string(), text.to_string());
        }
    }
    Ok(keys)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
struct Owned {
    uid: u32,
    mode: u32,
}

#[cfg(target_os = "linux")]
fn owned(meta: &std::fs::Metadata) -> Owned {
    use std::os::unix::fs::MetadataExt;
    Owned {
        uid: meta.uid(),
        mode: meta.mode() & 0o7777,
    }
}

/// `resolved` is the canonical path. `dirs` runs from its directory up to `/`.
#[cfg(target_os = "linux")]
fn trusted_launcher(resolved: &Path, file: Owned, dirs: &[(&Path, Owned)]) -> Result<(), String> {
    let Some(parent) = resolved.parent() else {
        return Err("it has no directory".to_string());
    };
    if !LINUX_LAUNCHER_DIRS
        .iter()
        .any(|system| Path::new(system) == parent)
    {
        return Err(format!(
            "{} is not a system directory for browsers",
            parent.display()
        ));
    }
    if file.uid != 0 {
        return Err("the launcher is not owned by root".to_string());
    }
    if file.mode & 0o022 != 0 {
        return Err("the launcher is writable by group or others".to_string());
    }
    if file.mode & 0o111 == 0 {
        return Err("the launcher is not executable".to_string());
    }
    for (dir, owner) in dirs {
        if owner.uid != 0 {
            return Err(format!(
                "the directory {} is not owned by root",
                dir.display()
            ));
        }
        if owner.mode & 0o022 != 0 {
            return Err(format!(
                "the directory {} is writable by group or others",
                dir.display()
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_wrapper_path(path: &Path) -> bool {
    path.starts_with("/snap") || path.starts_with("/var/lib/flatpak")
}

#[cfg(target_os = "linux")]
fn wrapper_error(path: &Path) -> BrowserFamilyError {
    BrowserFamilyError::new(format!(
        "{} is a Snap or Flatpak wrapper. Snap and Flatpak browsers are not accepted yet: choose a browser installed from a .deb or .rpm package, or its real executable.",
        path.display()
    ))
}

#[cfg(target_os = "linux")]
fn accept_linux(path: &Path) -> Result<PathBuf, BrowserFamilyError> {
    use std::io::Read;

    if is_wrapper_path(path) {
        return Err(wrapper_error(path));
    }
    let meta = std::fs::metadata(path).map_err(|error| {
        BrowserFamilyError::new(format!("cannot read {}: {error}", path.display()))
    })?;
    if !meta.is_file() {
        return Err(BrowserFamilyError::new(format!(
            "not a browser executable: {}. {LINUX_HINT}",
            path.display()
        )));
    }
    let target = std::fs::canonicalize(path).map_err(|error| {
        BrowserFamilyError::new(format!("cannot read {}: {error}", path.display()))
    })?;
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if is_wrapper_path(&target) || name == "snap" || name == "flatpak" {
        return Err(wrapper_error(path));
    }
    if name.to_ascii_lowercase().contains("cloak") {
        return Err(BrowserFamilyError::new(format!(
            "{} is not a supported browser. CloakBrowser is not accepted. {LINUX_HINT}",
            path.display()
        )));
    }
    let mut head = Vec::new();
    std::fs::File::open(&target)
        .and_then(|file| file.take(4).read_to_end(&mut head))
        .map_err(|error| {
            BrowserFamilyError::new(format!("cannot read {}: {error}", path.display()))
        })?;
    if head.starts_with(&ELF_MAGIC) {
        if LINUX_BINARY_NAMES.contains(&name) {
            return Ok(path.to_path_buf());
        }
        return Err(BrowserFamilyError::new(format!(
            "{} is not a supported browser. {LINUX_HINT}",
            path.display()
        )));
    }
    if head.starts_with(b"#!") && LINUX_LAUNCHER_NAMES.contains(&name) {
        let Some(dir) = target.parent() else {
            return Err(BrowserFamilyError::new(format!(
                "{} is not a supported browser. {LINUX_HINT}",
                path.display()
            )));
        };
        let file_meta = std::fs::metadata(&target).map_err(|error| {
            BrowserFamilyError::new(format!("cannot read {}: {error}", path.display()))
        })?;
        let mut dirs = Vec::new();
        for ancestor in dir.ancestors() {
            let owner = std::fs::metadata(ancestor).map_err(|error| {
                BrowserFamilyError::new(format!("cannot read {}: {error}", ancestor.display()))
            })?;
            dirs.push((ancestor, owned(&owner)));
        }
        trusted_launcher(&target, owned(&file_meta), &dirs).map_err(|why| {
            BrowserFamilyError::new(format!(
                "{} is a launcher that is not trusted: {why}. {LINUX_HINT}",
                path.display()
            ))
        })?;
        return Ok(path.to_path_buf());
    }
    Err(BrowserFamilyError::new(format!(
        "{} is a launcher or script, not the browser binary. {LINUX_HINT}",
        path.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloakbrowser_is_not_among_the_accepted_names() {
        let lists = MAC_BUNDLE_IDS
            .iter()
            .chain(LINUX_BINARY_NAMES)
            .chain(LINUX_LAUNCHER_NAMES);
        for name in lists {
            assert!(!name.to_ascii_lowercase().contains("cloak"), "{name}");
        }
        assert!(!LINUX_LAUNCHER_NAMES.contains(&"sh"));
        assert!(!LINUX_LAUNCHER_NAMES.contains(&"bash"));
    }

    fn scratch(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "sl-accept-browser-{name}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_shell_is_refused() {
        let err = accept_browser(Path::new("/bin/sh")).unwrap_err();
        assert!(
            err.to_string().contains("not") || err.to_string().contains("supported"),
            "{err}"
        );
    }

    #[test]
    fn a_script_named_like_a_browser_is_refused() {
        let dir = scratch("script");
        let script = dir.join("chromium");
        std::fs::write(&script, "#!/bin/sh\necho owned\n").unwrap();
        assert!(accept_browser(&script).is_err());
        let arbitrary = dir.join("chrome");
        std::fs::write(&arbitrary, b"not a program at all").unwrap();
        assert!(accept_browser(&arbitrary).is_err());
        let launcher = dir.join("google-chrome");
        std::fs::write(&launcher, "#!/bin/sh\nexec /bin/true\n").unwrap();
        assert!(accept_browser(&launcher).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_directory_and_a_missing_path_are_refused() {
        let dir = scratch("dir");
        assert!(accept_browser(&dir).is_err());
        assert!(accept_browser(&dir.join("missing")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_browser_binary_is_accepted_and_a_shell_under_a_browser_name_is_not() {
        let dir = scratch("linux");
        let brave = dir.join("brave-browser");
        std::fs::copy("/bin/sh", &brave).unwrap();
        assert_eq!(accept_browser(&brave).unwrap(), brave);
        let copy_as_sh = dir.join("sh");
        std::fs::copy("/bin/sh", &copy_as_sh).unwrap();
        assert!(accept_browser(&copy_as_sh).is_err());
        let link = dir.join("chromium");
        std::os::unix::fs::symlink("/bin/sh", &link).unwrap();
        assert!(accept_browser(&link).is_err());
        let cloak = dir.join("cloakbrowser");
        std::fs::copy("/bin/sh", &cloak).unwrap();
        let err = accept_browser(&cloak).unwrap_err();
        assert!(err.to_string().contains("CloakBrowser"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    fn root_owned(mode: u32) -> Owned {
        Owned { uid: 0, mode }
    }

    #[cfg(target_os = "linux")]
    fn root_chain(mode: u32) -> Vec<(&'static Path, Owned)> {
        vec![
            (Path::new("/usr/bin"), root_owned(mode)),
            (Path::new("/usr"), root_owned(0o755)),
            (Path::new("/"), root_owned(0o755)),
        ]
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_root_owned_launcher_in_a_system_directory_is_trusted() {
        let launchers = [
            ("/usr/bin/google-chrome", "/usr/bin", true),
            ("/usr/bin/chromium-browser", "/usr/bin", true),
            (
                "/opt/google/chrome/google-chrome",
                "/opt/google/chrome",
                true,
            ),
            (
                "/usr/lib64/chromium-browser/chromium-browser.sh",
                "/usr/lib64/chromium-browser",
                true,
            ),
            ("/home/user/bin/google-chrome", "/home/user/bin", false),
        ];
        for (file, dir, known) in launchers {
            let chain = [
                (Path::new(dir), root_owned(0o755)),
                (Path::new("/"), root_owned(0o755)),
            ];
            let result = trusted_launcher(Path::new(file), root_owned(0o755), &chain);
            assert_eq!(result.is_ok(), known, "{file}: {result:?}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_launcher_that_is_not_root_owned_or_writable_is_refused() {
        let file = Path::new("/usr/bin/google-chrome");
        let user = Owned {
            uid: 1000,
            mode: 0o755,
        };
        assert!(trusted_launcher(file, user, &root_chain(0o755)).is_err());
        assert!(trusted_launcher(file, root_owned(0o775), &root_chain(0o755)).is_err());
        assert!(trusted_launcher(file, root_owned(0o644), &root_chain(0o755)).is_err());
        assert!(trusted_launcher(file, root_owned(0o755), &root_chain(0o777)).is_err());
    }

    #[cfg(target_os = "macos")]
    fn fake_bundle(root: &Path, name: &str, bundle_id: &str, executable: &str) -> PathBuf {
        let app = root.join(format!("{name}.app"));
        std::fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
        std::fs::write(
            app.join("Contents/Info.plist"),
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>{bundle_id}</string>
<key>CFBundleExecutable</key><string>{executable}</string>
</dict></plist>"#
            ),
        )
        .unwrap();
        std::fs::write(app.join("Contents/MacOS").join(executable), b"stub").unwrap();
        app.join("Contents/MacOS").join(executable)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn supported_browser_bundles_are_accepted_and_others_are_refused() {
        let dir = scratch("mac");
        for (name, id) in [
            ("Google Chrome", "com.google.Chrome"),
            ("Google Chrome Beta", "com.google.Chrome.beta"),
            ("Google Chrome Dev", "com.google.Chrome.dev"),
            ("Google Chrome Canary", "com.google.Chrome.canary"),
            ("Google Chrome for Testing", "com.google.chrome.for.testing"),
            ("Chromium", "org.chromium.Chromium"),
            ("Brave Browser", "com.brave.Browser"),
            ("Microsoft Edge", "com.microsoft.edgemac"),
            ("Arc", "company.thebrowser.Browser"),
        ] {
            let exe = fake_bundle(&dir, name, id, name);
            assert_eq!(accept_browser(&exe).unwrap(), exe, "{id}");
        }
        let shell_bundle = fake_bundle(&dir, "Shell", "com.example.shell", "Shell");
        assert!(accept_browser(&shell_bundle).is_err());
        let cloak = fake_bundle(
            &dir,
            "CloakBrowser",
            "com.cloakbrowser.CloakBrowser",
            "CloakBrowser",
        );
        let err = accept_browser(&cloak).unwrap_err();
        assert!(err.to_string().contains("CloakBrowser"), "{err}");
        let wrong = dir.join("Brave Browser.app/Contents/MacOS/other");
        std::fs::write(&wrong, b"stub").unwrap();
        assert!(accept_browser(&wrong).is_err());
        assert!(accept_browser(Path::new("/bin/sh")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
