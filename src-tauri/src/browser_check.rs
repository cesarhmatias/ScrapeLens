//! Which programs the App accepts as its Chrome: Google Chrome (stable, Beta, Dev, Canary and
//! Chrome for Testing), Chromium, Brave, Microsoft Edge and Arc. Anything else is refused: a
//! shell, a script in a user folder, a directory, an arbitrary file. The check only reads: the
//! bundle's `Info.plist` (through the system `plutil`) on macOS, and the file header, name,
//! owner and mode on Linux. It never runs the file.
//!
//! The capture crate's own check (`validate_chrome`) is stricter and stays for the
//! controlled capture; this check decides what the App may start.

use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::path::Component;
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::io::Read;

/// macOS bundle identifiers of the accepted browsers.
pub const MAC_BUNDLE_IDS: &[&str] = &[
    "com.google.Chrome",          // Google Chrome (stable)
    "com.google.Chrome.beta",     // Google Chrome Beta (not checked on a Mac with it installed)
    "com.google.Chrome.dev",      // Google Chrome Dev (not checked on a Mac with it installed)
    "com.google.Chrome.canary",   // Google Chrome Canary (not checked on a Mac with it installed)
    "com.google.chrome.for.testing", // Chrome for Testing (from a forum report, not checked locally)
    "org.chromium.Chromium",      // Chromium
    "com.brave.Browser",          // Brave
    "com.microsoft.edgemac",      // Microsoft Edge
    "company.thebrowser.Browser", // Arc
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

/// Names of the launcher scripts that packages install (checked after symlinks are resolved).
/// A launcher is accepted only when it sits in one of `LINUX_LAUNCHER_DIRS`, is owned by root and
/// is not writable by group or others. The same name in a user folder is refused.
#[cfg(target_os = "linux")]
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
    // Fedora: /usr/bin/chromium-browser -> /usr/lib64/chromium-browser/chromium-browser.sh
    "chromium-browser.sh",
];

/// System directories in which a launcher script may sit (the directory of the resolved file).
#[cfg(target_os = "linux")]
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
    "/snap/bin",
    "/var/lib/flatpak/exports/bin",
];

#[cfg(target_os = "linux")]
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Checks a path the user picked or a saved preference, and returns it when it is an
/// accepted browser. Nothing is executed.
pub fn accept(path: &Path) -> Result<PathBuf, String> {
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
        Err("browser selection is only available on macOS and Linux".to_string())
    }
}

/// The first candidate, in order, that the App accepts. Used when a detected path is refused.
pub fn first_accepted(candidates: &[String]) -> Option<PathBuf> {
    candidates.iter().find_map(|candidate| accept(Path::new(candidate)).ok())
}

#[cfg(target_os = "macos")]
const MAC_HINT: &str = "Choose Google Chrome.app, Chromium.app, Brave.app, Microsoft Edge.app or Arc.app. Other files, shells and scripts are not accepted.";
#[cfg(target_os = "linux")]
const LINUX_HINT: &str = "Choose the browser executable, for example /opt/google/chrome/chrome or /usr/lib/chromium/chromium. Launcher scripts in a user folder, shells and other programs are not accepted.";

#[cfg(target_os = "macos")]
fn accept_mac(path: &Path) -> Result<PathBuf, String> {
    // The executable must sit in `<Name>.app/Contents/MacOS/<CFBundleExecutable>`.
    let inside = path.components().collect::<Vec<_>>();
    let macos_at = inside
        .windows(2)
        .position(|pair| matches!(pair, [Component::Normal(a), Component::Normal(b)] if *a == "Contents" && *b == "MacOS"));
    let Some(index) = macos_at else {
        return Err(format!("not a browser application: {}. {MAC_HINT}", path.display()));
    };
    let bundle: PathBuf = inside[..index].iter().collect();
    if bundle.extension().and_then(|e| e.to_str()) != Some("app") {
        return Err(format!("not a browser application: {}. {MAC_HINT}", path.display()));
    }
    let executable = inside.get(index + 2).and_then(|c| match c {
        Component::Normal(name) => name.to_str(),
        _ => None,
    });
    let Some(executable) = executable else {
        return Err(format!("not a browser application: {}. {MAC_HINT}", path.display()));
    };
    let meta = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(format!("not a browser executable: {}. {MAC_HINT}", path.display()));
    }
    let info = plist_text(&bundle.join("Contents/Info.plist"))?;
    let bundle_id = info.get("CFBundleIdentifier").cloned().unwrap_or_default();
    if !MAC_BUNDLE_IDS.contains(&bundle_id.as_str()) {
        return Err(format!(
            "{} is not a supported browser ({}). {MAC_HINT}",
            bundle.display(),
            if bundle_id.is_empty() { "no bundle identifier".to_string() } else { bundle_id }
        ));
    }
    if info.get("CFBundleExecutable").map(String::as_str) != Some(executable) {
        return Err(format!(
            "{} is not the browser's own executable. {MAC_HINT}",
            path.display()
        ));
    }
    Ok(path.to_path_buf())
}

/// Reads a few top-level keys of a property list through the system `plutil`.
#[cfg(target_os = "macos")]
fn plist_text(plist: &Path) -> Result<std::collections::HashMap<String, String>, String> {
    let output = Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-", "--"])
        .arg(plist)
        .output()
        .map_err(|error| format!("cannot read the bundle's Info.plist: {error}"))?;
    if !output.status.success() {
        return Err(format!("cannot read the bundle's Info.plist: {}", plist.display()));
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "the bundle's Info.plist is not readable".to_string())?;
    let mut keys = std::collections::HashMap::new();
    for key in ["CFBundleIdentifier", "CFBundleExecutable"] {
        if let Some(text) = value.get(key).and_then(|v| v.as_str()) {
            keys.insert(key.to_string(), text.to_string());
        }
    }
    Ok(keys)
}

/// Owner and permission bits of a file or directory.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
struct Owned {
    uid: u32,
    mode: u32,
}

#[cfg(target_os = "linux")]
fn owned(meta: &std::fs::Metadata) -> Owned {
    use std::os::unix::fs::MetadataExt;
    Owned { uid: meta.uid(), mode: meta.mode() & 0o7777 }
}

/// Decides whether a launcher script is a system one. `resolved` is the canonical path; `file`
/// and `dir` are the owner and mode of that file and of its directory. Pure, so the tests can
/// use fabricated owners (the test runner is not root).
#[cfg(target_os = "linux")]
fn trusted_launcher(resolved: &Path, file: Owned, dir: Owned) -> Result<(), String> {
    let Some(parent) = resolved.parent() else {
        return Err("it has no directory".to_string());
    };
    if !LINUX_LAUNCHER_DIRS.iter().any(|system| Path::new(system) == parent) {
        return Err(format!("{} is not a system directory for browsers", parent.display()));
    }
    if file.uid != 0 || dir.uid != 0 {
        return Err("the launcher or its directory is not owned by root".to_string());
    }
    if file.mode & 0o022 != 0 || dir.mode & 0o022 != 0 {
        return Err("the launcher or its directory is writable by group or others".to_string());
    }
    if file.mode & 0o111 == 0 {
        return Err("the launcher is not executable".to_string());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn accept_linux(path: &Path) -> Result<PathBuf, String> {
    let meta = std::fs::metadata(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    // Only a regular file: a FIFO or a device would block the open below.
    if !meta.is_file() {
        return Err(format!("not a browser executable: {}. {LINUX_HINT}", path.display()));
    }
    // Follow symlinks to the file that would run, and judge that file.
    let target = std::fs::canonicalize(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let name = target.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    let mut head = Vec::new();
    std::fs::File::open(&target)
        .and_then(|file| file.take(4).read_to_end(&mut head))
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if head.starts_with(&ELF_MAGIC) {
        // A binary is accepted by its name, wherever it lives (portable builds included).
        if LINUX_BINARY_NAMES.contains(&name) {
            return Ok(path.to_path_buf());
        }
        return Err(format!("{} is not a supported browser. {LINUX_HINT}", path.display()));
    }
    // Not a binary: only a system launcher of a known browser is accepted, and it is not run.
    if head.starts_with(b"#!") && LINUX_LAUNCHER_NAMES.contains(&name) {
        let Some(dir) = target.parent() else {
            return Err(format!("{} is not a supported browser. {LINUX_HINT}", path.display()));
        };
        let dir_meta = std::fs::metadata(dir).map_err(|error| format!("cannot read {}: {error}", dir.display()))?;
        let file_meta = std::fs::metadata(&target).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        trusted_launcher(&target, owned(&file_meta), owned(&dir_meta))
            .map_err(|why| format!("{} is a launcher that is not trusted: {why}. {LINUX_HINT}", path.display()))?;
        return Ok(path.to_path_buf());
    }
    Err(format!(
        "{} is a launcher or script, not the browser binary. {LINUX_HINT}",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch(name: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let dir = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("sl-browser-{name}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_shell_is_refused() {
        let err = accept(Path::new("/bin/sh")).unwrap_err();
        assert!(err.contains("not"), "{err}");
    }

    #[test]
    fn a_script_named_like_a_browser_is_refused() {
        let dir = scratch("script");
        let script = dir.join("chromium");
        fs::write(&script, "#!/bin/sh\necho owned\n").unwrap();
        assert!(accept(&script).is_err());
        let arbitrary = dir.join("chrome");
        fs::write(&arbitrary, b"not a program at all").unwrap();
        assert!(accept(&arbitrary).is_err());
        // A launcher name in a user folder is refused, whatever its content.
        let launcher = dir.join("google-chrome");
        fs::write(&launcher, "#!/bin/sh\nexec /bin/true\n").unwrap();
        assert!(accept(&launcher).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_directory_and_a_missing_path_are_refused() {
        let dir = scratch("dir");
        assert!(accept(&dir).is_err());
        assert!(accept(&dir.join("missing")).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_browser_binary_is_accepted_and_a_shell_under_a_browser_name_is_not() {
        let dir = scratch("linux");
        // A real ELF binary under an accepted name: accepted.
        let brave = dir.join("brave-browser");
        fs::copy("/bin/sh", &brave).unwrap();
        assert_eq!(accept(&brave).unwrap(), brave);
        // The same binary under the name of a shell: refused.
        let copy_as_sh = dir.join("sh");
        fs::copy("/bin/sh", &copy_as_sh).unwrap();
        assert!(accept(&copy_as_sh).is_err());
        // A symlink named like a browser that points at a shell: refused (the target is judged).
        let link = dir.join("chromium");
        std::os::unix::fs::symlink("/bin/sh", &link).unwrap();
        assert!(accept(&link).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(target_os = "linux")]
    fn root_owned(mode: u32) -> Owned {
        Owned { uid: 0, mode }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_root_owned_launcher_in_a_system_directory_is_trusted() {
        let launchers = [
            ("/usr/bin/google-chrome", "/usr/bin"),
            ("/usr/bin/chromium-browser", "/usr/bin"),
            ("/opt/google/chrome/google-chrome", "/opt/google/chrome"),
            ("/usr/lib64/chromium-browser/chromium-browser", "/usr/lib64/chromium-browser"),
            ("/usr/lib64/chromium-browser/chromium-browser.sh", "/usr/lib64/chromium-browser"),
        ];
        for (file, dir) in launchers {
            let is_known_dir = LINUX_LAUNCHER_DIRS.contains(&dir);
            let result = trusted_launcher(Path::new(file), root_owned(0o755), root_owned(0o755));
            assert_eq!(result.is_ok(), is_known_dir, "{file}: {result:?}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_launcher_that_is_not_root_owned_or_writable_is_refused() {
        let file = Path::new("/usr/bin/google-chrome");
        let user = Owned { uid: 1000, mode: 0o755 };
        assert!(trusted_launcher(file, user, root_owned(0o755)).is_err(), "file owner");
        assert!(trusted_launcher(file, root_owned(0o755), user).is_err(), "directory owner");
        assert!(trusted_launcher(file, root_owned(0o775), root_owned(0o755)).is_err(), "group write");
        assert!(trusted_launcher(file, root_owned(0o757), root_owned(0o755)).is_err(), "other write");
        assert!(trusted_launcher(file, root_owned(0o755), root_owned(0o777)).is_err(), "directory other write");
        assert!(trusted_launcher(file, root_owned(0o644), root_owned(0o755)).is_err(), "not executable");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_launcher_outside_the_system_directories_is_refused() {
        let home = Path::new("/home/user/bin/google-chrome");
        assert!(trusted_launcher(home, root_owned(0o755), root_owned(0o755)).is_err());
        let tmp = Path::new("/tmp/google-chrome");
        assert!(trusted_launcher(tmp, root_owned(0o755), root_owned(0o755)).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_system_directories_are_absolute_and_the_names_are_plain() {
        for dir in LINUX_LAUNCHER_DIRS {
            assert!(Path::new(dir).is_absolute(), "{dir}");
        }
        for name in LINUX_BINARY_NAMES.iter().chain(LINUX_LAUNCHER_NAMES) {
            assert!(!name.is_empty() && !name.contains('/'), "{name}");
        }
        assert!(!LINUX_LAUNCHER_NAMES.contains(&"sh"));
        assert!(!LINUX_LAUNCHER_NAMES.contains(&"bash"));
    }

    #[cfg(target_os = "macos")]
    fn fake_bundle(root: &Path, name: &str, bundle_id: &str, executable: &str) -> PathBuf {
        let app = root.join(format!("{name}.app"));
        fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
        fs::write(
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
        // The executable is never run by these tests: a plain file is enough.
        fs::write(app.join("Contents/MacOS").join(executable), b"stub").unwrap();
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
            assert_eq!(accept(&exe).unwrap(), exe, "{id}");
        }
        let shell_bundle = fake_bundle(&dir, "Shell", "com.example.shell", "Shell");
        assert!(accept(&shell_bundle).is_err());
        // An executable that is not the bundle's own: refused.
        let wrong = dir.join("Brave Browser.app/Contents/MacOS/other");
        fs::write(&wrong, b"stub").unwrap();
        assert!(accept(&wrong).is_err());
        // Bare system programs are not bundles.
        assert!(accept(Path::new("/bin/sh")).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn first_accepted_skips_refused_candidates() {
        let dir = scratch("first");
        let bad = dir.join("chromium");
        fs::write(&bad, "#!/bin/sh\n").unwrap();
        let candidates = vec![bad.display().to_string(), "/nonexistent/chrome".to_string()];
        assert!(first_accepted(&candidates).is_none());
        fs::remove_dir_all(&dir).ok();
    }
}
