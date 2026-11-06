//! Which programs the App accepts as its Chrome: Google Chrome (stable, Beta, Dev, Canary and
//! Chrome for Testing), Chromium, Brave, Microsoft Edge and Arc. Anything else is refused: a shell, a launcher script, a directory,
//! an arbitrary file. The check only reads: the bundle's `Info.plist` (through the system
//! `plutil`) on macOS, and the file header and name on Linux. It never runs the file.
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

#[cfg(target_os = "macos")]
const MAC_HINT: &str = "Choose Google Chrome.app, Chromium.app, Brave.app, Microsoft Edge.app or Arc.app. Other files, shells and scripts are not accepted.";
#[cfg(target_os = "linux")]
const LINUX_HINT: &str = "Choose the browser executable, for example /opt/google/chrome/chrome or /usr/lib/chromium/chromium. Launcher scripts, shells and other programs are not accepted.";

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

#[cfg(target_os = "linux")]
fn accept_linux(path: &Path) -> Result<PathBuf, String> {
    let meta = std::fs::metadata(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("not a browser executable: {}. {LINUX_HINT}", path.display()));
    }
    // Follow symlinks to the file that would run, and judge that file.
    let target = std::fs::canonicalize(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let name = target.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    if !LINUX_BINARY_NAMES.contains(&name) {
        return Err(format!("{} is not a supported browser. {LINUX_HINT}", path.display()));
    }
    let mut head = [0u8; 4];
    let read = std::fs::File::open(&target)
        .and_then(|mut file| file.read(&mut head))
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if read < 4 || head != ELF_MAGIC {
        // Launcher scripts (`google-chrome`, `chromium`) and other non-binaries end up here.
        return Err(format!(
            "{} is a launcher or script, not the browser binary. {LINUX_HINT}",
            path.display()
        ));
    }
    Ok(path.to_path_buf())
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
    #[test]
    fn every_accepted_linux_name_is_a_browser_name() {
        for name in LINUX_BINARY_NAMES {
            assert!(!name.is_empty() && !name.contains('/'));
        }
        assert!(!LINUX_BINARY_NAMES.contains(&"sh"));
        assert!(!LINUX_BINARY_NAMES.contains(&"bash"));
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
}
