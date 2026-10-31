//! Detecção e seleção manual do Chrome externo. O ScrapeLens nunca usa o
//! perfil pessoal: o launcher do core/ abre um perfil dedicado. Aqui só
//! localizamos/validamos o binário.

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

pub fn candidates() -> Vec<String> {
    let mut paths = vec![
        PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        PathBuf::from("/Applications/Chromium.app/Contents/MacOS/Chromium"),
        PathBuf::from("/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary"),
    ];
    paths.extend(home_candidates());
    paths
        .into_iter()
        .map(|path| path.display().to_string())
        .collect()
}

/// Normaliza o que o usuário escolheu no diálogo: aceita `.app`, o diretório
/// `Contents/MacOS` ou o binário direto.
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
// Validação estrita do navegador da CAPTURA CONTROLADA (docs/16b §2.1)
// ---------------------------------------------------------------------------

/// Identificador do bundle e Team ID da Google para o Chrome estável.
const CHROME_BUNDLE_ID: &str = "com.google.Chrome";
const CHROME_TEAM_ID: &str = "EQHXZ8M8AV";

/// Chrome aceito para a captura controlada, lido sem executar o binário.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedChrome {
    /// Binário dentro do bundle, com symlinks resolvidos.
    pub binary: PathBuf,
    pub app: PathBuf,
    /// `CFBundleShortVersionString` do `Info.plist`.
    pub version: String,
    pub team_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChromeError {
    NotFound(String),
    /// Não é o binário dentro de um `.app` (ex.: `/bin/echo`, um script).
    NotABundle(String),
    /// Bundle de outro produto (não é o Chrome estável).
    UnexpectedBundle(String),
    NoVersion,
    BadSignature(String),
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
            ChromeError::NotFound(p) => write!(f, "navegador não encontrado: {p}"),
            ChromeError::NotABundle(why) => write!(
                f,
                "só o Chrome estável instalado é aceito (um .app da Google); este caminho não é: {why}"
            ),
            ChromeError::UnexpectedBundle(id) => write!(
                f,
                "o bundle é {id:?}, não o Chrome estável ({CHROME_BUNDLE_ID})"
            ),
            ChromeError::NoVersion => write!(f, "o Info.plist do navegador não informa a versão"),
            ChromeError::BadSignature(why) => {
                write!(f, "a assinatura do navegador não confere com a Google: {why}")
            }
            ChromeError::UnsupportedPlatform => write!(
                f,
                "a validação do navegador da captura controlada só existe para macOS nesta versão"
            ),
        }
    }
}

impl std::error::Error for ChromeError {}

/// Aceita só o **Chrome estável** da Google: o binário precisa estar em
/// `<X>.app/Contents/MacOS/<CFBundleExecutable>`, o `Info.plist` precisa ter o
/// identificador `com.google.Chrome` e uma versão, e a assinatura de código
/// precisa verificar (`codesign --verify`) com o Team ID da Google. Nada é
/// executado: só `plutil` e `codesign` do sistema, por caminho absoluto, leem o
/// bundle. Recusa `/bin/echo`, scripts e `.app` falsos (mesmo com `Info.plist`
/// mentindo, a assinatura não confere).
pub fn validate_chrome(chosen: &Path) -> Result<ValidatedChrome, ChromeError> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = chosen;
        Err(ChromeError::UnsupportedPlatform)
    }
    #[cfg(target_os = "macos")]
    {
        validate_chrome_macos(chosen)
    }
}

#[cfg(target_os = "macos")]
fn validate_chrome_macos(chosen: &Path) -> Result<ValidatedChrome, ChromeError> {
    use std::process::Command;

    let resolved = std::fs::canonicalize(chosen)
        .map_err(|_| ChromeError::NotFound(chosen.display().to_string()))?;
    // Aceita o `.app`, o binário dentro dele ou o diretório `Contents/MacOS`.
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
            .ok_or_else(|| ChromeError::NotABundle(format!("{} não está dentro de um .app", b.display())))?,
    };
    let plist = app.join("Contents/Info.plist");
    let output = Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-", "--"])
        .arg(&plist)
        .output()
        .map_err(|e| ChromeError::NotABundle(format!("plutil: {e}")))?;
    if !output.status.success() {
        return Err(ChromeError::NotABundle(format!("sem Info.plist legível em {}", app.display())));
    }
    let info: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| ChromeError::NotABundle("Info.plist inválido".to_string()))?;
    let text = |key: &str| info.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let id = text("CFBundleIdentifier");
    if id != CHROME_BUNDLE_ID {
        return Err(ChromeError::UnexpectedBundle(id));
    }
    let executable = text("CFBundleExecutable");
    let expected = app.join("Contents/MacOS").join(&executable);
    if executable.is_empty() || executable.contains('/') {
        return Err(ChromeError::NotABundle("CFBundleExecutable inválido".to_string()));
    }
    let binary = match binary {
        Some(b) if b == expected => b,
        Some(b) => {
            return Err(ChromeError::NotABundle(format!(
                "{} não é o executável do bundle ({})",
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
            return Err(ChromeError::NotABundle("o binário não é executável".to_string()));
        }
    }
    let version = text("CFBundleShortVersionString");
    if version.trim().is_empty() {
        return Err(ChromeError::NoVersion);
    }
    // Assinatura: verifica o selo e lê o Team ID.
    let verify = Command::new("/usr/bin/codesign")
        .arg("--verify")
        .arg(&app)
        .output()
        .map_err(|e| ChromeError::BadSignature(format!("codesign: {e}")))?;
    if !verify.status.success() {
        return Err(ChromeError::BadSignature(
            String::from_utf8_lossy(&verify.stderr).trim().to_string(),
        ));
    }
    let display = Command::new("/usr/bin/codesign")
        .args(["-dv", "--verbose=2"])
        .arg(&app)
        .output()
        .map_err(|e| ChromeError::BadSignature(format!("codesign: {e}")))?;
    let details = String::from_utf8_lossy(&display.stderr).to_string();
    let field = |name: &str| {
        details
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let signed_id = field("Identifier=");
    let team_id = field("TeamIdentifier=");
    if signed_id != CHROME_BUNDLE_ID || team_id != CHROME_TEAM_ID {
        return Err(ChromeError::BadSignature(format!(
            "identificador {signed_id:?}, Team ID {team_id:?} (esperado {CHROME_BUNDLE_ID} / {CHROME_TEAM_ID})"
        )));
    }
    Ok(ValidatedChrome {
        binary,
        app,
        version,
        team_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Nesta máquina o Chrome existe; o teste aceita ambos os estados e só
        // exige que a decisão seja coerente com o disco.
        if let Some(path) = &info.path {
            assert!(Path::new(path).is_file());
            assert!(info.found);
        } else {
            assert!(!info.found);
            assert!(!info.candidates.is_empty());
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
                assert!(err.to_string().contains("Chrome estável"), "{err}");
            }
        }
    }

    #[test]
    fn validate_refuses_missing_paths_and_fake_scripts() {
        let err = validate_chrome(Path::new("/nao/existe/Google Chrome")).unwrap_err();
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

    #[cfg(target_os = "macos")]
    #[test]
    fn validate_refuses_a_fake_app_that_lies_in_its_info_plist() {
        // `Info.plist` diz com.google.Chrome e dá versão, o executável é um script:
        // a assinatura (inexistente) não confere.
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
            assert!(err.to_string().contains("assinatura"), "{err}");
        }
        assert!(!Path::new("/tmp/sl-fake-chrome-ran").exists(), "o script falso não pode ter rodado");
        // Bundle de outro produto.
        std::fs::write(
            app.join("Contents/Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>org.exemplo.Outro</string></dict></plist>"#,
        )
        .unwrap();
        let err = validate_chrome(&app).unwrap_err();
        assert!(matches!(err, ChromeError::UnexpectedBundle(ref id) if id == "org.exemplo.Outro"), "{err:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn validate_accepts_the_installed_chrome_and_reads_its_version() {
        let app = Path::new("/Applications/Google Chrome.app");
        if !app.is_dir() {
            eprintln!("Chrome não instalado: teste ignorado");
            return;
        }
        let ok = validate_chrome(app).expect("Chrome instalado");
        assert!(ok.binary.ends_with("Contents/MacOS/Google Chrome"));
        assert_eq!(ok.team_id, "EQHXZ8M8AV");
        assert!(ok.version.chars().next().unwrap().is_ascii_digit(), "{}", ok.version);
        // O binário direto e um symlink para ele resolvem para o mesmo bundle.
        assert_eq!(validate_chrome(&ok.binary).unwrap(), ok);
        let dir = scratch("link");
        let link = dir.join("meu-chrome");
        std::os::unix::fs::symlink(&ok.binary, &link).unwrap();
        assert_eq!(validate_chrome(&link).unwrap(), ok);
        let _ = std::fs::remove_dir_all(dir);
    }
}
