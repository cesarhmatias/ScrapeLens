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
/// Requisito de código que o Chrome estável precisa satisfazer.
pub const CHROME_REQUIREMENT: &str = "anchor apple generic and identifier \"com.google.Chrome\" and certificate leaf[subject.OU] = \"EQHXZ8M8AV\"";

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
    /// O caminho tem caractere de controle (quebra de linha, NUL, TAB...) ou não
    /// é UTF-8: nunca é um Chrome legítimo e engana quem faz parse de texto.
    UnsafePath(String),
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
            ChromeError::UnsafePath(shown) => write!(
                f,
                "o caminho do navegador tem caractere de controle ou não é UTF-8 e foi recusado: {shown}"
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
/// precisa satisfazer o requisito explícito [`CHROME_REQUIREMENT`] em
/// `codesign --verify --deep` (o código de saída decide; nada da saída de texto
/// é interpretado). Nada é executado: só `plutil` e `codesign` do sistema, por
/// caminho absoluto, leem o bundle. Recusa `/bin/echo`, scripts, `.app` falsos
/// (mesmo com `Info.plist` mentindo), caminhos com caractere de controle e
/// cópias do Chrome com um Helper/framework trocado (o `--deep` cobre os
/// aninhados). Sem `--strict`: o Chrome instalado tem atributos de Finder que
/// ele rejeita. O resultado não é guardado em cache: cada chamada reverifica.
///
/// O `binary` devolvido é o caminho canônico validado e é exatamente o que deve
/// ser executado. Sobra uma janela entre esta verificação e o `exec` (um
/// processo do mesmo usuário com escrita no bundle poderia trocar um arquivo
/// depois): `/Applications` é do grupo admin, e uma cópia em pasta do usuário é
/// do próprio usuário, que já poderia executar qualquer coisa. Documentado em
/// docs/16b §2.1.
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

/// Resolve o Chrome estável para a captura controlada: o `explicit` (se
/// houver) é validado e nunca substituído; sem ele, o primeiro candidato
/// instalado que passa em [`validate_chrome`]. É o que o servidor MCP deve
/// chamar para escolher e mostrar o navegador na confirmação.
pub fn resolve_stable_chrome(explicit: Option<&Path>) -> Result<ValidatedChrome, ChromeError> {
    if let Some(path) = explicit {
        return validate_chrome(path);
    }
    let mut last = ChromeError::NotFound("Chrome estável instalado".to_string());
    for candidate in candidates() {
        match validate_chrome(Path::new(&candidate)) {
            Ok(found) => return Ok(found),
            Err(ChromeError::NotFound(_)) => {}
            Err(other) => last = other,
        }
    }
    Err(last)
}

/// Recusa caminho que não é UTF-8 ou tem caractere de controle (`\n`, `\r`,
/// TAB, NUL, DEL, C1). Vale para o caminho dado e para o canônico.
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
    // Assinatura: requisito explícito, com o código de saída como único
    // veredito. `--deep` verifica também os bundles aninhados (Helpers,
    // frameworks). O requisito ancora na CA da Apple e exige o identificador e
    // o Team ID da Google no certificado folha, então um bundle assinado ad hoc
    // ou por outro certificado não satisfaz. Nada da saída de texto é lido.
    let verify = Command::new("/usr/bin/codesign")
        .args(["--verify", "--deep"])
        .arg(format!("-R={CHROME_REQUIREMENT}"))
        .arg("--")
        .arg(&app)
        .output()
        .map_err(|e| ChromeError::BadSignature(format!("codesign: {e}")))?;
    if !verify.status.success() {
        let stderr = String::from_utf8_lossy(&verify.stderr);
        // Mostra só a primeira linha e sem controles: a mensagem vai ao agente.
        let why: String = stderr
            .lines()
            .next()
            .unwrap_or("assinatura inválida")
            .chars()
            .filter(|c| !c.is_control())
            .take(200)
            .collect();
        return Err(ChromeError::BadSignature(format!(
            "não satisfaz o requisito da Google ({CHROME_BUNDLE_ID} / {CHROME_TEAM_ID}): {why}"
        )));
    }
    let team_id = CHROME_TEAM_ID.to_string();
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

    trait TapCreate {
        fn tap_create(self) -> PathBuf;
    }
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

    /// Monta um `.app` mínimo com o `Info.plist` do Chrome e um executável
    /// copiado de `/usr/bin/true`, assinado AD HOC com o identificador do Chrome.
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
        // Assinado (selo válido) e com o identificador do Chrome, mas ad hoc: o
        // requisito exige a âncora Apple e o Team ID da Google no certificado.
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
        // PoC da revisão: o nome do diretório injeta linhas `Identifier=` e
        // `TeamIdentifier=` falsas. Agora o caminho é recusado antes de qualquer
        // leitura, e o resultado nunca depende de texto da saída do codesign.
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
            assert!(!err.to_string().contains('\n'), "a mensagem não pode carregar a quebra de linha");
        }
        // Os outros controles também: TAB, CR, NUL (este nem chega ao sistema).
        for bad in ["a\tb", "a\rb", "a\u{7f}b", "a\u{85}b"] {
            let err = validate_chrome(Path::new(&format!("/Applications/{bad}.app"))).unwrap_err();
            assert!(matches!(err, ChromeError::UnsafePath(_)), "{bad:?}: {err:?}");
        }
        // Mesmo um bundle ad hoc num caminho limpo continua recusado (BadSignature).
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn r2_a_signed_copy_with_a_swapped_helper_is_refused() {
        let real = Path::new("/Applications/Google Chrome.app");
        if !real.is_dir() {
            eprintln!("Chrome não instalado: teste ignorado");
            return;
        }
        let dir = scratch("helper");
        let copy = dir.join("Google Chrome.app");
        // `cp -c` clona no APFS (instantâneo, sem copiar dados). Sem clone, pula.
        let cloned = std::process::Command::new("/bin/cp")
            .arg("-cR")
            .arg(real)
            .arg(&copy)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !cloned {
            eprintln!("clonefile indisponível: teste ignorado");
            let _ = std::fs::remove_dir_all(dir);
            return;
        }
        // Controle: a cópia intacta continua válida (assinatura da Google).
        let control = validate_chrome(&copy).expect("a cópia intacta satisfaz o requisito");
        assert_eq!(control.team_id, "EQHXZ8M8AV");
        // Troca o executável do Helper por um script que deixaria um marcador.
        let versions = copy.join("Contents/Frameworks/Google Chrome Framework.framework/Versions");
        let version = std::fs::read_dir(&versions)
            .unwrap()
            .filter_map(Result::ok)
            .find(|e| e.file_name() != "Current" && e.path().join("Helpers").is_dir())
            .expect("pasta de versão do framework")
            .path();
        let helper = version.join("Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper");
        assert!(helper.is_file(), "{}", helper.display());
        let marker = dir.join("helper-ran");
        std::fs::remove_file(&helper).unwrap();
        std::fs::write(&helper, format!("#!/bin/sh\ntouch {}\n", marker.display())).unwrap();
        make_executable(&helper);
        let err = validate_chrome(&copy).unwrap_err();
        assert!(matches!(err, ChromeError::BadSignature(_)), "{err:?}");
        // E também pelo binário principal.
        let err = validate_chrome(&copy.join("Contents/MacOS/Google Chrome")).unwrap_err();
        assert!(matches!(err, ChromeError::BadSignature(_)), "{err:?}");
        assert!(!marker.exists(), "o Helper trocado não pode ter rodado");
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
        // O que se executa é o caminho canônico, não o atalho dado.
        assert_eq!(first.binary, std::fs::canonicalize(&first.binary).unwrap());
        assert!(!first.binary.starts_with(&dir));
        // Troca o alvo do atalho por um bundle falso: a próxima chamada refaz a
        // verificação completa e recusa (sem cache entre chamadas).
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

    #[test]
    fn resolve_stable_chrome_never_substitutes_an_explicit_path() {
        let err = resolve_stable_chrome(Some(Path::new("/bin/echo"))).unwrap_err();
        assert_eq!(err.code(), "browser_invalid");
        #[cfg(target_os = "macos")]
        if Path::new("/Applications/Google Chrome.app").is_dir() {
            // Sem caminho explícito, acha o Chrome instalado e o valida.
            let found = resolve_stable_chrome(None).expect("Chrome instalado");
            assert!(found.binary.ends_with("Contents/MacOS/Google Chrome"));
        }
    }
}
