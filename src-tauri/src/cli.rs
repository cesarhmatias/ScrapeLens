//! Argumentos de linha de comando só para testes e validação da URL inicial.
//! Caminhos: absolutos, arquivo/diretório regular, sem symlink.

use std::path::{Path, PathBuf};

/// Ação pedida na linha de comando (uma por processo).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliAction {
    ImportHar(PathBuf),
    ImportNetlog(PathBuf),
    OpenCapture(PathBuf),
}

/// Tamanho máximo da URL inicial (caracteres).
pub const MAX_URL_LEN: usize = 2048;

/// Valida URL de captura: vazia → `about:blank`; senão só `http`/`https`.
pub fn resolve_capture_start_url(input: Option<&str>) -> Result<String, String> {
    let trimmed = input.unwrap_or("").trim();
    if trimmed.is_empty() {
        return Ok("about:blank".to_string());
    }
    validate_http_url(trimmed)?;
    Ok(trimmed.to_string())
}

/// Caracteres de formatação invisíveis (Unicode Cf) recusados na URL.
/// A mesma lista existe em `app/src/captureUrl.ts`; o Rust é a autoridade.
pub fn is_invisible_format(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891 | 0x08E2
        | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F
        | 0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD | 0x13430..=0x1343F
        | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F)
}

/// Partes de uma URL http(s) já validada.
struct UrlParts<'a> {
    scheme: &'a str,
    authority: &'a str,
    path: &'a str,
}

fn split_http_url(trimmed: &str) -> Result<UrlParts<'_>, String> {
    let lower = trimmed.to_ascii_lowercase();
    let scheme_len = if lower.starts_with("http://") {
        "http://".len()
    } else if lower.starts_with("https://") {
        "https://".len()
    } else {
        return Err("a URL inicial aceita só http:// ou https://".to_string());
    };
    let rest = &trimmed[scheme_len..];
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    let after = &rest[auth_end..];
    let path_end = after.find(['?', '#']).unwrap_or(after.len());
    Ok(UrlParts {
        scheme: &trimmed[..scheme_len],
        authority,
        path: &after[..path_end],
    })
}

/// Aceita só `http://` e `https://` com host; recusa userinfo, espaços,
/// controles, NUL, caracteres invisíveis (Cf) e mais de 2048 caracteres.
pub fn validate_http_url(raw: &str) -> Result<(), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("URL vazia".to_string());
    }
    if trimmed.chars().count() > MAX_URL_LEN {
        return Err(format!("URL maior que {MAX_URL_LEN} caracteres"));
    }
    if trimmed.chars().any(|c| c == '\0' || c.is_control()) {
        return Err("URL não pode conter caracteres de controle".to_string());
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err("URL não pode conter espaços".to_string());
    }
    if trimmed.chars().any(is_invisible_format) {
        return Err("URL não pode conter caracteres invisíveis".to_string());
    }
    let parts = split_http_url(trimmed)?;
    if parts.authority.contains('@') {
        return Err("URL com usuário/senha (user@host) não é aceita".to_string());
    }
    let host = if let Some(rest) = parts.authority.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return Err("host IPv6 malformado".to_string());
        };
        let tail = &rest[close + 1..];
        if !(tail.is_empty() || tail.starts_with(':')) {
            return Err("host IPv6 malformado".to_string());
        }
        validate_port(tail.strip_prefix(':'))?;
        &rest[..close]
    } else {
        let (host, port) = match parts.authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (parts.authority, None),
        };
        validate_port(port)?;
        host
    };
    if host.is_empty() {
        return Err("URL sem host".to_string());
    }
    Ok(())
}

fn validate_port(port: Option<&str>) -> Result<(), String> {
    match port {
        None => Ok(()),
        Some(p) if !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u32>().map(|n| n <= 65535).unwrap_or(false) => Ok(()),
        Some(_) => Err("porta inválida na URL".to_string()),
    }
}

/// Forma persistida da URL inicial: só esquema, host, porta e caminho
/// (sem query nem fragmento). A URL completa vale só na memória da sessão.
pub fn persistable_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    validate_http_url(trimmed)?;
    let parts = split_http_url(trimmed)?;
    Ok(format!("{}{}{}", parts.scheme, parts.authority, parts.path))
}

/// Resultado da leitura da linha de comando.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliOutcome {
    None,
    Action(CliAction),
    /// Argumentos ignorados (sem `SCRAPELENS_TEST_MODE=1`): aviso para a janela.
    Ignored(String),
    Error(String),
}

/// Liga a CLI de teste só com `SCRAPELENS_TEST_MODE=1`.
pub fn cli_outcome(args: &[String], test_mode: Option<&str>) -> CliOutcome {
    let has_flags = args.iter().skip(1).any(|a| a.starts_with("--"));
    if test_mode != Some("1") {
        return if has_flags {
            CliOutcome::Ignored(
                "argumentos de linha de comando ignorados: a CLI de teste só funciona com SCRAPELENS_TEST_MODE=1"
                    .to_string(),
            )
        } else {
            CliOutcome::None
        };
    }
    match parse_cli_args(args) {
        Ok(Some(action)) => CliOutcome::Action(action),
        Ok(None) => CliOutcome::None,
        Err(error) => CliOutcome::Error(error),
    }
}

/// Interpreta `args` (como `std::env::args`, incluindo argv[0]). No máximo uma ação.
/// Qualquer outro argumento `--…` ou posicional é erro (exceto `-psn_…` do macOS).
pub fn parse_cli_args(args: &[String]) -> Result<Option<CliAction>, String> {
    let mut i = 1usize;
    let mut found: Option<CliAction> = None;
    while i < args.len() {
        let flag = args[i].as_str();
        let action = match flag {
            "--import-har" => {
                let path = require_value(args, i, flag)?;
                i += 2;
                CliAction::ImportHar(validate_absolute_regular_file(Path::new(path))?)
            }
            "--import-netlog" => {
                let path = require_value(args, i, flag)?;
                i += 2;
                CliAction::ImportNetlog(validate_absolute_regular_file(Path::new(path))?)
            }
            "--open-capture" => {
                let path = require_value(args, i, flag)?;
                i += 2;
                CliAction::OpenCapture(validate_absolute_directory(Path::new(path))?)
            }
            other if other.starts_with("-psn_") => {
                i += 1;
                continue;
            }
            other => {
                return Err(format!(
                    "argumento desconhecido: {other} (use --import-har, --import-netlog ou --open-capture)"
                ));
            }
        };
        if found.is_some() {
            return Err("use só um de --import-har, --import-netlog ou --open-capture".to_string());
        }
        found = Some(action);
    }
    Ok(found)
}

fn require_value<'a>(args: &'a [String], flag_index: usize, flag: &str) -> Result<&'a str, String> {
    args.get(flag_index + 1)
        .map(String::as_str)
        .filter(|value| !value.is_empty() && !value.starts_with('-'))
        .ok_or_else(|| format!("{flag} exige um caminho absoluto"))
}

/// Absoluto, sem `..`/`.`, não a raiz, e nenhum componente (inclusive ancestrais) é symlink.
fn check_path_components(path: &Path) -> Result<std::fs::Metadata, String> {
    use std::path::Component;
    if !path.is_absolute() {
        return Err(format!("caminho deve ser absoluto: {}", path.display()));
    }
    let mut current = PathBuf::from("/");
    let mut depth = 0usize;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                current.push(name);
                depth += 1;
                let meta = std::fs::symlink_metadata(&current)
                    .map_err(|error| format!("caminho inacessível ({}): {error}", current.display()))?;
                if meta.file_type().is_symlink() {
                    return Err(format!("symlink recusado: {}", current.display()));
                }
            }
            _ => return Err(format!("caminho com . ou .. recusado: {}", path.display())),
        }
    }
    if depth == 0 {
        return Err("a raiz / não é aceita".to_string());
    }
    std::fs::symlink_metadata(path)
        .map_err(|error| format!("caminho inacessível ({}): {error}", path.display()))
}

pub fn validate_absolute_regular_file(path: &Path) -> Result<PathBuf, String> {
    let meta = check_path_components(path)?;
    if !meta.is_file() {
        return Err(format!("não é um arquivo regular: {}", path.display()));
    }
    Ok(path.to_path_buf())
}

pub fn validate_absolute_directory(path: &Path) -> Result<PathBuf, String> {
    let meta = check_path_components(path)?;
    if !meta.is_dir() {
        return Err(format!("não é um diretório: {}", path.display()));
    }
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn base_tmp() -> PathBuf {
        fs::canonicalize(std::env::temp_dir()).unwrap()
    }

    fn tmp_tag() -> String {
        format!(
            "cli-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        )
    }

    #[test]
    fn empty_url_becomes_about_blank() {
        assert_eq!(resolve_capture_start_url(None).unwrap(), "about:blank");
        assert_eq!(resolve_capture_start_url(Some("  ")).unwrap(), "about:blank");
    }

    #[test]
    fn http_and_https_urls_are_accepted() {
        assert_eq!(
            resolve_capture_start_url(Some("http://127.0.0.1:8781/page")).unwrap(),
            "http://127.0.0.1:8781/page"
        );
        assert!(validate_http_url("https://example.com/a").is_ok());
    }

    #[test]
    fn non_http_schemes_and_junk_are_rejected() {
        assert!(validate_http_url("about:blank").is_err());
        assert!(validate_http_url("file:///tmp/x").is_err());
        assert!(validate_http_url("javascript:alert(1)").is_err());
        assert!(validate_http_url("http:// spaced").is_err());
        assert!(validate_http_url("http://").is_err());
        assert!(resolve_capture_start_url(Some("ftp://x")).is_err());
    }

    #[test]
    fn parse_requires_absolute_regular_file_without_symlink() {
        let root = base_tmp().join(format!("scrapelens-{}", tmp_tag()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let file = root.join("sample.har");
        fs::write(&file, b"{}").unwrap();
        let link = root.join("link.har");
        symlink(&file, &link).unwrap();

        let abs = file.display().to_string();
        let args = vec![
            "scrapelens".into(),
            "--import-har".into(),
            abs.clone(),
        ];
        assert_eq!(
            parse_cli_args(&args).unwrap(),
            Some(CliAction::ImportHar(file.clone()))
        );

        let rel = vec!["scrapelens".into(), "--import-har".into(), "relative.har".into()];
        assert!(parse_cli_args(&rel).unwrap_err().contains("absoluto"));

        let linked = vec![
            "scrapelens".into(),
            "--import-netlog".into(),
            link.display().to_string(),
        ];
        assert!(parse_cli_args(&linked).unwrap_err().contains("symlink"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn parse_open_capture_requires_absolute_directory() {
        let root = base_tmp().join(format!("scrapelens-open-{}", tmp_tag()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let args = vec![
            "scrapelens".into(),
            "--open-capture".into(),
            root.display().to_string(),
        ];
        assert_eq!(
            parse_cli_args(&args).unwrap(),
            Some(CliAction::OpenCapture(root.clone()))
        );
        let file = root.join("x.json");
        fs::write(&file, b"{}").unwrap();
        let as_file = vec![
            "scrapelens".into(),
            "--open-capture".into(),
            file.display().to_string(),
        ];
        assert!(parse_cli_args(&as_file).unwrap_err().contains("diretório"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn parse_rejects_two_actions() {
        let root = base_tmp().join(format!("scrapelens-two-{}", tmp_tag()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let file = root.join("a.har");
        fs::write(&file, b"{}").unwrap();
        let args = vec![
            "scrapelens".into(),
            "--import-har".into(),
            file.display().to_string(),
            "--open-capture".into(),
            root.display().to_string(),
        ];
        assert!(parse_cli_args(&args).unwrap_err().contains("só um"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn url_rejects_userinfo_controls_invisible_empty_host_and_long() {
        for bad in [
            "http://user:pw@example.com/",
            "http://user@example.com",
            "http://@",
            "http:///",
            "http://:80/",
            "http://exa\u{0}mple.com",
            "http://exa\u{7}mple.com",
            "http://exa\u{200B}mple.com",
            "http://\u{FEFF}example.com",
            "http://example.com:99999/",
            "http://[::1/",
        ] {
            assert!(validate_http_url(bad).is_err(), "deveria recusar {bad:?}");
        }
        let long = format!("http://e.com/{}", "a".repeat(MAX_URL_LEN));
        assert!(validate_http_url(&long).unwrap_err().contains("2048"));
        assert!(validate_http_url("http://[::1]:8080/x").is_ok());
        assert!(validate_http_url("https://example.com:443/a?b=1#c").is_ok());
    }

    #[test]
    fn persisted_url_drops_query_and_fragment() {
        assert_eq!(
            persistable_url("https://example.com:8443/a/b?token=SECRET#frag").unwrap(),
            "https://example.com:8443/a/b"
        );
        assert_eq!(persistable_url("http://h?x=1").unwrap(), "http://h");
        assert!(persistable_url("http://u:p@h/").is_err());
    }

    #[test]
    fn cli_requires_test_mode_env() {
        let args: Vec<String> = vec!["scrapelens".into(), "--import-har".into(), "/x.har".into()];
        assert!(matches!(cli_outcome(&args, None), CliOutcome::Ignored(_)));
        assert!(matches!(cli_outcome(&args, Some("0")), CliOutcome::Ignored(_)));
        assert!(matches!(cli_outcome(&args, Some("1")), CliOutcome::Error(_)));
        assert_eq!(cli_outcome(&["scrapelens".into()], None), CliOutcome::None);
    }

    #[test]
    fn cli_rejects_unknown_flag_root_and_symlinked_ancestor() {
        let unknown: Vec<String> = vec!["scrapelens".into(), "--bogus".into()];
        assert!(parse_cli_args(&unknown).unwrap_err().contains("desconhecido"));
        let root: Vec<String> = vec!["scrapelens".into(), "--open-capture".into(), "/".into()];
        assert!(parse_cli_args(&root).unwrap_err().contains("raiz"));

        let base = base_tmp().join(format!("scrapelens-anc-{}", tmp_tag()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("real")).unwrap();
        fs::write(base.join("real/a.har"), b"{}").unwrap();
        symlink(base.join("real"), base.join("alias")).unwrap();
        let via_link: Vec<String> = vec![
            "scrapelens".into(),
            "--import-har".into(),
            base.join("alias/a.har").display().to_string(),
        ];
        assert!(parse_cli_args(&via_link).unwrap_err().contains("symlink"));
        let dotdot: Vec<String> = vec![
            "scrapelens".into(),
            "--import-har".into(),
            base.join("real/../real/a.har").display().to_string(),
        ];
        assert!(parse_cli_args(&dotdot).is_err());
        let _ = fs::remove_dir_all(&base);
    }
}
