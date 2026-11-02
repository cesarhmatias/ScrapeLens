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

/// Valida URL de captura: vazia → `about:blank`; senão só `http`/`https`.
pub fn resolve_capture_start_url(input: Option<&str>) -> Result<String, String> {
    let trimmed = input.unwrap_or("").trim();
    if trimmed.is_empty() {
        return Ok("about:blank".to_string());
    }
    validate_http_url(trimmed)?;
    Ok(trimmed.to_string())
}

/// Aceita só `http://` e `https://` (sem espaços, sem outros esquemas).
pub fn validate_http_url(raw: &str) -> Result<(), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("URL vazia".to_string());
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err("URL não pode conter espaços".to_string());
    }
    let lower = trimmed.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return Err("a URL inicial aceita só http:// ou https://".to_string());
    }
    if trimmed.len() <= "http://".len()
        || (lower.starts_with("https://") && trimmed.len() <= "https://".len())
    {
        return Err("URL incompleta".to_string());
    }
    Ok(())
}

/// Interpreta `args` (como `std::env::args`, incluindo argv[0]). No máximo uma ação.
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
            other if other.starts_with("--import-") || other == "--open-capture" => {
                return Err(format!("flag desconhecida ou incompleta: {other}"));
            }
            _ => {
                i += 1;
                continue;
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

pub fn validate_absolute_regular_file(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!("caminho deve ser absoluto: {}", path.display()));
    }
    let meta = std::fs::symlink_metadata(path)
        .map_err(|error| format!("caminho inacessível ({}): {error}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!("symlink recusado: {}", path.display()));
    }
    if !meta.is_file() {
        return Err(format!("não é um arquivo regular: {}", path.display()));
    }
    Ok(path.to_path_buf())
}

pub fn validate_absolute_directory(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!("caminho deve ser absoluto: {}", path.display()));
    }
    let meta = std::fs::symlink_metadata(path)
        .map_err(|error| format!("caminho inacessível ({}): {error}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!("symlink recusado: {}", path.display()));
    }
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
        let root = std::env::temp_dir().join(format!("scrapelens-{}", tmp_tag()));
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
        let root = std::env::temp_dir().join(format!("scrapelens-open-{}", tmp_tag()));
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
        let root = std::env::temp_dir().join(format!("scrapelens-two-{}", tmp_tag()));
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
}
