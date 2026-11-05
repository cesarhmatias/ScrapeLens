//! Command-line arguments for testing only, and for validating the initial URL.
//! Paths: absolute, regular file or directory, no symlinks.

use std::path::{Path, PathBuf};

/// Action requested on the command line (one per process).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliAction {
    ImportHar(PathBuf),
    ImportNetlog(PathBuf),
    OpenCapture(PathBuf),
}

/// Trimmed URL edges: Unicode whitespace (including U+0085) and the BOM U+FEFF.
/// Same set as `trimUrl` in `app/src/captureUrl.ts`.
pub fn trim_url(raw: &str) -> &str {
    raw.trim_matches(|c: char| c.is_whitespace() || c == '\u{FEFF}')
}

/// Maximum length of the initial URL (characters).
pub const MAX_URL_LEN: usize = 2048;

/// Validates the capture URL: empty → `about:blank`; otherwise only `http`/`https`.
pub fn resolve_capture_start_url(input: Option<&str>) -> Result<String, String> {
    let trimmed = trim_url(input.unwrap_or(""));
    if trimmed.is_empty() {
        return Ok("about:blank".to_string());
    }
    validate_http_url(trimmed)?;
    Ok(trimmed.to_string())
}

/// Invisible formatting characters (Unicode Cf) rejected in the URL.
/// The same list exists in `app/src/captureUrl.ts`; Rust is the authority.
pub fn is_invisible_format(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891 | 0x08E2
        | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F
        | 0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD | 0x13430..=0x1343F
        | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F)
}

/// Parts of an already validated http(s) URL.
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
        return Err("the initial URL only accepts http:// or https://".to_string());
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

/// Accepts only `http://` and `https://` with a host; rejects userinfo, spaces,
/// control characters, NUL, invisible characters (Cf) and more than 2048 characters.
pub fn validate_http_url(raw: &str) -> Result<(), String> {
    let trimmed = trim_url(raw);
    if trimmed.is_empty() {
        return Err("empty URL".to_string());
    }
    if trimmed.chars().count() > MAX_URL_LEN {
        return Err(format!("URL longer than {MAX_URL_LEN} characters"));
    }
    if trimmed.chars().any(|c| c == '\0' || c.is_control()) {
        return Err("URL cannot contain control characters".to_string());
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err("URL cannot contain spaces".to_string());
    }
    if trimmed.chars().any(is_invisible_format) {
        return Err("URL cannot contain invisible characters".to_string());
    }
    let parts = split_http_url(trimmed)?;
    if parts.authority.contains('@') {
        return Err("URL with user/password (user@host) is not accepted".to_string());
    }
    let host = if let Some(rest) = parts.authority.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return Err("malformed IPv6 host".to_string());
        };
        let tail = &rest[close + 1..];
        if !(tail.is_empty() || tail.starts_with(':')) {
            return Err("malformed IPv6 host".to_string());
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
        return Err("URL has no host".to_string());
    }
    Ok(())
}

fn validate_port(port: Option<&str>) -> Result<(), String> {
    match port {
        None => Ok(()),
        Some(p) if !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u32>().map(|n| n <= 65535).unwrap_or(false) => Ok(()),
        Some(_) => Err("invalid port in URL".to_string()),
    }
}

/// Persisted form of the initial URL: only scheme, host, port and path
/// (no query or fragment). The full URL is kept only in the session's memory.
pub fn persistable_url(raw: &str) -> Result<String, String> {
    let trimmed = trim_url(raw);
    validate_http_url(trimmed)?;
    let parts = split_http_url(trimmed)?;
    let cleaned = sanitize_persisted_path(parts.path);
    // Path with something redacted: store only the origin. Never store (or fill
    // into the field) a URL containing `[REDACTED]`, which Chrome would open.
    if cleaned != parts.path {
        return Ok(format!("{}{}", parts.scheme, parts.authority));
    }
    Ok(format!("{}{}{}", parts.scheme, parts.authority, parts.path))
}

/// Path written to disk (A9-B4): the core sanitizer (`;jsessionid=`, `token=`,
/// encoded forms) and, per segment, replaces with `[REDACTED]` whatever looks
/// like an opaque credential: encoded userinfo (`%40`/`%3A`) or a token of 16+
/// characters mixing letters and digits (`/reset/TOKEN`).
pub fn sanitize_persisted_path(path: &str) -> String {
    let options = scrapelens_core::export::sanitize::SanitizeOptions::default();
    let cleaned = scrapelens_core::export::sanitize::sanitize_path_and_query(path, &options);
    cleaned
        .split('/')
        .map(|segment| {
            let lower = segment.to_ascii_lowercase();
            let alnum: Vec<char> = segment.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
            let opaque = alnum.len() >= 16
                && alnum.iter().any(|c| c.is_ascii_digit())
                && alnum.iter().any(|c| c.is_ascii_alphabetic());
            if lower.contains("%40") || lower.contains("%3a") || opaque {
                options.placeholder.clone()
            } else {
                segment.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Result of reading the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliOutcome {
    None,
    Action(CliAction),
    /// Arguments ignored (without `SCRAPELENS_TEST_MODE=1`): warning for the window.
    Ignored(String),
    Error(String),
}

/// Enables the test CLI only with `SCRAPELENS_TEST_MODE=1`.
pub fn cli_outcome(args: &[String], test_mode: Option<&str>) -> CliOutcome {
    let has_flags = args.iter().skip(1).any(|a| a.starts_with("--"));
    if test_mode != Some("1") {
        return if has_flags {
            CliOutcome::Ignored(
                "command-line arguments ignored: the test CLI only works with SCRAPELENS_TEST_MODE=1"
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

/// Parses `args` (as from `std::env::args`, including argv[0]). At most one action.
/// Any other `--…` argument or positional argument is an error (except the macOS `-psn_…`).
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
                    "unknown argument: {other} (use --import-har, --import-netlog or --open-capture)"
                ));
            }
        };
        if found.is_some() {
            return Err("use only one of --import-har, --import-netlog or --open-capture".to_string());
        }
        found = Some(action);
    }
    Ok(found)
}

fn require_value<'a>(args: &'a [String], flag_index: usize, flag: &str) -> Result<&'a str, String> {
    args.get(flag_index + 1)
        .map(String::as_str)
        .filter(|value| !value.is_empty() && !value.starts_with('-'))
        .ok_or_else(|| format!("{flag} requires an absolute path"))
}

/// Absolute, without `..`/`.`, not the root, and no component (ancestors included) is a symlink.
fn check_path_components(path: &Path) -> Result<std::fs::Metadata, String> {
    use std::path::Component;
    if !path.is_absolute() {
        return Err(format!("path must be absolute: {}", path.display()));
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
                    .map_err(|error| format!("path inaccessible ({}): {error}", current.display()))?;
                if meta.file_type().is_symlink() {
                    return Err(format!("symlink refused: {}", current.display()));
                }
            }
            _ => return Err(format!("path with . or .. refused: {}", path.display())),
        }
    }
    if depth == 0 {
        return Err("the root / is not accepted".to_string());
    }
    std::fs::symlink_metadata(path)
        .map_err(|error| format!("path inaccessible ({}): {error}", path.display()))
}

pub fn validate_absolute_regular_file(path: &Path) -> Result<PathBuf, String> {
    let meta = check_path_components(path)?;
    if !meta.is_file() {
        return Err(format!("not a regular file: {}", path.display()));
    }
    Ok(path.to_path_buf())
}

pub fn validate_absolute_directory(path: &Path) -> Result<PathBuf, String> {
    let meta = check_path_components(path)?;
    if !meta.is_dir() {
        return Err(format!("not a directory: {}", path.display()));
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
        assert!(parse_cli_args(&rel).unwrap_err().contains("absolute"));

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
        assert!(parse_cli_args(&as_file).unwrap_err().contains("directory"));
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
        assert!(parse_cli_args(&args).unwrap_err().contains("only one"));
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
            assert!(validate_http_url(bad).is_err(), "should reject {bad:?}");
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
    fn persisted_path_is_sanitized() {
        for (input, secret) in [
            ("https://h/app;jsessionid=ABC123/x", "ABC123"),
            ("https://h/reset/SECRETTOKEN1234567890", "SECRETTOKEN1234567890"),
            ("https://h/go/user%3Apw%40h", "pw"),
        ] {
            let out = persistable_url(input).unwrap();
            assert!(!out.contains(secret), "{input} -> {out}");
            assert_eq!(out, "https://h", "only the origin when something was redacted");
        }
        assert_eq!(persistable_url("https://h/docs/page-2").unwrap(), "https://h/docs/page-2");
    }

    #[test]
    fn url_edges_trim_nel_and_bom_like_ts() {
        // Non-ASCII input under test: U+0085 (NEL) and U+FEFF (BOM) must be trimmed at the edges.
        for raw in ["\u{0085}http://h/a", "http://h/a\u{0085}", "\u{FEFF}http://h/a", "http://h/a\u{FEFF}"] {
            assert_eq!(resolve_capture_start_url(Some(raw)).unwrap(), "http://h/a", "{raw:?}");
        }
        assert!(validate_http_url("http://h\u{FEFF}/a").is_err());
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
        assert!(parse_cli_args(&unknown).unwrap_err().contains("unknown"));
        let root: Vec<String> = vec!["scrapelens".into(), "--open-capture".into(), "/".into()];
        assert!(parse_cli_args(&root).unwrap_err().contains("root"));

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
