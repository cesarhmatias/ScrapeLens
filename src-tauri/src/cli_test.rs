//! Test-only command-line actions (`--import-har`, `--import-netlog`, `--open-capture`).
//! Compiled only with the `test-hooks` feature: release builds have no command-line
//! test surface. Paths go through the same checks as the rest of the App.

use std::path::{Path, PathBuf};

use crate::cli::{validate_absolute_directory, validate_absolute_regular_file};

/// Action requested on the command line (one per process).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliAction {
    ImportHar(PathBuf),
    ImportNetlog(PathBuf),
    OpenCapture(PathBuf),
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
