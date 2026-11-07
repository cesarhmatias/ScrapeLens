//! Paths the webview may hand back to the backend (T17).
//!
//! The backend issues an opaque token for a path it chose itself: a session folder it opened
//! or wrote, a file it saved, a folder the user picked in the native dialog. The commands that
//! act on a path (`read_body`, `reveal_path`, `open_session` with a token) take the token, never
//! the path. A webview that invents a path, or sends a token of another kind, is refused before
//! any file is read or any program is started.
//!
//! The registry is process-wide because session payloads are built in several places, and each
//! one issues its own token. The same path and kind always get the same token.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// What a token may be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A session folder (or a session file): `read_body`, `open_session`, `reveal_path`.
    Session,
    /// A file the export wrote (0600): `reveal_path`.
    SavedFile,
    /// A file the user chose to import (HAR, NetLog, or an execution trace).
    ImportFile,
}

/// More distinct grants than this in one run are refused. No real use reaches it.
const MAX_GRANTS: usize = 4096;

#[derive(Default)]
pub(crate) struct Registry {
    by_token: HashMap<String, (Kind, PathBuf)>,
    by_path: HashMap<(Kind, PathBuf), String>,
}

impl Registry {
    /// Token for `path` of `kind`, issued once; refused when `max` distinct grants exist.
    pub(crate) fn issue(&mut self, kind: Kind, path: &Path, max: usize) -> Result<String, String> {
        let key = (kind, path.to_path_buf());
        if let Some(token) = self.by_path.get(&key) {
            return Ok(token.clone());
        }
        if self.by_token.len() >= max {
            return Err(
                "too many files and folders were used in this run; restart ScrapeLens".to_string(),
            );
        }
        let token = new_token()?;
        self.by_token.insert(token.clone(), key.clone());
        self.by_path.insert(key, token.clone());
        Ok(token)
    }

    /// The path behind `token`, when it was issued for one of `allowed` kinds. A path, an
    /// unknown token or a token of another kind is refused.
    pub(crate) fn resolve(&self, token: &str, allowed: &[Kind]) -> Result<PathBuf, String> {
        match self.by_token.get(token) {
            Some((kind, path)) if allowed.contains(kind) => Ok(path.clone()),
            _ => Err(
                "this file or folder is not available to ScrapeLens; choose it again".to_string(),
            ),
        }
    }
}

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Registry::default()))
}

/// Token for a path the backend chose (see the module comment).
pub fn issue(kind: Kind, path: &Path) -> Result<String, String> {
    let mut registry = registry()
        .lock()
        .map_err(|_| "file registry unavailable".to_string())?;
    registry.issue(kind, path, MAX_GRANTS)
}

/// The path behind a token that was issued for one of `allowed` kinds.
pub fn resolve(token: &str, allowed: &[Kind]) -> Result<PathBuf, String> {
    let registry = registry()
        .lock()
        .map_err(|_| "file registry unavailable".to_string())?;
    registry.resolve(token, allowed)
}

/// 128 random bits from the kernel, as 32 hex characters.
fn new_token() -> Result<String, String> {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| format!("cannot create a token: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(name: &str) -> PathBuf {
        PathBuf::from(format!("/granted/{name}"))
    }

    #[test]
    fn a_token_resolves_to_its_path_for_its_kind() {
        let mut reg = Registry::default();
        let token = reg.issue(Kind::Session, &path("s1"), 10).unwrap();
        assert_eq!(reg.resolve(&token, &[Kind::Session]).unwrap(), path("s1"));
    }

    #[test]
    fn a_path_or_an_unknown_token_is_refused() {
        let mut reg = Registry::default();
        reg.issue(Kind::Session, &path("s1"), 10).unwrap();
        assert!(
            reg.resolve("/granted/s1", &[Kind::Session]).is_err(),
            "a path is not a token"
        );
        assert!(reg.resolve("", &[Kind::Session]).is_err(), "an empty token");
        assert!(
            reg.resolve("00000000000000000000000000000000", &[Kind::Session])
                .is_err(),
            "an invented token"
        );
    }

    #[test]
    fn a_token_of_another_kind_is_refused() {
        let mut reg = Registry::default();
        let session = reg.issue(Kind::Session, &path("s1"), 10).unwrap();
        let saved = reg.issue(Kind::SavedFile, &path("f1"), 10).unwrap();
        assert!(reg.resolve(&session, &[Kind::SavedFile]).is_err());
        assert!(reg.resolve(&saved, &[Kind::Session]).is_err());
        assert_eq!(
            reg.resolve(&saved, &[Kind::Session, Kind::SavedFile])
                .unwrap(),
            path("f1")
        );
    }

    #[test]
    fn the_same_path_and_kind_get_the_same_token_and_different_paths_differ() {
        let mut reg = Registry::default();
        let first = reg.issue(Kind::Session, &path("s1"), 10).unwrap();
        let again = reg.issue(Kind::Session, &path("s1"), 10).unwrap();
        let other = reg.issue(Kind::Session, &path("s2"), 10).unwrap();
        assert_eq!(first, again);
        assert_ne!(first, other);
        assert_eq!(first.len(), 32);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn a_new_grant_is_refused_once_the_limit_is_reached_but_known_ones_still_work() {
        let mut reg = Registry::default();
        let known = reg.issue(Kind::Session, &path("s1"), 1).unwrap();
        assert!(reg.issue(Kind::Session, &path("s2"), 1).is_err());
        assert_eq!(reg.issue(Kind::Session, &path("s1"), 1).unwrap(), known);
    }
}
