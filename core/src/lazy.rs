//! Session with lazy attachments.
//!
//! [`LazySession`] keeps only the model (metadata); the bytes of each attachment are
//! read by name when needed and discarded afterwards. It serves search over
//! large sessions without keeping all bodies in memory:
//!
//! ```text
//! let (lazy, report) = open_session_dir_lazy(dir)?;      // session.json only
//! let found = search_lazy(&lazy, &SearchQuery::new("x")); // 1 body at a time
//! let bundle = lazy.into_bundle()?;                       // if you need everything
//! ```
//!
//! Reading refuses symlinks (directory and file), requires a regular file, and reads at
//! most [`BODY_READ_LIMIT`] bytes per body. `import_session_dir` remains
//! the eager API (export, sanitize and tests).

use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::model::{SessionBundle, SessionV1};
use crate::store;

/// Byte limit read per body in the search (contract: 5 MiB per body).
pub const BODY_READ_LIMIT: u64 = 5 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct LazySession {
    pub session: SessionV1,
    dir: PathBuf,
}

impl LazySession {
    pub fn new(session: SessionV1, dir: PathBuf) -> Self {
        Self { session, dir }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Reads an attachment (up to `limit` bytes). `true` = the file was larger than the limit.
    pub fn read_attachment(&self, name: &str, limit: u64) -> Result<(Vec<u8>, bool)> {
        store::read_attachment_limited(&self.dir, name, limit)
    }

    /// Loads everything into memory (equivalent to the eager bundle, without raw
    /// cdp/netlog), respecting the limits of `import_session_dir`.
    pub fn into_bundle(self) -> Result<SessionBundle> {
        Ok(crate::parse::own::import_session_dir(&self.dir)?.bundle)
    }
}
