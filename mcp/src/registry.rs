//! Open sessions: handle resolution, cache, original and masked views.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

use scrapelens_core::export::sanitize::{sanitize_bundle_owned, SanitizeOptions};
use scrapelens_core::lazy::LazySession;
use scrapelens_core::search::{BodySource, LazyBodies, Loaded};
use scrapelens_core::{SessionBundle, SessionV1};

use crate::config::{is_within, valid_name, Config};
use crate::error::ToolError;

/// Body read limit (the same as the core search).
pub const BODY_READ_LIMIT: u64 = scrapelens_core::lazy::BODY_READ_LIMIT;

pub struct Entry {
    pub handle: String,
    pub dir: PathBuf,
    pub read_only: bool,
    pub lazy: LazySession,
    stamp: (SystemTime, u64),
    masked: OnceLock<Result<SessionBundle, (&'static str, String)>>,
}

impl Entry {
    /// Sanitized copy (eager), computed once per session.
    pub fn masked(&self) -> Result<&SessionBundle, ToolError> {
        let result = self.masked.get_or_init(|| {
            let imported = scrapelens_core::import_session_dir(&self.dir).map_err(|error| {
                let code = if matches!(error, scrapelens_core::CoreError::LimitExceeded { .. }) {
                    "too_large"
                } else {
                    "io"
                };
                (
                    code,
                    format!("could not load the session to mask it: {error}"),
                )
            })?;
            // Consumes the imported bundle: without a copy of the session (docs/18 P7).
            Ok(sanitize_bundle_owned(imported.bundle, &SanitizeOptions::default()).bundle)
        });
        result
            .as_ref()
            .map_err(|(code, message)| ToolError::new(code, message.clone()))
    }
}

/// Source of the body bytes of a view.
pub enum Src<'a> {
    Lazy(LazyBodies<'a>),
    Bundle(&'a SessionBundle),
}

impl BodySource for Src<'_> {
    fn load(&self, name: &str) -> Option<Loaded<'_>> {
        match self {
            Src::Lazy(lazy) => lazy.load(name),
            Src::Bundle(bundle) => bundle.load(name),
        }
    }
}

/// View of a session: original (`reveal`) or masked.
pub struct View<'a> {
    pub entry: &'a Entry,
    pub session: &'a SessionV1,
    bundle: Option<&'a SessionBundle>,
    pub masked: bool,
}

impl<'a> View<'a> {
    pub fn original(entry: &'a Entry) -> Self {
        Self {
            entry,
            session: &entry.lazy.session,
            bundle: None,
            masked: false,
        }
    }

    pub fn masked(entry: &'a Entry) -> Result<Self, ToolError> {
        let bundle = entry.masked()?;
        Ok(Self {
            entry,
            session: &bundle.session,
            bundle: Some(bundle),
            masked: true,
        })
    }

    /// The same request in the original session (metadata the mask removes).
    pub fn original_request(&self, id: &str) -> Option<&scrapelens_core::model::LogicalRequest> {
        self.entry.lazy.session.find_request(id)
    }

    pub fn source(&self) -> Src<'_> {
        match self.bundle {
            Some(bundle) => Src::Bundle(bundle),
            None => Src::Lazy(LazyBodies(&self.entry.lazy)),
        }
    }

    /// Up to `limit` bytes of the attachment; `true` = there was more.
    pub fn read_attachment(&self, name: &str, limit: u64) -> Option<(Vec<u8>, bool)> {
        match self.bundle {
            Some(bundle) => bundle.attachment(name).map(|bytes| {
                let cut = bytes.len() as u64 > limit;
                (bytes[..bytes.len().min(limit as usize)].to_vec(), cut)
            }),
            None => self.entry.lazy.read_attachment(name, limit).ok(),
        }
    }
}

pub struct Ctx {
    pub cfg: Config,
    cache: Mutex<HashMap<String, Arc<Entry>>>,
}

impl Ctx {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn check_reveal(&self, reveal: bool) -> Result<(), ToolError> {
        if reveal && !self.cfg.allow_reveal {
            return Err(ToolError::new(
                "reveal_disabled",
                "reveal=true requires starting the server with --allow-reveal",
            ));
        }
        Ok(())
    }

    /// Known handles → (directory, read-only). `sessions_dir` wins
    /// collisions with the extra directories.
    pub fn handles(&self) -> BTreeMap<String, (PathBuf, bool)> {
        let mut found = BTreeMap::new();
        let roots = std::iter::once((&self.cfg.sessions_dir, false))
            .chain(self.cfg.extra_dirs.iter().map(|dir| (dir, true)));
        for (root, read_only) in roots {
            let Ok(entries) = std::fs::read_dir(root) else {
                continue;
            };
            for entry in entries.flatten() {
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                if !valid_name(&name) {
                    continue;
                }
                let path = entry.path();
                // `session.json` must be a regular file (never a symlink).
                if !std::fs::symlink_metadata(path.join("session.json"))
                    .map(|meta| meta.file_type().is_file())
                    .unwrap_or(false)
                {
                    continue;
                }
                let Ok(canonical) = path.canonicalize() else {
                    continue;
                };
                if !is_within(root, &canonical) {
                    continue;
                }
                found.entry(name).or_insert_with(|| (canonical, read_only));
            }
        }
        found
    }

    pub fn open(&self, handle: &str) -> Result<Arc<Entry>, ToolError> {
        if !valid_name(handle) {
            return Err(ToolError::invalid(format!(
                "invalid session_id: {handle:?} (use the id returned by list_sessions)"
            )));
        }
        let handles = self.handles();
        let Some((dir, read_only)) = handles.get(handle) else {
            return Err(ToolError::not_found(format!(
                "session {handle:?} not found (use list_sessions)"
            )));
        };
        let meta = std::fs::metadata(dir.join("session.json"))
            .map_err(|error| ToolError::new("io", format!("{handle}: {error}")))?;
        let stamp = (
            meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            meta.len(),
        );
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = cache.get(handle) {
            if entry.stamp == stamp && &entry.dir == dir {
                return Ok(entry.clone());
            }
        }
        let (lazy, _report) = scrapelens_core::open_session_dir_lazy(dir)
            .map_err(|error| ToolError::new("io", format!("{handle}: {error}")))?;
        let entry = Arc::new(Entry {
            handle: handle.to_string(),
            dir: dir.clone(),
            read_only: *read_only,
            lazy,
            stamp,
            masked: OnceLock::new(),
        });
        cache.insert(handle.to_string(), entry.clone());
        Ok(entry)
    }
}
