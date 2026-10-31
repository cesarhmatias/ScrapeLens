//! Sessões abertas: resolução de handles, cache, visão original e mascarada.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

use scrapelens_core::export::sanitize::{sanitize_bundle, SanitizeOptions};
use scrapelens_core::lazy::LazySession;
use scrapelens_core::search::{BodySource, LazyBodies, Loaded};
use scrapelens_core::{SessionBundle, SessionV1};

use crate::config::{is_within, valid_name, Config};
use crate::error::ToolError;

/// Limite de leitura de um corpo (o mesmo da busca do core).
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
    /// Cópia sanitizada (eager), calculada uma vez por sessão.
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
                    format!("não foi possível carregar a sessão para mascarar: {error}"),
                )
            })?;
            Ok(sanitize_bundle(&imported.bundle, &SanitizeOptions::default()).bundle)
        });
        result
            .as_ref()
            .map_err(|(code, message)| ToolError::new(code, message.clone()))
    }
}

/// Origem dos bytes de corpo de uma visão.
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

/// Visão de uma sessão: original (`reveal`) ou mascarada.
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

    /// A mesma requisição na sessão original (metadados que a máscara apaga).
    pub fn original_request(&self, id: &str) -> Option<&scrapelens_core::model::LogicalRequest> {
        self.entry.lazy.session.find_request(id)
    }

    pub fn source(&self) -> Src<'_> {
        match self.bundle {
            Some(bundle) => Src::Bundle(bundle),
            None => Src::Lazy(LazyBodies(&self.entry.lazy)),
        }
    }

    /// Até `limit` bytes do anexo; `true` = havia mais.
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
    value_queries: Mutex<HashMap<String, u32>>,
}

/// Teto de consultas `trace_value(value)` sem reveal por sessão, na vida do servidor.
pub const MAX_VALUE_QUERIES: u32 = 50;

impl Ctx {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            cache: Mutex::new(HashMap::new()),
            value_queries: Mutex::new(HashMap::new()),
        }
    }

    /// Conta uma consulta de valor inteiro sem reveal; recusa depois do teto.
    pub fn charge_value_query(&self, handle: &str) -> Result<(), ToolError> {
        let mut map = self.value_queries.lock().unwrap_or_else(|e| e.into_inner());
        let used = map.entry(handle.to_string()).or_insert(0);
        if *used >= MAX_VALUE_QUERIES {
            return Err(ToolError::new(
                "value_query_limit",
                format!("limite de {MAX_VALUE_QUERIES} consultas por valor sem reveal nesta sessão atingido"),
            ));
        }
        *used += 1;
        Ok(())
    }

    pub fn check_reveal(&self, reveal: bool) -> Result<(), ToolError> {
        if reveal && !self.cfg.allow_reveal {
            return Err(ToolError::new(
                "reveal_disabled",
                "reveal=true exige iniciar o servidor com --allow-reveal",
            ));
        }
        Ok(())
    }

    /// Handles conhecidos → (diretório, somente leitura). `sessions_dir` vence
    /// colisões com os diretórios extras.
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
                // `session.json` precisa ser arquivo regular (nunca symlink).
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
                "session_id inválido: {handle:?} (use o id devolvido por list_sessions)"
            )));
        }
        let handles = self.handles();
        let Some((dir, read_only)) = handles.get(handle) else {
            return Err(ToolError::not_found(format!(
                "sessão {handle:?} não encontrada (use list_sessions)"
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
