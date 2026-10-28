//! Sessão com anexos preguiçosos.
//!
//! [`LazySession`] guarda só o modelo (metadados); os bytes de cada anexo são
//! lidos por nome quando necessário e descartados em seguida. Serve a busca em
//! sessões grandes sem manter todos os corpos em memória:
//!
//! ```text
//! let (lazy, report) = open_session_dir_lazy(dir)?;      // só session.json
//! let found = search_lazy(&lazy, &SearchQuery::new("x")); // 1 corpo por vez
//! let bundle = lazy.into_bundle()?;                       // se precisar de tudo
//! ```
//!
//! A leitura recusa symlink (pasta e arquivo), exige arquivo regular e lê no
//! máximo [`BODY_READ_LIMIT`] bytes por corpo. `import_session_dir` continua
//! sendo a API eager (export, sanitize e testes).

use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::model::{SessionBundle, SessionV1};
use crate::store;

/// Limite de bytes lidos por corpo na busca (contrato: 5 MiB por corpo).
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

    /// Lê um anexo (até `limit` bytes). `true` = o arquivo era maior que o limite.
    pub fn read_attachment(&self, name: &str, limit: u64) -> Result<(Vec<u8>, bool)> {
        store::read_attachment_limited(&self.dir, name, limit)
    }

    /// Carrega tudo em memória (equivalente ao bundle eager, sem cdp/netlog
    /// brutos), respeitando os limites de `import_session_dir`.
    pub fn into_bundle(self) -> Result<SessionBundle> {
        Ok(crate::parse::own::import_session_dir(&self.dir)?.bundle)
    }
}
