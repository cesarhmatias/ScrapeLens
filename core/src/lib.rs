//! ScrapeLens core.
//!
//! Implementa o formato de sessão v1 (`docs/03-contratos.md`), importadores
//! HAR/NetLog/formato próprio, correlação CDP×NetLog com ambiguidade explícita,
//! visões normalizadas derivadas, diff e exportadores.
//!
//! Princípios:
//! - o original nunca é reescrito: headers são arrays ordenados de pares, com
//!   duplicatas e pseudoheaders separados;
//! - cada unidade de informação carrega proveniência e estado de verificação;
//! - nada falha em silêncio: todo dado descartado ou não entendido vira
//!   [`model::Warning`];
//! - nenhuma função deste crate abre conexões de rede.

#![forbid(unsafe_code)]

pub mod assess;
pub mod compare;
pub mod correlate;
pub mod diff;
pub mod error;
pub mod export;
pub mod flow;
pub mod html;
pub mod lazy;
pub mod model;
pub mod normalize;
pub mod parse;
pub mod search;
pub mod store;

pub use error::{CoreError, Result};
pub use model::{
    Attempt, AttemptOutcome, Body, BodyState, BrowserInfo, CdpRef, Completeness, CompletenessState,
    Connection, CookieField, CookiePairEntry, HeaderEntry, HeaderView, LogicalRequest, MatchState,
    ParsedSetCookie, Protocol, Provenance, Redirect, SessionBundle, SessionMeta, SessionV1,
    SetCookieRecord, Source, StreamSession, Verification, Warning, WarningSeverity, SCHEMA_VERSION,
};
pub use parse::{
    import_capture, import_capture_labeled, import_capture_with_bodies, import_har, import_netlog,
    import_session_dir, open_session_dir_lazy, ImportReport, ImportedSession, InputFormat,
};
