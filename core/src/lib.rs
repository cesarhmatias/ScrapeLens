//! ScrapeLens core.
//!
//! Implements the session format v1 (`docs/03-contratos.md`), importers for
//! HAR/NetLog/own format, CDP×NetLog correlation with explicit ambiguity,
//! derived normalized views, diff and exporters.
//!
//! Principles:
//! - the original is never rewritten: headers are ordered arrays of pairs, with
//!   duplicates and pseudoheaders kept separate;
//! - every unit of information carries provenance and verification state;
//! - nothing fails silently: every discarded or misunderstood piece of data
//!   becomes a [`model::Warning`];
//! - no function in this crate opens network connections.

#![forbid(unsafe_code)]

pub mod adapter;
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
pub mod timeline;
pub mod validate;

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
