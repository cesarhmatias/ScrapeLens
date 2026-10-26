//! Importadores de sessão.
//!
//! Todo importador devolve também um [`ImportReport`]: dados ausentes,
//! desconhecidos ou descartados aparecem como [`Warning`], nunca em silêncio.

pub mod cdp;
pub mod har;
pub mod netlog;
pub mod own;

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::model::{SessionBundle, Warning, WarningSeverity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InputFormat {
    OwnV1,
    Har,
    NetLog,
    Cdp,
    /// CDP + NetLog combinados (captura do produto).
    Capture,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    pub format: InputFormat,
    #[serde(default)]
    pub warnings: Vec<Warning>,
    #[serde(default)]
    pub source_events: usize,
    #[serde(default)]
    pub source_events_used: usize,
    #[serde(default)]
    pub source_events_unknown: usize,
    #[serde(default)]
    pub attachments_loaded: usize,
    #[serde(default)]
    pub attachments_missing: usize,
    #[serde(default)]
    pub bytes_read: usize,
}

impl ImportReport {
    pub fn new(format: InputFormat) -> Self {
        Self {
            format,
            warnings: Vec::new(),
            source_events: 0,
            source_events_used: 0,
            source_events_unknown: 0,
            attachments_loaded: 0,
            attachments_missing: 0,
            bytes_read: 0,
        }
    }

    pub fn warn(&mut self, warning: Warning) {
        self.warnings.push(warning);
    }

    pub fn merge(&mut self, other: ImportReport) {
        self.warnings.extend(other.warnings);
        self.source_events += other.source_events;
        self.source_events_used += other.source_events_used;
        self.source_events_unknown += other.source_events_unknown;
        self.attachments_loaded += other.attachments_loaded;
        self.attachments_missing += other.attachments_missing;
        self.bytes_read += other.bytes_read;
    }

    pub fn has_errors(&self) -> bool {
        self.warnings
            .iter()
            .any(|warning| warning.severity == WarningSeverity::Error)
    }
}

/// Sessão importada + relatório. O chamador pode persistir `bundle` e exibir
/// `report`; os avisos também ficam em `bundle.session.warnings`.
#[derive(Debug, Clone)]
pub struct ImportedSession {
    pub bundle: SessionBundle,
    pub report: ImportReport,
}

impl ImportedSession {
    pub fn new(bundle: SessionBundle, report: ImportReport) -> Self {
        Self { bundle, report }
    }
}

/// Lê uma sessão no formato próprio v1 (diretório com `session.json`).
pub fn import_session_dir(path: &Path) -> Result<ImportedSession> {
    own::import_session_dir(path)
}

/// Importa HAR 1.2. Ordem/duplicatas em HAR são **não verificadas**: a matriz
/// não instrumentou o exportador do DevTools.
pub fn import_har(json: &[u8]) -> Result<ImportedSession> {
    har::import_har(json)
}

/// Importa um NetLog do Chrome isoladamente (sem CDP).
pub fn import_netlog(json: &[u8]) -> Result<ImportedSession> {
    netlog::import_netlog(json)
}

/// Importa CDP + NetLog e correlaciona com ambiguidade explícita.
pub fn import_capture(
    cdp_events_jsonl: &[u8],
    netlog_json: &[u8],
    options: crate::correlate::CorrelationOptions,
) -> Result<ImportedSession> {
    let cdp = cdp::parse_cdp_jsonl(cdp_events_jsonl)?;
    let netlog = netlog::parse_netlog(netlog_json)?;
    let mut report = ImportReport::new(InputFormat::Capture);
    let (session, mut cdp_report) = cdp::build_cdp_session(&cdp);
    let (_netlog_session, netlog_report) = netlog::build_netlog_session(&netlog);
    let mut session = session;
    if session.session.browser.version.is_none() && netlog.browser.version.is_some() {
        session.session.browser = netlog.browser.clone();
    }
    if let Some(version) = session.session.browser.version.clone() {
        crate::model::backfill_browser_version(&mut session, &version);
    }
    let outcome = crate::correlate::attach_netlog(&mut session, &netlog, &options);
    cdp_report.merge(netlog_report);
    // `attach_netlog` já registra os avisos na sessão; o relatório recebe cópia.
    for warning in outcome.warnings {
        cdp_report.warn(warning);
    }

    let total_events = cdp.events_total + netlog.events_total;
    let used_events = cdp.events_used + netlog.events_used;
    session.session.completeness = crate::model::Completeness::complete();
    session.session.completeness.counts.source_events = total_events;
    session.session.completeness.counts.source_events_used = used_events;
    session.session.completeness.counts.source_events_unknown = netlog.events_unknown;
    if cdp_report.has_errors() {
        session
            .session
            .completeness
            .add_reason("captura com avisos de erro");
    }
    session.recompute_completeness();
    report.merge(cdp_report);
    report.format = InputFormat::Capture;
    report.source_events = total_events;
    report.source_events_used = used_events;
    report.source_events_unknown = netlog.events_unknown;
    let bundle = SessionBundle {
        session,
        cdp_events_jsonl: Some(cdp_events_jsonl.to_vec()),
        netlog_json: Some(netlog_json.to_vec()),
        attachments: Default::default(),
    };
    Ok(ImportedSession::new(bundle, report))
}
