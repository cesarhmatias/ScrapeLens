//! Session importers.
//!
//! Every importer also returns an [`ImportReport`]: missing data,
//! unknown or discarded items appear as [`Warning`], never silently.

pub mod cdp;
pub mod cdp_bodies;
pub mod har;
pub mod netlog;
pub mod own;
pub mod trace;

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
    /// CDP + NetLog combined (product capture).
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

/// Imported session + report. The caller may persist `bundle` and display
/// `report`; the warnings are also kept in `bundle.session.warnings`.
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

/// Reads a session in the native v1 format (directory with `session.json`).
pub fn import_session_dir(path: &Path) -> Result<ImportedSession> {
    own::import_session_dir(path)
}

/// Opens a v1 session with lazy attachments (see [`crate::lazy`]).
pub fn open_session_dir_lazy(path: &Path) -> Result<(crate::lazy::LazySession, ImportReport)> {
    own::open_session_dir_lazy(path)
}

/// Imports HAR 1.2. Order/duplicates in HAR are **unverified**: the matrix
/// did not instrument the DevTools exporter.
pub fn import_har(json: &[u8]) -> Result<ImportedSession> {
    har::import_har(json)
}

/// Imports the script execution trace (`scrapelens.trace/1`).
pub fn import_trace(json: &[u8]) -> Result<ImportedSession> {
    trace::import_trace(json)
}

/// Imports a Chrome NetLog on its own (without CDP).
pub fn import_netlog(json: &[u8]) -> Result<ImportedSession> {
    netlog::import_netlog(json)
}

/// Imports CDP + NetLog and correlates them with explicit ambiguity.
pub fn import_capture(
    cdp_events_jsonl: &[u8],
    netlog_json: &[u8],
    options: crate::correlate::CorrelationOptions,
) -> Result<ImportedSession> {
    import_capture_with_bodies(cdp_events_jsonl, netlog_json, None, options)
}

/// Like [`import_capture`], with the optional content of `cdp-bodies.jsonl`
/// (`docs/08-corpos-busca.md` §1). Without it, the bodies stay `unavailable` and the
/// session gets a single `cdp.bodies_file_absent` warning.
pub fn import_capture_with_bodies(
    cdp_events_jsonl: &[u8],
    netlog_json: &[u8],
    cdp_bodies_jsonl: Option<&[u8]>,
    options: crate::correlate::CorrelationOptions,
) -> Result<ImportedSession> {
    import_capture_labeled(
        cdp_events_jsonl,
        netlog_json,
        cdp_bodies_jsonl,
        &[],
        options,
    )
}

/// Like [`import_capture_with_bodies`], with origin labels declared by
/// the caller. Without `live-capture` in `labels`, the session gets the label
/// `capture-import` (file import); with it, the capturer declares the
/// live cycle and `capture-import` is not recorded. Other labels (e.g.:
/// `synthetic-fixture`) are appended without duplication.
pub fn import_capture_labeled(
    cdp_events_jsonl: &[u8],
    netlog_json: &[u8],
    cdp_bodies_jsonl: Option<&[u8]>,
    labels: &[String],
    options: crate::correlate::CorrelationOptions,
) -> Result<ImportedSession> {
    let cdp = cdp::parse_cdp_jsonl(cdp_events_jsonl)?;
    // Calibrates the NetLog clock by the median of the CDP `wallTime`s of the same
    // capture. This does not match requests: it only picks the unit of `time`.
    let wall_clock = median_wall_clock(&cdp);
    let netlog = netlog::parse_netlog_with_wall_clock(netlog_json, wall_clock)?;
    let mut report = ImportReport::new(InputFormat::Capture);
    let (session, mut cdp_report) = cdp::build_cdp_session(&cdp);
    let (netlog_session, netlog_report) = netlog::build_netlog_session(&netlog);
    let netlog_requests = netlog_session.requests.len();
    let mut session = session;
    // NetLog file warnings (unknown types, unresolved chain) are
    // relevant; per-request background warnings are not imported.
    for warning in &netlog.warnings {
        if !session
            .warnings
            .iter()
            .any(|existing| existing.code == warning.code && existing.message == warning.message)
        {
            session.warnings.push(warning.clone());
        }
    }
    let mut id_seed = cdp_events_jsonl.to_vec();
    id_seed.extend_from_slice(netlog_json);
    session.session.id = format!("capture-{}", har::stable_id(&id_seed));
    if !labels
        .iter()
        .any(|label| label == crate::model::LABEL_LIVE_CAPTURE)
    {
        session
            .session
            .labels
            .push(crate::model::LABEL_CAPTURE_IMPORT.to_string());
    }
    for label in labels {
        if !session.session.labels.contains(label) {
            session.session.labels.push(label.clone());
        }
    }
    if session.session.browser.version.is_none() && netlog.browser.version.is_some() {
        session.session.browser = netlog.browser.clone();
    }
    if let Some(version) = session.session.browser.version.clone() {
        crate::model::backfill_browser_version(&mut session, &version);
    }
    let outcome = crate::correlate::attach_netlog(&mut session, &netlog, &options);
    cdp_report.merge(netlog_report);
    let mut attachments = std::collections::BTreeMap::new();
    match cdp_bodies_jsonl {
        Some(bodies) => {
            let applied = cdp_bodies::apply_cdp_bodies_with_capture(
                &mut session,
                &mut attachments,
                bodies,
                Some(&cdp),
            );
            for warning in applied.warnings {
                session.add_warning(warning.clone());
                cdp_report.warn(warning);
            }
        }
        None => {
            let warning = Warning::new(
                "cdp.bodies_file_absent",
                "cdp-bodies.jsonl missing: CDP bodies not imported (unavailable)",
            );
            session.add_warning(warning.clone());
            cdp_report.warn(warning);
        }
    }
    // `attach_netlog` already records the warnings on the session; the report gets a copy.
    for warning in outcome.warnings {
        cdp_report.warn(warning);
    }

    let total_events = cdp.events_total + netlog.events_total;
    let unknown_events = netlog.events_unknown + cdp.events_invalid;
    let used_events = total_events.saturating_sub(unknown_events);
    // The completeness reasons of `build_cdp_session` (e.g.: "no usable CDP
    // request") and of `attach_netlog` survive: the joint capture is only
    // `complete` if no source reported a gap. Only the reason "CDP capture without correlated NetLog"
    // (valid for importing CDP alone) is dropped: here the correlation
    // with NetLog has just been done.
    let inherited_reasons = std::mem::take(&mut session.session.completeness.reasons);
    session.session.completeness = crate::model::Completeness::complete();
    for reason in inherited_reasons
        .into_iter()
        .filter(|reason| reason != cdp::REASON_CDP_WITHOUT_NETLOG)
    {
        session.session.completeness.add_reason(reason);
    }
    if session.requests.is_empty() && (netlog_requests > 0 || netlog.events_total > 0) {
        session.session.completeness.add_reason(format!(
            "NetLog with {} event(s) and {netlog_requests} request(s) without a CDP match: the capture has no correlatable request",
            netlog.events_total
        ));
    }
    session.session.completeness.counts.source_events = total_events;
    session.session.completeness.counts.source_events_used = used_events;
    session.session.completeness.counts.source_events_unknown = unknown_events;
    if cdp_report.has_errors() {
        session
            .session
            .completeness
            .add_reason("capture with error warnings");
    }
    session.recompute_completeness();
    report.merge(cdp_report);
    report.format = InputFormat::Capture;
    report.source_events = total_events;
    report.source_events_used = used_events;
    report.source_events_unknown = unknown_events;
    let bundle = SessionBundle {
        session,
        cdp_events_jsonl: Some(cdp_events_jsonl.to_vec()),
        netlog_json: Some(netlog_json.to_vec()),
        attachments,
    };
    Ok(ImportedSession::new(bundle, report))
}

/// Median of the `wallTime`s (epoch in seconds) of the capture's CDP events.
fn median_wall_clock(cdp: &cdp::CdpCapture) -> Option<f64> {
    let mut values: Vec<f64> = cdp
        .requests
        .iter()
        .flat_map(|request| request.attempts.iter())
        .filter_map(|attempt| attempt.wall_time_s)
        .collect();
    if values.is_empty() {
        return None;
    }
    values.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let middle = values.len() / 2;
    Some(if values.len() % 2 == 0 {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    })
}
