//! Importadores de sessão.
//!
//! Todo importador devolve também um [`ImportReport`]: dados ausentes,
//! desconhecidos ou descartados aparecem como [`Warning`], nunca em silêncio.

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

/// Abre uma sessão v1 com anexos preguiçosos (ver [`crate::lazy`]).
pub fn open_session_dir_lazy(path: &Path) -> Result<(crate::lazy::LazySession, ImportReport)> {
    own::open_session_dir_lazy(path)
}

/// Importa HAR 1.2. Ordem/duplicatas em HAR são **não verificadas**: a matriz
/// não instrumentou o exportador do DevTools.
pub fn import_har(json: &[u8]) -> Result<ImportedSession> {
    har::import_har(json)
}

/// Importa o trace de execução do script (`scrapelens.trace/1`).
pub fn import_trace(json: &[u8]) -> Result<ImportedSession> {
    trace::import_trace(json)
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
    import_capture_with_bodies(cdp_events_jsonl, netlog_json, None, options)
}

/// Como [`import_capture`], com o conteúdo opcional de `cdp-bodies.jsonl`
/// (`docs/08-corpos-busca.md` §1). Sem ele, os corpos seguem `unavailable` e a
/// sessão recebe um único aviso `cdp.bodies_file_absent`.
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

/// Como [`import_capture_with_bodies`], com rótulos de origem declarados por
/// quem chama. Sem `live-capture` em `labels`, a sessão recebe o rótulo
/// `capture-import` (importação de arquivos); com ele, quem captura declara o
/// ciclo ao vivo e `capture-import` não é gravado. Demais rótulos (ex.:
/// `synthetic-fixture`) são acrescentados sem duplicar.
pub fn import_capture_labeled(
    cdp_events_jsonl: &[u8],
    netlog_json: &[u8],
    cdp_bodies_jsonl: Option<&[u8]>,
    labels: &[String],
    options: crate::correlate::CorrelationOptions,
) -> Result<ImportedSession> {
    let cdp = cdp::parse_cdp_jsonl(cdp_events_jsonl)?;
    // Calibra o relógio do NetLog pela mediana dos `wallTime` do CDP da mesma
    // captura. Isso não associa requisições: só escolhe a unidade de `time`.
    let wall_clock = median_wall_clock(&cdp);
    let netlog = netlog::parse_netlog_with_wall_clock(netlog_json, wall_clock)?;
    let mut report = ImportReport::new(InputFormat::Capture);
    let (session, mut cdp_report) = cdp::build_cdp_session(&cdp);
    let (netlog_session, netlog_report) = netlog::build_netlog_session(&netlog);
    let netlog_requests = netlog_session.requests.len();
    let mut session = session;
    // Avisos do arquivo NetLog (tipos desconhecidos, cadeia não resolvida) são
    // relevantes; avisos por requisição de background não são importados.
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
                "cdp-bodies.jsonl ausente: corpos CDP não importados (unavailable)",
            );
            session.add_warning(warning.clone());
            cdp_report.warn(warning);
        }
    }
    // `attach_netlog` já registra os avisos na sessão; o relatório recebe cópia.
    for warning in outcome.warnings {
        cdp_report.warn(warning);
    }

    let total_events = cdp.events_total + netlog.events_total;
    let unknown_events = netlog.events_unknown + cdp.events_invalid;
    let used_events = total_events.saturating_sub(unknown_events);
    // As razões de completude de `build_cdp_session` (ex.: "nenhuma requisição CDP
    // utilizável") e de `attach_netlog` sobrevivem: a captura conjunta só é
    // `complete` se nenhuma fonte reportou lacuna. Só a razão "CDP sem NetLog"
    // (válida para a importação isolada do CDP) é descartada: aqui a correlação
    // com o NetLog acabou de ser feita.
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
            "NetLog com {} evento(s) e {netlog_requests} requisição(ões) sem correspondência CDP: a captura não tem nenhuma requisição correlacionável",
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
            .add_reason("captura com avisos de erro");
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

/// Mediana dos `wallTime` (epoch em segundos) dos eventos CDP da captura.
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
