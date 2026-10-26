use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::entities::{Connection, LogicalRequest, StreamSession};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CompletenessState {
    Complete,
    Partial,
}

impl Default for CompletenessState {
    fn default() -> Self {
        CompletenessState::Partial
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WarningSeverity {
    Info,
    Warning,
    Error,
}

impl Default for WarningSeverity {
    fn default() -> Self {
        WarningSeverity::Warning
    }
}

/// Aviso de importação/captura. Nada é descartado em silêncio: dados
/// desconhecidos, campos ausentes e limites de captura geram um `Warning`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Warning {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub severity: WarningSeverity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
}

impl Warning {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            severity: WarningSeverity::Warning,
            entity: None,
            detail: None,
        }
    }

    pub fn info(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: WarningSeverity::Info,
            ..Self::new(code, message)
        }
    }

    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: WarningSeverity::Error,
            ..Self::new(code, message)
        }
    }

    pub fn with_entity(mut self, entity: impl Into<String>) -> Self {
        self.entity = Some(entity.into());
        self
    }

    pub fn with_detail(mut self, detail: Value) -> Self {
        self.detail = Some(detail);
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletenessCounts {
    #[serde(default)]
    pub requests: usize,
    #[serde(default)]
    pub attempts: usize,
    #[serde(default)]
    pub redirects: usize,
    #[serde(default)]
    pub connections: usize,
    #[serde(default)]
    pub stream_sessions: usize,
    #[serde(default)]
    pub source_events: usize,
    #[serde(default)]
    pub source_events_used: usize,
    #[serde(default)]
    pub source_events_unknown: usize,
    #[serde(default)]
    pub warnings: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Completeness {
    pub state: CompletenessState,
    #[serde(default)]
    pub reasons: Vec<String>,
    #[serde(default)]
    pub counts: CompletenessCounts,
}

impl Default for Completeness {
    fn default() -> Self {
        Self {
            state: CompletenessState::Partial,
            reasons: vec!["completeness não informada pela fonte".to_string()],
            counts: CompletenessCounts::default(),
        }
    }
}

impl Completeness {
    pub fn complete() -> Self {
        Self {
            state: CompletenessState::Complete,
            reasons: Vec::new(),
            counts: CompletenessCounts::default(),
        }
    }

    pub fn partial(reason: impl Into<String>) -> Self {
        Self {
            state: CompletenessState::Partial,
            reasons: vec![reason.into()],
            counts: CompletenessCounts::default(),
        }
    }

    pub fn add_reason(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
        self.state = CompletenessState::Partial;
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserInfo {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

impl Default for BrowserInfo {
    fn default() -> Self {
        Self {
            name: "unknown".to_string(),
            version: None,
            platform: None,
            user_agent: None,
        }
    }
}

/// Fatos da captura; nada aqui é necessário para ler o modelo.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureMeta {
    /// Ex.: `cdp+netlog`, `har-import`, `netlog-import`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_binary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headless: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chrome_args: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionMeta {
    pub id: String,
    #[serde(default)]
    pub browser: BrowserInfo,
    /// ISO 8601 com offset/UTC.
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    #[serde(default)]
    pub completeness: Completeness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<CaptureMeta>,
    /// Rótulos livres; fixtures usam `synthetic-fixture`.
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl SessionMeta {
    pub fn new(id: impl Into<String>, started_at: impl Into<String>, browser: BrowserInfo) -> Self {
        Self {
            id: id.into(),
            browser,
            started_at: started_at.into(),
            ended_at: None,
            completeness: Completeness::partial("sessão em construção"),
            capture: None,
            labels: Vec::new(),
            notes: Vec::new(),
        }
    }
}

/// Documento persistido em `session.json`. Contém metadados, entidades e
/// avisos; os artefatos brutos (`cdp-events.jsonl`, `netlog.json`,
/// `attachments/`) ficam ao lado e não são reescritos.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionV1 {
    pub schema_version: u32,
    pub session: SessionMeta,
    #[serde(default)]
    pub requests: Vec<LogicalRequest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connections: Vec<Connection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stream_sessions: Vec<StreamSession>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
}

impl SessionV1 {
    pub fn new(session: SessionMeta) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            session,
            requests: Vec::new(),
            connections: Vec::new(),
            stream_sessions: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn add_warning(&mut self, warning: Warning) {
        if warning.severity == WarningSeverity::Error {
            self.session
                .completeness
                .add_reason(format!("{}: {}", warning.code, warning.message));
        }
        self.warnings.push(warning);
    }

    pub fn find_request(&self, id: &str) -> Option<&LogicalRequest> {
        self.requests.iter().find(|request| request.id == id)
    }

    pub fn find_attempt(&self, id: &str) -> Option<(&LogicalRequest, &super::entities::Attempt)> {
        self.requests.iter().find_map(|request| {
            request
                .attempts
                .iter()
                .find(|attempt| attempt.id == id)
                .map(|attempt| (request, attempt))
        })
    }

    /// Recalcula contagens e o estado de completude a partir do conteúdo.
    /// O estado só melhora para `Complete` se nenhuma fonte declarou parcial e
    /// não há avisos de erro.
    pub fn recompute_completeness(&mut self) {
        let previous = self.session.completeness.counts.clone();
        let mut counts = CompletenessCounts {
            requests: self.requests.len(),
            connections: self.connections.len(),
            stream_sessions: self.stream_sessions.len(),
            warnings: self.warnings.len(),
            source_events: previous.source_events,
            source_events_used: previous.source_events_used,
            source_events_unknown: previous.source_events_unknown,
            ..CompletenessCounts::default()
        };
        for request in &self.requests {
            counts.attempts += request.attempts.len();
            counts.redirects += request.redirects.len();
        }
        self.session.completeness.counts = counts;
        if !self.session.completeness.reasons.is_empty() {
            self.session.completeness.state = CompletenessState::Partial;
        }

        if self
            .warnings
            .iter()
            .any(|warning| warning.severity == WarningSeverity::Error)
            && self.session.completeness.state == CompletenessState::Complete
        {
            self.session
                .completeness
                .add_reason("há avisos de erro na sessão");
        }
    }

    /// Verificação agregada da sessão: a mais fraca entre as requisições.
    /// A UI nunca deve exibir um selo "verificado" por sessão quando uma
    /// informação é parcial; use proveniência por informação.
    pub fn weakest_verification(&self) -> super::provenance::Verification {
        if self.requests.is_empty() {
            return super::provenance::Verification::Unverified;
        }
        self.requests
            .iter()
            .map(|request| request.request_headers.verification())
            .fold(super::provenance::Verification::Verified, |acc, v| {
                acc.weakest(v)
            })
    }
}

/// Sessão + artefatos brutos carregados em memória. `source_dir` nunca é
/// necessário para interpretar o documento; é usado para gravar exportações.
#[derive(Debug, Clone)]
pub struct SessionBundle {
    pub session: SessionV1,
    pub cdp_events_jsonl: Option<Vec<u8>>,
    pub netlog_json: Option<Vec<u8>>,
    pub attachments: BTreeMap<String, Vec<u8>>,
}

impl SessionBundle {
    pub fn new(session: SessionV1) -> Self {
        Self {
            session,
            cdp_events_jsonl: None,
            netlog_json: None,
            attachments: BTreeMap::new(),
        }
    }

    pub fn attachment(&self, name: &str) -> Option<&[u8]> {
        self.attachments.get(name).map(Vec::as_slice)
    }

    pub fn insert_attachment(&mut self, name: impl Into<String>, bytes: Vec<u8>) {
        self.attachments.insert(name.into(), bytes);
    }
}

/// Fixtures e exports sintéticos são marcados aqui para que a UI nunca os
/// confunda com captura real.
pub const LABEL_SYNTHETIC: &str = "synthetic-fixture";

/// Preenche `browserVersion` em toda proveniência que ainda não o tem. Usado
/// quando a captura combinada descobre a versão no NetLog (o CDP não a traz).
pub fn backfill_browser_version(session: &mut SessionV1, version: &str) {
    fn fill(provenance: &mut super::provenance::Provenance, version: &str) {
        if provenance.browser_version.is_none() {
            provenance.browser_version = Some(version.to_string());
        }
    }
    fn fill_view(view: &mut super::headers::HeaderView, version: &str) {
        for entry in view
            .pseudo_headers
            .iter_mut()
            .chain(view.headers.iter_mut())
        {
            fill(&mut entry.provenance, version);
        }
    }
    fn fill_cookie(cookie: &mut super::cookies::CookieField, version: &str) {
        fill(&mut cookie.provenance, version);
        for pair in &mut cookie.pairs {
            fill(&mut pair.provenance, version);
        }
    }
    fn fill_body(body: &mut super::body::Body, version: &str) {
        fill(&mut body.provenance, version);
    }
    fn fill_request(request: &mut super::entities::LogicalRequest, version: &str) {
        fill(&mut request.provenance, version);
        fill_view(&mut request.request_headers, version);
        fill_view(&mut request.response_headers, version);
        fill_cookie(&mut request.cookie, version);
        for record in &mut request.set_cookies {
            fill(&mut record.provenance, version);
        }
        fill_body(&mut request.request_body, version);
        fill_body(&mut request.response_body, version);
        for redirect in &mut request.redirects {
            fill(&mut redirect.provenance, version);
        }
        for attempt in &mut request.attempts {
            fill(&mut attempt.provenance, version);
            fill_view(&mut attempt.request_headers, version);
            fill_view(&mut attempt.response_headers, version);
            fill_cookie(&mut attempt.cookie, version);
            for record in &mut attempt.set_cookies {
                fill(&mut record.provenance, version);
            }
            for evidence in &mut attempt.header_evidence {
                fill_view(&mut evidence.view, version);
            }
            fill_body(&mut attempt.request_body, version);
            fill_body(&mut attempt.response_body, version);
        }
    }

    for request in &mut session.requests {
        fill_request(request, version);
    }
    for connection in &mut session.connections {
        fill(&mut connection.provenance, version);
    }
    for stream in &mut session.stream_sessions {
        fill(&mut stream.provenance, version);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> SessionV1 {
        SessionV1::new(SessionMeta::new(
            "s-1",
            "2026-10-26T20:00:00Z",
            BrowserInfo {
                name: "Chrome".to_string(),
                version: Some("156.0.8078.48".to_string()),
                ..BrowserInfo::default()
            },
        ))
    }

    #[test]
    fn schema_version_is_one() {
        let value = serde_json::to_value(session()).unwrap();
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["session"]["id"], "s-1");
    }

    #[test]
    fn error_warning_marks_session_partial() {
        let mut s = session();
        s.session.completeness = Completeness::complete();
        s.add_warning(Warning::error("netlog.invalid", "arquivo corrompido"));
        assert_eq!(s.session.completeness.state, CompletenessState::Partial);
        assert!(!s.session.completeness.reasons.is_empty());
    }

    #[test]
    fn recompute_counts() {
        let mut s = session();
        s.requests
            .push(LogicalRequest::new("r1", "https://a.test/", "GET"));
        s.recompute_completeness();
        assert_eq!(s.session.completeness.counts.requests, 1);
        assert_eq!(s.session.completeness.counts.attempts, 0);
    }
}
