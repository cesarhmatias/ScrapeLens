use serde::{Deserialize, Serialize};

use super::body::Body;
use super::cookies::{CookieField, SetCookieRecord};
use super::headers::HeaderView;
use super::provenance::Provenance;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    H1,
    H2,
    H3,
    Unknown,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::H1 => "h1",
            Protocol::H2 => "h2",
            Protocol::H3 => "h3",
            Protocol::Unknown => "unknown",
        }
    }

    pub fn from_alpn(value: &str) -> Protocol {
        match value.to_ascii_lowercase().as_str() {
            "http/1.1" | "http/1.0" | "h1" => Protocol::H1,
            "h2" | "h2c" | "http/2" => Protocol::H2,
            "h3" | "http/3" => Protocol::H3,
            _ => Protocol::Unknown,
        }
    }

    pub fn parse_opt(value: Option<&str>) -> Protocol {
        value.map(Protocol::from_alpn).unwrap_or(Protocol::Unknown)
    }
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Unknown
    }
}

/// Resultado da associação de uma entidade com a fonte oposta. `Ambiguous`
/// nunca escolhe um candidato silenciosamente.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MatchState {
    Matched,
    Ambiguous,
    Unmatched,
}

impl MatchState {
    pub fn is_ambiguous(self) -> bool {
        matches!(self, MatchState::Ambiguous)
    }
}

impl Default for MatchState {
    fn default() -> Self {
        MatchState::Unmatched
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MatchCandidate {
    pub entity_id: String,
    /// 0..100; utilidade apenas para ordenar exibição, não para decidir.
    pub score: u8,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

impl MatchCandidate {
    pub fn new(entity_id: impl Into<String>, score: u8, reasons: Vec<String>) -> Self {
        Self {
            entity_id: entity_id.into(),
            score: score.min(100),
            reasons,
        }
    }
}

/// Iniciador de uma requisição: tipo da fonte (`parser`, `script`, `other`…) e
/// URL do iniciador, quando houver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Initiator {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
    /// Topo do stack (CDP `initiator.stack.callFrames[0]`); o stack inteiro não é guardado.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack_top: Option<InitiatorFrame>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitiatorFrame {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
}

impl Initiator {
    /// Lê `{type, url, lineNumber, stack}` (CDP e HAR `_initiator` têm a mesma forma).
    pub fn from_json(init: &serde_json::Map<String, serde_json::Value>) -> Option<Self> {
        let text = |v: Option<&serde_json::Value>| v.and_then(|v| v.as_str()).map(str::to_string);
        let line = |v: Option<&serde_json::Value>| {
            v.and_then(|v| v.as_u64())
                .and_then(|n| u32::try_from(n).ok())
        };
        let stack_top = init
            .get("stack")
            .and_then(|s| s.get("callFrames"))
            .and_then(|f| f.as_array())
            .and_then(|f| f.first())
            .map(|f| InitiatorFrame {
                url: text(f.get("url")),
                function: text(f.get("functionName")).filter(|n| !n.is_empty()),
                line_number: line(f.get("lineNumber")),
            });
        Some(Initiator {
            kind: init.get("type")?.as_str()?.to_string(),
            url: text(init.get("url")),
            line_number: line(init.get("lineNumber")),
            stack_top,
        })
    }
}

/// Referência a um evento CDP; IDs não são equivalentes aos do NetLog.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CdpRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loader_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_id: Option<String>,
}

impl CdpRef {
    pub fn is_empty(&self) -> bool {
        self.session_id.is_none()
            && self.request_id.is_none()
            && self.loader_id.is_none()
            && self.frame_id.is_none()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetlogRefs {
    /// IDs de fontes NetLog (`source.id`), tipicamente URL_REQUEST.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_ids: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stream_ids: Vec<u32>,
    /// IDs de `source_dependency` relevantes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependency_ids: Vec<u32>,
}

impl NetlogRefs {
    pub fn is_empty(&self) -> bool {
        self.source_ids.is_empty() && self.stream_ids.is_empty() && self.dependency_ids.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HeaderRole {
    Request,
    Response,
}

impl Default for HeaderRole {
    fn default() -> Self {
        HeaderRole::Request
    }
}

/// Evidência de headers de uma fonte específica. Uma tentativa pode ter várias
/// (ex.: transação + sessão h2), sem que uma substitua a outra.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderEvidence {
    pub id: String,
    pub role: HeaderRole,
    pub protocol: Protocol,
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<u32>,
    pub view: HeaderView,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AttemptOutcome {
    Completed,
    Failed,
    Aborted,
    Pending,
    Unknown,
}

impl Default for AttemptOutcome {
    fn default() -> Self {
        AttemptOutcome::Unknown
    }
}

/// Uma tentativa concreta de executar uma requisição lógica (retry, corrida
/// Happy Eyeballs, redirect etc.). Headers e corpos pertencem à tentativa.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attempt {
    pub id: String,
    pub logical_id: String,
    pub index: u32,
    pub url: String,
    pub method: String,
    pub protocol: Protocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_session_id: Option<String>,
    #[serde(default)]
    pub outcome: AttemptOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<f64>,
    #[serde(default)]
    pub request_headers: HeaderView,
    #[serde(default)]
    pub response_headers: HeaderView,
    #[serde(default)]
    pub cookie: CookieField,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub set_cookies: Vec<SetCookieRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub header_evidence: Vec<HeaderEvidence>,
    #[serde(default)]
    pub request_body: Body,
    #[serde(default)]
    pub response_body: Body,
    #[serde(default)]
    pub timings: Timings,
    pub cdp: Option<CdpRef>,
    /// Quem iniciou a requisição (CDP `initiator`, HAR `_initiator`), quando a
    /// fonte informa.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiator: Option<Initiator>,
    pub netlog: NetlogRefs,
    /// Estado do casamento desta tentativa com a fonte oposta.
    #[serde(rename = "match", default)]
    pub match_state: MatchState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_candidates: Vec<MatchCandidate>,
    #[serde(default)]
    pub provenance: Provenance,
}

impl Attempt {
    pub fn new(
        id: impl Into<String>,
        logical_id: impl Into<String>,
        index: u32,
        url: impl Into<String>,
        method: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            logical_id: logical_id.into(),
            index,
            url: url.into(),
            method: method.into(),
            protocol: Protocol::Unknown,
            status: None,
            connection_id: None,
            stream_session_id: None,
            outcome: AttemptOutcome::Unknown,
            failure: None,
            started_at: None,
            ended_at: None,
            request_headers: HeaderView::default(),
            response_headers: HeaderView::default(),
            cookie: CookieField::default(),
            set_cookies: Vec::new(),
            header_evidence: Vec::new(),
            request_body: Body::default(),
            response_body: Body::default(),
            timings: Timings::default(),
            cdp: None,
            initiator: None,
            netlog: NetlogRefs::default(),
            match_state: MatchState::Unmatched,
            match_candidates: Vec::new(),
            provenance: Provenance::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Redirect {
    pub id: String,
    pub logical_id: String,
    pub from_attempt_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_attempt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    pub from_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_url: Option<String>,
    #[serde(default)]
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Connection {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netlog_id: Option<u32>,
    pub protocol: Protocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reused: Option<bool>,
    #[serde(default)]
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamSession {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    pub protocol: Protocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netlog_session_id: Option<u32>,
    #[serde(default)]
    pub provenance: Provenance,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Span {
    pub start: f64,
    pub end: f64,
}

impl Span {
    pub fn duration_ms(&self) -> f64 {
        (self.end - self.start).max(0.0) * 1000.0
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Timings {
    /// Instante da fonte (segundos) em que a requisição começou.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_time: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Span>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect: Option<Span>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<Span>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send: Option<Span>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait: Option<Span>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receive: Option<Span>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_ms: Option<f64>,
    /// `true` quando a duração foi estimada (a UI mostra "≈").
    #[serde(default)]
    pub estimated: bool,
}

/// Requisição lógica: uma navegação/redirect chain agrupada, com tentativas.
/// Os campos de header no nível lógico são a **visão primária selecionada**;
/// todo original permanece em `attempts[].header_evidence`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogicalRequest {
    pub id: String,
    pub url: String,
    pub method: String,
    pub protocol: Protocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cdp: Option<CdpRef>,
    #[serde(default)]
    pub netlog: NetlogRefs,
    #[serde(default)]
    pub attempts: Vec<Attempt>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirects: Vec<Redirect>,
    #[serde(default)]
    pub request_headers: HeaderView,
    #[serde(default)]
    pub response_headers: HeaderView,
    #[serde(default)]
    pub cookie: CookieField,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub set_cookies: Vec<SetCookieRecord>,
    #[serde(default)]
    pub request_body: Body,
    #[serde(default)]
    pub response_body: Body,
    #[serde(default)]
    pub timings: Timings,
    /// Estado do casamento com a fonte oposta (CDP × NetLog).
    #[serde(rename = "match", default)]
    pub match_state: MatchState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_candidates: Vec<MatchCandidate>,
    #[serde(default)]
    pub provenance: Provenance,
}

impl LogicalRequest {
    pub fn new(id: impl Into<String>, url: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            url: url.into(),
            method: method.into(),
            protocol: Protocol::Unknown,
            status: None,
            resource_type: None,
            cdp: None,
            netlog: NetlogRefs::default(),
            attempts: Vec::new(),
            redirects: Vec::new(),
            request_headers: HeaderView::default(),
            response_headers: HeaderView::default(),
            cookie: CookieField::default(),
            set_cookies: Vec::new(),
            request_body: Body::default(),
            response_body: Body::default(),
            timings: Timings::default(),
            match_state: MatchState::Unmatched,
            match_candidates: Vec::new(),
            provenance: Provenance::default(),
        }
    }

    pub fn primary_attempt(&self) -> Option<&Attempt> {
        self.attempts.first()
    }

    /// Recalcula a visão primária a partir da última tentativa (a que
    /// completou a cadeia de redirect), preservando as evidências originais.
    pub fn refresh_primary_from_attempt(&mut self) {
        if let Some(attempt) = self.attempts.last() {
            self.protocol = attempt.protocol;
            self.status = attempt.status;
            self.request_headers = attempt.request_headers.clone();
            self.response_headers = attempt.response_headers.clone();
            self.cookie = attempt.cookie.clone();
            self.set_cookies = attempt.set_cookies.clone();
            self.request_body = attempt.request_body.clone();
            self.response_body = attempt.response_body.clone();
        }
    }

    pub fn total_ms(&self) -> Option<f64> {
        self.timings.total_ms
    }
}
