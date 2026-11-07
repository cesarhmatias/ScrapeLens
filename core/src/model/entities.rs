use serde::{Deserialize, Serialize};

use super::body::Body;
use super::cookies::{CookieField, SetCookieRecord};
use super::headers::HeaderView;
use super::provenance::Provenance;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    H1,
    H2,
    H3,
    #[default]
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

/// Result of associating an entity with the opposite source. `Ambiguous`
/// never silently picks a candidate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MatchState {
    Matched,
    Ambiguous,
    #[default]
    Unmatched,
}

impl MatchState {
    pub fn is_ambiguous(self) -> bool {
        matches!(self, MatchState::Ambiguous)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MatchCandidate {
    pub entity_id: String,
    /// 0..100; only useful for sorting the display, not for deciding.
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

/// Initiator of a request: source type (`parser`, `script`, `other`…) and
/// URL of the initiator, when available.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Initiator {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
    /// Top of the stack (CDP `initiator.stack.callFrames[0]`); the whole stack is not stored.
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
    /// Reads `{type, url, lineNumber, stack}` (CDP and HAR `_initiator` have the same shape).
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

/// CDP target type that originated a request (`Target.targetInfo.type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Page,
    Iframe,
    Worker,
    ServiceWorker,
    SharedWorker,
    #[default]
    Other,
}

impl TargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TargetKind::Page => "page",
            TargetKind::Iframe => "iframe",
            TargetKind::Worker => "worker",
            TargetKind::ServiceWorker => "service_worker",
            TargetKind::SharedWorker => "shared_worker",
            TargetKind::Other => "other",
        }
    }

    pub fn from_type(raw: &str) -> Self {
        match raw {
            "page" => TargetKind::Page,
            "iframe" => TargetKind::Iframe,
            "worker" => TargetKind::Worker,
            "service_worker" => TargetKind::ServiceWorker,
            "shared_worker" => TargetKind::SharedWorker,
            _ => TargetKind::Other,
        }
    }
}

/// Provenance of a request's CDP target, taken from the `Target.*` events.
/// Absent in old files (an implicit session) and in requests that only
/// NetLog saw (unknown type).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetProvenance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    #[serde(default)]
    pub kind: TargetKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opener_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_session_id: Option<String>,
    /// `false` = the target was seen and did not attach (warning, not error).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attached: Option<bool>,
    /// Informational notes about the target (e.g. closed during setup).
    /// These are not network warnings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl TargetProvenance {
    pub fn is_empty(&self) -> bool {
        self.target_id.is_none()
            && self.kind == TargetKind::Other
            && self.url.is_none()
            && self.opener_id.is_none()
            && self.parent_session_id.is_none()
            && self.attached.is_none()
            && self.notes.is_empty()
    }
}

/// Two observations of the same logical request (e.g. a fetch intercepted by
/// the service worker, seen in the SW session and on the page). Only exists
/// with explicit evidence; without it, the observations stay separate and the
/// ambiguity is recorded in `resolution: "ambiguous"` and in a warning.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestLink {
    /// `service_worker` for now.
    pub kind: String,
    /// Logical `id` of the other observation.
    pub request: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    /// `linked` (sufficient evidence) or `ambiguous`.
    pub resolution: String,
}

/// Reference to a CDP event; IDs are not equivalent to the NetLog ones.
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
    /// NetLog source IDs (`source.id`), typically URL_REQUEST.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_ids: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stream_ids: Vec<u32>,
    /// NetLog session/socket source IDs that carried the h2/h3 stream.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connection_source_ids: Vec<u32>,
    /// Relevant `source_dependency` IDs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependency_ids: Vec<u32>,
}

impl NetlogRefs {
    pub fn is_empty(&self) -> bool {
        self.source_ids.is_empty()
            && self.stream_ids.is_empty()
            && self.connection_source_ids.is_empty()
            && self.dependency_ids.is_empty()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HeaderRole {
    #[default]
    Request,
    Response,
}

/// Header evidence from a specific source. An attempt may have several
/// (e.g. transaction + h2 session), without one replacing the other.
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AttemptOutcome {
    Completed,
    Failed,
    Aborted,
    Pending,
    #[default]
    Unknown,
}

/// Whether a request reached the network. Set only when the NetLog proves that it
/// did not: the request was cancelled or failed and no request bytes were written
/// (no `HTTP_TRANSACTION_SEND_REQUEST`). Such an attempt has no protocol: the
/// protocol is never inferred from neighbouring requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkState {
    /// Cancelled or failed before any request bytes were written.
    NotSent,
}

/// A concrete attempt to execute a logical request (retry, Happy Eyeballs
/// race, redirect, etc.). Headers and bodies belong to the attempt.
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
    /// Who initiated the request (CDP `initiator`, HAR `_initiator`), when the
    /// source reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiator: Option<Initiator>,
    pub netlog: NetlogRefs,
    /// Match state of this attempt with the opposite source.
    #[serde(rename = "match", default)]
    pub match_state: MatchState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_candidates: Vec<MatchCandidate>,
    /// Set when the NetLog proves that the attempt never reached the network
    /// (see [`NetworkState`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_state: Option<NetworkState>,
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
            network_state: None,
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

/// One header field decoded from the plaintext bytes Chrome handed to TLS.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct H2Field {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct H2StreamEvidence {
    pub stream_id: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request: Vec<H2Field>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response: Vec<H2Field>,
    #[serde(default)]
    pub request_end_stream: bool,
    #[serde(default)]
    pub response_end_stream: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct H2Setting {
    pub id: u16,
    pub value: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct H2WindowUpdate {
    pub stream_id: u32,
    pub increment: u32,
}

/// HTTP/2 frames decoded from `SSL_SOCKET_BYTES_SENT`/`RECEIVED`: settings,
/// window updates and the real HPACK header order per stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct H2ConnectionEvidence {
    pub source_id: u32,
    #[serde(default)]
    pub preface: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub settings: Vec<H2Setting>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub window_updates: Vec<H2WindowUpdate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub streams: Vec<H2StreamEvidence>,
    #[serde(default)]
    pub provenance: Provenance,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// ClientHello fields and JA4 computed from `SSL_HANDSHAKE_MESSAGE_SENT`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsHelloEvidence {
    pub source_id: u32,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cipher_suites: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_versions: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature_algorithms: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<u16>,
    pub ja4: String,
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
    /// Source instant (seconds) at which the request started.
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
    /// `true` when the duration was estimated (the UI shows "≈").
    #[serde(default)]
    pub estimated: bool,
}

/// Logical request: a navigation/redirect chain grouped, with attempts.
/// The header fields at the logical level are the **selected primary view**;
/// every original stays in `attempts[].header_evidence`.
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
    /// CDP target the request came from (page, iframe, worker, service worker…).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetProvenance>,
    /// Sibling observations of the same logical request (service worker).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<RequestLink>,
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
    /// Match state with the opposite source (CDP × NetLog).
    #[serde(rename = "match", default)]
    pub match_state: MatchState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_candidates: Vec<MatchCandidate>,
    /// Set when the NetLog proves that the attempt never reached the network
    /// (see [`NetworkState`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_state: Option<NetworkState>,
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
            target: None,
            links: Vec::new(),
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
            network_state: None,
            provenance: Provenance::default(),
        }
    }

    pub fn primary_attempt(&self) -> Option<&Attempt> {
        self.attempts.first()
    }

    /// Recomputes the primary view from the last attempt (the one that
    /// completed the redirect chain), preserving the original evidence.
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
