use serde::{Deserialize, Serialize};

/// Origin of a piece of data. `Derived` marks computed views (normalization, diff,
/// export); `Manual` marks a correction made by the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Source {
    Cdp,
    #[serde(rename = "netlog")]
    NetLog,
    Har,
    OwnFormat,
    Capture,
    Derived,
    Manual,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Cdp => "cdp",
            Source::NetLog => "netlog",
            Source::Har => "har",
            Source::OwnFormat => "ownFormat",
            Source::Capture => "capture",
            Source::Derived => "derived",
            Source::Manual => "manual",
        }
    }
}

/// Verification state **per piece of information**, never per session.
///
/// - `Verified`: the sequence/value was checked against the decoded layer;
/// - `Partial`: preserves part of the information (e.g. h2/h3 order, merged `Cookie`);
/// - `Unverified`: the source does not prove what was requested (e.g. HAR, CDP
///   `requestWillBeSent.headers` for sequence) or there is no evidence.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum Verification {
    #[default]
    Unverified,
    Partial,
    Verified,
}

impl Verification {
    /// The weaker of two states. Used when aggregating provenances.
    pub fn weakest(self, other: Verification) -> Verification {
        self.min(other)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Verification::Verified => "verified",
            Verification::Partial => "partial",
            Verification::Unverified => "unverified",
        }
    }
}

/// Provenance of a unit of information (header pair, cookie, body,
/// entity). Absent fields mean "the source did not provide it".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    pub source: Source,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    /// Identifier in the source (CDP requestId, NetLog source id, HAR index).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    /// Source timestamp in seconds (CDP monotonic or NetLog `time`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<f64>,
    /// Absolute instant, when the source provides it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_version: Option<String>,
    /// How the data was obtained (e.g. `headersText`, `netlog.headers`,
    /// `heuristic:url+method+time`).
    pub method: String,
    pub verification: Verification,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl Default for Provenance {
    fn default() -> Self {
        Self {
            source: Source::OwnFormat,
            event: None,
            source_id: None,
            timestamp: None,
            wall_time: None,
            browser_version: None,
            method: "unspecified".to_string(),
            verification: Verification::Unverified,
            notes: Vec::new(),
        }
    }
}

impl Provenance {
    pub fn new(source: Source, method: impl Into<String>, verification: Verification) -> Self {
        Self {
            source,
            method: method.into(),
            verification,
            ..Self::default()
        }
    }

    pub fn with_event(mut self, event: impl Into<String>) -> Self {
        self.event = Some(event.into());
        self
    }

    pub fn with_source_id(mut self, id: impl Into<String>) -> Self {
        self.source_id = Some(id.into());
        self
    }

    pub fn with_timestamp(mut self, timestamp: f64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Only records the timestamp when the source provides it (never invents 0.0).
    pub fn with_optional_timestamp(mut self, timestamp: Option<f64>) -> Self {
        if let Some(timestamp) = timestamp {
            self.timestamp = Some(timestamp);
        }
        self
    }

    pub fn with_wall_time(mut self, wall_time: impl Into<String>) -> Self {
        self.wall_time = Some(wall_time.into());
        self
    }

    pub fn with_browser_version(mut self, version: impl Into<String>) -> Self {
        self.browser_version = Some(version.into());
        self
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    pub fn with_verification(mut self, verification: Verification) -> Self {
        self.verification = verification;
        self
    }

    /// Provenance of a heuristic association (never silent).
    pub fn heuristic(method: impl Into<String>, verification: Verification) -> Self {
        Self::new(Source::Derived, method, verification)
    }
}

/// Verification policy derived from `docs/02-fidelity-matrix.md` (D2).
///
/// The matrix is the source of the facts; this function only encodes the verdict
/// so that importers do not invent "verified" where the evidence is partial.
pub mod policy {
    use super::{Provenance, Source, Verification};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Direction {
        Request,
        Response,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum WireProtocol {
        H1,
        H2,
        H3,
        Unknown,
    }

    /// State for **sequence and duplicates** of a header block.
    pub fn verification_for(
        source: Source,
        event: Option<&str>,
        direction: Direction,
        protocol: WireProtocol,
    ) -> Verification {
        use Direction::*;
        use Source::*;
        use WireProtocol::*;

        match (source, event) {
            // CDP does not expose the sequence transmitted in any of the `headers`
            // objects (ASCII order, duplicates collapsed, subset).
            (Cdp, Some("Network.responseReceivedExtraInfo.headersText")) => {
                if protocol == H1 || protocol == Unknown {
                    Verification::Verified
                } else {
                    Verification::Unverified
                }
            }
            (Cdp, Some(e)) if e.contains("ExtraInfo") || e.contains("requestWillBeSent") => {
                Verification::Unverified
            }
            (Cdp, _) => Verification::Unverified,

            // NetLog transactional: faithful in h1; in h2/h3 it preserves order, but
            // the Cookie field may come merged (not the wire split).
            (NetLog, Some(e))
                if e == "HTTP_TRANSACTION_SEND_REQUEST_HEADERS"
                    || e == "HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS"
                    || e == "HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS"
                    || e == "HTTP_TRANSACTION_READ_RESPONSE_HEADERS" =>
            {
                match (direction, protocol) {
                    (Request, H1) => Verification::Verified,
                    (Request, H2 | H3) => Verification::Partial,
                    (Response, H1 | H2 | H3) => Verification::Verified,
                    (_, Unknown) => Verification::Partial,
                }
            }

            // h2/h3 session events: order preserved, repetitions merged with NUL
            // (expanded by the importer), Cookie may be split only on the wire,
            // never in the log.
            (NetLog, Some(e))
                if e == "HTTP2_SESSION_SEND_HEADERS"
                    || e == "HTTP2_SESSION_RECV_HEADERS"
                    || e == "QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS"
                    || e == "QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS" =>
            {
                match direction {
                    Request => Verification::Partial,
                    Response => Verification::Partial,
                }
            }

            (NetLog, _) => Verification::Partial,

            // DevTools HAR was not instrumented; order not proven.
            (Har, _) => Verification::Unverified,

            // Own format carries the state recorded in the capture.
            (OwnFormat, _) | (Capture, _) | (Derived, _) | (Manual, _) => Verification::Unverified,
        }
    }

    pub fn provenance_for(
        source: Source,
        event: Option<&str>,
        direction: Direction,
        protocol: WireProtocol,
        method: &str,
        browser_version: Option<&str>,
    ) -> Provenance {
        let mut p = Provenance::new(
            source,
            method,
            verification_for(source, event, direction, protocol),
        );
        if let Some(event) = event {
            p = p.with_event(event);
        }
        if let Some(version) = browser_version {
            p = p.with_browser_version(version);
        }
        p
    }
}
