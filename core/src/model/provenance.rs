use serde::{Deserialize, Serialize};

/// Origem de um dado. `Derived` marca visões calculadas (normalização, diff,
/// export); `Manual` marca correção feita pelo usuário.
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

/// Estado de verificação **por informação**, nunca por sessão.
///
/// - `Verified`: a sequência/valor foi conferida contra a camada decodificada;
/// - `Partial`: preserva parte da informação (ex.: ordem h2/h3, `Cookie` fundido);
/// - `Unverified`: a fonte não comprova o que foi pedido (ex.: HAR, CDP
///   `requestWillBeSent.headers` para sequência) ou não há evidência.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Verification {
    Unverified,
    Partial,
    Verified,
}

impl Verification {
    /// O estado mais fraco entre dois. Usado ao agregar proveniências.
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

impl Default for Verification {
    fn default() -> Self {
        Verification::Unverified
    }
}

/// Proveniência de uma unidade de informação (par de header, cookie, corpo,
/// entidade). Campos ausentes significam "a fonte não forneceu".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    pub source: Source,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    /// Identificador na fonte (requestId CDP, source id NetLog, índice HAR).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    /// Timestamp da fonte em segundos (monotônico CDP ou `time` do NetLog).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<f64>,
    /// Instante absoluto, quando a fonte fornece.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_version: Option<String>,
    /// Como o dado foi obtido (ex.: `headersText`, `netlog.headers`,
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

    /// Só grava timestamp quando a fonte o fornece (nunca inventa 0.0).
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

    /// Proveniência de uma associação heurística (nunca silenciosa).
    pub fn heuristic(method: impl Into<String>, verification: Verification) -> Self {
        Self::new(Source::Derived, method, verification)
    }
}

/// Política de verificação derivada de `docs/02-matriz-fidelidade.md` (D2).
///
/// A matriz é a fonte dos fatos; esta função só codifica o veredito para que
/// os importadores não inventem "verified" onde a evidência é parcial.
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

    /// Estado para **sequência e duplicatas** de um bloco de headers.
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
            // CDP não expõe a sequência transmitida em nenhum dos objetos
            // `headers` (ordem ASCII, duplicatas colapsadas, subconjunto).
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

            // NetLog transacional: fiel em h1; em h2/h3 preserva ordem, mas o
            // campo Cookie pode vir fundido (não a divisão do fio).
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

            // Eventos de sessão h2/h3: ordem preservada, repetições fundidas
            // com NUL (expandidas pelo importador), Cookie pode estar dividido
            // apenas no fio — nunca no log.
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

            // HAR do DevTools não foi instrumentado; ordem não comprovada.
            (Har, _) => Verification::Unverified,

            // Formato próprio carrega o estado gravado na captura.
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
