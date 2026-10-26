//! Protocol-neutral request/response shapes and the shared endpoint handler.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    H1,
    H2,
    H3,
}

impl Proto {
    pub fn id(self) -> &'static str {
        match self {
            Proto::H1 => "http/1.1",
            Proto::H2 => "h2",
            Proto::H3 => "h3",
        }
    }

    /// Human readable description of where the header order was observed.
    pub fn decode_point(self) -> &'static str {
        match self {
            Proto::H1 => {
                "raw socket bytes: request head split on CRLF, order, casing and duplicates preserved verbatim"
            }
            Proto::H2 => {
                "HPACK decoded field list (httlib-hpack 0.1.3), recorded in decode order before any map is built"
            }
            Proto::H3 => {
                "QPACK decoded field list from quiche 0.30 h3 Event::Headers (Vec<Header>, decode order); quiche does not expose the raw QPACK field section"
            }
        }
    }

    pub fn wire(self) -> &'static str {
        match self {
            Proto::H1 => "HTTP/1.1 over TCP",
            Proto::H2 => "HTTP/2 over TLS (ALPN h2)",
            Proto::H3 => "HTTP/3 over QUIC (ALPN h3)",
        }
    }
}

/// A request as observed by a server, with the header list in decoded order.
#[derive(Debug, Clone)]
pub struct Req {
    pub proto: Proto,
    pub conn: String,
    pub stream: Option<u64>,
    pub method: String,
    pub target: String,
    pub authority: Option<String>,
    /// Full decoded field list, pseudo-fields included, in decode order.
    pub headers: Vec<(String, String)>,
    /// Exact request head bytes (HTTP/1.1 only), terminator included.
    pub raw_head: Option<Vec<u8>>,
    /// Raw HPACK block (HTTP/2 only).
    pub header_block: Option<Vec<u8>>,
    pub body: Vec<u8>,
    pub body_truncated: bool,
    pub body_framing: Option<String>,
    pub notes: Vec<String>,
}

impl Req {
    pub fn pseudoheaders(&self) -> Vec<(String, String)> {
        self.headers
            .iter()
            .filter(|(n, _)| n.starts_with(':'))
            .cloned()
            .collect()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Path portion of the request target (without query string).
    pub fn path(&self) -> &str {
        let t = self.target.as_str();
        match t.find('?') {
            Some(i) => &t[..i],
            None => t,
        }
    }

    pub fn query(&self) -> Option<&str> {
        self.target.find('?').map(|i| &self.target[i + 1..])
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Resp {
    pub status: u16,
    /// Response headers in the order they must be written on the wire.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body,
        }
    }

    pub fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_string(), value.into()));
        self
    }

    pub fn json(status: u16, value: &serde_json::Value) -> Self {
        let body = serde_json::to_vec_pretty(value).unwrap_or_default();
        Self::new(status, body).header("content-type", "application/json; charset=utf-8")
    }

    pub fn text(status: u16, value: impl Into<String>) -> Self {
        Self::new(status, value.into().into_bytes())
            .header("content-type", "text/plain; charset=utf-8")
    }

    pub fn reason(&self) -> &'static str {
        match self.status {
            200 => "OK",
            204 => "No Content",
            302 => "Found",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            413 => "Payload Too Large",
            500 => "Internal Server Error",
            _ => "OK",
        }
    }
}

/// Header names on the wire for HTTP/2 and HTTP/3 must be lowercase.
pub fn lowercase_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(n, v)| (n.to_ascii_lowercase(), v.clone()))
        .collect()
}
