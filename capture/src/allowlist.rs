//! Host allowlist for controlled capture (`docs/16b-mcp-navegador.md` §2.2).
//!
//! **Official semantics:** the browser enforces the **host** (all ports); the
//! **port** is only enforced in `navigate`. Chrome does not know about ports in
//! the resolver rule, and we will not intercept the network (`Fetch`) to enforce
//! it, because that changes the fidelity of the capture. Measured (Chrome 156):
//! with `localhost:P1` approved, the page reaches `localhost:P2` via 302, JS
//! `location`, meta refresh, `window.open`, iframe, fetch, WebSocket and host in
//! uppercase. That is why a port outside the list is **reported**, never blocked:
//! [`Allowlist::report_from_events`] scans the CDP events (not the imported
//! session, which loses WebSocket) and lists each request, redirect, iframe,
//! popup and WebSocket to a host/port outside the list.
//!
//! Two layers with the SAME host decision:
//! 1. Chrome receives `--host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE …"` and
//!    does not resolve any name or literal IPv4 outside the list (measured:
//!    `127.0.0.1`, `127.1`, `2130706433`, `[::1]`); this applies to any tab,
//!    iframe, worker or CDP client;
//! 2. `permits_url` refuses before sending `Page.navigate` (scheme, host,
//!    port, userinfo).
//!
//! The URL parser is **stricter than Chrome's on purpose**: anything that is
//! ambiguous (backslash, space, `@`, `%` in the host, trailing dot, non-ASCII,
//! IPv4 outside the canonical form) is refused, so that what passes here is read
//! the same way by Chrome. No `url` crate, so as not to touch the shared
//! `Cargo.toml`. Literal IPv6 is not accepted in the list (the resolver does not
//! handle it reliably).

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Serialize;

use scrapelens_core::model::SessionV1;

/// A host pattern: exact name, subdomain wildcard or literal IP, with an
/// optional port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPattern {
    /// Lowercase, without the leading `*.`, without brackets.
    host: String,
    wildcard: bool,
    port: Option<u16>,
}

impl HostPattern {
    fn text(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let base = if self.wildcard {
            format!("*.{host}")
        } else {
            host
        };
        match self.port {
            Some(port) => format!("{base}:{port}"),
            None => base,
        }
    }

    fn matches_host(&self, host: &str) -> bool {
        if self.wildcard {
            host.len() > self.host.len() + 1
                && host.ends_with(&self.host)
                && host.as_bytes()[host.len() - self.host.len() - 1] == b'.'
        } else {
            host == self.host
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowlistError {
    /// No host in `allowed_hosts`.
    Empty,
    /// `*`, `*.com`, wildcard with IP… too broad to be an allowlist.
    TooBroad(String),
    /// Text that is not a host (scheme, path, `@`, space…).
    Invalid(String),
    /// Literal IPv6: Chrome's resolver does not handle it reliably.
    Unsupported(String),
}

impl AllowlistError {
    pub fn code(&self) -> &'static str {
        match self {
            AllowlistError::Empty => "allowlist_required",
            AllowlistError::TooBroad(_) => "allowlist_too_broad",
            AllowlistError::Invalid(_) => "allowlist_invalid",
            AllowlistError::Unsupported(_) => "allowlist_unsupported",
        }
    }
}

impl std::fmt::Display for AllowlistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AllowlistError::Empty => {
                write!(f, "allowed_hosts is required and must have at least one host")
            }
            AllowlistError::TooBroad(p) => write!(f, "pattern too broad: {p:?}"),
            AllowlistError::Invalid(p) => write!(f, "invalid host in the allowlist: {p:?}"),
            AllowlistError::Unsupported(p) => write!(
                f,
                "literal IPv6 is not supported in the allowlist: {p:?} (use the host name or an IPv4)"
            ),
        }
    }
}

impl std::error::Error for AllowlistError {}

/// Why a URL was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlDenied {
    Scheme(String),
    Malformed(String),
    Userinfo,
    HostNotAllowed(String),
    PortNotAllowed { host: String, port: u16 },
}

impl UrlDenied {
    pub fn code(&self) -> &'static str {
        "url_not_allowed"
    }
}

impl std::fmt::Display for UrlDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UrlDenied::Scheme(s) => write!(f, "scheme not allowed: {s:?} (only http and https)"),
            UrlDenied::Malformed(why) => write!(f, "URL refused: {why}"),
            UrlDenied::Userinfo => write!(f, "URL with user/password (userinfo) is refused"),
            UrlDenied::HostNotAllowed(h) => write!(f, "host outside the allowlist: {h}"),
            UrlDenied::PortNotAllowed { host, port } => {
                write!(f, "port {port} outside the allowlist for {host}")
            }
        }
    }
}

impl std::error::Error for UrlDenied {}

/// Validated URL: what `navigate` may send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedUrl {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// The original URL, unchanged (only accepted if safe).
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowlist {
    allowed: Vec<HostPattern>,
    third_party: Vec<HostPattern>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockedHost {
    pub host: String,
    pub requests: usize,
    pub example_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Violation {
    pub request_id: String,
    pub url: String,
    pub host: String,
    pub reason: String,
}

/// Post-capture result (`stop_capture.allowlist`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowlistReport {
    /// Hosts the page tried to load and the resolver denied
    /// (`ERR_NAME_NOT_RESOLVED`): evidence of a required third party.
    pub blocked_hosts: Vec<BlockedHost>,
    /// Requests to a host/port outside the list that did NOT fail resolution
    /// (literal IP, different port).
    pub violations: Vec<Violation>,
}

/// Host/port decision for a target already split into parts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    Allowed,
    HostDenied,
    PortDenied,
}

impl Allowlist {
    pub fn new(allowed_hosts: &[String], third_party_hosts: &[String]) -> Result<Self, AllowlistError> {
        if allowed_hosts.iter().all(|h| h.trim().is_empty()) {
            return Err(AllowlistError::Empty);
        }
        let parse_all = |items: &[String]| -> Result<Vec<HostPattern>, AllowlistError> {
            let mut out: Vec<HostPattern> = Vec::new();
            for item in items {
                let pattern = parse_pattern(item)?;
                if !out.contains(&pattern) {
                    out.push(pattern);
                }
            }
            Ok(out)
        };
        let allowed = parse_all(allowed_hosts)?;
        let third_party = parse_all(third_party_hosts)?;
        Ok(Self { allowed, third_party })
    }

    /// Patterns as text, to return to the caller.
    pub fn allowed_hosts(&self) -> Vec<String> {
        self.allowed.iter().map(HostPattern::text).collect()
    }

    pub fn third_party_hosts(&self) -> Vec<String> {
        self.third_party.iter().map(HostPattern::text).collect()
    }

    /// Value of `--host-resolver-rules`: denies everything (names and literal IP),
    /// except what is listed. The rule knows only the host, never the port.
    pub fn resolver_rules(&self) -> String {
        let mut rules = vec!["MAP * ~NOTFOUND".to_string()];
        let mut seen: Vec<String> = Vec::new();
        for pattern in self.allowed.iter().chain(self.third_party.iter()) {
            let name = if pattern.wildcard {
                format!("*.{}", pattern.host)
            } else {
                pattern.host.clone()
            };
            if !seen.contains(&name) {
                seen.push(name.clone());
                rules.push(format!("EXCLUDE {name}"));
            }
        }
        rules.join(", ")
    }

    /// `navigate`: only `allowed_hosts` (and `about:blank`). Declared third parties
    /// load subresources, but are not navigation targets.
    pub fn permits_url(&self, raw: &str) -> Result<AllowedUrl, UrlDenied> {
        if raw == "about:blank" {
            return Ok(AllowedUrl {
                scheme: "about".to_string(),
                host: String::new(),
                port: 0,
                url: raw.to_string(),
            });
        }
        let parsed = parse_url_strict(raw)?;
        match decide(&self.allowed, &parsed.host, parsed.port) {
            Decision::Allowed => Ok(AllowedUrl {
                scheme: parsed.scheme,
                host: parsed.host,
                port: parsed.port,
                url: raw.to_string(),
            }),
            Decision::HostDenied => Err(UrlDenied::HostNotAllowed(parsed.host)),
            Decision::PortDenied => Err(UrlDenied::PortNotAllowed {
                host: parsed.host,
                port: parsed.port,
            }),
        }
    }

    /// Host (any port) in `allowed_hosts` or `third_party_hosts`.
    pub fn host_allowed(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.allowed
            .iter()
            .chain(self.third_party.iter())
            .any(|p| p.matches_host(&host))
    }

    fn decide_any(&self, host: &str, port: u16) -> Decision {
        let a = decide(&self.allowed, host, port);
        let t = decide(&self.third_party, host, port);
        match (a, t) {
            (Decision::Allowed, _) | (_, Decision::Allowed) => Decision::Allowed,
            (Decision::PortDenied, _) | (_, Decision::PortDenied) => Decision::PortDenied,
            _ => Decision::HostDenied,
        }
    }

    /// Classifies a URL that already happened: `Blocked` (the resolver denied it) or
    /// `Violation` (host/port outside the list that did NOT fail resolution).
    fn classify(&self, url: &str, failure: Option<&str>, top_level: bool) -> Option<Classified> {
        let (scheme, host, port) = lenient_http_parts(url)?;
        let port = port.unwrap_or(if scheme == "https" || scheme == "wss" { 443 } else { 80 });
        let unresolved = failure.map(|f| f.contains("ERR_NAME_NOT_RESOLVED")).unwrap_or(false);
        match self.decide_any(&host, port) {
            Decision::Allowed => {
                // A host approved only as a subresource origin is not a top-level
                // navigation target.
                if top_level
                    && decide(&self.allowed, &host, port) != Decision::Allowed
                    && decide(&self.third_party, &host, port) == Decision::Allowed
                {
                    return Some(Classified::Violation {
                        host,
                        reason: "top-level navigation to a host approved only as a third party (subresources)"
                            .to_string(),
                    });
                }
                None
            }
            _ if unresolved => Some(Classified::Blocked { host }),
            _ => {
                let reason = if self.host_allowed(&host) {
                    format!(
                        "port {port} outside the allowlist (the browser enforces the host, not the port; only `navigate` enforces it)"
                    )
                } else if is_ip_literal(&host) {
                    "IP literal outside the allowlist".to_string()
                } else {
                    "host outside the allowlist without a resolution failure".to_string()
                };
                Some(Classified::Violation { host, reason })
            }
        }
    }

    /// Post-capture report over the imported session. Loses what the import does
    /// not keep (WebSocket); the capture uses [`Allowlist::report_from_events`].
    pub fn report(&self, session: &SessionV1) -> AllowlistReport {
        let mut out = ReportBuilder::default();
        for request in &session.requests {
            let mut urls: Vec<(&str, Option<&str>)> = Vec::new();
            if request.attempts.is_empty() {
                urls.push((request.url.as_str(), None));
            }
            for attempt in &request.attempts {
                urls.push((attempt.url.as_str(), attempt.failure.as_deref()));
            }
            for (url, failure) in urls {
                if let Some(c) = self.classify(url, failure, false) {
                    out.add(c, url, &request.id);
                }
            }
        }
        out.finish()
    }

    /// Report from the recorded CDP events (`cdp-events.jsonl`): each
    /// `Network.requestWillBeSent` (includes each redirect hop, iframe and popup,
    /// which have their own session) and each `Network.webSocketCreated`. It is
    /// the complete source; the ids become those of the imported session when the
    /// request exists there (`cdp.sessionId` + `cdp.requestId`), otherwise
    /// `cdp:<session>/<id>`.
    pub fn report_from_events(&self, events: &[String], session: &SessionV1) -> AllowlistReport {
        use serde_json::Value;
        // (sessionId, requestId) -> logical id of the imported session.
        let mut logical: HashMap<(String, String), String> = HashMap::new();
        for r in &session.requests {
            let refs = r.cdp.iter().chain(r.attempts.iter().filter_map(|a| a.cdp.as_ref()));
            for c in refs {
                if let (Some(sid), Some(rid)) = (&c.session_id, &c.request_id) {
                    logical.entry((sid.clone(), rid.clone())).or_insert_with(|| r.id.clone());
                }
            }
        }
        struct Hop {
            key: (String, String),
            url: String,
            top_level: bool,
        }
        let mut targets: HashMap<String, (String, String)> = HashMap::new(); // session -> (targetId, type)
        let mut hops: Vec<Hop> = Vec::new();
        let mut last_url: HashMap<(String, String), String> = HashMap::new();
        let mut failures: HashMap<(String, String), String> = HashMap::new();
        let mut seen: HashSet<(String, String, String)> = HashSet::new();
        for line in events {
            let Ok(v) = serde_json::from_str::<Value>(line) else { continue };
            let sid = v.get("sessionId").and_then(Value::as_str).unwrap_or("").to_string();
            let params = v.get("params").cloned().unwrap_or(Value::Null);
            let text = |p: &Value, k: &str| p.get(k).and_then(Value::as_str).unwrap_or("").to_string();
            match v.get("method").and_then(Value::as_str).unwrap_or("") {
                "Target.attachedToTarget" => {
                    let info = params.get("targetInfo").cloned().unwrap_or(Value::Null);
                    targets.insert(
                        text(&params, "sessionId"),
                        (text(&info, "targetId"), text(&info, "type")),
                    );
                }
                "Network.requestWillBeSent" => {
                    let rid = text(&params, "requestId");
                    let url = params
                        .get("request")
                        .map(|r| text(r, "url"))
                        .unwrap_or_default();
                    let top_level = text(&params, "type") == "Document"
                        && targets
                            .get(&sid)
                            .map(|(tid, ty)| ty == "page" && *tid == text(&params, "frameId"))
                            .unwrap_or(false);
                    if seen.insert((sid.clone(), rid.clone(), url.clone())) {
                        last_url.insert((sid.clone(), rid.clone()), url.clone());
                        hops.push(Hop { key: (sid, rid), url, top_level });
                    }
                }
                "Network.webSocketCreated" => {
                    let rid = text(&params, "requestId");
                    let url = text(&params, "url");
                    if seen.insert((sid.clone(), rid.clone(), url.clone())) {
                        last_url.insert((sid.clone(), rid.clone()), url.clone());
                        hops.push(Hop { key: (sid, rid), url, top_level: false });
                    }
                }
                "Network.loadingFailed" => {
                    failures.insert((sid, text(&params, "requestId")), text(&params, "errorText"));
                }
                _ => {}
            }
        }
        let mut out = ReportBuilder::default();
        for hop in hops {
            // The failure applies to the last hop of the requestId.
            let failure = if last_url.get(&hop.key) == Some(&hop.url) {
                failures.get(&hop.key).map(String::as_str)
            } else {
                None
            };
            if let Some(c) = self.classify(&hop.url, failure, hop.top_level) {
                let id = logical
                    .get(&hop.key)
                    .cloned()
                    .unwrap_or_else(|| format!("cdp:{}/{}", hop.key.0, hop.key.1));
                out.add(c, &hop.url, &id);
            }
        }
        out.finish()
    }
}

enum Classified {
    Blocked { host: String },
    Violation { host: String, reason: String },
}

#[derive(Default)]
struct ReportBuilder {
    blocked: BTreeMap<String, BlockedHost>,
    violations: Vec<Violation>,
}

impl ReportBuilder {
    fn add(&mut self, c: Classified, url: &str, request_id: &str) {
        match c {
            Classified::Blocked { host } => {
                let entry = self.blocked.entry(host.clone()).or_insert_with(|| BlockedHost {
                    host,
                    requests: 0,
                    example_url: redact_url(url),
                });
                entry.requests += 1;
            }
            Classified::Violation { host, reason } => self.violations.push(Violation {
                request_id: request_id.to_string(),
                url: redact_url(url),
                host,
                reason,
            }),
        }
    }

    fn finish(self) -> AllowlistReport {
        AllowlistReport {
            blocked_hosts: self.blocked.into_values().collect(),
            violations: self.violations,
        }
    }
}

/// URL without credentials, query, fragment or path parameters
/// (`;jsessionid=…`): what can go into warnings and reports without leaking a secret.
pub fn redact_url(url: &str) -> String {
    let cut = url.find(['?', '#']).unwrap_or(url.len());
    let had_tail = cut < url.len();
    let base = &url[..cut];
    let cleaned = match base.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, ""),
            };
            let authority = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
            let path = path
                .split('/')
                .map(|segment| segment.split(';').next().unwrap_or(""))
                .collect::<Vec<_>>()
                .join("/");
            format!("{scheme}://{authority}{path}")
        }
        None => base.split(';').next().unwrap_or("").to_string(),
    };
    if had_tail {
        format!("{cleaned}?…")
    } else {
        cleaned
    }
}

fn decide(patterns: &[HostPattern], host: &str, port: u16) -> Decision {
    let mut host_seen = false;
    for pattern in patterns {
        if pattern.matches_host(host) {
            host_seen = true;
            if pattern.port.map(|p| p == port).unwrap_or(true) {
                return Decision::Allowed;
            }
        }
    }
    if host_seen {
        Decision::PortDenied
    } else {
        Decision::HostDenied
    }
}

fn is_ip_literal(host: &str) -> bool {
    host.contains(':') || is_ipv4_shape(host)
}

/// Like Chrome (WHATWG): if the LAST label is numeric (decimal or `0x…`), the
/// host is read as IPv4, including short, hex and octal forms (`127.1`,
/// `2130706433`, `0x7f.0.0.1`). Any that is not canonical `a.b.c.d` is refused
/// instead of interpreted.
fn is_ipv4_shape(host: &str) -> bool {
    let last = host.rsplit('.').next().unwrap_or("");
    !last.is_empty()
        && (last.bytes().all(|b| b.is_ascii_digit())
            || last
                .strip_prefix("0x")
                .map(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
                .unwrap_or(false))
}

fn is_canonical_ipv4(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() == 4
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 3
                && l.bytes().all(|b| b.is_ascii_digit())
                && (l.len() == 1 || !l.starts_with('0'))
                && l.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
        })
}

fn valid_dns_name(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    })
}

fn valid_ipv6_chars(host: &str) -> bool {
    host.contains(':')
        && host
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
}

fn parse_pattern(raw: &str) -> Result<HostPattern, AllowlistError> {
    let text = raw.trim();
    let invalid = || AllowlistError::Invalid(raw.to_string());
    if text.is_empty() {
        return Err(invalid());
    }
    if text.bytes().any(|b| {
        b <= b' ' || b >= 0x7f || matches!(b, b'/' | b'\\' | b'?' | b'#' | b'@' | b'%')
    }) {
        return Err(invalid());
    }
    if text.contains("://") {
        return Err(invalid());
    }
    let lower = text.to_ascii_lowercase();
    if lower.starts_with('[') || lower.starts_with("*.[") || lower.matches(':').count() > 1 {
        return Err(AllowlistError::Unsupported(raw.to_string()));
    }
    // Split off the port.
    let (host_part, port) = if let Some(rest) = lower.strip_prefix('[') {
        let end = rest.find(']').ok_or_else(invalid)?;
        let host = &rest[..end];
        let tail = &rest[end + 1..];
        let port = match tail {
            "" => None,
            t if t.starts_with(':') => Some(parse_port(&t[1..]).ok_or_else(invalid)?),
            _ => return Err(invalid()),
        };
        (host.to_string(), port)
    } else if let Some((host, port)) = lower.rsplit_once(':') {
        if host.contains(':') {
            return Err(invalid()); // IPv6 without brackets is ambiguous
        }
        (host.to_string(), Some(parse_port(port).ok_or_else(invalid)?))
    } else {
        (lower.clone(), None)
    };
    if host_part == "*" {
        return Err(AllowlistError::TooBroad(raw.to_string()));
    }
    let (wildcard, host) = match host_part.strip_prefix("*.") {
        Some(rest) => (true, rest.to_string()),
        None => (false, host_part),
    };
    if host.contains('*') {
        return Err(invalid());
    }
    if host.ends_with('.') {
        return Err(invalid());
    }
    if host.contains(':') {
        if wildcard || !valid_ipv6_chars(&host) {
            return Err(if wildcard {
                AllowlistError::TooBroad(raw.to_string())
            } else {
                invalid()
            });
        }
    } else if is_ipv4_shape(&host) {
        if wildcard {
            return Err(AllowlistError::TooBroad(raw.to_string()));
        }
        if !is_canonical_ipv4(&host) {
            return Err(invalid());
        }
    } else {
        if !valid_dns_name(&host) {
            return Err(invalid());
        }
        // A wildcard needs at least two labels after the `*.`
        // (`*.com` is too broad; there is no public-suffix list here).
        if wildcard && !host.contains('.') {
            return Err(AllowlistError::TooBroad(raw.to_string()));
        }
    }
    Ok(HostPattern { host, wildcard, port })
}

fn parse_port(text: &str) -> Option<u16> {
    if text.is_empty() || text.len() > 5 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port: u32 = text.parse().ok()?;
    (1..=65535).contains(&port).then_some(port as u16)
}

struct StrictUrl {
    scheme: String,
    host: String,
    port: u16,
}

fn parse_url_strict(raw: &str) -> Result<StrictUrl, UrlDenied> {
    let malformed = |why: &str| UrlDenied::Malformed(why.to_string());
    if raw.is_empty() {
        return Err(malformed("empty"));
    }
    if raw.len() > 8192 {
        return Err(malformed("too long"));
    }
    if raw
        .bytes()
        .any(|b| b <= b' ' || b >= 0x7f || b == b'\\')
    {
        return Err(malformed(
            "contains a space, control character, backslash or non-ASCII character",
        ));
    }
    let (scheme, rest) = raw
        .split_once(':')
        .ok_or_else(|| malformed("no scheme"))?;
    let scheme_lower = scheme.to_ascii_lowercase();
    if scheme_lower != "http" && scheme_lower != "https" {
        return Err(UrlDenied::Scheme(scheme_lower));
    }
    let rest = rest
        .strip_prefix("//")
        .ok_or_else(|| malformed("expected // after the scheme"))?;
    let end = rest
        .find(['/', '?', '#'])
        .unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() {
        return Err(malformed("empty host"));
    }
    if authority.contains('@') {
        return Err(UrlDenied::Userinfo);
    }
    let default_port = if scheme_lower == "https" { 443 } else { 80 };
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let close = inner.find(']').ok_or_else(|| malformed("IPv6 without ]"))?;
        let host = inner[..close].to_ascii_lowercase();
        let tail = &inner[close + 1..];
        let port = match tail {
            "" => default_port,
            t if t.starts_with(':') => {
                parse_port(&t[1..]).ok_or_else(|| malformed("invalid port"))?
            }
            _ => return Err(malformed("text after IPv6")),
        };
        if !valid_ipv6_chars(&host) {
            return Err(malformed("invalid IPv6"));
        }
        (host, port)
    } else {
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, parse_port(p).ok_or_else(|| malformed("invalid port"))?),
            None => (authority, default_port),
        };
        let host = host.to_ascii_lowercase();
        if host.contains('%') || host.contains('*') {
            return Err(malformed("invalid character in host"));
        }
        if host.ends_with('.') {
            return Err(malformed("host with trailing dot"));
        }
        if is_ipv4_shape(&host) {
            if !is_canonical_ipv4(&host) {
                return Err(malformed("IPv4 not in canonical a.b.c.d form"));
            }
        } else if !valid_dns_name(&host) {
            return Err(malformed("invalid host"));
        }
        (host, port)
    };
    Ok(StrictUrl {
        scheme: scheme_lower,
        host,
        port,
    })
}

/// For the report: extracts (scheme, host, port) from http(s)/ws(s) URLs without
/// refusing anything (the session already happened; we only classify).
fn lenient_http_parts(url: &str) -> Option<(String, String, Option<u16>)> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https" | "ws" | "wss") {
        return None;
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let authority = authority.rsplit_once('@').map(|(_, a)| a).unwrap_or(authority);
    if let Some(inner) = authority.strip_prefix('[') {
        let close = inner.find(']')?;
        let port = inner[close + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok());
        return Some((scheme, inner[..close].to_ascii_lowercase(), port));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()),
        None => (authority, None),
    };
    if host.is_empty() {
        return None;
    }
    Some((scheme, host.to_ascii_lowercase(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn al(allowed: &[&str], third: &[&str]) -> Allowlist {
        Allowlist::new(&list(allowed), &list(third)).unwrap()
    }

    #[test]
    fn empty_allowlist_is_an_error() {
        assert_eq!(Allowlist::new(&[], &[]).unwrap_err(), AllowlistError::Empty);
        assert_eq!(
            Allowlist::new(&list(&["  ", ""]), &[]).unwrap_err().code(),
            "allowlist_required"
        );
        // Third parties alone are not enough: at least one navigation host is needed.
        assert_eq!(
            Allowlist::new(&[], &list(&["cdn.example.net"])).unwrap_err(),
            AllowlistError::Empty
        );
    }

    #[test]
    fn too_broad_and_invalid_patterns_are_rejected() {
        for broad in ["*", "*.com", "*.127.0.0.1"] {
            let err = Allowlist::new(&list(&[broad]), &[]).unwrap_err();
            assert_eq!(err.code(), "allowlist_too_broad", "{broad}");
        }
        for v6 in ["::1", "[::1]", "*.[::1]", "[::1]:8080", "[fe80::1]"] {
            let err = Allowlist::new(&list(&[v6]), &[]).unwrap_err();
            assert_eq!(err.code(), "allowlist_unsupported", "{v6}: {err:?}");
            assert!(err.to_string().contains("IPv6"), "{err}");
        }
        for bad in [
            "http://example.com",
            "example.com/caminho",
            "user@example.com",
            "example.com.",
            "exe mplo.com",
            "example.com:0",
            "example.com:99999",
            "example.com:abc",
            "ex*mplo.com",
            "127.1",
            "2130706433",
            "0x7f.0.0.1",
            "256.1.1.1",
            "01.2.3.4",
            "exémplo.com",
            "-a.com",
            "a..com",
        ] {
            let err = Allowlist::new(&list(&[bad]), &[]).unwrap_err();
            assert_eq!(err.code(), "allowlist_invalid", "{bad}: {err:?}");
        }
    }

    #[test]
    fn exact_wildcard_and_port_matching() {
        let a = al(&["example.com", "*.api.example.com", "loja.test:8443", "127.0.0.1:9000"], &[]);
        assert!(a.permits_url("https://example.com/").is_ok());
        assert!(a.permits_url("HTTPS://EXAMPLE.COM/x?y=1#z").is_ok());
        assert!(a.permits_url("http://example.com:8080/").is_ok(), "no port in the rule = any port");
        assert!(a.permits_url("https://v1.api.example.com/").is_ok());
        assert!(a.permits_url("https://a.b.api.example.com/").is_ok());
        // The wildcard matches neither the base domain nor similar suffixes.
        assert!(a.permits_url("https://api.example.com/").is_err());
        assert!(a.permits_url("https://evilapi.example.com/").is_err());
        assert!(a.permits_url("https://xapi.example.com.evil.net/").is_err());
        assert!(a.permits_url("https://example.com.evil.net/").is_err());
        assert!(a.permits_url("https://evil-example.com/").is_err());
        // Explicit port in the rule.
        assert!(a.permits_url("https://loja.test:8443/").is_ok());
        assert_eq!(
            a.permits_url("https://loja.test/").unwrap_err(),
            UrlDenied::PortNotAllowed { host: "loja.test".into(), port: 443 }
        );
        assert!(a.permits_url("http://127.0.0.1:9000/").is_ok());
        assert!(a.permits_url("http://127.0.0.1:9001/").is_err());
        // Literal IPv6 is never in the list.
        assert!(a.permits_url("http://[::1]/").is_err());
    }

    #[test]
    fn dangerous_url_shapes_are_denied() {
        let a = al(&["example.com", "127.0.0.1"], &[]);
        let cases = [
            ("http://example.com@evil.net/", "userinfo"),
            ("http://evil.net@example.com/", "userinfo"),
            ("http://example.com:80@evil.net/", "userinfo"),
            ("http://example.com\\@evil.net/", "backslash"),
            ("http://example.com\\.evil.net/", "backslash"),
            ("http://example.com%2eevil.net/", "% in host"),
            ("http://example.com./", "trailing dot"),
            ("http://example.com /", "space"),
            ("http://example.com\t.evil.net/", "control"),
            ("http://example.com\n/", "control"),
            ("http://exémplo.com/", "non-ASCII"),
            ("http://127.1/", "short IPv4"),
            ("http://2130706433/", "decimal IPv4"),
            ("http://0x7f.0.0.1/", "hex"),
            ("http://0177.0.0.1/", "octal"),
            ("http://127.0.0.1.evil.net/", "suffix"),
            ("http:/example.com/", "one slash"),
            ("http:example.com/", "no //"),
            ("//example.com/", "no scheme"),
            ("example.com/", "no scheme"),
            ("http:///", "empty host"),
            ("http://:80/", "empty host with port"),
            ("http://example.com:/", "empty port"),
            ("http://example.com:99999/", "port too large"),
            ("javascript:alert(1)", "javascript"),
            ("data:text/html,<h1>x</h1>", "data"),
            ("file:///etc/passwd", "file"),
            ("chrome://settings", "chrome"),
            ("blob:http://example.com/abc", "blob"),
            ("ftp://example.com/", "ftp"),
            ("view-source:http://example.com/", "view-source"),
            ("about:srcdoc", "about not blank"),
            ("", "empty"),
        ];
        for (url, why) in cases {
            assert!(a.permits_url(url).is_err(), "{url} ({why}) should be refused");
        }
        assert!(a.permits_url("about:blank").is_ok());
        assert_eq!(a.permits_url("http://example.com@evil.net/").unwrap_err(), UrlDenied::Userinfo);
        assert!(matches!(a.permits_url("data:text/html,x").unwrap_err(), UrlDenied::Scheme(_)));
    }

    #[test]
    fn third_party_loads_subresources_but_is_not_a_navigation_target() {
        let a = al(&["site.test"], &["cdn.example.net", "*.captcha.example.net"]);
        assert!(a.host_allowed("cdn.example.net"));
        assert!(a.host_allowed("x.captcha.example.net"));
        assert!(!a.host_allowed("other.net"));
        assert!(a.permits_url("https://site.test/").is_ok());
        assert_eq!(
            a.permits_url("https://cdn.example.net/app.js").unwrap_err(),
            UrlDenied::HostNotAllowed("cdn.example.net".into())
        );
        let rules = a.resolver_rules();
        assert_eq!(
            rules,
            "MAP * ~NOTFOUND, EXCLUDE site.test, EXCLUDE cdn.example.net, EXCLUDE *.captcha.example.net"
        );
    }

    #[test]
    fn resolver_rules_include_ipv4_literals_and_dedupe() {
        let a = al(&["127.0.0.1:8080", "example.com", "example.com:8443"], &["example.com"]);
        // A literal IPv4 needs EXCLUDE: without it `MAP * ~NOTFOUND` denies it (measured).
        assert_eq!(
            a.resolver_rules(),
            "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE example.com"
        );
        assert_eq!(a.allowed_hosts(), vec!["127.0.0.1:8080", "example.com", "example.com:8443"]);
    }

    #[test]
    fn report_separates_blocked_hosts_from_violations() {
        use scrapelens_core::model::{Attempt, LogicalRequest, SessionMeta, SessionV1, BrowserInfo};
        let mut session = SessionV1::new(SessionMeta::new(
            "t",
            "2026-10-31T00:00:00Z",
            BrowserInfo::default(),
        ));
        let mut add = |id: &str, url: &str, failure: Option<&str>| {
            let mut r = LogicalRequest::new(id, url, "GET");
            let mut at = Attempt::new(format!("{id}.a1"), id, 0, url, "GET");
            at.failure = failure.map(str::to_string);
            r.attempts.push(at);
            session.requests.push(r);
        };
        add("r1", "http://site.test/", None);
        add("r2", "https://challenges.example.net/api.js", Some("net::ERR_NAME_NOT_RESOLVED"));
        add("r3", "https://challenges.example.net/b.js", Some("net::ERR_NAME_NOT_RESOLVED"));
        add("r4", "http://10.1.2.3/x", Some("net::ERR_CONNECTION_REFUSED"));
        add("r5", "http://site.test:9999/", None);
        add("r6", "data:text/plain,hi", None);
        add("r7", "chrome-extension://abc/x.js", None);
        add("r8", "http://[fe80::1]:81/", None);
        let a = al(&["site.test:80"], &[]);
        let report = a.report(&session);
        assert_eq!(report.blocked_hosts.len(), 1);
        assert_eq!(report.blocked_hosts[0].host, "challenges.example.net");
        assert_eq!(report.blocked_hosts[0].requests, 2);
        let ids: Vec<&str> = report.violations.iter().map(|v| v.request_id.as_str()).collect();
        assert_eq!(ids, vec!["r4", "r5", "r8"]);
        assert!(report.violations[0].reason.contains("IP literal"));
        assert!(report.violations[1].reason.contains("port"));
    }

    fn event(sid: &str, method: &str, params: serde_json::Value) -> String {
        serde_json::json!({ "sessionId": sid, "method": method, "params": params }).to_string()
    }

    fn will_be_sent(sid: &str, rid: &str, url: &str, kind: &str, frame: &str) -> String {
        event(
            sid,
            "Network.requestWillBeSent",
            serde_json::json!({ "requestId": rid, "type": kind, "frameId": frame, "request": { "url": url } }),
        )
    }

    fn failed(sid: &str, rid: &str, text: &str) -> String {
        event(sid, "Network.loadingFailed", serde_json::json!({ "requestId": rid, "errorText": text }))
    }

    #[test]
    fn port_gap_is_reported_for_every_path_from_cdp_events() {
        use scrapelens_core::model::{BrowserInfo, CdpRef, LogicalRequest, SessionMeta, SessionV1};
        let a = al(&["localhost:1000"], &["cdn.test"]);
        let events = vec![
            event("P", "Target.attachedToTarget", serde_json::json!({ "sessionId": "P", "targetInfo": { "targetId": "T1", "type": "page" } })),
            will_be_sent("P", "r1", "http://localhost:1000/", "Document", "T1"),
            // 302 / location= / meta refresh: new document (or hop) on another port.
            will_be_sent("P", "r1", "http://localhost:2000/redirected-top-level", "Document", "T1"),
            will_be_sent("P", "r9", "http://localhost:2000/meta-refresh", "Document", "T1"),
            // iframe in its own session, host in uppercase.
            event("I", "Target.attachedToTarget", serde_json::json!({ "sessionId": "I", "targetInfo": { "targetId": "TI", "type": "iframe" } })),
            will_be_sent("I", "r3", "http://LOCALHOST:2000/iframe-other-port", "Document", "TI"),
            // popup: new page in another session.
            event("W", "Target.attachedToTarget", serde_json::json!({ "sessionId": "W", "targetInfo": { "targetId": "TW", "type": "page" } })),
            will_be_sent("W", "r4", "http://localhost:2000/popup-other-port", "Document", "TW"),
            // fetch and WebSocket (the latter never enters the imported session).
            will_be_sent("P", "r5", "http://localhost:2000/fetch-other-port", "Fetch", "T1"),
            event("P", "Network.webSocketCreated", serde_json::json!({ "requestId": "r6", "url": "ws://localhost:2000/ws-other-port" })),
            // query, fragment, ;params and userinfo never leave.
            will_be_sent("P", "r7", "http://u:senha@localhost:2000/p;jsessionid=SEGREDO?token=X#frag", "Fetch", "T1"),
            // resolver: name and literal IP denied => blockedHosts, not violations.
            will_be_sent("P", "r10", "https://blocked.test/a.js", "Script", "T1"),
            failed("P", "r10", "net::ERR_NAME_NOT_RESOLVED"),
            will_be_sent("P", "r11", "http://10.0.0.1:9/x", "Image", "T1"),
            failed("P", "r11", "net::ERR_NAME_NOT_RESOLVED"),
            // approved third party: subresource ok, top-level navigation is a violation.
            will_be_sent("P", "r12", "https://cdn.test/app.js", "Script", "T1"),
            will_be_sent("P", "r13", "https://cdn.test/landing", "Document", "T1"),
        ];
        let mut session = SessionV1::new(SessionMeta::new("s", "2026-10-31T00:00:00Z", BrowserInfo::default()));
        let mut mapped = LogicalRequest::new("cdp-r0007", "http://localhost:2000/redirected-top-level", "GET");
        mapped.cdp = Some(CdpRef { session_id: Some("P".into()), request_id: Some("r1".into()), ..CdpRef::default() });
        session.requests.push(mapped);
        let report = a.report_from_events(&events, &session);
        let urls: Vec<&str> = report.violations.iter().map(|v| v.url.as_str()).collect();
        for expected in [
            "http://localhost:2000/redirected-top-level",
            "http://localhost:2000/meta-refresh",
            "http://LOCALHOST:2000/iframe-other-port",
            "http://localhost:2000/popup-other-port",
            "http://localhost:2000/fetch-other-port",
            "ws://localhost:2000/ws-other-port",
            "http://localhost:2000/p?…",
            "https://cdn.test/landing",
        ] {
            assert!(urls.contains(&expected), "missing {expected}: {urls:?}");
        }
        assert_eq!(urls.len(), 8, "{urls:?}");
        for v in &report.violations {
            assert!(!v.url.contains("SEGREDO") && !v.url.contains("senha") && !v.url.contains("frag"), "{}", v.url);
        }
        let by_url = |u: &str| report.violations.iter().find(|v| v.url == u).unwrap();
        assert!(by_url("http://localhost:2000/fetch-other-port").reason.contains("port 2000"));
        assert!(by_url("https://cdn.test/landing").reason.contains("third party"));
        // The redirect hop uses the session's logical id; the WebSocket, the CDP id.
        assert_eq!(by_url("http://localhost:2000/redirected-top-level").request_id, "cdp-r0007");
        assert_eq!(by_url("ws://localhost:2000/ws-other-port").request_id, "cdp:P/r6");
        let blocked: Vec<&str> = report.blocked_hosts.iter().map(|b| b.host.as_str()).collect();
        assert_eq!(blocked, vec!["10.0.0.1", "blocked.test"]);
        // What is inside the list does not appear.
        assert!(!urls.iter().any(|u| *u == "http://localhost:1000/" || u.contains("cdn.test/app.js")));
    }

    #[test]
    fn host_without_port_in_the_list_allows_every_port_and_redact_url_cleans() {
        let a = al(&["localhost"], &[]);
        let events = vec![will_be_sent("P", "r1", "http://localhost:31337/x", "Fetch", "T")];
        let session = scrapelens_core::model::SessionV1::new(scrapelens_core::model::SessionMeta::new(
            "s",
            "2026-10-31T00:00:00Z",
            scrapelens_core::model::BrowserInfo::default(),
        ));
        assert!(a.report_from_events(&events, &session).violations.is_empty());
        assert_eq!(redact_url("https://a:b@x.test:8443/p/q;jsessionid=Z/r?t=1#f"), "https://x.test:8443/p/q/r?…");
        assert_eq!(redact_url("https://x.test/a"), "https://x.test/a");
        assert_eq!(redact_url("https://x.test/a#access_token=Z"), "https://x.test/a?…");
    }
}
