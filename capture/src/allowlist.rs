//! Allowlist de hosts da captura controlada (`docs/16b-mcp-navegador.md` §2.2).
//!
//! **Semântica oficial:** o navegador impõe o **host** (todas as portas); a
//! **porta** só é imposta em `navigate`. O Chrome não conhece porta na regra
//! do resolvedor, e não vamos interceptar a rede (`Fetch`) para impô-la, porque
//! isso altera a fidelidade da captura. Medido (Chrome 156): com
//! `localhost:P1` aprovado, a página alcança `localhost:P2` por 302, JS
//! `location`, meta refresh, `window.open`, iframe, fetch, WebSocket e host em
//! maiúsculas. Por isso a porta fora da lista é **reportada**, nunca bloqueada:
//! [`Allowlist::report_from_events`] varre os eventos CDP (não a sessão
//! importada, que perde WebSocket) e lista cada requisição, redirect, iframe,
//! popup e WebSocket para host/porta fora da lista.
//!
//! Duas camadas com a MESMA decisão de host:
//! 1. o Chrome recebe `--host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE …"` e
//!    não resolve nenhum nome nem IPv4 literal fora da lista (medido:
//!    `127.0.0.1`, `127.1`, `2130706433`, `[::1]`); vale para qualquer aba,
//!    iframe, worker ou cliente CDP;
//! 2. `permits_url` recusa antes de enviar `Page.navigate` (esquema, host,
//!    porta, userinfo).
//!
//! O analisador de URL é **mais estrito que o do Chrome de propósito**: tudo o
//! que for ambíguo (barra invertida, espaço, `@`, `%` no host, ponto final,
//! não-ASCII, IPv4 fora da forma canônica) é recusado, para que o que passa
//! aqui seja lido da mesma forma pelo Chrome. Sem a crate `url`, para não mexer
//! no `Cargo.toml` compartilhado. IPv6 literal não é aceito na lista (o
//! resolvedor não o trata de forma confiável).

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Serialize;

use scrapelens_core::model::SessionV1;

/// Um padrão de host: nome exato, curinga de subdomínio ou IP literal, com
/// porta opcional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPattern {
    /// Minúsculo, sem o `*.` inicial, sem colchetes.
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
    /// Nenhum host em `allowed_hosts`.
    Empty,
    /// `*`, `*.com`, curinga com IP… largo demais para ser uma allowlist.
    TooBroad(String),
    /// Texto que não é um host (esquema, caminho, `@`, espaço…).
    Invalid(String),
    /// IPv6 literal: o resolvedor do Chrome não o trata de forma confiável.
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
                write!(f, "allowed_hosts é obrigatório e precisa ter ao menos um host")
            }
            AllowlistError::TooBroad(p) => write!(f, "padrão largo demais: {p:?}"),
            AllowlistError::Invalid(p) => write!(f, "host inválido na allowlist: {p:?}"),
            AllowlistError::Unsupported(p) => write!(
                f,
                "IPv6 literal não é suportado na allowlist: {p:?} (use o nome do host ou um IPv4)"
            ),
        }
    }
}

impl std::error::Error for AllowlistError {}

/// Por que uma URL foi recusada.
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
            UrlDenied::Scheme(s) => write!(f, "esquema não permitido: {s:?} (só http e https)"),
            UrlDenied::Malformed(why) => write!(f, "URL recusada: {why}"),
            UrlDenied::Userinfo => write!(f, "URL com usuário/senha (userinfo) é recusada"),
            UrlDenied::HostNotAllowed(h) => write!(f, "host fora da allowlist: {h}"),
            UrlDenied::PortNotAllowed { host, port } => {
                write!(f, "porta {port} fora da allowlist para {host}")
            }
        }
    }
}

impl std::error::Error for UrlDenied {}

/// URL já validada: o que `navigate` pode enviar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedUrl {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// A URL original, sem alteração (só é aceita se for segura).
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

/// Resultado pós-captura (`stop_capture.allowlist`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowlistReport {
    /// Hosts que a página tentou carregar e o resolvedor negou
    /// (`ERR_NAME_NOT_RESOLVED`): evidência de terceiro necessário.
    pub blocked_hosts: Vec<BlockedHost>,
    /// Requisições a host/porta fora da lista que NÃO falharam na resolução
    /// (IP literal, porta diferente).
    pub violations: Vec<Violation>,
}

/// Decisão de host/porta para um alvo já separado em partes.
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

    /// Padrões em texto, para devolver ao chamador.
    pub fn allowed_hosts(&self) -> Vec<String> {
        self.allowed.iter().map(HostPattern::text).collect()
    }

    pub fn third_party_hosts(&self) -> Vec<String> {
        self.third_party.iter().map(HostPattern::text).collect()
    }

    /// Valor de `--host-resolver-rules`: nega tudo (nomes e IP literal),
    /// exceto o que está listado. A regra conhece só o host, nunca a porta.
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

    /// `navigate`: só `allowed_hosts` (e `about:blank`). Terceiros declarados
    /// carregam subrecursos, mas não são destino de navegação.
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

    /// Host (qualquer porta) em `allowed_hosts` ou `third_party_hosts`.
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

    /// Classifica uma URL já acontecida: `Blocked` (o resolvedor negou) ou
    /// `Violation` (host/porta fora da lista que NÃO falhou na resolução).
    fn classify(&self, url: &str, failure: Option<&str>, top_level: bool) -> Option<Classified> {
        let (scheme, host, port) = lenient_http_parts(url)?;
        let port = port.unwrap_or(if scheme == "https" || scheme == "wss" { 443 } else { 80 });
        let unresolved = failure.map(|f| f.contains("ERR_NAME_NOT_RESOLVED")).unwrap_or(false);
        match self.decide_any(&host, port) {
            Decision::Allowed => {
                // Host aprovado só como origem de subrecursos não é destino de
                // navegação de topo.
                if top_level
                    && decide(&self.allowed, &host, port) != Decision::Allowed
                    && decide(&self.third_party, &host, port) == Decision::Allowed
                {
                    return Some(Classified::Violation {
                        host,
                        reason: "navegação de topo para host aprovado só como terceiro (subrecursos)"
                            .to_string(),
                    });
                }
                None
            }
            _ if unresolved => Some(Classified::Blocked { host }),
            _ => {
                let reason = if self.host_allowed(&host) {
                    format!(
                        "porta {port} fora da allowlist (o navegador impõe o host, não a porta; só `navigate` a impõe)"
                    )
                } else if is_ip_literal(&host) {
                    "IP literal fora da allowlist".to_string()
                } else {
                    "host fora da allowlist sem falha de resolução".to_string()
                };
                Some(Classified::Violation { host, reason })
            }
        }
    }

    /// Relatório pós-captura sobre a sessão importada. Perde o que a
    /// importação não guarda (WebSocket); a captura usa
    /// [`Allowlist::report_from_events`].
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

    /// Relatório a partir dos eventos CDP gravados (`cdp-events.jsonl`): cada
    /// `Network.requestWillBeSent` (inclui cada salto de redirect, iframe e
    /// popup, que têm sessão própria) e cada `Network.webSocketCreated`. É a
    /// fonte completa; os ids viram os da sessão importada quando a requisição
    /// existe nela (`cdp.sessionId` + `cdp.requestId`), senão `cdp:<sessão>/<id>`.
    pub fn report_from_events(&self, events: &[String], session: &SessionV1) -> AllowlistReport {
        use serde_json::Value;
        // (sessionId, requestId) -> id lógico da sessão importada.
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
        let mut targets: HashMap<String, (String, String)> = HashMap::new(); // sessão -> (targetId, tipo)
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
            // A falha vale para o último salto do requestId.
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

/// URL sem credenciais, consulta, fragmento nem parâmetros de caminho
/// (`;jsessionid=…`): o que pode ir para avisos e relatórios sem vazar segredo.
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

/// Como o Chrome (WHATWG): se o ÚLTIMO rótulo é numérico (decimal ou `0x…`), o
/// host é lido como IPv4, inclusive formas curtas, hex e octal (`127.1`,
/// `2130706433`, `0x7f.0.0.1`). Qualquer uma que não seja `a.b.c.d` canônica é
/// recusada em vez de interpretada.
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
    // Separa a porta.
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
            return Err(invalid()); // IPv6 sem colchetes é ambíguo
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
        // Curinga precisa de pelo menos dois rótulos depois do `*.`
        // (`*.com` é largo demais; não há lista de sufixos públicos aqui).
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
        return Err(malformed("vazia"));
    }
    if raw.len() > 8192 {
        return Err(malformed("longa demais"));
    }
    if raw
        .bytes()
        .any(|b| b <= b' ' || b >= 0x7f || b == b'\\')
    {
        return Err(malformed(
            "contém espaço, controle, barra invertida ou caractere não ASCII",
        ));
    }
    let (scheme, rest) = raw
        .split_once(':')
        .ok_or_else(|| malformed("sem esquema"))?;
    let scheme_lower = scheme.to_ascii_lowercase();
    if scheme_lower != "http" && scheme_lower != "https" {
        return Err(UrlDenied::Scheme(scheme_lower));
    }
    let rest = rest
        .strip_prefix("//")
        .ok_or_else(|| malformed("esperado // depois do esquema"))?;
    let end = rest
        .find(['/', '?', '#'])
        .unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() {
        return Err(malformed("host vazio"));
    }
    if authority.contains('@') {
        return Err(UrlDenied::Userinfo);
    }
    let default_port = if scheme_lower == "https" { 443 } else { 80 };
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let close = inner.find(']').ok_or_else(|| malformed("IPv6 sem ]"))?;
        let host = inner[..close].to_ascii_lowercase();
        let tail = &inner[close + 1..];
        let port = match tail {
            "" => default_port,
            t if t.starts_with(':') => {
                parse_port(&t[1..]).ok_or_else(|| malformed("porta inválida"))?
            }
            _ => return Err(malformed("texto depois do IPv6")),
        };
        if !valid_ipv6_chars(&host) {
            return Err(malformed("IPv6 inválido"));
        }
        (host, port)
    } else {
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, parse_port(p).ok_or_else(|| malformed("porta inválida"))?),
            None => (authority, default_port),
        };
        let host = host.to_ascii_lowercase();
        if host.contains('%') || host.contains('*') {
            return Err(malformed("caractere inválido no host"));
        }
        if host.ends_with('.') {
            return Err(malformed("host com ponto final"));
        }
        if is_ipv4_shape(&host) {
            if !is_canonical_ipv4(&host) {
                return Err(malformed("IPv4 fora da forma canônica a.b.c.d"));
            }
        } else if !valid_dns_name(&host) {
            return Err(malformed("host inválido"));
        }
        (host, port)
    };
    Ok(StrictUrl {
        scheme: scheme_lower,
        host,
        port,
    })
}

/// Para o relatório: extrai (esquema, host, porta) de URLs http(s)/ws(s) sem
/// recusar nada (a sessão já aconteceu; só classificamos).
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
        // Só terceiros não basta: precisa de pelo menos um host de navegação.
        assert_eq!(
            Allowlist::new(&[], &list(&["cdn.exemplo.net"])).unwrap_err(),
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
            "http://exemplo.com",
            "exemplo.com/caminho",
            "user@exemplo.com",
            "exemplo.com.",
            "exe mplo.com",
            "exemplo.com:0",
            "exemplo.com:99999",
            "exemplo.com:abc",
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
        let a = al(&["exemplo.com", "*.api.exemplo.com", "loja.test:8443", "127.0.0.1:9000"], &[]);
        assert!(a.permits_url("https://exemplo.com/").is_ok());
        assert!(a.permits_url("HTTPS://EXEMPLO.COM/x?y=1#z").is_ok());
        assert!(a.permits_url("http://exemplo.com:8080/").is_ok(), "sem porta na regra = qualquer porta");
        assert!(a.permits_url("https://v1.api.exemplo.com/").is_ok());
        assert!(a.permits_url("https://a.b.api.exemplo.com/").is_ok());
        // O curinga não casa o domínio base nem sufixos parecidos.
        assert!(a.permits_url("https://api.exemplo.com/").is_err());
        assert!(a.permits_url("https://evilapi.exemplo.com/").is_err());
        assert!(a.permits_url("https://xapi.exemplo.com.evil.net/").is_err());
        assert!(a.permits_url("https://exemplo.com.evil.net/").is_err());
        assert!(a.permits_url("https://evil-exemplo.com/").is_err());
        // Porta explícita na regra.
        assert!(a.permits_url("https://loja.test:8443/").is_ok());
        assert_eq!(
            a.permits_url("https://loja.test/").unwrap_err(),
            UrlDenied::PortNotAllowed { host: "loja.test".into(), port: 443 }
        );
        assert!(a.permits_url("http://127.0.0.1:9000/").is_ok());
        assert!(a.permits_url("http://127.0.0.1:9001/").is_err());
        // IPv6 literal nunca está na lista.
        assert!(a.permits_url("http://[::1]/").is_err());
    }

    #[test]
    fn dangerous_url_shapes_are_denied() {
        let a = al(&["exemplo.com", "127.0.0.1"], &[]);
        let cases = [
            ("http://exemplo.com@evil.net/", "userinfo"),
            ("http://evil.net@exemplo.com/", "userinfo"),
            ("http://exemplo.com:80@evil.net/", "userinfo"),
            ("http://exemplo.com\\@evil.net/", "barra invertida"),
            ("http://exemplo.com\\.evil.net/", "barra invertida"),
            ("http://exemplo.com%2eevil.net/", "% no host"),
            ("http://exemplo.com./", "ponto final"),
            ("http://exemplo.com /", "espaço"),
            ("http://exemplo.com\t.evil.net/", "controle"),
            ("http://exemplo.com\n/", "controle"),
            ("http://exémplo.com/", "não ASCII"),
            ("http://127.1/", "IPv4 curto"),
            ("http://2130706433/", "IPv4 decimal"),
            ("http://0x7f.0.0.1/", "hex"),
            ("http://0177.0.0.1/", "octal"),
            ("http://127.0.0.1.evil.net/", "sufixo"),
            ("http:/exemplo.com/", "uma barra"),
            ("http:exemplo.com/", "sem //"),
            ("//exemplo.com/", "sem esquema"),
            ("exemplo.com/", "sem esquema"),
            ("http:///", "host vazio"),
            ("http://:80/", "host vazio com porta"),
            ("http://exemplo.com:/", "porta vazia"),
            ("http://exemplo.com:99999/", "porta grande"),
            ("javascript:alert(1)", "javascript"),
            ("data:text/html,<h1>x</h1>", "data"),
            ("file:///etc/passwd", "file"),
            ("chrome://settings", "chrome"),
            ("blob:http://exemplo.com/abc", "blob"),
            ("ftp://exemplo.com/", "ftp"),
            ("view-source:http://exemplo.com/", "view-source"),
            ("about:srcdoc", "about não blank"),
            ("", "vazia"),
        ];
        for (url, why) in cases {
            assert!(a.permits_url(url).is_err(), "{url} ({why}) devia ser recusada");
        }
        assert!(a.permits_url("about:blank").is_ok());
        assert_eq!(a.permits_url("http://exemplo.com@evil.net/").unwrap_err(), UrlDenied::Userinfo);
        assert!(matches!(a.permits_url("data:text/html,x").unwrap_err(), UrlDenied::Scheme(_)));
    }

    #[test]
    fn third_party_loads_subresources_but_is_not_a_navigation_target() {
        let a = al(&["site.test"], &["cdn.exemplo.net", "*.captcha.exemplo.net"]);
        assert!(a.host_allowed("cdn.exemplo.net"));
        assert!(a.host_allowed("x.captcha.exemplo.net"));
        assert!(!a.host_allowed("outro.net"));
        assert!(a.permits_url("https://site.test/").is_ok());
        assert_eq!(
            a.permits_url("https://cdn.exemplo.net/app.js").unwrap_err(),
            UrlDenied::HostNotAllowed("cdn.exemplo.net".into())
        );
        let rules = a.resolver_rules();
        assert_eq!(
            rules,
            "MAP * ~NOTFOUND, EXCLUDE site.test, EXCLUDE cdn.exemplo.net, EXCLUDE *.captcha.exemplo.net"
        );
    }

    #[test]
    fn resolver_rules_include_ipv4_literals_and_dedupe() {
        let a = al(&["127.0.0.1:8080", "exemplo.com", "exemplo.com:8443"], &["exemplo.com"]);
        // IPv4 literal precisa de EXCLUDE: sem ele `MAP * ~NOTFOUND` o nega (medido).
        assert_eq!(
            a.resolver_rules(),
            "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE exemplo.com"
        );
        assert_eq!(a.allowed_hosts(), vec!["127.0.0.1:8080", "exemplo.com", "exemplo.com:8443"]);
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
        add("r2", "https://challenges.exemplo.net/api.js", Some("net::ERR_NAME_NOT_RESOLVED"));
        add("r3", "https://challenges.exemplo.net/b.js", Some("net::ERR_NAME_NOT_RESOLVED"));
        add("r4", "http://10.1.2.3/x", Some("net::ERR_CONNECTION_REFUSED"));
        add("r5", "http://site.test:9999/", None);
        add("r6", "data:text/plain,hi", None);
        add("r7", "chrome-extension://abc/x.js", None);
        add("r8", "http://[fe80::1]:81/", None);
        let a = al(&["site.test:80"], &[]);
        let report = a.report(&session);
        assert_eq!(report.blocked_hosts.len(), 1);
        assert_eq!(report.blocked_hosts[0].host, "challenges.exemplo.net");
        assert_eq!(report.blocked_hosts[0].requests, 2);
        let ids: Vec<&str> = report.violations.iter().map(|v| v.request_id.as_str()).collect();
        assert_eq!(ids, vec!["r4", "r5", "r8"]);
        assert!(report.violations[0].reason.contains("IP literal"));
        assert!(report.violations[1].reason.contains("porta"));
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
            // 302 / location= / meta refresh: novo documento (ou salto) em outra porta.
            will_be_sent("P", "r1", "http://localhost:2000/redirected-top-level", "Document", "T1"),
            will_be_sent("P", "r9", "http://localhost:2000/meta-refresh", "Document", "T1"),
            // iframe em sessão própria, host em maiúsculas.
            event("I", "Target.attachedToTarget", serde_json::json!({ "sessionId": "I", "targetInfo": { "targetId": "TI", "type": "iframe" } })),
            will_be_sent("I", "r3", "http://LOCALHOST:2000/iframe-other-port", "Document", "TI"),
            // popup: página nova em outra sessão.
            event("W", "Target.attachedToTarget", serde_json::json!({ "sessionId": "W", "targetInfo": { "targetId": "TW", "type": "page" } })),
            will_be_sent("W", "r4", "http://localhost:2000/popup-other-port", "Document", "TW"),
            // fetch e WebSocket (este último nunca entra na sessão importada).
            will_be_sent("P", "r5", "http://localhost:2000/fetch-other-port", "Fetch", "T1"),
            event("P", "Network.webSocketCreated", serde_json::json!({ "requestId": "r6", "url": "ws://localhost:2000/ws-other-port" })),
            // consulta, fragmento, ;params e userinfo nunca saem.
            will_be_sent("P", "r7", "http://u:senha@localhost:2000/p;jsessionid=SEGREDO?token=X#frag", "Fetch", "T1"),
            // resolvedor: nome e IP literal negados => blockedHosts, não violações.
            will_be_sent("P", "r10", "https://blocked.test/a.js", "Script", "T1"),
            failed("P", "r10", "net::ERR_NAME_NOT_RESOLVED"),
            will_be_sent("P", "r11", "http://10.0.0.1:9/x", "Image", "T1"),
            failed("P", "r11", "net::ERR_NAME_NOT_RESOLVED"),
            // terceiro aprovado: subrecurso ok, navegação de topo é violação.
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
            assert!(urls.contains(&expected), "faltou {expected}: {urls:?}");
        }
        assert_eq!(urls.len(), 8, "{urls:?}");
        for v in &report.violations {
            assert!(!v.url.contains("SEGREDO") && !v.url.contains("senha") && !v.url.contains("frag"), "{}", v.url);
        }
        let by_url = |u: &str| report.violations.iter().find(|v| v.url == u).unwrap();
        assert!(by_url("http://localhost:2000/fetch-other-port").reason.contains("porta 2000"));
        assert!(by_url("https://cdn.test/landing").reason.contains("terceiro"));
        // O salto do redirect usa o id lógico da sessão; o WebSocket, o id CDP.
        assert_eq!(by_url("http://localhost:2000/redirected-top-level").request_id, "cdp-r0007");
        assert_eq!(by_url("ws://localhost:2000/ws-other-port").request_id, "cdp:P/r6");
        let blocked: Vec<&str> = report.blocked_hosts.iter().map(|b| b.host.as_str()).collect();
        assert_eq!(blocked, vec!["10.0.0.1", "blocked.test"]);
        // O que está dentro da lista não aparece.
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
