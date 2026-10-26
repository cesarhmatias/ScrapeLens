//! Visões normalizadas **derivadas** para busca/comparação.
//!
//! Nada aqui substitui o original: o header bruto permanece em
//! `HeaderView.headers`/`pseudoHeaders`. A visão normalizada agrupa por nome
//! (case-insensitive), preserva todos os valores na ordem de ocorrência e
//! mantém a ordem de primeira aparição — nunca ordena alfabeticamente em
//! silêncio. `order` é explicitamente `notWireOrder`.

use serde::{Deserialize, Serialize};

use crate::model::{
    CookieField, HeaderView, LogicalRequest, SetCookieRecord, Verification,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedHeader {
    /// Nome em minúsculas, usado para busca.
    pub name: String,
    /// Primeira grafia observada, para exibição.
    pub display_name: String,
    /// Todos os valores, na ordem de ocorrência; duplicatas preservadas.
    pub values: Vec<String>,
    #[serde(default)]
    pub occurrences: usize,
    /// Estado mais fraco entre as ocorrências.
    pub verification: Verification,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedHeaders {
    pub entries: Vec<NormalizedHeader>,
    /// Sempre `notWireOrder`: a visão não representa o fio.
    pub order: String,
    #[serde(default)]
    pub pseudo_headers: Vec<NormalizedHeader>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl NormalizedHeaders {
    pub fn get(&self, name: &str) -> Option<&NormalizedHeader> {
        let name = name.to_ascii_lowercase();
        self.entries
            .iter()
            .chain(self.pseudo_headers.iter())
            .find(|entry| entry.name == name)
    }

    pub fn values(&self, name: &str) -> Vec<String> {
        self.get(name)
            .map(|entry| entry.values.clone())
            .unwrap_or_default()
    }

    pub fn total_occurrences(&self) -> usize {
        self.entries
            .iter()
            .chain(self.pseudo_headers.iter())
            .map(|entry| entry.occurrences)
            .sum()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedQueryPair {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedUrl {
    pub original: String,
    pub canonical: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub path: String,
    /// Pares na ordem original; duplicatas de nome preservadas.
    #[serde(default)]
    pub query: Vec<NormalizedQueryPair>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedCookie {
    pub name: String,
    pub values: Vec<String>,
    pub occurrences: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedCookies {
    #[serde(default)]
    pub entries: Vec<NormalizedCookie>,
    #[serde(default)]
    pub raw_field_count: usize,
    #[serde(default)]
    pub wire_field_count: usize,
    #[serde(default)]
    pub wire_fragmented: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedSetCookie {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default)]
    pub secure: bool,
    #[serde(default)]
    pub http_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_site: Option<String>,
}

/// Visão derivada de uma requisição lógica. Não é persistida por cima do
/// documento v1; é calculada quando a UI precisa buscar/filtrar.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedRequest {
    pub request_id: String,
    pub method: String,
    pub url: NormalizedUrl,
    pub request_headers: NormalizedHeaders,
    pub response_headers: NormalizedHeaders,
    pub cookies: NormalizedCookies,
    #[serde(default)]
    pub set_cookies: Vec<NormalizedSetCookie>,
    /// Marca inequívoca de que a ordem não é a do fio.
    pub derived: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

pub fn normalize_request(request: &LogicalRequest) -> NormalizedRequest {
    NormalizedRequest {
        request_id: request.id.clone(),
        method: request.method.clone(),
        url: normalize_url(&request.url),
        request_headers: normalize_headers(&request.request_headers),
        response_headers: normalize_headers(&request.response_headers),
        cookies: normalize_cookies(&request.cookie),
        set_cookies: request
            .set_cookies
            .iter()
            .map(normalize_set_cookie)
            .collect(),
        derived: true,
        notes: vec![
            "visão derivada: agrupa por nome e não representa a ordem transmitida".to_string(),
        ],
    }
}

pub fn normalize_headers(view: &HeaderView) -> NormalizedHeaders {
    let mut entries: Vec<NormalizedHeader> = Vec::new();
    let mut pseudo_headers: Vec<NormalizedHeader> = Vec::new();
    for entry in view.iter_all() {
        let name = entry.name.to_ascii_lowercase();
        let bucket = if entry.is_pseudo() {
            &mut pseudo_headers
        } else {
            &mut entries
        };
        match bucket.iter_mut().find(|candidate| candidate.name == name) {
            Some(existing) => {
                existing.values.push(entry.value.clone());
                existing.occurrences += 1;
                existing.verification = existing.verification.weakest(entry.provenance.verification);
            }
            None => bucket.push(NormalizedHeader {
                name,
                display_name: entry.name.clone(),
                values: vec![entry.value.clone()],
                occurrences: 1,
                verification: entry.provenance.verification,
            }),
        }
    }
    let mut headers = NormalizedHeaders {
        entries,
        order: "notWireOrder".to_string(),
        pseudo_headers,
        notes: view.notes.clone(),
    };
    if view.order_state == crate::model::OrderState::SourceOrder {
        headers.notes.push(
            "original preserva a ordem da fonte; esta visão agrupa por nome".to_string(),
        );
    }
    headers
}

pub fn normalize_url(url: &str) -> NormalizedUrl {
    let original = url.to_string();
    let (without_fragment, fragment) = match url.split_once('#') {
        Some((left, right)) => (left, Some(right.to_string())),
        None => (url, None),
    };
    let (scheme, rest) = match without_fragment.split_once("://") {
        Some((scheme, rest)) => (Some(scheme.to_ascii_lowercase()), rest),
        None => (None, without_fragment),
    };
    let (authority, path_and_query) = match rest.split_once('/') {
        Some((authority, rest)) => (authority, format!("/{rest}")),
        None => (rest, "/".to_string()),
    };
    let (host, port, _userinfo) = split_authority(authority);
    let (path, query) = match path_and_query.split_once('?') {
        Some((path, query)) => (path.to_string(), parse_query(query)),
        None => (path_and_query, Vec::new()),
    };
    NormalizedUrl {
        canonical: canonical_url(url),
        original,
        scheme,
        host,
        port,
        path,
        query,
        fragment,
    }
}

pub fn normalize_cookies(cookie: &CookieField) -> NormalizedCookies {
    let mut entries: Vec<NormalizedCookie> = Vec::new();
    for pair in &cookie.pairs {
        match entries.iter_mut().find(|entry| entry.name == pair.name) {
            Some(existing) => {
                existing.values.push(pair.value.clone());
                existing.occurrences += 1;
            }
            None => entries.push(NormalizedCookie {
                name: pair.name.clone(),
                values: vec![pair.value.clone()],
                occurrences: 1,
            }),
        }
    }
    NormalizedCookies {
        entries,
        raw_field_count: cookie.raw.len(),
        wire_field_count: cookie.wire_lines.len(),
        wire_fragmented: cookie.wire_is_fragmented(),
        notes: cookie.notes.clone(),
    }
}

fn normalize_set_cookie(record: &SetCookieRecord) -> NormalizedSetCookie {
    match &record.parsed {
        Some(parsed) => NormalizedSetCookie {
            name: parsed.name.clone(),
            domain: parsed.domain.clone(),
            path: parsed.path.clone(),
            secure: parsed.secure,
            http_only: parsed.http_only,
            same_site: parsed.same_site.clone(),
        },
        None => NormalizedSetCookie {
            name: record.raw.split('=').next().unwrap_or("").trim().to_string(),
            domain: None,
            path: None,
            secure: false,
            http_only: false,
            same_site: None,
        },
    }
}

/// Normalização de URL usada por busca e correlação. Não altera o original.
pub fn canonical_url(url: &str) -> String {
    let mut value = url.split('#').next().unwrap_or(url).to_string();
    if let Some((scheme, rest)) = value.clone().split_once("://") {
        let scheme_lower = scheme.to_ascii_lowercase();
        let mut authority = rest.split('/').next().unwrap_or(rest).to_string();
        let path_and_query = rest[authority.len()..].to_string();
        authority = authority.to_ascii_lowercase();
        if (scheme_lower == "http" && authority.ends_with(":80"))
            || (scheme_lower == "https" && authority.ends_with(":443"))
        {
            authority = authority
                .rsplit_once(':')
                .map(|(host, _)| host.to_string())
                .unwrap_or(authority);
        }
        value = format!("{scheme_lower}://{authority}{path_and_query}");
    }
    if value.ends_with('/') && value.matches('/').count() == 3 {
        value.pop();
    }
    value
}

fn split_authority(authority: &str) -> (Option<String>, Option<u16>, Option<String>) {
    let (userinfo, host_port) = match authority.rsplit_once('@') {
        Some((userinfo, host_port)) => (Some(userinfo.to_string()), host_port),
        None => (None, authority),
    };
    if let Some(stripped) = host_port.strip_prefix('[') {
        if let Some((host, remainder)) = stripped.split_once(']') {
            let port = remainder
                .strip_prefix(':')
                .and_then(|port| port.parse().ok());
            return (Some(host.to_string()), port, userinfo);
        }
    }
    match host_port.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|ch| ch.is_ascii_digit()) => (
            Some(host.to_ascii_lowercase()),
            port.parse().ok(),
            userinfo,
        ),
        _ => (
            if host_port.is_empty() {
                None
            } else {
                Some(host_port.to_ascii_lowercase())
            },
            None,
            userinfo,
        ),
    }
}

fn parse_query(query: &str) -> Vec<NormalizedQueryPair> {
    if query.is_empty() {
        return Vec::new();
    }
    query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => NormalizedQueryPair {
                name: name.to_string(),
                value: value.to_string(),
            },
            None => NormalizedQueryPair {
                name: pair.to_string(),
                value: String::new(),
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HeaderView, OrderState, Provenance, Source, Verification};

    fn provenance(verification: Verification) -> Provenance {
        Provenance::new(Source::NetLog, "test", verification)
    }

    #[test]
    fn merges_duplicates_without_losing_values_or_sorting_names() {
        let view = HeaderView::from_pairs(
            [
                ("X-Rep", "a"),
                ("x-seq", "1"),
                ("x-rep", "b"),
                ("accept", "*/*"),
            ],
            &provenance(Verification::Verified),
        );
        let normalized = normalize_headers(&view);
        assert_eq!(normalized.order, "notWireOrder");
        // Ordem de primeira aparição, não alfabética.
        let names: Vec<&str> = normalized
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(names, vec!["x-rep", "x-seq", "accept"]);
        let x_rep = normalized.get("X-Rep").unwrap();
        assert_eq!(x_rep.values, vec!["a", "b"]);
        assert_eq!(x_rep.occurrences, 2);
        assert_eq!(x_rep.display_name, "X-Rep");
        assert_eq!(normalized.total_occurrences(), 4);
        // O original não foi tocado.
        assert_eq!(view.len(), 4);
        assert_eq!(view.headers[0].name, "X-Rep");
    }

    #[test]
    fn normalizes_url_query_and_keeps_duplicates() {
        let url = normalize_url("HTTPS://User:pass@Demo.Invalid:443/a?b=2&b=3&c#frag");
        assert_eq!(url.scheme.as_deref(), Some("https"));
        assert_eq!(url.host.as_deref(), Some("demo.invalid"));
        assert_eq!(url.port, Some(443));
        assert_eq!(url.path, "/a");
        assert_eq!(url.query.len(), 3);
        assert_eq!(url.query[0].name, "b");
        assert_eq!(url.query[1].value, "3");
        assert_eq!(url.fragment.as_deref(), Some("frag"));
        assert_eq!(url.canonical, "https://user:pass@demo.invalid/a?b=2&b=3&c");
    }
}
