//! Sucesso da aplicação × sucesso HTTP (docs/11-priming-sucesso.md §2).
//!
//! Um HTTP 200 não prova que a aplicação respondeu: pode ser uma página de
//! proteção, uma resposta sem os campos de sempre ou um `ERRORMESSAGE`
//! preenchido. [`response_outcome`] avalia uma resposta e
//! [`assess_session`] avalia a sessão inteira, aprendendo na própria sessão
//! quais campos cada rota costuma trazer.
//!
//! Princípios: regras são dados (JSON, sem código executável), `blocked?` só
//! sai com evidência explícita e sempre com "?", e o que não dá para afirmar
//! numa rota que já tem expectativa é `indeterminado`, com a lista do que
//! faltou. Resposta sem sinal da aplicação e sem expectativa aprendida na
//! rota é `não-avaliado` (`not-assessed`): página, frame, estático ou
//! recurso de proteção não enchem a lista de suspeitos. Nada aqui abre rede.
//!
//! Um marcador de proteção SOZINHO não bloqueia: páginas da aplicação citam
//! `/TSPD/` num `<script src>`. `blocked?` exige status 403/429, rota de
//! proteção (configurável), conteúdo de desafio sem a página esperada ou uma
//! rota que trazia controles e agora vem sem eles.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::html::html_controls;
use crate::model::{BodyState, LogicalRequest, SessionV1};
use crate::search::BodySource;

pub const RULES_SCHEMA: &str = "scrapelens.assess-rules/1";

/// Como um campo conta para a avaliação.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FieldKind {
    /// Basta o campo existir.
    Present,
    /// O campo precisa existir e não estar vazio.
    PresentNonempty,
    /// Campo de erro: não vazio vira `app-error`.
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldRule {
    /// Nome do campo (controle HTML, chave de form ou caminho/chave JSON),
    /// sem distinguir maiúsculas.
    pub name: String,
    /// Nome do sinal mostrado no veredito; padrão = `name`.
    #[serde(default)]
    pub signal: Option<String>,
    pub kind: FieldKind,
}

impl FieldRule {
    fn signal(&self) -> &str {
        self.signal.as_deref().unwrap_or(&self.name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MarkerRule {
    /// Trecho (sem distinguir maiúsculas) procurado em respostas HTML.
    pub contains: String,
    #[serde(default)]
    pub signal: Option<String>,
    /// Como o marcador aparece: citação (URL/script) ou conteúdo do desafio.
    #[serde(default)]
    pub kind: MarkerKind,
}

/// Como o marcador de proteção aparece na resposta.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MarkerKind {
    /// Citação numa página da aplicação (`<script src="/TSPD/...">`): sozinha
    /// não é evidência de bloqueio.
    #[default]
    Reference,
    /// Conteúdo do próprio desafio (variável/código da proteção): sem os
    /// controles esperados, é bloqueio.
    Challenge,
}

/// Regras de avaliação. Só dados; `Default` é conservador.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AssessRules {
    pub schema: String,
    pub fields: Vec<FieldRule>,
    /// Campos que toda resposta de aplicação deve trazer (além dos aprendidos).
    pub required_fields: Vec<String>,
    /// Marcadores de proteção: só bloqueiam como desafio, como rota de
    /// proteção ou quando substituem a página esperada.
    pub protection_markers: Vec<MarkerRule>,
    /// Prefixos de caminho que são, eles próprios, resposta de proteção.
    pub protection_paths: Vec<String>,
    /// Status HTTP que são evidência explícita de bloqueio.
    pub blocked_statuses: Vec<u16>,
    /// Aprende, na sessão, os campos que cada rota (método + caminho) traz.
    pub learn_routes: bool,
}

impl Default for AssessRules {
    fn default() -> Self {
        let field = |name: &str, kind| FieldRule {
            name: name.to_string(),
            signal: None,
            kind,
        };
        let marker = |contains: &str, signal: &str, kind| MarkerRule {
            contains: contains.to_string(),
            signal: Some(signal.to_string()),
            kind,
        };
        Self {
            schema: RULES_SCHEMA.to_string(),
            fields: vec![
                field("XML", FieldKind::PresentNonempty),
                field("STAMP", FieldKind::Present),
                field("ERRORMESSAGE", FieldKind::Error),
            ],
            required_fields: Vec::new(),
            protection_markers: vec![
                marker("/TSPD/", "TSPD", MarkerKind::Reference),
                marker("_tsChallenge", "TSPD", MarkerKind::Challenge),
            ],
            protection_paths: vec!["/TSPD/".to_string()],
            blocked_statuses: vec![403, 429],
            learn_routes: true,
        }
    }
}

impl AssessRules {
    /// Lê regras de JSON. Campos ausentes assumem o padrão; schema diferente
    /// de [`RULES_SCHEMA`] é recusado.
    pub fn from_json(text: &str) -> Result<Self, String> {
        let rules: Self =
            serde_json::from_str(text).map_err(|e| format!("regras de assess inválidas: {e}"))?;
        if rules.schema != RULES_SCHEMA {
            return Err(format!(
                "schema de regras desconhecido: {} (esperado {RULES_SCHEMA})",
                rules.schema
            ));
        }
        Ok(rules)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignalKind {
    /// Sinal de que a aplicação respondeu.
    Ok,
    /// Erro declarado pela aplicação (campo de erro não vazio, HTTP 4xx/5xx).
    Error,
    /// Evidência explícita de proteção/bloqueio.
    Protection,
    /// Campo esperado e ausente (ou vazio).
    Missing,
    /// Observação que não muda o veredito.
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSignal {
    pub signal: String,
    pub kind: SignalKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerdictKind {
    AppOk,
    AppError,
    Blocked,
    Indeterminado,
    /// Sem sinal da aplicação e sem expectativa aprendida na rota.
    NotAssessed,
}

impl VerdictKind {
    /// Chave de `counts` no JSON (`scrapelens.assess/1`), igual a `verdictKind`.
    #[must_use]
    pub const fn count_key(self) -> &'static str {
        match self {
            Self::AppOk => "app-ok",
            Self::AppError => "app-error",
            Self::Blocked => "blocked",
            Self::Indeterminado => "indeterminado",
            Self::NotAssessed => "not-assessed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseOutcome {
    pub request_id: String,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    /// 2xx/3xx.
    pub http_ok: bool,
    pub app_signals: Vec<AppSignal>,
    /// `app-ok`, `app-error (<sinal>)`, `blocked? (<sinal>)`, `indeterminado`
    /// ou `não-avaliado`.
    pub verdict: String,
    pub verdict_kind: VerdictKind,
    /// Campos esperados (aprendidos na rota ou exigidos pelas regras) que
    /// faltaram ou vieram vazios.
    pub missing_fields: Vec<String>,
    /// Por que o veredito é `indeterminado` ou `não-avaliado` (vazio nos demais).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

/// Campos aprendidos por rota (`"POST /servlet/Connector"` → nomes).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteExpectations {
    routes: BTreeMap<String, BTreeSet<String>>,
}

impl RouteExpectations {
    pub fn expected(&self, request: &LogicalRequest) -> Option<&BTreeSet<String>> {
        self.routes.get(&route_key(request))
    }
}

fn route_key(request: &LogicalRequest) -> String {
    let url = request.url.split(['?', '#']).next().unwrap_or("");
    format!("{} {}", request.method.to_ascii_uppercase(), url)
}

/// Um campo lido do corpo da resposta.
struct Found {
    name: String,
    value: String,
}

struct ParsedBody {
    fields: Vec<Found>,
    html: bool,
    text: Option<String>,
    truncated: bool,
}

fn media_of(request: &LogicalRequest) -> String {
    request
        .response_headers
        .first_value("content-type")
        .or(request.response_body.content_type.as_deref())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn parse_body(request: &LogicalRequest, source: &dyn BodySource) -> ParsedBody {
    let body = &request.response_body;
    let mut out = ParsedBody {
        fields: Vec::new(),
        html: false,
        text: None,
        truncated: body.state == BodyState::Truncated,
    };
    if !matches!(body.state, BodyState::Captured | BodyState::Truncated) {
        return out;
    }
    let Some(loaded) = body.attachment.as_deref().and_then(|n| source.load(n)) else {
        return out;
    };
    out.truncated |= loaded.cut;
    let text = String::from_utf8_lossy(&loaded.bytes).into_owned();
    let media = media_of(request);
    let head = text.trim_start();
    let html_like = media.contains("html")
        || head.starts_with('<')
            && !media.contains("json")
            && !media.contains("javascript")
            && !media.contains("xml");
    if html_like {
        out.html = true;
        for control in html_controls(&text) {
            out.fields.push(Found {
                name: control.name,
                value: control.value,
            });
        }
        // Corpo de form puro sob Content-Type html (caso do Connector).
        if out.fields.is_empty() && looks_form(&text) {
            out.fields = form_fields(&text);
        }
    } else if media.contains("json") || head.starts_with('{') || head.starts_with('[') {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
            json_leaves(&value, "", &mut out.fields);
        }
    } else if media.contains("x-www-form-urlencoded") || looks_form(&text) {
        out.fields = form_fields(&text);
    }
    out.text = Some(text);
    out
}

fn looks_form(text: &str) -> bool {
    let t = text.trim();
    !t.is_empty()
        && !t.contains(['<', '\n'])
        && t.split('&').all(|part| {
            part.split_once('=').is_some_and(|(k, _)| {
                !k.is_empty()
                    && k.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_.-[]".contains(c))
            })
        })
}

fn form_fields(text: &str) -> Vec<Found> {
    text.trim()
        .split('&')
        .filter_map(|part| part.split_once('='))
        .map(|(k, v)| Found {
            name: percent_decode(k),
            value: percent_decode(v),
        })
        .collect()
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len()
                && raw.is_char_boundary(i + 1)
                && raw.is_char_boundary(i + 3) =>
            {
                match u8::from_str_radix(&raw[i + 1..i + 3], 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn json_leaves(value: &serde_json::Value, path: &str, out: &mut Vec<Found>) {
    if out.len() >= 5_000 {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let next = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                json_leaves(child, &next, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                json_leaves(child, &format!("{path}[{index}]"), out);
            }
        }
        serde_json::Value::Null => out.push(Found {
            name: path.to_string(),
            value: String::new(),
        }),
        serde_json::Value::String(text) => out.push(Found {
            name: path.to_string(),
            value: text.clone(),
        }),
        other => out.push(Found {
            name: path.to_string(),
            value: other.to_string(),
        }),
    }
}

fn name_matches(found: &str, rule: &str) -> bool {
    let last = found.rsplit('.').next().unwrap_or(found);
    found.eq_ignore_ascii_case(rule) || last.eq_ignore_ascii_case(rule)
}

fn find<'a>(fields: &'a [Found], rule: &str) -> Option<&'a Found> {
    fields.iter().find(|f| name_matches(&f.name, rule))
}

/// Há erro de aplicação ou bloqueio explícito nesta resposta? Quem aprende a
/// rota ignora essas respostas.
fn is_clean_sample(request: &LogicalRequest, parsed: &ParsedBody, rules: &AssessRules) -> bool {
    let status_ok = request.status.is_some_and(|s| s < 400);
    status_ok
        && !rules
            .fields
            .iter()
            .filter(|r| r.kind == FieldKind::Error)
            .any(|r| find(&parsed.fields, &r.name).is_some_and(|f| !f.value.trim().is_empty()))
}

/// Aprende, para cada rota, os campos positivos que as respostas limpas
/// trouxeram.
pub fn learn_routes(
    session: &SessionV1,
    source: &dyn BodySource,
    rules: &AssessRules,
) -> RouteExpectations {
    let mut learned = RouteExpectations::default();
    if !rules.learn_routes {
        return learned;
    }
    for request in &session.requests {
        let parsed = parse_body(request, source);
        if parsed.fields.is_empty() || !is_clean_sample(request, &parsed, rules) {
            continue;
        }
        for rule in rules.fields.iter().filter(|r| r.kind != FieldKind::Error) {
            let Some(found) = find(&parsed.fields, &rule.name) else {
                continue;
            };
            if rule.kind == FieldKind::PresentNonempty && found.value.is_empty() {
                continue;
            }
            learned
                .routes
                .entry(route_key(request))
                .or_default()
                .insert(rule.name.clone());
        }
    }
    learned
}

/// Caminho da URL (sem esquema/host e sem query/fragmento).
fn path_of(url: &str) -> &str {
    let no_frag = url.split('#').next().unwrap_or(url);
    let no_query = no_frag.split('?').next().unwrap_or(no_frag);
    match no_query.find("://") {
        Some(scheme) => {
            let rest = &no_query[scheme + 3..];
            let cut = rest.find('/').unwrap_or(rest.len());
            &rest[cut..]
        }
        None => no_query,
    }
}

/// Avalia uma resposta só com as regras (sem aprendizado de rota).
pub fn response_outcome(
    request: &LogicalRequest,
    source: &dyn BodySource,
    rules: &AssessRules,
) -> ResponseOutcome {
    response_outcome_with(request, source, rules, &RouteExpectations::default())
}

/// Avalia uma resposta usando também os campos aprendidos na sessão.
pub fn response_outcome_with(
    request: &LogicalRequest,
    source: &dyn BodySource,
    rules: &AssessRules,
    learned: &RouteExpectations,
) -> ResponseOutcome {
    let parsed = parse_body(request, source);
    let http_ok = request.status.is_some_and(|s| (200..400).contains(&s));
    let mut signals: Vec<AppSignal> = Vec::new();
    let sig = |signal: &str, kind, detail: String| AppSignal {
        signal: signal.to_string(),
        kind,
        detail,
    };

    // 1. Erro declarado pela aplicação.
    let mut error_signal: Option<String> = None;
    for rule in rules.fields.iter().filter(|r| r.kind == FieldKind::Error) {
        if let Some(found) = find(&parsed.fields, &rule.name) {
            if !found.value.trim().is_empty() {
                error_signal.get_or_insert_with(|| rule.signal().to_string());
                signals.push(sig(
                    rule.signal(),
                    SignalKind::Error,
                    format!(
                        "campo {} preenchido ({} caracteres)",
                        found.name,
                        found.value.chars().count()
                    ),
                ));
            }
        }
    }

    // 2. Evidência explícita de bloqueio.
    let mut block_signal: Option<String> = None;
    if let Some(status) = request.status {
        if rules.blocked_statuses.contains(&status) {
            let name = format!("http-{status}");
            block_signal.get_or_insert_with(|| name.clone());
            signals.push(sig(&name, SignalKind::Protection, format!("HTTP {status}")));
        }
    }
    let marker_hit = parsed.html.then_some(()).and_then(|()| {
        let text = parsed.text.as_deref()?.to_ascii_lowercase();
        let mut citation = None;
        for marker in &rules.protection_markers {
            if text.contains(&marker.contains.to_ascii_lowercase()) {
                // Conteúdo de desafio é evidência mais forte que uma citação.
                if marker.kind == MarkerKind::Challenge {
                    return Some(marker);
                }
                citation.get_or_insert(marker);
            }
        }
        citation
    });
    let path = path_of(&request.url);
    let protection_path = rules
        .protection_paths
        .iter()
        .any(|p| !p.is_empty() && path.contains(p.as_str()));
    if let Some(marker) = marker_hit {
        let name = marker
            .signal
            .clone()
            .unwrap_or_else(|| marker.contains.clone());
        let no_controls = parsed.fields.is_empty();
        let replaces_expected = no_controls && learned.expected(request).is_some();
        let challenge = marker.kind == MarkerKind::Challenge && no_controls;
        if protection_path || challenge || replaces_expected {
            block_signal.get_or_insert_with(|| name.clone());
            let detail = if protection_path {
                format!("rota de proteção com o marcador {}", marker.contains)
            } else if challenge {
                format!(
                    "conteúdo de desafio sem a página esperada (marcador {})",
                    marker.contains
                )
            } else {
                format!(
                    "conteúdo de desafio sem os controles esperados (marcador {})",
                    marker.contains
                )
            };
            signals.push(sig(&name, SignalKind::Protection, detail));
        } else {
            signals.push(sig(
                &name,
                SignalKind::Info,
                format!(
                    "marcador {} citado por uma página da aplicação; sozinho não é bloqueio",
                    marker.contains
                ),
            ));
        }
    } else if protection_path && parsed.html {
        // A própria rota de proteção, sem corpo ou sem marcador reconhecível.
        // Scripts/CSS servidos por ela não são resposta de desafio.
        let name = rules
            .protection_markers
            .iter()
            .find(|m| path.contains(m.contains.as_str()))
            .and_then(|m| m.signal.clone())
            .unwrap_or_else(|| "proteção".to_string());
        block_signal.get_or_insert_with(|| name.clone());
        signals.push(sig(
            &name,
            SignalKind::Protection,
            format!("rota de proteção {path}"),
        ));
    }

    // 3. Sinais positivos e campos esperados ausentes.
    let mut positives = 0usize;
    for rule in rules.fields.iter().filter(|r| r.kind != FieldKind::Error) {
        if let Some(found) = find(&parsed.fields, &rule.name) {
            if rule.kind == FieldKind::PresentNonempty && found.value.is_empty() {
                signals.push(sig(
                    rule.signal(),
                    SignalKind::Missing,
                    format!("{} presente, mas vazio", found.name),
                ));
            } else {
                positives += 1;
                signals.push(sig(
                    rule.signal(),
                    SignalKind::Ok,
                    format!("{} presente", found.name),
                ));
            }
        }
    }
    let mut expected: BTreeSet<String> = rules.required_fields.iter().cloned().collect();
    if let Some(known) = learned.expected(request) {
        expected.extend(known.iter().cloned());
    }
    let mut missing: Vec<String> = Vec::new();
    for name in &expected {
        let rule = rules
            .fields
            .iter()
            .find(|r| r.name.eq_ignore_ascii_case(name));
        let nonempty = rule.is_some_and(|r| r.kind == FieldKind::PresentNonempty);
        match find(&parsed.fields, name) {
            Some(found) if !(nonempty && found.value.is_empty()) => {}
            _ => missing.push(name.clone()),
        }
    }

    // 4. Veredito.
    let status_text = request
        .status
        .map_or("sem status".to_string(), |s| s.to_string());
    let mut reason = String::new();
    let (kind, verdict) = if let Some(signal) = error_signal {
        (VerdictKind::AppError, format!("app-error ({signal})"))
    } else if let Some(signal) = block_signal {
        (VerdictKind::Blocked, format!("blocked? ({signal})"))
    } else if request.status.is_some_and(|s| s >= 400) {
        let name = format!("http-{status_text}");
        signals.push(sig(&name, SignalKind::Error, format!("HTTP {status_text}")));
        (VerdictKind::AppError, format!("app-error ({name})"))
    } else if parsed.html && parsed.fields.is_empty() && learned.expected(request).is_some() {
        signals.push(sig(
            "html-sem-controles",
            SignalKind::Protection,
            format!(
                "HTML sem controles numa rota que os trazia ({})",
                missing.join(", ")
            ),
        ));
        (
            VerdictKind::Blocked,
            "blocked? (html-sem-controles)".to_string(),
        )
    } else if !missing.is_empty() {
        let fields = missing.join(", ");
        reason = if parsed.text.is_none() {
            format!("corpo da resposta indisponível; faltam campos esperados: {fields}")
        } else if parsed.truncated {
            format!("corpo truncado; faltam campos esperados: {fields}")
        } else {
            format!("faltam campos esperados: {fields}")
        };
        (VerdictKind::Indeterminado, "indeterminado".to_string())
    } else if positives > 0 {
        (VerdictKind::AppOk, "app-ok".to_string())
    } else {
        reason = if parsed.text.is_none() {
            "corpo da resposta indisponível; rota sem expectativa aprendida".to_string()
        } else if parsed.truncated {
            "corpo truncado; rota sem expectativa aprendida".to_string()
        } else {
            "sem sinais de aplicação nem campos esperados nesta rota".to_string()
        };
        (VerdictKind::NotAssessed, "não-avaliado".to_string())
    };
    if kind == VerdictKind::Indeterminado && parsed.truncated && !reason.contains("truncado") {
        reason.push_str("; corpo truncado");
    }

    ResponseOutcome {
        request_id: request.id.clone(),
        method: request.method.clone(),
        url: request.url.clone(),
        status: request.status,
        http_ok,
        app_signals: signals,
        verdict,
        verdict_kind: kind,
        missing_fields: missing,
        reason,
    }
}

/// Avalia todas as requisições da sessão, na ordem, aprendendo antes quais
/// campos cada rota costuma trazer.
pub fn assess_session(
    session: &SessionV1,
    source: &dyn BodySource,
    rules: &AssessRules,
) -> Vec<ResponseOutcome> {
    let learned = learn_routes(session, source, rules);
    session
        .requests
        .iter()
        .map(|request| response_outcome_with(request, source, rules, &learned))
        .collect()
}
