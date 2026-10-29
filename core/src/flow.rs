//! Origem dos valores e cadeia de priming (`docs/09-cadeia-comparacao.md` §1).
//!
//! API para o App:
//!
//! ```text
//! pub fn value_origins(session: &SessionV1, source: &dyn BodySource,
//!                      request_id: &str, options: &FlowOptions) -> Result<ValueOrigins>
//! pub fn priming_chain(session: &SessionV1, source: &dyn BodySource,
//!                      request_id: &str, options: &FlowOptions) -> Result<PrimingChain>
//! ```
//!
//! Esquema JSON (camelCase; `origins`, `chain` e `compare` no CLI):
//!
//! ```text
//! origins: { requestId, attemptId, values: [ValueOrigin], redactedValues, ties, warnings }
//! ValueOrigin: { scope: query|header|cookie|body, field, occurrence, value, length,
//!   status: origin|ambiguous|repeated|none|composite|redacted, label (PT-BR),
//!   confidence: strong|possible|null ("possível origem (<tipo>)" quando só há evidência média),
//!   offset (trechos), oldest (índice em evidences), parent (campo opaco do trecho),
//!   repeatedFrom[], unobservable: [{requestId, state, reason}], note, evidences: [ { kind: cookie-jar|same-field|value-match|initiator,
//!     strength: strong|medium|complement, role: produced|reissued, producerRequestId,
//!     producerAttemptId, scope: setCookie|responseHeader|location|responseBody, field,
//!     producerOffset, consumedOffset, consumedLength, timing: observed|inferred } ] }
//! chain: { requestId, steps: [ChainStep], protection: [ChainStep], pages: [ChainStep]
//!   (class: page, "página de contexto" por Referer; nunca produtoras), unresolved[], warnings }
//! ChainStep: { requestId, attemptId, method, url, startedAt, class: application|protection,
//!   confidence: strong|possible, reason, reasons: [ { provides, field, kind, strength, consumedBy } ] }
//! ```
//!
//! Rodada 6 (docs/10), campos novos:
//! - `evidences[].htmlControl`: o produtor é um controle de formulário HTML
//!   (`input`/`textarea`/`select` de uma resposta text/html; ver [`crate::html`]);
//!   `producerOffset` aponta o valor no HTML original, mesmo com entidades;
//! - `ValueOrigin.context[]` `{requestId, field, note}`: valor também presente em
//!   recurso estático (script, css, fonte, imagem, mídia): pode ser constante do
//!   protocolo; nunca é produtor nem passo;
//! - `ValueOrigin.partialComposition[]` `{producerRequestId, field, start, length}`: valor
//!   curto sem origem que contém (alinhado a `_ - . : |` ou à borda, >= 8 bytes) o
//!   valor de um produtor e uma parte sem fonte: dica de composição no cliente, não
//!   é origem e não cria passo;
//! - `unobservable[].suggestion`: ocorrência equivalente (mesmo modelo) mais
//!   adiante com corpo observável;
//! - `chain.auxiliaryPages[]`: frames (documentos com `initiator.kind == parser`, fonte CDP
//!   `initiator` ou HAR `_initiator`) no caminho de Referer, fora de `pages`;
//! - `chain.pages[]` (`class: page`): documentos que carregaram a página de onde
//!   cada passo foi emitido (Referer); "página de contexto", nunca produtoras;
//! - avisos de HAR sem cookies (`har.cookies_absent`) repetidos em `warnings`.
//!
//! O esquema de `compare` está em [`crate::compare`].
//!
//! Trechos: só valores consumidos com >= 40 bytes (campos opacos, como o XML do
//! Natural) são procurados por trechos; nos demais vale o valor inteiro.
//!
//! Regras:
//! - só entram produtores cuja RESPOSTA terminou (`ended_at`) até o início da
//!   tentativa alvo; resposta que termina depois não é produtora. Sem tempos, a
//!   ordem da sessão vale e a evidência leva `timing: inferred`. Empate de
//!   início nunca vira produtor: fica em `ties`;
//! - evidências separadas: `cookieJar` (forte) e `sameField` (forte só com nome
//!   não genérico — id, value, data, page, type, lang, name, key, code, state,
//!   status, action, op, mode, format, limit, offset, q, query, v, t, ts — e
//!   valor com ≥ 4 caracteres; senão média), `valueMatch`
//!   (média; valor de resposta com >= 8 caracteres encontrado na requisição,
//!   inteiro ou como substring de campo opaco) e `initiator` (complemento; o
//!   modelo atual não preserva o initiator do CDP, o que é declarado);
//! - nenhum candidato = `none` ("sem origem observada"); vários produtores
//!   independentes = `ambiguous` com todos os candidatos e o mais antigo
//!   indicado; `reissued` só quando o valor circulou numa requisição entre um
//!   produtor e o seguinte (senão são concorrentes: `ambiguous`);
//! - "origem observada" exige evidência forte; só média = `confidence:
//!   possible` ("possível origem (<tipo>)"); a cadeia marca cada passo
//!   `strong` ou `possible`;
//! - valores redigidos (`[REDACTED]`) não casam e são declarados.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::model::{Attempt, BodyState, SessionV1};
use crate::search::BodySource;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowOptions {
    /// Comprimento mínimo para `valueMatch`.
    pub min_match_len: usize,
    /// Máximo de evidências devolvidas por valor.
    pub max_evidence: usize,
    /// Máximo de células de DP para comparar dois campos opacos.
    pub max_opaque_cells: usize,
}

impl Default for FlowOptions {
    fn default() -> Self {
        Self {
            min_match_len: 8,
            max_evidence: 8,
            max_opaque_cells: 4_000_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    CookieJar,
    SameField,
    ValueMatch,
    Initiator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Strength {
    Strong,
    Medium,
    Complement,
}

/// Confiança da origem: `strong` exige evidência forte; só evidência média é
/// `possible` ("possível origem").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Confidence {
    Strong,
    Possible,
}

/// Como a ordem produtor → consumidor foi estabelecida.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Timing {
    /// A resposta do produtor terminou (tempo da fonte) antes do início do alvo.
    Observed,
    /// Faltou tempo de início/fim: valeu a ordem da sessão.
    Inferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Role {
    Produced,
    Reissued,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProducerScope {
    SetCookie,
    ResponseHeader,
    Location,
    ResponseBody,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConsumedScope {
    Query,
    Header,
    Cookie,
    Body,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OriginStatus {
    /// Um produtor observado.
    Origin,
    /// Mais de um produtor independente: ver `oldest`.
    Ambiguous,
    /// Sem produtor, mas o valor já circulava em requisição anterior.
    Repeated,
    /// "Sem origem observada": constante, entrada do usuário ou gerado no cliente.
    None,
    /// Campo opaco cujas partes têm origem própria (entradas `parent`).
    Composite,
    /// Valor redigido: não rastreável.
    Redacted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub strength: Strength,
    pub role: Role,
    /// Requisição lógica que produz o valor.
    #[serde(rename = "producerRequestId")]
    pub request_id: String,
    #[serde(rename = "producerAttemptId")]
    pub attempt_id: String,
    pub scope: ProducerScope,
    /// Nome do campo/header/cookie/variável no produtor, quando houver.
    pub field: Option<String>,
    /// Offset do valor dentro do corpo/valor do produtor.
    pub producer_offset: Option<u64>,
    /// Onde o trecho aparece no valor consumido (campos opacos).
    pub consumed_offset: Option<u64>,
    pub consumed_length: Option<u64>,
    pub timing: Timing,
    /// O produtor é um controle de formulário HTML (`input`/`textarea`/`select`).
    pub html_control: bool,
}

/// Dica informativa (não é origem): o valor contém, alinhado a um separador ou
/// à borda, o valor de um produtor, e o resto não tem fonte observada.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartialComposition {
    pub producer_request_id: String,
    pub field: Option<String>,
    pub start: usize,
    pub length: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextNote {
    pub request_id: String,
    pub field: Option<String>,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Unobservable {
    pub request_id: String,
    /// `unavailable`, `discarded` ou `truncated`.
    pub state: String,
    pub reason: Option<String>,
    /// Ocorrência equivalente (mesmo modelo) mais adiante, com corpo observável:
    /// onde procurar a mesma informação.
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValueOrigin {
    pub scope: ConsumedScope,
    pub field: String,
    /// Ocorrência do campo repetido (0 = primeira).
    pub occurrence: usize,
    /// Valor (prévia de até 160 caracteres).
    pub value: String,
    pub length: usize,
    pub status: OriginStatus,
    /// Rótulo legível ("sem origem observada", "ambíguo…"…).
    pub label: String,
    /// `strong` (há evidência forte) ou `possible` (só evidência média).
    pub confidence: Option<Confidence>,
    /// Offset do trecho no valor consumido (entradas `parent`).
    pub offset: Option<u64>,
    /// Índice em `evidences` do produtor mais antigo.
    pub oldest: Option<usize>,
    pub evidences: Vec<Evidence>,
    /// Requisições anteriores que já carregavam o valor (`repeated`).
    pub repeated_from: Vec<String>,
    /// Respostas anteriores sem corpo observável (unavailable/discarded/
    /// truncated): a origem pode estar nelas (até 20; o total vai no rótulo).
    pub unobservable: Vec<Unobservable>,
    /// Valor também presente em recursos estáticos (pode ser constante do
    /// protocolo): nunca é produtor nem passo da cadeia.
    pub context: Vec<ContextNote>,
    /// Composição parcial provável (cliente): ver [`PartialComposition`].
    pub partial_composition: Vec<PartialComposition>,
    /// Campo opaco de que este trecho faz parte (`composite`).
    pub parent: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValueOrigins {
    pub request_id: String,
    pub attempt_id: String,
    pub values: Vec<ValueOrigin>,
    /// Quantidade de valores redigidos (não rastreáveis).
    pub redacted_values: usize,
    /// Tentativas com o mesmo tempo de início, excluídas como produtores.
    pub ties: Vec<String>,
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Dados de produtor / consumidor por tentativa
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Item {
    scope: ProducerScope,
    field: Option<String>,
    value: String,
    offset: Option<u64>,
    /// Pode servir de `sameField` (tem nome de campo/header/cookie).
    named: bool,
    /// Controle de formulário HTML (`input`/`textarea`/`select`).
    html: bool,
    /// Controle pré-preenchido que não é `hidden`: no máximo evidência média.
    soft: bool,
}

#[derive(Debug)]
struct OpaqueField {
    name: String,
    value: String,
    /// Mapa de offsets decodificado → original (controles HTML).
    map: Option<Vec<usize>>,
    html: bool,
}

#[derive(Debug, Default)]
struct ProducerData {
    items: Vec<Item>,
    /// Campos opacos de resposta para comparação por substring.
    opaque: Vec<OpaqueField>,
}

#[derive(Debug, Clone)]
pub(crate) struct Consumed {
    pub(crate) scope: ConsumedScope,
    pub(crate) field: String,
    pub(crate) occurrence: usize,
    pub(crate) value: String,
}

const REDACTED_MARK: &str = "REDACTED";
/// Produtor: campo de resposta guardado para comparação por trechos.
const OPAQUE_MIN: usize = 16;
/// Consumidor: só valores longos (>= 40 bytes, com estrutura interna como o XML
/// do Natural) são procurados por trechos. Em campos comuns (form/JSON/query/
/// header) vale o valor inteiro: prefixo comum não é origem.
pub(crate) const OPAQUE_CONSUMER_MIN: usize = 40;

fn is_redacted(value: &str) -> bool {
    value.contains(REDACTED_MARK)
}

fn pct_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = |b: u8| (b as char).to_digit(16);
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_pairs(url: &str) -> Vec<(String, String)> {
    let Some((_, rest)) = url.split_once('?') else {
        return Vec::new();
    };
    rest.split('#')
        .next()
        .unwrap_or("")
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => (pct_decode(name), pct_decode(value)),
            None => (pct_decode(pair), String::new()),
        })
        .collect()
}

/// Headers de protocolo ou constantes: nunca são "valores consumidos".
fn is_protocol_header(lower: &str) -> bool {
    lower.starts_with(':')
        || lower.starts_with("sec-")
        || lower.starts_with("accept")
        || matches!(
            lower,
            "host"
                | "content-length"
                | "content-type"
                | "content-encoding"
                | "user-agent"
                | "cache-control"
                | "pragma"
                | "connection"
                | "upgrade-insecure-requests"
                | "origin"
                | "referer"
                | "cookie"
                | "set-cookie"
                | "date"
                | "server"
                | "vary"
                | "etag"
                | "expires"
                | "last-modified"
                | "transfer-encoding"
                | "keep-alive"
                | "age"
        )
}

fn form_fields(text: &str) -> Vec<(String, String, u64)> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    for segment in text.split('&') {
        if let Some((name, value)) = segment.split_once('=') {
            out.push((
                pct_decode(name),
                pct_decode(value),
                (offset + name.len() + 1) as u64,
            ));
        }
        offset += segment.len() + 1;
    }
    out
}

fn looks_form(text: &str) -> bool {
    let head = &text[..text.len().min(4096)];
    !head.contains('<')
        && !head.contains('\n')
        && head.contains('=')
        && head
            .split('&')
            .next()
            .is_some_and(|first| first.split('=').next().is_some_and(is_field_name))
}

fn is_field_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'[' | b']'))
}

fn json_leaves(value: &serde_json::Value, path: &str, out: &mut Vec<(String, String)>) {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                json_leaves(child, &child_path, out);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                json_leaves(child, &format!("{path}[{index}]"), out);
            }
        }
        Value::String(text) => out.push((path.to_string(), text.clone())),
        Value::Number(number) => out.push((path.to_string(), number.to_string())),
        Value::Bool(flag) => out.push((path.to_string(), flag.to_string())),
        Value::Null => {}
    }
}

/// Literais entre aspas (com a variável que os recebe, quando aparece).
fn string_literals(text: &str, min: usize) -> Vec<(String, u64, Option<String>)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let quote = bytes[i];
        if quote != b'"' && quote != b'\'' {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut j = start;
        while j < bytes.len() && bytes[j] != quote && bytes[j] != b'\n' && j - start <= 2048 {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == quote {
            if j - start >= min {
                if let Some(literal) = text.get(start..j) {
                    out.push((literal.to_string(), start as u64, assigned_name(text, i)));
                }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// Nome da variável/chave imediatamente antes de `= "` ou `: "`.
fn assigned_name(text: &str, quote_at: usize) -> Option<String> {
    let before = text.get(..quote_at)?.trim_end();
    let before = before
        .strip_suffix('=')
        .or_else(|| before.strip_suffix(':'))?;
    let before = before.trim_end();
    // chave de objeto entre aspas: `{"token": "…"}` / `{'token': '…'}`
    let before = before
        .strip_suffix(['"', '\''])
        .filter(|rest| rest.ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$'))
        .unwrap_or(before);
    let name: String = before
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    (!name.is_empty()).then_some(name)
}

fn body_text(source: &dyn BodySource, attempt_body: &crate::model::Body) -> Option<String> {
    if !matches!(
        attempt_body.state,
        BodyState::Captured | BodyState::Truncated
    ) {
        return None;
    }
    let name = attempt_body.attachment.as_deref()?;
    let loaded = source.load(name)?;
    String::from_utf8(loaded.bytes.into_owned()).ok()
}

fn media_of(headers: &crate::model::HeaderView, body: &crate::model::Body) -> String {
    headers
        .first_value("content-type")
        .or(body.content_type.as_deref())
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Campos nomeados de um corpo (form / JSON); `None` se for texto livre.
fn named_fields(text: &str, media: &str) -> Option<Vec<(String, String, Option<u64>)>> {
    let json_like =
        media.contains("json") || matches!(text.trim_start().as_bytes().first(), Some(b'{' | b'['));
    if json_like {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
            let mut leaves = Vec::new();
            json_leaves(&value, "", &mut leaves);
            return Some(leaves.into_iter().map(|(n, v)| (n, v, None)).collect());
        }
    }
    if media.contains("x-www-form-urlencoded") || looks_form(text) {
        return Some(
            form_fields(text)
                .into_iter()
                .map(|(n, v, o)| (n, v, Some(o)))
                .collect(),
        );
    }
    None
}

fn producer_data(attempt: &Attempt, source: &dyn BodySource, min: usize) -> ProducerData {
    let mut data = ProducerData::default();
    for record in &attempt.set_cookies {
        if let Some(parsed) = &record.parsed {
            data.items.push(Item {
                scope: ProducerScope::SetCookie,
                field: Some(parsed.name.clone()),
                value: parsed.value.trim_matches('"').to_string(),
                offset: None,
                named: true,
                html: false,
                soft: false,
            });
        }
    }
    for entry in attempt
        .response_headers
        .pseudo_headers
        .iter()
        .chain(attempt.response_headers.headers.iter())
    {
        let lower = entry.name.to_ascii_lowercase();
        if lower == "location" {
            data.items.push(Item {
                scope: ProducerScope::Location,
                field: Some("location".to_string()),
                value: entry.value.clone(),
                offset: None,
                named: false,
                html: false,
                soft: false,
            });
            for (name, value) in query_pairs(&entry.value) {
                data.items.push(Item {
                    scope: ProducerScope::Location,
                    field: Some(name),
                    value,
                    offset: None,
                    named: true,
                    html: false,
                    soft: false,
                });
            }
        } else if !is_protocol_header(&lower) {
            data.items.push(Item {
                scope: ProducerScope::ResponseHeader,
                field: Some(lower),
                value: entry.value.clone(),
                offset: None,
                named: true,
                html: false,
                soft: false,
            });
        }
    }
    if let Some(text) = body_text(source, &attempt.response_body) {
        let media = media_of(&attempt.response_headers, &attempt.response_body);
        let is_html = (media.contains("html") && text.contains('<'))
            || find_ci_ascii(&text, "<textarea")
            || find_ci_ascii(&text, "<input");
        if is_html {
            for c in crate::html::html_controls(&text) {
                if c.value.len() >= OPAQUE_MIN {
                    data.opaque.push(OpaqueField {
                        name: c.name.clone(),
                        value: c.value.clone(),
                        map: Some(c.map.clone()),
                        html: true,
                    });
                }
                data.items.push(Item {
                    scope: ProducerScope::ResponseBody,
                    field: Some(c.name),
                    value: c.value,
                    offset: Some(c.start as u64),
                    named: true,
                    html: true,
                    soft: !c.hidden,
                });
            }
        }
        match named_fields(&text, &media) {
            Some(fields) if !is_html => {
                for (name, value, offset) in fields {
                    if value.len() >= OPAQUE_MIN {
                        data.opaque.push(OpaqueField {
                            name: name.clone(),
                            value: value.clone(),
                            map: None,
                            html: false,
                        });
                    }
                    data.items.push(Item {
                        scope: ProducerScope::ResponseBody,
                        field: Some(name),
                        value,
                        offset,
                        named: true,
                        html: false,
                        soft: false,
                    });
                }
            }
            _ => {
                for (literal, offset, hint) in string_literals(&text, min) {
                    data.items.push(Item {
                        scope: ProducerScope::ResponseBody,
                        field: hint,
                        value: literal,
                        offset: Some(offset),
                        named: false,
                        html: false,
                        soft: false,
                    });
                }
            }
        }
    }
    data
}

fn find_ci_ascii(text: &str, needle: &str) -> bool {
    let (h, n) = (text.as_bytes(), needle.as_bytes());
    h.len() >= n.len() && (0..=h.len() - n.len()).any(|i| h[i..i + n.len()].eq_ignore_ascii_case(n))
}

fn consumed_values(attempt: &Attempt, source: &dyn BodySource) -> Vec<Consumed> {
    let mut out: Vec<Consumed> = Vec::new();
    let mut counts: HashMap<(u8, String), usize> = HashMap::new();
    let mut push = |scope: ConsumedScope, field: String, value: String, out: &mut Vec<Consumed>| {
        let key = (scope as u8, field.to_ascii_lowercase());
        let occurrence = counts.entry(key).or_default();
        out.push(Consumed {
            scope,
            field,
            occurrence: *occurrence,
            value,
        });
        *occurrence += 1;
    };
    for (name, value) in query_pairs(&attempt.url) {
        push(ConsumedScope::Query, name, value, &mut out);
    }
    for entry in attempt
        .request_headers
        .pseudo_headers
        .iter()
        .chain(attempt.request_headers.headers.iter())
    {
        if !is_protocol_header(&entry.name.to_ascii_lowercase()) {
            push(
                ConsumedScope::Header,
                entry.name.clone(),
                entry.value.clone(),
                &mut out,
            );
        }
    }
    for pair in &attempt.cookie.pairs {
        push(
            ConsumedScope::Cookie,
            pair.name.clone(),
            pair.value.trim_matches('"').to_string(),
            &mut out,
        );
    }
    if let Some(text) = body_text(source, &attempt.request_body) {
        let media = media_of(&attempt.request_headers, &attempt.request_body);
        match named_fields(&text, &media) {
            Some(fields) => {
                for (name, value, _) in fields {
                    push(ConsumedScope::Body, name, value, &mut out);
                }
            }
            None => push(ConsumedScope::Body, "(body)".to_string(), text, &mut out),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Contexto (cache)
// ---------------------------------------------------------------------------

pub(crate) type Pos = (usize, usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rel {
    Before,
    Tie,
    After,
}

pub(crate) struct FlowContext<'a> {
    pub(crate) session: &'a SessionV1,
    pub(crate) source: &'a dyn BodySource,
    pub(crate) options: FlowOptions,
    producers: RefCell<HashMap<Pos, Rc<ProducerData>>>,
    consumed: RefCell<HashMap<Pos, Rc<Vec<Consumed>>>>,
    /// Índice por prefixo de 8 bytes: valores de produtor com >= 8 bytes.
    index: RefCell<Option<Rc<PrefixIndex>>>,
    seq: HashMap<Pos, usize>,
    by_attempt: HashMap<String, Pos>,
    ordered: Vec<Pos>,
}

struct PrefixIndex {
    map: HashMap<[u8; 8], Vec<(Pos, usize)>>,
}

impl<'a> FlowContext<'a> {
    pub(crate) fn new(
        session: &'a SessionV1,
        source: &'a dyn BodySource,
        options: &FlowOptions,
    ) -> Self {
        let mut seq = HashMap::new();
        let mut by_attempt = HashMap::new();
        let mut ordered = Vec::new();
        let mut next = 0;
        for (ri, request) in session.requests.iter().enumerate() {
            for (ai, attempt) in request.attempts.iter().enumerate() {
                seq.insert((ri, ai), next);
                by_attempt.insert(attempt.id.clone(), (ri, ai));
                ordered.push((ri, ai));
                next += 1;
            }
        }
        Self {
            session,
            source,
            options: options.clone(),
            producers: RefCell::new(HashMap::new()),
            consumed: RefCell::new(HashMap::new()),
            index: RefCell::new(None),
            seq,
            by_attempt,
            ordered,
        }
    }

    fn attempt(&self, pos: Pos) -> &'a Attempt {
        &self.session.requests[pos.0].attempts[pos.1]
    }

    pub(crate) fn positions(&self) -> impl Iterator<Item = Pos> + '_ {
        self.session
            .requests
            .iter()
            .enumerate()
            .flat_map(|(ri, r)| (0..r.attempts.len()).map(move |ai| (ri, ai)))
    }

    /// `Before` só se a resposta do candidato terminou até o início do alvo
    /// (`ended_at`); sem tempos, vale a ordem da sessão (ver [`Self::inferred`]).
    fn rel(&self, candidate: Pos, target: Pos) -> Rel {
        if candidate == target {
            return Rel::After;
        }
        let (a, b) = (self.attempt(candidate), self.attempt(target));
        match (a.started_at, b.started_at) {
            (Some(x), Some(y)) => {
                if x == y {
                    Rel::Tie
                } else if x > y {
                    Rel::After
                } else {
                    match a.ended_at {
                        Some(end) if end <= y => Rel::Before,
                        Some(_) => Rel::After,
                        None => Rel::Before,
                    }
                }
            }
            _ => {
                if self.seq[&candidate] < self.seq[&target] {
                    Rel::Before
                } else {
                    Rel::After
                }
            }
        }
    }

    /// A ordem candidato → alvo veio da sequência da sessão, não dos tempos.
    fn inferred(&self, candidate: Pos, target: Pos) -> bool {
        let (a, b) = (self.attempt(candidate), self.attempt(target));
        a.started_at.is_none() || b.started_at.is_none() || a.ended_at.is_none()
    }

    /// O valor circulou numa requisição depois da resposta de `from` e até a
    /// resposta de `to` (inclusive o pedido do próprio `to`, que o enviou antes
    /// de a resposta chegar): então `to` só reemite o valor.
    fn circulated(&self, text: &str, from: Pos, to: Pos) -> bool {
        let (lo, hi) = (self.seq[&from], self.seq[&to]);
        let after = self.attempt(from).ended_at;
        let before = self.attempt(to).ended_at.or(self.attempt(to).started_at);
        for pos in &self.ordered {
            let n = self.seq[pos];
            if n <= lo || n > hi || *pos == from {
                continue;
            }
            if let (Some(after), Some(before), Some(start)) =
                (after, before, self.attempt(*pos).started_at)
            {
                if start < after || start > before {
                    continue;
                }
            }
            if self
                .consumed_of(*pos)
                .iter()
                .any(|c| c.value.contains(text))
            {
                return true;
            }
        }
        false
    }

    /// Recurso estático (script, stylesheet, fonte, imagem, mídia) por tipo,
    /// MIME ou extensão: não é produtor de valores de sessão.
    pub(crate) fn is_static(&self, pos: Pos) -> bool {
        self.static_candidate(pos) && !self.maybe_dynamic(pos)
    }

    /// Script com query string, `Cache-Control: no-store|no-cache` ou corpo
    /// JSON/JSONP pode ser produtor dinâmico, mesmo com cara de estático.
    fn maybe_dynamic(&self, pos: Pos) -> bool {
        let attempt = self.attempt(pos);
        let url = attempt.url.split('#').next().unwrap_or("");
        let path = url.split('?').next().unwrap_or("").to_ascii_lowercase();
        let is_script = path.ends_with(".js") || path.ends_with(".mjs");
        let mime = attempt
            .response_headers
            .first_value("content-type")
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_script = is_script || mime.contains("javascript") || mime.contains("ecmascript");
        if is_script && url.contains('?') {
            return true;
        }
        // `no-store`/`no-cache` só conta fora de scripts: bibliotecas JS reais
        // costumam vir assim (caso DETRAN) e não são produtoras por isso.
        if !is_script {
            let cache = attempt
                .response_headers
                .first_value("cache-control")
                .unwrap_or("")
                .to_ascii_lowercase();
            if cache.contains("no-store") || cache.contains("no-cache") {
                return true;
            }
        }
        if is_script || mime.contains("json") {
            if let Some(text) = body_text(self.source, &attempt.response_body) {
                let t = text.trim_start();
                let jsonp = t.split_once('(').is_some_and(|(head, rest)| {
                    !head.is_empty()
                        && head
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '.'))
                        && rest.trim_start().starts_with(['{', '['])
                });
                if t.starts_with(['{', '[']) || jsonp {
                    return true;
                }
            }
        }
        false
    }

    fn static_candidate(&self, pos: Pos) -> bool {
        let request = &self.session.requests[pos.0];
        let attempt = self.attempt(pos);
        if let Some(kind) = request.resource_type.as_deref() {
            if matches!(
                kind.to_ascii_lowercase().as_str(),
                "script" | "stylesheet" | "font" | "image" | "media"
            ) {
                return true;
            }
        }
        let mime = attempt
            .response_headers
            .first_value("content-type")
            .unwrap_or("")
            .to_ascii_lowercase();
        if mime.contains("javascript")
            || mime.contains("ecmascript")
            || mime.contains("text/css")
            || mime.starts_with("image/")
            || mime.starts_with("font/")
            || mime.starts_with("audio/")
            || mime.starts_with("video/")
            || mime.contains("woff")
        {
            return true;
        }
        let path = attempt.url.split(['?', '#']).next().unwrap_or("");
        let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        path.contains('.')
            && matches!(
                ext.as_str(),
                "js" | "mjs"
                    | "css"
                    | "png"
                    | "jpg"
                    | "jpeg"
                    | "gif"
                    | "svg"
                    | "ico"
                    | "woff"
                    | "woff2"
                    | "ttf"
                    | "otf"
                    | "eot"
                    | "webp"
                    | "map"
            )
    }

    fn producer(&self, pos: Pos) -> Rc<ProducerData> {
        if let Some(found) = self.producers.borrow().get(&pos) {
            return found.clone();
        }
        let data = Rc::new(producer_data(
            self.attempt(pos),
            self.source,
            self.options.min_match_len,
        ));
        self.producers.borrow_mut().insert(pos, data.clone());
        data
    }

    fn consumed_of(&self, pos: Pos) -> Rc<Vec<Consumed>> {
        if let Some(found) = self.consumed.borrow().get(&pos) {
            return found.clone();
        }
        let data = Rc::new(consumed_values(self.attempt(pos), self.source));
        self.consumed.borrow_mut().insert(pos, data.clone());
        data
    }

    fn prefix_index(&self) -> Rc<PrefixIndex> {
        if let Some(found) = self.index.borrow().as_ref() {
            return found.clone();
        }
        let mut map: HashMap<[u8; 8], Vec<(Pos, usize)>> = HashMap::new();
        for pos in self.positions().collect::<Vec<_>>() {
            let data = self.producer(pos);
            for (n, item) in data.items.iter().enumerate() {
                if item.value.len() >= self.options.min_match_len.max(8)
                    && !is_redacted(&item.value)
                {
                    let mut key = [0u8; 8];
                    key.copy_from_slice(&item.value.as_bytes()[..8]);
                    map.entry(key).or_default().push((pos, n));
                }
            }
        }
        let index = Rc::new(PrefixIndex { map });
        *self.index.borrow_mut() = Some(index.clone());
        index
    }

    pub(crate) fn find(&self, request_id: &str) -> Option<Pos> {
        let ri = self
            .session
            .requests
            .iter()
            .position(|r| r.id == request_id)?;
        let ai = self.session.requests[ri].attempts.len().checked_sub(1)?;
        Some((ri, ai))
    }

    pub(crate) fn consumed_for(&self, pos: Pos) -> Rc<Vec<Consumed>> {
        self.consumed_of(pos)
    }

    pub(crate) fn request_id(&self, pos: Pos) -> &'a str {
        &self.session.requests[pos.0].id
    }

    pub(crate) fn attempt_ref(&self, pos: Pos) -> &'a Attempt {
        self.attempt(pos)
    }
}

/// Nomes de campo genéricos: `same-field` com eles é só evidência média.
const GENERIC_NAMES: &[&str] = &[
    "id", "value", "data", "page", "type", "lang", "name", "key", "code", "state", "status",
    "action", "op", "mode", "format", "limit", "offset", "q", "query", "v", "t", "ts",
];

fn is_generic_name(name: &str) -> bool {
    GENERIC_NAMES
        .iter()
        .any(|generic| generic.eq_ignore_ascii_case(name))
}

fn preview(value: &str) -> String {
    let mut out: String = value.chars().take(160).collect();
    if value.chars().count() > 160 {
        out.push('…');
    }
    out
}

// ---------------------------------------------------------------------------
// value_origins
// ---------------------------------------------------------------------------

/// Origem dos valores consumidos pela requisição `request_id` (última
/// tentativa). Veja o módulo para as regras.
pub fn value_origins(
    session: &SessionV1,
    source: &dyn BodySource,
    request_id: &str,
    options: &FlowOptions,
) -> Result<ValueOrigins> {
    let ctx = FlowContext::new(session, source, options);
    origins_in(&ctx, request_id)
}

pub(crate) fn origins_in(ctx: &FlowContext<'_>, request_id: &str) -> Result<ValueOrigins> {
    let target = ctx
        .find(request_id)
        .ok_or_else(|| CoreError::MissingField {
            field: format!("requisição {request_id} (ou sem tentativas)"),
        })?;
    let attempt = ctx.attempt(target);
    let consumed = ctx.consumed_of(target);
    let mut result = ValueOrigins {
        request_id: request_id.to_string(),
        attempt_id: attempt.id.clone(),
        values: Vec::new(),
        redacted_values: 0,
        ties: Vec::new(),
        warnings: Vec::new(),
    };
    if attempt.initiator.is_none() {
        result.warnings.push(
            "initiator do CDP não é preservado no modelo: evidência `initiator` indisponível"
                .to_string(),
        );
    }

    if let Some(w) = ctx
        .session
        .warnings
        .iter()
        .find(|w| w.code == "har.cookies_absent")
    {
        result.warnings.push(w.message.clone());
    }
    let mut earlier: Vec<Pos> = Vec::new();
    for pos in ctx.positions() {
        match ctx.rel(pos, target) {
            Rel::Before => earlier.push(pos),
            Rel::Tie => result.ties.push(ctx.attempt(pos).id.clone()),
            Rel::After => {}
        }
    }
    earlier.sort_by(|a, b| {
        let (x, y) = (ctx.attempt(*a).started_at, ctx.attempt(*b).started_at);
        match (x, y) {
            (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal),
            _ => ctx.seq[a].cmp(&ctx.seq[b]),
        }
    });
    let earlier_set: BTreeSet<Pos> = earlier.iter().copied().collect();
    let rank: HashMap<Pos, usize> = earlier.iter().enumerate().map(|(i, p)| (*p, i)).collect();
    let index = ctx.prefix_index();

    for value in consumed.iter() {
        if is_redacted(&value.value) {
            result.redacted_values += 1;
            result.values.push(ValueOrigin {
                scope: value.scope,
                field: value.field.clone(),
                occurrence: value.occurrence,
                value: preview(&value.value),
                length: value.value.len(),
                status: OriginStatus::Redacted,
                label: "redigido: não rastreável".to_string(),
                confidence: None,
                offset: None,
                oldest: None,
                evidences: Vec::new(),
                repeated_from: Vec::new(),
                unobservable: Vec::new(),
                context: Vec::new(),
                partial_composition: Vec::new(),
                parent: None,
                note: Some("valor redigido: não rastreável".to_string()),
            });
            continue;
        }
        let mut evidences: Vec<(usize, Evidence)> = Vec::new();

        // cookieJar / sameField: igualdade de nome + valor.
        for pos in &earlier {
            let data = ctx.producer(*pos);
            for item in data.items.iter() {
                if !item.named || item.value.is_empty() || item.value != value.value {
                    continue;
                }
                let name = item.field.as_deref().unwrap_or("");
                let kind = match (value.scope, item.scope) {
                    (ConsumedScope::Cookie, ProducerScope::SetCookie) if name == value.field => {
                        Some(EvidenceKind::CookieJar)
                    }
                    (ConsumedScope::Cookie, _) => None,
                    (_, ProducerScope::SetCookie) => None,
                    _ if name.eq_ignore_ascii_case(&value.field) => Some(EvidenceKind::SameField),
                    _ => None,
                };
                if let Some(kind) = kind {
                    let strength = if kind == EvidenceKind::SameField
                        && (is_generic_name(&value.field) || value.value.len() < 4 || item.soft)
                    {
                        Strength::Medium
                    } else {
                        Strength::Strong
                    };
                    evidences.push((
                        rank[pos],
                        evidence(ctx, *pos, item, kind, strength, None, None),
                    ));
                }
            }
        }

        // valueMatch inteiro: valor de produtor igual ao valor consumido.
        let min = ctx.options.min_match_len.max(8);
        let bytes = value.value.as_bytes();
        let mut found: FoundMap = HashMap::new();
        if bytes.len() >= min {
            let partial_ok = bytes.len() >= OPAQUE_CONSUMER_MIN;
            // campo nomeado curto: peças só servem para a decomposição por inteiro
            let decomp_ok = !partial_ok && bytes.len() >= 16 && value.scope == ConsumedScope::Body;
            let strong_from: BTreeSet<Pos> = evidences.iter().map(|(r, _)| earlier[*r]).collect();
            for start in 0..=bytes.len() - 8 {
                let mut key = [0u8; 8];
                key.copy_from_slice(&bytes[start..start + 8]);
                let Some(candidates) = index.map.get(&key) else {
                    continue;
                };
                for (pos, n) in candidates {
                    if !earlier_set.contains(pos) {
                        continue;
                    }
                    let data = ctx.producer(*pos);
                    let item = &data.items[*n];
                    if !bytes[start..].starts_with(item.value.as_bytes()) {
                        continue;
                    }
                    if item.value.len() == bytes.len() {
                        if strong_from.contains(pos) {
                            continue; // já coberto por evidência forte
                        }
                        evidences.push((
                            rank[pos],
                            evidence(
                                ctx,
                                *pos,
                                item,
                                EvidenceKind::ValueMatch,
                                Strength::Medium,
                                None,
                                None,
                            ),
                        ));
                    } else if (partial_ok || decomp_ok) && !ctx.is_static(*pos) {
                        found.entry((start, item.value.len())).or_default().push((
                            *pos,
                            item.scope,
                            item.field.clone(),
                            item.offset,
                            item.html,
                        ));
                    }
                }
            }
            if value.scope == ConsumedScope::Body && partial_ok {
                opaque_candidates(ctx, value, &earlier, &mut found);
            }
        }
        let mut entry = finish_entry(ctx, value, evidences, &earlier);
        // Valor composto: campo nomeado curto coberto POR INTEIRO por >= 2 valores
        // de produtores + separadores. Cobertura parcial (só um prefixo) não vale.
        let mut composite_cover = false;
        let mut partial_hints: Vec<PartialComposition> = Vec::new();
        if entry.status == OriginStatus::None
            && !found.is_empty()
            && bytes.len() < OPAQUE_CONSUMER_MIN
        {
            match cover_pieces(bytes, &found) {
                Some(chosen) => {
                    found.retain(|key, _| chosen.contains(key));
                    composite_cover = true;
                }
                None => {
                    partial_hints = aligned_hints(ctx, bytes, &found, &rank);
                    found.clear();
                }
            }
        }
        // campo com origem própria não vira também "composto" (sem duplicar)
        let sub = if matches!(entry.status, OriginStatus::Origin | OriginStatus::Ambiguous) {
            Vec::new()
        } else {
            partial_entries(ctx, value, found, &rank)
        };
        if entry.status == OriginStatus::None && !sub.is_empty() {
            entry.status = OriginStatus::Composite;
            if composite_cover {
                entry.confidence = Some(Confidence::Possible);
            }
        }
        if entry.status == OriginStatus::None && !value.value.is_empty() {
            entry.repeated_from = repeated_from(ctx, value, &earlier);
            if !entry.repeated_from.is_empty() {
                entry.status = OriginStatus::Repeated;
            }
        }
        if matches!(entry.status, OriginStatus::None | OriginStatus::Repeated) {
            // Repetido: só valem os produtores anteriores à 1ª ocorrência do valor.
            if let Some(first) = entry.repeated_from.first().and_then(|id| ctx.find(id)) {
                if let Some(limit) = rank.get(&first).copied() {
                    partial_hints.retain(|h| {
                        ctx.find(&h.producer_request_id)
                            .and_then(|pos| rank.get(&pos).copied())
                            .is_some_and(|r| r < limit)
                    });
                }
            }
            entry.partial_composition = partial_hints;
        }
        relabel(&mut entry);
        result.values.push(entry);
        for part in sub {
            result.values.push(part);
        }
    }
    for entry in result.values.iter_mut() {
        for e in entry.evidences.iter_mut() {
            if let Some(pos) = ctx.by_attempt.get(&e.attempt_id) {
                if ctx.inferred(*pos, target) {
                    e.timing = Timing::Inferred;
                }
            }
        }
    }
    let hidden: Vec<Unobservable> = earlier
        .iter()
        .filter_map(|pos| {
            let body = &ctx.attempt(*pos).response_body;
            matches!(
                body.state,
                BodyState::Unavailable | BodyState::Discarded | BodyState::Truncated
            )
            .then(|| Unobservable {
                request_id: ctx.request_id(*pos).to_string(),
                state: body.state.as_str().to_string(),
                reason: body.note.clone(),
                suggestion: equivalent_later(ctx, *pos),
            })
        })
        .collect();
    if !hidden.is_empty() {
        for entry in result.values.iter_mut().filter(|v| {
            v.length > 0 && matches!(v.status, OriginStatus::None | OriginStatus::Repeated)
        }) {
            entry.unobservable = hidden.iter().take(20).cloned().collect();
            entry.label = format!(
                "{}; {} resposta(s) anterior(es) sem corpo observável",
                entry.label,
                hidden.len()
            );
            if let Some(hint) = hidden.iter().find_map(|h| {
                h.suggestion
                    .as_ref()
                    .map(|s| format!(" (ocorrência equivalente com corpo: {s})"))
            }) {
                entry.label.push_str(&hint);
            }
        }
    }
    if result.redacted_values > 0 {
        result.warnings.push(format!(
            "{} valor(es) redigido(s) ([REDACTED]) não podem ser rastreados",
            result.redacted_values
        ));
    }
    Ok(result)
}

fn evidence(
    ctx: &FlowContext<'_>,
    pos: Pos,
    item: &Item,
    kind: EvidenceKind,
    strength: Strength,
    consumed_offset: Option<u64>,
    consumed_length: Option<u64>,
) -> Evidence {
    Evidence {
        kind,
        strength,
        role: Role::Produced,
        request_id: ctx.request_id(pos).to_string(),
        attempt_id: ctx.attempt(pos).id.clone(),
        scope: item.scope,
        field: item.field.clone(),
        producer_offset: item.offset,
        consumed_offset,
        consumed_length,
        timing: Timing::Observed,
        html_control: item.html,
    }
}

/// Ordena por tempo, marca reemissões e decide o estado.
fn finish_entry(
    _ctx: &FlowContext<'_>,
    value: &Consumed,
    mut raw: Vec<(usize, Evidence)>,
    _earlier: &[Pos],
) -> ValueOrigin {
    raw.sort_by_key(|(rank, _)| *rank);
    // Mesmos bytes lidos por dois caminhos (controle HTML + literal `value="…"`)
    // são um produtor só: dedupe por (tentativa, intervalo sobreposto).
    let width = value.value.len() as u64;
    let rank_of = |e: &Evidence| {
        let s = match e.strength {
            Strength::Strong => 2,
            Strength::Medium => 1,
            Strength::Complement => 0,
        };
        (s, e.html_control)
    };
    let mut deduped: Vec<(usize, Evidence)> = Vec::new();
    for (r, e) in raw {
        let dup = e.producer_offset.and_then(|o| {
            deduped.iter().position(|(_, d)| {
                d.attempt_id == e.attempt_id
                    && d.producer_offset
                        .is_some_and(|d_o| d_o.abs_diff(o) < width.max(1))
            })
        });
        match dup {
            Some(i) => {
                if rank_of(&e) > rank_of(&deduped[i].1) {
                    deduped[i] = (r, e);
                }
            }
            None => deduped.push((r, e)),
        }
    }
    let mut raw = deduped;
    // Recurso estático só dá contexto: value-match estático nunca é produtor.
    let mut context: Vec<ContextNote> = Vec::new();
    let is_static_ev = |e: &Evidence| {
        e.kind == EvidenceKind::ValueMatch
            && _ctx
                .by_attempt
                .get(&e.attempt_id)
                .is_some_and(|pos| _ctx.is_static(*pos))
    };
    if raw.iter().any(|(_, e)| is_static_ev(e)) {
        let has_dynamic = raw.iter().any(|(_, e)| !is_static_ev(e));
        let (statics, dynamic): (Vec<_>, Vec<_>) =
            raw.into_iter().partition(|(_, e)| is_static_ev(e));
        if !has_dynamic {
            for (_, e) in &statics {
                if !context.iter().any(|c| c.request_id == e.request_id) {
                    context.push(ContextNote {
                        request_id: e.request_id.clone(),
                        field: e.field.clone(),
                        note: "valor também presente em recurso estático (pode ser constante do protocolo)".to_string(),
                    });
                }
            }
        }
        raw = dynamic;
    }
    let mut last: HashMap<(EvidenceKind, ProducerScope, Option<String>, Option<u64>), Pos> =
        HashMap::new();
    let mut evidences = Vec::new();
    let mut produced = 0usize;
    for (_, mut e) in raw {
        let key = (e.kind, e.scope, e.field.clone(), e.consumed_offset);
        let pos = _ctx.by_attempt.get(&e.attempt_id).copied();
        let mut reissued = false;
        if let (Some(prev), Some(pos)) = (last.get(&key).copied(), pos) {
            reissued = _ctx.circulated(&value.value, prev, pos);
        }
        if let Some(pos) = pos {
            last.insert(key, pos);
        }
        if reissued {
            e.role = Role::Reissued;
        } else {
            produced += 1;
        }
        evidences.push(e);
    }
    let oldest = if evidences.is_empty() { None } else { Some(0) };
    let mut note = None;
    if evidences.len() > _ctx.options.max_evidence {
        note = Some(format!(
            "{} evidência(s) adicionais omitidas (reemissões)",
            evidences.len() - _ctx.options.max_evidence
        ));
        evidences.truncate(_ctx.options.max_evidence);
    }
    let status = match produced {
        0 => OriginStatus::None,
        1 => OriginStatus::Origin,
        _ => OriginStatus::Ambiguous,
    };
    let confidence = (status != OriginStatus::None).then(|| {
        if evidences
            .iter()
            .any(|e| e.role == Role::Produced && e.strength == Strength::Strong)
        {
            Confidence::Strong
        } else {
            Confidence::Possible
        }
    });
    ValueOrigin {
        scope: value.scope,
        field: value.field.clone(),
        occurrence: value.occurrence,
        value: preview(&value.value),
        length: value.value.len(),
        status,
        label: String::new(),
        confidence,
        offset: None,
        oldest,
        evidences,
        repeated_from: Vec::new(),
        unobservable: Vec::new(),
        context,
        partial_composition: Vec::new(),
        parent: None,
        note,
    }
}

/// Próxima ocorrência do mesmo modelo (método + host + caminho + nomes de
/// campos) depois de `pos`, com corpo de resposta observável.
fn equivalent_later(ctx: &FlowContext<'_>, pos: Pos) -> Option<String> {
    let attempt = ctx.attempt(pos);
    let (host, path) = crate::compare::split_url(&attempt.url);
    let names = |p: Pos| -> Vec<String> {
        let mut n: Vec<String> = ctx
            .consumed_of(p)
            .iter()
            .filter(|c| matches!(c.scope, ConsumedScope::Query | ConsumedScope::Body))
            .map(|c| format!("{:?}:{}", c.scope, c.field))
            .collect();
        n.sort();
        n.dedup();
        n
    };
    let wanted = names(pos);
    let from = ctx.seq[&pos];
    for candidate in &ctx.ordered {
        if ctx.seq[candidate] <= from {
            continue;
        }
        let other = ctx.attempt(*candidate);
        if !other.method.eq_ignore_ascii_case(&attempt.method) {
            continue;
        }
        let (h, p) = crate::compare::split_url(&other.url);
        if h != host || p != path {
            continue;
        }
        if matches!(
            other.response_body.state,
            BodyState::Captured | BodyState::Truncated
        ) && names(*candidate) == wanted
        {
            return Some(ctx.request_id(*candidate).to_string());
        }
    }
    None
}

fn composition_label(entry: &ValueOrigin) -> String {
    let h = &entry.partial_composition[0];
    format!(
        "sem origem observada; contém o valor de {} de {} ({}) e parte sem fonte observada — provável composição no cliente",
        h.field.as_deref().unwrap_or("?"),
        h.producer_request_id,
        if h.start == 0 { "prefixo" } else { "trecho" }
    )
}

fn relabel(entry: &mut ValueOrigin) {
    entry.label = match entry.status {
        OriginStatus::Origin | OriginStatus::Ambiguous => {
            let oldest = entry.oldest.and_then(|i| entry.evidences.get(i));
            let kind = oldest.map_or("?", |e| match e.kind {
                EvidenceKind::CookieJar => "cookie-jar",
                EvidenceKind::SameField => "same-field",
                EvidenceKind::ValueMatch => "value-match",
                EvidenceKind::Initiator => "initiator",
            });
            let id = oldest.map_or("?", |e| e.request_id.as_str());
            match (entry.status, entry.confidence) {
                (OriginStatus::Origin, Some(Confidence::Strong)) => "origem observada".to_string(),
                (OriginStatus::Origin, _) => format!("possível origem ({kind})"),
                (_, Some(Confidence::Strong)) => format!("ambíguo (mais antigo: {id})"),
                _ => format!("possível origem ({kind}), ambíguo (mais antigo: {id})"),
            }
        }
        OriginStatus::Repeated if !entry.partial_composition.is_empty() => format!(
            "{} (valor já circulava em {})",
            composition_label(entry),
            entry.repeated_from.join(", ")
        ),
        OriginStatus::Repeated => format!(
            "sem origem observada (valor já circulava em {})",
            entry.repeated_from.join(", ")
        ),
        OriginStatus::None if !entry.partial_composition.is_empty() => composition_label(entry),
        OriginStatus::None if !entry.context.is_empty() => {
            "sem origem observada; valor também presente em recurso estático (pode ser constante do protocolo)".to_string()
        }
        OriginStatus::None => "sem origem observada".to_string(),
        OriginStatus::Composite if entry.confidence == Some(Confidence::Possible) => {
            "possível origem composta: ver trechos (parent)".to_string()
        }
        OriginStatus::Composite => "composto: ver trechos (parent)".to_string(),
        OriginStatus::Redacted => "redigido: não rastreável".to_string(),
    };
}

fn repeated_from(ctx: &FlowContext<'_>, value: &Consumed, earlier: &[Pos]) -> Vec<String> {
    let mut out = Vec::new();
    for pos in earlier {
        let data = ctx.consumed_of(*pos);
        if data.iter().any(|c| {
            c.scope == value.scope
                && c.field.eq_ignore_ascii_case(&value.field)
                && c.value == value.value
        }) {
            let id = ctx.request_id(*pos).to_string();
            if !out.contains(&id) {
                out.push(id);
            }
        }
    }
    out
}

type Producer = (Pos, ProducerScope, Option<String>, Option<u64>, bool);
type FoundMap = HashMap<(usize, usize), Vec<Producer>>;

/// Trechos de um campo opaco que coincidem (>= 8) com o mesmo campo em
/// respostas anteriores (substrings comuns maximais). Um trecho que difere de
/// um contador numérico (`...0005` × `...0001`) não é uma coincidência.
fn opaque_candidates(
    ctx: &FlowContext<'_>,
    value: &Consumed,
    earlier: &[Pos],
    found: &mut FoundMap,
) {
    let min = ctx.options.min_match_len.max(8);
    let a = value.value.as_bytes();
    for pos in earlier {
        let data = ctx.producer(*pos);
        for field in data.opaque.iter() {
            let (name, other) = (&field.name, &field.value);
            if !name.eq_ignore_ascii_case(&value.field) || is_redacted(other) {
                continue;
            }
            let b = other.as_bytes();
            if a.len().saturating_mul(b.len()) > ctx.options.max_opaque_cells {
                continue;
            }
            for (start, len, other_start) in maximal_common(a, b, min) {
                if start == 0 && len == a.len() {
                    continue; // valor inteiro: evidência do próprio campo
                }
                if cut_in_number(a, b, start, len, other_start) {
                    continue;
                }
                let original = field
                    .map
                    .as_ref()
                    .and_then(|m| m.get(other_start).copied())
                    .unwrap_or(other_start);
                found.entry((start, len)).or_default().push((
                    *pos,
                    ProducerScope::ResponseBody,
                    Some(name.clone()),
                    Some(original as u64),
                    field.html,
                ));
            }
        }
    }
}

/// O trecho comum termina (ou começa) no meio de uma sequência de dígitos que
/// difere dos dois lados: é um contador, não um valor compartilhado.
/// Peças que cobrem o valor inteiro (exceto separadores `_ - . : |`), com pelo
/// menos 2 produtores distintos; `None` se houver lacuna (prefixo parcial não vale).
/// Partes conhecidas (>= 8) de um valor curto alinhadas a um separador
/// `_ - . : |` ou à borda: dica de composição parcial (não é origem).
fn aligned_hints(
    ctx: &FlowContext<'_>,
    bytes: &[u8],
    found: &FoundMap,
    rank: &HashMap<Pos, usize>,
) -> Vec<PartialComposition> {
    let sep = |b: u8| matches!(b, b'_' | b'-' | b'.' | b':' | b'|');
    let mut keys: Vec<&(usize, usize)> = found.keys().collect();
    keys.sort_by(|x, y| y.1.cmp(&x.1).then(x.0.cmp(&y.0)));
    let mut taken: Vec<(usize, usize)> = Vec::new();
    let mut out = Vec::new();
    for &&(start, len) in &keys {
        let end = start + len;
        let left = start == 0 || sep(bytes[start - 1]);
        let right = end == bytes.len() || sep(bytes[end]);
        if len < 8 || !left || !right || (start == 0 && end == bytes.len()) {
            continue;
        }
        if taken.iter().any(|(s, l)| start < s + l && *s < end) {
            continue;
        }
        let Some((pos, _, field, _, _)) = found[&(start, len)]
            .iter()
            .min_by_key(|(pos, ..)| rank.get(pos).copied().unwrap_or(usize::MAX))
        else {
            continue;
        };
        taken.push((start, len));
        out.push(PartialComposition {
            producer_request_id: ctx.request_id(*pos).to_string(),
            field: field.clone(),
            start,
            length: len,
        });
    }
    out.sort_by_key(|h| h.start);
    out
}

fn cover_pieces(bytes: &[u8], found: &FoundMap) -> Option<Vec<(usize, usize)>> {
    let mut chosen: Vec<(usize, usize)> = Vec::new();
    let mut producers: BTreeSet<Pos> = BTreeSet::new();
    let mut i = 0;
    while i < bytes.len() {
        if matches!(bytes[i], b'_' | b'-' | b'.' | b':' | b'|') {
            i += 1;
            continue;
        }
        let best = found
            .keys()
            .filter(|(start, _)| *start == i)
            .max_by_key(|(_, len)| *len)?;
        chosen.push(*best);
        producers.insert(found[best][0].0);
        i += best.1;
    }
    (chosen.len() >= 2 && producers.len() >= 2).then_some(chosen)
}

fn cut_in_number(a: &[u8], b: &[u8], start: usize, len: usize, other_start: usize) -> bool {
    let digit = |s: &[u8], i: usize| s.get(i).is_some_and(u8::is_ascii_digit);
    let right = digit(a, start + len) && digit(b, other_start + len) && digit(a, start + len - 1);
    let left = start > 0
        && other_start > 0
        && digit(a, start - 1)
        && digit(b, other_start - 1)
        && digit(a, start);
    right || left
}

/// Entradas `parent` para os trechos escolhidos (mais longos primeiro, sem
/// sobreposição).
fn partial_entries(
    ctx: &FlowContext<'_>,
    value: &Consumed,
    found: FoundMap,
    rank: &HashMap<Pos, usize>,
) -> Vec<ValueOrigin> {
    let a = value.value.as_bytes();
    let mut chosen: Vec<_> = found.into_iter().collect();
    chosen.sort_by(|x, y| y.0 .1.cmp(&x.0 .1).then(x.0 .0.cmp(&y.0 .0)));
    let mut taken: Vec<(usize, usize)> = Vec::new();
    let mut out = Vec::new();
    let min_len = ctx.options.min_match_len.max(8);
    for ((orig_start, orig_len), producers) in chosen {
        // Um trecho que sobrepõe um já escolhido é aparado ao que sobra livre
        // (>= mínimo), em vez de descartado: a ponta de um valor (ex.: o delta no
        // fim do XML) não pode se perder por 1 byte de sobreposição.
        let (mut s0, mut e0) = (orig_start, orig_start + orig_len);
        for _ in 0..2 {
            for (ts, tl) in &taken {
                let te = ts + tl;
                if s0 < te && *ts < e0 {
                    if *ts <= s0 {
                        s0 = te.min(e0);
                    } else if te >= e0 {
                        e0 = (*ts).max(s0);
                    } else {
                        e0 = s0; // trecho já escolhido no meio: descarta
                    }
                }
            }
        }
        if e0 <= s0 || e0 - s0 < min_len {
            continue;
        }
        let shift = (s0 - orig_start) as u64;
        let (start, len) = (s0, e0 - s0);
        let producers: Vec<_> = producers
            .into_iter()
            .map(|(pos, scope, field, offset, html)| {
                (pos, scope, field, offset.map(|o| o + shift), html)
            })
            .collect();
        taken.push((start, len));
        let mut raw = Vec::new();
        for (pos, scope, field, offset, html) in producers {
            let item = Item {
                scope,
                field,
                value: String::new(),
                offset,
                named: true,
                html,
                soft: false,
            };
            raw.push((
                rank[&pos],
                evidence(
                    ctx,
                    pos,
                    &item,
                    EvidenceKind::ValueMatch,
                    Strength::Medium,
                    Some(start as u64),
                    Some(len as u64),
                ),
            ));
        }
        let sub = Consumed {
            scope: value.scope,
            field: value.field.clone(),
            occurrence: value.occurrence,
            value: String::from_utf8_lossy(&a[start..start + len]).into_owned(),
        };
        let mut entry = finish_entry(ctx, &sub, raw, &[]);
        entry.parent = Some(value.field.clone());
        entry.offset = Some(start as u64);
        if a.len() < OPAQUE_CONSUMER_MIN {
            // componentes de um campo nomeado curto: `token[0]`, `token[1]`…
            entry.field = format!("{}[{}]", value.field, out.len());
        }
        relabel(&mut entry);
        out.push((start, entry));
    }
    // Trechos sem nenhum produtor: "sem origem observada" (constantes,
    // entrada do usuário ou gerado no cliente).
    if !taken.is_empty() {
        taken.sort();
        let mut cursor = 0usize;
        let mut gaps: Vec<(usize, usize)> = Vec::new();
        for (start, len) in &taken {
            if *start > cursor {
                gaps.push((cursor, *start));
            }
            cursor = cursor.max(start + len);
        }
        if cursor < a.len() {
            gaps.push((cursor, a.len()));
        }
        for (start, end) in gaps.into_iter().filter(|(s, e)| e - s >= 4) {
            let text = String::from_utf8_lossy(&a[start..end]).into_owned();
            let mut entry = ValueOrigin {
                scope: value.scope,
                field: value.field.clone(),
                occurrence: value.occurrence,
                value: preview(&text),
                length: end - start,
                status: OriginStatus::None,
                label: String::new(),
                confidence: None,
                offset: Some(start as u64),
                oldest: None,
                evidences: Vec::new(),
                repeated_from: Vec::new(),
                unobservable: Vec::new(),
                context: Vec::new(),
                partial_composition: Vec::new(),
                parent: Some(value.field.clone()),
                note: None,
            };
            relabel(&mut entry);
            out.push((start, entry));
        }
    }
    out.sort_by_key(|(start, _)| *start);
    out.into_iter().map(|(_, entry)| entry).collect()
}

/// Substrings comuns maximais (à direita) de `a` e `b` com >= `min` bytes:
/// (início em `a`, comprimento, início em `b`).
pub(crate) fn maximal_common(a: &[u8], b: &[u8], min: usize) -> Vec<(usize, usize, usize)> {
    let mut out = Vec::new();
    if a.len() < min || b.len() < min {
        return out;
    }
    // prev[j] = comprimento do sufixo comum terminando em (i-1, j-1).
    let mut prev = vec![0u32; b.len() + 1];
    let mut cur = vec![0u32; b.len() + 1];
    // Para detectar maximalidade à direita precisamos da linha seguinte; então
    // guardamos candidatos e confirmamos quando a diagonal seguinte não cresce.
    let mut pending: Vec<(usize, usize, u32)> = Vec::new(); // (i, j, len) da linha anterior
    for i in 0..a.len() {
        for j in 0..b.len() {
            cur[j + 1] = if a[i] == b[j] { prev[j] + 1 } else { 0 };
        }
        // confirma candidatos da linha anterior
        for (pi, pj, plen) in pending.drain(..) {
            let grew = pi + 1 < a.len() && pj + 1 < b.len() && cur[pj + 2] == plen + 1;
            if !grew {
                let len = plen as usize;
                out.push((pi + 1 - len, len, pj + 1 - len));
            }
        }
        for j in 0..b.len() {
            if cur[j + 1] as usize >= min && (cur[j + 1] as usize) > 0 {
                pending.push((i, j, cur[j + 1]));
            }
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    for (pi, pj, plen) in pending {
        let len = plen as usize;
        out.push((pi + 1 - len, len, pj + 1 - len));
    }
    out.sort();
    out.dedup();
    out
}

// ---------------------------------------------------------------------------
// priming_chain
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StepClass {
    Application,
    Protection,
    /// Página de contexto (documento que carregou a página de onde um passo
    /// foi emitido): nunca produtora de valor.
    Page,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StepReason {
    /// Valor que a requisição fornece (campo e prévia).
    pub provides: String,
    pub field: String,
    pub kind: EvidenceKind,
    pub strength: Strength,
    /// Requisição da cadeia que consome o valor.
    pub consumed_by: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainStep {
    pub request_id: String,
    pub attempt_id: String,
    pub method: String,
    pub url: String,
    pub started_at: Option<f64>,
    pub class: StepClass,
    /// `strong` se algum motivo tem evidência forte; senão `possible`.
    pub confidence: Confidence,
    /// Motivo legível (campos que a requisição fornece e quem os consome).
    pub reason: String,
    pub reasons: Vec<StepReason>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrimingChain {
    pub request_id: String,
    /// Requisições da aplicação necessárias, na ordem do fluxo.
    pub steps: Vec<ChainStep>,
    /// Requisições de proteção (/TSPD/, cookies TS*), separadas.
    pub protection: Vec<ChainStep>,
    /// Páginas de contexto (Referer): documentos que carregaram a página de onde
    /// cada passo foi emitido. Não produzem valores.
    pub pages: Vec<ChainStep>,
    /// Frames auxiliares no caminho de Referer (`*_JLIBS.html`, `cscform.html`…):
    /// recolhidos fora de `pages`.
    pub auxiliary_pages: Vec<ChainStep>,
    /// Valores sem origem observada, ambíguos ou redigidos (não resolvidos).
    pub unresolved: Vec<UnresolvedValue>,
    pub redacted_values: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnresolvedValue {
    pub label: String,
    pub partial_composition: Vec<PartialComposition>,
    pub unobservable: Vec<Unobservable>,
    pub request_id: String,
    pub scope: ConsumedScope,
    pub field: String,
    pub status: OriginStatus,
}

pub(crate) fn is_protection_path(url: &str) -> bool {
    let path = url.split('?').next().unwrap_or(url);
    path.contains("/TSPD/") || path.ends_with("/TSPD")
}

fn is_ts_cookie(name: &str) -> bool {
    name.len() > 2 && name.starts_with("TS") && name[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// Documento que carregou `pos` (Referer ou `initiator.url`): GET HTML, anterior,
/// fora de proteção e de estáticos. É a aresta da cadeia de páginas.
fn referer_page_of(ctx: &FlowContext<'_>, pos: Pos) -> Option<Pos> {
    let attempt = ctx.attempt_ref(pos);
    let referer = attempt
        .request_headers
        .first_value("referer")
        .or_else(|| attempt.initiator.as_ref().and_then(|i| i.url.as_deref()))?;
    let referer = referer.split('#').next().unwrap_or(referer);
    ctx.positions()
        .filter(|cand| {
            let a = ctx.attempt_ref(*cand);
            *cand != pos
                && ctx.rel(*cand, pos) == Rel::Before
                && a.url.split('#').next() == Some(referer)
                && a.method.eq_ignore_ascii_case("GET")
                && !ctx.is_static(*cand)
                && !is_protection_path(&a.url)
        })
        .max_by_key(|cand| ctx.seq[cand])
}

/// Raiz da cadeia de Referer acima de `pos`: a entrada da rodada a que ele pertence.
fn referer_root(ctx: &FlowContext<'_>, pos: Pos) -> Option<Pos> {
    let mut cur = pos;
    let mut root = None;
    for _ in 0..12 {
        let Some(parent) = referer_page_of(ctx, cur) else {
            break;
        };
        root = Some(parent);
        cur = parent;
    }
    root
}

/// Documento de entrada: GET HTML da aplicação, fora de proteção e de estáticos e
/// não iniciado pelo parser (frame).
fn is_entry_document(ctx: &FlowContext<'_>, pos: Pos) -> bool {
    let a = ctx.attempt_ref(pos);
    if !a.method.eq_ignore_ascii_case("GET")
        || ctx.is_static(pos)
        || is_protection_path(&a.url)
        || a.initiator
            .as_ref()
            .is_some_and(|i| i.kind.eq_ignore_ascii_case("parser"))
    {
        return false;
    }
    a.response_headers
        .first_value("content-type")
        .is_some_and(|ct| ct.to_ascii_lowercase().contains("html"))
}

/// Começo da rodada do alvo: a ocorrência mais recente, até ele, do documento de
/// entrada (o primeiro documento da aplicação da sessão). Um POST do Connector tem
/// Referer do próprio Connector, então a raiz de Referer sozinha não acha a rodada.
/// Sem documento de entrada, cai na raiz da cadeia de Referer.
fn round_start_of(ctx: &FlowContext<'_>, target: Pos) -> Option<Pos> {
    let first = ctx
        .positions()
        .filter(|pos| is_entry_document(ctx, *pos))
        .min_by_key(|pos| ctx.seq[pos]);
    if let Some(first) = first {
        let base = |pos: Pos| {
            let (host, path) = crate::compare::split_url(&ctx.attempt_ref(pos).url);
            format!("{host}|{path}")
        };
        let entry = base(first);
        let start = ctx
            .positions()
            .filter(|pos| ctx.seq[pos] < ctx.seq[&target])
            .filter(|pos| is_entry_document(ctx, *pos))
            .filter(|pos| base(*pos) == entry)
            .max_by_key(|pos| ctx.seq[pos]);
        return start.or(Some(first).filter(|pos| ctx.seq[pos] <= ctx.seq[&target]));
    }
    referer_root(ctx, target)
}

/// Fecho transitivo das origens fortes e médias da requisição alvo.
pub fn priming_chain(
    session: &SessionV1,
    source: &dyn BodySource,
    request_id: &str,
    options: &FlowOptions,
) -> Result<PrimingChain> {
    let ctx = FlowContext::new(session, source, options);
    let mut chain = PrimingChain {
        request_id: request_id.to_string(),
        steps: Vec::new(),
        protection: Vec::new(),
        pages: Vec::new(),
        auxiliary_pages: Vec::new(),
        unresolved: Vec::new(),
        redacted_values: 0,
        warnings: Vec::new(),
    };
    let mut included: HashMap<String, ChainStep> = HashMap::new();
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut queue = vec![request_id.to_string()];
    // A cadeia fica na rodada do alvo: produtores anteriores à entrada da rodada
    // (raiz da cadeia de Referer do alvo) não viram passo. Sem Referer, não há
    // fronteira e vale a sessão inteira.
    let round_start = ctx
        .find(request_id)
        .and_then(|target| round_start_of(&ctx, target))
        .map(|start| ctx.seq[&start]);
    while let Some(current) = queue.pop() {
        if !visited.insert(current.clone()) {
            continue;
        }
        let origins = origins_in(&ctx, &current)?;
        chain.redacted_values += origins.redacted_values;
        for w in &origins.warnings {
            if !chain.warnings.contains(w) {
                chain.warnings.push(w.clone());
            }
        }
        let current_protection = ctx
            .find(&current)
            .is_some_and(|pos| is_protection_path(&ctx.attempt_ref(pos).url));
        for value in &origins.values {
            if value.status == OriginStatus::Composite {
                continue;
            }
            if matches!(
                value.status,
                OriginStatus::None | OriginStatus::Redacted | OriginStatus::Repeated
            ) {
                if value.parent.is_none() && value.length > 0 && !current_protection {
                    chain.unresolved.push(UnresolvedValue {
                        label: value.label.clone(),
                        partial_composition: value.partial_composition.clone(),
                        unobservable: value.unobservable.clone(),
                        request_id: current.clone(),
                        scope: value.scope,
                        field: value.field.clone(),
                        status: value.status,
                    });
                }
                continue;
            }
            if value.status == OriginStatus::Ambiguous
                && value.parent.is_none()
                && !current_protection
            {
                chain.unresolved.push(UnresolvedValue {
                    label: value.label.clone(),
                    partial_composition: value.partial_composition.clone(),
                    unobservable: value.unobservable.clone(),
                    request_id: current.clone(),
                    scope: value.scope,
                    field: value.field.clone(),
                    status: value.status,
                });
            }
            // Para a CADEIA, o passo é o produtor da própria rodada do alvo
            // (`produced` ou `reissued`): um valor constante do protocolo (ex.:
            // STAMP=INIT) é reemitido por cada página, e repetir as reemissões
            // só engorda a cadeia sem acrescentar valor. Escolhe-se o primeiro
            // produtor da rodada; só quando não há nenhum nela (ex.: cookie
            // definido uma única vez) sobe-se para o mais recente anterior. As
            // origens continuam listando todos os produtores.
            let nearest = ctx.find(&current).and_then(|consumer| {
                let candidates: Vec<(Pos, &Evidence)> = value
                    .evidences
                    .iter()
                    .filter(|e| {
                        matches!(e.role, Role::Produced | Role::Reissued)
                            && matches!(e.strength, Strength::Strong | Strength::Medium)
                            && e.request_id != current
                    })
                    .filter_map(|e| ctx.find(&e.request_id).map(|pos| (pos, e)))
                    .filter(|(pos, _)| ctx.rel(*pos, consumer) == Rel::Before)
                    .collect();
                match round_start {
                    Some(start) => candidates
                        .iter()
                        .copied()
                        .filter(|(pos, _)| ctx.seq[pos] >= start)
                        .min_by_key(|(pos, _)| ctx.seq[pos])
                        .or_else(|| {
                            // Exceção: valor forte (ex.: cookie definido uma única
                            // vez) cujo único produtor ficou numa rodada anterior.
                            // Fragmentos médios de XML não justificam subir.
                            candidates
                                .iter()
                                .copied()
                                .filter(|(_, e)| e.strength == Strength::Strong)
                                .max_by_key(|(pos, _)| ctx.seq[pos])
                        }),
                    None => candidates
                        .iter()
                        .copied()
                        .max_by_key(|(pos, _)| ctx.seq[pos]),
                }
            });
            if let Some((pos, e)) = nearest {
                let attempt = ctx.attempt_ref(pos);
                let producer_id = ctx.request_id(pos).to_string();
                let step = included
                    .entry(producer_id.clone())
                    .or_insert_with(|| ChainStep {
                        request_id: producer_id.clone(),
                        attempt_id: attempt.id.clone(),
                        method: attempt.method.clone(),
                        url: attempt.url.clone(),
                        started_at: attempt.started_at,
                        class: StepClass::Application,
                        confidence: Confidence::Possible,
                        reason: String::new(),
                        reasons: Vec::new(),
                    });
                step.reasons.push(StepReason {
                    provides: value.value.chars().take(60).collect(),
                    field: value.field.clone(),
                    kind: e.kind,
                    strength: e.strength,
                    consumed_by: current.clone(),
                });
                queue.push(producer_id);
            }
        }
    }
    let target_pos = ctx.find(request_id);
    let mut all: Vec<ChainStep> = included.into_values().collect();
    for step in &mut all {
        step.confidence = if step.reasons.iter().any(|r| r.strength == Strength::Strong) {
            Confidence::Strong
        } else {
            Confidence::Possible
        };
        let only_ts =
            !step.reasons.is_empty() && step.reasons.iter().all(|r| is_ts_cookie(&r.field));
        if is_protection_path(&step.url) || only_ts {
            step.class = StepClass::Protection;
        }
    }
    // Requisições /TSPD/ anteriores ao alvo entram como proteção, mesmo sem
    // fornecer um valor consumido (regra explícita por caminho).
    if let Some(target) = target_pos {
        for pos in ctx.positions() {
            let attempt = ctx.attempt_ref(pos);
            let id = ctx.request_id(pos);
            if ctx.rel(pos, target) == Rel::Before
                && is_protection_path(&attempt.url)
                && !all.iter().any(|s| s.request_id == id)
            {
                all.push(ChainStep {
                    request_id: id.to_string(),
                    attempt_id: attempt.id.clone(),
                    method: attempt.method.clone(),
                    url: attempt.url.clone(),
                    started_at: attempt.started_at,
                    class: StepClass::Protection,
                    confidence: Confidence::Possible,
                    reason: "proteção: caminho /TSPD/ antes da requisição alvo".to_string(),
                    reasons: vec![StepReason {
                        provides: "proteção (caminho /TSPD/)".to_string(),
                        field: String::new(),
                        kind: EvidenceKind::Initiator,
                        strength: Strength::Complement,
                        consumed_by: request_id.to_string(),
                    }],
                });
            }
        }
    }
    for step in &mut all {
        if step.reason.is_empty() {
            let mut parts: Vec<String> = Vec::new();
            for r in &step.reasons {
                let text = format!("fornece {} a {} ({:?})", r.field, r.consumed_by, r.kind);
                if !parts.contains(&text) {
                    parts.push(text);
                }
            }
            let prefix = if step.class == StepClass::Protection {
                "proteção: "
            } else {
                ""
            };
            step.reason = format!("{prefix}{}", parts.join("; "));
        }
    }
    all.sort_by(|a, b| {
        let key = |s: &ChainStep| {
            let pos = ctx.find(&s.request_id).unwrap_or((usize::MAX, 0));
            (s.started_at.map(|t| (t * 1e6) as i64), pos.0)
        };
        key(a).cmp(&key(b))
    });
    // Páginas de contexto, só a partir do alvo e dos passos da aplicação (nunca de
    // proteção ou estáticos). Sobe a cadeia de Referer entre documentos: a raiz
    // (entrada) e o documento logo abaixo dela são as páginas; os frames
    // intermediários (ex.: `*_JLIBS.html`, `cscform.html`) são `auxiliaryPages`.
    {
        let emitters: Vec<(String, Pos)> = std::iter::once(request_id.to_string())
            .chain(
                all.iter()
                    .filter(|s| s.class == StepClass::Application)
                    .map(|s| s.request_id.clone()),
            )
            .filter_map(|id| ctx.find(&id).map(|pos| (id, pos)))
            .collect();
        let referer_page = |pos: Pos| -> Option<Pos> { referer_page_of(&ctx, pos) };
        let make = |cand: Pos, emitter: &str, aux: bool| {
            let a = ctx.attempt_ref(cand);
            ChainStep {
                request_id: ctx.request_id(cand).to_string(),
                attempt_id: a.id.clone(),
                method: a.method.clone(),
                url: a.url.clone(),
                started_at: a.started_at,
                class: StepClass::Page,
                confidence: Confidence::Possible,
                reason: if aux {
                    format!("página auxiliar (frame) no caminho de {emitter}")
                } else {
                    format!(
                        "página de contexto: carregou a página de onde {emitter} foi emitido (Referer)"
                    )
                },
                reasons: vec![StepReason {
                    provides: if aux {
                        "página auxiliar".to_string()
                    } else {
                        "página de contexto".to_string()
                    },
                    field: String::new(),
                    kind: EvidenceKind::Initiator,
                    strength: Strength::Complement,
                    consumed_by: emitter.to_string(),
                }],
            }
        };
        let mut pages: Vec<ChainStep> = Vec::new();
        let mut auxiliary: Vec<ChainStep> = Vec::new();
        // Passos de rodadas anteriores (antes da raiz de Referer do alvo) não
        // trazem as páginas da rodada deles.
        for (emitter, pos) in emitters {
            if round_start.is_some_and(|start| ctx.seq[&pos] < start) {
                continue;
            }
            let mut ancestors: Vec<Pos> = Vec::new();
            let mut cur = pos;
            while let Some(parent) = referer_page(cur) {
                if ancestors.contains(&parent) || ancestors.len() >= 12 {
                    break;
                }
                ancestors.push(parent);
                cur = parent;
            }
            // Frame auxiliar = documento iniciado pelo parser (iframe/frame); sem
            // iniciador na fonte, todo documento do caminho é página.
            for cand in ancestors {
                let id = ctx.request_id(cand);
                if id == request_id {
                    continue;
                }
                // Páginas de rodadas anteriores não entram na rodada do alvo.
                if round_start.is_some_and(|start| ctx.seq[&cand] < start) {
                    continue;
                }
                let aux = ctx
                    .attempt_ref(cand)
                    .initiator
                    .as_ref()
                    .is_some_and(|i| i.kind.eq_ignore_ascii_case("parser"));
                let list = if aux { &mut auxiliary } else { &mut pages };
                if !list.iter().any(|p| p.request_id == id) {
                    list.push(make(cand, &emitter, aux));
                }
            }
        }
        auxiliary.retain(|a| !pages.iter().any(|p| p.request_id == a.request_id));
        let by_time = |a: &ChainStep, b: &ChainStep| {
            a.started_at
                .partial_cmp(&b.started_at)
                .unwrap_or(std::cmp::Ordering::Equal)
        };
        pages.sort_by(by_time);
        auxiliary.sort_by(by_time);
        chain.pages = pages;
        chain.auxiliary_pages = auxiliary;
    }
    for step in all {
        match step.class {
            StepClass::Page => {}
            StepClass::Application => chain.steps.push(step),
            StepClass::Protection => chain.protection.push(step),
        }
    }
    let protection_ids: BTreeSet<String> = chain
        .protection
        .iter()
        .map(|step| step.request_id.clone())
        .collect();
    chain
        .unresolved
        .retain(|u| !protection_ids.contains(&u.request_id));
    chain.unresolved.dedup();
    Ok(chain)
}
