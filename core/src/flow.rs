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
//!   offset (trechos), oldest (índice em evidences), parent (campo opaco do trecho),
//!   repeatedFrom[], note, evidences: [ { kind: cookie-jar|same-field|value-match|initiator,
//!     strength: strong|medium|complement, role: produced|reissued, producerRequestId,
//!     producerAttemptId, scope: setCookie|responseHeader|location|responseBody, field,
//!     producerOffset, consumedOffset, consumedLength } ] }
//! chain: { requestId, steps: [ChainStep], protection: [ChainStep], unresolved[], warnings }
//! ChainStep: { requestId, attemptId, method, url, startedAt, class: application|protection,
//!   reason, reasons: [ { provides, field, kind, strength, consumedBy } ] }
//! ```
//!
//! O esquema de `compare` está em [`crate::compare`].
//!
//! Regras:
//! - só entram produtores observados ANTES da tentativa alvo (tempo de início da
//!   tentativa; sem tempo em algum dos lados, a ordem da sessão). Empate de
//!   tempo nunca vira produtor: fica em `ties`;
//! - evidências separadas: `cookieJar` e `sameField` (fortes; `sameField`
//!   vale mesmo para valores curtos porque o nome amarra), `valueMatch`
//!   (média; valor de resposta com >= 8 caracteres encontrado na requisição,
//!   inteiro ou como substring de campo opaco) e `initiator` (complemento; o
//!   modelo atual não preserva o initiator do CDP, o que é declarado);
//! - nenhum candidato = `none` ("sem origem observada"); vários produtores
//!   independentes = `ambiguous` com todos os candidatos e o mais antigo
//!   indicado; reemissões do mesmo valor pela mesma fonte são `reissued`;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Role {
    Produced,
    Reissued,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Offset do trecho no valor consumido (entradas `parent`).
    pub offset: Option<u64>,
    /// Índice em `evidences` do produtor mais antigo.
    pub oldest: Option<usize>,
    pub evidences: Vec<Evidence>,
    /// Requisições anteriores que já carregavam o valor (`repeated`).
    pub repeated_from: Vec<String>,
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
}

#[derive(Debug, Default)]
struct ProducerData {
    items: Vec<Item>,
    /// Campos opacos de resposta (nome, valor) para comparação por substring.
    opaque: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub(crate) struct Consumed {
    pub(crate) scope: ConsumedScope,
    pub(crate) field: String,
    pub(crate) occurrence: usize,
    pub(crate) value: String,
}

const REDACTED_MARK: &str = "REDACTED";
const OPAQUE_MIN: usize = 16;

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
            });
            for (name, value) in query_pairs(&entry.value) {
                data.items.push(Item {
                    scope: ProducerScope::Location,
                    field: Some(name),
                    value,
                    offset: None,
                    named: true,
                });
            }
        } else if !is_protocol_header(&lower) {
            data.items.push(Item {
                scope: ProducerScope::ResponseHeader,
                field: Some(lower),
                value: entry.value.clone(),
                offset: None,
                named: true,
            });
        }
    }
    if let Some(text) = body_text(source, &attempt.response_body) {
        let media = media_of(&attempt.response_headers, &attempt.response_body);
        match named_fields(&text, &media) {
            Some(fields) => {
                for (name, value, offset) in fields {
                    if value.len() >= OPAQUE_MIN {
                        data.opaque.push((name.clone(), value.clone()));
                    }
                    data.items.push(Item {
                        scope: ProducerScope::ResponseBody,
                        field: Some(name),
                        value,
                        offset,
                        named: true,
                    });
                }
            }
            None => {
                for (literal, offset, hint) in string_literals(&text, min) {
                    data.items.push(Item {
                        scope: ProducerScope::ResponseBody,
                        field: hint,
                        value: literal,
                        offset: Some(offset),
                        named: false,
                    });
                }
            }
        }
    }
    data
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
        let mut next = 0;
        for (ri, request) in session.requests.iter().enumerate() {
            for ai in 0..request.attempts.len() {
                seq.insert((ri, ai), next);
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

    fn rel(&self, candidate: Pos, target: Pos) -> Rel {
        if candidate == target {
            return Rel::After;
        }
        let (a, b) = (self.attempt(candidate), self.attempt(target));
        match (a.started_at, b.started_at) {
            (Some(x), Some(y)) => {
                if x < y {
                    Rel::Before
                } else if x > y {
                    Rel::After
                } else {
                    Rel::Tie
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
        warnings: vec![
            "initiator do CDP não é preservado no modelo: evidência `initiator` indisponível"
                .to_string(),
        ],
    };

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
                offset: None,
                oldest: None,
                evidences: Vec::new(),
                repeated_from: Vec::new(),
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
                    evidences.push((
                        rank[pos],
                        evidence(ctx, *pos, item, kind, Strength::Strong, None, None),
                    ));
                }
            }
        }

        // valueMatch inteiro: valor de produtor igual ao valor consumido.
        let min = ctx.options.min_match_len.max(8);
        let bytes = value.value.as_bytes();
        let mut found: FoundMap = HashMap::new();
        if bytes.len() >= min {
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
                    } else {
                        found.entry((start, item.value.len())).or_default().push((
                            *pos,
                            item.scope,
                            item.field.clone(),
                            item.offset,
                        ));
                    }
                }
            }
            if value.scope == ConsumedScope::Body && bytes.len() >= OPAQUE_MIN {
                opaque_candidates(ctx, value, &earlier, &mut found);
            }
        }
        let sub = partial_entries(ctx, value, found, &rank);
        let mut entry = finish_entry(ctx, value, evidences, &earlier);
        if entry.status == OriginStatus::None && !sub.is_empty() {
            entry.status = OriginStatus::Composite;
        }
        if entry.status == OriginStatus::None && !value.value.is_empty() {
            entry.repeated_from = repeated_from(ctx, value, &earlier);
            if !entry.repeated_from.is_empty() {
                entry.status = OriginStatus::Repeated;
            }
        }
        relabel(&mut entry);
        result.values.push(entry);
        for part in sub {
            result.values.push(part);
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
    let mut groups: Vec<(EvidenceKind, ProducerScope, Option<String>, Option<u64>)> = Vec::new();
    let mut evidences = Vec::new();
    let mut produced = 0usize;
    for (_, mut e) in raw {
        let key = (e.kind, e.scope, e.field.clone(), e.consumed_offset);
        if groups.contains(&key) {
            e.role = Role::Reissued;
        } else {
            groups.push(key);
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
    let strongest = evidences
        .iter()
        .map(|e| e.strength)
        .min_by_key(|s| match s {
            Strength::Strong => 0,
            Strength::Medium => 1,
            Strength::Complement => 2,
        });
    let _ = strongest;
    ValueOrigin {
        scope: value.scope,
        field: value.field.clone(),
        occurrence: value.occurrence,
        value: preview(&value.value),
        length: value.value.len(),
        status,
        label: String::new(),
        offset: None,
        oldest,
        evidences,
        repeated_from: Vec::new(),
        parent: None,
        note,
    }
}

fn relabel(entry: &mut ValueOrigin) {
    entry.label = match entry.status {
        OriginStatus::Origin => "origem observada".to_string(),
        OriginStatus::Ambiguous => format!(
            "ambíguo (mais antigo: {})",
            entry
                .oldest
                .and_then(|i| entry.evidences.get(i))
                .map_or("?", |e| e.request_id.as_str())
        ),
        OriginStatus::Repeated => format!(
            "sem origem observada (valor já circulava em {})",
            entry.repeated_from.join(", ")
        ),
        OriginStatus::None => "sem origem observada".to_string(),
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

type Producer = (Pos, ProducerScope, Option<String>, Option<u64>);
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
        for (name, other) in data.opaque.iter() {
            if !name.eq_ignore_ascii_case(&value.field) || is_redacted(other) {
                continue;
            }
            let b = other.as_bytes();
            if a.len().saturating_mul(b.len()) > ctx.options.max_opaque_cells {
                continue;
            }
            for (start, len, other_start) in maximal_common(a, b, min) {
                if cut_in_number(a, b, start, len, other_start) {
                    continue;
                }
                found.entry((start, len)).or_default().push((
                    *pos,
                    ProducerScope::ResponseBody,
                    Some(name.clone()),
                    Some(other_start as u64),
                ));
            }
        }
    }
}

/// O trecho comum termina (ou começa) no meio de uma sequência de dígitos que
/// difere dos dois lados: é um contador, não um valor compartilhado.
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
    for ((start, len), producers) in chosen {
        if taken.iter().any(|(s, l)| start < s + l && *s < start + len) {
            continue;
        }
        taken.push((start, len));
        let mut raw = Vec::new();
        for (pos, scope, field, offset) in producers {
            let item = Item {
                scope,
                field,
                value: String::new(),
                offset,
                named: true,
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
                offset: Some(start as u64),
                oldest: None,
                evidences: Vec::new(),
                repeated_from: Vec::new(),
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
    /// Valores sem origem observada, ambíguos ou redigidos (não resolvidos).
    pub unresolved: Vec<UnresolvedValue>,
    pub redacted_values: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnresolvedValue {
    pub request_id: String,
    pub scope: ConsumedScope,
    pub field: String,
    pub status: OriginStatus,
}

fn is_protection_path(url: &str) -> bool {
    let path = url.split('?').next().unwrap_or(url);
    path.contains("/TSPD/") || path.ends_with("/TSPD")
}

fn is_ts_cookie(name: &str) -> bool {
    name.len() > 2 && name.starts_with("TS") && name[2..].bytes().all(|b| b.is_ascii_hexdigit())
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
        unresolved: Vec::new(),
        redacted_values: 0,
        warnings: Vec::new(),
    };
    let mut included: HashMap<String, ChainStep> = HashMap::new();
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut queue = vec![request_id.to_string()];
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
        for value in &origins.values {
            if value.status == OriginStatus::Composite {
                continue;
            }
            if matches!(
                value.status,
                OriginStatus::None | OriginStatus::Redacted | OriginStatus::Repeated
            ) {
                if value.parent.is_none() && value.length > 0 {
                    chain.unresolved.push(UnresolvedValue {
                        request_id: current.clone(),
                        scope: value.scope,
                        field: value.field.clone(),
                        status: value.status,
                    });
                }
                continue;
            }
            if value.status == OriginStatus::Ambiguous && value.parent.is_none() {
                chain.unresolved.push(UnresolvedValue {
                    request_id: current.clone(),
                    scope: value.scope,
                    field: value.field.clone(),
                    status: value.status,
                });
            }
            for e in value.evidences.iter().filter(|e| {
                e.role == Role::Produced
                    && matches!(e.strength, Strength::Strong | Strength::Medium)
            }) {
                if e.request_id == current {
                    continue;
                }
                let pos = ctx.find(&e.request_id).unwrap_or((0, 0));
                let attempt = ctx.attempt_ref(pos);
                let step = included
                    .entry(e.request_id.clone())
                    .or_insert_with(|| ChainStep {
                        request_id: e.request_id.clone(),
                        attempt_id: e.attempt_id.clone(),
                        method: attempt.method.clone(),
                        url: attempt.url.clone(),
                        started_at: attempt.started_at,
                        class: StepClass::Application,
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
                queue.push(e.request_id.clone());
            }
        }
    }
    let target_pos = ctx.find(request_id);
    let mut all: Vec<ChainStep> = included.into_values().collect();
    for step in &mut all {
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
    for step in all {
        match step.class {
            StepClass::Application => chain.steps.push(step),
            StepClass::Protection => chain.protection.push(step),
        }
    }
    chain.unresolved.dedup();
    Ok(chain)
}
