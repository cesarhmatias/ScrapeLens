//! Script de priming em Python (docs/11-priming-sucesso.md §1).
//!
//! Gera um script `requests.Session` que recria a sessão: cada passo da
//! cadeia (`flow::priming_chain`, só `steps`) é refeito na ordem, e os valores
//! que têm origem observada são EXTRAÍDOS em runtime da resposta do produtor,
//! pelo mesmo tipo de evidência. Se a extração não achar o valor, o script
//! falha com mensagem clara; nunca cai no valor capturado.
//!
//! Segurança do código gerado: todo dado capturado entra só em literais
//! Python escapados (ASCII, `\x`/`\u`/`\U`) ou em comentários feitos por
//! [`super::comment`]. Nomes de parâmetros são saneados. O script não é
//! executado pelo ScrapeLens.
//!
//! Heurísticas declaradas: valores que parecem entrada do usuário dentro de
//! campos opacos sem origem (placa, CPF/CNPJ/RENAVAM após `v_cpf`, `v_cnpj`,
//! `v_renavam`) viram parâmetros obrigatórios, sem padrão.
//!
//! Padrão de parâmetro: um valor sem origem observada só vira padrão do
//! parâmetro se for constante comprovada (aparece igual, no mesmo campo, em
//! ≥ 2 requisições da sessão, ou está num recurso estático/contexto). Os
//! demais — inclusive o sufixo de `partialComposition` e o `STAMP` sem
//! produtor — são obrigatórios e o valor capturado não entra no código.
//!
//! Cadeia incompleta: se um valor consumido pela cadeia não tem origem e
//! havia resposta anterior sem corpo observável, `to_python` RECUSA por
//! padrão (listando os produtores e a ocorrência equivalente com corpo).
//! `allow_incomplete` gera o script com `fail()` explícito nesses passos.
//!
//! Cada passo valida a PRÓPRIA resposta antes de devolver: status fora de
//! 2xx/3xx, controle/campo/cookie/header que ele entrega aos passos seguintes
//! (pela cadeia) e `ERRORMESSAGE` preenchido falham `priming: passo N: …` e
//! nenhum pedido é enviado depois. Header fora de latin-1 também falha com
//! mensagem `priming:` clara, em vez de `UnicodeEncodeError` cru.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;

use crate::error::{CoreError, Result};
use crate::flow::{
    priming_chain, value_origins, ConsumedScope, Evidence, EvidenceKind, FlowOptions, OriginStatus,
    PrimingChain, ProducerScope, Role, Unobservable, ValueOrigin, ValueOrigins,
};
use crate::html::html_controls;
use crate::model::{BodyState, LogicalRequest, SessionV1, Warning};
use crate::search::BodySource;

use super::{comment, is_header_token, is_safe_header_value, ExportOutput};

#[derive(Debug, Clone, Default)]
pub struct PrimingOptions {
    pub flow: FlowOptions,
    /// Gera o script mesmo quando a cadeia depende de resposta sem corpo
    /// observável, com `fail()` explícito nesses passos.
    pub allow_incomplete: bool,
    /// Origins (`esquema://host[:porta]`) além do alvo que a cadeia pode
    /// contatar; sem eles, um passo com outro origin é recusado na geração.
    pub allow_origins: Vec<String>,
}

const CONTEXT_BEFORE: usize = 16;
const CONTEXT_AFTER: usize = 6;
const SKIP_HEADERS: &[&str] = &[
    "cookie",
    "content-length",
    "host",
    "connection",
    "accept-encoding",
    "authorization",
    "proxy-authorization",
    "transfer-encoding",
    "te",
    "upgrade",
    "keep-alive",
    "expect",
];
const SENSITIVE_WORDS: &[&str] = &[
    "password",
    "passwd",
    "senha",
    "secret",
    "token",
    "authorization",
    "apikey",
    "api_key",
    "api-key",
    "cpf",
    "cnpj",
    "renavam",
    "cartao",
    "credential",
    "chave",
    "nome",
    "email",
    "telefone",
    "celular",
    "endereco",
    "endereço",
    "nascimento",
    "session",
    "callback",
];
/// Palavras curtas demais para casar por substring (`rg` em `target`): só
/// valem como palavra inteira do nome (`rg`, `user_rg`, `sid`, `jsid`).
const SENSITIVE_SHORT_WORDS: &[&str] = &["rg", "sid", "sessid", "jsid", "tel", "fone"];

/// Literal Python ASCII com aspas simples; nada além de `[ -~]` sai cru.
fn lit(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ' '..='~' => out.push(c),
            c if (c as u32) <= 0xff => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c if (c as u32) <= 0xffff => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => {
                let _ = write!(out, "\\U{:08x}", c as u32);
            }
        }
    }
    out.push('\'');
    out
}

fn bytes_lit(bytes: &[u8]) -> String {
    let mut out = String::from("b'");
    for &b in bytes {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'\'' => out.push_str("\\'"),
            b' '..=b'~' => out.push(b as char),
            _ => {
                let _ = write!(out, "\\x{b:02x}");
            }
        }
    }
    out.push('\'');
    out
}

fn is_sensitive_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if SENSITIVE_WORDS.iter().any(|w| lower.contains(w)) {
        return true;
    }
    lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| SENSITIVE_SHORT_WORDS.contains(&word))
}

fn is_plate_at(b: &[u8], i: usize) -> bool {
    if i + 7 > b.len() {
        return false;
    }
    let w = &b[i..i + 7];
    let ok = w[..3].iter().all(u8::is_ascii_uppercase)
        && w[3].is_ascii_digit()
        && (w[4].is_ascii_digit() || w[4].is_ascii_uppercase())
        && w[5].is_ascii_digit()
        && w[6].is_ascii_digit();
    let before_ok = i == 0 || !(b[i - 1].is_ascii_uppercase() || b[i - 1].is_ascii_digit());
    let after_ok =
        i + 7 == b.len() || !(b[i + 7].is_ascii_uppercase() || b[i + 7].is_ascii_digit());
    ok && before_ok && after_ok
}

fn looks_sensitive_value(value: &str) -> bool {
    value.contains("REDACTED") || (0..value.len()).any(|i| is_plate_at(value.as_bytes(), i))
}

/// Identificador opaco (CPF/processo/timestamp): longo e só de dígitos, ou hex
/// longo. Nunca é constante estrutural, mesmo que apareça numa URL de
/// navegação.
fn looks_opaque_id(value: &str) -> bool {
    let digits = value.bytes().all(|b| b.is_ascii_digit());
    if digits && value.len() >= 6 {
        return true;
    }
    if value.len() >= 16 && value.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return true;
    }
    // Versões e contadores (`1.2.3`, `123_456`, `jQuery123_456`): cara de valor
    // dinâmico, nunca constante estrutural.
    if value.bytes().any(|b| b.is_ascii_digit())
        && value.bytes().any(|b| matches!(b, b'.' | b'_' | b'-'))
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
    {
        return true;
    }
    let digits = value.bytes().filter(u8::is_ascii_digit).count();
    if digits >= 3 && value.contains('_') && value.bytes().any(|b| b.is_ascii_alphabetic()) {
        return true;
    }
    // Base64/base64url longo e misto.
    value.len() >= 20
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-'))
        && value.bytes().any(|b| b.is_ascii_digit())
        && value.bytes().any(|b| b.is_ascii_uppercase())
        && value.bytes().any(|b| b.is_ascii_lowercase())
}

/// Tokens de navegação de uma URL: segmentos do caminho, nome do recurso sem
/// extensão/`_JLIBS` e valores de query. São candidatos a constante estrutural
/// (`op=S37`, `page=NatLogon`, `SIM1000X.html`).
fn navigation_tokens(url: &str) -> Vec<String> {
    let mut out = Vec::new();
    let url = url.split('#').next().unwrap_or(url);
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let (path, query) = match rest.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (rest, None),
    };
    let path = match path.split_once('/') {
        Some((_, p)) => p,
        None => "",
    };
    for segment in path.split('/') {
        // `;nome=valor` no caminho é dado, nunca navegação.
        let segment = segment.split(';').next().unwrap_or(segment).trim();
        if segment.is_empty() {
            continue;
        }
        out.push(segment.to_string());
        if let Some((stem, _ext)) = segment.rsplit_once('.') {
            if !stem.is_empty() {
                out.push(stem.to_string());
                if let Some(base) = stem.strip_suffix("_JLIBS") {
                    if !base.is_empty() {
                        out.push(base.to_string());
                    }
                }
            }
        }
    }
    if let Some(query) = query {
        for (_, value) in form_pairs(query) {
            if !value.is_empty() {
                out.push(value);
            }
        }
    }
    out
}

/// Nome Python seguro para um parâmetro (`[a-z0-9_]`, não começa com dígito).
fn sanitize_name(raw: &str) -> String {
    let mut name: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    name = name.trim_matches('_').to_string();
    if name.is_empty() || name.as_bytes()[0].is_ascii_digit() {
        name = format!("param_{name}");
    }
    name.truncate(40);
    if matches!(name.as_str(), "confirmar" | "base_url" | "help" | "h") {
        name = format!("p_{name}");
    }
    name
}

#[derive(Debug, Clone)]
struct Param {
    name: String,
    default: Option<String>,
    captured: String,
    note: String,
}

/// O que um passo precisa entregar na própria resposta para os passos
/// seguintes da cadeia (checado no passo, antes de qualquer outro pedido).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Expectation {
    Cookie(String),
    Header(String),
    Control(String, usize),
    Field(String),
    /// Corpo genérico (extração por contexto): exige resposta não vazia.
    Body,
}

impl Expectation {
    fn python(&self) -> String {
        match self {
            Expectation::Cookie(name) => format!("('cookie', {}, 0)", lit(name)),
            Expectation::Header(name) => format!("('header', {}, 0)", lit(name)),
            Expectation::Control(name, index) => format!("('control', {}, {index})", lit(name)),
            Expectation::Field(name) => format!("('field', {}, 0)", lit(name)),
            Expectation::Body => "('body', 'corpo', 0)".to_string(),
        }
    }
}

/// Onde o valor foi localizado na resposta do produtor.
enum Located {
    Control(String, usize),
    Field(String),
    Body,
}

#[derive(Default)]
struct Params {
    list: Vec<Param>,
    /// Trechos montados no cliente (valor capturado → expressão), para que o
    /// mesmo trecho em campos opacos use o mesmo parâmetro.
    client_parts: Vec<(String, String)>,
}

impl Params {
    /// Registra (ou reaproveita) um parâmetro; devolve a expressão `P[...]`.
    /// Mesmo nome com valor capturado diferente vira outro parâmetro (`_2`…).
    /// `constant` só pode ser `true` quando houver prova de que o valor é
    /// constante do protocolo; sem ela o parâmetro é obrigatório e o valor
    /// capturado não vira padrão.
    fn get(
        &mut self,
        raw: &str,
        captured: &str,
        sensitive: bool,
        note: &str,
        constant: bool,
    ) -> String {
        let base = sanitize_name(raw);
        let mut name = base.clone();
        let mut n = 1;
        loop {
            match self.list.iter().find(|p| p.name == name) {
                Some(p) if p.captured == captured => break,
                Some(_) => {
                    n += 1;
                    name = format!("{base}_{n}");
                }
                None => {
                    let default =
                        (!sensitive && constant && !captured.is_empty() && captured.len() <= 200)
                            .then(|| captured.to_string());
                    self.list.push(Param {
                        name: name.clone(),
                        default,
                        captured: captured.to_string(),
                        note: note.to_string(),
                    });
                    break;
                }
            }
        }
        format!("P[{}]", lit(&name))
    }
}

/// Peça de um valor montado: literal ou expressão Python.
enum Piece {
    Lit(String),
    Expr(String),
}

fn pieces_expr(pieces: Vec<Piece>) -> String {
    let parts: Vec<String> = pieces
        .into_iter()
        .filter_map(|p| match p {
            Piece::Lit(s) if s.is_empty() => None,
            Piece::Lit(s) => Some(lit(&s)),
            Piece::Expr(e) => Some(e),
        })
        .collect();
    match parts.len() {
        0 => "''".to_string(),
        1 => parts.into_iter().next().unwrap_or_default(),
        _ => parts.join(" + "),
    }
}

/// Separa de um trecho literal os valores que parecem entrada do usuário.
fn scrub_literal(text: &str, params: &mut Params) -> Vec<Piece> {
    let bytes = text.as_bytes();
    let mut hits: Vec<(usize, usize, &str)> = Vec::new();
    for i in 0..bytes.len() {
        if is_plate_at(bytes, i) {
            hits.push((i, i + 7, "placa"));
        }
    }
    for (kw, name, min, max) in [
        ("v_cpf", "cpf", 11usize, 11usize),
        ("v_cnpj", "cnpj", 14, 14),
        ("v_renavam", "renavam", 9, 11),
    ] {
        let mut from = 0;
        while let Some(p) = text[from..].find(kw) {
            let start = from + p + kw.len();
            let digits = bytes[start..]
                .iter()
                .take_while(|b| b.is_ascii_digit())
                .count();
            if digits >= min {
                let end = start + digits.min(max);
                hits.push((start, end, name));
            }
            from = start;
        }
    }
    let mut client: Vec<(usize, usize, String)> = Vec::new();
    for (value, expr) in &params.client_parts {
        let mut from = 0;
        while let Some(p) = text[from..].find(value.as_str()) {
            client.push((from + p, from + p + value.len(), expr.clone()));
            from += p + value.len();
        }
    }
    let mut marks: Vec<(usize, usize, Option<&str>, Option<String>)> = hits
        .into_iter()
        .map(|(a, b, n)| (a, b, Some(n), None))
        .collect();
    marks.extend(client.into_iter().map(|(a, b, e)| (a, b, None, Some(e))));
    marks.sort_by_key(|m| m.0);
    let mut out = Vec::new();
    let mut at = 0;
    for (start, end, name, expr) in marks {
        if start < at {
            continue;
        }
        out.push(Piece::Lit(text[at..start].to_string()));
        match (name, expr) {
            (Some(name), _) => out.push(Piece::Expr(params.get(
                name,
                &text[start..end],
                true,
                "entrada do usuário dentro de campo opaco",
                false,
            ))),
            (_, Some(expr)) => out.push(Piece::Expr(expr)),
            _ => {}
        }
        at = end;
    }
    out.push(Piece::Lit(text[at..].to_string()));
    out
}

// ---------------------------------------------------------------------------
// Decodificação de corpos capturados
// ---------------------------------------------------------------------------

fn percent_decode(raw: &str) -> String {
    let b = raw.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len()
                && b[i + 1].is_ascii_hexdigit()
                && b[i + 2].is_ascii_hexdigit() =>
            {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("00");
                out.push(u8::from_str_radix(hex, 16).unwrap_or(b'%'));
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn form_pairs(text: &str) -> Vec<(String, String)> {
    if text.is_empty() {
        return Vec::new();
    }
    text.split('&')
        .map(|part| match part.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(part), String::new()),
        })
        .collect()
}

fn response_text(request: &LogicalRequest, source: &dyn BodySource) -> Option<String> {
    if !matches!(
        request.response_body.state,
        BodyState::Captured | BodyState::Truncated
    ) {
        return None;
    }
    let loaded = source.load(request.response_body.attachment.as_deref()?)?;
    Some(String::from_utf8_lossy(&loaded.bytes).into_owned())
}

fn char_floor(text: &str, mut i: usize) -> usize {
    i = i.min(text.len());
    while !text.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn char_ceil(text: &str, mut i: usize) -> usize {
    i = i.min(text.len());
    while !text.is_char_boundary(i) {
        i += 1;
    }
    i
}

// ---------------------------------------------------------------------------
// Gerador
// ---------------------------------------------------------------------------

struct Gen<'a> {
    session: &'a SessionV1,
    source: &'a dyn BodySource,
    step_ids: HashSet<String>,
    /// Ids dos passos na ordem do plano: um valor cujo produtor ficou fora da
    /// cadeia pode ser extraído do passo equivalente que está dentro dela.
    steps: Vec<String>,
    params: Params,
    warnings: Vec<Warning>,
    /// Notas (viram comentários) do passo em construção.
    notes: Vec<String>,
    /// Prova de constância: (campo, valor) → nº de requisições distintas com
    /// esse par. Calculado uma vez, sob demanda.
    occurrences: Option<HashMap<(String, String), usize>>,
    /// Cache de "valor aparece em alguma resposta".
    response_hits: HashMap<String, bool>,
    /// Valores que a própria cadeia usa como rota de navegação: segmento de
    /// caminho, nome de página/recurso ou valor de query de `steps`/`pages`.
    /// São constantes estruturais, não dados de sessão.
    structural: BTreeSet<String>,
    /// Passo produtor → o que a resposta dele precisa conter para os
    /// consumidores seguintes (preenchido ao gerar cada consumidor).
    expectations: BTreeMap<String, BTreeSet<Expectation>>,
}

impl Gen<'_> {
    fn expect(&mut self, producer: &str, expectation: Expectation) {
        self.expectations
            .entry(producer.to_string())
            .or_default()
            .insert(expectation);
    }

    fn warn(&mut self, code: &str, message: String) {
        self.warnings.push(Warning::new(code, message));
    }

    fn who(step: &LogicalRequest, label: &str) -> String {
        format!("{} ({})", label, step.id)
    }

    /// Pares (campo, valor) que aparecem no mesmo campo em ≥ 1 requisição,
    /// contando requisições distintas. Prova barata de constância: campos de
    /// query e corpos form-urlencoded pequenos (até 1 MiB).
    fn occurrences(&mut self) -> &HashMap<(String, String), usize> {
        if self.occurrences.is_none() {
            let mut counts: HashMap<(String, String), usize> = HashMap::new();
            for request in &self.session.requests {
                let mut seen: HashSet<(String, String)> = HashSet::new();
                if let Some((_, query)) = request.url.split_once('?') {
                    let query = query.split('#').next().unwrap_or(query);
                    for (k, v) in form_pairs(query) {
                        if !v.is_empty() {
                            seen.insert((k.to_ascii_lowercase(), v));
                        }
                    }
                }
                let content_type = request
                    .request_headers
                    .first_value("content-type")
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if content_type.contains("x-www-form-urlencoded")
                    && request.request_body.has_bytes()
                {
                    if let Some(loaded) = request
                        .request_body
                        .attachment
                        .as_deref()
                        .and_then(|a| self.source.load(a))
                    {
                        if loaded.bytes.len() <= 1_048_576 {
                            let text = String::from_utf8_lossy(&loaded.bytes).into_owned();
                            for (k, v) in form_pairs(&text) {
                                if !v.is_empty() {
                                    seen.insert((k.to_ascii_lowercase(), v));
                                }
                            }
                        }
                    }
                }
                for key in seen {
                    *counts.entry(key).or_default() += 1;
                }
            }
            self.occurrences = Some(counts);
        }
        self.occurrences.as_ref().expect("calculado acima")
    }

    /// Prova de constância: o mesmo (campo, valor) em ≥ 2 requisições
    /// distintas da sessão E o valor nunca aparece numa resposta (se a
    /// aplicação o produziu, é valor de sessão, não constante do protocolo).
    fn is_proven_constant(&mut self, field: &str, value: &str) -> bool {
        if value.is_empty() || value.len() > 200 {
            return false;
        }
        let key = (field.to_ascii_lowercase(), value.to_string());
        let seen = self.occurrences().get(&key).copied().unwrap_or(0);
        seen >= 2 && !self.value_in_any_response(value)
    }

    /// `true` se o valor aparece em algum corpo de resposta capturado.
    fn value_in_any_response(&mut self, value: &str) -> bool {
        if let Some(hit) = self.response_hits.get(value) {
            return *hit;
        }
        let needle = value.as_bytes();
        let mut hit = false;
        for request in &self.session.requests {
            if !matches!(
                request.response_body.state,
                BodyState::Captured | BodyState::Truncated
            ) {
                continue;
            }
            let Some(loaded) = request
                .response_body
                .attachment
                .as_deref()
                .and_then(|a| self.source.load(a))
            else {
                continue;
            };
            let hay = &loaded.bytes;
            if needle.len() <= hay.len() && hay.windows(needle.len()).any(|w| w == needle) {
                hit = true;
                break;
            }
        }
        self.response_hits.insert(value.to_string(), hit);
        hit
    }

    /// Texto bruto da resposta do produtor, para localizar contexto.
    fn producer_request(&self, evidence: &Evidence) -> Option<&LogicalRequest> {
        self.session.find_request(&evidence.request_id)
    }

    /// Expressão que extrai, em runtime, o valor de `origin` (ou do trecho
    /// `value`) da resposta do produtor. `None` se não houver como.
    fn source_expr(
        &mut self,
        origin: &ValueOrigin,
        value: &str,
        step: &LogicalRequest,
        label: &str,
    ) -> Option<String> {
        let usable = |e: &&Evidence| self.step_ids.contains(&e.request_id);
        let evidence = origin
            .oldest
            .and_then(|i| origin.evidences.get(i))
            .filter(usable)
            .or_else(|| {
                origin
                    .evidences
                    .iter()
                    .find(|e| e.role == Role::Produced && usable(e))
            })?;
        let producer = self.producer_request(evidence)?.clone();
        let who = lit(&Self::who(step, label));
        let rid = lit(&evidence.request_id);
        let field = evidence.field.clone();
        match evidence.scope {
            ProducerScope::SetCookie => {
                let name = field?;
                self.expect(&evidence.request_id, Expectation::Cookie(name.clone()));
                Some(format!("get_cookie(S, {}, {who})", lit(&name)))
            }
            ProducerScope::ResponseHeader | ProducerScope::Location => {
                let name = field.unwrap_or_else(|| "location".to_string());
                self.expect(&evidence.request_id, Expectation::Header(name.clone()));
                Some(format!("get_header(R[{rid}], {}, {who})", lit(&name)))
            }
            ProducerScope::ResponseBody => {
                let text = response_text(&producer, self.source)?;
                let (container, container_text, whole, located) =
                    self.body_container(&producer, &text, evidence, value, &rid, &who)?;
                self.expect(
                    &evidence.request_id,
                    match located {
                        Located::Control(name, index) => Expectation::Control(name, index),
                        Located::Field(name) => Expectation::Field(name),
                        Located::Body => Expectation::Body,
                    },
                );
                if whole {
                    return Some(container);
                }
                let pos = locate(&container_text, value, evidence, &producer, &text)?;
                let (before, after) = context_for(&container_text, pos, value.len());
                Some(format!(
                    "ctx_extract({container}, {}, {}, {who})",
                    lit(&before),
                    lit(&after)
                ))
            }
        }
    }

    /// Valor que a cadeia gera, mas cujo produtor registrado ficou fora dela
    /// (rodada anterior, página equivalente): procura nos passos anteriores do
    /// plano um controle/campo/literal da página com o mesmo nome e valor e
    /// extrai em runtime. Assim `STAMP=INIT` da cscform não vira `--stamp`.
    fn chain_definition_expr(
        &mut self,
        name: &str,
        value: &str,
        step: &LogicalRequest,
    ) -> Option<String> {
        if value.is_empty() || value.len() > 200 || looks_opaque_id(value) {
            return None;
        }
        let pos = self.steps.iter().position(|id| id == &step.id)?;
        let who = lit(&Self::who(step, name));
        let previous: Vec<String> = self.steps[..pos].to_vec();
        for rid in previous {
            let producer = self.session.find_request(&rid)?.clone();
            let Some(text) = response_text(&producer, self.source) else {
                continue;
            };
            // 1. Controle da página com o mesmo nome e o mesmo valor.
            let mut index = 0usize;
            for control in &html_controls(&text) {
                if control.name != name {
                    continue;
                }
                if control.value == value {
                    self.expect(&rid, Expectation::Control(name.to_string(), index));
                    self.notes.push(format!(
                        "{name}: definido pelo controle da página ({rid}); extraído em runtime"
                    ));
                    return Some(format!(
                        "html_control(R[{}], {}, {}, {who})",
                        lit(&rid),
                        lit(name),
                        index
                    ));
                }
                index += 1;
            }
            // 2. Campo form/JSON da página com o mesmo nome e valor.
            if form_pairs(&text)
                .iter()
                .any(|(k, v)| k == name && v == value)
            {
                self.expect(&rid, Expectation::Field(name.to_string()));
                self.notes.push(format!(
                    "{name}: definido por campo da página ({rid}); extraído em runtime"
                ));
                return Some(format!(
                    "body_field(R[{}], {}, {who})",
                    lit(&rid),
                    lit(name)
                ));
            }
            // 3. Literal citado junto do nome no script da página.
            if let Some(expr) = self.page_literal_expr(&text, &rid, name, value, &who) {
                return Some(expr);
            }
        }
        None
    }

    /// Literal entre aspas, citado perto do nome do campo, no script da página.
    fn page_literal_expr(
        &mut self,
        text: &str,
        rid: &str,
        name: &str,
        value: &str,
        who: &str,
    ) -> Option<String> {
        let lower = text.to_ascii_lowercase();
        let needle = name.to_ascii_lowercase();
        let mut search = 0usize;
        while let Some(rel) = lower[search..].find(&needle) {
            let at = search + rel;
            let end = char_ceil(text, at + needle.len() + 96);
            let window = text.get(at..end)?;
            for quote in ['\'', '"'] {
                let literal = format!("{quote}{value}{quote}");
                if let Some(off) = window.find(&literal) {
                    let value_at = at + off + quote.len_utf8();
                    let (before, after) = context_for(text, value_at, value.len());
                    self.expect(rid, Expectation::Body);
                    self.notes.push(format!(
                        "{name}: literal da página ({rid}); extraído em runtime"
                    ));
                    return Some(format!(
                        "ctx_extract(R[{}].text, {}, {}, {who})",
                        lit(rid),
                        lit(&before),
                        lit(&after)
                    ));
                }
            }
            search = at + needle.len();
        }
        None
    }

    /// Onde procurar: controle HTML, campo form/JSON ou o corpo inteiro.
    /// Devolve (expressão do contêiner, texto do contêiner, valor inteiro?,
    /// localização para a checagem no passo produtor).
    fn body_container(
        &self,
        producer: &LogicalRequest,
        text: &str,
        evidence: &Evidence,
        value: &str,
        rid: &str,
        who: &str,
    ) -> Option<(String, String, bool, Located)> {
        if let Some(field) = evidence.field.as_deref() {
            if evidence.html_control {
                let controls = html_controls(text);
                let offset = evidence.producer_offset.unwrap_or(0) as usize;
                let chosen = controls
                    .iter()
                    .filter(|c| c.name == field)
                    .enumerate()
                    .find(|(_, c)| offset >= c.start && offset <= c.end)
                    .map(|(i, c)| (i, c.value.clone()));
                let (index, ctext) = chosen.or_else(|| {
                    controls
                        .iter()
                        .filter(|c| c.name == field)
                        .enumerate()
                        .find(|(_, c)| c.value.contains(value))
                        .map(|(i, c)| (i, c.value.clone()))
                })?;
                let expr = format!("html_control(R[{rid}], {}, {index}, {who})", lit(field));
                let whole = ctext == value && evidence.kind == EvidenceKind::SameField;
                return Some((
                    expr,
                    ctext,
                    whole,
                    Located::Control(field.to_string(), index),
                ));
            }
            // Campo form/JSON; ou variável de script (nesse caso o corpo cru).
            let fields = form_pairs(text);
            if let Some((_, v)) = fields.iter().find(|(k, _)| k == field) {
                let expr = format!("body_field(R[{rid}], {}, {who})", lit(field));
                let whole = v == value && evidence.kind == EvidenceKind::SameField;
                return Some((expr, v.clone(), whole, Located::Field(field.to_string())));
            }
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
                if let Some(v) = json_find(&json, field) {
                    let expr = format!("body_field(R[{rid}], {}, {who})", lit(field));
                    let whole = v == value && evidence.kind == EvidenceKind::SameField;
                    return Some((expr, v, whole, Located::Field(field.to_string())));
                }
            }
        }
        let _ = producer;
        Some((
            format!("R[{rid}].text"),
            text.to_string(),
            false,
            Located::Body,
        ))
    }

    /// Expressão de um valor escalar de `step` (campo de corpo, query ou header).
    fn value_expr(
        &mut self,
        step: &LogicalRequest,
        origin: Option<&ValueOrigin>,
        origins: &ValueOrigins,
        name: &str,
        value: &str,
        scope: ConsumedScope,
    ) -> String {
        let label = name.to_string();
        let sensitive = is_sensitive_name(name) || looks_sensitive_value(value);
        // Valor também visto em recurso estático/contexto: constante do protocolo.
        let in_context = origin.is_some_and(|o| !o.context.is_empty());
        let Some(origin) = origin else {
            return self.fallback_param(name, value, sensitive, in_context, true);
        };
        match origin.status {
            OriginStatus::Redacted => {
                self.notes.push(format!(
                    "{name}: valor redigido na captura; informe pelo parâmetro"
                ));
                self.params
                    .get(name, "", true, "redigido na captura", false)
            }
            OriginStatus::Origin | OriginStatus::Ambiguous => {
                if let Some(expr) = self.source_expr(origin, value, step, &label) {
                    let how = match origin.confidence {
                        Some(crate::flow::Confidence::Strong) => "forte",
                        _ => "possível",
                    };
                    let amb = if origin.status == OriginStatus::Ambiguous {
                        "; ambíguo: usa o produtor mais antigo"
                    } else {
                        ""
                    };
                    self.notes
                        .push(format!("{name}: extraído em runtime (origem {how}{amb})"));
                    expr
                } else if let Some(expr) = self.chain_definition_expr(name, value, step) {
                    expr
                } else {
                    self.fallback_param(name, value, sensitive, in_context, false)
                }
            }
            OriginStatus::Composite if scope == ConsumedScope::Body => {
                self.opaque_expr(step, origins, name, value)
            }
            _ => {
                if let Some(pc) = origin.partial_composition.first() {
                    if let Some(expr) = self.partial_expr(step, name, value, pc) {
                        return expr;
                    }
                }
                let structural = origin.partial_composition.is_empty();
                if structural {
                    if let Some(expr) = self.chain_definition_expr(name, value, step) {
                        return expr;
                    }
                }
                self.fallback_param(name, value, sensitive, in_context, structural)
            }
        }
    }

    /// Parâmetro para um valor sem origem observada: o valor capturado só
    /// vira padrão com prova de constância ou quando é constante estrutural da
    /// própria cadeia (rota/navegação); fora disso é obrigatório.
    fn fallback_param(
        &mut self,
        name: &str,
        value: &str,
        sensitive: bool,
        in_context: bool,
        structural_ok: bool,
    ) -> String {
        if value.is_empty() {
            return "''".to_string();
        }
        let structural = structural_ok
            && !value.is_empty()
            && value.len() <= 200
            && !looks_opaque_id(value)
            && self.structural.contains(value);
        let constant = !sensitive
            && (in_context
                || structural
                || (!looks_opaque_id(value) && self.is_proven_constant(name, value)));
        if constant {
            self.notes.push(if structural {
                format!(
                    "{name}: constante estrutural (rota/navegação); parâmetro com o valor capturado como padrão"
                )
            } else {
                format!(
                    "{name}: constante comprovada; parâmetro com o valor capturado como padrão"
                )
            });
        } else {
            self.notes.push(format!(
                "{name}: sem origem observada; parâmetro obrigatório, sem padrão"
            ));
        }
        self.params.get(
            name,
            value,
            sensitive,
            if constant {
                if structural {
                    "constante estrutural"
                } else {
                    "constante do protocolo"
                }
            } else {
                "sem origem observada"
            },
            constant,
        )
    }

    /// `partialComposition`: parte extraída do produtor + parte montada no cliente.
    fn partial_expr(
        &mut self,
        step: &LogicalRequest,
        name: &str,
        value: &str,
        pc: &crate::flow::PartialComposition,
    ) -> Option<String> {
        let producer = self.session.find_request(&pc.producer_request_id)?.clone();
        if !self.step_ids.contains(&producer.id) {
            return None;
        }
        let end = pc.start + pc.length;
        let piece = value.get(pc.start..end)?;
        let text = response_text(&producer, self.source)?;
        let pos = text.find(piece)?;
        let rid = lit(&producer.id);
        let who = lit(&Self::who(step, name));
        self.expect(&pc.producer_request_id, Expectation::Body);
        let (cb, ca) = context_for(&text, pos, piece.len());
        let extracted = format!(
            "ctx_extract(R[{rid}].text, {}, {}, {who})",
            lit(&cb),
            lit(&ca)
        );
        let mut pieces = Vec::new();
        let before = &value[..pc.start];
        let after = &value[end..];
        if !before.is_empty() {
            // Parte montada no cliente: sem prova de valor, sempre obrigatória.
            pieces.push(Piece::Expr(self.params.get(
                &format!("{name}_cliente_inicio"),
                before,
                false,
                "montado no cliente",
                false,
            )));
        }
        pieces.push(Piece::Expr(extracted));
        if !after.is_empty() {
            let expr = self.params.get(
                &format!("{name}_cliente"),
                after,
                false,
                "montado no cliente",
                false,
            );
            self.params
                .client_parts
                .push((after.to_string(), expr.clone()));
            pieces.push(Piece::Expr(expr));
        }
        self.notes.push(format!(
            "{name}: montado no cliente: complete aqui (parte inicial extraída do produtor {}; o resto é o parâmetro {}_cliente, obrigatório)",
            pc.producer_request_id,
            sanitize_name(name)
        ));
        Some(pieces_expr(pieces))
    }

    /// Campo opaco (`composite`): concatena trechos extraídos e literais.
    fn opaque_expr(
        &mut self,
        step: &LogicalRequest,
        origins: &ValueOrigins,
        name: &str,
        value: &str,
    ) -> String {
        let mut parts: Vec<&ValueOrigin> = origins
            .values
            .iter()
            .filter(|v| v.scope == ConsumedScope::Body && v.parent.as_deref() == Some(name))
            .filter(|v| v.offset.is_some())
            .collect();
        parts.sort_by_key(|v| v.offset.unwrap_or(0));
        let mut pieces: Vec<Piece> = Vec::new();
        let mut at = 0usize;
        let mut dynamic = 0usize;
        for part in parts {
            let start = part.offset.unwrap_or(0) as usize;
            let end = start + part.length;
            if start < at
                || end > value.len()
                || !value.is_char_boundary(start)
                || !value.is_char_boundary(end)
            {
                continue;
            }
            if start > at {
                pieces.extend(scrub_literal(&value[at..start], &mut self.params));
            }
            let text = &value[start..end];
            // Trecho só de letras/símbolos (sem dígitos) com origem apenas
            // possível: coincidência com texto do produtor, provável
            // constante do protocolo. Fica literal, com nota.
            let constant_like = part.confidence != Some(crate::flow::Confidence::Strong)
                && !text.bytes().any(|b| b.is_ascii_digit());
            if constant_like
                && matches!(part.status, OriginStatus::Origin | OriginStatus::Ambiguous)
            {
                self.notes.push(format!(
                    "{name}: trecho {start}..{end} sem dígitos e origem só possível: tratado como constante do protocolo"
                ));
            }
            let expr = (matches!(part.status, OriginStatus::Origin | OriginStatus::Ambiguous)
                && !constant_like)
                .then(|| self.source_expr(part, text, step, &format!("{name}[{start}]")))
                .flatten();
            match expr {
                Some(e) => {
                    dynamic += 1;
                    let amb = if part.status == OriginStatus::Ambiguous {
                        ", ambíguo"
                    } else {
                        ""
                    };
                    self.notes.push(format!(
                        "{name}: trecho {start}..{end} extraído em runtime (origem possível{amb})"
                    ));
                    pieces.push(Piece::Expr(format!(
                        "checked({e}, {}, {})",
                        end - start,
                        lit(&format!("{name}[{start}]"))
                    )));
                }
                None => pieces.extend(scrub_literal(text, &mut self.params)),
            }
            at = end;
        }
        if at < value.len() {
            pieces.extend(scrub_literal(&value[at..], &mut self.params));
        }
        if dynamic == 0 {
            self.notes.push(format!(
                "{name}: campo opaco sem trechos dinâmicos; mantido como capturado"
            ));
        }
        pieces_expr(pieces)
    }
}

/// Contexto mínimo (antes, depois) que identifica `container[pos..pos+len]`
/// de forma única; começa curto para não amarrar o script a texto vizinho
/// que muda (nomes de página, deltas). Antes vazio = início do texto; depois
/// vazio = fim do texto.
fn context_for(container: &str, pos: usize, len: usize) -> (String, String) {
    let end = pos + len;
    let b0 = char_ceil(container, pos.saturating_sub(CONTEXT_BEFORE));
    let a1 = char_floor(container, end + CONTEXT_AFTER);
    let before_full = &container[b0..pos];
    let after_full = &container[end..a1];
    let before_chars: Vec<usize> = before_full.char_indices().map(|(i, _)| i).collect();
    let after_chars: Vec<usize> = after_full
        .char_indices()
        .map(|(i, c)| i + c.len_utf8())
        .collect();
    // Candidatos: do mais curto ao mais longo (mín. 4 antes, 1 depois).
    let befores: Vec<&str> = if before_full.is_empty() {
        vec![""]
    } else {
        let mut v: Vec<&str> = before_chars
            .iter()
            .rev()
            .map(|&i| &before_full[i..])
            .filter(|b| b.chars().count() >= 4.min(before_full.chars().count()))
            .collect();
        v.dedup();
        v
    };
    let afters: Vec<&str> = if after_full.is_empty() {
        vec![""]
    } else {
        after_chars.iter().map(|&i| &after_full[..i]).collect()
    };
    for b in &befores {
        for a in &afters {
            if simulate(container, b, a) == Some((pos, end)) {
                return ((*b).to_string(), (*a).to_string());
            }
        }
    }
    (before_full.to_string(), after_full.to_string())
}

/// Reproduz `re.search(esc(b) + '(.+?)' + esc(a) or \\Z)`: onde o script
/// extrairia (início, fim) neste texto. Antes vazio ancora no início.
fn simulate(container: &str, before: &str, after: &str) -> Option<(usize, usize)> {
    let starts: Vec<usize> = if before.is_empty() {
        vec![0]
    } else {
        container
            .match_indices(before)
            .map(|(i, _)| i + before.len())
            .collect()
    };
    for start in starts {
        if start >= container.len() {
            continue;
        }
        let first = start + container[start..].chars().next().map_or(1, char::len_utf8);
        if after.is_empty() {
            return Some((start, container.len()));
        }
        if let Some(i) = container[first..].find(after) {
            return Some((start, first + i));
        }
    }
    None
}

/// Posição de `value` no contêiner do produtor (por offset quando confere, senão por busca).
fn locate(
    container: &str,
    value: &str,
    evidence: &Evidence,
    _producer: &LogicalRequest,
    raw: &str,
) -> Option<usize> {
    if container == raw {
        if let Some(off) = evidence.producer_offset {
            let off = off as usize;
            if raw.get(off..off + value.len()) == Some(value) {
                return Some(off);
            }
        }
    }
    container.find(value)
}

fn json_find(value: &serde_json::Value, key: &str) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if k == key {
                    return Some(match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    });
                }
                if let Some(found) = json_find(v, key) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(items) => items.iter().find_map(|v| json_find(v, key)),
        _ => None,
    }
}

fn split_origin(url: &str) -> (&str, &str) {
    let Some(scheme_end) = url.find("://") else {
        return ("", url);
    };
    let rest = &url[scheme_end + 3..];
    let cut = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    url.split_at(scheme_end + 3 + cut)
}

/// URL com parâmetros de caminho (`;jsessionid=...`): cada valor vira
/// parâmetro obrigatório (dado de sessão, nunca literal). Devolve a URL para o
/// plano (valores trocados por `<nome>`) e a expressão Python.
fn path_param_expr(gen: &mut Gen, url_base: &str) -> (String, String) {
    let (origin, path) = split_origin(url_base);
    if !path.contains(';') {
        return (
            url_base.to_string(),
            format!("rebase({}, base)", lit(url_base)),
        );
    }
    let mut plan = String::from(origin);
    let mut pieces: Vec<String> = Vec::new();
    let mut literal = String::from(origin);
    let mut rest = path;
    while let Some(at) = rest.find(';') {
        literal.push_str(&rest[..at]);
        plan.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let end = after.find(['/', ';']).unwrap_or(after.len());
        let (name, value) = after[..end].split_once('=').unwrap_or((&after[..end], ""));
        literal.push(';');
        literal.push_str(name);
        literal.push('=');
        plan.push_str(&format!(";{name}=<{name}>"));
        let expr = gen.fallback_param(&format!("path_{name}"), value, true, false, false);
        if pieces.is_empty() {
            pieces.push(format!("rebase({}, base)", lit(&literal)));
        } else {
            pieces.push(lit(&literal));
        }
        pieces.push(format!("urllib.parse.quote({expr}, safe='')"));
        literal = String::new();
        rest = &after[end..];
    }
    literal.push_str(rest);
    plan.push_str(rest);
    if !literal.is_empty() {
        pieces.push(lit(&literal));
    }
    (plan, pieces.join(" + "))
}

/// Recurso estático (script, css, imagem, fonte, mídia): nunca é passo.
fn is_static(request: &LogicalRequest) -> bool {
    let media = request
        .response_headers
        .first_value("content-type")
        .or(request.response_body.content_type.as_deref())
        .unwrap_or("")
        .to_ascii_lowercase();
    let path = request
        .url
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    media.contains("javascript")
        || media.contains("ecmascript")
        || media.contains("text/css")
        || media.starts_with("image/")
        || media.starts_with("font/")
        || media.starts_with("audio/")
        || media.starts_with("video/")
        || [
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
            ".ttf",
        ]
        .iter()
        .any(|ext| path.ends_with(ext))
}

fn is_idempotent(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS"
    )
}

/// Cabeçalhos condicionais de cache: não são valor da aplicação e não provam
/// dependência de corpo ausente.
const CONDITIONAL_HEADERS: &[&str] = &["if-modified-since", "if-none-match", "if-range"];

/// Valor consumido pela cadeia que só poderia ter vindo de uma resposta sem
/// corpo observável.
#[derive(Debug, Clone)]
struct MissingBody {
    request_id: String,
    field: String,
    producers: Vec<Unobservable>,
}

/// Dependências da cadeia em respostas sem corpo observável: valor sem origem
/// observada (não repetido, sem composição parcial, não header condicional)
/// cujas únicas pistas são respostas anteriores `unavailable`/`discarded`/
/// `truncated`.
fn missing_body_dependencies(chain: &PrimingChain) -> Vec<MissingBody> {
    let mut out: Vec<MissingBody> = Vec::new();
    for value in &chain.unresolved {
        if value.status != OriginStatus::None
            || !value.partial_composition.is_empty()
            || value.unobservable.is_empty()
            || CONDITIONAL_HEADERS.contains(&value.field.to_ascii_lowercase().as_str())
        {
            continue;
        }
        for request_id in &value.request_ids {
            match out.iter_mut().find(|m| m.request_id == *request_id) {
                Some(entry) => {
                    if !entry.producers.is_empty() {
                        entry.field.push_str(", ");
                    }
                    entry.field.push_str(&value.field);
                }
                None => out.push(MissingBody {
                    request_id: request_id.clone(),
                    field: value.field.clone(),
                    producers: value.unobservable.clone(),
                }),
            }
        }
    }
    out
}

fn incomplete_chain_error(missing: &[MissingBody]) -> CoreError {
    let consumers: Vec<String> = missing
        .iter()
        .map(|m| format!("{} [{}]", m.request_id, m.field))
        .collect();
    let mut producers: Vec<String> = Vec::new();
    for entry in missing.iter().flat_map(|m| m.producers.iter()) {
        let text = format!("{} ({})", entry.request_id, entry.state);
        if !producers.contains(&text) {
            producers.push(text);
        }
    }
    let shown: Vec<String> = producers.iter().take(6).cloned().collect();
    let more = if producers.len() > shown.len() {
        format!(" e mais {}", producers.len() - shown.len())
    } else {
        String::new()
    };
    let mut suggestions: Vec<String> = Vec::new();
    for entry in missing.iter().flat_map(|m| m.producers.iter()) {
        if let Some(suggestion) = &entry.suggestion {
            if !suggestions.contains(suggestion) {
                suggestions.push(suggestion.clone());
            }
        }
    }
    let suggestion = if suggestions.is_empty() {
        "nenhuma ocorrência equivalente com corpo observável nesta sessão".to_string()
    } else {
        format!(
            "gere o script para a ocorrência equivalente com corpo completo: {}",
            suggestions.join(", ")
        )
    };
    CoreError::Export {
        message: format!(
            "cadeia incompleta: {} valor(es) dependem de resposta(s) sem corpo observável ({}). \
             Respostas sem corpo: {}{}. Nenhum valor capturado é usado no lugar. {}; ou use \
             --allow-incomplete para gerar o script com fail() explícito nesses passos.",
            missing.len(),
            consumers.join("; "),
            shown.join(", "),
            more,
            suggestion
        ),
    }
}

/// Gera o script de priming para a requisição `target_request_id`.
pub fn to_python(
    session: &SessionV1,
    source: &dyn BodySource,
    target_request_id: &str,
    opts: &PrimingOptions,
) -> Result<ExportOutput> {
    let chain = priming_chain(session, source, target_request_id, &opts.flow)?;
    let missing = missing_body_dependencies(&chain);
    if !missing.is_empty() && !opts.allow_incomplete {
        return Err(incomplete_chain_error(&missing));
    }
    let target = session
        .find_request(target_request_id)
        .ok_or_else(|| CoreError::Export {
            message: format!("requisição {target_request_id} não encontrada"),
        })?;
    // O alvo é o último passo; se a cadeia não o traz (sem dependências), inclui.
    let mut step_reqs: Vec<(&LogicalRequest, Vec<String>, String)> = Vec::new();
    for step in &chain.steps {
        if let Some(r) = session.find_request(&step.request_id) {
            if r.id != target.id && is_static(r) {
                continue;
            }
            let reasons: Vec<String> = std::iter::once(step.reason.clone())
                .chain(std::iter::once(format!(
                    "confiança {}",
                    match step.confidence {
                        crate::flow::Confidence::Strong => "strong",
                        crate::flow::Confidence::Possible => "possible",
                    }
                )))
                .collect();
            step_reqs.push((r, reasons, step.reason.clone()));
        }
    }
    if !step_reqs.iter().any(|(r, _, _)| r.id == target.id) {
        step_reqs.push((target, vec!["requisição alvo".to_string()], String::new()));
    }

    let mut structural: BTreeSet<String> = BTreeSet::new();
    for url in std::iter::once(target.url.as_str())
        .chain(chain.steps.iter().map(|s| s.url.as_str()))
        .chain(chain.pages.iter().map(|s| s.url.as_str()))
        .chain(chain.auxiliary_pages.iter().map(|s| s.url.as_str()))
    {
        structural.extend(navigation_tokens(url));
    }

    let mut gen = Gen {
        session,
        source,
        step_ids: step_reqs.iter().map(|(r, _, _)| r.id.clone()).collect(),
        steps: step_reqs.iter().map(|(r, _, _)| r.id.clone()).collect(),
        params: Params::default(),
        warnings: Vec::new(),
        notes: Vec::new(),
        occurrences: None,
        response_hits: HashMap::new(),
        structural,
        expectations: BTreeMap::new(),
    };
    let (captured_origin, _) = split_origin(&target.url);
    let captured_origin = captured_origin.to_string();
    let mut foreign: BTreeSet<String> = BTreeSet::new();
    for (request, _, _) in &step_reqs {
        let (origin, _) = split_origin(&request.url);
        if origin != captured_origin
            && !opts
                .allow_origins
                .iter()
                .any(|a| a.trim_end_matches('/').eq_ignore_ascii_case(origin))
        {
            foreign.insert(origin.to_string());
        }
    }
    if !foreign.is_empty() {
        return Err(CoreError::Export {
            message: format!(
                "a cadeia contata origin(s) diferente(s) do alvo ({}); recusado. Passe --allow-origin <esquema://host[:porta]> para cada um que você aceita contatar",
                foreign.into_iter().collect::<Vec<_>>().join(", ")
            ),
        });
    }

    // Com `allow_incomplete`, cada consumidor afetado falha explicitamente em
    // vez de seguir com a cadeia incompleta.
    let mut incomplete_steps: BTreeMap<String, String> = BTreeMap::new();
    if opts.allow_incomplete {
        for entry in &missing {
            let producers: Vec<String> = entry
                .producers
                .iter()
                .take(4)
                .map(|u| format!("{} ({})", u.request_id, u.state))
                .collect();
            let more = entry.producers.len().saturating_sub(producers.len());
            incomplete_steps.entry(entry.request_id.clone()).or_insert_with(|| {
                format!(
                    "cadeia incompleta: {} sem produtor com corpo observável ({}{}); gere o script para o alvo equivalente de outra rodada",
                    entry.field,
                    producers.join(", "),
                    if more > 0 {
                        format!(" e mais {more}")
                    } else {
                        String::new()
                    }
                )
            });
        }
    }

    let mut plan = String::new();
    let mut unresolved_comments = String::new();
    struct GeneratedStep {
        body: String,
        method: String,
        data_arg: String,
    }
    let mut steps_out: Vec<GeneratedStep> = Vec::new();
    for u in &chain.unresolved {
        let _ = write!(
            unresolved_comments,
            "{}",
            comment(&format!(
                "não resolvido: {} {} ({}){}",
                u.request_ids.join(", "),
                u.field,
                u.label,
                if u.partial_composition.is_empty() {
                    ""
                } else {
                    " — montado no cliente: complete aqui"
                }
            ))
        );
    }

    let mut has_unsafe = false;
    for (n, (request, reasons, _)) in step_reqs.iter().enumerate() {
        let n = n + 1;
        gen.notes.clear();
        let origins = value_origins(session, source, &request.id, &opts.flow)?;
        has_unsafe |= !is_idempotent(&request.method);

        let find_origin = |scope: ConsumedScope, field: &str, occ: usize| -> Option<&ValueOrigin> {
            origins.values.iter().find(|v| {
                v.scope == scope && v.parent.is_none() && v.field == field && v.occurrence == occ
            })
        };

        // URL e query
        let (url_base, query) = match request.url.split_once('?') {
            Some((b, q)) => (
                b.split('#').next().unwrap_or(b),
                Some(q.split('#').next().unwrap_or(q)),
            ),
            None => (request.url.split('#').next().unwrap_or(&request.url), None),
        };
        let (url_base_clean, mut url_expr) = path_param_expr(&mut gen, url_base);
        if let Some(q) = query {
            let mut seen: BTreeMap<String, usize> = BTreeMap::new();
            let mut items = Vec::new();
            for (k, v) in form_pairs(q) {
                let occ = seen.entry(k.clone()).or_default();
                let origin = find_origin(ConsumedScope::Query, &k, *occ);
                *occ += 1;
                let e = gen.value_expr(request, origin, &origins, &k, &v, ConsumedScope::Query);
                items.push(format!("({}, {})", lit(&k), e));
            }
            url_expr = format!(
                "{url_expr} + '?' + urllib.parse.urlencode([{}])",
                items.join(", ")
            );
        }

        // Headers
        let mut header_items = Vec::new();
        for entry in request.request_headers.iter_all() {
            let lname = entry.name.to_ascii_lowercase();
            if entry.name.starts_with(':') {
                continue;
            }
            if SKIP_HEADERS.contains(&lname.as_str()) {
                if lname == "authorization" || lname == "proxy-authorization" {
                    gen.notes
                        .push(format!("header {lname} omitido (credencial)"));
                }
                continue;
            }
            if !is_header_token(&entry.name) || !is_safe_header_value(&entry.value) {
                gen.warn(
                    "priming.header_skipped",
                    format!("passo {n}: header com nome/valor inválido omitido"),
                );
                continue;
            }
            let origin = find_origin(ConsumedScope::Header, &lname, 0);
            let value = if matches!(lname.as_str(), "referer" | "origin") {
                format!("rebase({}, base)", lit(&entry.value))
            } else if origin.is_some_and(|o| matches!(o.status, OriginStatus::Origin)) {
                gen.value_expr(
                    request,
                    origin,
                    &origins,
                    &lname,
                    &entry.value,
                    ConsumedScope::Header,
                )
            } else {
                lit(&entry.value)
            };
            header_items.push(format!("{}: {}", lit(&entry.name), value));
        }

        // Corpo
        let content_type = request
            .request_headers
            .first_value("content-type")
            .unwrap_or("")
            .to_ascii_lowercase();
        let mut body_line = String::new();
        if request.request_body.has_bytes() {
            let bytes = request
                .request_body
                .attachment
                .as_deref()
                .and_then(|a| source.load(a))
                .map(|l| l.bytes.into_owned());
            match bytes {
                Some(bytes) if content_type.contains("x-www-form-urlencoded") => {
                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
                    let mut items = Vec::new();
                    for (k, v) in form_pairs(&text) {
                        let occ = seen.entry(k.clone()).or_default();
                        let origin = find_origin(ConsumedScope::Body, &k, *occ);
                        *occ += 1;
                        let e =
                            gen.value_expr(request, origin, &origins, &k, &v, ConsumedScope::Body);
                        items.push(format!("({}, {})", lit(&k), e));
                    }
                    body_line = format!(
                        "data = urllib.parse.urlencode([\n        {}\n    ])\n",
                        items.join(",\n        ")
                    );
                }
                Some(bytes) => {
                    gen.warn(
                        "priming.body_literal",
                        format!(
                            "passo {n}: corpo não form-urlencoded reenviado como capturado (valores dinâmicos não substituídos)"
                        ),
                    );
                    gen.notes.push(
                        "corpo reenviado como capturado: valores dinâmicos NÃO substituídos"
                            .to_string(),
                    );
                    body_line = format!("data = {}\n", bytes_lit(&bytes));
                }
                None => {
                    gen.warn(
                        "priming.body_missing",
                        format!("passo {n}: corpo da requisição indisponível; enviado vazio"),
                    );
                }
            }
        }

        // Corpo do passo: comentários, fail-safe e montagem. A requisição e as
        // checagens da própria resposta são emitidas depois (quando já se sabe
        // o que os passos seguintes vão consumir desta resposta).
        let mut body = String::new();
        for r in reasons {
            for line in comment(&format!("passo {n}: {r}")).lines() {
                let _ = writeln!(body, "    {line}");
            }
        }
        for note in gen.notes.clone() {
            for line in comment(&note).lines() {
                let _ = writeln!(body, "    {line}");
            }
        }
        if let Some(message) = incomplete_steps.get(&request.id) {
            // Fail-safe explícito: o passo não prossegue com valor sem origem.
            let _ = writeln!(body, "    fail({})", lit(message));
        }
        let _ = writeln!(body, "    url = {url_expr}");
        let _ = writeln!(body, "    headers = {{{}}}", header_items.join(", "));
        let data_arg = if body_line.is_empty() {
            String::new()
        } else {
            body.push_str("    ");
            body.push_str(&body_line);
            ", data=data".to_string()
        };
        steps_out.push(GeneratedStep {
            body,
            method: request.method.to_ascii_uppercase(),
            data_arg,
        });

        let _ = writeln!(
            plan,
            "    ({}, {}, {}, {}, {}),",
            lit(&request.id),
            lit(&request.method.to_ascii_uppercase()),
            lit(&url_base_clean),
            lit(&reasons
                .first()
                .map(|r| r.chars().take(160).collect::<String>())
                .unwrap_or_default()),
            if is_idempotent(&request.method) {
                "True"
            } else {
                "False"
            }
        );
    }

    // Emissão dos passos: cada um checa a PRÓPRIA resposta antes de devolver,
    // para que a cadeia nunca envie outro pedido depois de uma resposta ruim.
    let mut step_code = String::new();
    for (index, step) in steps_out.iter().enumerate() {
        let n = index + 1;
        let _ = write!(step_code, "\n\ndef step_{n}(S, R, P, base):\n");
        step_code.push_str(&step.body);
        let _ = writeln!(step_code, "    try:");
        let _ = writeln!(
            step_code,
            "        resp = send(S, {}, url, {n}, base, headers=headers{}, timeout=30)",
            lit(&step.method),
            step.data_arg
        );
        let _ = writeln!(step_code, "    except UnicodeEncodeError as exc:");
        let _ = writeln!(
            step_code,
            "        fail('passo {n}: header com caractere fora de latin-1: %s' % exc)"
        );
        let _ = writeln!(step_code, "    if not (200 <= resp.status_code < 400):");
        let _ = writeln!(
            step_code,
            "        fail('passo {n}: HTTP %d' % resp.status_code)"
        );
        let expected = step_reqs
            .get(index)
            .and_then(|(request, _, _)| gen.expectations.get(&request.id));
        if let Some(expected) = expected.filter(|e| !e.is_empty()) {
            let items: Vec<String> = expected.iter().map(Expectation::python).collect();
            let _ = writeln!(
                step_code,
                "    step_expected(resp, S, {n}, [{}])",
                items.join(", ")
            );
        }
        let _ = writeln!(step_code, "    step_error(resp, {n})");
        let _ = writeln!(step_code, "    return resp");
    }

    // Parâmetros
    let mut params_code = String::new();
    for p in &gen.params.list {
        let _ = writeln!(
            params_code,
            "    ({}, {}, {}),",
            lit(&p.name),
            p.default.as_deref().map_or("None".to_string(), lit),
            lit(&p.note)
        );
    }

    let mut text = String::new();
    text.push_str("#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n");
    for line in [
        format!("Script de priming gerado pelo ScrapeLens para a requisição {target_request_id}."),
        "Reprodução semântica: a ordem de headers e a fidelidade de transporte (TLS, HTTP/2, fingerprint) NÃO são garantidas.".to_string(),
        "Não executado pelo ScrapeLens: quem roda é você, sob sua responsabilidade.".to_string(),
        "Passos que alteram estado (POST/PUT/PATCH/DELETE) exigem --confirmar; sem ela o script imprime o plano e sai.".to_string(),
        "Valores com origem observada são extraídos das respostas em runtime; nunca se usa o valor capturado no lugar de um extraído.".to_string(),
        "Valores sensíveis ou redigidos são parâmetros obrigatórios, sem padrão.".to_string(),
    ] {
        text.push_str(&comment(&line));
    }
    text.push_str(&unresolved_comments);
    text.push_str(PRELUDE);
    let _ = writeln!(text, "CAPTURED_ORIGIN = {}", lit(&captured_origin));
    let _ = writeln!(
        text,
        "EXTRA_ORIGINS = [{}]",
        opts.allow_origins
            .iter()
            .map(|o| lit(o.trim_end_matches('/')))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let _ = writeln!(text, "TARGET = {}", lit(target_request_id));
    let _ = writeln!(
        text,
        "HAS_STATE_CHANGE = {}",
        if has_unsafe { "True" } else { "False" }
    );
    let _ = writeln!(text, "PLAN = [\n{plan}]");
    let _ = writeln!(text, "PARAMS = [\n{params_code}]");
    text.push_str(&step_code);
    let _ = writeln!(
        text,
        "\n\nSTEPS = [{}]",
        (1..=step_reqs.len())
            .map(|n| format!("step_{n}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    text.push_str(MAIN);

    let mut output = ExportOutput::new(text);
    output.warnings = gen.warnings;
    for w in &chain.warnings {
        output
            .warnings
            .push(Warning::info("priming.chain", w.clone()));
    }
    if !incomplete_steps.is_empty() {
        output.warnings.push(Warning::new(
            "priming.incomplete_chain",
            format!(
                "{} passo(s) falham explicitamente: a cadeia depende de resposta sem corpo observável (ver --allow-incomplete)",
                incomplete_steps.len()
            ),
        ));
    }
    Ok(output)
}

const PRELUDE: &str = r#"
import argparse
import html.parser
import json
import re
import sys
import urllib.parse


def safe_text(value):
    """Texto vindo de resposta: sem ESC, controles nem bidi/invisíveis."""
    return ''.join(c if (c.isprintable() and c not in '\u200e\u200f\u061c\u2028\u2029'
                         and not '\u202a' <= c <= '\u202e' and not '\u2066' <= c <= '\u2069'
                         and c != '\ufeff') else '?' for c in str(value))


def fail(message):
    sys.exit('priming: ' + safe_text(message))


class _Controls(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.items = []
        self._area = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v if v is not None else '') for k, v in attrs}
        if tag == 'input' and 'name' in a:
            if a.get('type', '').lower() in ('checkbox', 'radio') and not any(k == 'checked' for k, _ in attrs):
                return
            self.items.append((a['name'], a.get('value', '')))
        elif tag == 'textarea' and 'name' in a:
            self._area = [a['name'], '']

    def handle_data(self, data):
        if self._area is not None:
            self._area[1] += data

    def handle_endtag(self, tag):
        if tag == 'textarea' and self._area is not None:
            self.items.append((self._area[0], self._area[1]))
            self._area = None


def find_control(resp, name, index):
    parser = _Controls()
    parser.feed(resp.text)
    parser.close()
    found = [v for k, v in parser.items if k == name]
    if index >= len(found):
        return None
    return found[index]


def html_control(resp, name, index, who):
    value = find_control(resp, name, index)
    if value is None:
        fail('controle HTML %r não encontrado na resposta de %s' % (name, who))
    return value


def find_body_field(resp, name):
    text = resp.text
    try:
        stack = [json.loads(text)]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                if name in node:
                    return node[name] if isinstance(node[name], str) else json.dumps(node[name])
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
    except ValueError:
        pass
    values = urllib.parse.parse_qs(text, keep_blank_values=True).get(name)
    if values:
        return values[0]
    return None


def body_field(resp, name, who):
    value = find_body_field(resp, name)
    if value is None:
        fail('campo %r não encontrado na resposta de %s' % (name, who))
    return value


def step_expected(resp, session, index, expected):
    """Controles/campos que ESTE passo precisa entregar aos passos seguintes."""
    missing = []
    for kind, name, extra in expected:
        if kind == 'cookie':
            ok = session.cookies.get(name) is not None
        elif kind == 'header':
            ok = resp.headers.get(name) is not None
        elif kind == 'control':
            ok = find_control(resp, name, extra) is not None
        elif kind == 'field':
            ok = find_body_field(resp, name) is not None
        else:
            ok = bool(resp.content)
        if not ok:
            missing.append(name)
    if missing:
        fail('passo %d: resposta sem %s (provável bloqueio ou sessão inválida)'
             % (index, ', '.join(missing)))


def step_error(resp, index):
    """ERRORMESSAGE preenchido é erro da aplicação; ausência não é erro."""
    value = find_control(resp, 'ERRORMESSAGE', 0)
    if value is not None and value.strip():
        fail('a aplicação respondeu com ERRORMESSAGE no passo %d: %s'
             % (index, safe_text(value.strip()[:200])))


def get_cookie(session, name, who):
    value = session.cookies.get(name)
    if value is None:
        fail('cookie %r não está no cookie jar (%s)' % (name, who))
    return value


def get_header(resp, name, who):
    value = resp.headers.get(name)
    if value is None:
        fail('header %r ausente na resposta usada por %s' % (name, who))
    return value


def ctx_extract(text, before, after, who):
    start = 0
    if before:
        at = text.find(before)
        if at < 0:
            fail('não achei o valor pelo contexto (%r ... %r) para %s' % (before, after, who))
        start = at + len(before)
    if after:
        end = text.find(after, start + 1)
        if end < 0:
            fail('não achei o valor pelo contexto (%r ... %r) para %s' % (before, after, who))
    else:
        end = len(text)
        if end <= start:
            fail('não achei o valor pelo contexto (%r ... %r) para %s' % (before, after, who))
    return text[start:end]


def checked(value, size, who):
    if len(value) != size:
        sys.stderr.write('priming: aviso: %s mudou de tamanho (%d -> %d); prefixos de comprimento do protocolo podem precisar de ajuste\n' % (who, size, len(value)))
    return value


def url_origin(url):
    parts = urllib.parse.urlsplit(url)
    return (parts.scheme + '://' + parts.netloc).lower()


def rebase(url, base):
    if base and url_origin(url) == CAPTURED_ORIGIN.lower():
        return base.rstrip('/') + url[len(CAPTURED_ORIGIN):]
    return url


def send(S, method, url, index, base, **kw):
    """Envia um passo sem seguir redirects sozinho: só o MESMO origin é seguido."""
    home = url_origin(base) if base else CAPTURED_ORIGIN.lower()
    allowed = {home} | {o.lower() for o in EXTRA_ORIGINS}
    if url_origin(url) not in allowed:
        fail('passo %d: origin %s fora dos permitidos; nada foi enviado' % (index, url_origin(url)))
    resp = S.request(method, url, allow_redirects=False, **kw)
    hops = 0
    while resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get('Location')
        if not location:
            fail('passo %d: redirect HTTP %d sem Location' % (index, resp.status_code))
        nxt = urllib.parse.urljoin(url, location)
        if url_origin(nxt) != url_origin(url):
            fail('passo %d: redirect para outro origin (%s) recusado' % (index, safe_text(url_origin(nxt))))
        hops += 1
        if hops > 5:
            fail('passo %d: redirects demais' % index)
        if resp.status_code == 303 or (resp.status_code in (301, 302) and method == 'POST'):
            method = 'GET'
            kw = {k: v for k, v in kw.items() if k not in ('data', 'json', 'files')}
            kw['headers'] = {k: v for k, v in kw.get('headers', {}).items()
                             if k.lower() not in ('content-type', 'content-length')}
        url = nxt
        resp = S.request(method, url, allow_redirects=False, **kw)
    return resp

"#;

const MAIN: &str = r#"

def main():
    parser = argparse.ArgumentParser(description='Script de priming (ScrapeLens)')
    parser.add_argument('--confirmar', action='store_true', help='executa os passos que alteram estado')
    parser.add_argument('--base-url', default=None, help='troca esquema/host/porta do alvo capturado (ex.: http://127.0.0.1:8791)')
    for name, default, note in PARAMS:
        parser.add_argument('--' + name.replace('_', '-'), dest='p_' + name, default=default,
                            required=False, help=(note + (' (obrigatório)' if default is None else ' (padrão: valor capturado)')).replace('%', '%%'))
    args = parser.parse_args()
    P = {name: getattr(args, 'p_' + name) for name, _, _ in PARAMS}
    base = args.base_url

    print('Plano de priming para %s (%d passos):' % (TARGET, len(PLAN)))
    for index, (rid, method, url, reason, idem) in enumerate(PLAN, 1):
        print('  %d. %s %s [%s]%s' % (index, method, rebase(url, base), rid, '' if idem else ' (altera estado)'))
        print('       %s' % reason)
    if HAS_STATE_CHANGE and not args.confirmar:
        print('Nada foi enviado: o plano tem passos que alteram estado. Use --confirmar para executar.')
        return 0
    missing = [name for name, default, _ in PARAMS if P[name] is None]
    if missing:
        fail('parâmetros obrigatórios ausentes: ' + ', '.join('--' + m.replace('_', '-') for m in missing))

    try:
        import requests
    except ImportError:
        fail('o pacote "requests" não está instalado (pip install requests)')
    S = requests.Session()
    R = {}
    for index, (step, (rid, method, url, _, _)) in enumerate(zip(STEPS, PLAN), 1):
        resp = step(S, R, P, base)
        R[rid] = resp
        print('  [%d/%d] %s %s -> HTTP %d' % (index, len(STEPS), method, rebase(url, base), resp.status_code))
    print('Cadeia concluída; último HTTP %d.' % R[PLAN[-1][0]].status_code)
    return 0


if __name__ == '__main__':
    sys.exit(main())
"#;
