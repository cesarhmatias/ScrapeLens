//! Busca em metadados e corpos de uma sessão (`docs/08-corpos-busca.md` §2).
//!
//! API para o App (onda 4b, via Tauri):
//!
//! ```text
//! pub fn search(bundle: &SessionBundle, query: &SearchQuery) -> SearchResult
//! SearchResult { matches: Vec<Match>, skipped_binary: usize,
//!                partial: bool, partial_attempts: Vec<String>, limit_reached: bool }
//! Match { request_id, attempt_id, scope, field: Option<String>,
//!         byte_offset: Option<u64>, snippet, decoded }
//! ```
//!
//! Recebe o [`SessionBundle`] (e não só a sessão) porque os corpos vivem em
//! anexos. `request_id` é o id lógico da sessão (`LogicalRequest::id`).
//!
//! Semântica:
//! - `byte_offset` é sempre relativo ao original (URL, valor do header ou bytes
//!   do corpo). Em form-urlencoded é o início do valor/chave no corpo bruto; em
//!   JSON, o início do texto da string no corpo bruto.
//! - `decoded=true` quer dizer "achado pela visão estruturada": chaves e valores
//!   de form-urlencoded com percent-decoding (`+` = espaço) e strings JSON sem
//!   escape, com `field` = chave ou caminho (`a.b[0]`). Trechos fora dessas
//!   unidades (ou corpos que não são form/JSON) são buscados nos bytes brutos
//!   com `decoded=false`.
//! - Corpos binários (UTF-8 inválido) são contados em `skipped_binary`.
//! - Corpos `truncated` são pesquisados e marcam `partial`.
//! - Sem ignorar maiúsculas Unicode: só ASCII é dobrado.

use serde::{Deserialize, Serialize};

use crate::model::{Attempt, BodyState, HeaderView, LogicalRequest, SessionBundle};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Scope {
    Url,
    RequestHeaders,
    ResponseHeaders,
    Cookies,
    RequestBody,
    ResponseBody,
}

impl Scope {
    pub const ALL: [Scope; 6] = [
        Scope::Url,
        Scope::RequestHeaders,
        Scope::ResponseHeaders,
        Scope::Cookies,
        Scope::RequestBody,
        Scope::ResponseBody,
    ];

    pub fn parse(value: &str) -> Option<Scope> {
        Some(match value {
            "url" => Scope::Url,
            "requestHeaders" => Scope::RequestHeaders,
            "responseHeaders" => Scope::ResponseHeaders,
            "cookies" => Scope::Cookies,
            "requestBody" => Scope::RequestBody,
            "responseBody" => Scope::ResponseBody,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchQuery {
    pub text: String,
    /// Vazio = todos os escopos.
    #[serde(default)]
    pub scopes: Vec<Scope>,
    #[serde(default)]
    pub case_sensitive: bool,
    /// Limite de matches devolvidos; ao atingir, `limit_reached` fica true.
    #[serde(default = "default_max_matches")]
    pub max_matches: usize,
}

fn default_max_matches() -> usize {
    5000
}

impl SearchQuery {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            scopes: Vec::new(),
            case_sensitive: false,
            max_matches: default_max_matches(),
        }
    }

    fn wants(&self, scope: Scope) -> bool {
        self.scopes.is_empty() || self.scopes.contains(&scope)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Match {
    pub request_id: String,
    pub attempt_id: String,
    pub scope: Scope,
    pub field: Option<String>,
    pub byte_offset: Option<u64>,
    pub snippet: String,
    pub decoded: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub matches: Vec<Match>,
    /// Corpos com bytes não-texto, não pesquisados.
    pub skipped_binary: usize,
    /// Algum corpo `truncated` foi pesquisado: a busca é parcial.
    pub partial: bool,
    pub partial_attempts: Vec<String>,
    pub limit_reached: bool,
}

struct Matcher {
    needle: Vec<u8>,
    case_sensitive: bool,
}

impl Matcher {
    /// Offsets (em bytes) de todas as ocorrências, sem sobreposição.
    fn find_all(&self, haystack: &[u8]) -> Vec<usize> {
        let mut found = Vec::new();
        if self.needle.is_empty() || haystack.len() < self.needle.len() {
            return found;
        }
        let folded;
        let hay: &[u8] = if self.case_sensitive {
            haystack
        } else {
            folded = haystack.to_ascii_lowercase();
            &folded
        };
        let mut index = 0;
        while index + self.needle.len() <= hay.len() {
            if hay[index..index + self.needle.len()] == self.needle[..] {
                found.push(index);
                index += self.needle.len();
            } else {
                index += 1;
            }
        }
        found
    }
}

struct Ctx<'a> {
    matcher: Matcher,
    query: &'a SearchQuery,
    result: SearchResult,
    request_id: String,
    attempt_id: String,
}

impl Ctx<'_> {
    fn push(
        &mut self,
        scope: Scope,
        field: Option<&str>,
        offset: usize,
        text: &str,
        at: usize,
        decoded: bool,
    ) {
        if self.result.matches.len() >= self.query.max_matches {
            self.result.limit_reached = true;
            return;
        }
        self.result.matches.push(Match {
            request_id: self.request_id.clone(),
            attempt_id: self.attempt_id.clone(),
            scope,
            field: field.map(str::to_string),
            byte_offset: Some(offset as u64),
            snippet: snippet(text, at, self.matcher.needle.len()),
            decoded,
        });
    }

    /// URL: busca no texto original e, se houver `%XX`, também na visão
    /// percent-decoded (`decoded=true`), sem duplicar trechos já achados.
    fn scan_url(&mut self, url: &str) {
        let raw: Vec<usize> = self.matcher.find_all(url.as_bytes());
        let needle_len = self.matcher.needle.len();
        for &at in &raw {
            self.push(Scope::Url, None, at, url, at, false);
        }
        let (text, map) = percent_decode_map(url, 0);
        if text == url {
            return;
        }
        for at in self.matcher.find_all(text.as_bytes()) {
            let (from, to) = (map[at], map[(at + needle_len).min(text.len())]);
            if raw.iter().any(|&r| from < r + needle_len && r < to) {
                continue;
            }
            self.push(Scope::Url, None, from, &text, at, true);
        }
    }

    /// Busca em texto simples (URL, header, nome/valor de cookie).
    fn scan_text(&mut self, scope: Scope, field: Option<&str>, text: &str) {
        for at in self.matcher.find_all(text.as_bytes()) {
            self.push(scope, field, at, text, at, false);
        }
    }
}

fn snippet(text: &str, at: usize, len: usize) -> String {
    const CONTEXT: usize = 40;
    let mut start = at.saturating_sub(CONTEXT);
    while start > 0 && !text.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = (at + len + CONTEXT).min(text.len());
    while end < text.len() && !text.is_char_boundary(end) {
        end += 1;
    }
    let mut out = String::new();
    if start > 0 {
        out.push('…');
    }
    out.push_str(&text[start..end]);
    if end < text.len() {
        out.push('…');
    }
    out.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Busca `query` na sessão. Veja o módulo para a semântica.
pub fn search(bundle: &SessionBundle, query: &SearchQuery) -> SearchResult {
    let needle = if query.case_sensitive {
        query.text.as_bytes().to_vec()
    } else {
        query.text.to_ascii_lowercase().into_bytes()
    };
    let mut ctx = Ctx {
        matcher: Matcher {
            needle,
            case_sensitive: query.case_sensitive,
        },
        query,
        result: SearchResult::default(),
        request_id: String::new(),
        attempt_id: String::new(),
    };
    if query.text.is_empty() {
        return ctx.result;
    }
    for request in &bundle.session.requests {
        ctx.request_id = request.id.clone();
        if request.attempts.is_empty() {
            ctx.attempt_id = String::new();
            search_logical(&mut ctx, bundle, request);
        }
        for attempt in &request.attempts {
            ctx.attempt_id = attempt.id.clone();
            search_attempt(&mut ctx, bundle, attempt);
        }
    }
    ctx.result
}

fn search_logical(ctx: &mut Ctx<'_>, bundle: &SessionBundle, request: &LogicalRequest) {
    if ctx.query.wants(Scope::Url) {
        ctx.scan_url(&request.url);
    }
    search_headers(ctx, Scope::RequestHeaders, &request.request_headers);
    search_headers(ctx, Scope::ResponseHeaders, &request.response_headers);
    search_cookies(ctx, &request.cookie, &request.set_cookies);
    search_body(
        ctx,
        bundle,
        Scope::RequestBody,
        &request.request_body,
        &request.request_headers,
    );
    search_body(
        ctx,
        bundle,
        Scope::ResponseBody,
        &request.response_body,
        &request.response_headers,
    );
}

fn search_attempt(ctx: &mut Ctx<'_>, bundle: &SessionBundle, attempt: &Attempt) {
    if ctx.query.wants(Scope::Url) {
        ctx.scan_url(&attempt.url);
    }
    search_headers(ctx, Scope::RequestHeaders, &attempt.request_headers);
    search_headers(ctx, Scope::ResponseHeaders, &attempt.response_headers);
    search_cookies(ctx, &attempt.cookie, &attempt.set_cookies);
    search_body(
        ctx,
        bundle,
        Scope::RequestBody,
        &attempt.request_body,
        &attempt.request_headers,
    );
    search_body(
        ctx,
        bundle,
        Scope::ResponseBody,
        &attempt.response_body,
        &attempt.response_headers,
    );
}

fn search_headers(ctx: &mut Ctx<'_>, scope: Scope, headers: &HeaderView) {
    if !ctx.query.wants(scope) {
        return;
    }
    for entry in headers.iter_all() {
        let name = entry.name.clone();
        ctx.scan_text(scope, Some(&name), &entry.name);
        ctx.scan_text(scope, Some(&name), &entry.value);
    }
}

fn search_cookies(
    ctx: &mut Ctx<'_>,
    cookie: &crate::model::CookieField,
    set_cookies: &[crate::model::SetCookieRecord],
) {
    if !ctx.query.wants(Scope::Cookies) {
        return;
    }
    for pair in &cookie.pairs {
        let name = pair.name.clone();
        ctx.scan_text(Scope::Cookies, Some(&name), &pair.name);
        ctx.scan_text(Scope::Cookies, Some(&name), &pair.value);
    }
    for record in set_cookies {
        match &record.parsed {
            Some(parsed) => {
                let name = parsed.name.clone();
                ctx.scan_text(Scope::Cookies, Some(&name), &parsed.name);
                ctx.scan_text(Scope::Cookies, Some(&name), &parsed.value);
            }
            None => ctx.scan_text(Scope::Cookies, None, &record.raw),
        }
    }
}

/// Texto UTF-8 de um corpo; `None` se não for texto. Um corte no meio de um
/// caractere no fim de corpo truncado é tolerado.
fn text_of(bytes: &[u8], truncated: bool) -> Option<&str> {
    match std::str::from_utf8(bytes) {
        Ok(text) => Some(text),
        Err(error) if truncated && error.error_len().is_none() => {
            std::str::from_utf8(&bytes[..error.valid_up_to()]).ok()
        }
        Err(_) => None,
    }
}

fn search_body(
    ctx: &mut Ctx<'_>,
    bundle: &SessionBundle,
    scope: Scope,
    body: &crate::model::Body,
    headers: &HeaderView,
) {
    if !ctx.query.wants(scope) || !body.has_bytes() {
        return;
    }
    let Some(bytes) = body
        .attachment
        .as_deref()
        .and_then(|name| bundle.attachment(name))
    else {
        return;
    };
    let truncated = body.state == BodyState::Truncated;
    let Some(text) = text_of(bytes, truncated) else {
        ctx.result.skipped_binary += 1;
        return;
    };
    if truncated {
        ctx.result.partial = true;
        if !ctx.result.partial_attempts.contains(&ctx.attempt_id) {
            ctx.result.partial_attempts.push(ctx.attempt_id.clone());
        }
    }
    let content_type = headers
        .first_value("content-type")
        .or(body.content_type.as_deref())
        .unwrap_or("")
        .to_ascii_lowercase();
    let units = if content_type.contains("x-www-form-urlencoded") {
        Some(form_units(text))
    } else if content_type.contains("json") || looks_like_json(text) {
        json_units(text, truncated)
    } else {
        None
    };
    let mut covered: Vec<(usize, usize)> = Vec::new();
    if let Some(units) = &units {
        for unit in units {
            for at in ctx.matcher.find_all(unit.text.as_bytes()) {
                let (offset, span) = unit.original_span(at, ctx.matcher.needle.len());
                covered.push(span);
                ctx.push(scope, Some(&unit.field), offset, &unit.text, at, true);
            }
        }
    }
    for at in ctx.matcher.find_all(text.as_bytes()) {
        let span = (at, at + ctx.matcher.needle.len());
        if covered.iter().any(|c| span.0 < c.1 && c.0 < span.1) {
            continue;
        }
        let field = units.as_ref().and_then(|units| {
            units
                .iter()
                .find(|unit| unit.start <= at && at < unit.end)
                .map(|unit| unit.field.clone())
        });
        ctx.push(scope, field.as_deref(), at, text, at, false);
    }
}

/// Unidade estruturada: texto decodificado de uma chave/valor e o mapa de cada
/// byte decodificado para o byte correspondente do original.
struct Unit {
    field: String,
    text: String,
    /// Intervalo do trecho original que gerou `text`.
    start: usize,
    end: usize,
    /// `map[i]` = offset original do byte decodificado `i`; `map[text.len()]` =
    /// `end`.
    map: Vec<usize>,
}

impl Unit {
    /// Offset e intervalo original de uma ocorrência em `text`.
    fn original_span(&self, at: usize, len: usize) -> (usize, (usize, usize)) {
        let from = self.map[at];
        (from, (from, self.map[(at + len).min(self.text.len())]))
    }
}

/// Percent-decoding (`+` = espaço) com mapa de offsets. Se o resultado não for
/// UTF-8 válido, devolve o texto cru com mapa identidade.
fn percent_decode_map(raw: &str, base: usize) -> (String, Vec<usize>) {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut map = Vec::with_capacity(bytes.len() + 1);
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                map.push(base + index);
                index += 1;
            }
            b'%' if index + 2 < bytes.len()
                && hex(bytes[index + 1]).is_some()
                && hex(bytes[index + 2]).is_some() =>
            {
                out.push(hex(bytes[index + 1]).unwrap() << 4 | hex(bytes[index + 2]).unwrap());
                map.push(base + index);
                index += 3;
            }
            byte => {
                out.push(byte);
                map.push(base + index);
                index += 1;
            }
        }
    }
    map.push(base + bytes.len());
    match String::from_utf8(out) {
        Ok(text) => (text, map),
        Err(_) => (raw.to_string(), (0..=raw.len()).map(|i| base + i).collect()),
    }
}

fn hex(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|d| d as u8)
}

fn unit_from(field: String, raw: &str, start: usize) -> Unit {
    let (text, map) = percent_decode_map(raw, start);
    Unit {
        field,
        text,
        start,
        end: start + raw.len(),
        map,
    }
}

fn form_units(text: &str) -> Vec<Unit> {
    let mut units = Vec::new();
    let mut offset = 0;
    for segment in text.split('&') {
        let (raw_key, raw_value, value_start) = match segment.find('=') {
            Some(eq) => (&segment[..eq], &segment[eq + 1..], offset + eq + 1),
            None => (segment, "", offset + segment.len()),
        };
        let key = unit_from(String::new(), raw_key, offset);
        let field = key.text.clone();
        units.push(Unit {
            field: field.clone(),
            ..key
        });
        if !raw_value.is_empty() {
            units.push(unit_from(field, raw_value, value_start));
        }
        offset += segment.len() + 1;
    }
    units
}

/// Desfaz escapes JSON de uma string (conteúdo sem as aspas) com mapa de
/// offsets. Escape inválido é mantido literalmente.
fn json_unescape_map(raw: &str, base: usize) -> (String, Vec<usize>) {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut map = Vec::with_capacity(raw.len() + 1);
    let push = |out: &mut String, map: &mut Vec<usize>, ch: char, at: usize| {
        let mut buffer = [0u8; 4];
        for _ in 0..ch.encode_utf8(&mut buffer).len() {
            map.push(base + at);
        }
        out.push(ch);
    };
    let hex4 = |at: usize| -> Option<u32> {
        let digits = raw.get(at..at + 4)?;
        u32::from_str_radix(digits, 16).ok()
    };
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' || index + 1 >= bytes.len() {
            let ch = raw[index..].chars().next().unwrap();
            push(&mut out, &mut map, ch, index);
            index += ch.len_utf8();
            continue;
        }
        let simple = match bytes[index + 1] {
            b'"' => Some('"'),
            b'\\' => Some('\\'),
            b'/' => Some('/'),
            b'b' => Some('\u{8}'),
            b'f' => Some('\u{c}'),
            b'n' => Some('\n'),
            b'r' => Some('\r'),
            b't' => Some('\t'),
            _ => None,
        };
        if let Some(ch) = simple {
            push(&mut out, &mut map, ch, index);
            index += 2;
        } else if bytes[index + 1] == b'u' {
            match hex4(index + 2) {
                Some(high @ 0xD800..=0xDBFF) if raw.get(index + 6..index + 8) == Some("\\u") => {
                    match hex4(index + 8) {
                        Some(low @ 0xDC00..=0xDFFF) => {
                            let ch =
                                char::from_u32(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00))
                                    .unwrap_or('\u{FFFD}');
                            push(&mut out, &mut map, ch, index);
                            index += 12;
                        }
                        _ => {
                            push(&mut out, &mut map, '\u{FFFD}', index);
                            index += 6;
                        }
                    }
                }
                Some(code) => {
                    push(
                        &mut out,
                        &mut map,
                        char::from_u32(code).unwrap_or('\u{FFFD}'),
                        index,
                    );
                    index += 6;
                }
                None => {
                    push(&mut out, &mut map, '\\', index);
                    index += 1;
                }
            }
        } else {
            push(&mut out, &mut map, '\\', index);
            index += 1;
        }
    }
    map.push(base + bytes.len());
    (out, map)
}

fn looks_like_json(text: &str) -> bool {
    matches!(
        text.trim_start().as_bytes().first(),
        Some(b'{') | Some(b'[')
    )
}

const MAX_JSON_DEPTH: usize = 64;

/// Strings JSON sem escape, com caminho. `None` se o texto não for JSON válido
/// (então é tratado como texto simples). Em corpo truncado o JSON fica
/// incompleto: devolve as strings lidas até o corte.
fn json_units(text: &str, truncated: bool) -> Option<Vec<Unit>> {
    let mut parser = JsonScan {
        bytes: text.as_bytes(),
        text,
        pos: 0,
        units: Vec::new(),
    };
    parser.skip_ws();
    if parser.value("", 0).is_none() && !truncated {
        return None;
    }
    Some(parser.units)
}

struct JsonScan<'a> {
    bytes: &'a [u8],
    text: &'a str,
    pos: usize,
    units: Vec<Unit>,
}

impl JsonScan<'_> {
    fn skip_ws(&mut self) {
        while matches!(self.bytes.get(self.pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    /// Lê uma string; devolve (início do conteúdo, fim, tinha escape).
    fn string(&mut self) -> Option<(usize, usize, bool)> {
        if self.bytes.get(self.pos) != Some(&b'"') {
            return None;
        }
        self.pos += 1;
        let start = self.pos;
        let mut escaped = false;
        while let Some(&byte) = self.bytes.get(self.pos) {
            match byte {
                b'"' => {
                    let end = self.pos;
                    self.pos += 1;
                    return Some((start, end, escaped));
                }
                b'\\' => {
                    escaped = true;
                    self.pos += 2;
                }
                _ => self.pos += 1,
            }
        }
        None
    }

    fn add(&mut self, path: &str, start: usize, end: usize, _escaped: bool) {
        let (text, map) = json_unescape_map(&self.text[start..end], start);
        self.units.push(Unit {
            field: path.to_string(),
            text,
            start,
            end,
            map,
        });
    }

    fn value(&mut self, path: &str, depth: usize) -> Option<()> {
        if depth > MAX_JSON_DEPTH {
            return None;
        }
        self.skip_ws();
        match *self.bytes.get(self.pos)? {
            b'"' => {
                let (start, end, escaped) = self.string()?;
                self.add(path, start, end, escaped);
                Some(())
            }
            b'{' => {
                self.pos += 1;
                self.skip_ws();
                if self.bytes.get(self.pos) == Some(&b'}') {
                    self.pos += 1;
                    return Some(());
                }
                loop {
                    self.skip_ws();
                    let (start, end, escaped) = self.string()?;
                    let key = json_unescape_map(&self.text[start..end], start).0;
                    let child = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    self.add(&child, start, end, escaped);
                    self.skip_ws();
                    if self.bytes.get(self.pos) != Some(&b':') {
                        return None;
                    }
                    self.pos += 1;
                    self.value(&child, depth + 1)?;
                    self.skip_ws();
                    match self.bytes.get(self.pos)? {
                        b',' => self.pos += 1,
                        b'}' => {
                            self.pos += 1;
                            return Some(());
                        }
                        _ => return None,
                    }
                }
            }
            b'[' => {
                self.pos += 1;
                self.skip_ws();
                if self.bytes.get(self.pos) == Some(&b']') {
                    self.pos += 1;
                    return Some(());
                }
                let mut index = 0;
                loop {
                    let child = format!("{path}[{index}]");
                    self.value(&child, depth + 1)?;
                    self.skip_ws();
                    match self.bytes.get(self.pos)? {
                        b',' => self.pos += 1,
                        b']' => {
                            self.pos += 1;
                            return Some(());
                        }
                        _ => return None,
                    }
                    index += 1;
                }
            }
            _ => {
                // número, true, false, null
                let start = self.pos;
                while self.bytes.get(self.pos).is_some_and(|b| {
                    !matches!(b, b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
                }) {
                    self.pos += 1;
                }
                (self.pos > start).then_some(())
            }
        }
    }
}
