//! Search over metadata and bodies of a session (`docs/08-bodies-search.md` §2).
//!
//! API for the App (wave 4b, via Tauri):
//!
//! ```text
//! pub fn search(source: &dyn BodySource, query: &SearchQuery) -> SearchResult
//! SearchResult { matches: Vec<Match>, skipped_binary: usize,
//!                partial: bool, partial_attempts: Vec<String>, limit_reached: bool }
//! Match { request_id, attempt_id, scope, field: Option<String>,
//!         byte_offset: Option<u64>, byte_length: Option<u64>, exact: bool,
//!         snippet, decoded }
//! ```
//!
//! Large sessions: `search_lazy(&LazySession, &SearchQuery)` (see
//! [`crate::lazy`]) reads one body at a time from disk; `search_with` accepts any
//! [`BodySource`].
//!
//! Takes the [`SessionBundle`] (not just the session) because the bodies live in
//! attachments. `request_id` is the logical id of the session (`LogicalRequest::id`).
//!
//! Semantics:
//! - `byte_offset` is always relative to the original (URL, header value or bytes
//!   of the body). In form-urlencoded it is the start of the value/key in the raw body; in
//!   JSON, the start of the string text in the raw body.
//! - `decoded=true` means "found by the structured view": keys and values
//!   of form-urlencoded with percent-decoding (`+` = space) and JSON strings without
//!   escape, with `field` = key or path (`a.b[0]`). Excerpts outside these
//!   units (or bodies that are not form/JSON) are searched in the raw bytes
//!   with `decoded=false`.
//! - Binary bodies (invalid UTF-8) are counted in `skipped_binary`.
//! - `truncated` bodies are searched and mark `partial`.
//! - Unicode case is not ignored: only ASCII is folded.

use serde::{Deserialize, Serialize};

use std::borrow::Cow;

use crate::model::{Attempt, BodyState, HeaderView, LogicalRequest, SessionBundle, SessionV1};

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
    /// Empty = all scopes.
    #[serde(default)]
    pub scopes: Vec<Scope>,
    #[serde(default)]
    pub case_sensitive: bool,
    /// Limit of matches returned; when reached, `limit_reached` becomes true.
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
    /// Length in bytes of the excerpt in the original (`None` if there is no offset).
    pub byte_length: Option<u64>,
    /// `false` when the mapping through the decoding could not be exact: the
    /// range (`byte_offset`, `byte_length`) then covers the whole value.
    pub exact: bool,
    pub snippet: String,
    pub decoded: bool,
    /// The field is an HTML form control (`input`/`textarea`/`select`).
    #[serde(default)]
    pub html_control: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub matches: Vec<Match>,
    /// Bodies with non-text bytes, not searched.
    pub skipped_binary: usize,
    /// Some `truncated` body was searched: the search is partial.
    pub partial: bool,
    pub partial_attempts: Vec<String>,
    pub limit_reached: bool,
}

struct Matcher {
    needle: Vec<u8>,
    case_sensitive: bool,
}

impl Matcher {
    /// Offsets (in bytes) of all occurrences, without overlap.
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
    /// The next `push` comes from an HTML form control.
    html: bool,
}

impl Ctx<'_> {
    fn push(
        &mut self,
        scope: Scope,
        field: Option<&str>,
        span: (usize, usize, bool),
        text: &str,
        at: usize,
        decoded: bool,
    ) {
        let (offset, length, exact) = span;
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
            byte_length: Some(length as u64),
            exact,
            snippet: snippet(text, at, self.matcher.needle.len()),
            decoded,
            html_control: self.html,
        });
    }

    /// URL: searches the original text and, if there is `%XX`, also in the view
    /// percent-decoded (`decoded=true`), without duplicating excerpts already found.
    fn scan_url(&mut self, url: &str) {
        let raw: Vec<usize> = self.matcher.find_all(url.as_bytes());
        let needle_len = self.matcher.needle.len();
        for &at in &raw {
            self.push(Scope::Url, None, (at, needle_len, true), url, at, false);
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
            self.push(Scope::Url, None, (from, to - from, true), &text, at, true);
        }
    }

    /// Search in plain text (URL, header, cookie name/value).
    fn scan_text(&mut self, scope: Scope, field: Option<&str>, text: &str) {
        for at in self.matcher.find_all(text.as_bytes()) {
            let length = self.matcher.needle.len();
            self.push(scope, field, (at, length, true), text, at, false);
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

/// Bytes of an attachment delivered to the search. `cut` = there were more bytes than the limit
/// of reading (the search becomes partial).
pub struct Loaded<'a> {
    pub bytes: Cow<'a, [u8]>,
    pub cut: bool,
}

/// Origin of the searched bodies. The search requests one body at a time and releases it
/// when done scanning it.
pub trait BodySource {
    fn load(&self, name: &str) -> Option<Loaded<'_>>;
}

impl BodySource for SessionBundle {
    fn load(&self, name: &str) -> Option<Loaded<'_>> {
        self.attachment(name).map(|bytes| Loaded {
            bytes: Cow::Borrowed(bytes),
            cut: false,
        })
    }
}

/// Bodies read on demand from a [`crate::lazy::LazySession`].
pub struct LazyBodies<'a>(pub &'a crate::lazy::LazySession);

impl BodySource for LazyBodies<'_> {
    fn load(&self, name: &str) -> Option<Loaded<'_>> {
        let (bytes, cut) = self
            .0
            .read_attachment(name, crate::lazy::BODY_READ_LIMIT)
            .ok()?;
        Some(Loaded {
            bytes: Cow::Owned(bytes),
            cut,
        })
    }
}

/// Searches `query` in the session. See the module for the semantics.
pub fn search(bundle: &SessionBundle, query: &SearchQuery) -> SearchResult {
    search_with(&bundle.session, bundle, query)
}

/// Search in an open session with [`crate::lazy::LazySession`]: reads one body at a
/// time from disk (no symlinks, up to 5 MiB per body; a larger body is searched only
/// in the prefix and marks the search as partial) and does not retain the bytes.
pub fn search_lazy(lazy: &crate::lazy::LazySession, query: &SearchQuery) -> SearchResult {
    search_with(&lazy.session, &LazyBodies(lazy), query)
}

/// Search with an arbitrary body source.
pub fn search_with(
    session: &SessionV1,
    source: &dyn BodySource,
    query: &SearchQuery,
) -> SearchResult {
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
        html: false,
    };
    if query.text.is_empty() {
        return ctx.result;
    }
    for request in &session.requests {
        ctx.request_id = request.id.clone();
        if request.attempts.is_empty() {
            ctx.attempt_id = String::new();
            search_logical(&mut ctx, source, request);
        }
        for attempt in &request.attempts {
            ctx.attempt_id = attempt.id.clone();
            search_attempt(&mut ctx, source, attempt);
        }
    }
    ctx.result
}

fn search_logical(ctx: &mut Ctx<'_>, source: &dyn BodySource, request: &LogicalRequest) {
    if ctx.query.wants(Scope::Url) {
        ctx.scan_url(&request.url);
    }
    search_headers(ctx, Scope::RequestHeaders, &request.request_headers);
    search_headers(ctx, Scope::ResponseHeaders, &request.response_headers);
    search_cookies(ctx, &request.cookie, &request.set_cookies);
    search_body(
        ctx,
        source,
        Scope::RequestBody,
        &request.request_body,
        &request.request_headers,
    );
    search_body(
        ctx,
        source,
        Scope::ResponseBody,
        &request.response_body,
        &request.response_headers,
    );
}

fn search_attempt(ctx: &mut Ctx<'_>, source: &dyn BodySource, attempt: &Attempt) {
    if ctx.query.wants(Scope::Url) {
        ctx.scan_url(&attempt.url);
    }
    search_headers(ctx, Scope::RequestHeaders, &attempt.request_headers);
    search_headers(ctx, Scope::ResponseHeaders, &attempt.response_headers);
    search_cookies(ctx, &attempt.cookie, &attempt.set_cookies);
    search_body(
        ctx,
        source,
        Scope::RequestBody,
        &attempt.request_body,
        &attempt.request_headers,
    );
    search_body(
        ctx,
        source,
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

/// UTF-8 text of a body; `None` if it is not text. A cut in the middle of a
/// character at the end of a truncated body is tolerated.
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
    source: &dyn BodySource,
    scope: Scope,
    body: &crate::model::Body,
    headers: &HeaderView,
) {
    if !ctx.query.wants(scope) || !body.has_bytes() {
        return;
    }
    let Some(loaded) = body
        .attachment
        .as_deref()
        .and_then(|name| source.load(name))
    else {
        return;
    };
    let bytes: &[u8] = &loaded.bytes;
    let truncated = body.state == BodyState::Truncated || loaded.cut;
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
    } else if content_type.contains("html") || text.contains("<textarea") || text.contains("<input")
    {
        let units: Vec<Unit> = crate::html::html_controls(text)
            .into_iter()
            .map(|c| Unit {
                field: c.name,
                text: c.value,
                start: c.start,
                end: c.end,
                map: c.map,
                lossy: false,
                html: true,
            })
            .collect();
        (!units.is_empty()).then_some(units)
    } else {
        None
    };
    let mut covered: Vec<(usize, usize)> = Vec::new();
    if let Some(units) = &units {
        for unit in units {
            for at in ctx.matcher.find_all(unit.text.as_bytes()) {
                if ctx.result.limit_reached {
                    break;
                }
                let span = unit.original_span(at, ctx.matcher.needle.len());
                covered.push((span.0, span.0 + span.1));
                ctx.html = unit.html;
                ctx.push(scope, Some(&unit.field), span, &unit.text, at, true);
                ctx.html = false;
            }
        }
    }
    for at in ctx.matcher.find_all(text.as_bytes()) {
        if ctx.result.limit_reached {
            break;
        }
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
        let length = ctx.matcher.needle.len();
        ctx.push(scope, field.as_deref(), (at, length, true), text, at, false);
    }
}

/// Structured unit: decoded text of a key/value and the map of each
/// decoded byte to the corresponding byte of the original.
struct Unit {
    field: String,
    text: String,
    /// Range of the original excerpt that produced `text`.
    start: usize,
    end: usize,
    /// `map[i]` = original offset of decoded byte `i`; `map[text.len()]` =
    /// `end`.
    map: Vec<usize>,
    /// The decoding replaced something with U+FFFD: the map is not exact.
    lossy: bool,
    /// The field is an HTML form control.
    html: bool,
}

impl Unit {
    /// (offset, length, exact) of an occurrence in the original. If the
    /// decoding was lossy, it covers the whole value (`exact=false`).
    fn original_span(&self, at: usize, len: usize) -> (usize, usize, bool) {
        if self.lossy {
            return (self.start, self.end - self.start, false);
        }
        let from = self.map[at];
        let to = self.map[(at + len).min(self.text.len())];
        (from, to - from, true)
    }
}

/// Percent-decoding (`+` = space) with an offset map. If the result is not
/// valid UTF-8, returns the raw text with an identity map.
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
        lossy: false,
        html: false,
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

/// Undoes JSON escapes of a string (content without the quotes) with a map of
/// offsets. An invalid escape is kept literally.
fn json_unescape_map(raw: &str, base: usize) -> (String, Vec<usize>, bool) {
    let mut lossy = false;
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
                            lossy = true;
                            push(&mut out, &mut map, '\u{FFFD}', index);
                            index += 6;
                        }
                    }
                }
                Some(code) => {
                    lossy |= char::from_u32(code).is_none();
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
    (out, map, lossy)
}

fn looks_like_json(text: &str) -> bool {
    matches!(
        text.trim_start().as_bytes().first(),
        Some(b'{') | Some(b'[')
    )
}

const MAX_JSON_DEPTH: usize = 64;

/// JSON strings without escapes, with a path. `None` if the text is not valid JSON
/// (so it is treated as plain text). In a truncated body the JSON becomes
/// incomplete: returns the strings read up to the cut.
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

    /// Reads a string; returns (content start, end, had escape).
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
        let (text, map, lossy) = json_unescape_map(&self.text[start..end], start);
        self.units.push(Unit {
            field: path.to_string(),
            text,
            start,
            end,
            map,
            lossy,
            html: false,
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
                // number, true, false, null
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
