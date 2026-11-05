//! Structural redaction of secrets in free text (header values, request line,
//! notes, messages, JSON strings, parameter values).
//!
//! The text is processed in **levels**. At each level:
//!
//! 1. Split on the RAW delimiters of that level (whitespace, quotes,
//!    parentheses, brackets, `, | \ & # ;`), forming *groups*. `? / =` and `:` stay
//!    inside the group: they delimit names, not values.
//! 2. Inside the group, each raw `=` closes a name (`parte`). If the **effective name**
//!    of the part is sensitive, the value (up to the end of the group, or up to the closing
//!    quote/parenthesis, or the next group if there is a space after the `=`) is redacted.
//!    The effective name is the last segment of the part after `? / & # ; , | =`,
//!    percent-decoded for ONE round.
//! 3. The whole group is decoded ONCE (`%XX`; `+` stays `+`) and becomes the next level
//!    down. A separator that only appears after decoding belongs to the
//!    lower level and never ends a value of the current level: `%2B`, `%2520`,
//!    `%2526` and `%2523` do not cut a base64 credential.
//!
//! Each level only produces *edits* (ranges in the ORIGINAL text, via a map of
//! positions of the decoded bytes); the text comes out of a single application of the
//! edits, so nothing that was not redacted is rewritten (or re-encoded).
//! Cost: one scan pass per level + one apply pass; decoding
//! only happens in groups that contain a valid `%XX`, and the depth is limited.
//!
//! # Extent of the value
//!
//! - Level 0: the value runs up to a space or `& #`; `;` only closes it at the end or before
//!   `name=`. Decoded levels (1+): the space came from `%XX` of the same value and does not
//!   close it. `, ( ) [ ] { } | " ' \ < >` are part of the value, except the closing
//!   of an opening BEFORE the name (`{token=X}`); openings inside the value with a
//!   nearby closing are skipped whole.
//! - In PATHS (`/seg=value/`, `;param=value` after a token with `/`) the value of a
//!   SENSITIVE name runs up to the next `?` (or `#`, or the end) and is redacted whole, `/`
//!   included: a credential may contain `/` (base64) and there is no way to know where it ends.
//!   ACCEPTED LIMITATION (A7-B5/A8-M1): `/a;v=2/session=keep/b` comes out as
//!   `/a;v=2/session=[REDACTED]` (the `/b` is lost); security takes precedence over
//!   fidelity. NON-sensitive names change nothing and the rest of the path keeps being
//!   examined. The cost is linear: no heuristic looks back at each `/`.
//!   Exception (A9-B1): `,` or `|` followed by `/` ends the value in path context (list
//!   without spaces `/a/token=x/b,/c/keep` preserves the next item). Accepted limitation: a
//!   credential that contains `,/` or `|/` leaks what comes after it.
//! - Quotes/brackets after `=`: the interior is the value; text or another opening GLUED
//!   after the closing (`"a"X`, `[a][X]`, `'a'"X`) is also value.
//! - HTML entities for `=` (`&#61;`, `&equals;`...) count at any number of escape layers
//!   (`&amp;`, `&#38;`); above 256 layers it fails closed (treated as `=`).
//! - A value that starts with the placeholder has already been redacted (idempotence).
//!
//! # Failing closed
//!
//! Whenever it cannot be decided, the WHOLE remaining VALUE is redacted instead of
//! leaving the tail raw: (1) at the 8-level ceiling the text is decoded until stable
//! and scanned in closed mode (the value runs to the end of the level; if `%XX` still remains, the
//! whole group is redacted); (2) an invalid/overlong byte right after a sensitive name
//! redacts the rest of the group; (3) GROUP ABOVE 1 MiB with `%XX`: position maps are not built;
//! it is decoded "dry" (bytes only) to DECIDE, and the group is
//! redacted in full ONLY if some level has a sensitive name or if it cannot be decided
//! (`%XX` remains at the ceiling); without a sensitive name the group passes through intact.

use std::borrow::Cow;
use std::collections::HashMap;

use super::sanitize::{is_business_key, is_sensitive_key, url_placeholder, SanitizeOptions};

/// Decoding levels examined (0 = the text as received).
const MAX_LEVELS: usize = 8;
/// Names longer than this are never known credentials.
const MAX_NAME_LEN: usize = 128;
/// Entries of the name cache; when it overflows, the cache is emptied.
const NAME_CACHE_CAP: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Repl {
    /// Parameter value: percent-encoded placeholder (`%5BREDACTED%5D`).
    Param,
    /// Credential after a scheme (`Bearer`): ` [REDACTED]` at level 0.
    Auth,
    /// The same, inside a decoded level: `%20%5BREDACTED%5D`.
    AuthEnc,
}

struct Edit {
    start: usize,
    end: usize,
    repl: Repl,
}

/// One level: the text bytes (decoded, from level 1 on) and, for each
/// byte, the corresponding range in the original text.
struct Level<'a> {
    bytes: Cow<'a, [u8]>,
    map: Option<Vec<(u32, u32)>>,
    /// "Dry" level (group above the work ceiling): no position map, only to
    /// DECIDE whether there is a sensitive name; the edits it produces are discarded.
    dry: bool,
}

impl Level<'_> {
    fn orig(&self, index: usize) -> (usize, usize) {
        match &self.map {
            Some(map) => (map[index].0 as usize, map[index].1 as usize),
            None => (index, index + 1),
        }
    }

    /// `[start, end)` of this level → range in the original text.
    fn range(&self, start: usize, end: usize) -> (usize, usize) {
        (self.orig(start).0, self.orig(end - 1).1)
    }
}

pub(super) struct Scrubber<'a> {
    options: &'a SanitizeOptions,
    edits: Vec<Edit>,
    names: HashMap<Vec<u8>, bool>,
    param: std::cell::OnceCell<String>,
    /// "Fail closed" mode: when the level ceiling is hit, the value of a
    /// sensitive name runs to the end of the whole level (we no longer know which
    /// separators belong to the value).
    closed: bool,
}

/// Applies the rules to the text. `None` when nothing changed.
pub(super) fn scrub(text: &str, options: &SanitizeOptions) -> Option<String> {
    Scrubber::new(options).run(text)
}

impl<'a> Scrubber<'a> {
    pub(super) fn new(options: &'a SanitizeOptions) -> Self {
        Self {
            options,
            edits: Vec::new(),
            names: HashMap::new(),
            param: std::cell::OnceCell::new(),
            closed: false,
        }
    }

    /// Scans `text`; the sensitive-name cache is reused between calls
    /// (lookup with millions of pairs). `None` when nothing changed.
    pub(super) fn run(&mut self, text: &str) -> Option<String> {
        if !text.contains(['=', '%', '@', '&', '\u{FF1D}']) && !has_scheme_word(text.as_bytes()) {
            return None;
        }
        self.edits.clear();
        self.closed = false;
        let level = Level {
            bytes: Cow::Borrowed(text.as_bytes()),
            map: None,
            dry: false,
        };
        self.scan_level(&level, 0);
        if self.edits.is_empty() {
            return None;
        }
        Some(self.apply(text))
    }
}

fn has_scheme_word(bytes: &[u8]) -> bool {
    bytes.windows(5).any(|w| w.eq_ignore_ascii_case(b"basic"))
        || bytes.windows(6).any(|w| w.eq_ignore_ascii_case(b"bearer"))
}

#[inline]
fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

/// Raw delimiters that end a group.
#[inline]
fn is_hard(byte: u8) -> bool {
    is_space(byte)
        || matches!(
            byte,
            b'"' | b'\''
                | b'('
                | b')'
                | b'<'
                | b'>'
                | b'['
                | b']'
                | b'{'
                | b'}'
                | b','
                | b'|'
                | b'\\'
                | b'&'
                | b'#'
                | b';'
        )
}

/// Extra decoding rounds when the level ceiling is reached.
const FIXPOINT_ROUNDS: usize = 24;
/// Work ceiling per group: above this the group (if it has `%XX`) is not
/// decoded and is redacted whole (fail closed), which also bounds the memory of
/// the position maps (8 bytes per decoded byte).
const MAX_DECODE_BYTES: usize = 1 << 20;

/// Decodes `[start, end)` of `level` (`%XX`; `+` stays `+`), with the map back
/// to the positions of the original text.
fn decode_level(level: &Level<'_>, start: usize, end: usize, dry: bool) -> Level<'static> {
    let src = &level.bytes[start..end];
    let mut bytes = Vec::with_capacity(src.len());
    let mut map: Vec<(u32, u32)> = Vec::with_capacity(if dry { 0 } else { src.len() });
    let mut i = 0;
    while i < src.len() {
        if src[i] == b'%' && i + 2 < src.len() {
            if let (Some(h), Some(l)) = (hex(src[i + 1]), hex(src[i + 2])) {
                bytes.push(h * 16 + l);
                if !dry {
                    let (a, _) = level.orig(start + i);
                    let (_, b) = level.orig(start + i + 2);
                    map.push((a as u32, b as u32));
                }
                i += 3;
                continue;
            }
        }
        bytes.push(src[i]);
        if !dry {
            let (a, b) = level.orig(start + i);
            map.push((a as u32, b as u32));
        }
        i += 1;
    }
    Level {
        bytes: Cow::Owned(bytes),
        map: if dry { None } else { Some(map) },
        dry,
    }
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Is there a valid `%XX`?
fn has_escape(bytes: &[u8]) -> bool {
    bytes
        .windows(3)
        .any(|w| w[0] == b'%' && hex(w[1]).is_some() && hex(w[2]).is_some())
}

impl Scrubber<'_> {
    fn param(&self) -> &str {
        self.param.get_or_init(|| url_placeholder(self.options))
    }

    /// Is the slice already the placeholder (or its core between brackets)? Keeps
    /// the redaction idempotent: sanitizing twice does not stack placeholders.
    fn is_placeholder(&self, level: &Level<'_>, start: usize, end: usize) -> bool {
        let slice = &level.bytes[start..end];
        let placeholder = self.options.placeholder.as_bytes();
        if slice == placeholder || slice == self.param().as_bytes() {
            return true;
        }
        let inner = self.options.placeholder.trim_matches(['[', ']']).as_bytes();
        !inner.is_empty()
            && slice == inner
            && start > 0
            && level.bytes.get(start - 1) == Some(&b'[')
            && level.bytes.get(end) == Some(&b']')
    }

    fn push(&mut self, level: &Level<'_>, start: usize, end: usize, repl: Repl) {
        if end > start && !(repl == Repl::Param && self.is_placeholder(level, start, end)) {
            let (start, end) = level.range(start, end);
            self.edits.push(Edit { start, end, repl });
        }
    }

    fn scan_level(&mut self, level: &Level<'_>, depth: usize) {
        self.find_userinfo(level);
        self.find_auth(level, depth);
        let bytes: &[u8] = &level.bytes;
        // Openings (quotes, parentheses, brackets) not yet closed: the value of a
        // sensitive name ends at the closing of any of them.
        let mut stack: Vec<u8> = Vec::new();
        let mut pos = 0;
        while pos < bytes.len() {
            if is_hard(bytes[pos]) {
                pos += track_enclosing(bytes, pos, &mut stack);
                continue;
            }
            let end = bytes[pos..]
                .iter()
                .position(|b| is_hard(*b))
                .map_or(bytes.len(), |n| pos + n);
            let next = self.scan_group(level, pos, end, depth, &stack).max(end);
            if next > end {
                // the skipped stretch was a redacted value; its openings do not count
                stack.clear();
            }
            pos = next;
        }
    }

    /// A group `[start, end)`; returns where the scan continues (beyond `end`
    /// when the redacted value took quotes/brackets or the next group).
    fn scan_group(
        &mut self,
        level: &Level<'_>,
        start: usize,
        end: usize,
        depth: usize,
        stack: &[u8],
    ) -> usize {
        let bytes: &[u8] = &level.bytes;
        // `seg_start`: start of the stretch not yet decoded/examined;
        // `part_start`: start of the current name.
        let mut seg_start = start;
        let mut part_start = start;
        let mut cursor = start;
        while cursor < end {
            let Some((eq, eq_len)) = find_equals(bytes, cursor, end) else {
                break;
            };
            if self.is_sensitive_part(&bytes[part_start..eq]) {
                // what came BEFORE the name may still carry an encoded secret
                self.decode_child(level, seg_start, eq, depth);
                let query_ends = path_context(bytes, start, part_start, eq);
                let next = self.redact_value(level, eq + eq_len, end, depth, stack, query_ends);
                if next >= end {
                    return next;
                }
                seg_start = next;
                part_start = next;
                cursor = next;
                continue;
            }
            part_start = eq + eq_len;
            cursor = part_start;
        }
        // In decoded levels, a byte that is not valid UTF-8 right after a sensitive name
        // (`token%C0%BDvalor`: `=` in "overlong" encoding) is a separator we cannot
        // classify: fail closed, the rest of the group is value.
        if level.map.is_some() && part_start < end {
            if let Err(error) = std::str::from_utf8(&bytes[part_start..end]) {
                let bad = part_start + error.valid_up_to();
                if bad > part_start && self.is_sensitive_part(&bytes[part_start..bad]) {
                    self.decode_child(level, seg_start, bad, depth);
                    self.push(level, bad, end, Repl::Param);
                    return end;
                }
            }
        }
        // `token =valor`, `token = valor`, `token&#61;valor`, `token &#61; valor`:
        // space and/or HTML entity between the name and the value.
        let mut look = end;
        while look < bytes.len() && matches!(bytes[look], b' ' | b'\t') {
            look += 1;
        }
        if let Some(len) = equals_len_at(bytes, look) {
            if self.is_sensitive_part(&bytes[part_start..end]) {
                self.decode_child(level, seg_start, end, depth);
                let vstart = look + len;
                return self.redact_value(level, vstart, vstart, depth, stack, false);
            }
        }
        self.decode_child(level, seg_start, end, depth);
        end
    }

    /// Redacts the value starting at `vstart` (after the `=`) and returns where the
    /// scan continues. `group_end` is the end of the name's group.
    fn redact_value(
        &mut self,
        level: &Level<'_>,
        vstart: usize,
        group_end: usize,
        depth: usize,
        stack: &[u8],
        query_ends: bool,
    ) -> usize {
        let bytes: &[u8] = &level.bytes;
        if self.closed {
            // Fail closed: everything left in the level is value.
            self.push(level, vstart, bytes.len(), Repl::Param);
            return bytes.len();
        }
        let (value_start, value_end, next) =
            self.value_extent(bytes, vstart, group_end, depth, stack, query_ends);
        self.push(level, value_start, value_end, Repl::Param);
        // After a value in quotes/brackets, whatever is GLUED on still counts as value:
        // text (`token="abc"TAIL`, `[abc]TAIL`) or another opening (`'a'"X`, `[a][X]`,
        // `"a"(X)`). Each round consumes at least one byte.
        let mut next = next;
        if next > value_end {
            while next < bytes.len() {
                let b = bytes[next];
                if is_tail_byte(b) {
                    let tail_end = bytes[next..]
                        .iter()
                        .position(|c| !is_tail_byte(*c))
                        .map_or(bytes.len(), |n| next + n);
                    // `TAIL=...` is not a tail: it is the name of the next parameter.
                    if starts_with_equals(bytes, tail_end) {
                        break;
                    }
                    self.push(level, next, tail_end, Repl::Param);
                    next = tail_end;
                    continue;
                }
                let opens = match b {
                    b'"' | b'\'' => !stack.contains(&b),
                    b'(' | b'[' | b'{' | b'<' => true,
                    b'\\' => {
                        matches!(bytes.get(next + 1), Some(b'"' | b'\''))
                            && !stack.contains(&(0x80 | bytes[next + 1]))
                    }
                    _ => false,
                };
                if !opens {
                    break;
                }
                let (s0, e0, n0) = self.value_extent(bytes, next, next, depth, stack, false);
                if n0 <= next {
                    break;
                }
                self.push(level, s0, e0, Repl::Param);
                next = n0;
            }
        }
        next
    }

    /// Where the value of a sensitive name whose `=` is before `vstart` ends.
    /// Returns (start, end, where the scan continues).
    fn value_extent(
        &self,
        bytes: &[u8],
        vstart: usize,
        group_end: usize,
        depth: usize,
        stack: &[u8],
        query_ends: bool,
    ) -> (usize, usize, usize) {
        if vstart < group_end {
            return self.attached_extent(bytes, vstart, depth, stack, query_ends);
        }
        // `=` is the last byte of the group; what comes after is a delimiter or the end
        let mut p = vstart;
        while p < bytes.len() && matches!(bytes[p], b' ' | b'\t') {
            p += 1;
        }
        if p >= bytes.len() {
            return (p, p, p);
        }
        // `token=&#61;X`: another "equals" (entity) glued to the first; the value comes after.
        let mut after_equals = p;
        while let Some(n) = equals_len_at(bytes, after_equals) {
            after_equals += n;
        }
        if after_equals > p {
            return self.value_extent(bytes, after_equals, after_equals, depth, stack, false);
        }
        // `token=\X`: a backslash that does not escape quotes is just one more byte of the value.
        if bytes[p] == b'\\' && !matches!(bytes.get(p + 1), Some(b'"' | b'\'')) {
            return self.attached_extent(bytes, p, depth, stack, false);
        }
        if bytes[p] == b'\\' && matches!(bytes.get(p + 1), Some(b'"' | b'\'')) {
            // `\"value\"` (escaped quotes, common in text inside JSON)
            let quote = bytes[p + 1];
            let mut q = p + 2;
            while q + 1 < bytes.len()
                && bytes[q] != b'\n'
                && !(bytes[q] == b'\\' && bytes[q + 1] == quote)
            {
                q += 1;
            }
            let close = if q + 1 < bytes.len() && bytes[q] == b'\\' && bytes[q + 1] == quote {
                q
            } else {
                bytes.len()
            };
            let next = if close < bytes.len() {
                close + 2
            } else {
                close
            };
            return (p + 2, close, next);
        }
        match bytes[p] {
            quote @ (b'"' | b'\'') => {
                let mut q = p + 1;
                while q < bytes.len() && bytes[q] != quote && bytes[q] != b'\n' {
                    if bytes[q] == b'\\' && q + 1 < bytes.len() {
                        q += 1;
                    }
                    q += 1;
                }
                let mut close = q.min(bytes.len());
                let closed = close < bytes.len() && bytes[close] == quote;
                if !closed && depth == 0 {
                    // unclosed opening: the value runs up to the next space
                    close = bytes[p + 1..]
                        .iter()
                        .position(|b| is_space(*b))
                        .map_or(bytes.len(), |n| p + 1 + n);
                }
                (p + 1, close, if closed { close + 1 } else { close })
            }
            open @ (b'(' | b'[' | b'{' | b'<') => {
                let closer = match open {
                    b'(' => b')',
                    b'[' => b']',
                    b'{' => b'}',
                    _ => b'>',
                };
                let mut nest = 1usize;
                let mut q = p + 1;
                while q < bytes.len() && bytes[q] != b'\n' {
                    if bytes[q] == open {
                        nest += 1;
                    } else if bytes[q] == closer {
                        nest -= 1;
                        if nest == 0 {
                            break;
                        }
                    }
                    q += 1;
                }
                let mut close = q.min(bytes.len());
                let closed = close < bytes.len() && bytes[close] == closer;
                if !closed && depth == 0 {
                    close = bytes[p + 1..]
                        .iter()
                        .position(|b| is_space(*b))
                        .map_or(bytes.len(), |n| p + 1 + n);
                }
                (p + 1, close, if closed { close + 1 } else { close })
            }
            b if !is_hard(b) => self.attached_extent(bytes, p, depth, stack, false),
            _ => (vstart, vstart, vstart),
        }
    }

    /// Unquoted value. At level 0 it runs up to a space or `& #`; at decoded levels
    /// (1+) the space came from `%XX` of the same value and does not end it:
    /// only `& #`. (`;` does not end it: `token=AB;resto` is value; `token=X; Path=/`
    /// keeps preserving ` Path=/`.) In both, `, ( ) < > [ ] { } | " ' \\` are part of the
    /// value, except the closing of an opening BEFORE the name (`{token=X}`,
    /// `"token=X"`, `(token=X)`). A value that STARTS with the placeholder has already been
    /// redacted: it stops after it if what follows is `/ ?` or a delimiter
    /// (idempotence: `jsessionid=%5BREDACTED%5D/b/c?x=1`).
    fn attached_extent(
        &self,
        bytes: &[u8],
        vstart: usize,
        depth: usize,
        stack: &[u8],
        query_ends: bool,
    ) -> (usize, usize, usize) {
        let rest = &bytes[vstart..];
        for placeholder in [self.options.placeholder.as_bytes(), self.param().as_bytes()] {
            if !placeholder.is_empty() && rest.starts_with(placeholder) {
                let after = vstart + placeholder.len();
                if after >= bytes.len() || !is_tail_byte(bytes[after]) {
                    return (vstart, vstart, after);
                }
                break; // placeholder with a glued tail: the tail is also value
            }
        }
        // Openings INSIDE the value (`AB(c)X`, `AB[c d]X`, `AB'x y'Z`) with a nearby closing
        // (up to 64 bytes, on the same line) are skipped whole: their closing is part of
        // the value and is not confused with that of an opening before the name. Without a
        // nearby closing, the opening is just one more byte of the value.
        let mut q = vstart;
        while q < bytes.len() {
            let b = bytes[q];
            if matches!(b, b'&' | b'#') {
                break;
            }
            // In a path (`/a;jsessionid=X/b`, `/s/session=X/b`) the value ends at `/` or `?`:
            // the rest is the path/query, which keeps being examined.
            if query_ends && b == b'?' {
                break;
            }
            // Path list without spaces (`/a/token=x/b,/c/keep`): `,` or `|` followed by `/`
            // opens the next item and ends the value in path context (A9-B1).
            if query_ends && matches!(b, b',' | b'|') && bytes.get(q + 1) == Some(&b'/') {
                break;
            }
            if depth == 0 && is_space(b) {
                break;
            }
            // `;` closes the value if it is the end (`k=X;`, `k=X; Path=/`) or if what follows is
            // another `name=` (`;v=2`); `token=AB;RAWc3x` (a loose word after `;`) is value.
            if b == b';' && semicolon_ends_value(bytes, q + 1) {
                break;
            }
            // escaped quotes (`\"`) that close an escaped opening before the name
            if b == b'\\' && matches!(bytes.get(q + 1), Some(b'"' | b'\'')) {
                let code = 0x80 | bytes[q + 1];
                if stack.contains(&code) {
                    break;
                }
                q += 2;
                continue;
            }
            match b {
                b'(' | b'[' | b'{' | b'<' => {
                    if let Some(close) = closer_nearby(bytes, q) {
                        q = close + 1;
                        continue;
                    }
                }
                b'"' | b'\'' => {
                    if stack.contains(&b) {
                        break; // closes the opening before the name
                    }
                    if let Some(close) = closer_nearby(bytes, q) {
                        q = close + 1;
                        continue;
                    }
                }
                b')' | b']' | b'}' | b'>' => {
                    let open = match b {
                        b')' => b'(',
                        b']' => b'[',
                        b'}' => b'{',
                        _ => b'<',
                    };
                    if stack.contains(&open) {
                        break;
                    }
                }
                _ => {}
            }
            q += 1;
        }
        (vstart, q, q)
    }

    /// Decodes `[start, end)` ONCE and scans the result as the next level.
    fn decode_child(&mut self, level: &Level<'_>, start: usize, end: usize, depth: usize) {
        if depth >= MAX_LEVELS || end <= start {
            return;
        }
        let src = &level.bytes[start..end];
        if !src.contains(&b'%') || !has_escape(src) {
            return;
        }
        if src.len() > MAX_DECODE_BYTES && !level.dry {
            // Group above the work ceiling: we do not build position maps (8 bytes per
            // byte). We decode "dry" only to DECIDE: if some level has a sensitive name
            // (or if it cannot be decided: `%XX` remains at the ceiling), the whole group is
            // redacted (fail closed); otherwise it stays as it is.
            let before = self.edits.len();
            self.decode_child_inner(level, start, end, depth, true);
            let produced = self.edits.len() > before;
            self.edits.truncate(before);
            if produced {
                self.push(level, start, end, Repl::Param);
            }
            return;
        }
        self.decode_child_inner(level, start, end, depth, level.dry);
    }

    fn decode_child_inner(
        &mut self,
        level: &Level<'_>,
        start: usize,
        end: usize,
        depth: usize,
        dry: bool,
    ) {
        let mut child = decode_level(level, start, end, dry);
        if depth + 1 >= MAX_LEVELS {
            // Level ceiling: decode until stable (with a limit) and scan one
            // last time in closed mode (the value runs to the end of the level).
            for _ in 0..FIXPOINT_ROUNDS {
                if !has_escape(&child.bytes) {
                    break;
                }
                let whole = child.bytes.len();
                child = decode_level(&child, 0, whole, dry);
            }
            if has_escape(&child.bytes) {
                self.push(level, start, end, Repl::Param);
                return;
            }
            let was = std::mem::replace(&mut self.closed, true);
            self.scan_level(&child, MAX_LEVELS);
            self.closed = was;
            return;
        }
        self.scan_level(&child, depth + 1);
    }

    /// Is the effective name of `part` sensitive?
    fn is_sensitive_part(&mut self, part: &[u8]) -> bool {
        let tail = last_segment(part);
        if tail.is_empty() {
            return false;
        }
        if let Some(known) = self.names.get(tail) {
            return *known;
        }
        let result = {
            let name: Cow<str> = if tail.contains(&b'%') {
                let decoded = decode_once(tail);
                let decoded = last_segment(&decoded).to_vec();
                Cow::Owned(String::from_utf8_lossy(&decoded).trim().to_string())
            } else {
                String::from_utf8_lossy(tail)
            };
            let name = name.trim();
            // Long names are also examined (fail closed): `aaaa…token=X` is
            // `token`; only the cache is restricted to short names.
            !name.is_empty()
                && (is_sensitive_key(name) || is_business_key(name, &self.options.business_fields))
        };
        if tail.len() <= MAX_NAME_LEN {
            if self.names.len() >= NAME_CACHE_CAP {
                self.names.clear();
            }
            self.names.insert(tail.to_vec(), result);
        }
        result
    }

    /// `scheme://user:password@host`, `scheme:/\\user@host` and `//user:password@host`
    /// (authority after `:` + slashes, or after `//` at the start or after a
    /// delimiter): the userinfo is redacted.
    fn find_userinfo(&mut self, level: &Level<'_>) {
        let bytes: &[u8] = &level.bytes;
        let is_slash = |b: u8| b == b'/' || b == b'\\';
        let mut i = 0;
        while i < bytes.len() {
            if !is_slash(bytes[i]) {
                i += 1;
                continue;
            }
            let run_start = i;
            while i < bytes.len() && is_slash(bytes[i]) {
                i += 1;
            }
            let run_len = i - run_start;
            let prev = run_start.checked_sub(1).map(|p| bytes[p]);
            let after_scheme = prev == Some(b':')
                && run_start >= 2
                && bytes[run_start - 2].is_ascii_alphanumeric();
            let opens = run_len >= 2
                && (prev.is_none()
                    || prev.is_some_and(|p| {
                        is_space(p)
                            || matches!(
                                p,
                                b':' | b'='
                                    | b'"'
                                    | b'\''
                                    | b'('
                                    | b'['
                                    | b'{'
                                    | b'<'
                                    | b','
                                    | b';'
                                    | b'|'
                                    | b'&'
                                    | b'?'
                            )
                    }));
            if !after_scheme && !opens {
                continue;
            }
            let auth_start = i;
            let auth_end = bytes[auth_start..]
                .iter()
                .position(|b| {
                    is_space(*b)
                        || matches!(b, b'/' | b'\\' | b'?' | b'#' | b'"' | b'\'' | b'<' | b'>')
                })
                .map_or(bytes.len(), |n| auth_start + n);
            if let Some(at_sign) = bytes[auth_start..auth_end].iter().rposition(|b| *b == b'@') {
                self.push(level, auth_start, auth_start + at_sign, Repl::Param);
            }
            i = auth_end.max(auth_start);
        }
    }

    /// `Bearer <cred>` / `Basic <cred>` in any case and with any whitespace;
    /// only when what follows looks like a credential.
    fn find_auth(&mut self, level: &Level<'_>, depth: usize) {
        let bytes: &[u8] = &level.bytes;
        let mut pos = 0;
        while pos < bytes.len() {
            let scheme_len = if bytes[pos..].len() >= 6
                && bytes[pos..pos + 6].eq_ignore_ascii_case(b"bearer")
            {
                6
            } else if bytes[pos..].len() >= 5 && bytes[pos..pos + 5].eq_ignore_ascii_case(b"basic")
            {
                5
            } else {
                pos += 1;
                continue;
            };
            let before_ok =
                pos == 0 || !(bytes[pos - 1].is_ascii_alphanumeric() || bytes[pos - 1] == b'_');
            let after = pos + scheme_len;
            let mut cred_start = after;
            loop {
                let len = space_len_at(bytes, cred_start);
                if len == 0 {
                    break;
                }
                cred_start += len;
            }
            if !before_ok || cred_start == after {
                pos = after;
                continue;
            }
            let cred_end = bytes[cred_start..]
                .iter()
                .position(|b| !is_cred_char(*b))
                .map_or(bytes.len(), |n| cred_start + n);
            let cred = &bytes[cred_start..cred_end];
            let param = self.param().as_bytes();
            let already_redacted = cred.windows(param.len()).any(|w| w == param)
                || cred.starts_with(self.options.placeholder.as_bytes());
            if cred.len() >= 4
                && looks_like_credential(cred)
                && !already_redacted
                && !cred.starts_with(b"//")
                && !cred.starts_with(b":")
            {
                // replaces from the first position after the scheme up to the end of the credential
                let (start, end) = level.range(after, cred_end);
                self.edits.push(Edit {
                    start,
                    end,
                    repl: if depth == 0 {
                        Repl::Auth
                    } else {
                        Repl::AuthEnc
                    },
                });
            }
            pos = cred_end.max(after);
        }
    }

    fn apply(&mut self, text: &str) -> String {
        self.edits
            .sort_by_key(|e| (e.start, std::cmp::Reverse(e.end)));
        let param = self.param().to_string();
        let mut out = String::with_capacity(text.len() + 16);
        let mut copied = 0;
        for edit in &self.edits {
            if edit.start < copied {
                // overlaps a previous edit: only extends the covered range
                if edit.end > copied && text.is_char_boundary(edit.end) {
                    copied = edit.end;
                }
                continue;
            }
            // do not cut in the middle of a UTF-8 character
            if !text.is_char_boundary(edit.start) || !text.is_char_boundary(edit.end) {
                continue;
            }
            out.push_str(&text[copied..edit.start]);
            match edit.repl {
                Repl::Param => out.push_str(&param),
                Repl::Auth => {
                    out.push(' ');
                    out.push_str(&self.options.placeholder);
                }
                Repl::AuthEnc => {
                    out.push_str("%20");
                    out.push_str(&param);
                }
            }
            copied = edit.end;
        }
        out.push_str(&text[copied..]);
        out
    }
}

/// Updates the stack of openings with the delimiter at `bytes[pos]`; returns
/// how many bytes it consumed (2 for escaped quotes `\\\"`).
fn track_enclosing(bytes: &[u8], pos: usize, stack: &mut Vec<u8>) -> usize {
    let toggle = |stack: &mut Vec<u8>, code: u8| {
        if stack.last() == Some(&code) {
            stack.pop();
        } else if stack.len() < 64 {
            stack.push(code);
        }
    };
    match bytes[pos] {
        b'\\' if matches!(bytes.get(pos + 1), Some(b'"' | b'\'')) => {
            toggle(stack, 0x80 | bytes[pos + 1]);
            return 2;
        }
        quote @ (b'"' | b'\'') => toggle(stack, quote),
        open @ (b'(' | b'[' | b'{' | b'<') if stack.len() < 64 => stack.push(open),
        close @ (b')' | b']' | b'}' | b'>') => {
            let open = match close {
                b')' => b'(',
                b']' => b'[',
                b'}' => b'{',
                _ => b'<',
            };
            if stack.last() == Some(&open) {
                stack.pop();
            }
        }
        _ => {}
    }
    1
}

/// Does `;` at `bytes[at - 1]` end the value? Yes at the end, before a delimiter or
/// before `name=`; not before a loose word.
fn semicolon_ends_value(bytes: &[u8], at: usize) -> bool {
    let Some(&first) = bytes.get(at) else {
        return true;
    };
    if is_hard(first) {
        return true;
    }
    let word = bytes[at..]
        .iter()
        .position(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'%')))
        .unwrap_or(bytes.len() - at);
    bytes.get(at + word) == Some(&b'=')
}

/// Is the name in `bytes[part_start..eq]` in a PATH (segment `/name=value/` or
/// matrix parameter `;name=value` after a token with `/`)? Then the value of a
/// SENSITIVE name runs up to the next `?` (`#` and `&` already end it) or the end, `/` included:
/// a credential may contain `/` and there is no way to know where it ends (A8-M1). This
/// costs the rest of the path (`/a;v=2/session=keep/b` → `/a;v=2/session=[REDACTED]`),
/// an accepted limitation (A7-B5): security takes precedence over fidelity. In a query
/// value (`?token=ab/cd`) or a bare value the value runs up to the space.
fn path_context(bytes: &[u8], group_start: usize, part_start: usize, eq: usize) -> bool {
    let part = &bytes[part_start..eq];
    if let Some(last_slash) = part.iter().rposition(|b| *b == b'/') {
        let last_query = part.iter().rposition(|b| *b == b'?');
        return last_query.map_or(true, |q| q < last_slash);
    }
    if part_start != group_start {
        return false;
    }
    // matrix: the group starts right after `;` and one of the `;`-chained groups
    // before it (up to a delimiter other than `;`) contains `/`
    let mut pos = group_start;
    while pos > 0 && bytes[pos - 1] == b';' {
        let mut j = pos - 1;
        while j > 0 && !is_hard(bytes[j - 1]) {
            j -= 1;
        }
        if bytes[j..pos - 1].contains(&b'/') {
            return true;
        }
        pos = j;
    }
    false
}

/// Closing of the opening at `bytes[at]` (`( [ { <`, quotes) within 64 bytes and
/// without crossing a line break; `None` if there is none. Nesting of the same
/// kind is respected; quotes honor `\\` como escape.
fn closer_nearby(bytes: &[u8], at: usize) -> Option<usize> {
    const WINDOW: usize = 64;
    let open = bytes[at];
    let end = bytes.len().min(at + 1 + WINDOW);
    if matches!(open, b'"' | b'\'') {
        let mut i = at + 1;
        while i < end && bytes[i] != b'\n' {
            if bytes[i] == b'\\' {
                i += 2;
                continue;
            }
            if bytes[i] == open {
                return Some(i);
            }
            i += 1;
        }
        return None;
    }
    let closer = match open {
        b'(' => b')',
        b'[' => b']',
        b'{' => b'}',
        _ => b'>',
    };
    let mut nest = 1usize;
    for (i, &c) in bytes.iter().enumerate().take(end).skip(at + 1) {
        if c == b'\n' {
            return None;
        }
        if c == open {
            nest += 1;
        } else if c == closer {
            nest -= 1;
            if nest == 0 {
                return Some(i);
            }
        }
    }
    None
}

/// Byte that continues a value after a closing/placeholder: anything that is not
/// a delimiter nor `/` or `?` (which start the rest of a path/URL).
#[inline]
fn is_tail_byte(byte: u8) -> bool {
    !is_hard(byte) && !matches!(byte, b'/' | b'?' | b'=')
}

/// Does `bytes[at..]` start with `=` (or `＝`)?
fn starts_with_equals(bytes: &[u8], at: usize) -> bool {
    matches!(find_equals(bytes, at, (at + 3).min(bytes.len())), Some((pos, _)) if pos == at)
}

/// Next `=` (or `＝` fullwidth U+FF1D) in `bytes[from..to]`: (position, length).
fn find_equals(bytes: &[u8], from: usize, to: usize) -> Option<(usize, usize)> {
    let mut i = from;
    while i < to {
        match bytes[i] {
            b'=' => return Some((i, 1)),
            0xEF if i + 2 < bytes.len() && bytes[i + 1] == 0xBC && bytes[i + 2] == 0x9D => {
                return Some((i, 3))
            }
            _ => i += 1,
        }
    }
    None
}

/// HTML escape layers of `&` examined before failing closed.
const MAX_AMP_LAYERS: usize = 256;

#[derive(PartialEq, Eq)]
enum Entity {
    Equals,
    Ampersand,
}

/// An HTML entity at the start of `rest`: `&equals;`, `&#61;`/`&#x3D;` (any leading zeros,
/// `;` optional) → equals; `&amp;`, `&#38;`/`&#x26;` → `&` (another escape layer).
/// After a layer, the initial `&` is optional (`&amp;amp;#61;`, `&#38;#61;`).
fn parse_entity(rest: &[u8], amp_optional: bool) -> Option<(Entity, usize)> {
    let lead = usize::from(rest.first() == Some(&b'&'));
    if lead == 0 && !amp_optional {
        return None;
    }
    let body = &rest[lead..];
    if body.len() >= 7 && body[..7].eq_ignore_ascii_case(b"equals;") {
        return Some((Entity::Equals, lead + 7));
    }
    if body.len() >= 4 && body[..4].eq_ignore_ascii_case(b"amp;") {
        return Some((Entity::Ampersand, lead + 4));
    }
    if body.first() == Some(&b'#') {
        let (radix, digits_at) = match body.get(1) {
            Some(b'x' | b'X') => (16, 2),
            _ => (10, 1),
        };
        let mut j = digits_at;
        let mut value: u32 = 0;
        while j < body.len() && j - digits_at < 12 {
            let Some(d) = (body[j] as char).to_digit(radix) else {
                break;
            };
            value = value.saturating_mul(radix).saturating_add(d);
            j += 1;
        }
        if j > digits_at && matches!(value, 0x3D | 0x26) {
            if body.get(j) == Some(&b';') {
                j += 1;
            }
            let kind = if value == 0x3D {
                Entity::Equals
            } else {
                Entity::Ampersand
            };
            return Some((kind, lead + j));
        }
    }
    None
}

/// Length of an "equals" in `bytes[at..]`: `=`, `＝`, `&equals;`, `&#61;`, `&#0061;`,
/// `&#x3D;`, `&#X003d;` (`;` optional) and any of them escaped again, in as many
/// layers as there are (`&amp;#61;`, `&amp;amp;equals;`, `&#38;#61;`, `&amp;&#38;&#x3D;`...).
/// Above [`MAX_AMP_LAYERS`] layers it fails closed: treated as "equals".
fn equals_len_at(bytes: &[u8], at: usize) -> Option<usize> {
    let rest = bytes.get(at..)?;
    match rest.first()? {
        b'=' => Some(1),
        0xEF if rest.len() >= 3 && rest[1] == 0xBC && rest[2] == 0x9D => Some(3),
        b'&' => {
            let mut pos = 0;
            for layer in 0..=MAX_AMP_LAYERS {
                match parse_entity(&rest[pos..], layer > 0)? {
                    (Entity::Equals, len) => return Some(pos + len),
                    (Entity::Ampersand, len) => pos += len,
                }
            }
            Some(pos)
        }
        _ => None,
    }
}

/// Last segment after a name separator (`? / & # ; , | =`).
fn last_segment(part: &[u8]) -> &[u8] {
    let start = part
        .iter()
        .rposition(|b| matches!(b, b'?' | b'/' | b'&' | b'#' | b';' | b',' | b'|' | b'='))
        .map_or(0, |i| i + 1);
    &part[start..]
}

/// Percent-decode of one round (`+` stays `+`).
fn decode_once(src: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len());
    let mut i = 0;
    while i < src.len() {
        if src[i] == b'%' && i + 2 < src.len() {
            if let (Some(h), Some(l)) = (hex(src[i + 1]), hex(src[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(src[i]);
        i += 1;
    }
    out
}

/// Length of the whitespace (ASCII or Unicode) at `bytes[at..]`, or 0.
fn space_len_at(bytes: &[u8], at: usize) -> usize {
    match bytes.get(at) {
        Some(b) if is_space(*b) => 1,
        Some(b) if *b >= 0x80 => {
            let chunk = &bytes[at..bytes.len().min(at + 4)];
            for len in 2..=chunk.len().min(4) {
                if let Ok(text) = std::str::from_utf8(&chunk[..len]) {
                    return match text.chars().next() {
                        Some(ch) if ch.is_whitespace() => len,
                        _ => 0,
                    };
                }
            }
            0
        }
        _ => 0,
    }
}

fn is_cred_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-' | b'%' | b':'
        )
}

/// Digit, symbol, uppercase after the first letter, or 16+ characters: does not
/// erase prose such as "Basic authentication".
fn looks_like_credential(cred: &[u8]) -> bool {
    cred.len() >= 16
        || cred.iter().any(|c| {
            c.is_ascii_digit()
                || matches!(
                    c,
                    b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-' | b'%' | b':'
                )
        })
        || cred.iter().skip(1).any(|c| c.is_ascii_uppercase())
}
