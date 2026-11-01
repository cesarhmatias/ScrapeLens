//! Redação estrutural de segredos em texto livre (valores de header, linha de
//! requisição, notas, mensagens, strings de JSON, valores de parâmetro).
//!
//! O texto é tratado em **níveis**. Em cada nível:
//!
//! 1. Separa-se por delimitadores CRUS daquele nível (espaço em branco, aspas,
//!    parênteses, colchetes, `, | \ & # ;`), formando *grupos*. `? / =` e `:` ficam
//!    dentro do grupo: delimitam nomes, não valores.
//! 2. Dentro do grupo, cada `=` crú fecha um nome (`parte`). Se o **nome efetivo**
//!    da parte é sensível, o valor (até o fim do grupo, ou até o fechamento de
//!    aspas/parênteses, ou o próximo grupo se há espaço depois do `=`) é redigido.
//!    O nome efetivo é o último segmento da parte depois de `? / & # ; , | =`,
//!    com percent-decode de UMA rodada.
//! 3. O grupo inteiro é decodificado UMA vez (`%XX`; `+` fica `+`) e vira o nível
//!    seguinte. Um separador que só aparece depois da decodificação pertence ao
//!    nível de baixo e nunca encerra um valor do nível atual: `%2B`, `%2520`,
//!    `%2526` e `%2523` não cortam uma credencial base64.
//!
//! Cada nível só produz *edições* (intervalos no texto ORIGINAL, via um mapa de
//! posições dos bytes decodificados); o texto sai de uma única aplicação das
//! edições, então nada que não foi redigido é reescrito (nem recodificado).
//! Custo: uma passada de varredura por nível + uma de aplicação; a decodificação
//! só acontece em grupos que contêm `%XX` válido, e a profundidade é limitada.

use std::borrow::Cow;
use std::collections::HashMap;

use super::sanitize::{is_business_key, is_sensitive_key, url_placeholder, SanitizeOptions};

/// Níveis de decodificação examinados (0 = o texto como veio).
const MAX_LEVELS: usize = 8;
/// Nomes mais longos que isto nunca são credenciais conhecidas.
const MAX_NAME_LEN: usize = 128;
/// Entradas do cache de nomes; ao estourar, o cache é esvaziado.
const NAME_CACHE_CAP: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Repl {
    /// Valor de parâmetro: placeholder percent-encoded (`%5BREDACTED%5D`).
    Param,
    /// Credencial depois de um esquema (`Bearer`): ` [REDACTED]` no nível 0.
    Auth,
}

struct Edit {
    start: usize,
    end: usize,
    repl: Repl,
}

/// Um nível: bytes do texto (decodificados, a partir do nível 1) e, para cada
/// byte, o intervalo correspondente no texto original.
struct Level<'a> {
    bytes: Cow<'a, [u8]>,
    map: Option<Vec<(u32, u32)>>,
}

impl Level<'_> {
    fn orig(&self, index: usize) -> (usize, usize) {
        match &self.map {
            Some(map) => (map[index].0 as usize, map[index].1 as usize),
            None => (index, index + 1),
        }
    }

    /// `[start, end)` deste nível → intervalo no texto original.
    fn range(&self, start: usize, end: usize) -> (usize, usize) {
        (self.orig(start).0, self.orig(end - 1).1)
    }
}

struct Scrubber<'a> {
    options: &'a SanitizeOptions,
    edits: Vec<Edit>,
    names: HashMap<Vec<u8>, bool>,
    param: String,
}

/// Aplica as regras ao texto. `None` quando nada mudou.
pub(super) fn scrub(text: &str, options: &SanitizeOptions) -> Option<String> {
    if !text.contains(['=', '%', '@']) && !has_scheme_word(text.as_bytes()) {
        return None;
    }
    let mut scrubber = Scrubber {
        options,
        edits: Vec::new(),
        names: HashMap::new(),
        param: url_placeholder(options),
    };
    let level = Level {
        bytes: Cow::Borrowed(text.as_bytes()),
        map: None,
    };
    scrubber.scan_level(&level, 0);
    if scrubber.edits.is_empty() {
        return None;
    }
    Some(scrubber.apply(text))
}

fn has_scheme_word(bytes: &[u8]) -> bool {
    bytes.windows(5).any(|w| w.eq_ignore_ascii_case(b"basic"))
        || bytes.windows(6).any(|w| w.eq_ignore_ascii_case(b"bearer"))
}

#[inline]
fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

/// Delimitadores crus que encerram um grupo.
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

/// Rodadas extras de decodificação ao chegar no teto de níveis.
const FIXPOINT_ROUNDS: usize = 24;

/// Decodifica `[start, end)` de `level` (`%XX`; `+` fica `+`), com o mapa de
/// volta às posições do texto original.
fn decode_level(level: &Level<'_>, start: usize, end: usize) -> Level<'static> {
    let src = &level.bytes[start..end];
    let mut bytes = Vec::with_capacity(src.len());
    let mut map: Vec<(u32, u32)> = Vec::with_capacity(src.len());
    let mut i = 0;
    while i < src.len() {
        if src[i] == b'%' && i + 2 < src.len() {
            if let (Some(h), Some(l)) = (hex(src[i + 1]), hex(src[i + 2])) {
                bytes.push(h * 16 + l);
                let (a, _) = level.orig(start + i);
                let (_, b) = level.orig(start + i + 2);
                map.push((a as u32, b as u32));
                i += 3;
                continue;
            }
        }
        bytes.push(src[i]);
        let (a, b) = level.orig(start + i);
        map.push((a as u32, b as u32));
        i += 1;
    }
    Level {
        bytes: Cow::Owned(bytes),
        map: Some(map),
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

/// Existe `%XX` válido?
fn has_escape(bytes: &[u8]) -> bool {
    bytes
        .windows(3)
        .any(|w| w[0] == b'%' && hex(w[1]).is_some() && hex(w[2]).is_some())
}

impl Scrubber<'_> {
    /// O trecho já é o placeholder (ou o miolo dele entre colchetes)? Mantém a
    /// redação idempotente: sanitizar duas vezes não empilha placeholders.
    fn is_placeholder(&self, level: &Level<'_>, start: usize, end: usize) -> bool {
        let slice = &level.bytes[start..end];
        let placeholder = self.options.placeholder.as_bytes();
        if slice == placeholder || slice == self.param.as_bytes() {
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
        let mut pos = 0;
        while pos < bytes.len() {
            if is_hard(bytes[pos]) {
                pos += 1;
                continue;
            }
            let end = bytes[pos..]
                .iter()
                .position(|b| is_hard(*b))
                .map_or(bytes.len(), |n| pos + n);
            pos = self.scan_group(level, pos, end, depth).max(end);
        }
    }

    /// Um grupo `[start, end)`; devolve onde a varredura continua (além de `end`
    /// quando o valor redigido tomou aspas/parênteses ou o grupo seguinte).
    fn scan_group(&mut self, level: &Level<'_>, start: usize, end: usize, depth: usize) -> usize {
        let bytes: &[u8] = &level.bytes;
        let group = &bytes[start..end];
        let mut part_start = start;
        let mut cursor = start;
        while let Some(offset) = group[cursor - start..].iter().position(|b| *b == b'=') {
            let eq = cursor + offset;
            if self.is_sensitive_part(&bytes[part_start..eq]) {
                let (value_start, value_end, next) = value_extent(bytes, eq + 1, end);
                self.push(level, value_start, value_end, Repl::Param);
                // o que veio ANTES do nome ainda pode carregar segredo codificado
                self.decode_child(level, start, eq, depth);
                return next;
            }
            part_start = eq + 1;
            cursor = eq + 1;
            if cursor >= end {
                break;
            }
        }
        // `token =valor` / `token = valor`: espaço antes do `=`.
        let mut look = end;
        while look < bytes.len() && matches!(bytes[look], b' ' | b'\t') {
            look += 1;
        }
        if look > end
            && look < bytes.len()
            && bytes[look] == b'='
            && self.is_sensitive_part(&bytes[part_start..end])
        {
            let (value_start, value_end, next) = value_extent(bytes, look + 1, look + 1);
            self.push(level, value_start, value_end, Repl::Param);
            self.decode_child(level, start, end, depth);
            return next;
        }
        self.decode_child(level, start, end, depth);
        end
    }

    /// Decodifica `[start, end)` UMA vez e varre o resultado como o nível seguinte.
    fn decode_child(&mut self, level: &Level<'_>, start: usize, end: usize, depth: usize) {
        if depth >= MAX_LEVELS {
            return;
        }
        let src = &level.bytes[start..end];
        if !src.contains(&b'%') || !has_escape(src) {
            return;
        }
        let mut child = decode_level(level, start, end);
        if depth + 1 >= MAX_LEVELS {
            // Teto de níveis: decodifica até estabilizar (com limite) e varre uma
            // última vez, sem descer mais.
            for _ in 0..FIXPOINT_ROUNDS {
                if !has_escape(&child.bytes) {
                    break;
                }
                let whole = child.bytes.len();
                child = decode_level(&child, 0, whole);
            }
            self.scan_level(&child, MAX_LEVELS);
            return;
        }
        self.scan_level(&child, depth + 1);
    }

    /// O nome efetivo de `part` é sensível?
    fn is_sensitive_part(&mut self, part: &[u8]) -> bool {
        let tail = last_segment(part);
        if tail.is_empty() || tail.len() > MAX_NAME_LEN * 3 {
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
            !name.is_empty()
                && name.len() <= MAX_NAME_LEN
                && (is_sensitive_key(name) || is_business_key(name, &self.options.business_fields))
        };
        if self.names.len() >= NAME_CACHE_CAP {
            self.names.clear();
        }
        self.names.insert(tail.to_vec(), result);
        result
    }

    /// `esquema://usuario:senha@host`: o userinfo é redigido.
    fn find_userinfo(&mut self, level: &Level<'_>) {
        let bytes: &[u8] = &level.bytes;
        let mut pos = 0;
        while let Some(at) = find(bytes, b"://", pos) {
            let auth_start = at + 3;
            let auth_end = bytes[auth_start..]
                .iter()
                .position(|b| {
                    is_space(*b) || matches!(b, b'/' | b'?' | b'#' | b'"' | b'\'' | b'<' | b'>')
                })
                .map_or(bytes.len(), |n| auth_start + n);
            if let Some(at_sign) = bytes[auth_start..auth_end].iter().rposition(|b| *b == b'@') {
                self.push(level, auth_start, auth_start + at_sign, Repl::Param);
            }
            pos = auth_end.max(auth_start);
        }
    }

    /// `Bearer <cred>` / `Basic <cred>` em qualquer caixa e com qualquer espaço
    /// em branco; só quando o que segue parece credencial.
    fn find_auth(&mut self, level: &Level<'_>, _depth: usize) {
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
            while cred_start < bytes.len() && is_space(bytes[cred_start]) {
                cred_start += 1;
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
            if cred.len() >= 4 && looks_like_credential(cred) {
                // substitui da primeira posição depois do esquema até o fim da credencial
                let (start, end) = level.range(after, cred_end);
                self.edits.push(Edit {
                    start,
                    end,
                    repl: Repl::Auth,
                });
            }
            pos = cred_end.max(after);
        }
    }

    fn apply(&mut self, text: &str) -> String {
        self.edits
            .sort_by_key(|e| (e.start, std::cmp::Reverse(e.end)));
        let param = self.param.clone();
        let mut out = String::with_capacity(text.len() + 16);
        let mut copied = 0;
        for edit in &self.edits {
            if edit.start < copied {
                // sobreposta a uma edição anterior: só estende o intervalo coberto
                if edit.end > copied && text.is_char_boundary(edit.end) {
                    copied = edit.end;
                }
                continue;
            }
            // não corta no meio de um caractere UTF-8
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
            }
            copied = edit.end;
        }
        out.push_str(&text[copied..]);
        out
    }
}

/// Fim do valor de um nome sensível cujo `=` está antes de `vstart`.
/// Devolve (início, fim, onde a varredura continua).
fn value_extent(bytes: &[u8], vstart: usize, group_end: usize) -> (usize, usize, usize) {
    if vstart < group_end {
        // valor colado ao `=`: vai até o fim do grupo
        return (vstart, group_end, group_end);
    }
    // `=` é o último byte do grupo; o que vem depois é um delimitador
    let mut p = vstart;
    while p < bytes.len() && matches!(bytes[p], b' ' | b'\t') {
        p += 1;
    }
    if p >= bytes.len() {
        return (p, p, p);
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
            let close = q.min(bytes.len());
            (
                p + 1,
                close,
                if close < bytes.len() && bytes[close] == quote {
                    close + 1
                } else {
                    close
                },
            )
        }
        open @ (b'(' | b'[' | b'{' | b'<') => {
            let closer = match open {
                b'(' => b')',
                b'[' => b']',
                b'{' => b'}',
                _ => b'>',
            };
            let mut depth = 1usize;
            let mut q = p + 1;
            while q < bytes.len() && bytes[q] != b'\n' {
                if bytes[q] == open {
                    depth += 1;
                } else if bytes[q] == closer {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                q += 1;
            }
            let close = q.min(bytes.len());
            (
                p + 1,
                close,
                if close < bytes.len() && bytes[close] == closer {
                    close + 1
                } else {
                    close
                },
            )
        }
        b if !is_hard(b) => {
            let end = bytes[p..]
                .iter()
                .position(|c| is_hard(*c))
                .map_or(bytes.len(), |n| p + n);
            (p, end, end)
        }
        _ => (vstart, vstart, vstart),
    }
}

/// Último segmento depois de um separador de nome (`? / & # ; , | =`).
fn last_segment(part: &[u8]) -> &[u8] {
    let start = part
        .iter()
        .rposition(|b| matches!(b, b'?' | b'/' | b'&' | b'#' | b';' | b',' | b'|' | b'='))
        .map_or(0, |i| i + 1);
    &part[start..]
}

/// Percent-decode de uma rodada (`+` fica `+`).
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

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|n| from + n)
}

fn is_cred_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-')
}

/// Dígito, símbolo, maiúscula depois da primeira letra ou 16+ caracteres: não
/// apaga prosa como "Basic authentication".
fn looks_like_credential(cred: &[u8]) -> bool {
    cred.len() >= 16
        || cred.iter().any(|c| {
            c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-')
        })
        || cred.iter().skip(1).any(|c| c.is_ascii_uppercase())
}
