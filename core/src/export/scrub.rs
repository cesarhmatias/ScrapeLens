//! Redação estrutural de segredos em texto livre (valores de header, linha de
//! requisição, notas, mensagens, strings de JSON, valores de parâmetro).
//!
//! O texto é tratado em **níveis**. Em cada nível:
//!
//! 1. Separa-se por delimitadores CRUS daquele nível (espaço em branco, aspas,
//!    parênteses, colchetes, `, | \ & # ;`), formando *grupos*. `? / =` e `:` ficam
//!    dentro do grupo: delimitam nomes, não valores.
//! 2. Dentro do grupo, cada `=` cru fecha um nome (`parte`). Se o **nome efetivo**
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
//!
//! # Extensão do valor
//!
//! - Nível 0: o valor vai até espaço ou `& #`; `;` só o fecha no fim ou antes de
//!   `nome=`. Níveis decodificados (1+): o espaço veio de `%XX` do mesmo valor e não
//!   o fecha. `, ( ) [ ] { } | " ' \ < >` fazem parte do valor, exceto o fechamento
//!   de uma abertura ANTERIOR ao nome (`{token=X}`); aberturas dentro do valor com
//!   fechamento por perto são puladas inteiras.
//! - Em CAMINHO (`/seg=valor/`, `;param=valor` depois de um token com `/`) o valor
//!   acaba em `/` ou `?` (o resto do caminho segue examinado), salvo base64 com barra.
//! - Aspas/colchetes após `=`: o interior é o valor; texto ou outra abertura COLADA
//!   depois do fechamento (`"a"X`, `[a][X]`, `'a'"X`) também é valor.
//! - Valor que começa pelo placeholder já foi redigido (idempotência).
//!
//! # Falhar fechado
//!
//! Sempre que não dá para decidir, redige-se o VALOR inteiro que sobra em vez de
//! deixar a cauda crua: (1) no teto de 8 níveis o texto é decodificado até estabilizar
//! e varrido em modo fechado (o valor vai até o fim do nível; se ainda sobra `%XX`, o
//! grupo inteiro é redigido); (2) byte inválido/overlong logo depois de um nome
//! sensível redige o resto do grupo; (3) GRUPO ACIMA DE 1 MiB com `%XX`: não se montam
//! mapas de posição; decodifica-se "a seco" (só os bytes) para DECIDIR, e o grupo é
//! redigido por inteiro SÓ se algum nível tem um nome sensível ou se não dá para decidir
//! (sobra `%XX` no teto); sem nome sensível o grupo passa intacto.

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
    /// O mesmo, dentro de um nível decodificado: `%20%5BREDACTED%5D`.
    AuthEnc,
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
    /// Nível "a seco" (grupo acima do teto de trabalho): sem mapa de posições, só para
    /// DECIDIR se há nome sensível; as edições que ele produz são descartadas.
    dry: bool,
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

pub(super) struct Scrubber<'a> {
    options: &'a SanitizeOptions,
    edits: Vec<Edit>,
    names: HashMap<Vec<u8>, bool>,
    param: std::cell::OnceCell<String>,
    /// Modo "falhar fechado": ao bater no teto de níveis, o valor de um nome
    /// sensível vai até o fim do nível inteiro (não sabemos mais quais
    /// separadores pertencem ao valor).
    closed: bool,
}

/// Aplica as regras ao texto. `None` quando nada mudou.
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

    /// Varre `text`; o cache de nomes sensíveis é reaproveitado entre chamadas
    /// (consulta com milhões de pares). `None` quando nada mudou.
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
/// Teto de trabalho por grupo: acima disto o grupo (se tiver `%XX`) não é
/// decodificado e é redigido inteiro (falha fechada), o que também limita a
/// memória dos mapas de posição (8 bytes por byte decodificado).
const MAX_DECODE_BYTES: usize = 1 << 20;

/// Decodifica `[start, end)` de `level` (`%XX`; `+` fica `+`), com o mapa de
/// volta às posições do texto original.
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

/// Existe `%XX` válido?
fn has_escape(bytes: &[u8]) -> bool {
    bytes
        .windows(3)
        .any(|w| w[0] == b'%' && hex(w[1]).is_some() && hex(w[2]).is_some())
}

impl Scrubber<'_> {
    fn param(&self) -> &str {
        self.param.get_or_init(|| url_placeholder(self.options))
    }

    /// O trecho já é o placeholder (ou o miolo dele entre colchetes)? Mantém a
    /// redação idempotente: sanitizar duas vezes não empilha placeholders.
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
        // Aberturas (aspas, parênteses, colchetes) ainda não fechadas: o valor de um
        // nome sensível termina no fechamento de qualquer uma delas.
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
                // o trecho pulado era valor redigido; as aberturas dele não contam
                stack.clear();
            }
            pos = next;
        }
    }

    /// Um grupo `[start, end)`; devolve onde a varredura continua (além de `end`
    /// quando o valor redigido tomou aspas/colchetes ou o grupo seguinte).
    fn scan_group(
        &mut self,
        level: &Level<'_>,
        start: usize,
        end: usize,
        depth: usize,
        stack: &[u8],
    ) -> usize {
        let bytes: &[u8] = &level.bytes;
        // `seg_start`: início do trecho ainda não decodificado/examinado;
        // `part_start`: início do nome corrente.
        let mut seg_start = start;
        let mut part_start = start;
        let mut cursor = start;
        while cursor < end {
            let Some((eq, eq_len)) = find_equals(bytes, cursor, end) else {
                break;
            };
            if self.is_sensitive_part(&bytes[part_start..eq]) {
                // o que veio ANTES do nome ainda pode carregar segredo codificado
                self.decode_child(level, seg_start, eq, depth);
                let slash_ends = path_context(bytes, start, part_start, eq);
                let next = self.redact_value(level, eq + eq_len, end, depth, stack, slash_ends);
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
        // Em níveis decodificados, um byte que não é UTF-8 válido logo depois de um nome
        // sensível (`token%C0%BDvalor`: `=` em codificação "overlong") é um separador que
        // não sabemos classificar: falha fechada, o resto do grupo é valor.
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
        // espaço e/ou entidade HTML entre o nome e o valor.
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

    /// Redige o valor que começa em `vstart` (depois do `=`) e devolve onde a
    /// varredura continua. `group_end` é o fim do grupo do nome.
    fn redact_value(
        &mut self,
        level: &Level<'_>,
        vstart: usize,
        group_end: usize,
        depth: usize,
        stack: &[u8],
        slash_ends: bool,
    ) -> usize {
        let bytes: &[u8] = &level.bytes;
        if self.closed {
            // Falha fechada: tudo que resta no nível é valor.
            self.push(level, vstart, bytes.len(), Repl::Param);
            return bytes.len();
        }
        let (value_start, value_end, next) =
            self.value_extent(bytes, vstart, group_end, depth, stack, slash_ends);
        self.push(level, value_start, value_end, Repl::Param);
        // Depois de um valor entre aspas/colchetes, o que vier COLADO ainda é valor:
        // texto (`token="abc"TAIL`, `[abc]TAIL`) ou outra abertura (`'a'"X`, `[a][X]`,
        // `"a"(X)`). Cada volta consome pelo menos um byte.
        let mut next = next;
        if next > value_end {
            while next < bytes.len() {
                let b = bytes[next];
                if is_tail_byte(b) {
                    let tail_end = bytes[next..]
                        .iter()
                        .position(|c| !is_tail_byte(*c))
                        .map_or(bytes.len(), |n| next + n);
                    // `TAIL=...` não é cauda: é o nome do próximo parâmetro.
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

    /// Onde termina o valor de um nome sensível cujo `=` está antes de `vstart`.
    /// Devolve (início, fim, onde a varredura continua).
    fn value_extent(
        &self,
        bytes: &[u8],
        vstart: usize,
        group_end: usize,
        depth: usize,
        stack: &[u8],
        slash_ends: bool,
    ) -> (usize, usize, usize) {
        if vstart < group_end {
            return self.attached_extent(bytes, vstart, depth, stack, slash_ends);
        }
        // `=` é o último byte do grupo; o que vem depois é um delimitador ou fim
        let mut p = vstart;
        while p < bytes.len() && matches!(bytes[p], b' ' | b'\t') {
            p += 1;
        }
        if p >= bytes.len() {
            return (p, p, p);
        }
        // `token=&#61;X`: outro "igual" (entidade) colado ao primeiro; o valor vem depois.
        let mut after_equals = p;
        while let Some(n) = equals_len_at(bytes, after_equals) {
            after_equals += n;
        }
        if after_equals > p {
            return self.value_extent(bytes, after_equals, after_equals, depth, stack, false);
        }
        // `token=\X`: a barra invertida que não escapa aspas é só mais um byte do valor.
        if bytes[p] == b'\\' && !matches!(bytes.get(p + 1), Some(b'"' | b'\'')) {
            return self.attached_extent(bytes, p, depth, stack, false);
        }
        if bytes[p] == b'\\' && matches!(bytes.get(p + 1), Some(b'"' | b'\'')) {
            // `\"valor\"` (aspas escapadas, comuns em texto dentro de JSON)
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
                    // abertura sem fechamento: o valor vai até o próximo espaço
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

    /// Valor sem aspas. No nível 0 vai até espaço ou `& #`; em níveis
    /// decodificados (1+) o espaço veio de `%XX` do mesmo valor e não o encerra:
    /// só `& #`. (`;` não encerra: `token=AB;resto` é valor; `token=X; Path=/`
    /// continua preservando ` Path=/`.) Em ambos, `, ( ) < > [ ] { } | " ' \\` fazem parte do
    /// valor, exceto o fechamento de uma abertura ANTERIOR ao nome (`{token=X}`,
    /// `"token=X"`, `(token=X)`). Um valor que COMEÇA pelo placeholder já foi
    /// redigido: para depois dele se o que vem é `/ ?` ou delimitador
    /// (idempotência: `jsessionid=%5BREDACTED%5D/b/c?x=1`).
    fn attached_extent(
        &self,
        bytes: &[u8],
        vstart: usize,
        depth: usize,
        stack: &[u8],
        slash_ends: bool,
    ) -> (usize, usize, usize) {
        let rest = &bytes[vstart..];
        for placeholder in [self.options.placeholder.as_bytes(), self.param().as_bytes()] {
            if !placeholder.is_empty() && rest.starts_with(placeholder) {
                let after = vstart + placeholder.len();
                if after >= bytes.len() || !is_tail_byte(bytes[after]) {
                    return (vstart, vstart, after);
                }
                break; // placeholder com cauda colada: a cauda também é valor
            }
        }
        // Aberturas DENTRO do valor (`AB(c)X`, `AB[c d]X`, `AB'x y'Z`) com fechamento por
        // perto (até 64 bytes, na mesma linha) são puladas inteiras: o fechamento delas
        // é parte do valor e não confunde com o de uma abertura anterior ao nome. Sem
        // fechamento por perto, a abertura é só mais um byte do valor.
        let mut q = vstart;
        while q < bytes.len() {
            let b = bytes[q];
            if matches!(b, b'&' | b'#') {
                break;
            }
            // Em caminho (`/a;jsessionid=X/b`, `/s/session=X/b`) o valor acaba em `/` ou `?`:
            // o resto é o caminho/consulta, que segue sendo examinado.
            if slash_ends && b == b'?' {
                break;
            }
            // `/` acaba o valor num caminho, a menos que o credencial pareça base64 com
            // barra (`AAA+x/yyy==`): `+` antes da barra, ou `+`, `=` ou 16+ caracteres no
            // trecho seguinte.
            if slash_ends && b == b'/' && !base64_slash(bytes, vstart, q) {
                break;
            }
            if depth == 0 && is_space(b) {
                break;
            }
            // `;` fecha o valor se é o fim (`k=X;`, `k=X; Path=/`) ou se o que vem é outro
            // `nome=` (`;v=2`); `token=AB;RAWc3x` (palavra solta depois de `;`) é valor.
            if b == b';' && semicolon_ends_value(bytes, q + 1) {
                break;
            }
            // aspas escapadas (`\"`) que fecham uma abertura escapada anterior ao nome
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
                        break; // fecha a abertura anterior ao nome
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

    /// Decodifica `[start, end)` UMA vez e varre o resultado como o nível seguinte.
    fn decode_child(&mut self, level: &Level<'_>, start: usize, end: usize, depth: usize) {
        if depth >= MAX_LEVELS || end <= start {
            return;
        }
        let src = &level.bytes[start..end];
        if !src.contains(&b'%') || !has_escape(src) {
            return;
        }
        if src.len() > MAX_DECODE_BYTES && !level.dry {
            // Grupo acima do teto de trabalho: não montamos mapas de posição (8 bytes por
            // byte). Decodificamos "a seco" só para DECIDIR: se algum nível tem um nome
            // sensível (ou se não dá para decidir: sobra `%XX` no teto), o grupo inteiro é
            // redigido (falha fechada); senão fica como está.
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
            // Teto de níveis: decodifica até estabilizar (com limite) e varre uma
            // última vez em modo fechado (o valor vai até o fim do nível).
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

    /// O nome efetivo de `part` é sensível?
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
            // Nomes longos também são examinados (falha fechada): `aaaa…token=X` é
            // `token`; só o cache fica restrito a nomes curtos.
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

    /// `esquema://usuario:senha@host`, `esquema:/\\usuario@host` e `//usuario:senha@host`
    /// (autoridade depois de `:` + barras, ou de `//` no começo/depois de um
    /// delimitador): o userinfo é redigido.
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

    /// `Bearer <cred>` / `Basic <cred>` em qualquer caixa e com qualquer espaço
    /// em branco; só quando o que segue parece credencial.
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
                // substitui da primeira posição depois do esquema até o fim da credencial
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

/// Atualiza a pilha de aberturas com o delimitador em `bytes[pos]`; devolve
/// quantos bytes consumiu (2 para aspas escapadas `\\\"`).
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

/// `;` em `bytes[at - 1]` encerra o valor? Sim no fim, antes de delimitador ou
/// antes de `nome=`; não antes de uma palavra solta.
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

/// A barra em `bytes[slash]` faz parte de um credencial base64 (e não do caminho)?
fn base64_slash(bytes: &[u8], value_start: usize, slash: usize) -> bool {
    if bytes[value_start..slash].contains(&b'+') {
        return true;
    }
    let rest = &bytes[slash + 1..];
    let segment = rest
        .iter()
        .position(|b| is_hard(*b) || matches!(b, b'/' | b'?'))
        .unwrap_or(rest.len());
    segment >= 16 || rest[..segment].iter().any(|b| matches!(b, b'+' | b'='))
}

/// O nome em `bytes[part_start..eq]` está num CAMINHO (segmento `/nome=valor/` ou
/// parâmetro de matriz `;nome=valor` depois de um token com `/`)? Então o valor acaba
/// em `/` ou `?`. Num valor de consulta (`?token=ab/cd`) ou solto (`token=ab/cd`) a
/// barra é parte do credencial (base64) e o valor vai até o espaço.
fn path_context(bytes: &[u8], group_start: usize, part_start: usize, eq: usize) -> bool {
    let part = &bytes[part_start..eq];
    if let Some(last_slash) = part.iter().rposition(|b| *b == b'/') {
        let last_query = part.iter().rposition(|b| *b == b'?');
        return last_query.map_or(true, |q| q < last_slash);
    }
    if part_start != group_start {
        return false;
    }
    // matriz: o grupo começa logo depois de `;` e um dos grupos `;`-encadeados
    // anteriores (até um delimitador que não seja `;`) contém `/`
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

/// Fechamento da abertura em `bytes[at]` (`( [ { <`, aspas) dentro de 64 bytes e
/// sem passar de uma quebra de linha; `None` se não houver. Aninhamento do mesmo
/// tipo é respeitado; aspas honram `\\` como escape.
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

/// Byte que continua um valor depois de um fechamento/placeholder: tudo que não
/// é delimitador nem `/` ou `?` (que começam o resto de um caminho/URL).
#[inline]
fn is_tail_byte(byte: u8) -> bool {
    !is_hard(byte) && !matches!(byte, b'/' | b'?' | b'=')
}

/// `bytes[at..]` começa com `=` (ou `＝`)?
fn starts_with_equals(bytes: &[u8], at: usize) -> bool {
    matches!(find_equals(bytes, at, (at + 3).min(bytes.len())), Some((pos, _)) if pos == at)
}

/// Próximo `=` (ou `＝` fullwidth U+FF1D) em `bytes[from..to]`: (posição, tamanho).
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

/// Tamanho de um "igual" em `bytes[at..]`: `=`, `＝`, `&equals;`, `&#61;`,
/// `&#0061;`, `&#x3D;`, `&#X003d;` (`;` opcional) e qualquer um deles escapado
/// de novo (`&amp;#61;`, `&amp;equals;`, `&amp;&#61;`, `&amp;amp;#61;`...).
fn equals_len_at(bytes: &[u8], at: usize) -> Option<usize> {
    let rest = bytes.get(at..)?;
    match rest.first()? {
        b'=' => Some(1),
        0xEF if rest.len() >= 3 && rest[1] == 0xBC && rest[2] == 0x9D => Some(3),
        b'&' => {
            // `&amp;` repetido: cada camada de escape HTML conta
            let mut skip = 0;
            while rest[skip..].len() >= 5 && rest[skip..skip + 5].eq_ignore_ascii_case(b"&amp;") {
                skip += 5;
                if skip > 40 {
                    break;
                }
            }
            let body = &rest[skip..];
            // depois de `&amp;` o `&` da entidade é opcional (`&amp;#61;`)
            let entity = if body.first() == Some(&b'&') {
                &body[1..]
            } else if skip > 0 {
                body
            } else {
                return None;
            };
            let lead = skip + usize::from(body.first() == Some(&b'&'));
            if entity.len() >= 7 && entity[..7].eq_ignore_ascii_case(b"equals;") {
                return Some(lead + 7);
            }
            if entity.first() == Some(&b'#') {
                let (radix, digits_at) = match entity.get(1) {
                    Some(b'x' | b'X') => (16, 2),
                    _ => (10, 1),
                };
                let mut j = digits_at;
                let mut value: u32 = 0;
                while j < entity.len() && j - digits_at < 12 {
                    let Some(d) = (entity[j] as char).to_digit(radix) else {
                        break;
                    };
                    value = value.saturating_mul(radix).saturating_add(d);
                    j += 1;
                }
                if j > digits_at && value == 0x3D {
                    if entity.get(j) == Some(&b';') {
                        j += 1;
                    }
                    return Some(lead + j);
                }
            }
            None
        }
        _ => None,
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

/// Comprimento do espaço em branco (ASCII ou Unicode) em `bytes[at..]`, ou 0.
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

/// Dígito, símbolo, maiúscula depois da primeira letra ou 16+ caracteres: não
/// apaga prosa como "Basic authentication".
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
