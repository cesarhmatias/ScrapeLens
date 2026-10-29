//! Tokenizador HTML tolerante para controles de formulário (L1, docs/10).
//!
//! Não executa nada e não monta DOM: percorre o texto procurando `<input>`,
//! `<textarea>` e `<select>`, ignorando comentários, `<script>` e `<style>`.
//! Aceita atributos com aspas duplas, simples ou sem aspas, nomes em
//! maiúsculas, atributos sem valor e tags mal fechadas. As entidades
//! (`&amp;`, `&lt;`, `&#38;`, `&#x26;`…) são decodificadas no valor, com um
//! mapa de offsets de cada byte decodificado para o original.

/// Um controle de formulário com valor.
#[derive(Debug, Clone, PartialEq)]
pub struct HtmlControl {
    pub name: String,
    /// Valor com entidades decodificadas.
    pub value: String,
    /// `map[i]` = offset original do byte decodificado `i`; `map[len]` = fim.
    pub map: Vec<usize>,
    /// Intervalo do valor no texto original.
    pub start: usize,
    pub end: usize,
    /// `hidden` (input) — única forma de controle que a página define como
    /// valor de protocolo; os demais são pré-preenchimentos.
    pub hidden: bool,
}

const MAX_CONTROLS: usize = 20_000;
const MAX_RUNAWAY_TAGS: usize = 64;

/// Decodifica entidades HTML com mapa de offsets (base = deslocamento do
/// trecho no texto original). Entidade desconhecida fica literal.
pub fn decode_entities(raw: &str, base: usize) -> (String, Vec<usize>) {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut map: Vec<usize> = Vec::with_capacity(raw.len() + 1);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            if let Some((ch, len)) = entity_at(raw, i) {
                for _ in 0..ch.len_utf8() {
                    map.push(base + i);
                }
                out.push(ch);
                i += len;
                continue;
            }
        }
        let ch = raw[i..].chars().next().unwrap_or('\u{FFFD}');
        for _ in 0..ch.len_utf8() {
            map.push(base + i);
        }
        out.push(ch);
        i += ch.len_utf8();
    }
    map.push(base + raw.len());
    (out, map)
}

fn entity_at(raw: &str, at: usize) -> Option<(char, usize)> {
    let rest = &raw[at + 1..];
    let end = rest.find(';').filter(|e| *e <= 10)?;
    let body = &rest[..end];
    let ch = if let Some(num) = body.strip_prefix('#') {
        let code = if let Some(hex) = num.strip_prefix(['x', 'X']) {
            u32::from_str_radix(hex, 16).ok()?
        } else {
            num.parse::<u32>().ok()?
        };
        char::from_u32(code)?
    } else {
        match body {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            "nbsp" => '\u{a0}',
            _ => return None,
        }
    };
    Some((ch, end + 2))
}

struct Tag<'a> {
    name: String,
    /// (nome minúsculo, valor bruto, início do valor no texto, presente)
    attrs: Vec<(String, &'a str, usize)>,
    /// Posição logo depois do `>`.
    end: usize,
    closing: bool,
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0c)
}

/// Lê a tag que começa em `at` (`<`). `None` se não parecer uma tag.
fn parse_tag<'a>(text: &'a str, at: usize, no_close: &mut [usize; 3]) -> Option<Tag<'a>> {
    // Tag que corre até o fim do texto custa uma varredura inteira; depois de
    // algumas, o resto do documento deixa de ser lido como tag (linear).
    if no_close[2] >= MAX_RUNAWAY_TAGS {
        return None;
    }
    let bytes = text.as_bytes();
    let mut i = at + 1;
    let closing = bytes.get(i) == Some(&b'/');
    if closing {
        i += 1;
    }
    let name_start = i;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'-') {
        i += 1;
    }
    if i == name_start {
        return None;
    }
    let name = text[name_start..i].to_ascii_lowercase();
    let mut attrs: Vec<(String, &str, usize)> = Vec::new();
    loop {
        while i < bytes.len() && (is_space(bytes[i]) || bytes[i] == b'/') {
            i += 1;
        }
        if i >= bytes.len() {
            no_close[2] += 1;
            return None; // tag sem `>`
        }
        if bytes[i] == b'>' {
            return Some(Tag {
                name,
                attrs,
                end: i + 1,
                closing,
            });
        }
        let a_start = i;
        while i < bytes.len() && !is_space(bytes[i]) && !matches!(bytes[i], b'=' | b'>' | b'/') {
            i += 1;
        }
        if i == a_start {
            i += 1; // caractere estranho: segue adiante
            continue;
        }
        let attr = text[a_start..i].to_ascii_lowercase();
        let mut j = i;
        while j < bytes.len() && is_space(bytes[j]) {
            j += 1;
        }
        if bytes.get(j) != Some(&b'=') {
            attrs.push((attr, "", i));
            continue;
        }
        j += 1;
        while j < bytes.len() && is_space(bytes[j]) {
            j += 1;
        }
        match bytes.get(j) {
            Some(&q) if q == b'"' || q == b'\'' => {
                let v_start = j + 1;
                // Memoriza onde já não há aspas de fechamento: mantém o
                // tokenizador linear com aspas sem par (`<a b="` repetido).
                let slot = usize::from(q == b'\'');
                if v_start >= no_close[slot] {
                    no_close[2] += 1;
                    return None;
                }
                let Some(e) = text[v_start..].find(q as char) else {
                    no_close[slot] = no_close[slot].min(v_start);
                    no_close[2] += 1;
                    return None;
                };
                let v_end = v_start + e;
                attrs.push((attr, &text[v_start..v_end], v_start));
                i = v_end + 1;
            }
            Some(_) => {
                let v_start = j;
                let mut k = j;
                while k < bytes.len() && !is_space(bytes[k]) && bytes[k] != b'>' {
                    k += 1;
                }
                attrs.push((attr, &text[v_start..k], v_start));
                i = k;
            }
            None => {
                no_close[2] += 1;
                return None;
            }
        }
    }
}

fn attr<'a>(tag: &'a Tag<'_>, name: &str) -> Option<(&'a str, usize)> {
    tag.attrs
        .iter()
        .find(|(n, _, _)| n == name)
        .map(|(_, v, s)| (*v, *s))
}

fn has_attr(tag: &Tag<'_>, name: &str) -> bool {
    tag.attrs.iter().any(|(n, _, _)| n == name)
}

fn find_ci(text: &str, from: usize, needle: &str) -> Option<usize> {
    let hay = text.as_bytes();
    let n = needle.as_bytes();
    if from >= hay.len() || n.is_empty() {
        return None;
    }
    (from..=hay.len().saturating_sub(n.len()))
        .find(|&i| hay[i..i + n.len()].eq_ignore_ascii_case(n))
}

fn control(name: &str, raw: &str, start: usize) -> Option<HtmlControl> {
    if name.is_empty() {
        return None;
    }
    let (value, map) = decode_entities(raw, start);
    Some(HtmlControl {
        name: decode_entities(name, 0).0,
        value,
        map,
        start,
        end: start + raw.len(),
        hidden: false,
    })
}

/// Extrai os controles com nome de um documento HTML.
pub fn html_controls(text: &str) -> Vec<HtmlControl> {
    let bytes = text.as_bytes();
    let mut out: Vec<HtmlControl> = Vec::new();
    let mut no_close = [usize::MAX, usize::MAX, 0];
    let mut i = 0;
    while i < bytes.len() && out.len() < MAX_CONTROLS {
        let Some(rel) = text[i..].find('<') else {
            break;
        };
        let at = i + rel;
        if text[at..].starts_with("<!--") {
            i = text[at + 4..]
                .find("-->")
                .map_or(bytes.len(), |e| at + 4 + e + 3);
            continue;
        }
        let Some(tag) = parse_tag(text, at, &mut no_close) else {
            i = at + 1;
            continue;
        };
        i = tag.end;
        if tag.closing {
            continue;
        }
        match tag.name.as_str() {
            "script" | "style" => {
                let close = format!("</{}", tag.name);
                i = find_ci(text, tag.end, &close).unwrap_or(bytes.len());
            }
            "input" => {
                let Some((name, _)) = attr(&tag, "name") else {
                    continue;
                };
                let kind =
                    attr(&tag, "type").map_or(String::new(), |(t, _)| t.to_ascii_lowercase());
                if matches!(kind.as_str(), "checkbox" | "radio") && !has_attr(&tag, "checked") {
                    continue;
                }
                // Botões nunca são produtores de valor.
                if matches!(kind.as_str(), "submit" | "button" | "image" | "reset") {
                    continue;
                }
                let (raw, start) = attr(&tag, "value").unwrap_or(("", tag.end - 1));
                if let Some(mut c) = control(name, raw, start) {
                    c.hidden = kind == "hidden";
                    out.push(c);
                }
            }
            "textarea" => {
                let Some((name, _)) = attr(&tag, "name") else {
                    continue;
                };
                let end = find_ci(text, tag.end, "</textarea").unwrap_or(bytes.len());
                if let Some(c) = control(name, &text[tag.end..end], tag.end) {
                    out.push(c);
                }
                i = end;
            }
            "select" => {
                let Some((name, _)) = attr(&tag, "name") else {
                    continue;
                };
                let end = find_ci(text, tag.end, "</select").unwrap_or(bytes.len());
                let mut j = tag.end;
                while j < end {
                    let Some(rel) = text[j..end].find('<') else {
                        break;
                    };
                    let Some(option) = parse_tag(text, j + rel, &mut no_close) else {
                        j += rel + 1;
                        continue;
                    };
                    j = option.end;
                    if option.name == "option" && !option.closing && has_attr(&option, "selected") {
                        let (raw, start) = match attr(&option, "value") {
                            Some((v, s)) => (v, s),
                            None => {
                                let stop = text[option.end..end]
                                    .find('<')
                                    .map_or(end, |e| option.end + e);
                                (text[option.end..stop].trim(), option.end)
                            }
                        };
                        if let Some(c) = control(name, raw, start) {
                            out.push(c);
                        }
                        break;
                    }
                }
                i = end;
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_quote_styles_case_and_entities() {
        let html = r#"<SCRIPT>var x = "<input name=nope value=1>";</SCRIPT>
<INPUT TYPE=hidden NAME=STAMP VALUE="20&#x30;5">
<input type='hidden' name='A' value='a&amp;b'>
<input name=bare value=unquoted>
<input name="novalue">
<input type="checkbox" name="off"><input type="checkbox" name="on" checked value="y">
<textarea name="XML" rows=3>x08DLTA&lt;1&gt; &amp; fim</textarea>
<select name="S"><option value="1">u<option selected value="2">d</select>"#;
        let c = html_controls(html);
        let get = |n: &str| c.iter().find(|c| c.name == n).map(|c| c.value.as_str());
        assert_eq!(get("STAMP"), Some("2005"));
        assert_eq!(get("A"), Some("a&b"));
        assert_eq!(get("bare"), Some("unquoted"));
        assert_eq!(get("novalue"), Some(""));
        assert_eq!(get("off"), None);
        assert_eq!(get("on"), Some("y"));
        assert_eq!(get("XML"), Some("x08DLTA<1> & fim"));
        assert_eq!(get("S"), Some("2"));
        assert_eq!(get("nope"), None, "script ignorado");
    }

    #[test]
    fn maps_offsets_through_entities() {
        let html = "<textarea name=\"XML\">a&lt;cmd_</textarea>";
        let c = &html_controls(html)[0];
        let at = c.value.find("cmd_").unwrap();
        assert_eq!(&html[c.map[at]..c.map[at] + 4], "cmd_");
        assert_eq!(c.map[c.value.len()], c.end);
    }

    #[test]
    fn tolerates_broken_markup() {
        assert!(html_controls("<input name=\"x\" value=\"abc").is_empty());
        assert!(html_controls("<textarea name=\"x\">sem fim").len() == 1);
        assert!(html_controls("<<>><input").is_empty());
    }

    #[test]
    fn unclosed_quotes_stay_linear() {
        for unit in ["<a b=\"", "<a b='", "<input name=\"x\" value='"] {
            let html = unit.repeat(50_000);
            let t = std::time::Instant::now();
            assert!(html_controls(&html).is_empty());
            let limit = if cfg!(debug_assertions) { 5.0 } else { 1.0 };
            assert!(
                t.elapsed().as_secs_f64() < limit,
                "{unit}: {:?}",
                t.elapsed()
            );
        }
    }
}
