use serde::{Deserialize, Serialize};

use super::provenance::{Provenance, Verification};

/// Um par de header como apareceu na fonte. A ordem do vetor é significativa.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderEntry {
    pub name: String,
    pub value: String,
    #[serde(flatten)]
    pub provenance: Provenance,
}

impl HeaderEntry {
    pub fn new(name: impl Into<String>, value: impl Into<String>, provenance: &Provenance) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            provenance: provenance.clone(),
        }
    }

    pub fn is_pseudo(&self) -> bool {
        self.name.starts_with(':')
    }

    pub fn name_lower(&self) -> String {
        self.name.to_ascii_lowercase()
    }
}

/// Como a ordem do bloco foi obtida.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OrderState {
    /// Ordem da fonte, sem reordenação.
    SourceOrder,
    /// Reconstruída (ex.: linha de status sintética do NetLog em h2/h3).
    Reconstructed,
    /// Visão normalizada: ordem não é a do fio.
    Normalized,
    Unknown,
}

impl Default for OrderState {
    fn default() -> Self {
        OrderState::Unknown
    }
}

/// Bloco de headers de uma requisição ou resposta.
///
/// Pseudoheaders ficam em `pseudo_headers`; nunca são misturados a `headers`.
/// Duplicatas são preservadas em ambos. `raw_block`, quando existe, é o texto
/// original (h1 `headersText` ou linhas do NetLog) e não deve ser regerado.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderView {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pseudo_headers: Vec<HeaderEntry>,
    #[serde(default)]
    pub headers: Vec<HeaderEntry>,
    /// Linha de request/status quando a fonte a fornece (`GET /x HTTP/1.1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_line: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_block: Option<String>,
    #[serde(default)]
    pub order_state: OrderState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl Default for HeaderView {
    fn default() -> Self {
        Self {
            pseudo_headers: Vec::new(),
            headers: Vec::new(),
            start_line: None,
            raw_block: None,
            order_state: OrderState::Unknown,
            notes: Vec::new(),
        }
    }
}

impl HeaderView {
    pub fn new(order_state: OrderState) -> Self {
        Self {
            order_state,
            ..Self::default()
        }
    }

    pub fn from_pairs<I, N, V>(pairs: I, provenance: &Provenance) -> Self
    where
        I: IntoIterator<Item = (N, V)>,
        N: Into<String>,
        V: Into<String>,
    {
        let mut view = Self::new(OrderState::SourceOrder);
        for (name, value) in pairs {
            view.push(HeaderEntry::new(name, value, provenance));
        }
        view
    }

    pub fn push(&mut self, entry: HeaderEntry) {
        if entry.is_pseudo() {
            self.pseudo_headers.push(entry);
        } else {
            self.headers.push(entry);
        }
    }

    pub fn add(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
        provenance: &Provenance,
    ) {
        self.push(HeaderEntry::new(name, value, provenance));
    }

    /// Todos os pares na ordem de origem: pseudoheaders primeiro, como no fio
    /// (h2/h3) ou no texto (h1).
    pub fn iter_all(&self) -> impl Iterator<Item = &HeaderEntry> {
        self.pseudo_headers.iter().chain(self.headers.iter())
    }

    pub fn len(&self) -> usize {
        self.pseudo_headers.len() + self.headers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Todos os valores de um nome, na ordem de ocorrência (case-insensitive).
    pub fn get_all(&self, name: &str) -> Vec<&HeaderEntry> {
        let lower = name.to_ascii_lowercase();
        self.iter_all()
            .filter(|entry| entry.name_lower() == lower)
            .collect()
    }

    pub fn first(&self, name: &str) -> Option<&HeaderEntry> {
        self.get_all(name).into_iter().next()
    }

    pub fn first_value(&self, name: &str) -> Option<&str> {
        self.first(name).map(|entry| entry.value.as_str())
    }

    pub fn contains(&self, name: &str) -> bool {
        self.first(name).is_some()
    }

    /// Valores distintos do campo `Cookie`, na ordem em que aparecem.
    pub fn cookie_field_values(&self) -> Vec<String> {
        self.get_all("cookie")
            .into_iter()
            .map(|entry| entry.value.clone())
            .collect()
    }

    /// Estado de verificação mais fraco do bloco. Um bloco inteiro só é
    /// `verified` se todas as informações que o compõem forem `verified`.
    pub fn verification(&self) -> Verification {
        if self.is_empty() {
            return Verification::Unverified;
        }
        self.iter_all()
            .map(|entry| entry.provenance.verification)
            .fold(Verification::Verified, Verification::weakest)
    }

    /// Converte linhas no formato `Name: value` (ou `:path: /x`) em pares.
    ///
    /// Preserva ordem, caixa e duplicatas. Linhas sem `:` (fora a linha de
    /// status) retornam em `issues` e nunca são descartadas em silêncio.
    pub fn from_header_lines(
        lines: &[String],
        provenance: &Provenance,
        order_state: OrderState,
    ) -> (Self, Vec<String>, Vec<String>) {
        let mut view = Self::new(order_state);
        let mut issues = Vec::new();
        let mut unparsed = Vec::new();

        for (index, raw) in lines.iter().enumerate() {
            let line = raw.trim_end_matches(['\r', '\n']);
            if index == 0 && (line.starts_with("HTTP/") || line.contains(" HTTP/")) {
                view.start_line = Some(line.to_string());
                continue;
            }
            if line.is_empty() {
                continue;
            }
            match split_header_line(line) {
                Some((name, value)) => view.add(name, value, provenance),
                None => {
                    issues.push(format!(
                        "linha sem separador ':' na posição {index}: {line:?}"
                    ));
                    unparsed.push(line.to_string());
                }
            }
        }

        if !unparsed.is_empty() {
            view.notes.push(format!(
                "{} linha(s) não parseada(s) preservada(s) em issues",
                unparsed.len()
            ));
        }
        (view, issues, unparsed)
    }

    /// Parse de um bloco HTTP/1 bruto (`HTTP/1.1 200 OK\r\nName: value...`).
    pub fn from_http_block(block: &str, provenance: &Provenance) -> (Self, Vec<String>) {
        let lines: Vec<String> = block.lines().map(|line| line.to_string()).collect();
        let (view, issues, _) =
            Self::from_header_lines(&lines, provenance, OrderState::SourceOrder);
        let mut view = view;
        view.raw_block = Some(block.to_string());
        (view, issues)
    }
}

/// Separa `Name: value` preservando o valor exatamente após um único espaço/
/// tab opcional. Suporta pseudoheaders (`:path: /x`).
pub fn split_header_line(line: &str) -> Option<(String, String)> {
    let idx = line.find(':')?;
    if idx == 0 {
        // Pseudoheader: procura o segundo ':'.
        let rest = &line[1..];
        let second = rest.find(':')?;
        let name = &line[..second + 1];
        let value = rest[second + 1..].trim_start_matches([' ', '\t']);
        return Some((name.to_string(), value.to_string()));
    }
    let name = line[..idx].trim();
    if name.is_empty() {
        return None;
    }
    let value = line[idx + 1..].trim_start_matches([' ', '\t']);
    Some((name.to_string(), value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::provenance::Source;

    fn provenance() -> Provenance {
        Provenance::new(Source::NetLog, "test", Verification::Verified)
    }

    #[test]
    fn preserves_order_duplicates_and_case() {
        let view = HeaderView::from_pairs(
            [
                ("x-rep", "a"),
                ("X-Rep", "b"),
                ("x-seq", "1"),
                ("x-rep", "c"),
            ],
            &provenance(),
        );
        let names: Vec<_> = view
            .headers
            .iter()
            .map(|entry| (entry.name.as_str(), entry.value.as_str()))
            .collect();
        assert_eq!(
            names,
            vec![
                ("x-rep", "a"),
                ("X-Rep", "b"),
                ("x-seq", "1"),
                ("x-rep", "c")
            ]
        );
        assert_eq!(view.get_all("X-REP").len(), 3);
    }

    #[test]
    fn keeps_pseudoheaders_separate() {
        let view = HeaderView::from_pairs(
            [(":method", "GET"), ("host", "example.test"), (":path", "/")],
            &provenance(),
        );
        assert_eq!(view.pseudo_headers.len(), 2);
        assert_eq!(view.headers.len(), 1);
        assert_eq!(view.pseudo_headers[0].name, ":method");
        assert_eq!(view.iter_all().count(), 3);
    }

    #[test]
    fn parses_status_line_and_values_with_colons() {
        let block = "HTTP/1.1 200 OK\r\ncontent-type: text/plain: charset=utf-8\r\nset-cookie: a=1\r\nset-cookie: b=2\r\n";
        let (view, issues) = HeaderView::from_http_block(block, &provenance());
        assert!(issues.is_empty());
        assert_eq!(view.start_line.as_deref(), Some("HTTP/1.1 200 OK"));
        assert_eq!(
            view.first_value("content-type"),
            Some("text/plain: charset=utf-8")
        );
        assert_eq!(view.get_all("set-cookie").len(), 2);
        assert_eq!(view.raw_block.as_deref(), Some(block));
    }

    #[test]
    fn pseudoheader_line_parses_name_with_colon() {
        assert_eq!(
            split_header_line(":path: /echo-order?from=page"),
            Some((":path".to_string(), "/echo-order?from=page".to_string()))
        );
        assert_eq!(
            split_header_line(":status: 200"),
            Some((":status".to_string(), "200".to_string()))
        );
    }

    #[test]
    fn empty_view_is_unverified_not_verified() {
        let view = HeaderView::default();
        assert_eq!(view.verification(), Verification::Unverified);
    }

    #[test]
    fn malformed_line_is_reported_not_dropped_silently() {
        let lines = vec!["x-good: 1".to_string(), "not a header".to_string()];
        let (view, issues, unparsed) =
            HeaderView::from_header_lines(&lines, &provenance(), OrderState::SourceOrder);
        assert_eq!(view.len(), 1);
        assert_eq!(issues.len(), 1);
        assert_eq!(unparsed, vec!["not a header".to_string()]);
    }
}
