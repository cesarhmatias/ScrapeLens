//! Diff de duas requisições lógicas.
//!
//! Regras:
//! - cada ocorrência de header é tratada separadamente (duplicatas nunca são
//!   fundidas);
//! - a ordem original é usada; nada é ordenado alfabeticamente;
//! - pares iguais que mudaram de posição viram `reordered`, não
//!   adicionado+removido;
//! - a visão normalizada é um recurso separado ([`crate::normalize`]) e nunca
//!   substitui a original.

use serde::{Deserialize, Serialize};

use crate::model::{
    Body, BodyState, CookieField, HeaderView, LogicalRequest, Protocol,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffOptions {
    /// Compara nomes sem diferenciar maiúsculas/minúsculas (padrão HTTP).
    pub case_sensitive_names: bool,
    /// Colapsa espaços internos do valor antes de comparar.
    pub collapse_whitespace: bool,
    pub include_pseudo_headers: bool,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            case_sensitive_names: false,
            collapse_whitespace: false,
            include_pseudo_headers: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderOccurrence {
    /// Posição global na sequência original (0-based), pseudoheaders inclusos.
    pub index: usize,
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub pseudo: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderChange {
    pub name: String,
    pub a: HeaderOccurrence,
    pub b: HeaderOccurrence,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderMove {
    pub name: String,
    pub a: HeaderOccurrence,
    pub b: HeaderOccurrence,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderDiff {
    #[serde(default)]
    pub added: Vec<HeaderOccurrence>,
    #[serde(default)]
    pub removed: Vec<HeaderOccurrence>,
    #[serde(default)]
    pub changed: Vec<HeaderChange>,
    #[serde(default)]
    pub reordered: Vec<HeaderMove>,
    pub unchanged: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl HeaderDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.changed.is_empty()
            && self.reordered.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CookieOccurrence {
    pub index: usize,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CookieDiff {
    #[serde(default)]
    pub added: Vec<CookieOccurrence>,
    #[serde(default)]
    pub removed: Vec<CookieOccurrence>,
    #[serde(default)]
    pub changed: Vec<(CookieOccurrence, CookieOccurrence)>,
    pub unchanged: usize,
    pub raw_fields_a: usize,
    pub raw_fields_b: usize,
    pub wire_fields_a: usize,
    pub wire_fields_b: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BodyDiff {
    pub a: BodyState,
    pub b: BodyState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_a: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_b: Option<u64>,
    pub changed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScalarChange<T> {
    pub a: T,
    pub b: T,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestDiff {
    pub a_id: String,
    pub b_id: String,
    pub url: ScalarChange<String>,
    pub method: ScalarChange<String>,
    pub protocol: ScalarChange<Protocol>,
    pub status: ScalarChange<Option<u16>>,
    pub request_headers: HeaderDiff,
    pub response_headers: HeaderDiff,
    pub set_cookies: HeaderDiff,
    pub cookies: CookieDiff,
    pub request_body: BodyDiff,
    pub response_body: BodyDiff,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

pub fn diff_requests(
    a: &LogicalRequest,
    b: &LogicalRequest,
    options: &DiffOptions,
) -> RequestDiff {
    let request_headers = diff_header_views(&a.request_headers, &b.request_headers, options);
    let response_headers = diff_header_views(&a.response_headers, &b.response_headers, options);
    let set_cookies = diff_set_cookies(&a.set_cookies, &b.set_cookies);
    let cookies = diff_cookies(&a.cookie, &b.cookie);

    let mut notes = Vec::new();
    if a.request_headers.order_state != b.request_headers.order_state {
        notes.push(format!(
            "ordem da fonte difere: {:?} × {:?}",
            a.request_headers.order_state, b.request_headers.order_state
        ));
    }
    if a.protocol != b.protocol {
        notes.push("protocolos diferentes: o diff de headers não compara semântica de fio".to_string());
    }

    RequestDiff {
        a_id: a.id.clone(),
        b_id: b.id.clone(),
        url: ScalarChange {
            a: a.url.clone(),
            b: b.url.clone(),
            changed: a.url != b.url,
        },
        method: ScalarChange {
            a: a.method.clone(),
            b: b.method.clone(),
            changed: a.method != b.method,
        },
        protocol: ScalarChange {
            a: a.protocol,
            b: b.protocol,
            changed: a.protocol != b.protocol,
        },
        status: ScalarChange {
            a: a.status,
            b: b.status,
            changed: a.status != b.status,
        },
        request_headers,
        response_headers,
        set_cookies,
        cookies,
        request_body: diff_bodies(&a.request_body, &b.request_body),
        response_body: diff_bodies(&a.response_body, &b.response_body),
        notes,
    }
}

pub fn diff_header_views(a: &HeaderView, b: &HeaderView, options: &DiffOptions) -> HeaderDiff {
    let sequence_a = to_occurrences(a, options);
    let sequence_b = to_occurrences(b, options);
    let keys_a: Vec<String> = sequence_a
        .iter()
        .map(|occurrence| header_key(occurrence, options))
        .collect();
    let keys_b: Vec<String> = sequence_b
        .iter()
        .map(|occurrence| header_key(occurrence, options))
        .collect();
    let matched = lcs_pairs(&keys_a, &keys_b);

    let mut matched_a = vec![false; sequence_a.len()];
    let mut matched_b = vec![false; sequence_b.len()];
    for &(i, j) in &matched {
        matched_a[i] = true;
        matched_b[j] = true;
    }

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut reordered = Vec::new();

    // Pares idênticos fora da LCS moveram de posição.
    for (i, occurrence) in sequence_a.iter().enumerate() {
        if matched_a[i] {
            continue;
        }
        let key = header_key(occurrence, options);
        if let Some(position) = keys_b
            .iter()
            .enumerate()
            .find(|(j, candidate)| !matched_b[*j] && **candidate == key)
            .map(|(j, _)| j)
        {
            matched_b[position] = true;
            reordered.push(HeaderMove {
                name: occurrence.name.clone(),
                a: occurrence.clone(),
                b: sequence_b[position].clone(),
            });
        }
    }

    // Restantes: pareia por nome para detectar valor alterado.
    let mut used_b: Vec<bool> = vec![false; sequence_b.len()];
    for (i, occurrence) in sequence_a.iter().enumerate() {
        if matched_a[i] || reordered.iter().any(|mv| mv.a.index == occurrence.index) {
            continue;
        }
        let name = comparable_name(&occurrence.name, options);
        let candidate = sequence_b.iter().enumerate().find(|(j, other)| {
            !matched_b[*j] && !used_b[*j] && comparable_name(&other.name, options) == name
        });
        if let Some((j, other)) = candidate {
            matched_a[i] = true;
            used_b[j] = true;
            changed.push(HeaderChange {
                name: occurrence.name.clone(),
                a: occurrence.clone(),
                b: other.clone(),
            });
        } else {
            matched_a[i] = true;
            removed.push(occurrence.clone());
        }
    }
    for (j, occurrence) in sequence_b.iter().enumerate() {
        if !matched_b[j] && !used_b[j] {
            added.push(occurrence.clone());
        }
    }

    HeaderDiff {
        unchanged: matched.len() + reordered.len(),
        added,
        removed,
        changed,
        reordered,
        notes: Vec::new(),
    }
}

fn to_occurrences(view: &HeaderView, options: &DiffOptions) -> Vec<HeaderOccurrence> {
    let mut sequence = Vec::new();
    let mut index = 0usize;
    for entry in view.iter_all() {
        if entry.is_pseudo() && !options.include_pseudo_headers {
            continue;
        }
        sequence.push(HeaderOccurrence {
            index,
            name: entry.name.clone(),
            value: entry.value.clone(),
            pseudo: entry.is_pseudo(),
        });
        index += 1;
    }
    sequence
}

fn header_key(occurrence: &HeaderOccurrence, options: &DiffOptions) -> String {
    let value = if options.collapse_whitespace {
        occurrence
            .value
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        occurrence.value.clone()
    };
    format!("{}\u{0}{value}", comparable_name(&occurrence.name, options))
}

fn comparable_name(name: &str, options: &DiffOptions) -> String {
    if options.case_sensitive_names {
        name.to_string()
    } else {
        name.to_ascii_lowercase()
    }
}

fn lcs_pairs(a: &[String], b: &[String]) -> Vec<(usize, usize)> {
    let mut table = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            table[i][j] = if a[i] == b[j] {
                table[i + 1][j + 1] + 1
            } else {
                table[i + 1][j].max(table[i][j + 1])
            };
        }
    }
    let mut pairs = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        if a[i] == b[j] {
            pairs.push((i, j));
            i += 1;
            j += 1;
        } else if table[i + 1][j] >= table[i][j + 1] {
            i += 1;
        } else {
            j += 1;
        }
    }
    pairs
}

fn diff_cookies(a: &CookieField, b: &CookieField) -> CookieDiff {
    let pairs_a: Vec<CookieOccurrence> = a
        .pairs
        .iter()
        .enumerate()
        .map(|(index, pair)| CookieOccurrence {
            index,
            name: pair.name.clone(),
            value: pair.value.clone(),
        })
        .collect();
    let pairs_b: Vec<CookieOccurrence> = b
        .pairs
        .iter()
        .enumerate()
        .map(|(index, pair)| CookieOccurrence {
            index,
            name: pair.name.clone(),
            value: pair.value.clone(),
        })
        .collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut used_b = vec![false; pairs_b.len()];
    let mut unchanged = 0usize;

    for occurrence in &pairs_a {
        if let Some((index, _other)) = pairs_b.iter().enumerate().find(|(index, other)| {
            !used_b[*index] && other.name == occurrence.name && other.value == occurrence.value
        }) {
            used_b[index] = true;
            unchanged += 1;
        } else if let Some((index, other)) = pairs_b.iter().enumerate().find(|(index, other)| {
            !used_b[*index] && other.name == occurrence.name
        }) {
            used_b[index] = true;
            changed.push((occurrence.clone(), other.clone()));
        } else {
            removed.push(occurrence.clone());
        }
    }
    for (index, occurrence) in pairs_b.iter().enumerate() {
        if !used_b[index] {
            added.push(occurrence.clone());
        }
    }

    let mut notes = Vec::new();
    if a.raw != b.raw {
        notes.push("campos Cookie brutos diferem (ordem/valor)".to_string());
    }
    if a.wire_lines.len() != b.wire_lines.len() {
        notes.push(format!(
            "fragmentação no fio difere: {} × {} campos",
            a.wire_lines.len(),
            b.wire_lines.len()
        ));
    }

    CookieDiff {
        added,
        removed,
        changed,
        unchanged,
        raw_fields_a: a.raw.len(),
        raw_fields_b: b.raw.len(),
        wire_fields_a: a.wire_lines.len(),
        wire_fields_b: b.wire_lines.len(),
        notes,
    }
}

fn diff_set_cookies(
    a: &[crate::model::SetCookieRecord],
    b: &[crate::model::SetCookieRecord],
) -> HeaderDiff {
    let view = |records: &[crate::model::SetCookieRecord]| {
        let mut view = HeaderView::new(crate::model::OrderState::SourceOrder);
        for record in records {
            view.add("set-cookie", record.raw.clone(), &record.provenance);
        }
        view
    };
    diff_header_views(&view(a), &view(b), &DiffOptions::default())
}

fn diff_bodies(a: &Body, b: &Body) -> BodyDiff {
    let mut notes = Vec::new();
    if a.attachment.as_deref().is_some_and(|name| {
        b.attachment.as_deref().is_some_and(|other| other != name)
    }) {
        notes.push("anexos diferentes; o conteúdo dos bytes não é comparado aqui".to_string());
    }
    BodyDiff {
        a: a.state,
        b: b.state,
        bytes_a: a.bytes,
        bytes_b: b.bytes,
        changed: a.state != b.state || a.bytes != b.bytes || a.content_type != b.content_type,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HeaderView, OrderState, Provenance, Source, Verification};

    fn provenance() -> Provenance {
        Provenance::new(Source::NetLog, "test", Verification::Verified)
    }

    fn view(pairs: &[(&str, &str)]) -> HeaderView {
        HeaderView::from_pairs(pairs.iter().copied(), &provenance())
    }

    #[test]
    fn duplicate_occurrences_are_not_collapsed() {
        let a = view(&[("x-rep", "a"), ("x-rep", "b"), ("x-rep", "c")]);
        let b = view(&[("x-rep", "a"), ("x-rep", "b")]);
        let diff = diff_header_views(&a, &b, &DiffOptions::default());
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.removed[0].value, "c");
        assert_eq!(diff.unchanged, 2);
        assert!(diff.added.is_empty());
        assert!(diff.changed.is_empty());
    }

    #[test]
    fn changed_value_at_same_name_is_changed_not_add_remove() {
        let a = view(&[("x-rep", "a"), ("x-rep", "b")]);
        let b = view(&[("x-rep", "a"), ("x-rep", "c")]);
        let diff = diff_header_views(&a, &b, &DiffOptions::default());
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].a.value, "b");
        assert_eq!(diff.changed[0].b.value, "c");
        assert!(diff.added.is_empty() && diff.removed.is_empty());
    }

    #[test]
    fn reordered_pair_is_reported_and_original_order_untouched() {
        let a = view(&[("x-zeta", "1"), ("x-alpha", "2"), ("x-mid", "3")]);
        let b = view(&[("x-alpha", "2"), ("x-zeta", "1"), ("x-mid", "3")]);
        let diff = diff_header_views(&a, &b, &DiffOptions::default());
        assert_eq!(diff.reordered.len(), 1);
        assert_eq!(diff.reordered[0].name, "x-zeta");
        assert!(diff.added.is_empty() && diff.removed.is_empty() && diff.changed.is_empty());
        // O original continua na ordem de injeção.
        assert_eq!(a.headers[0].name, "x-zeta");
        assert_eq!(b.headers[0].name, "x-alpha");
    }

    #[test]
    fn added_and_removed_are_kept_in_original_order() {
        let a = view(&[("x-a", "1"), ("x-b", "2")]);
        let b = view(&[("x-a", "1"), ("x-c", "3"), ("x-b", "2")]);
        let diff = diff_header_views(&a, &b, &DiffOptions::default());
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].name, "x-c");
        assert_eq!(diff.added[0].index, 1);
        assert!(diff.removed.is_empty());
    }

    #[test]
    fn pseudoheaders_are_compared_and_can_be_excluded() {
        let a = view(&[(":method", "GET"), ("host", "a.test")]);
        let b = view(&[(":method", "POST"), ("host", "a.test")]);
        let diff = diff_header_views(&a, &b, &DiffOptions::default());
        assert_eq!(diff.changed.len(), 1);
        let without = DiffOptions {
            include_pseudo_headers: false,
            ..Default::default()
        };
        assert!(diff_header_views(&a, &b, &without).is_empty());
    }

    #[test]
    fn cookie_duplicates_and_fragmentation_are_visible() {
        let mut a = CookieField::from_header_values(&["a=1; a=2".to_string()], &provenance());
        a.push_wire_line("a=1");
        a.push_wire_line("a=2");
        let b = CookieField::from_header_values(&["a=1; a=3".to_string()], &provenance());
        let diff = diff_cookies(&a, &b);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.wire_fields_a, 2);
        assert_eq!(diff.wire_fields_b, 0);
        assert_eq!(diff.removed.len(), 0);
    }

    #[test]
    fn body_state_is_compared_without_claiming_bytes() {
        let a = Body::unavailable("x");
        let b = Body::discarded("y");
        let diff = diff_bodies(&a, &b);
        assert!(diff.changed);
        assert_eq!(diff.a, BodyState::Unavailable);
        assert_eq!(diff.b, BodyState::Discarded);
    }

    #[test]
    fn case_insensitive_names_by_default() {
        let a = view(&[("X-Rep", "a")]);
        let b = view(&[("x-rep", "a")]);
        assert!(diff_header_views(&a, &b, &DiffOptions::default()).is_empty());
        let strict = DiffOptions {
            case_sensitive_names: true,
            ..Default::default()
        };
        let diff = diff_header_views(&a, &b, &strict);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.removed.len(), 1);
    }
}
