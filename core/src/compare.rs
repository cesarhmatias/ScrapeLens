//! Comparação entre duas capturas do mesmo fluxo (`docs/09-cadeia-comparacao.md` §2).
//!
//! ```text
//! pub fn compare_sessions(a: &SessionV1, a_source: &dyn BodySource,
//!                         b: &SessionV1, b_source: &dyn BodySource,
//!                         options: &CompareOptions) -> SessionComparison
//! ```
//!
//! - Alinhamento A↔B por modelo (método + host + caminho normalizado +
//!   nomes de query + nomes de campos do corpo); requisições do mesmo modelo
//!   são pareadas em ordem. Sobras ficam `onlyInA`/`onlyInB`; as que só
//!   diferem nos nomes de campos são pareadas por caminho (`alignedBy: path`)
//!   e a ambiguidade é listada em `ambiguities`. Nunca por horário absoluto.
//! - Por campo (query, headers, cookies, corpo): `static`, `dynamic`, `onlyA`,
//!   `onlyB`, `redacted`. Campos repetidos são pareados por ocorrência, na
//!   ordem da fonte (sem ordenação alfabética).
//! - Dinâmico + origem observada em B (resposta anterior de B) =
//!   `runtime`; dinâmico sem origem = `noOrigin`; campos opacos (>= 16
//!   caracteres) são comparados por valor inteiro e por trechos que diferem
//!   (`parts`), cada um com a própria origem.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::flow::{
    origins_in, ConsumedScope, Evidence, EvidenceKind, FlowContext, FlowOptions, OriginStatus,
    ProducerScope, ValueOrigin, ValueOrigins,
};
use crate::model::SessionV1;
use crate::search::BodySource;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompareOptions {
    pub flow: FlowOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FieldClass {
    Static,
    Dynamic,
    OnlyA,
    OnlyB,
    Redacted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DynamicKind {
    /// "obter em runtime": a origem em B é uma resposta anterior de B.
    Runtime,
    /// "dinâmico sem origem": gerado no cliente, constante de entrada etc.
    NoOrigin,
    /// O valor já circulava em requisição anterior, sem produtor observado.
    Repeated,
    /// Campo opaco: ver `parts`.
    Composite,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OriginSummary {
    pub kind: EvidenceKind,
    /// Requisição de B que produz o valor (a mais antiga).
    pub request_id: String,
    pub scope: ProducerScope,
    pub field: Option<String>,
    pub ambiguous: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartDiff {
    /// `static` (trecho comum >= 8 bytes) ou `dynamic`.
    pub class: FieldClass,
    pub label: String,
    pub a_offset: u64,
    pub b_offset: u64,
    pub a: String,
    pub b: String,
    pub dynamic_kind: DynamicKind,
    pub origin_label: String,
    pub origin: Option<OriginSummary>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldDiff {
    pub scope: ConsumedScope,
    pub field: String,
    pub occurrence: usize,
    pub class: FieldClass,
    /// Rótulo em português: estático, dinâmico, só em A, só em B, redigido.
    pub label: String,
    pub dynamic_kind: Option<DynamicKind>,
    /// "obter em runtime (origem: …)" ou "dinâmico sem origem".
    pub origin_label: Option<String>,
    pub a: Option<String>,
    pub b: Option<String>,
    pub origin: Option<OriginSummary>,
    pub parts: Vec<PartDiff>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestRef {
    pub request_id: String,
    pub method: String,
    pub url: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairCounts {
    pub r#static: usize,
    pub dynamic: usize,
    pub runtime: usize,
    pub no_origin: usize,
    pub only_a: usize,
    pub only_b: usize,
    pub redacted: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairComparison {
    pub a: RequestRef,
    pub b: RequestRef,
    /// `model` (modelo idêntico) ou `path` (só método + host + caminho).
    pub aligned_by: String,
    /// B não preserva a ordem relativa de A neste par.
    pub out_of_order: bool,
    pub fields: Vec<FieldDiff>,
    pub counts: PairCounts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionComparison {
    pub pairs: Vec<PairComparison>,
    pub only_in_a: Vec<RequestRef>,
    pub only_in_b: Vec<RequestRef>,
    pub ambiguities: Vec<String>,
    pub counts: PairCounts,
    pub redacted_fields: usize,
    pub warnings: Vec<String>,
}

const OPAQUE_MIN: usize = 16;

fn is_redacted(value: &str) -> bool {
    value.contains("REDACTED")
}

fn split_url(url: &str) -> (String, String) {
    let no_frag = url.split('#').next().unwrap_or(url);
    let no_query = no_frag.split('?').next().unwrap_or(no_frag);
    let (host, path) = match no_query.split_once("://") {
        Some((_, rest)) => match rest.split_once('/') {
            Some((host, path)) => (host, format!("/{path}")),
            None => (rest, "/".to_string()),
        },
        None => ("", no_query.to_string()),
    };
    let path = path
        .split('/')
        .map(|segment| {
            let hex =
                segment.len() >= 8 && segment.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-');
            if !segment.is_empty() && (segment.bytes().all(|b| b.is_ascii_digit()) || hex) {
                "{id}"
            } else {
                segment
            }
            .to_string()
        })
        .collect::<Vec<_>>()
        .join("/");
    (
        host.to_ascii_lowercase(),
        path.trim_end_matches('/').to_string(),
    )
}

struct Entry {
    index: usize,
    id: String,
    method: String,
    url: String,
    base: String,
    model: String,
}

fn entries(ctx: &FlowContext<'_>) -> Vec<Entry> {
    let mut out = Vec::new();
    for (index, request) in ctx.session.requests.iter().enumerate() {
        let Some(pos) = ctx.find(&request.id) else {
            continue;
        };
        let attempt = ctx.attempt_ref(pos);
        let (host, path) = split_url(&attempt.url);
        let base = format!("{}|{host}|{path}", attempt.method.to_ascii_uppercase());
        let mut names: Vec<String> = ctx
            .consumed_for(pos)
            .iter()
            .filter(|c| matches!(c.scope, ConsumedScope::Query | ConsumedScope::Body))
            .map(|c| format!("{:?}:{}", c.scope, c.field))
            .collect();
        names.sort();
        names.dedup();
        let model = format!("{base}|{}", names.join(","));
        out.push(Entry {
            index,
            id: request.id.clone(),
            method: attempt.method.clone(),
            url: attempt.url.clone(),
            base,
            model,
        });
    }
    out
}

fn request_ref(entry: &Entry) -> RequestRef {
    RequestRef {
        request_id: entry.id.clone(),
        method: entry.method.clone(),
        url: entry.url.clone(),
    }
}

fn preview(value: &str) -> String {
    let mut out: String = value.chars().take(160).collect();
    if value.chars().count() > 160 {
        out.push('…');
    }
    out
}

fn summary(value: &ValueOrigin) -> Option<OriginSummary> {
    let oldest: &Evidence = value.evidences.get(value.oldest?)?;
    Some(OriginSummary {
        kind: oldest.kind,
        request_id: oldest.request_id.clone(),
        scope: oldest.scope,
        field: oldest.field.clone(),
        ambiguous: value.status == OriginStatus::Ambiguous,
    })
}

fn kind_of(value: &ValueOrigin) -> DynamicKind {
    match value.status {
        OriginStatus::Origin | OriginStatus::Ambiguous => DynamicKind::Runtime,
        OriginStatus::Repeated => DynamicKind::Repeated,
        _ => DynamicKind::NoOrigin,
    }
}

/// Regiões que diferem (a_ini, a_fim, b_ini, b_fim) por LCS de bytes; acima do
/// limite de células, usa só prefixo/sufixo comuns.
fn diff_regions(a: &[u8], b: &[u8], cap: usize) -> Vec<(usize, usize, usize, usize)> {
    let prefix = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let suffix = a[prefix..]
        .iter()
        .rev()
        .zip(b[prefix..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (a_mid, b_mid) = (&a[prefix..a.len() - suffix], &b[prefix..b.len() - suffix]);
    if a_mid.is_empty() && b_mid.is_empty() {
        return Vec::new();
    }
    if a_mid.len().saturating_mul(b_mid.len()) > cap {
        return vec![(prefix, a.len() - suffix, prefix, b.len() - suffix)];
    }
    let (n, m) = (a_mid.len(), b_mid.len());
    let mut table = vec![0u16; (n + 1) * (m + 1)];
    let at = |i: usize, j: usize| i * (m + 1) + j;
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            table[at(i, j)] = if a_mid[i] == b_mid[j] {
                table[at(i + 1, j + 1)].saturating_add(1)
            } else {
                table[at(i + 1, j)].max(table[at(i, j + 1)])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut regions: Vec<(usize, usize, usize, usize)> = Vec::new();
    let mut open: Option<(usize, usize)> = None;
    while i < n || j < m {
        if i < n && j < m && a_mid[i] == b_mid[j] {
            if let Some((si, sj)) = open.take() {
                regions.push((si, i, sj, j));
            }
            i += 1;
            j += 1;
        } else {
            if open.is_none() {
                open = Some((i, j));
            }
            if j >= m || (i < n && table[at(i + 1, j)] >= table[at(i, j + 1)]) {
                i += 1;
            } else {
                j += 1;
            }
        }
    }
    if let Some((si, sj)) = open {
        regions.push((si, n, sj, m));
    }
    // une regiões separadas por poucos bytes iguais (mesmo token)
    let mut merged: Vec<(usize, usize, usize, usize)> = Vec::new();
    for region in regions {
        if let Some(last) = merged.last_mut() {
            if region.0.saturating_sub(last.1) <= 2 && region.2.saturating_sub(last.3) <= 2 {
                last.1 = region.1;
                last.3 = region.3;
                continue;
            }
        }
        merged.push(region);
    }
    merged
        .into_iter()
        .map(|(a0, a1, b0, b1)| (a0 + prefix, a1 + prefix, b0 + prefix, b1 + prefix))
        .collect()
}

/// Trecho alterado com contexto à esquerda até ter >= 12 bytes (campos opacos
/// concatenados não têm separadores confiáveis).
fn window_around(text: &str, start: usize, end: usize) -> String {
    let mut s = start.min(text.len());
    let e = end.min(text.len());
    while s > 0 && e - s < 16 {
        s -= 1;
    }
    while !text.is_char_boundary(s) {
        s -= 1;
    }
    let mut e = e;
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    while e < text.len() && word(text.as_bytes()[e]) && e - end.min(text.len()) < 8 {
        e += 1;
    }
    while !text.is_char_boundary(e) {
        e += 1;
    }
    text[s..e].to_string()
}

#[allow(dead_code)]
fn token_around(text: &str, start: usize, end: usize) -> (usize, String) {
    let bytes = text.as_bytes();
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut s = start.min(bytes.len());
    let mut e = end.min(bytes.len());
    while s > 0 && word(bytes[s - 1]) && end - s.min(end) < 64 {
        s -= 1;
    }
    while e < bytes.len() && word(bytes[e]) && e - s < 64 {
        e += 1;
    }
    while !text.is_char_boundary(s) {
        s -= 1;
    }
    while !text.is_char_boundary(e) {
        e += 1;
    }
    (s, text[s..e].to_string())
}

pub fn compare_sessions(
    a: &SessionV1,
    a_source: &dyn BodySource,
    b: &SessionV1,
    b_source: &dyn BodySource,
    options: &CompareOptions,
) -> SessionComparison {
    let ctx_a = FlowContext::new(a, a_source, &options.flow);
    let ctx_b = FlowContext::new(b, b_source, &options.flow);
    let ea = entries(&ctx_a);
    let eb = entries(&ctx_b);
    let mut result = SessionComparison {
        pairs: Vec::new(),
        only_in_a: Vec::new(),
        only_in_b: Vec::new(),
        ambiguities: Vec::new(),
        counts: PairCounts::default(),
        redacted_fields: 0,
        warnings: Vec::new(),
    };

    // 1) mesmo modelo, em ordem.
    let mut by_model_b: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, e) in eb.iter().enumerate() {
        by_model_b.entry(&e.model).or_default().push(i);
    }
    let mut cursor: HashMap<&str, usize> = HashMap::new();
    let mut pairs: Vec<(usize, usize, &'static str)> = Vec::new();
    let mut used_b = vec![false; eb.len()];
    let mut left_a: Vec<usize> = Vec::new();
    for (i, e) in ea.iter().enumerate() {
        let slot = cursor.entry(&e.model).or_default();
        match by_model_b.get(e.model.as_str()).and_then(|v| v.get(*slot)) {
            Some(&j) => {
                *slot += 1;
                used_b[j] = true;
                pairs.push((i, j, "model"));
            }
            None => left_a.push(i),
        }
    }
    // 2) sobras com o mesmo método + host + caminho.
    let mut left_b: Vec<usize> = (0..eb.len()).filter(|j| !used_b[*j]).collect();
    let mut still_a = Vec::new();
    for i in left_a {
        let found = left_b.iter().position(|&j| eb[j].base == ea[i].base);
        match found {
            Some(pos) => {
                let j = left_b.remove(pos);
                pairs.push((i, j, "path"));
                result.ambiguities.push(format!(
                    "{} ↔ {}: mesmo método/host/caminho, mas nomes de campos diferentes; pareados por ordem",
                    ea[i].id, eb[j].id
                ));
            }
            None => still_a.push(i),
        }
    }
    // Modelos com contagem diferente: sobra posicional é ambígua.
    let mut count_a: HashMap<&str, usize> = HashMap::new();
    let mut count_b: HashMap<&str, usize> = HashMap::new();
    for e in &ea {
        *count_a.entry(&e.model).or_default() += 1;
    }
    for e in &eb {
        *count_b.entry(&e.model).or_default() += 1;
    }
    for (model, na) in &count_a {
        let nb = count_b.get(model).copied().unwrap_or(0);
        if nb > 0 && nb != *na {
            let label = model.split('|').take(3).collect::<Vec<_>>().join(" ");
            result.ambiguities.push(format!(
                "{label}: A tem {na} e B tem {nb} requisição(ões) do mesmo modelo; as sobras são posicionais"
            ));
        }
    }
    for i in still_a {
        result.only_in_a.push(request_ref(&ea[i]));
    }
    for j in left_b {
        result.only_in_b.push(request_ref(&eb[j]));
    }

    pairs.sort_by_key(|(i, _, _)| *i);
    let mut max_b_seen: Option<usize> = None;
    for (i, j, how) in pairs {
        let out_of_order = max_b_seen.is_some_and(|m| eb[j].index < m);
        max_b_seen = Some(max_b_seen.map_or(eb[j].index, |m| m.max(eb[j].index)));
        let pair = compare_pair(&ctx_a, &ctx_b, &ea[i], &eb[j], how, out_of_order);
        add_counts(&mut result.counts, &pair.counts);
        result.pairs.push(pair);
    }
    result.redacted_fields = result.counts.redacted;
    if result.redacted_fields > 0 {
        result.warnings.push(format!(
            "{} campo(s) redigido(s) ([REDACTED]) não podem ser comparados nem rastreados",
            result.redacted_fields
        ));
    }
    result
}

fn add_counts(total: &mut PairCounts, add: &PairCounts) {
    total.r#static += add.r#static;
    total.dynamic += add.dynamic;
    total.runtime += add.runtime;
    total.no_origin += add.no_origin;
    total.only_a += add.only_a;
    total.only_b += add.only_b;
    total.redacted += add.redacted;
}

fn field_key(scope: ConsumedScope, field: &str, occurrence: usize) -> (u8, String, usize) {
    let name = match scope {
        ConsumedScope::Header | ConsumedScope::Cookie => field.to_ascii_lowercase(),
        _ => field.to_string(),
    };
    (scope as u8, name, occurrence)
}

fn compare_pair(
    ctx_a: &FlowContext<'_>,
    ctx_b: &FlowContext<'_>,
    ea: &Entry,
    eb: &Entry,
    how: &str,
    out_of_order: bool,
) -> PairComparison {
    let pos_a = ctx_a.find(&ea.id).expect("posição A");
    let pos_b = ctx_b.find(&eb.id).expect("posição B");
    let ca = ctx_a.consumed_for(pos_a);
    let cb = ctx_b.consumed_for(pos_b);
    let mut index_b: HashMap<(u8, String, usize), usize> = HashMap::new();
    for (n, c) in cb.iter().enumerate() {
        index_b.insert(field_key(c.scope, &c.field, c.occurrence), n);
    }
    let mut used = vec![false; cb.len()];
    let mut fields: Vec<FieldDiff> = Vec::new();
    for c in ca.iter() {
        let key = field_key(c.scope, &c.field, c.occurrence);
        match index_b.get(&key) {
            Some(&n) => {
                used[n] = true;
                let other = &cb[n];
                let class = if is_redacted(&c.value) || is_redacted(&other.value) {
                    FieldClass::Redacted
                } else if c.value == other.value {
                    FieldClass::Static
                } else {
                    FieldClass::Dynamic
                };
                fields.push(FieldDiff {
                    scope: c.scope,
                    field: c.field.clone(),
                    occurrence: c.occurrence,
                    class,
                    label: String::new(),
                    origin_label: None,
                    dynamic_kind: None,
                    a: Some(preview(&c.value)),
                    b: Some(preview(&other.value)),
                    origin: None,
                    parts: Vec::new(),
                });
            }
            None => fields.push(FieldDiff {
                scope: c.scope,
                field: c.field.clone(),
                occurrence: c.occurrence,
                class: FieldClass::OnlyA,
                label: String::new(),
                origin_label: None,
                dynamic_kind: None,
                a: Some(preview(&c.value)),
                b: None,
                origin: None,
                parts: Vec::new(),
            }),
        }
    }
    for (n, c) in cb.iter().enumerate() {
        if !used[n] {
            fields.push(FieldDiff {
                scope: c.scope,
                field: c.field.clone(),
                occurrence: c.occurrence,
                class: FieldClass::OnlyB,
                label: String::new(),
                origin_label: None,
                dynamic_kind: None,
                a: None,
                b: Some(preview(&c.value)),
                origin: None,
                parts: Vec::new(),
            });
        }
    }

    // Origens de B, só se houver campo dinâmico.
    if fields.iter().any(|f| f.class == FieldClass::Dynamic) {
        let origins: Option<ValueOrigins> = origins_in(ctx_b, &eb.id).ok();
        for diff in fields.iter_mut().filter(|f| f.class == FieldClass::Dynamic) {
            let a_value = ca
                .iter()
                .find(|c| {
                    field_key(c.scope, &c.field, c.occurrence)
                        == field_key(diff.scope, &diff.field, diff.occurrence)
                })
                .map(|c| c.value.clone())
                .unwrap_or_default();
            let b_value = cb
                .iter()
                .find(|c| {
                    field_key(c.scope, &c.field, c.occurrence)
                        == field_key(diff.scope, &diff.field, diff.occurrence)
                })
                .map(|c| c.value.clone())
                .unwrap_or_default();
            let entry = origins.as_ref().and_then(|o| {
                o.values.iter().find(|v| {
                    v.parent.is_none()
                        && v.scope == diff.scope
                        && v.occurrence == diff.occurrence
                        && field_key(v.scope, &v.field, v.occurrence)
                            == field_key(diff.scope, &diff.field, diff.occurrence)
                })
            });
            let opaque = diff.scope == ConsumedScope::Body
                && a_value.len() >= OPAQUE_MIN
                && b_value.len() >= OPAQUE_MIN
                && !entry.is_some_and(|v| {
                    matches!(v.status, OriginStatus::Origin | OriginStatus::Ambiguous)
                });
            if opaque {
                diff.dynamic_kind = Some(DynamicKind::Composite);
                let subs: Vec<&ValueOrigin> = origins
                    .as_ref()
                    .map(|o| {
                        o.values
                            .iter()
                            .filter(|v| {
                                v.parent.as_deref() == Some(diff.field.as_str())
                                    && v.occurrence == diff.occurrence
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                for (a0, a1, b0, b1) in
                    diff_regions(a_value.as_bytes(), b_value.as_bytes(), options_cap(ctx_b))
                {
                    let covering = subs.iter().find(|v| {
                        !v.evidences.is_empty()
                            && v.offset.is_some_and(|offset| {
                                let (s, l) = (offset as usize, v.length);
                                s < b1.max(b0 + 1) && b0 < s + l
                            })
                    });
                    let b_token = match covering {
                        Some(v) => v.value.clone(),
                        None => window_around(&b_value, b0, b1),
                    };
                    let a_token = window_around(&a_value, a0, a1);
                    diff.parts.push(PartDiff {
                        class: FieldClass::Dynamic,
                        label: "dinâmico".to_string(),
                        a_offset: a0 as u64,
                        b_offset: b0 as u64,
                        a: a_token,
                        b: b_token,
                        dynamic_kind: covering.map_or(DynamicKind::NoOrigin, |v| kind_of(v)),
                        origin_label: String::new(),
                        origin: covering.and_then(|v| summary(v)),
                    });
                }
                diff.parts
                    .extend(static_runs(&a_value, &b_value, options_cap(ctx_b)));
                diff.parts.sort_by_key(|p| p.b_offset);
                if !diff.parts.iter().any(|p| p.class == FieldClass::Dynamic) {
                    diff.dynamic_kind = Some(DynamicKind::NoOrigin);
                }
            } else if let Some(v) = entry {
                diff.dynamic_kind = Some(kind_of(v));
                diff.origin = summary(v);
            } else {
                diff.dynamic_kind = Some(DynamicKind::NoOrigin);
            }
        }
    }

    for f in &mut fields {
        f.label = match f.class {
            FieldClass::Static => "estático",
            FieldClass::Dynamic => "dinâmico",
            FieldClass::OnlyA => "só em A",
            FieldClass::OnlyB => "só em B",
            FieldClass::Redacted => "redigido",
        }
        .to_string();
        f.origin_label = origin_label(f.dynamic_kind, f.origin.as_ref());
        for part in &mut f.parts {
            if part.class == FieldClass::Dynamic {
                part.origin_label =
                    origin_label(Some(part.dynamic_kind), part.origin.as_ref()).unwrap_or_default();
            }
        }
    }
    let mut counts = PairCounts::default();
    for f in &fields {
        match f.class {
            FieldClass::Static => counts.r#static += 1,
            FieldClass::Dynamic => {
                counts.dynamic += 1;
                let runtime = match f.dynamic_kind {
                    Some(DynamicKind::Runtime) => true,
                    Some(DynamicKind::Composite) => f
                        .parts
                        .iter()
                        .any(|p| p.dynamic_kind == DynamicKind::Runtime),
                    _ => false,
                };
                if runtime {
                    counts.runtime += 1;
                } else {
                    counts.no_origin += 1;
                }
            }
            FieldClass::OnlyA => counts.only_a += 1,
            FieldClass::OnlyB => counts.only_b += 1,
            FieldClass::Redacted => counts.redacted += 1,
        }
    }
    PairComparison {
        a: request_ref(ea),
        b: request_ref(eb),
        aligned_by: how.to_string(),
        out_of_order,
        fields,
        counts,
    }
}

/// Trechos comuns (>= 8 bytes) entre as duas versões do campo opaco.
fn static_runs(a: &str, b: &str, cap: usize) -> Vec<PartDiff> {
    let regions = diff_regions(a.as_bytes(), b.as_bytes(), cap);
    let (mut ca, mut cb) = (0usize, 0usize);
    let mut spans: Vec<(usize, usize, usize)> = Vec::new(); // (a0, b0, len)
    for (a0, a1, b0, b1) in &regions {
        if a0 - ca == b0 - cb && a0 - ca >= 8 {
            spans.push((ca, cb, a0 - ca));
        }
        ca = *a1;
        cb = *b1;
    }
    if a.len() - ca == b.len() - cb && a.len() - ca >= 8 {
        spans.push((ca, cb, a.len() - ca));
    }
    spans
        .into_iter()
        .filter_map(|(a0, b0, len)| {
            let text = a.get(a0..a0 + len)?.to_string();
            Some(PartDiff {
                class: FieldClass::Static,
                label: "estático".to_string(),
                a_offset: a0 as u64,
                b_offset: b0 as u64,
                a: text.clone(),
                b: text,
                dynamic_kind: DynamicKind::NoOrigin,
                origin_label: String::new(),
                origin: None,
            })
        })
        .collect()
}

fn origin_label(kind: Option<DynamicKind>, origin: Option<&OriginSummary>) -> Option<String> {
    match kind? {
        DynamicKind::Runtime => Some(match origin {
            Some(o) if o.ambiguous => {
                format!("obter em runtime (origem: {}, ambíguo)", o.request_id)
            }
            Some(o) => format!("obter em runtime (origem: {})", o.request_id),
            None => "obter em runtime".to_string(),
        }),
        DynamicKind::NoOrigin => Some("dinâmico sem origem".to_string()),
        DynamicKind::Repeated => Some("dinâmico sem origem (valor já circulava)".to_string()),
        DynamicKind::Composite => None,
    }
}

fn options_cap(ctx: &FlowContext<'_>) -> usize {
    ctx.options.max_opaque_cells
}
