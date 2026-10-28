//! Comparação entre duas capturas do mesmo fluxo (`docs/09-cadeia-comparacao.md` §2).
//!
//! ```text
//! pub fn compare_sessions(a: &SessionV1, a_source: &dyn BodySource,
//!                         b: &SessionV1, b_source: &dyn BodySource,
//!                         options: &CompareOptions) -> SessionComparison
//! ```
//!
//! Esquema JSON (camelCase): `{ pairs: [ { a, b: {requestId, method, url}, alignedBy: model|path,
//! outOfOrder, counts, fields: [ { scope, field, occurrence, class: static|dynamic|onlyA|onlyB|redacted,
//! label (estático|dinâmico|só em A|só em B|redigido), dynamicKind: runtime|noOrigin|repeated|composite,
//! originLabel ("obter em runtime (origem: cdp-rNNNN)" | "dinâmico sem origem"), a, b,
//! origin: {kind, requestId, scope, field, ambiguous}, parts: [ { class: static|dynamic, label, aOffset,
//! bOffset, a, b, dynamicKind, originLabel, origin } ] } ] } ], onlyInA[], onlyInB[], reordered: [{a, b}] (sobras de mesmo modelo nos dois lados), ambiguities[],
//! counts, partsCounts, redactedFields, warnings[] }`. `counts` soma campos escalares e os trechos
//! dinâmicos de campos compostos (`dynamic == runtime + noOrigin`); `partsCounts` mostra só a parte dos trechos
//! (e os estáticos).
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
//!   `runtime`; dinâmico sem origem = `noOrigin`; campos opacos (>= 40
//!   caracteres) são comparados por valor inteiro e por trechos que diferem
//!   (`parts`), cada um com a própria origem.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::flow::{
    origins_in, Confidence, ConsumedScope, Evidence, EvidenceKind, FlowContext, FlowOptions,
    OriginStatus, ProducerScope, ValueOrigin, ValueOrigins,
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
    /// `strong` ou `possible` (só evidência média).
    pub confidence: Option<Confidence>,
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

/// Trechos de campos compostos (opacos). Os dinâmicos já estão somados em
/// `PairCounts` (`dynamic == runtime + noOrigin`); aqui eles aparecem separados
/// e os trechos estáticos só existem aqui.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartsCounts {
    pub r#static: usize,
    pub dynamic: usize,
    pub runtime: usize,
    pub no_origin: usize,
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
    /// Campos escalares + trechos dinâmicos de campos compostos (um campo
    /// composto não conta por si; contam os trechos).
    pub counts: PairCounts,
    pub parts_counts: PartsCounts,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReorderedPair {
    pub a: RequestRef,
    pub b: RequestRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionComparison {
    /// Sobras dos dois lados com o MESMO modelo: provavelmente as mesmas
    /// requisições em outra ordem (o pareamento continua monotônico).
    pub reordered: Vec<ReorderedPair>,
    pub pairs: Vec<PairComparison>,
    pub only_in_a: Vec<RequestRef>,
    pub only_in_b: Vec<RequestRef>,
    pub ambiguities: Vec<String>,
    pub counts: PairCounts,
    pub parts_counts: PartsCounts,
    pub redacted_fields: usize,
    pub warnings: Vec<String>,
}

const OPAQUE_MIN: usize = crate::flow::OPAQUE_CONSUMER_MIN;

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
        confidence: value.confidence,
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
        reordered: Vec::new(),
        pairs: Vec::new(),
        only_in_a: Vec::new(),
        only_in_b: Vec::new(),
        ambiguities: Vec::new(),
        counts: PairCounts::default(),
        parts_counts: PartsCounts::default(),
        redacted_fields: 0,
        warnings: Vec::new(),
    };

    // Alinhamento monotônico (sem cruzar a ordem): mesmo modelo pesa mais que
    // só método + host + caminho.
    let (pairs, dropped) = align(&ea, &eb);
    let mut used_a = vec![false; ea.len()];
    let mut used_b = vec![false; eb.len()];
    for (i, j, how) in &pairs {
        used_a[*i] = true;
        used_b[*j] = true;
        if *how == "path" {
            result.ambiguities.push(format!(
                "{} ↔ {}: mesmo método/host/caminho, mas nomes de campos diferentes; pareados por ordem",
                ea[*i].id, eb[*j].id
            ));
        }
    }
    for (i, j) in dropped {
        result.ambiguities.push(format!(
            "{} ↔ {}: mesmo modelo, mas o pareamento cruzaria a ordem; não pareados",
            ea[i].id, eb[j].id
        ));
    }
    let still_a: Vec<usize> = (0..ea.len()).filter(|i| !used_a[*i]).collect();
    let left_b: Vec<usize> = (0..eb.len()).filter(|j| !used_b[*j]).collect();
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
    let mut taken_b = vec![false; left_b.len()];
    for &i in &still_a {
        if let Some(k) = left_b
            .iter()
            .enumerate()
            .position(|(k, &j)| !taken_b[k] && eb[j].model == ea[i].model)
        {
            taken_b[k] = true;
            result.reordered.push(ReorderedPair {
                a: request_ref(&ea[i]),
                b: request_ref(&eb[left_b[k]]),
            });
            result.ambiguities.push(format!(
                "{} ↔ {}: mesmo modelo nas sobras dos dois lados; provavelmente reordenadas",
                ea[i].id, eb[left_b[k]].id
            ));
        }
    }
    for i in still_a {
        result.only_in_a.push(request_ref(&ea[i]));
    }
    for j in left_b {
        result.only_in_b.push(request_ref(&eb[j]));
    }

    let mut max_b_seen: Option<usize> = None;
    for (i, j, how) in pairs {
        let out_of_order = max_b_seen.is_some_and(|m| eb[j].index < m);
        max_b_seen = Some(max_b_seen.map_or(eb[j].index, |m| m.max(eb[j].index)));
        let pair = compare_pair(&ctx_a, &ctx_b, &ea[i], &eb[j], how, out_of_order);
        add_counts(&mut result.counts, &pair.counts);
        result.parts_counts.r#static += pair.parts_counts.r#static;
        result.parts_counts.dynamic += pair.parts_counts.dynamic;
        result.parts_counts.runtime += pair.parts_counts.runtime;
        result.parts_counts.no_origin += pair.parts_counts.no_origin;
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

/// Pareamento A↔B monotônico. Devolve os pares `(i, j, "model"|"path")` em
/// ordem e os pares de mesmo modelo descartados por cruzarem a ordem.
type Aligned = (Vec<(usize, usize, &'static str)>, Vec<(usize, usize)>);

fn align(ea: &[Entry], eb: &[Entry]) -> Aligned {
    let (n, m) = (ea.len(), eb.len());
    let weight = |i: usize, j: usize| -> u32 {
        if ea[i].model == eb[j].model {
            4
        } else if ea[i].base == eb[j].base {
            1
        } else {
            0
        }
    };
    if n.saturating_mul(m) <= 16_000_000 {
        let width = m + 1;
        let mut table = vec![0u32; (n + 1) * width];
        for i in (0..n).rev() {
            for j in (0..m).rev() {
                let mut best = table[(i + 1) * width + j].max(table[i * width + j + 1]);
                let w = weight(i, j);
                if w > 0 {
                    best = best.max(table[(i + 1) * width + j + 1] + w);
                }
                table[i * width + j] = best;
            }
        }
        let (mut i, mut j) = (0, 0);
        let mut pairs = Vec::new();
        while i < n && j < m {
            let w = weight(i, j);
            if w > 0 && table[i * width + j] == table[(i + 1) * width + j + 1] + w {
                pairs.push((i, j, if w == 4 { "model" } else { "path" }));
                i += 1;
                j += 1;
            } else if table[(i + 1) * width + j] >= table[i * width + j + 1] {
                i += 1;
            } else {
                j += 1;
            }
        }
        return (pairs, Vec::new());
    }
    // Sessões enormes: modelo em ordem + maior subsequência crescente.
    let mut by_model: HashMap<&str, Vec<usize>> = HashMap::new();
    for (j, e) in eb.iter().enumerate() {
        by_model.entry(&e.model).or_default().push(j);
    }
    let mut cursor: HashMap<&str, usize> = HashMap::new();
    let mut greedy: Vec<(usize, usize)> = Vec::new();
    for (i, e) in ea.iter().enumerate() {
        let slot = cursor.entry(&e.model).or_default();
        if let Some(&j) = by_model.get(e.model.as_str()).and_then(|v| v.get(*slot)) {
            *slot += 1;
            greedy.push((i, j));
        }
    }
    // LIS por j
    let mut tails: Vec<usize> = Vec::new();
    let mut prev: Vec<Option<usize>> = vec![None; greedy.len()];
    let mut tail_idx: Vec<usize> = Vec::new();
    for (k, (_, j)) in greedy.iter().enumerate() {
        let pos = tails.partition_point(|t| t < j);
        if pos == tails.len() {
            tails.push(*j);
            tail_idx.push(k);
        } else {
            tails[pos] = *j;
            tail_idx[pos] = k;
        }
        prev[k] = if pos > 0 {
            Some(tail_idx[pos - 1])
        } else {
            None
        };
    }
    let mut keep = vec![false; greedy.len()];
    let mut cur = tail_idx.last().copied();
    while let Some(k) = cur {
        keep[k] = true;
        cur = prev[k];
    }
    let pairs = greedy
        .iter()
        .zip(&keep)
        .filter(|(_, k)| **k)
        .map(|((i, j), _)| (*i, *j, "model"))
        .collect();
    let dropped = greedy
        .iter()
        .zip(&keep)
        .filter(|(_, k)| !**k)
        .map(|((i, j), _)| (*i, *j))
        .collect();
    (pairs, dropped)
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
        let origins_a: Option<ValueOrigins> = origins_in(ctx_a, &ea.id).ok();
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
                let subs_of = |o: &Option<ValueOrigins>| -> Vec<ValueOrigin> {
                    o.as_ref()
                        .map(|o| {
                            o.values
                                .iter()
                                .filter(|v| {
                                    v.parent.as_deref() == Some(diff.field.as_str())
                                        && v.occurrence == diff.occurrence
                                        && !v.evidences.is_empty()
                                })
                                .cloned()
                                .collect()
                        })
                        .unwrap_or_default()
                };
                let (subs_a, subs_b) = (subs_of(&origins_a), subs_of(&origins));
                diff.parts = opaque_parts(&a_value, &b_value, &subs_a, &subs_b, options_cap(ctx_b));
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
    let mut parts_counts = PartsCounts::default();
    for f in &fields {
        match f.class {
            FieldClass::Static => counts.r#static += 1,
            FieldClass::Dynamic => {
                let dynamic_parts: Vec<&PartDiff> = f
                    .parts
                    .iter()
                    .filter(|p| p.class == FieldClass::Dynamic)
                    .collect();
                if f.dynamic_kind == Some(DynamicKind::Composite) && !dynamic_parts.is_empty() {
                    for part in dynamic_parts {
                        counts.dynamic += 1;
                        parts_counts.dynamic += 1;
                        if part.dynamic_kind == DynamicKind::Runtime {
                            counts.runtime += 1;
                            parts_counts.runtime += 1;
                        } else {
                            counts.no_origin += 1;
                            parts_counts.no_origin += 1;
                        }
                    }
                } else {
                    counts.dynamic += 1;
                    if f.dynamic_kind == Some(DynamicKind::Runtime) {
                        counts.runtime += 1;
                    } else {
                        counts.no_origin += 1;
                    }
                }
                parts_counts.r#static += f
                    .parts
                    .iter()
                    .filter(|p| p.class == FieldClass::Static)
                    .count();
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
        parts_counts,
    }
}

fn expand_class(text: &str, start: usize, end: usize) -> (usize, usize) {
    let bytes = text.as_bytes();
    let region = &bytes[start.min(bytes.len())..end.min(bytes.len())];
    let upper = |b: u8| b.is_ascii_uppercase() || b.is_ascii_digit();
    let lower = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let class: fn(u8) -> bool = if !region.is_empty() && region.iter().all(|b| upper(*b)) {
        |b| b.is_ascii_uppercase() || b.is_ascii_digit()
    } else if !region.is_empty() && region.iter().all(|b| lower(*b)) {
        |b| b.is_ascii_lowercase() || b.is_ascii_digit()
    } else {
        return (start, end);
    };
    let (mut s, mut e) = (start, end);
    while s > 0 && class(bytes[s - 1]) {
        s -= 1;
    }
    while e < bytes.len() && class(bytes[e]) {
        e += 1;
    }
    (s, e)
}

fn sub_key(v: &ValueOrigin) -> Option<(String, ProducerScope, Option<String>, Option<u64>)> {
    let e = v.evidences.get(v.oldest?)?;
    Some((
        e.request_id.clone(),
        e.scope,
        e.field.clone(),
        e.producer_offset,
    ))
}

/// Trechos de um campo opaco: âncoras = valores conhecidos (com origem) que
/// existem nos dois lados, pareados pelo mesmo produtor; os gaps entre as
/// mesmas âncoras se correspondem e só neles se calcula a diferença. Assim uma
/// âncora nunca corta um valor conhecido e cada trecho dinâmico cobre o valor
/// inteiro (SESSIONID, processId, delta…).
fn opaque_parts(
    a: &str,
    b: &str,
    subs_a: &[ValueOrigin],
    subs_b: &[ValueOrigin],
    cap: usize,
) -> Vec<PartDiff> {
    // pares (sub A, sub B) com a mesma chave de produtor, na ordem
    let mut used_b = vec![false; subs_b.len()];
    let mut pairs: Vec<(usize, usize)> = Vec::new();
    for (i, va) in subs_a.iter().enumerate() {
        let Some(key) = sub_key(va) else { continue };
        if let Some(j) = subs_b
            .iter()
            .enumerate()
            .position(|(j, vb)| !used_b[j] && sub_key(vb).as_ref() == Some(&key))
        {
            used_b[j] = true;
            pairs.push((i, j));
        }
    }
    pairs.sort_by_key(|(i, _)| subs_a[*i].offset);
    // mantém só pares monotônicos nos dois lados e sem sobreposição
    let mut anchors: Vec<(usize, usize, usize, usize, usize)> = Vec::new(); // a0,a1,b0,b1,j
    for (i, j) in pairs {
        let (Some(ao), Some(bo)) = (subs_a[i].offset, subs_b[j].offset) else {
            continue;
        };
        let (a0, b0) = (ao as usize, bo as usize);
        let (a1, b1) = (a0 + subs_a[i].length, b0 + subs_b[j].length);
        if a1 > a.len() || b1 > b.len() {
            continue;
        }
        if anchors.last().map_or(true, |l| a0 >= l.1 && b0 >= l.3) {
            anchors.push((a0, a1, b0, b1, j));
        }
    }
    let mut parts: Vec<PartDiff> = Vec::new();
    let (mut ca, mut cb) = (0usize, 0usize);
    let unpaired_b: Vec<&ValueOrigin> = subs_b
        .iter()
        .enumerate()
        .filter(|(j, _)| !anchors.iter().any(|x| x.4 == *j))
        .map(|(_, v)| v)
        .collect();
    for (a0, a1, b0, b1, j) in anchors {
        gap_parts(a, b, (ca, a0), (cb, b0), &unpaired_b, cap, &mut parts);
        let (ta, tb) = (&a[a0..a1], &b[b0..b1]);
        let sub = &subs_b[j];
        if ta == tb {
            parts.push(static_part(a0, b0, ta));
        } else {
            parts.push(PartDiff {
                class: FieldClass::Dynamic,
                label: "dinâmico".to_string(),
                a_offset: a0 as u64,
                b_offset: b0 as u64,
                a: ta.to_string(),
                b: tb.to_string(),
                dynamic_kind: kind_of(sub),
                origin_label: String::new(),
                origin: summary(sub),
            });
        }
        ca = a1;
        cb = b1;
    }
    gap_parts(
        a,
        b,
        (ca, a.len()),
        (cb, b.len()),
        &unpaired_b,
        cap,
        &mut parts,
    );
    parts.sort_by_key(|p| p.b_offset);
    parts
}

fn static_part(a_off: usize, b_off: usize, text: &str) -> PartDiff {
    PartDiff {
        class: FieldClass::Static,
        label: "estático".to_string(),
        a_offset: a_off as u64,
        b_offset: b_off as u64,
        a: text.to_string(),
        b: text.to_string(),
        dynamic_kind: DynamicKind::NoOrigin,
        origin_label: String::new(),
        origin: None,
    }
}

/// Diferença dentro de um par de gaps correspondentes.
fn gap_parts(
    a: &str,
    b: &str,
    (a_start, a_end): (usize, usize),
    (b_start, b_end): (usize, usize),
    unpaired_b: &[&ValueOrigin],
    cap: usize,
    parts: &mut Vec<PartDiff>,
) {
    let (ga, gb) = (&a[a_start..a_end], &b[b_start..b_end]);
    if ga.is_empty() && gb.is_empty() {
        return;
    }
    if ga == gb {
        if ga.len() >= 8 {
            parts.push(static_part(a_start, b_start, ga));
        }
        return;
    }
    // regiões que diferem, expandidas para o "token" e unidas se sobrepostas
    let mut regions: Vec<(usize, usize, usize, usize)> = Vec::new();
    for (a0, a1, b0, b1) in diff_regions(ga.as_bytes(), gb.as_bytes(), cap) {
        let (ea0, ea1) = expand_class(ga, a0, a1);
        let (eb0, eb1) = expand_class(gb, b0, b1);
        match regions.last_mut() {
            Some(last) if ea0 <= last.1 || eb0 <= last.3 => {
                last.1 = last.1.max(ea1);
                last.3 = last.3.max(eb1);
            }
            _ => regions.push((ea0, ea1, eb0, eb1)),
        }
    }
    let (mut ca, mut cb) = (0usize, 0usize);
    let emit_static = |ca: usize, cb: usize, na: usize, nb: usize, parts: &mut Vec<PartDiff>| {
        if na - ca == nb - cb && na - ca >= 8 {
            parts.push(static_part(a_start + ca, b_start + cb, &ga[ca..na]));
        }
    };
    for (a0, a1, b0, b1) in regions {
        emit_static(ca, cb, a0, b0, parts);
        let abs_b = (b_start + b0, b_start + b1);
        let covering = unpaired_b.iter().find(|v| {
            v.offset.is_some_and(|o| {
                let (s, l) = (o as usize, v.length);
                s < abs_b.1.max(abs_b.0 + 1) && abs_b.0 < s + l
            })
        });
        parts.push(PartDiff {
            class: FieldClass::Dynamic,
            label: "dinâmico".to_string(),
            a_offset: (a_start + a0) as u64,
            b_offset: (b_start + b0) as u64,
            a: ga[a0..a1].to_string(),
            b: covering.map_or_else(|| gb[b0..b1].to_string(), |v| v.value.clone()),
            dynamic_kind: covering.map_or(DynamicKind::NoOrigin, |v| kind_of(v)),
            origin_label: String::new(),
            origin: covering.and_then(|v| summary(v)),
        });
        ca = a1;
        cb = b1;
    }
    emit_static(ca, cb, ga.len(), gb.len(), parts);
}

fn origin_label(kind: Option<DynamicKind>, origin: Option<&OriginSummary>) -> Option<String> {
    match kind? {
        DynamicKind::Runtime => Some(match origin {
            Some(o) => {
                let word = if o.confidence == Some(Confidence::Possible) {
                    "origem possível"
                } else {
                    "origem"
                };
                let amb = if o.ambiguous { ", ambíguo" } else { "" };
                format!("obter em runtime ({word}: {}{amb})", o.request_id)
            }
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
