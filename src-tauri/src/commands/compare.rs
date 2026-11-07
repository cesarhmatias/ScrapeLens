//! Comparing two sessions: the summary, the pages and the fields of a comparison.

use super::*;

/// Comparison kept in Rust: the UI receives only the summary and requests pages of pairs
/// and the fields of a pair on demand (avoids tens of MB of JSON over IPC).
pub(super) struct StoredComparison {
    pub(super) id: u64,
    pub(super) result: Arc<scrapelens_core::compare::SessionComparison>,
}

pub(super) static COMPARISON: Mutex<Option<StoredComparison>> = Mutex::new(None);

pub(super) static COMPARISON_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub(super) const ONLY_LIST_CAP: usize = 200;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompareSummary {
    pub handle: u64,
    pub pairs: usize,
    /// Pairs with at least one field that is not static (candidates for the "only dynamic" filter).
    pub dynamic_pairs: usize,
    pub counts: scrapelens_core::compare::PairCounts,
    pub parts_counts: scrapelens_core::compare::PartsCounts,
    pub redacted_fields: usize,
    pub ambiguities: Vec<String>,
    pub warnings: Vec<String>,
    pub only_in_a: Vec<scrapelens_core::compare::RequestRef>,
    pub only_in_a_total: usize,
    pub only_in_b: Vec<scrapelens_core::compare::RequestRef>,
    pub only_in_b_total: usize,
    /// Leftovers of the same model on both sides (probable reordering), limited.
    pub reordered: Vec<scrapelens_core::compare::ReorderedPair>,
    pub reordered_total: usize,
    /// Paired rounds, unpaired rounds and the entry request (docs/10 L6).
    pub rounds: Vec<scrapelens_core::compare::RoundInfo>,
    pub unpaired_rounds: Vec<scrapelens_core::compare::UnpairedRound>,
    pub entry_request: Option<String>,
    /// Protection/static fields outside the alignment: type + totals, with limited lists.
    pub groups: Vec<GroupSummary>,
    pub include_all: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupSummary {
    pub kind: String,
    pub a: Vec<scrapelens_core::compare::RequestRef>,
    pub a_total: usize,
    pub b: Vec<scrapelens_core::compare::RequestRef>,
    pub b_total: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairSummary {
    pub index: usize,
    /// Index into `rounds`.
    pub round: usize,
    pub a: scrapelens_core::compare::RequestRef,
    pub b: scrapelens_core::compare::RequestRef,
    pub aligned_by: String,
    pub out_of_order: bool,
    pub counts: scrapelens_core::compare::PairCounts,
    pub parts_counts: scrapelens_core::compare::PartsCounts,
    pub field_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComparePage {
    /// Pairs that pass the filter (not only those on this page).
    pub total: usize,
    pub items: Vec<PairSummary>,
}

pub(super) fn pair_is_dynamic(pair: &scrapelens_core::compare::PairComparison) -> bool {
    let c = &pair.counts;
    c.dynamic + c.only_a + c.only_b + c.redacted > 0
}

/// Compares the open session (A) with another folder (B), off the UI thread.
#[tauri::command]
pub async fn compare_open(
    token_a: String,
    token_b: String,
    include_all: Option<bool>,
    a_range: Option<String>,
    b_range: Option<String>,
) -> Result<CompareSummary, String> {
    let dir_a = session_dir_for_token(&token_a)?;
    let dir_b = session_dir_for_token(&token_b)?;
    tauri::async_runtime::spawn_blocking(move || {
        let options = compare_options(
            include_all.unwrap_or(false),
            a_range.as_deref(),
            b_range.as_deref(),
        )?;
        open_comparison_with(&dir_a, &dir_b, options)
    })
    .await
    .map_err(|error| format!("the comparison was interrupted: {error}"))?
}

/// Page of pairs (summaries, without fields).
#[tauri::command]
pub async fn compare_page(
    handle: u64,
    offset: usize,
    limit: usize,
    only_dynamic: bool,
) -> Result<ComparePage, String> {
    tauri::async_runtime::spawn_blocking(move || {
        comparison_page(handle, offset, limit, only_dynamic)
    })
    .await
    .map_err(|error| format!("the read was interrupted: {error}"))?
}

/// Fields of a pair (in source order), loaded on expansion.
#[tauri::command]
pub async fn compare_fields(
    handle: u64,
    index: usize,
) -> Result<Vec<scrapelens_core::compare::FieldDiff>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let result = stored_comparison(handle)?;
        result
            .pairs
            .get(index)
            .map(|pair| pair.fields.clone())
            .ok_or_else(|| format!("pair {index} does not exist"))
    })
    .await
    .map_err(|error| format!("the read was interrupted: {error}"))?
}

pub(super) fn stored_comparison(
    handle: u64,
) -> Result<Arc<scrapelens_core::compare::SessionComparison>, String> {
    let guard = COMPARISON
        .lock()
        .map_err(|_| "comparison corrupted".to_string())?;
    match guard.as_ref() {
        Some(stored) if stored.id == handle => Ok(stored.result.clone()),
        _ => Err("this comparison was replaced by another; compare again".to_string()),
    }
}

pub(super) fn comparison_page(
    handle: u64,
    offset: usize,
    limit: usize,
    only_dynamic: bool,
) -> Result<ComparePage, String> {
    let result = stored_comparison(handle)?;
    let limit = limit.clamp(1, 500);
    let mut total = 0usize;
    let mut items = Vec::new();
    for (index, pair) in result.pairs.iter().enumerate() {
        if only_dynamic && !pair_is_dynamic(pair) {
            continue;
        }
        if total >= offset && items.len() < limit {
            items.push(PairSummary {
                index,
                round: pair.round,
                a: pair.a.clone(),
                b: pair.b.clone(),
                aligned_by: pair.aligned_by.clone(),
                out_of_order: pair.out_of_order,
                counts: pair.counts.clone(),
                parts_counts: pair.parts_counts.clone(),
                field_count: pair.fields.len(),
            });
        }
        total += 1;
    }
    Ok(ComparePage { total, items })
}

/// Canonicalized paths (resolves `./s`, `s` and symlinks): the same session through
/// two paths is refused.
pub(super) fn compare_options(
    include_all: bool,
    a_range: Option<&str>,
    b_range: Option<&str>,
) -> Result<scrapelens_core::compare::CompareOptions, String> {
    use scrapelens_core::compare::RequestRange;
    let range = |label: &str, text: Option<&str>| -> Result<Option<RequestRange>, String> {
        match text.map(str::trim).filter(|t| !t.is_empty()) {
            None => Ok(None),
            Some(text) => RequestRange::parse(text)
                .map(Some)
                .ok_or_else(|| format!("invalid {label} range ({text}); use from:to, for example 10:50 or har-0010:har-0050")),
        }
    };
    Ok(scrapelens_core::compare::CompareOptions {
        include_all,
        a_range: range("A", a_range)?,
        b_range: range("B", b_range)?,
        flow: crate::adapters::flow_options(),
        ..Default::default()
    })
}

#[cfg(test)]
pub(super) fn open_comparison(dir_a: &str, dir_b: &str) -> Result<CompareSummary, String> {
    open_comparison_with(
        dir_a,
        dir_b,
        scrapelens_core::compare::CompareOptions::default(),
    )
}

pub(super) fn open_comparison_with(
    dir_a: &str,
    dir_b: &str,
    options: scrapelens_core::compare::CompareOptions,
) -> Result<CompareSummary, String> {
    let canon = |label: &str, dir: &str| {
        fs::canonicalize(dir)
            .map_err(|error| format!("session {label} is inaccessible ({dir}): {error}"))
    };
    let a_path = canon("A", dir_a)?;
    let b_path = canon("B", dir_b)?;
    if a_path == b_path {
        return Err(format!(
            "A and B are the same session ({}); choose another folder to compare",
            a_path.display()
        ));
    }
    let a = cached_session(&a_path)?;
    let b = cached_session(&b_path).map_err(|error| format!("session B: {error}"))?;
    let result = scrapelens_core::compare::compare_sessions(
        &a.session,
        &scrapelens_core::search::LazyBodies(&a),
        &b.session,
        &scrapelens_core::search::LazyBodies(&b),
        &options,
    );
    let id = COMPARISON_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let summary = CompareSummary {
        handle: id,
        pairs: result.pairs.len(),
        dynamic_pairs: result
            .pairs
            .iter()
            .filter(|pair| pair_is_dynamic(pair))
            .count(),
        counts: result.counts.clone(),
        parts_counts: result.parts_counts.clone(),
        redacted_fields: result.redacted_fields,
        ambiguities: result
            .ambiguities
            .iter()
            .take(ONLY_LIST_CAP)
            .cloned()
            .collect(),
        warnings: result.warnings.clone(),
        only_in_a: result
            .only_in_a
            .iter()
            .take(ONLY_LIST_CAP)
            .cloned()
            .collect(),
        only_in_a_total: result.only_in_a.len(),
        only_in_b: result
            .only_in_b
            .iter()
            .take(ONLY_LIST_CAP)
            .cloned()
            .collect(),
        only_in_b_total: result.only_in_b.len(),
        reordered: result
            .reordered
            .iter()
            .take(ONLY_LIST_CAP)
            .cloned()
            .collect(),
        reordered_total: result.reordered.len(),
        rounds: result.rounds.clone(),
        unpaired_rounds: result.unpaired_rounds.clone(),
        entry_request: result.entry_request.clone(),
        groups: result
            .groups
            .iter()
            .map(|group| GroupSummary {
                kind: group.kind.clone(),
                a: group.a.iter().take(ONLY_LIST_CAP).cloned().collect(),
                a_total: group.a.len(),
                b: group.b.iter().take(ONLY_LIST_CAP).cloned().collect(),
                b_total: group.b.len(),
            })
            .collect(),
        include_all: options.include_all,
    };
    *COMPARISON
        .lock()
        .map_err(|_| "comparison corrupted".to_string())? = Some(StoredComparison {
        id,
        result: Arc::new(result),
    });
    Ok(summary)
}
