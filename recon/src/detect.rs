//! Detection: signatures (data) + generic findings (status, protocol,
//! cookies, tokens). Only reads the session; nothing opens the network.

use std::collections::{BTreeMap, BTreeSet};

use scrapelens_core::flow::{
    value_origins, ConsumedScope, FlowOptions, OriginStatus, ProducerScope,
};
use scrapelens_core::model::{
    Attempt, Body, CookieField, HeaderView, LogicalRequest, Protocol, SessionV1, SetCookieRecord,
    TargetKind,
};
use scrapelens_core::search::BodySource;

use crate::signatures::{SigKind, Signature, SignatureSet, SourceKind, Weight};
use crate::{Confidence, Evidence, Finding, ProfileOptions, Sample, SourceRef};

/// One attempt (or the request, when there are no attempts) with everything
/// that detection reads.
struct View<'a> {
    index: usize,
    started: Option<f64>,
    req: &'a LogicalRequest,
    attempt_id: Option<&'a str>,
    url: &'a str,
    status: Option<u16>,
    failure: Option<&'a str>,
    req_headers: &'a HeaderView,
    resp_headers: &'a HeaderView,
    set_cookies: &'a [SetCookieRecord],
    cookie: &'a CookieField,
    req_body: &'a Body,
    resp_body: &'a Body,
}

fn views(session: &SessionV1) -> Vec<View<'_>> {
    let mut out = Vec::new();
    for (index, req) in session.requests.iter().enumerate() {
        if req.attempts.is_empty() {
            out.push(View {
                index,
                started: req.timings.request_time,
                req,
                attempt_id: None,
                url: &req.url,
                status: req.status,
                failure: None,
                req_headers: &req.request_headers,
                resp_headers: &req.response_headers,
                set_cookies: &req.set_cookies,
                cookie: &req.cookie,
                req_body: &req.request_body,
                resp_body: &req.response_body,
            });
            continue;
        }
        for attempt in &req.attempts {
            out.push(attempt_view(index, req, attempt));
        }
    }
    // The order of `session.requests` is not chronological (Core sorts by id).
    // "Before/after" uses the start of the attempt when ALL have a time (same
    // capture clock); otherwise the session order applies.
    if !out.is_empty() && out.iter().all(|v| v.started.is_some()) {
        out.sort_by(|a, b| {
            a.started
                .partial_cmp(&b.started)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }
    for (i, v) in out.iter_mut().enumerate() {
        v.index = i;
    }
    out
}

fn attempt_view<'a>(index: usize, req: &'a LogicalRequest, a: &'a Attempt) -> View<'a> {
    View {
        index,
        started: a.started_at.or(req.timings.request_time),
        req,
        attempt_id: Some(&a.id),
        url: &a.url,
        status: a.status,
        failure: a.failure.as_deref(),
        req_headers: &a.request_headers,
        resp_headers: &a.response_headers,
        set_cookies: &a.set_cookies,
        cookie: &a.cookie,
        req_body: &a.request_body,
        resp_body: &a.response_body,
    }
}

// --- utilities ------------------------------------------------------------

fn redacted(len: usize) -> String {
    format!("[redacted, {len} bytes]")
}

/// URL without query or fragment (they may carry tokens).
fn safe_url(url: &str) -> String {
    let cut = url.find(['?', '#']).unwrap_or(url.len());
    if cut == url.len() {
        url.to_string()
    } else {
        format!("{}?…", &url[..cut])
    }
}

fn url_parts(url: &str) -> Option<(String, String, String)> {
    // (origin, host, path)
    let (scheme, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let authority = authority.rsplit_once('@').map(|(_, a)| a).unwrap_or(authority);
    let host = if let Some(inner) = authority.strip_prefix('[') {
        inner.split(']').next().unwrap_or("").to_string()
    } else {
        authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(authority).to_string()
    };
    let path_start = &rest[end..];
    let path_end = path_start.find(['?', '#']).unwrap_or(path_start.len());
    let path = if path_start.is_empty() { "/" } else { &path_start[..path_end] };
    Some((
        format!("{}://{}", scheme.to_ascii_lowercase(), authority.to_ascii_lowercase()),
        host.to_ascii_lowercase(),
        path.to_string(),
    ))
}

fn route_key(url: &str) -> String {
    match url_parts(url) {
        Some((origin, _, path)) => format!("{origin}{path}"),
        None => url.to_string(),
    }
}

fn rtype(req: &LogicalRequest) -> String {
    req.resource_type.clone().unwrap_or_default().to_ascii_lowercase()
}

fn is_document(req: &LogicalRequest) -> bool {
    rtype(req) == "document"
}

fn is_static(req: &LogicalRequest) -> bool {
    matches!(
        rtype(req).as_str(),
        "script" | "stylesheet" | "image" | "font" | "media" | "manifest" | "texttrack" | "other" | "ping" | "prefetch"
    )
}

/// Application route: document, XHR/fetch or write; never static.
fn is_app(req: &LogicalRequest) -> bool {
    if is_static(req) {
        return false;
    }
    true
}

fn is_xhr_like(req: &LogicalRequest) -> bool {
    matches!(rtype(req).as_str(), "xhr" | "fetch")
        || (rtype(req).is_empty() && !matches!(req.method.to_ascii_uppercase().as_str(), "GET" | "HEAD"))
}

fn cookie_set_name(record: &SetCookieRecord) -> Option<String> {
    record
        .name()
        .map(str::to_string)
        .or_else(|| record.raw.split_once('=').map(|(n, _)| n.trim().to_string()))
        .filter(|n| !n.is_empty())
}

fn source_of(entry: &scrapelens_core::model::HeaderEntry) -> Option<String> {
    Some(entry.provenance.source.as_str().to_string())
}

fn evidence(
    v: &View<'_>,
    scope: &str,
    field: Option<&str>,
    value: Option<String>,
    source: Option<String>,
) -> Evidence {
    Evidence {
        request_id: v.req.id.clone(),
        attempt_id: v.attempt_id.map(str::to_string),
        scope: scope.to_string(),
        field: field.map(str::to_string),
        value,
        url: safe_url(v.url),
        status: v.status,
        source,
        third_party: false,
    }
}

fn load_text(bodies: &dyn BodySource, body: &Body, limit: usize) -> Option<String> {
    let name = body.attachment.as_deref()?;
    if !body.has_bytes() {
        return None;
    }
    let loaded = bodies.load(name)?;
    let bytes = &loaded.bytes[..loaded.bytes.len().min(limit)];
    Some(String::from_utf8_lossy(bytes).to_string())
}

// --- signatures -------------------------------------------------------------

struct Hit {
    evidence: Evidence,
    block: bool,
    view_index: usize,
    blocked_by_allowlist: bool,
    /// The value was a block value, but the observed HTTP status is not the documented one
    /// (observed, documented).
    status_mismatch: Option<(u16, u16)>,
}

fn name_in(names: &[String], prefixes: &[String], name: &str) -> bool {
    names.iter().any(|n| n == name) || prefixes.iter().any(|p| name.starts_with(p.as_str()))
}

fn header_hits(sig: &Signature, v: &View<'_>, response: bool) -> Vec<Hit> {
    let name = sig.name.as_deref().unwrap_or("");
    let view = if response { v.resp_headers } else { v.req_headers };
    let mut hits = Vec::new();
    for entry in view.get_all(name) {
        let value = entry.value.trim().to_ascii_lowercase();
        if !sig.values.is_empty() && !sig.values.contains(&value) {
            continue;
        }
        let mut block = sig.weight == Weight::Block
            && (sig.block_values.contains(&value)
                || (!sig.block_unless.is_empty() && !sig.block_unless.contains(&value)));
        // The documentation fixes the status that goes with the value (AWS WAF: 202 for
        // challenge, 405 for captcha). Another status is not that action.
        let mut status_mismatch = None;
        if block {
            if let (Some(expected), Some(observed)) = (sig.value_status.get(&value), v.status) {
                if *expected != observed {
                    block = false;
                    status_mismatch = Some((observed, *expected));
                }
            }
        }
        let known = sig.values.contains(&value)
            || sig.block_values.contains(&value)
            || sig.block_unless.contains(&value);
        // Documented enumeration values and numeric status codes
        // (e.g. X-DataDomeResponse: 403) may appear; the rest is redacted.
        let numeric_status = !sig.block_unless.is_empty()
            && !value.is_empty()
            && value.len() <= 3
            && value.bytes().all(|b| b.is_ascii_digit());
        let shown = if known || numeric_status {
            Some(entry.value.trim().to_string())
        } else {
            Some(redacted(entry.value.len()))
        };
        hits.push(Hit {
            evidence: evidence(
                v,
                if response { "response-header" } else { "request-header" },
                Some(&entry.name),
                shown,
                source_of(entry),
            ),
            block,
            view_index: v.index,
            blocked_by_allowlist: false,
            status_mismatch,
        });
    }
    hits
}

fn cookie_hits(sig: &Signature, v: &View<'_>) -> Vec<Hit> {
    let mut hits = Vec::new();
    for record in v.set_cookies {
        let Some(name) = cookie_set_name(record) else { continue };
        if name_in(&sig.names, &sig.prefixes, &name) {
            let len = record.parsed.as_ref().map(|p| p.value.len()).unwrap_or(0);
            hits.push(Hit {
                evidence: evidence(
                    v,
                    "set-cookie",
                    Some(&name),
                    Some(redacted(len)),
                    Some(record.provenance.source.as_str().to_string()),
                ),
                block: false,
                view_index: v.index,
                blocked_by_allowlist: false,
                status_mismatch: None,
            });
        }
    }
    for pair in &v.cookie.pairs {
        if name_in(&sig.names, &sig.prefixes, &pair.name) {
            hits.push(Hit {
                evidence: evidence(
                    v,
                    "request-cookie",
                    Some(&pair.name),
                    Some(redacted(pair.value.len())),
                    Some(pair.provenance.source.as_str().to_string()),
                ),
                block: false,
                view_index: v.index,
                blocked_by_allowlist: false,
                status_mismatch: None,
            });
        }
    }
    hits
}

fn host_hit(sig: &Signature, v: &View<'_>) -> Option<Hit> {
    let (_, host, path) = url_parts(v.url)?;
    let host_ok = match (&sig.host, &sig.host_suffix) {
        (Some(h), _) if host == h.to_ascii_lowercase() => true,
        (_, Some(s)) => {
            let s = s.to_ascii_lowercase();
            host == s || host.ends_with(&format!(".{s}"))
        }
        _ => false,
    };
    if !host_ok {
        return None;
    }
    if let Some(prefix) = &sig.path_prefix {
        if !path.to_ascii_lowercase().starts_with(&prefix.to_ascii_lowercase()) {
            return None;
        }
    }
    if let Some(part) = &sig.path_contains {
        if !path.to_ascii_lowercase().contains(&part.to_ascii_lowercase()) {
            return None;
        }
    }
    Some(Hit {
        evidence: evidence(v, "url", None, None, None),
        block: false,
        view_index: v.index,
        blocked_by_allowlist: v
            .failure
            .map(|f| f.contains("ERR_NAME_NOT_RESOLVED"))
            .unwrap_or(false),
        status_mismatch: None,
    })
}

fn path_hit(sig: &Signature, v: &View<'_>) -> Option<Hit> {
    let (_, _, path) = url_parts(v.url)?;
    let prefix = sig.path_prefix.as_ref()?.to_ascii_lowercase();
    path.to_ascii_lowercase().starts_with(&prefix).then(|| Hit {
        evidence: evidence(v, "url", None, None, None),
        block: false,
        view_index: v.index,
        blocked_by_allowlist: false,
                status_mismatch: None,
    })
}

fn field_in_text(text: &str, name: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let n = name.to_ascii_lowercase();
    // `name="field"`, `name='field'`, JSON `"field":`, form `field=` and `&field=`.
    lower.contains(&format!("name=\"{n}\""))
        || lower.contains(&format!("name='{n}'"))
        || lower.contains(&format!("\"{n}\":"))
        || lower.starts_with(&format!("{n}="))
        || lower.contains(&format!("&{n}="))
        || lower.contains(&format!("?{n}="))
}

fn form_hits(sig: &Signature, v: &View<'_>, bodies: &dyn BodySource, limit: usize) -> Vec<Hit> {
    let name = sig.name.as_deref().unwrap_or("");
    let mut hits = Vec::new();
    if let Some((_, query)) = v.url.split_once('?') {
        if field_in_text(query, name) {
            hits.push(Hit {
                evidence: evidence(v, "query", Some(name), None, None),
                block: false,
                view_index: v.index,
                blocked_by_allowlist: false,
                status_mismatch: None,
            });
        }
    }
    if let Some(text) = load_text(bodies, v.req_body, limit) {
        if field_in_text(&text, name) {
            hits.push(Hit {
                evidence: evidence(v, "request-body", Some(name), None, None),
                block: false,
                view_index: v.index,
                blocked_by_allowlist: false,
                status_mismatch: None,
            });
        }
    }
    let html = v
        .resp_body
        .content_type
        .as_deref()
        .map(|c| c.to_ascii_lowercase().contains("html"))
        .unwrap_or(false);
    if html {
        if let Some(text) = load_text(bodies, v.resp_body, limit) {
            if field_in_text(&text, name) {
                hits.push(Hit {
                    evidence: evidence(v, "response-body", Some(name), None, None),
                    block: false,
                    view_index: v.index,
                    blocked_by_allowlist: false,
                status_mismatch: None,
                });
            }
        }
    }
    hits
}

fn signature_hits(sig: &Signature, v: &View<'_>, bodies: &dyn BodySource, limit: usize) -> Vec<Hit> {
    match sig.kind {
        SigKind::Cookie => cookie_hits(sig, v),
        SigKind::ResponseHeader => header_hits(sig, v, true),
        SigKind::RequestHeader => header_hits(sig, v, false),
        SigKind::Host => host_hit(sig, v).into_iter().collect(),
        SigKind::Path => path_hit(sig, v).into_iter().collect(),
        SigKind::FormField => form_hits(sig, v, bodies, limit),
    }
}

fn host_of(url: &str) -> String {
    url_parts(url).map(|(_, host, _)| host).unwrap_or_default()
}

/// Same site, conservatively: equal, or one is a subdomain of the other. There is no
/// public suffix list here (declared limit).
fn same_site(a: &str, b: &str) -> bool {
    !a.is_empty() && !b.is_empty() && (a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}")))
}

/// Hosts of the top-level documents (the target site's). Third-party iframes are
/// not included: a captcha iframe does not make the captcha host "the site".
fn target_hosts(vs: &[View<'_>]) -> BTreeSet<String> {
    vs.iter()
        .filter(|v| {
            is_document(v.req)
                && v.req.target.as_ref().map(|t| t.kind != TargetKind::Iframe).unwrap_or(true)
        })
        .map(|v| host_of(v.url))
        .filter(|h| !h.is_empty())
        .collect()
}

fn is_foreign(url: &str, targets: &BTreeSet<String>) -> bool {
    if targets.is_empty() {
        return false;
    }
    let host = host_of(url);
    !targets.iter().any(|t| same_site(&host, t))
}

/// Only 2xx resolves a challenge: a 3xx may be the redirect to the challenge itself.
fn is_ok2xx(status: Option<u16>) -> bool {
    matches!(status, Some(200..=299))
}

fn is_success(status: Option<u16>) -> bool {
    matches!(status, Some(200..=399))
}

/// Was there a 2xx response AFTER on the same route, or a clearance cookie set
/// AFTER by the same site? A redirect (3xx) does not resolve it (it may lead to
/// the challenge itself), and a cookie from another host does not clear this one.
fn resolved_after(
    vs: &[View<'_>],
    sigs: &SignatureSet,
    hit: &Hit,
) -> bool {
    let route = route_key(&hit.evidence.url);
    let hit_host = host_of(&hit.evidence.url);
    let later_same_route = vs.iter().any(|v| {
        v.index > hit.view_index && route_key(v.url) == route && is_ok2xx(v.status)
    });
    if later_same_route {
        return true;
    }
    sigs.signatures.iter().filter(|s| s.clearance).any(|s| {
        vs.iter()
            .filter(|v| v.index > hit.view_index && same_site(&host_of(v.url), &hit_host))
            .any(|v| v.set_cookies.iter().any(|r| {
                cookie_set_name(r)
                    .map(|n| name_in(&s.names, &s.prefixes, &n))
                    .unwrap_or(false)
            }))
    })
}

fn confidence_of(sig: &Signature, block: bool) -> Confidence {
    match (sig.source.kind, block) {
        (SourceKind::Vendor, true) => Confidence::High,
        (_, true) => Confidence::Medium,
        (SourceKind::Vendor, false) => Confidence::Medium,
        (SourceKind::Project, false) | (SourceKind::Secondary, false) => Confidence::Low,
    }
}

fn is_weak_scope(scope: &str) -> bool {
    // Reflected text, a query controllable by whoever creates the link, and a cookie
    // that only appears in the request (may come from `document.cookie`): weak evidence.
    matches!(scope, "query" | "request-body" | "response-body" | "request-cookie")
}

fn signature_findings(
    vs: &[View<'_>],
    bodies: &dyn BodySource,
    opts: &ProfileOptions,
    sigs: &SignatureSet,
    targets: &BTreeSet<String>,
) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    for sig in &sigs.signatures {
        let mut hits: Vec<Hit> = Vec::new();
        for v in vs {
            hits.extend(signature_hits(sig, v, bodies, opts.body_limit));
        }
        if hits.is_empty() {
            continue;
        }
        // Cookie, header and path seen on a resource from ANOTHER host do not
        // attribute the protection to the target site (script/form field are
        // references embedded by the page itself and fall outside this rule).
        if matches!(
            sig.kind,
            SigKind::Cookie | SigKind::ResponseHeader | SigKind::RequestHeader | SigKind::Path
        ) {
            for h in &mut hits {
                if is_foreign(&h.evidence.url, targets) {
                    h.evidence.third_party = true;
                    h.block = false;
                    h.status_mismatch = None;
                }
            }
        }
        let own_exists = hits.iter().any(|h| !h.evidence.third_party);
        let pool: Vec<&Hit> = if own_exists {
            hits.iter().filter(|h| !h.evidence.third_party).collect()
        } else {
            hits.iter().collect()
        };
        let foreign_only = !own_exists;
        let any_block = pool.iter().any(|h| h.block);
        let used: Vec<&Hit> = if any_block {
            pool.iter().copied().filter(|h| h.block).collect()
        } else {
            pool.clone()
        };
        let occurrences = used.len();
        let mut limits: Vec<String> = Vec::new();
        if used.iter().any(|h| h.blocked_by_allowlist) {
            limits.push(
                "loading was blocked by the allowlist (ERR_NAME_NOT_RESOLVED): the script did not run, only the attempt was seen"
                    .to_string(),
            );
        }
        if sig.source.kind != SourceKind::Vendor {
            limits.push(format!(
                "signature from source {}: indication, not proof",
                sig.source.kind.as_str()
            ));
        }
        if sig.kind == SigKind::Path {
            limits.push("a path citation alone does not indicate a block".to_string());
        }
        let mut confidence = confidence_of(sig, any_block);
        if foreign_only {
            let hosts: BTreeSet<String> =
                used.iter().map(|h| host_of(&h.evidence.url)).collect();
            limits.push(format!(
                "seen only on a resource from another host ({}), not in the target site's documents ({}): does not attribute the protection to the target",
                hosts.into_iter().collect::<Vec<_>>().join(", "),
                targets.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
            confidence = Confidence::Low;
        }
        // Observed status differs from the documented one (AWS WAF: 202/405): it is not
        // the documented action, so it is not a challenge.
        let mismatches: Vec<(u16, u16)> = used.iter().filter_map(|h| h.status_mismatch).collect();
        if !any_block && !mismatches.is_empty() {
            let (seen, expected) = mismatches[0];
            limits.push(format!(
                "observed status {seen} differs from the documented one ({expected}) for this value: product presence, not a challenge served"
            ));
            confidence = Confidence::Low;
        }
        // Presence only in body, query or request cookie: low.
        if !foreign_only && used.iter().all(|h| is_weak_scope(&h.evidence.scope)) {
            let scopes: BTreeSet<&str> = used.iter().map(|h| h.evidence.scope.as_str()).collect();
            limits.push(format!(
                "evidence only in {}: may be reflected text, a query controllable by third parties, or a cookie created by the page's JavaScript",
                scopes.into_iter().collect::<Vec<_>>().join(", ")
            ));
            confidence = Confidence::Low;
        }
        let resolved_later = any_block.then(|| used.iter().all(|h| resolved_after(vs, sigs, h)));
        let evidence_list: Vec<Evidence> = used
            .iter()
            .take(opts.max_evidence)
            .map(|h| h.evidence.clone())
            .collect();
        let mut category = sig.category.clone();
        if !any_block && category == "challenge" {
            // E.g.: X-DataDomeResponse: 200 — the product is present, it did not challenge.
            category = "protection".to_string();
        }
        findings.push(Finding {
            id: String::new(),
            category,
            vendor: Some(sig.vendor.clone()),
            kind: sig.kind.as_str().to_string(),
            signature_id: Some(sig.id.clone()),
            summary: sig.summary.clone(),
            confidence,
            occurrences,
            evidence: evidence_list,
            source: Some(SourceRef {
                kind: sig.source.kind.as_str().to_string(),
                url: sig.source.url.clone(),
            }),
            resolved_later,
            limits,
        });
    }
    // A form field only in body/query is raised to `media` when the SAME
    // vendor has an independent, strong indication (script, header
    // or cookie from the vendor's source, on the target site).
    let strong_vendors: BTreeMap<String, String> = findings
        .iter()
        .filter(|f| {
            f.kind != "form-field"
                && f.confidence >= Confidence::Medium
                && f.source.as_ref().map(|s| s.kind.as_str()) == Some("vendor")
                && f.evidence.iter().any(|e| !e.third_party || f.kind == "script-host")
        })
        .filter_map(|f| Some((f.vendor.clone()?, f.signature_id.clone()?)))
        .collect();
    for f in &mut findings {
        if f.kind == "form-field" && f.confidence == Confidence::Low {
            if let Some(other) = f.vendor.as_ref().and_then(|v| strong_vendors.get(v)) {
                f.confidence = Confidence::Medium;
                f.limits.push(format!("corroborated by {other} from the same vendor"));
            }
        }
    }
    // Two or more independent secondary-source indications from the same
    // vendor are raised to `media`.
    let mut secondary: BTreeMap<String, usize> = BTreeMap::new();
    for f in &findings {
        if f.source.as_ref().map(|s| s.kind.as_str()) == Some("secondary") && f.limits.iter().all(|l| !l.contains("another host")) {
            if let Some(v) = &f.vendor {
                *secondary.entry(v.clone()).or_default() += 1;
            }
        }
    }
    for f in &mut findings {
        let multi = f
            .vendor
            .as_ref()
            .map(|v| secondary.get(v).copied().unwrap_or(0) >= 2)
            .unwrap_or(false);
        if multi
            && f.source.as_ref().map(|s| s.kind.as_str()) == Some("secondary")
            && f.confidence == Confidence::Low
            && f.limits.iter().all(|l| !l.contains("another host") && !l.contains("evidence only in"))
        {
            f.confidence = Confidence::Medium;
            f.limits.push("two or more secondary-source indications from the same vendor".to_string());
        }
    }
    findings
}

// --- generic findings ------------------------------------------------------

fn status_findings(
    vs: &[View<'_>],
    sigs: &SignatureSet,
    opts: &ProfileOptions,
    targets: &BTreeSet<String>,
) -> Vec<Finding> {
    // (status, from another host?) -> responses. A block on a resource from another host
    // is not a block of the target site.
    let mut by_status: BTreeMap<(u16, bool), Vec<&View<'_>>> = BTreeMap::new();
    for v in vs {
        if let Some(s @ (403 | 429 | 503)) = v.status {
            if is_app(v.req) {
                by_status.entry((s, is_foreign(v.url, targets))).or_default().push(v);
            }
        }
    }
    let first_doc = vs.iter().find(|v| is_document(v.req)).map(|v| v.req.id.clone());
    let mut out = Vec::new();
    for ((status, foreign), list) in by_status {
        let mut unresolved = 0usize;
        let mut hits_for_resolution = Vec::new();
        for v in &list {
            let hit = Hit {
                evidence: evidence(v, "status", None, None, None),
                block: true,
                view_index: v.index,
                blocked_by_allowlist: false,
                status_mismatch: None,
            };
            if !resolved_after(vs, sigs, &hit) {
                unresolved += 1;
            }
            hits_for_resolution.push(hit);
        }
        let main_blocked = list.iter().any(|v| Some(&v.req.id) == first_doc.as_ref());
        let app_unresolved = unresolved > 0;
        let confidence = if foreign {
            Confidence::Low
        } else if app_unresolved && (main_blocked || list.iter().any(|v| is_document(v.req) || is_xhr_like(v.req))) {
            Confidence::High
        } else {
            Confidence::Medium
        };
        let mut evidence_list: Vec<Evidence> = Vec::new();
        for v in list.iter().take(opts.max_evidence) {
            evidence_list.push(evidence(v, "status", None, Some(status.to_string()), None));
            if let Some(retry) = v.resp_headers.first_value("retry-after") {
                evidence_list.push(evidence(
                    v,
                    "response-header",
                    Some("retry-after"),
                    Some(retry.trim().to_string()),
                    None,
                ));
            }
        }
        evidence_list.truncate(opts.max_evidence * 2);
        if foreign {
            for e in &mut evidence_list {
                e.third_party = true;
            }
        }
        let label = match status {
            403 => "403 (forbidden)",
            429 => "429 (rate limit)",
            _ => "503 (unavailable)",
        };
        out.push(Finding {
            id: String::new(),
            category: "block".to_string(),
            vendor: None,
            kind: "status".to_string(),
            signature_id: None,
            summary: if foreign {
                format!("{} response(s) {} on a resource from another host", list.len(), label)
            } else {
                format!(
                    "{} response(s) {} on an application route{}",
                    list.len(),
                    label,
                    if main_blocked { ", including the main document" } else { "" }
                )
            },
            confidence,
            occurrences: list.len(),
            evidence: evidence_list,
            source: None,
            resolved_later: if foreign { None } else { Some(!app_unresolved) },
            limits: if foreign {
                vec![format!(
                    "resource from another host than the target site's documents ({}): does not count as a site block",
                    targets.iter().cloned().collect::<Vec<_>>().join(", ")
                )]
            } else {
                vec!["the status alone does not say who blocked; it applies to this capture".to_string()]
            },
        });
    }
    out
}

fn origin_of(url: &str) -> Option<String> {
    url_parts(url).map(|(origin, _, _)| origin)
}

fn protocol_name(p: Protocol) -> Option<&'static str> {
    match p {
        Protocol::H1 => Some("h1"),
        Protocol::H2 => Some("h2"),
        Protocol::H3 => Some("h3"),
        Protocol::Unknown => None,
    }
}

pub(crate) fn sample(session: &SessionV1) -> Sample {
    let mut protocols: BTreeMap<String, BTreeSet<&'static str>> = BTreeMap::new();
    let mut documents = 0;
    let mut app = 0;
    for req in &session.requests {
        if is_document(req) {
            documents += 1;
        }
        if is_app(req) && (is_document(req) || is_xhr_like(req)) {
            app += 1;
        }
        let proto = req
            .attempts
            .last()
            .map(|a| a.protocol)
            .filter(|p| *p != Protocol::Unknown)
            .unwrap_or(req.protocol);
        if let (Some(name), Some(origin)) = (protocol_name(proto), origin_of(&req.url)) {
            protocols.entry(origin).or_default().insert(name);
        }
    }
    Sample {
        requests: session.requests.len(),
        documents,
        app_requests: app,
        partial: session.session.completeness.state != scrapelens_core::model::CompletenessState::Complete,
        protocols: protocols
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().map(str::to_string).collect()))
            .collect(),
    }
}

fn protocol_findings(session: &SessionV1, vs: &[View<'_>], opts: &ProfileOptions) -> Vec<Finding> {
    let sample = sample(session);
    let doc_origins: BTreeSet<String> = vs
        .iter()
        .filter(|v| is_document(v.req))
        .filter_map(|v| origin_of(v.url))
        .collect();
    let mut out = Vec::new();
    for origin in doc_origins {
        let Some(list) = sample.protocols.get(&origin) else { continue };
        if !list.iter().any(|p| p == "h2" || p == "h3") {
            continue;
        }
        let evidence_list: Vec<Evidence> = session
            .requests
            .iter()
            .filter(|r| origin_of(&r.url).as_deref() == Some(origin.as_str()))
            .take(opts.max_evidence)
            .map(|r| Evidence {
                request_id: r.id.clone(),
                attempt_id: r.attempts.last().map(|a| a.id.clone()),
                scope: "protocol".to_string(),
                field: None,
                value: protocol_name(r.protocol).map(str::to_string),
                url: safe_url(&r.url),
                status: r.status,
                source: None,
                third_party: false,
            })
            .collect();
        out.push(Finding {
            id: String::new(),
            category: "protocol".to_string(),
            vendor: None,
            kind: "protocol".to_string(),
            signature_id: None,
            summary: format!("protocol observed on {origin}: {}", list.join(", ")),
            confidence: Confidence::Medium,
            occurrences: evidence_list.len(),
            evidence: evidence_list,
            source: None,
            resolved_later: None,
            limits: vec![
                "observed, not required: proving the requirement needs an h1 attempt that fails".to_string(),
            ],
        });
    }
    out
}

fn cookie_flow_findings(vs: &[View<'_>], sigs: &SignatureSet, opts: &ProfileOptions) -> Vec<Finding> {
    // name → index (in `vs`) of the first definition.
    let mut producer: BTreeMap<String, usize> = BTreeMap::new();
    for (i, v) in vs.iter().enumerate() {
        for record in v.set_cookies {
            if let Some(name) = cookie_set_name(record) {
                producer.entry(name).or_insert(i);
            }
        }
    }
    let mut consumers: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, v) in vs.iter().enumerate() {
        for pair in &v.cookie.pairs {
            if let Some(p) = producer.get(&pair.name) {
                if *p < i {
                    consumers.entry(pair.name.clone()).or_default().push(i);
                }
            }
        }
    }
    let mut names: Vec<(String, Vec<usize>)> = consumers.into_iter().collect();
    names.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
    names.truncate(10);
    let mut out = Vec::new();
    for (name, list) in names {
        let p = &vs[producer[&name]];
        let vendor = sigs
            .signatures
            .iter()
            .find(|s| s.kind == SigKind::Cookie && name_in(&s.names, &s.prefixes, &name))
            .map(|s| s.vendor.clone());
        let mut evidence_list = vec![evidence(
            p,
            "set-cookie",
            Some(&name),
            None,
            None,
        )];
        for i in list.iter().take(opts.max_evidence.saturating_sub(1)) {
            evidence_list.push(evidence(&vs[*i], "request-cookie", Some(&name), None, None));
        }
        out.push(Finding {
            id: String::new(),
            category: "cookie".to_string(),
            vendor,
            kind: "cookie-flow".to_string(),
            signature_id: None,
            summary: format!(
                "cookie `{name}` set by {} and resent in {} following request(s)",
                route_key(p.url),
                list.len()
            ),
            confidence: Confidence::Medium,
            occurrences: list.len(),
            evidence: evidence_list,
            source: None,
            resolved_later: None,
            limits: vec![
                "observed: set and resent in the same capture; being REQUIRED needs removing it and testing (validate_run)".to_string(),
            ],
        });
    }
    out
}

fn token_findings(
    session: &SessionV1,
    vs: &[View<'_>],
    bodies: &dyn BodySource,
    opts: &ProfileOptions,
    warnings: &mut Vec<String>,
) -> Vec<Finding> {
    let targets: Vec<String> = match &opts.target_request_id {
        Some(id) => vec![id.clone()],
        None => {
            let mut seen = BTreeSet::new();
            let mut picked: Vec<String> = Vec::new();
            for v in vs.iter().rev() {
                if !is_xhr_like(v.req) || !is_success(v.status) {
                    continue;
                }
                let key = format!("{} {}", v.req.method, route_key(v.url));
                if seen.insert(key) {
                    picked.push(v.req.id.clone());
                }
                if picked.len() >= opts.max_token_targets {
                    break;
                }
            }
            picked
        }
    };
    let flow_opts = FlowOptions::default();
    let mut out: Vec<Finding> = Vec::new();
    let mut seen_keys = BTreeSet::new();
    let mut redacted_total = 0usize;
    for target in targets {
        let origins = match value_origins(session, bodies, &target, &flow_opts) {
            Ok(o) => o,
            Err(e) => {
                warnings.push(format!("flow::value_origins({target}): {e}"));
                continue;
            }
        };
        redacted_total += origins.redacted_values;
        for value in &origins.values {
            if value.status != OriginStatus::Origin
                || value.confidence.is_none()
                || value.length < 8
                || value.scope == ConsumedScope::Cookie
            {
                continue;
            }
            let strong = value.confidence == Some(scrapelens_core::flow::Confidence::Strong);
            let Some(ev) = value.evidences.get(value.oldest.unwrap_or(0)).or_else(|| value.evidences.first()) else {
                continue;
            };
            let key = (value.field.clone(), ev.request_id.clone());
            if !seen_keys.insert(key) {
                continue;
            }
            let consumer = vs.iter().find(|v| v.req.id == target);
            let producer = vs.iter().find(|v| v.req.id == ev.request_id);
            let (Some(consumer), Some(producer)) = (consumer, producer) else { continue };
            let scope_name = match value.scope {
                ConsumedScope::Query => "query",
                ConsumedScope::Header => "request-header",
                ConsumedScope::Body => "request-body",
                ConsumedScope::Cookie => "request-cookie",
            };
            let producer_scope = match ev.scope {
                ProducerScope::SetCookie => "set-cookie",
                ProducerScope::ResponseHeader => "response-header",
                ProducerScope::Location => "location",
                ProducerScope::ResponseBody => "response-body",
            };
            out.push(Finding {
                id: String::new(),
                category: "token".to_string(),
                vendor: None,
                kind: "token-origin".to_string(),
                signature_id: None,
                summary: format!(
                    "dynamic value `{}` ({} B) in {} comes from {} ({})",
                    value.field,
                    value.length,
                    route_key(consumer.url),
                    route_key(producer.url),
                    producer_scope
                ),
                confidence: if strong { Confidence::Medium } else { Confidence::Low },
                occurrences: 1,
                evidence: vec![
                    evidence(consumer, scope_name, Some(&value.field), Some(redacted(value.length)), None),
                    Evidence {
                        request_id: ev.request_id.clone(),
                        attempt_id: Some(ev.attempt_id.clone()),
                        scope: producer_scope.to_string(),
                        field: ev.field.clone(),
                        value: None,
                        url: safe_url(producer.url),
                        status: producer.status,
                        source: None,
                        third_party: false,
                    },
                ],
                source: None,
                resolved_later: None,
                limits: vec![format!(
                    "origin by value equality (flow::value_origins, {}); does not prove the value is required",
                    if strong { "strong evidence" } else { "medium evidence only: possible origin" }
                )],
            });
        }
    }
    if redacted_total > 0 {
        warnings.push(format!(
            "{redacted_total} redacted value(s) in the session could not be traced"
        ));
    }
    out
}

fn blocked_host_findings(session: &SessionV1) -> Vec<Finding> {
    let mut out = Vec::new();
    for w in &session.warnings {
        if w.code != "capture.third_party_blocked" {
            continue;
        }
        let host = w
            .detail
            .as_ref()
            .and_then(|d| d.get("host"))
            .and_then(|h| h.as_str())
            .unwrap_or("?")
            .to_string();
        let requests = w
            .detail
            .as_ref()
            .and_then(|d| d.get("requests"))
            .and_then(|n| n.as_u64())
            .unwrap_or(0) as usize;
        out.push(Finding {
            id: String::new(),
            category: "third-party-blocked".to_string(),
            vendor: None,
            kind: "blocked-host".to_string(),
            signature_id: None,
            summary: format!(
                "the page tried to load {host} ({requests} request(s)) and the allowlist blocked it; a protection or resource may be hidden"
            ),
            confidence: Confidence::High,
            occurrences: requests,
            evidence: Vec::new(),
            source: None,
            resolved_later: None,
            limits: vec![
                "redo the capture with this host in third_party_hosts (new confirmation) to see what it serves".to_string(),
            ],
        });
    }
    out
}

pub(crate) fn detect(
    session: &SessionV1,
    bodies: &dyn BodySource,
    opts: &ProfileOptions,
    sigs: &SignatureSet,
    warnings: &mut Vec<String>,
) -> Vec<Finding> {
    let vs = views(session);
    let mut findings = Vec::new();
    let targets = target_hosts(&vs);
    findings.extend(signature_findings(&vs, bodies, opts, sigs, &targets));
    findings.extend(status_findings(&vs, sigs, opts, &targets));
    findings.extend(blocked_host_findings(session));
    findings.extend(protocol_findings(session, &vs, opts));
    findings.extend(cookie_flow_findings(&vs, sigs, opts));
    findings.extend(token_findings(session, &vs, bodies, opts, warnings));
    findings
}
