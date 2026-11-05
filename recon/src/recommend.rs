//! Deterministic recommendation (`docs/16b-mcp-navegador.md` §5.3).

use scrapelens_core::model::SessionV1;

use crate::signatures::SignatureSet;
use crate::{Confidence, Finding, Recommendation, RecommendationValue, Sample};

fn is_doc(rt: &Option<String>) -> bool {
    rt.as_deref().map(|r| r.eq_ignore_ascii_case("document")).unwrap_or(false)
}

pub(crate) fn recommend(
    session: &SessionV1,
    sample: &Sample,
    partial: bool,
    findings: &[Finding],
    sigs: &SignatureSet,
) -> Recommendation {
    let mut limits = vec![
        format!(
            "sample: one capture with {} request(s); does not prove behavior in other sessions",
            sample.requests
        ),
        "no human interaction beyond the navigation performed; pages behind login/action were not seen".to_string(),
        "\"blocked\" and \"passed\" apply to normal Chrome in this capture".to_string(),
    ];
    let blocked_hosts: Vec<String> = findings
        .iter()
        .filter(|f| f.category == "third-party-blocked")
        .map(|f| f.summary.clone())
        .collect();
    if !blocked_hosts.is_empty() {
        limits.push(format!(
            "third-party hosts were blocked by the allowlist and may hide protection ({} host(s)); see the `third-party-blocked` findings",
            blocked_hosts.len()
        ));
    }

    let main_doc = session
        .requests
        .iter()
        .find(|r| is_doc(&r.resource_type));
    let main_status = main_doc.and_then(|r| r.status);

    // 1. Indeterminate.
    let mut why: Vec<String> = Vec::new();
    if partial {
        why.push("the session is marked partial/incomplete by Core".to_string());
    }
    if sample.requests < 2 {
        why.push("fewer than 2 requests".to_string());
    }
    if main_doc.is_none() || main_status.is_none() {
        why.push("no main document with a response".to_string());
    }
    if !why.is_empty() {
        return Recommendation {
            value: RecommendationValue::Undetermined,
            confidence: Confidence::Low,
            reasons: why,
            limits,
            based_on: Vec::new(),
        };
    }

    // 2. Candidate for CloakBrowser: normal Chrome was blocked and nothing resolved it.
    let hard: Vec<&Finding> = findings
        .iter()
        .filter(|f| {
            matches!(f.category.as_str(), "challenge" | "block")
                && f.confidence == Confidence::High
                && f.resolved_later == Some(false)
        })
        .collect();
    if !hard.is_empty() {
        let main_blocked = matches!(main_status, Some(403 | 429 | 503))
            || hard.iter().any(|f| {
                f.evidence
                    .iter()
                    .any(|e| Some(e.request_id.as_str()) == main_doc.map(|r| r.id.as_str()))
            });
        let vendor_based = hard.iter().any(|f| f.signature_id.is_some());
        let mut reasons: Vec<String> = hard.iter().map(|f| format!("{} ({})", f.summary, f.id)).collect();
        reasons.push(
            "normal Chrome was blocked and there was no successful response afterwards on the same route, nor a clearance cookie".to_string(),
        );
        limits.push(
            "this does NOT prove that CloakBrowser would pass; it is the trigger to revisit this topic (D6)".to_string(),
        );
        return Recommendation {
            value: RecommendationValue::CloakbrowserCandidate,
            confidence: if main_blocked && vendor_based { Confidence::High } else { Confidence::Medium },
            reasons,
            limits,
            based_on: hard.iter().map(|f| f.id.clone()).collect(),
        };
    }

    // 3. Needs priming.
    let resolved_challenges: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.category == "challenge" && f.resolved_later == Some(true))
        .collect();
    let tokens: Vec<&Finding> = findings.iter().filter(|f| f.kind == "token-origin").collect();
    // Only a reused CLEARANCE cookie (cf_clearance, aws-waf-token) counts as
    // priming. A presence cookie (`__cf_bm`, `datadome`, `_px3`, `bm_sv`…) is
    // resent by any client with a cookie jar: it becomes an observation, not a trigger.
    let is_clearance = |f: &Finding| {
        f.kind == "cookie-flow"
            && f.evidence
                .first()
                .and_then(|e| e.field.as_deref())
                .map(|name| {
                    sigs.signatures.iter().any(|s| {
                        s.clearance
                            && (s.names.iter().any(|n| n == name)
                                || s.prefixes.iter().any(|p| name.starts_with(p.as_str())))
                    })
                })
                .unwrap_or(false)
    };
    let protection_cookie_flow: Vec<&Finding> =
        findings.iter().filter(|f| is_clearance(f)).collect();
    let passive_cookie_flow: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.kind == "cookie-flow" && f.vendor.is_some() && !is_clearance(f))
        .collect();
    let mut priming: Vec<&Finding> = Vec::new();
    priming.extend(&resolved_challenges);
    priming.extend(&tokens);
    priming.extend(&protection_cookie_flow);
    if !priming.is_empty() {
        let mut reasons = Vec::new();
        for f in &resolved_challenges {
            reasons.push(format!(
                "a challenge was served and solved in the browser itself ({}, {}); a client without a browser needs to reproduce that exchange",
                f.summary, f.id
            ));
        }
        for f in &tokens {
            reasons.push(format!("{} ({})", f.summary, f.id));
        }
        for f in &protection_cookie_flow {
            reasons.push(format!(
                "protection cookie ({}) set and resent: {} ({})",
                f.vendor.as_deref().unwrap_or("?"),
                f.summary,
                f.id
            ));
        }
        limits.push(
            "\"needs priming\" is what the capture OBSERVED circulating; that each item is required is only proven by removing it (validate_run)".to_string(),
        );
        let confidence = if !resolved_challenges.is_empty() {
            Confidence::High
        } else if !protection_cookie_flow.is_empty() || tokens.iter().any(|f| f.confidence >= Confidence::Medium) {
            Confidence::Medium
        } else {
            Confidence::Low // only "possible origin" of token
        };
        return Recommendation {
            value: RecommendationValue::NeedsPriming,
            confidence,
            reasons,
            limits,
            based_on: priming.iter().map(|f| f.id.clone()).collect(),
        };
    }

    // 4. Chrome normal basta.
    let protections: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.category == "protection" || f.category == "captcha")
        .collect();
    let mut reasons = vec![format!(
        "main document responded {} and no application route was blocked",
        main_status.map(|s| s.to_string()).unwrap_or_else(|| "?".to_string())
    )];
    if !protections.is_empty() {
        reasons.push(format!(
            "protection is passively present ({} finding(s)), with no block in this capture",
            protections.len()
        ));
    }
    for f in &passive_cookie_flow {
        reasons.push(format!(
            "protection cookie ({}) resent by the browser ({}): observed; a client with a cookie jar resends it on its own and the requirement was not proven",
            f.vendor.as_deref().unwrap_or("?"),
            f.id
        ));
    }
    Recommendation {
        value: RecommendationValue::RegularChromeSuffices,
        confidence: if sample.requests >= 5 { Confidence::Medium } else { Confidence::Low },
        reasons,
        limits,
        based_on: protections.iter().map(|f| f.id.clone()).collect(),
    }
}
