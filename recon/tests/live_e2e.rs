//! Ponta a ponta: sessões reais capturadas pelo ScrapeLens (Chrome headless,
//! servidor em loopback que imita sinais documentados) → `site_profile`.
//! `recon/scripts/live_e2e.sh` gera as sessões e roda este teste.

use std::path::PathBuf;

use scrapelens_core::lazy::LazySession;
use scrapelens_core::model::SessionV1;
use scrapelens_core::search::LazyBodies;
use scrapelens_recon::{site_profile, Confidence, ProfileOptions, RecommendationValue};

fn load(name: &str) -> (LazySession, SessionV1) {
    let root = PathBuf::from(std::env::var("SL_RECON_E2E_DIR").expect("SL_RECON_E2E_DIR"));
    let dir = root.join(name);
    let text = std::fs::read(dir.join("session.json")).expect("session.json");
    let session: SessionV1 = serde_json::from_slice(&text).expect("sessão válida");
    (LazySession::new(session.clone(), dir), session)
}

#[test]
#[ignore]
fn live_plain_site_needs_nothing() {
    let (lazy, session) = load("plain");
    let p = site_profile(&session, &LazyBodies(&lazy), &ProfileOptions::default());
    println!("{}", serde_json::to_string_pretty(&p).unwrap());
    assert!(p.findings.iter().any(|f| f.signature_id.as_deref() == Some("cf-006")), "cf-ray");
    assert!(p.findings.iter().any(|f| f.signature_id.as_deref() == Some("cf-001")), "__cf_bm");
    assert!(!p.findings.iter().any(|f| f.category == "bloqueio" || f.category == "desafio"));
    assert_eq!(p.recommendation.value, RecommendationValue::ChromeNormalBasta, "{:#?}", p.recommendation);
    let json = serde_json::to_string(&p).unwrap();
    assert!(!json.contains("SEGREDO-BM-1"));
    // Todo id de evidência resolve na sessão.
    for f in &p.findings {
        for e in &f.evidence {
            assert!(session.find_request(&e.request_id).is_some(), "{} sem requisição", e.request_id);
        }
    }
}

#[test]
#[ignore]
fn live_unsolved_challenge_is_cloakbrowser_candidate() {
    let (lazy, session) = load("unsolved");
    let p = site_profile(&session, &LazyBodies(&lazy), &ProfileOptions::default());
    println!("{}", serde_json::to_string_pretty(&p).unwrap());
    let cf = p.findings.iter().find(|f| f.signature_id.as_deref() == Some("cf-005")).expect("cf-mitigated");
    assert_eq!(cf.confidence, Confidence::Alta);
    assert_eq!(cf.resolved_later, Some(false));
    // O Turnstile não carregou (allowlist): fica a tentativa e o achado de terceiro.
    assert!(p.findings.iter().any(|f| f.category == "terceiro-bloqueado" && f.summary.contains("challenges.cloudflare.com")));
    assert!(p.findings.iter().any(|f| f.signature_id.as_deref() == Some("cf-007")));
    assert_eq!(p.recommendation.value, RecommendationValue::CandidatoACloakbrowser, "{:#?}", p.recommendation);
    assert!(p.recommendation.limits.iter().any(|l| l.contains("allowlist")));
}

#[test]
#[ignore]
fn live_solved_challenge_needs_priming() {
    let (lazy, session) = load("solved");
    let p = site_profile(&session, &LazyBodies(&lazy), &ProfileOptions::default());
    println!("{}", serde_json::to_string_pretty(&p).unwrap());
    let cf = p.findings.iter().find(|f| f.signature_id.as_deref() == Some("cf-005")).expect("cf-mitigated");
    assert_eq!(cf.resolved_later, Some(true));
    assert!(p.findings.iter().any(|f| f.signature_id.as_deref() == Some("cf-002")), "cf_clearance");
    assert_eq!(p.recommendation.value, RecommendationValue::PrecisaDePriming, "{:#?}", p.recommendation);
    assert!(!serde_json::to_string(&p).unwrap().contains("SEGREDO-CLEARANCE-9"));
}
