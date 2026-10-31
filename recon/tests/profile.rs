mod common;

use common::{build, with_main, Req};
use scrapelens_core::model::Protocol;
use scrapelens_recon::{
    site_profile, site_profile_with, Confidence, ProfileOptions, RecommendationValue, SigKind,
    Signature, SignatureSet, SiteProfile, SourceKind, Weight,
};

fn profile(bundle: &scrapelens_core::model::SessionBundle) -> SiteProfile {
    site_profile(&bundle.session, bundle, &ProfileOptions::default())
}

fn finding<'a>(p: &'a SiteProfile, sig: &str) -> Option<&'a scrapelens_recon::Finding> {
    p.findings.iter().find(|f| f.signature_id.as_deref() == Some(sig))
}

// --- tabela de assinaturas ---------------------------------------------------

#[test]
fn embedded_signatures_are_valid_sourced_and_match_the_contract() {
    let set = SignatureSet::embedded();
    set.validate().unwrap();
    let ids: Vec<&str> = set.signatures.iter().map(|s| s.id.as_str()).collect();
    let expected = [
        "cf-001", "cf-002", "cf-003", "cf-004", "cf-005", "cf-006", "cf-007", "cf-008", "aw-001",
        "aw-002", "dd-001", "dd-002", "dd-003", "dd-004", "dd-005", "dd-006", "dd-007", "hm-001",
        "ak-001", "ak-002", "ak-003", "im-001", "rc-001", "rc-002", "rc-003", "hc-001", "hc-002",
        "f5-001",
    ];
    assert_eq!(ids, expected, "a tabela deve coincidir com docs/16b §6.1");
    for s in &set.signatures {
        assert!(!s.source.quote.trim().is_empty(), "{}", s.id);
        match s.source.kind {
            SourceKind::Fornecedor | SourceKind::Secundaria => {
                assert!(s.source.url.starts_with("https://"), "{}: {}", s.id, s.source.url)
            }
            SourceKind::Projeto => assert!(s.source.url.contains("docs/") || s.source.url.contains("core/")),
        }
    }
    // Fontes secundárias nunca chegam a `alta`: só `weight=present`.
    for s in set.signatures.iter().filter(|s| s.source.kind != SourceKind::Fornecedor) {
        assert_eq!(s.weight, Weight::Present, "{}", s.id);
    }
}

#[test]
fn signature_without_source_is_refused() {
    let bad = r#"{"schema":"scrapelens.recon-signatures/1","signatures":[
      {"id":"x-1","vendor":"x","kind":"cookie","names":["a"],"category":"protecao","weight":"present","summary":"s",
       "source":{"kind":"fornecedor","url":"","quote":""}}]}"#;
    assert!(SignatureSet::from_json(bad).unwrap_err().contains("sem fonte"));
    let unknown = r#"{"schema":"outro","signatures":[]}"#;
    assert!(SignatureSet::from_json(unknown).is_err());
}

/// Gera uma requisição que dispara a assinatura (fixture sintética, loopback
/// zero: nenhuma rede). Prova o detector, não a existência da proteção.
fn trigger(sig: &Signature) -> Req {
    let ts = || -> String {
        sig.host
            .clone()
            .or_else(|| sig.host_suffix.clone().map(|s| format!("sub.{s}")))
            .unwrap_or_else(|| "app.test".to_string())
    };
    match sig.kind {
        SigKind::Cookie => {
            let name = sig
                .names
                .first()
                .cloned()
                .unwrap_or_else(|| format!("{}x", sig.prefixes[0]));
            Req::doc("t1", "https://app.test/p", 200).set_cookie(&format!("{name}=SEGREDO123; Path=/"))
        }
        SigKind::ResponseHeader => {
            let value = sig
                .block_values
                .first()
                .or_else(|| sig.values.first())
                .cloned()
                .unwrap_or_else(|| if sig.block_unless.is_empty() { "x".to_string() } else { "403".to_string() });
            let status = sig
                .value_status
                .get(&value)
                .copied()
                .unwrap_or(if sig.weight == Weight::Block { 403 } else { 200 });
            Req::doc("t1", "https://app.test/p", status).rh(sig.name.as_deref().unwrap(), &value)
        }
        SigKind::RequestHeader => Req::xhr("t1", "GET", "https://app.test/api", 200).qh(sig.name.as_deref().unwrap(), "cid-1"),
        SigKind::Host => {
            let mut path = sig.path_prefix.clone().unwrap_or_else(|| "/".to_string());
            if let Some(c) = &sig.path_contains {
                if !path.contains(c.as_str()) {
                    path.push_str(c);
                }
            }
            Req::script("t1", &format!("https://{}{}", ts(), path), 200)
        }
        SigKind::FormField => Req::xhr("t1", "POST", "https://app.test/login", 200)
            .req_body("application/x-www-form-urlencoded", &format!("{}=AAAA&x=1", sig.name.as_deref().unwrap())),
        SigKind::Path => Req::script("t1", &format!("https://app.test{}x.js", sig.path_prefix.as_deref().unwrap()), 200),
    }
}

#[test]
fn every_signature_has_a_synthetic_fixture_that_triggers_it() {
    let set = SignatureSet::embedded();
    for sig in &set.signatures {
        // `rc-001` e `rc-002`: o mesmo host, caminhos diferentes: um não dispara o outro.
        let bundle = with_main(vec![trigger(sig)]);
        let p = profile(&bundle);
        let f = finding(&p, &sig.id).unwrap_or_else(|| panic!("{} não disparou: {:#?}", sig.id, p.findings));
        assert_eq!(f.vendor.as_deref(), Some(sig.vendor.as_str()), "{}", sig.id);
        assert_eq!(f.source.as_ref().unwrap().url, sig.source.url, "{}", sig.id);
        assert!(f.evidence.iter().any(|e| e.request_id == "t1"), "{}: {:?}", sig.id, f.evidence);
        // Redação: o valor sintético do cookie nunca sai.
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("SEGREDO123"), "{} vazou valor", sig.id);
    }
    // E nenhum outro dispara por engano: a sessão só com o documento principal está limpa.
    let clean = profile(&with_main(vec![]));
    assert!(clean.findings.iter().all(|f| f.signature_id.is_none()), "{:#?}", clean.findings);
}

// --- confiança -----------------------------------------------------------------

#[test]
fn confidence_follows_source_and_weight() {
    // fornecedor + bloqueio documentado => alta
    let p = profile(&with_main(vec![Req::doc("c", "https://app.test/x", 403).rh("cf-mitigated", "challenge")]));
    assert_eq!(finding(&p, "cf-005").unwrap().confidence, Confidence::Alta);
    assert_eq!(finding(&p, "cf-005").unwrap().category, "desafio");
    // fornecedor + presença => media
    let p = profile(&with_main(vec![Req::doc("c", "https://app.test/x", 200).set_cookie("__cf_bm=abc; Path=/")]));
    assert_eq!(finding(&p, "cf-001").unwrap().confidence, Confidence::Media);
    // fonte secundária sozinha => baixa
    let p = profile(&with_main(vec![Req::doc("c", "https://app.test/x", 200).set_cookie("incap_ses_1_2=abc; Path=/")]));
    assert_eq!(finding(&p, "im-001").unwrap().confidence, Confidence::Baixa);
    // dois indícios secundários do mesmo fornecedor => media
    let p = profile(&with_main(vec![Req::doc("c", "https://app.test/x", 200)
        .set_cookie("_abck=abc; Path=/")
        .set_cookie("bm_sz=def; Path=/")]));
    assert_eq!(finding(&p, "ak-002").unwrap().confidence, Confidence::Media);
    assert_eq!(finding(&p, "ak-003").unwrap().confidence, Confidence::Media);
    // projeto (/TSPD/): baixa, com a ressalva escrita
    let p = profile(&with_main(vec![Req::script("c", "https://app.test/TSPD/abc?type=1", 200)]));
    let f = finding(&p, "f5-001").unwrap();
    assert_eq!(f.confidence, Confidence::Baixa);
    assert!(f.limits.iter().any(|l| l.contains("não indica bloqueio")));
}

#[test]
fn datadome_response_header_is_block_only_when_not_200() {
    let ok = profile(&with_main(vec![Req::xhr("c", "GET", "https://app.test/a", 200).rh("X-DataDomeResponse", "200")]));
    let f = finding(&ok, "dd-003").unwrap();
    assert_eq!(f.category, "protecao", "200 = permitido: presença, não desafio");
    assert_eq!(f.confidence, Confidence::Media);
    let blocked = profile(&with_main(vec![Req::xhr("c", "GET", "https://app.test/a", 403).rh("X-DataDomeResponse", "403")]));
    let f = finding(&blocked, "dd-003").unwrap();
    assert_eq!(f.category, "desafio");
    assert_eq!(f.confidence, Confidence::Alta);
    assert_eq!(f.evidence[0].value.as_deref(), Some("403"));
}

#[test]
fn secrets_never_leave_in_evidence() {
    let secret = "TOKENSECRETO0987654321";
    let bundle = with_main(vec![
        Req::doc("c", "https://app.test/x?session=TOKENSECRETO0987654321&a=1", 200)
            .set_cookie(&format!("datadome={secret}; Path=/; Secure"))
            .rh("cf-ray", secret)
            .qh("authorization", secret),
        Req::xhr("d", "GET", "https://app.test/y", 200).cookie(&format!("datadome={secret}")),
    ]);
    let p = profile(&bundle);
    let json = serde_json::to_string_pretty(&p).unwrap();
    assert!(!json.contains(secret), "{json}");
    assert!(json.contains("[redigido,"));
    // URL aparece sem a consulta.
    assert!(json.contains("https://app.test/x?…"));
}

// --- bloqueios e recomendação -----------------------------------------------------

#[test]
fn marker_alone_does_not_block_and_chrome_is_enough() {
    let bundle = with_main(vec![
        Req::script("s1", "https://challenges.cloudflare.com/turnstile/v0/api.js", 200),
        Req::doc("d1", "https://app.test/home", 200).rh("cf-ray", "abc-GRU").set_cookie("__cf_bm=zzz; Path=/"),
        Req::xhr("x1", "GET", "https://app.test/api/list", 200),
        Req::xhr("x2", "GET", "https://app.test/api/more", 200),
    ]);
    let p = profile(&bundle);
    assert!(finding(&p, "cf-007").is_some() && finding(&p, "cf-006").is_some());
    assert_eq!(p.recommendation.value, RecommendationValue::ChromeNormalBasta, "{:#?}", p.recommendation);
    assert!(p.findings.iter().all(|f| f.category != "bloqueio" && f.category != "desafio"));
    assert!(p.recommendation.reasons.iter().any(|r| r.contains("passiva")));
}

#[test]
fn unresolved_challenge_on_main_document_is_cloakbrowser_candidate() {
    let bundle = build(vec![
        Req::doc("m", "https://app.test/", 403).rh("cf-mitigated", "challenge").resp_body("text/html", "<html>desafio</html>"),
        Req::script("s", "https://challenges.cloudflare.com/turnstile/v0/api.js", 200),
    ]);
    let p = profile(&bundle);
    let f = finding(&p, "cf-005").unwrap();
    assert_eq!(f.resolved_later, Some(false));
    assert_eq!(p.recommendation.value, RecommendationValue::CandidatoACloakbrowser, "{:#?}", p.recommendation);
    assert_eq!(p.recommendation.confidence, Confidence::Alta);
    assert!(p.recommendation.limits.iter().any(|l| l.contains("NÃO prova")));
    assert!(p.recommendation.based_on.contains(&f.id));
}

#[test]
fn challenge_solved_in_the_browser_needs_priming_not_cloakbrowser() {
    let bundle = build(vec![
        Req::doc("m1", "https://app.test/", 403).rh("cf-mitigated", "challenge").resp_body("text/html", "<html>desafio</html>"),
        Req::doc("m2", "https://app.test/", 200)
            .set_cookie("cf_clearance=ABCDEF; Path=/; Secure")
            .resp_body("text/html", "<html>ok</html>"),
        Req::xhr("x1", "GET", "https://app.test/api", 200).cookie("cf_clearance=ABCDEF"),
    ]);
    let p = profile(&bundle);
    assert_eq!(finding(&p, "cf-005").unwrap().resolved_later, Some(true));
    assert_eq!(p.recommendation.value, RecommendationValue::PrecisaDePriming, "{:#?}", p.recommendation);
    assert_eq!(p.recommendation.confidence, Confidence::Alta);
}

#[test]
fn clearance_cookie_alone_resolves_a_challenge_on_another_route() {
    // O desafio é servido na rota /a; a liberação chega por cookie, depois.
    let bundle = build(vec![
        Req::doc("m", "https://app.test/", 200).resp_body("text/html", "<html></html>"),
        Req::xhr("x1", "GET", "https://app.test/a", 202).rh("x-amzn-waf-action", "challenge"),
        Req::xhr("x2", "GET", "https://app.test/b", 200).set_cookie("aws-waf-token=ZZZ; Path=/"),
    ]);
    let p = profile(&bundle);
    assert_eq!(finding(&p, "aw-001").unwrap().resolved_later, Some(true));
}

#[test]
fn blocked_api_route_that_recovers_is_not_a_candidate() {
    let bundle = with_main(vec![
        Req::xhr("x1", "GET", "https://app.test/api/list", 429).rh("Retry-After", "30"),
        Req::xhr("x2", "GET", "https://app.test/api/list", 200),
    ]);
    let p = profile(&bundle);
    let f = p.findings.iter().find(|f| f.kind == "status").unwrap();
    assert_eq!(f.resolved_later, Some(true));
    assert_eq!(f.confidence, Confidence::Media);
    assert!(f.evidence.iter().any(|e| e.field.as_deref() == Some("retry-after") && e.value.as_deref() == Some("30")));
    assert_ne!(p.recommendation.value, RecommendationValue::CandidatoACloakbrowser);
}

#[test]
fn blocked_api_route_without_recovery_is_alta_and_candidate() {
    let bundle = with_main(vec![Req::xhr("x1", "POST", "https://app.test/api/buscar", 403)]);
    let p = profile(&bundle);
    let f = p.findings.iter().find(|f| f.kind == "status").unwrap();
    assert_eq!(f.confidence, Confidence::Alta);
    assert_eq!(f.resolved_later, Some(false));
    assert_eq!(p.recommendation.value, RecommendationValue::CandidatoACloakbrowser);
    // O documento principal respondeu 200: a confiança da recomendação é menor.
    assert_eq!(p.recommendation.confidence, Confidence::Media);
}

#[test]
fn static_asset_403_is_not_an_application_block() {
    let bundle = with_main(vec![
        Req::new("i1", "GET", "https://cdn.test/logo.png", Some(403), "Image"),
        Req::script("s1", "https://cdn.test/app.js", 403),
    ]);
    let p = profile(&bundle);
    assert!(p.findings.iter().all(|f| f.kind != "status"));
    assert_eq!(p.recommendation.value, RecommendationValue::ChromeNormalBasta);
}

#[test]
fn indeterminate_when_partial_or_too_small_or_without_main_document() {
    // parcial
    let mut b = with_main(vec![Req::xhr("x", "GET", "https://app.test/a", 200)]);
    b.session.session.completeness = scrapelens_core::model::Completeness::partial("NetLog truncado");
    let p = site_profile(&b.session, &b, &ProfileOptions::default());
    assert_eq!(p.recommendation.value, RecommendationValue::Indeterminado);
    assert!(p.sample.partial);
    // uma só requisição
    let p = profile(&build(vec![Req::doc("m", "https://app.test/", 200)]));
    assert_eq!(p.recommendation.value, RecommendationValue::Indeterminado);
    // sem documento principal
    let p = profile(&build(vec![
        Req::xhr("a", "GET", "https://app.test/a", 200),
        Req::xhr("b", "GET", "https://app.test/b", 200),
    ]));
    assert_eq!(p.recommendation.value, RecommendationValue::Indeterminado);
    assert!(p.recommendation.reasons.iter().any(|r| r.contains("documento principal")));
}

// --- achados genéricos -------------------------------------------------------------

#[test]
fn protocol_is_observed_not_required() {
    let bundle = build(vec![
        Req::doc("m", "https://app.test/", 200).proto(Protocol::H2),
        Req::xhr("x", "GET", "https://app.test/a", 200).proto(Protocol::H2),
        Req::new("i", "GET", "https://img.test/a.png", Some(200), "Image").proto(Protocol::H3),
    ]);
    let p = profile(&bundle);
    let f = p.findings.iter().find(|f| f.category == "protocolo").unwrap();
    assert!(f.summary.contains("h2") && f.summary.contains("app.test"));
    assert!(f.limits[0].contains("observado, não exigido"));
    // Só a origem do documento vira achado; a do ícone fica na amostra.
    assert_eq!(p.findings.iter().filter(|f| f.category == "protocolo").count(), 1);
    assert_eq!(p.sample.protocols.get("https://img.test").unwrap(), &vec!["h3".to_string()]);
}

#[test]
fn cookie_flow_is_observed_and_never_called_mandatory() {
    let bundle = build(vec![
        Req::doc("m", "https://app.test/", 200).set_cookie("sessao=ABCDEFGH; Path=/; HttpOnly"),
        Req::xhr("x1", "GET", "https://app.test/a", 200).cookie("sessao=ABCDEFGH"),
        Req::xhr("x2", "GET", "https://app.test/b", 200).cookie("sessao=ABCDEFGH"),
    ]);
    let p = profile(&bundle);
    let f = p.findings.iter().find(|f| f.kind == "cookie-flow").unwrap();
    assert_eq!(f.occurrences, 2);
    assert!(f.limits[0].contains("OBRIGATÓRIO"));
    assert!(f.vendor.is_none());
    // Cookie comum sem fornecedor não vira priming sozinho.
    assert_eq!(p.recommendation.value, RecommendationValue::ChromeNormalBasta);
}

#[test]
fn presence_cookie_reused_is_noted_but_clearance_cookie_reused_means_priming() {
    // `datadome` é cookie de presença/identificação: observação, não gatilho.
    let bundle = build(vec![
        Req::doc("m", "https://app.test/", 200).set_cookie("datadome=ABCDEFGH; Path=/"),
        Req::xhr("x1", "GET", "https://app.test/a", 200).cookie("datadome=ABCDEFGH"),
    ]);
    let p = profile(&bundle);
    let f = p.findings.iter().find(|f| f.kind == "cookie-flow").unwrap();
    assert_eq!(f.vendor.as_deref(), Some("datadome"));
    assert_eq!(p.recommendation.value, RecommendationValue::ChromeNormalBasta);
    assert!(p.recommendation.reasons.iter().any(|r| r.contains("obrigatoriedade não foi provada")));

    // `aws-waf-token` é cookie de liberação: reutilizado => priming (media).
    let bundle = build(vec![
        Req::doc("m", "https://app.test/", 200).set_cookie("aws-waf-token=ABCDEFGH; Path=/"),
        Req::xhr("x1", "GET", "https://app.test/a", 200).cookie("aws-waf-token=ABCDEFGH"),
    ]);
    let p = profile(&bundle);
    assert_eq!(p.recommendation.value, RecommendationValue::PrecisaDePriming);
    assert_eq!(p.recommendation.confidence, Confidence::Media);
}

#[test]
fn dynamic_token_origin_comes_from_flow_and_is_redacted() {
    let token = "tok-ABCDEFGH12345678";
    // Campo com nome diferente do produtor (csrf × x-csrf): a Core diz "possível origem".
    let bundle = build(vec![
        Req::doc("m", "https://app.test/", 200).resp_body("text/html", "<html></html>"),
        Req::xhr("p", "GET", "https://app.test/api/token", 200)
            .resp_body("application/json", &format!("{{\"csrf\":\"{token}\"}}")),
        Req::xhr("c", "POST", "https://app.test/api/buscar", 200).qh("x-csrf", token),
    ]);
    let p = profile(&bundle);
    let f = p.findings.iter().find(|f| f.kind == "token-origin").unwrap_or_else(|| panic!("{:#?}", p));
    assert_eq!(f.category, "token");
    assert_eq!(f.confidence, Confidence::Baixa, "valor igual, campo diferente = possível origem");
    assert_eq!(f.evidence.len(), 2);
    assert_eq!(f.evidence[0].request_id, "c");
    assert_eq!(f.evidence[1].request_id, "p");
    assert_eq!(f.evidence[1].scope, "response-body");
    assert!(!serde_json::to_string(&p).unwrap().contains(token));
    assert_eq!(p.recommendation.value, RecommendationValue::PrecisaDePriming);
    assert_eq!(p.recommendation.confidence, Confidence::Baixa);

    // Mesmo nome de campo: evidência forte => media.
    let bundle = build(vec![
        Req::doc("m", "https://app.test/", 200).resp_body("text/html", "<html></html>"),
        Req::xhr("p", "GET", "https://app.test/api/token", 200)
            .resp_body("application/json", &format!("{{\"csrf\":\"{token}\"}}")),
        Req::xhr("c", "POST", "https://app.test/api/buscar", 200).qh("csrf", token),
    ]);
    let p = profile(&bundle);
    let f = p.findings.iter().find(|f| f.kind == "token-origin").unwrap_or_else(|| panic!("{:#?}", p));
    assert_eq!(f.confidence, Confidence::Media);
    assert_eq!(p.recommendation.confidence, Confidence::Media);
    assert!(!serde_json::to_string(&p).unwrap().contains(token));
}

#[test]
fn allowlist_blocked_third_party_is_a_finding_and_a_limit() {
    let mut bundle = build(vec![
        Req::doc("m", "https://app.test/", 200).resp_body("text/html", "<html></html>"),
        Req::script("h", "https://js.hcaptcha.com/1/api.js", 0).fail("net::ERR_NAME_NOT_RESOLVED"),
        Req::xhr("x", "GET", "https://app.test/a", 200),
    ]);
    bundle.session.warnings.push(
        scrapelens_core::model::Warning::info("capture.third_party_blocked", "x")
            .with_detail(serde_json::json!({ "host": "js.hcaptcha.com", "requests": 1 })),
    );
    let p = profile(&bundle);
    let blocked = p.findings.iter().find(|f| f.category == "terceiro-bloqueado").unwrap();
    assert!(blocked.summary.contains("js.hcaptcha.com"));
    assert_eq!(blocked.confidence, Confidence::Alta);
    let sig = finding(&p, "hc-001").unwrap();
    assert!(sig.limits.iter().any(|l| l.contains("allowlist")));
    assert!(p.recommendation.limits.iter().any(|l| l.contains("allowlist")));
}

#[test]
fn form_field_in_html_and_query_is_found() {
    let bundle = with_main(vec![
        Req::doc("f", "https://app.test/login?h-captcha-response=1", 200)
            .resp_body("text/html", "<form><input name=\"g-recaptcha-response\" type=\"hidden\"></form>"),
    ]);
    let p = profile(&bundle);
    let rc = finding(&p, "rc-003").unwrap();
    assert!(rc.evidence.iter().any(|e| e.scope == "response-body"));
    assert!(finding(&p, "hc-002").unwrap().evidence.iter().any(|e| e.scope == "query"));
}

#[test]
fn custom_signature_set_is_data_driven() {
    let json = r#"{"schema":"scrapelens.recon-signatures/1","signatures":[
      {"id":"t-1","vendor":"teste","kind":"response-header","name":"x-teste","category":"protecao","weight":"present","summary":"teste",
       "source":{"kind":"projeto","url":"docs/16b-mcp-navegador.md","quote":"fixture"}}]}"#;
    let set = SignatureSet::from_json(json).unwrap();
    let bundle = with_main(vec![Req::xhr("x", "GET", "https://app.test/a", 200).rh("X-Teste", "1")]);
    let p = site_profile_with(&bundle.session, &bundle, &ProfileOptions::default(), &set);
    assert_eq!(p.findings.iter().filter(|f| f.signature_id.is_some()).count(), 1);
}

#[test]
fn output_is_camel_case_json_with_stable_ids() {
    let bundle = with_main(vec![Req::doc("c", "https://app.test/x", 403).rh("cf-mitigated", "challenge")]);
    let p = profile(&bundle);
    let v = serde_json::to_value(&p).unwrap();
    assert_eq!(v["schema"], "scrapelens.site-profile/1");
    assert!(v["sessionId"].is_string());
    assert_eq!(v["recommendation"]["value"], "candidato-a-cloakbrowser");
    assert_eq!(v["findings"][0]["id"], "F001");
    assert!(v["findings"][0]["signatureId"].is_string());
    assert!(v["findings"][0]["evidence"][0]["requestId"].is_string());
    assert_eq!(v["findings"][0]["confidence"], "alta");
    assert!(v["sample"]["appRequests"].is_number());
}

// --- Revisão de segurança (docs/17): confiança do site_profile -----------------------

#[test]
fn r1_presence_only_in_body_query_or_request_cookie_is_low() {
    // Texto refletido numa página de busca.
    let p = profile(&with_main(vec![Req::doc("s", "https://app.test/search?q=x", 200)
        .resp_body("text/html", "<p>Resultados para: name=\"cf-turnstile-response\"</p>")]));
    let f = finding(&p, "cf-008").unwrap();
    assert_eq!(f.confidence, Confidence::Baixa);
    assert!(f.limits.iter().any(|l| l.contains("indício só em response-body")), "{:?}", f.limits);
    // Só na consulta de um link qualquer.
    let p = profile(&with_main(vec![Req::xhr("q", "GET", "https://app.test/api?g-recaptcha-response=1", 200)]));
    let f = finding(&p, "rc-003").unwrap();
    assert_eq!(f.confidence, Confidence::Baixa);
    assert!(f.evidence.iter().all(|e| e.scope == "query"));
    // Cookie só no pedido (pode vir de `document.cookie`).
    let p = profile(&with_main(vec![Req::xhr("c", "GET", "https://app.test/api", 200).cookie("datadome=x; _px3=y")]));
    assert_eq!(finding(&p, "dd-001").unwrap().confidence, Confidence::Baixa);
    assert_eq!(finding(&p, "hm-001").unwrap().confidence, Confidence::Baixa);
    // O mesmo cookie vindo num Set-Cookie do servidor continua `media`.
    let p = profile(&with_main(vec![Req::doc("d", "https://app.test/x", 200).set_cookie("datadome=x; Path=/")]));
    assert_eq!(finding(&p, "dd-001").unwrap().confidence, Confidence::Media);
    // Com um indício forte e independente do MESMO fornecedor (o script), sobe a `media`.
    let p = profile(&with_main(vec![
        Req::script("rcs", "https://www.google.com/recaptcha/api.js", 200),
        Req::doc("s", "https://app.test/login", 200).resp_body("text/html", "<textarea name=\"g-recaptcha-response\"></textarea>"),
    ]));
    let f = finding(&p, "rc-003").unwrap();
    assert_eq!(f.confidence, Confidence::Media);
    assert!(f.limits.iter().any(|l| l.contains("corroborado por rc-001")), "{:?}", f.limits);
}

#[test]
fn r2_aws_waf_challenge_needs_the_documented_status() {
    // x-amzn-waf-action: challenge com 200 não é a ação documentada (202).
    let p = profile(&with_main(vec![
        Req::xhr("w", "GET", "https://app.test/api/x", 200).rh("x-amzn-waf-action", "challenge"),
        Req::xhr("w2", "GET", "https://app.test/api/y", 200),
    ]));
    let f = finding(&p, "aw-001").unwrap();
    assert_eq!(f.confidence, Confidence::Baixa);
    assert_eq!(f.category, "protecao");
    assert_eq!(f.resolved_later, None);
    assert!(f.limits.iter().any(|l| l.contains("difere do documentado (202)")), "{:?}", f.limits);
    assert_ne!(p.recommendation.value, RecommendationValue::CandidatoACloakbrowser);
    assert!(p.findings.iter().all(|f| f.category != "desafio"));
    // captcha com 403 (documentado: 405) também não.
    let p = profile(&with_main(vec![Req::doc("c", "https://app.test/x", 403).rh("x-amzn-waf-action", "captcha")]));
    assert_eq!(finding(&p, "aw-001").unwrap().confidence, Confidence::Baixa);
    // Os pares documentados continuam `alta`.
    for (value, status) in [("challenge", 202), ("captcha", 405)] {
        let p = profile(&with_main(vec![Req::doc("c", "https://app.test/x", status).rh("x-amzn-waf-action", value)]));
        let f = finding(&p, "aw-001").unwrap();
        assert_eq!(f.confidence, Confidence::Alta, "{value}/{status}");
        assert_eq!(f.category, "desafio");
    }
}

#[test]
fn r3_block_on_a_third_party_resource_does_not_decide_the_recommendation() {
    let p = profile(&with_main(vec![
        Req::new("i", "GET", "https://cdn.other.test/pixel.png", Some(403), "Image").rh("cf-mitigated", "challenge"),
        Req::xhr("x1", "GET", "https://app.test/api/a", 200),
        Req::xhr("x2", "GET", "https://app.test/api/b", 200),
    ]));
    let f = finding(&p, "cf-005").unwrap();
    assert_eq!(f.confidence, Confidence::Baixa);
    assert_eq!(f.category, "protecao", "sem bloqueio atribuído ao alvo");
    assert!(f.evidence.iter().all(|e| e.third_party));
    assert!(f.limits.iter().any(|l| l.contains("outro host") && l.contains("app.test")), "{:?}", f.limits);
    assert_eq!(p.recommendation.value, RecommendationValue::ChromeNormalBasta, "{:#?}", p.recommendation);
    // Cookie de proteção vindo só de outro host também não atribui.
    let p = profile(&with_main(vec![Req::script("t", "https://cdn.other.test/x.js", 200).set_cookie("__cf_bm=z; Path=/")]));
    let f = finding(&p, "cf-001").unwrap();
    assert_eq!(f.confidence, Confidence::Baixa);
    assert!(f.evidence.iter().all(|e| e.third_party));
    // XHR 403 num host de terceiro: achado marcado, fora da recomendação.
    let p = profile(&with_main(vec![
        Req::xhr("a", "GET", "https://metrics.other.test/collect", 403),
        Req::xhr("x1", "GET", "https://app.test/api/a", 200),
    ]));
    let f = p.findings.iter().find(|f| f.kind == "status").unwrap();
    assert_eq!(f.confidence, Confidence::Baixa);
    assert!(f.evidence.iter().all(|e| e.third_party));
    assert_ne!(p.recommendation.value, RecommendationValue::CandidatoACloakbrowser);
    // O mesmo bloqueio num subdomínio do site-alvo CONTA.
    let p = profile(&with_main(vec![Req::xhr("a", "GET", "https://api.app.test/v1", 403).rh("cf-mitigated", "challenge")]));
    let f = finding(&p, "cf-005").unwrap();
    assert_eq!(f.confidence, Confidence::Alta);
    assert!(f.evidence.iter().all(|e| !e.third_party));
    assert_eq!(p.recommendation.value, RecommendationValue::CandidatoACloakbrowser);
    // Script de captcha de outro host é referência embutida pela página: continua atribuído.
    let p = profile(&with_main(vec![Req::script("s", "https://challenges.cloudflare.com/turnstile/v0/api.js", 200)]));
    assert_eq!(finding(&p, "cf-007").unwrap().confidence, Confidence::Media);
}

#[test]
fn r4_a_redirect_or_a_cookie_from_another_host_does_not_resolve_a_challenge() {
    // (a) 403 de desafio e depois 302 na MESMA rota (para a página de desafio).
    let p = profile(&build(vec![
        Req::doc("m1", "https://app.test/", 403).rh("cf-mitigated", "challenge").resp_body("text/html", "<html>c</html>"),
        Req::doc("m2", "https://app.test/", 302).rh("location", "https://app.test/__challenge"),
    ]));
    assert_eq!(finding(&p, "cf-005").unwrap().resolved_later, Some(false));
    assert_eq!(p.recommendation.value, RecommendationValue::CandidatoACloakbrowser, "{:#?}", p.recommendation);
    // (b) cf_clearance definido por OUTRO host.
    let p = profile(&build(vec![
        Req::doc("m1", "https://app.test/", 403).rh("cf-mitigated", "challenge").resp_body("text/html", "<html>c</html>"),
        Req::script("t", "https://cdn.other.test/x.js", 200).set_cookie("cf_clearance=Z; Path=/"),
    ]));
    assert_eq!(finding(&p, "cf-005").unwrap().resolved_later, Some(false));
    assert_eq!(p.recommendation.value, RecommendationValue::CandidatoACloakbrowser, "{:#?}", p.recommendation);
    // (c) o mesmo cookie vindo de um subdomínio do site-alvo libera.
    let p = profile(&build(vec![
        Req::doc("m1", "https://app.test/", 403).rh("cf-mitigated", "challenge").resp_body("text/html", "<html>c</html>"),
        Req::xhr("x", "GET", "https://api.app.test/ok", 200).set_cookie("cf_clearance=Z; Path=/"),
    ]));
    assert_eq!(finding(&p, "cf-005").unwrap().resolved_later, Some(true));
    assert_eq!(p.recommendation.value, RecommendationValue::PrecisaDePriming);
    // (d) 2xx depois na mesma rota continua resolvendo.
    let p = profile(&build(vec![
        Req::doc("m1", "https://app.test/", 403).rh("cf-mitigated", "challenge").resp_body("text/html", "<html>c</html>"),
        Req::doc("m2", "https://app.test/", 200).resp_body("text/html", "<html>ok</html>"),
    ]));
    assert_eq!(finding(&p, "cf-005").unwrap().resolved_later, Some(true));
}
