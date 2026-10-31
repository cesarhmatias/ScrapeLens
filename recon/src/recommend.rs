//! Recomendação determinística (`docs/16b-mcp-navegador.md` §5.3).

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
    _sigs: &SignatureSet,
) -> Recommendation {
    let mut limits = vec![
        format!(
            "amostra: uma captura com {} requisição(ões); não prova o comportamento em outras sessões",
            sample.requests
        ),
        "sem interação humana além da navegação feita; páginas atrás de login/ação não foram vistas".to_string(),
        "\"barrado\" e \"passou\" valem para o Chrome normal nesta captura".to_string(),
    ];
    let blocked_hosts: Vec<String> = findings
        .iter()
        .filter(|f| f.category == "terceiro-bloqueado")
        .map(|f| f.summary.clone())
        .collect();
    if !blocked_hosts.is_empty() {
        limits.push(format!(
            "hosts de terceiros foram bloqueados pela allowlist e podem esconder proteção ({} host(s)); veja os achados `terceiro-bloqueado`",
            blocked_hosts.len()
        ));
    }

    let main_doc = session
        .requests
        .iter()
        .find(|r| is_doc(&r.resource_type));
    let main_status = main_doc.and_then(|r| r.status);

    // 1. Indeterminado.
    let mut why: Vec<String> = Vec::new();
    if partial {
        why.push("a sessão está marcada parcial/incompleta pela Core".to_string());
    }
    if sample.requests < 2 {
        why.push("menos de 2 requisições".to_string());
    }
    if main_doc.is_none() || main_status.is_none() {
        why.push("nenhum documento principal com resposta".to_string());
    }
    if !why.is_empty() {
        return Recommendation {
            value: RecommendationValue::Indeterminado,
            confidence: Confidence::Baixa,
            reasons: why,
            limits,
            based_on: Vec::new(),
        };
    }

    // 2. Candidato a CloakBrowser: o Chrome normal foi barrado e nada resolveu.
    let hard: Vec<&Finding> = findings
        .iter()
        .filter(|f| {
            matches!(f.category.as_str(), "desafio" | "bloqueio")
                && f.confidence == Confidence::Alta
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
            "o Chrome normal foi barrado e não houve resposta bem-sucedida depois na mesma rota nem cookie de liberação".to_string(),
        );
        limits.push(
            "isto NÃO prova que o CloakBrowser passaria; é o gatilho para voltar a esse assunto (D6)".to_string(),
        );
        return Recommendation {
            value: RecommendationValue::CandidatoACloakbrowser,
            confidence: if main_blocked && vendor_based { Confidence::Alta } else { Confidence::Media },
            reasons,
            limits,
            based_on: hard.iter().map(|f| f.id.clone()).collect(),
        };
    }

    // 3. Precisa de priming.
    let resolved_challenges: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.category == "desafio" && f.resolved_later == Some(true))
        .collect();
    let tokens: Vec<&Finding> = findings.iter().filter(|f| f.kind == "token-origin").collect();
    let protection_cookie_flow: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.kind == "cookie-flow" && f.vendor.is_some())
        .collect();
    let mut priming: Vec<&Finding> = Vec::new();
    priming.extend(&resolved_challenges);
    priming.extend(&tokens);
    priming.extend(&protection_cookie_flow);
    if !priming.is_empty() {
        let mut reasons = Vec::new();
        for f in &resolved_challenges {
            reasons.push(format!(
                "um desafio foi servido e resolvido no próprio navegador ({}, {}); um cliente sem navegador precisa reproduzir essa troca",
                f.summary, f.id
            ));
        }
        for f in &tokens {
            reasons.push(format!("{} ({})", f.summary, f.id));
        }
        for f in &protection_cookie_flow {
            reasons.push(format!(
                "cookie de proteção ({}) definido e reenviado: {} ({})",
                f.vendor.as_deref().unwrap_or("?"),
                f.summary,
                f.id
            ));
        }
        limits.push(
            "\"precisa de priming\" é o que a captura OBSERVOU circulando; que cada item seja obrigatório só se prova removendo-o (validate_run)".to_string(),
        );
        let confidence = if !resolved_challenges.is_empty() {
            Confidence::Alta
        } else if !protection_cookie_flow.is_empty() || tokens.iter().any(|f| f.confidence >= Confidence::Media) {
            Confidence::Media
        } else {
            Confidence::Baixa // só "possível origem" de token
        };
        return Recommendation {
            value: RecommendationValue::PrecisaDePriming,
            confidence,
            reasons,
            limits,
            based_on: priming.iter().map(|f| f.id.clone()).collect(),
        };
    }

    // 4. Chrome normal basta.
    let protections: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.category == "protecao" || f.category == "captcha")
        .collect();
    let mut reasons = vec![format!(
        "documento principal respondeu {} e nenhuma rota da aplicação foi barrada",
        main_status.map(|s| s.to_string()).unwrap_or_else(|| "?".to_string())
    )];
    if !protections.is_empty() {
        reasons.push(format!(
            "há proteção presente de forma passiva ({} achado(s)), sem bloqueio nesta captura",
            protections.len()
        ));
    }
    Recommendation {
        value: RecommendationValue::ChromeNormalBasta,
        confidence: if sample.requests >= 5 { Confidence::Media } else { Confidence::Baixa },
        reasons,
        limits,
        based_on: protections.iter().map(|f| f.id.clone()).collect(),
    }
}
