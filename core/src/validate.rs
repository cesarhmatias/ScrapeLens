//! Validação da execução do script (docs/13 §3): compara a captura com a
//! sessão importada do trace e resume em três vereditos:
//! - `equivalent`: "execução equivalente à captura";
//! - `diverges`: "diverge no passo N (<motivo>)" — status ou veredito do
//!   assess diferente, passo extra no trace, passo ausente, campo que
//!   deveria ser constante e mudou;
//! - `incomplete`: "incompleta: parou no passo N" — o passo N do trace
//!   falhou no transporte (sem resposta / `trace.step_error`).
//!
//! Passo = posição (1 = primeira) da requisição na sessão do trace. Passos
//! da captura que o trace não executou depois do último passo pareado não
//! contam (o script cobre uma cadeia até o alvo, não a captura inteira).
//! Diferenças esperadas (dinâmicos com origem, ambiente: cabeçalhos e
//! cookies) saem separadas das inesperadas.

use serde::Serialize;

use crate::assess::{assess_session, AssessRules, VerdictKind};
use crate::compare::{compare_sessions, CompareOptions, FieldClass, OriginMap};
use crate::flow::ConsumedScope;
use crate::model::SessionV1;
use crate::search::BodySource;

#[derive(Debug, Clone, Default)]
pub struct ValidateOptions {
    pub compare: CompareOptions,
    pub rules: AssessRules,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationVerdict {
    Equivalent,
    Diverges,
    Incomplete,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldNote {
    pub scope: String,
    pub field: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StepValidation {
    /// Posição do passo no trace (1 = primeiro).
    pub step: usize,
    pub trace_request_id: String,
    /// Requisição da captura pareada (`None` = passo extra no trace).
    pub capture_request_id: Option<String>,
    pub method: String,
    pub url: String,
    pub status_capture: Option<u16>,
    pub status_trace: Option<u16>,
    pub verdict_capture: Option<VerdictKind>,
    pub verdict_trace: VerdictKind,
    /// Dinâmicos com origem e diferenças de ambiente.
    pub expected: Vec<FieldNote>,
    pub unexpected: Vec<FieldNote>,
    /// Motivo de divergência neste passo, se houver.
    pub problem: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Validation {
    pub schema: String,
    pub verdict: ValidationVerdict,
    pub step: Option<usize>,
    pub reason: Option<String>,
    /// Linha de resumo: "execução equivalente à captura" etc.
    pub summary: String,
    pub steps: Vec<StepValidation>,
    /// Passos da captura (POST/não-GET) sem par entre passos pareados do trace.
    pub missing_in_trace: Vec<String>,
    pub mapped_origin: Option<OriginMap>,
    pub warnings: Vec<String>,
}

const ENV_HEADERS: &[&str] = &[
    "host",
    "origin",
    "referer",
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "content-length",
    "connection",
    "date",
    "server",
    "cache-control",
    "pragma",
    "upgrade-insecure-requests",
];

fn env_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ENV_HEADERS.contains(&n.as_str()) || n.starts_with("sec-") || n.starts_with("x-forwarded")
}

/// Valor longo (>= 16) e sem espaços nos dois lados: identificador gerado no
/// cliente (id de sessão do cliente), não uma entrada de usuário.
fn generated_id(a: Option<&str>, b: Option<&str>) -> bool {
    let id = |v: &str| v.len() >= 16 && !v.contains(char::is_whitespace);
    matches!((a, b), (Some(a), Some(b)) if id(a) && id(b))
}

pub fn validate(
    capture: &SessionV1,
    capture_source: &dyn BodySource,
    trace: &SessionV1,
    trace_source: &dyn BodySource,
    options: &ValidateOptions,
) -> Validation {
    let cmp = compare_sessions(
        capture,
        capture_source,
        trace,
        trace_source,
        &options.compare,
    );
    let out_a = assess_session(capture, capture_source, &options.rules);
    let out_b = assess_session(trace, trace_source, &options.rules);
    let verdict_a = |id: &str| out_a.iter().find(|o| o.request_id == id);
    let verdict_b = |id: &str| out_b.iter().find(|o| o.request_id == id);
    let step_of = |id: &str| {
        trace
            .requests
            .iter()
            .position(|r| r.id == id)
            .map(|i| i + 1)
    };
    let trace_err = |id: &str| -> bool {
        trace
            .warnings
            .iter()
            .any(|w| w.code == "trace.step_error" && w.entity.as_deref() == Some(id))
    };

    // parâmetros do usuário declarados no trace (nomes, sem valores)
    let params: Vec<&str> = trace
        .session
        .notes
        .iter()
        .filter_map(|n| n.strip_prefix(crate::parse::trace::PARAM_NOTE_PREFIX))
        .collect();
    let mut steps: Vec<StepValidation> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = Default::default();
    for pair in &cmp.pairs {
        let (Some(step), Some(ob)) = (step_of(&pair.b.request_id), verdict_b(&pair.b.request_id))
        else {
            continue;
        };
        seen.insert(pair.b.request_id.clone());
        let oa = verdict_a(&pair.a.request_id);
        let (mut expected, mut unexpected) = (Vec::new(), Vec::new());
        for f in &pair.fields {
            let note = |why: &str| FieldNote {
                scope: format!("{:?}", f.scope).to_ascii_lowercase(),
                field: f.field.clone(),
                reason: why.to_string(),
            };
            let env = f.scope == ConsumedScope::Cookie
                || (f.scope == ConsumedScope::Header && env_header(&f.field));
            let is_param = |name: &str| params.iter().any(|p| p.eq_ignore_ascii_case(name));
            match f.class {
                FieldClass::Static | FieldClass::Redacted => {}
                _ if is_param(&f.field) => {
                    expected.push(note("esperado (parâmetro do usuário)"));
                }
                FieldClass::Dynamic => {
                    let composite_dynamic = !f.parts.is_empty();
                    if env {
                        expected.push(note("ambiente (cookie/cabeçalho da execução)"));
                    } else if f.origin.is_some()
                        || f.origin_label
                            .as_deref()
                            .is_some_and(|l| l.contains("runtime"))
                    {
                        expected.push(note("dinâmico com origem observada"));
                    } else if generated_id(f.a.as_deref(), f.b.as_deref()) {
                        expected.push(note(
                            "identificador gerado no cliente (valor longo e opaco)",
                        ));
                    } else if composite_dynamic {
                        for p in f.parts.iter().filter(|p| p.class == FieldClass::Dynamic) {
                            if p.origin.is_some() {
                                expected.push(note("trecho dinâmico com origem observada"));
                            } else if generated_id(Some(&p.a), Some(&p.b)) {
                                expected.push(note(
                                    "identificador gerado no cliente (valor longo e opaco)",
                                ));
                            } else {
                                unexpected.push(note(
                                    "trecho dinâmico sem origem (deveria ser constante)",
                                ));
                            }
                        }
                    } else {
                        unexpected.push(note("campo que deveria ser constante mudou (sem origem)"));
                    }
                }
                FieldClass::OnlyA | FieldClass::OnlyB => {
                    let side = if f.class == FieldClass::OnlyA {
                        "só na captura"
                    } else {
                        "só no trace"
                    };
                    if env {
                        expected.push(note(&format!("ambiente ({side})")));
                    } else {
                        unexpected.push(note(side));
                    }
                }
            }
        }
        let a_req = capture.requests.iter().find(|r| r.id == pair.a.request_id);
        let status_a = a_req.and_then(|r| r.attempts.last()).and_then(|a| a.status);
        let b_req = trace.requests.iter().find(|r| r.id == pair.b.request_id);
        let status_b = b_req.and_then(|r| r.attempts.last()).and_then(|a| a.status);
        let mut problem = None;
        if status_b.is_none() || status_b == Some(0) {
            // sem resposta: tratado como falha de transporte abaixo
        } else if status_a != status_b {
            problem = Some(format!(
                "status {} na captura × {} no trace",
                status_a.map_or("?".into(), |s| s.to_string()),
                status_b.map_or("?".into(), |s| s.to_string())
            ));
        } else if oa.is_some_and(|oa| {
            // a captura é a referência: app-ok nela exige app-ok no trace;
            // fora disso, vereditos diferentes só contam se ambos foram avaliados
            if oa.verdict_kind == VerdictKind::AppOk {
                ob.verdict_kind != VerdictKind::AppOk
            } else {
                oa.verdict_kind != ob.verdict_kind
                    && oa.verdict_kind != VerdictKind::NotAssessed
                    && ob.verdict_kind != VerdictKind::NotAssessed
            }
        }) {
            problem = Some(format!(
                "veredito {} no trace × {} na captura",
                ob.verdict,
                oa.map_or("?", |o| o.verdict.as_str())
            ));
        } else if let Some(u) = unexpected.first() {
            problem = Some(format!("{} `{}`: {}", u.scope, u.field, u.reason));
        }
        steps.push(StepValidation {
            step,
            trace_request_id: pair.b.request_id.clone(),
            capture_request_id: Some(pair.a.request_id.clone()),
            method: pair.b.method.clone(),
            url: pair.b.url.clone(),
            status_capture: status_a,
            status_trace: status_b,
            verdict_capture: oa.map(|o| o.verdict_kind),
            verdict_trace: ob.verdict_kind,
            expected,
            unexpected,
            problem,
        });
    }
    // passos do trace sem par: extras
    for (i, r) in trace.requests.iter().enumerate() {
        if seen.contains(&r.id) {
            continue;
        }
        let Some(ob) = verdict_b(&r.id) else { continue };
        let a = r.attempts.last();
        steps.push(StepValidation {
            step: i + 1,
            trace_request_id: r.id.clone(),
            capture_request_id: None,
            method: a.map(|a| a.method.clone()).unwrap_or_default(),
            url: a.map(|a| a.url.clone()).unwrap_or_default(),
            status_capture: None,
            status_trace: a.and_then(|a| a.status),
            verdict_capture: None,
            verdict_trace: ob.verdict_kind,
            expected: Vec::new(),
            unexpected: Vec::new(),
            problem: Some("passo extra no trace (sem correspondente na captura)".to_string()),
        });
    }
    steps.sort_by_key(|s| s.step);

    // passos da captura entre passos pareados que o trace não executou
    let paired_a: Vec<usize> = cmp
        .pairs
        .iter()
        .filter_map(|p| capture.requests.iter().position(|r| r.id == p.a.request_id))
        .collect();
    let (lo, hi) = (
        paired_a.iter().copied().min().unwrap_or(0),
        paired_a.iter().copied().max().unwrap_or(0),
    );
    let missing: Vec<String> = cmp
        .only_in_a
        .iter()
        .filter(|r| !r.method.eq_ignore_ascii_case("GET"))
        .filter(|r| {
            capture
                .requests
                .iter()
                .position(|q| q.id == r.request_id)
                .is_some_and(|i| i > lo && i < hi)
        })
        .map(|r| r.request_id.clone())
        .collect();

    // primeiro problema, em ordem de passo
    let mut verdict = ValidationVerdict::Equivalent;
    let (mut step, mut reason) = (None, None);
    for s in &steps {
        let transport = trace_err(&s.trace_request_id) || matches!(s.status_trace, None | Some(0));
        if transport {
            verdict = ValidationVerdict::Incomplete;
            step = Some(s.step);
            reason = Some("sem resposta (falha de transporte registrada no trace)".to_string());
            break;
        }
        if let Some(p) = &s.problem {
            verdict = ValidationVerdict::Diverges;
            step = Some(s.step);
            reason = Some(p.clone());
            break;
        }
    }
    if verdict == ValidationVerdict::Equivalent && !missing.is_empty() {
        let next = cmp
            .only_in_a
            .iter()
            .find(|r| r.request_id == missing[0])
            .and_then(|m| {
                let idx = capture.requests.iter().position(|q| q.id == m.request_id)?;
                cmp.pairs
                    .iter()
                    .filter(|p| {
                        capture
                            .requests
                            .iter()
                            .position(|q| q.id == p.a.request_id)
                            .is_some_and(|i| i > idx)
                    })
                    .filter_map(|p| step_of(&p.b.request_id))
                    .min()
            });
        verdict = ValidationVerdict::Diverges;
        step = next;
        reason = Some(format!(
            "passo ausente no trace ({} {})",
            cmp.only_in_a
                .iter()
                .find(|r| r.request_id == missing[0])
                .map_or("", |r| r.method.as_str()),
            missing[0]
        ));
    }
    let summary = match (verdict, step) {
        (ValidationVerdict::Equivalent, _) => "execução equivalente à captura".to_string(),
        (ValidationVerdict::Diverges, Some(n)) => {
            format!(
                "diverge no passo {n} ({})",
                reason.as_deref().unwrap_or("?")
            )
        }
        (ValidationVerdict::Diverges, None) => {
            format!("diverge ({})", reason.as_deref().unwrap_or("?"))
        }
        (ValidationVerdict::Incomplete, Some(n)) => format!("incompleta: parou no passo {n}"),
        (ValidationVerdict::Incomplete, None) => "incompleta".to_string(),
    };
    if trace.requests.is_empty() {
        // trace vazio nunca é "equivalente"
        return Validation {
            schema: "scrapelens.validate/1".to_string(),
            verdict: ValidationVerdict::Incomplete,
            step: Some(1),
            reason: Some("trace sem passos".to_string()),
            summary: "incompleta: parou no passo 1".to_string(),
            steps,
            missing_in_trace: missing,
            mapped_origin: cmp.mapped_origin,
            warnings: cmp.warnings,
        };
    }
    Validation {
        schema: "scrapelens.validate/1".to_string(),
        verdict,
        step,
        reason,
        summary,
        steps,
        missing_in_trace: missing,
        mapped_origin: cmp.mapped_origin,
        warnings: cmp.warnings,
    }
}
