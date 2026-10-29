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
//! Diferenças esperadas (dinâmicos com origem equivalente, ambiente:
//! cabeçalhos e cookies, parâmetros do usuário válidos) saem separadas das
//! inesperadas.
//!
//! Proveniência equivalente: um campo com origem na resposta R_k da captura
//! precisa, no trace, ter origem na resposta pareada de R_k. Valor capturado
//! ausente da resposta pareada = "valor congelado"; vindo de outra resposta =
//! "origem diferente".
//!
//! Completude: o trace declara `target` (requestId do alvo na captura, que
//! tem de estar pareado) e `complete=true`; senão é "incompleta".
//!
//! `parameters` só vale para campo sem origem na captura e que não seja
//! constante (identificador longo e opaco); os demais são ignorados com o
//! aviso "parâmetro inválido". `plan.parameters` são os obrigatórios do plano:
//! classificam como parâmetro do usuário, mas não passam por essas checagens.
//! A isenção de `parameters` vale só para o par (name, part) que o plano
//! regenerado da captura realmente produz (ex. sessionid_cliente → XML.sid);
//! outro par sob um nome do plano passa por todas as checagens e ganha o aviso
//! "parâmetro não corresponde ao plano: <name> → <part>".
//!
//! Plano versionado: `plan.version` igual a [`PLAN_VERSION`] compara o hash do
//! plano (divergência se não confere); versão ausente ou diferente é plano de
//! build anterior e só avisa; plano sem hash avisa "plano sem impressão".

use std::collections::HashMap;
use std::fmt::Write as _;

use serde::Serialize;

use crate::assess::{assess_session, AssessRules, VerdictKind};
use crate::compare::{
    compare_sessions, single_app_origin, split_url, CompareOptions, FieldClass, OriginMap,
};
use crate::error::Result;
use crate::export::priming::{plan_parameter_uses, AdapterEncoder, PrimingOptions};
use crate::flow::{
    origins_in, priming_chain, ConsumedScope, FlowContext, FlowOptions, OriginStatus, ValueOrigin,
    ValueOrigins,
};
use crate::model::SessionV1;
use crate::parse::trace::{
    COMPLETE_NOTE_PREFIX, PARAM_NOTE_PREFIX, PLAN_HASH_NOTE_PREFIX, PLAN_PARAM_NOTE_PREFIX,
    PLAN_PRESENT_NOTE, PLAN_VERSION_NOTE_PREFIX, TARGET_NOTE_PREFIX,
};
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

type Key = (String, String, usize);

fn key_of(scope: ConsumedScope, field: &str, occurrence: usize) -> Key {
    (format!("{scope:?}"), field.to_string(), occurrence)
}

/// Valor longo (>= 16) e sem espaços: identificador/segredo, não entrada de usuário.
fn long_opaque(v: &str) -> bool {
    v.len() >= 16 && !v.contains(char::is_whitespace)
}

/// A captura marca o valor como composto/gerado no cliente.
fn client_composed(v: &ValueOrigin) -> bool {
    !v.partial_composition.is_empty()
        || v.label.contains("composição no cliente")
        || v.label.contains("gerado no cliente")
}

/// Versão atual do plano (`plan.version` no trace). O hash só é comparado
/// quando o trace declara exatamente esta versão; versão ausente ou diferente
/// é plano de build anterior e gera só um aviso. Mudou a definição do hash?
/// Suba a versão.
pub const PLAN_VERSION: u32 = 2;

/// Impressão do plano de um alvo: passos da cadeia (método + caminho
/// normalizado, sem host) e nomes dos parâmetros. FNV-1a 64 em hexadecimal.
/// O gerador do script grava este valor em `plan.hash` do trace.
pub fn plan_hash(
    capture: &SessionV1,
    source: &dyn BodySource,
    target: &str,
    flow: &FlowOptions,
    parameter_names: &[String],
) -> Result<String> {
    let chain = priming_chain(capture, source, target, flow)?;
    let mut text = String::new();
    let line = |text: &mut String, tag: &str, method: &str, url: &str| {
        let (_, path) = split_url(url);
        let _ = writeln!(text, "{tag} {} {path}", method.to_ascii_uppercase());
    };
    for step in &chain.steps {
        line(&mut text, "step", &step.method, &step.url);
    }
    if let Some(r) = capture.requests.iter().find(|r| r.id == target) {
        if let Some(a) = r.attempts.last() {
            line(&mut text, "target", &a.method, &a.url);
        }
    }
    let mut names: Vec<String> = parameter_names
        .iter()
        .map(|n| n.to_ascii_lowercase())
        .collect();
    names.sort();
    names.dedup();
    for n in names {
        let _ = writeln!(text, "param {n}");
    }
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in text.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    Ok(format!("{hash:016x}"))
}

fn note_value<'a>(trace: &'a SessionV1, prefix: &str) -> Option<&'a str> {
    trace
        .session
        .notes
        .iter()
        .find_map(|n| n.strip_prefix(prefix))
}

/// Pares `(parâmetro, parte/campo)` que o plano REGENERADO DA CAPTURA instala.
/// Nunca usa o que o trace declara: o gerador é chamado com a captura, o alvo
/// e o mesmo fluxo do hash. Codificadores só entram na forma do texto gerado;
/// aqui basta um marcador por adaptador para que as partes sejam decodificadas
/// e os nomes registrados (o texto é descartado).
fn produced_parameter_uses(
    capture: &SessionV1,
    source: &dyn BodySource,
    target: &str,
    flow: &FlowOptions,
) -> Option<Vec<(String, String)>> {
    let adapter_encoders: Vec<AdapterEncoder> = flow
        .adapters
        .iter()
        .map(|a| AdapterEncoder {
            adapter_id: a.id().to_string(),
            function: format!("{}_encode", a.id().replace('-', "_")),
            decoder: String::new(),
            source: String::new(),
        })
        .collect();
    let opts = PrimingOptions {
        flow: flow.clone(),
        adapter_encoders,
        ..Default::default()
    };
    plan_parameter_uses(capture, source, target, &opts)
        .ok()
        .map(|uses| uses.into_iter().collect())
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
    let mut warnings = cmp.warnings.clone();
    let ctx_a = FlowContext::new(capture, capture_source, &options.compare.flow);
    let ctx_b = FlowContext::new(trace, trace_source, &options.compare.flow);
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
    let a_to_b: HashMap<&str, &str> = cmp
        .pairs
        .iter()
        .map(|p| (p.a.request_id.as_str(), p.b.request_id.as_str()))
        .collect();

    // origens da captura por requisição pareada (uma vez)
    let origins_a: HashMap<&str, ValueOrigins> = cmp
        .pairs
        .iter()
        .filter_map(|p| {
            Some((
                p.a.request_id.as_str(),
                origins_in(&ctx_a, &p.a.request_id).ok()?,
            ))
        })
        .collect();
    let origins_b: HashMap<&str, ValueOrigins> = cmp
        .pairs
        .iter()
        .filter_map(|p| {
            Some((
                p.b.request_id.as_str(),
                origins_in(&ctx_b, &p.b.request_id).ok()?,
            ))
        })
        .collect();

    // alvo declarado e pares que o plano REGENERADO DA CAPTURA produz; só esses
    // pares podem ser isentos. Sem alvo (ou se a geração falhar), não isenta.
    let target_note = note_value(trace, TARGET_NOTE_PREFIX).map(str::to_string);
    let produced: Vec<(String, String)> = target_note
        .as_deref()
        .and_then(|t| produced_parameter_uses(capture, capture_source, t, &options.compare.flow))
        .unwrap_or_default();
    let plan_names: Vec<&str> = trace
        .session
        .notes
        .iter()
        .filter_map(|n| n.strip_prefix(PLAN_PARAM_NOTE_PREFIX))
        .collect();

    // parâmetros declarados no trace: `(name, part)`. Só a parte que o plano
    // produz é isenta; as demais passam pelas checagens normais.
    let declared: Vec<(String, String)> = trace
        .session
        .notes
        .iter()
        .filter_map(|n| n.strip_prefix(PARAM_NOTE_PREFIX))
        .filter_map(|v| {
            let doc: Option<serde_json::Value> = serde_json::from_str(v).ok();
            let (name, part) = match doc {
                Some(o) => (
                    o.get("name")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                    o.get("part")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                ),
                // formato antigo: só a parte
                None => (Some(v.to_string()), Some(v.to_string())),
            };
            let part = part.filter(|s| !s.is_empty())?;
            Some((name.unwrap_or_else(|| part.clone()), part))
        })
        .collect();
    let mut params: Vec<&str> = Vec::new();
    for (name, part) in &declared {
        let produced_pair = produced
            .iter()
            .any(|(n, p)| n.eq_ignore_ascii_case(name) && p.eq_ignore_ascii_case(part));
        if produced_pair {
            if !params.iter().any(|p| p.eq_ignore_ascii_case(part)) {
                params.push(part.as_str());
            }
            continue;
        }
        let mut seen = false;
        let mut why: Option<&str> = None;
        for o in origins_a.values() {
            for v in o.values.iter().filter(|v| {
                matches!(v.scope, ConsumedScope::Body | ConsumedScope::Query)
                    && v.field.eq_ignore_ascii_case(part)
            }) {
                seen = true;
                if v.evidences
                    .iter()
                    .any(|e| e.kind != crate::flow::EvidenceKind::Initiator)
                {
                    why = Some("tem origem na captura");
                } else if long_opaque(&v.value) && why.is_none() {
                    why = Some("é uma constante/identificador longo");
                }
            }
        }
        match (seen, why) {
            (false, _) => warnings.push(format!(
                "parâmetro inválido: `{part}` não existe nos passos pareados da captura"
            )),
            (true, Some(why)) => warnings.push(format!("parâmetro inválido: `{part}` {why}")),
            (true, None) => {}
        }
        let in_plan = plan_names.iter().any(|n| n.eq_ignore_ascii_case(name))
            || produced.iter().any(|(n, _)| n.eq_ignore_ascii_case(name));
        if in_plan {
            warnings.push(format!(
                "parâmetro não corresponde ao plano: {name} → {part}"
            ));
            // não classifica: a parte segue a proveniência e o diff normais
        } else if seen && why.is_none() && !params.iter().any(|p| p.eq_ignore_ascii_case(part)) {
            params.push(part.as_str());
        }
    }
    // `plan.parameters` são os parâmetros obrigatórios do plano: também só
    // classificam, sem as checagens acima.
    for name in &plan_names {
        if !params.iter().any(|p| p.eq_ignore_ascii_case(name)) {
            params.push(name);
        }
    }
    let is_param = |field: &str| params.iter().any(|p| p.eq_ignore_ascii_case(field));

    let mut steps: Vec<StepValidation> = Vec::new();
    let mut seen_b: std::collections::BTreeSet<String> = Default::default();
    for pair in &cmp.pairs {
        let (Some(step), Some(ob)) = (step_of(&pair.b.request_id), verdict_b(&pair.b.request_id))
        else {
            continue;
        };
        seen_b.insert(pair.b.request_id.clone());
        let oa = verdict_a(&pair.a.request_id);
        let (mut expected, mut unexpected) = (Vec::new(), Vec::new());
        let mut handled: std::collections::BTreeSet<Key> = Default::default();
        let note = |scope: ConsumedScope, field: &str, why: &str| FieldNote {
            scope: format!("{scope:?}").to_ascii_lowercase(),
            field: field.to_string(),
            reason: why.to_string(),
        };

        // 1) proveniência equivalente dos campos com origem na captura
        if let (Some(va), Some(vb)) = (
            origins_a.get(pair.a.request_id.as_str()),
            origins_b.get(pair.b.request_id.as_str()),
        ) {
            for a in va.values.iter().filter(|v| {
                matches!(v.scope, ConsumedScope::Body | ConsumedScope::Query)
                    && !v.value.is_empty()
                    && matches!(v.status, OriginStatus::Origin | OriginStatus::Ambiguous)
                    && v.parent
                        .as_ref()
                        .map_or(true, |p| v.field.starts_with(&format!("{p}.")))
            }) {
                let producers_a: Vec<&str> = a
                    .evidences
                    .iter()
                    .filter(|e| e.kind != crate::flow::EvidenceKind::Initiator)
                    .map(|e| e.request_id.as_str())
                    .collect();
                if producers_a.is_empty() {
                    continue;
                }
                let key = key_of(a.scope, &a.field, a.occurrence);
                let Some(b) = vb.values.iter().find(|v| {
                    key_of(v.scope, &v.field, v.occurrence) == key
                        && v.parent
                            .as_ref()
                            .map_or(true, |p| v.field.starts_with(&format!("{p}.")))
                }) else {
                    continue; // campo ausente no trace: tratado pelo diff
                };
                handled.insert(key);
                if is_param(&a.field) {
                    continue;
                }
                let paired: Vec<&str> = producers_a
                    .iter()
                    .filter_map(|id| a_to_b.get(id).copied())
                    .collect();
                let producers_b: Vec<&str> = b
                    .evidences
                    .iter()
                    .filter(|e| e.kind != crate::flow::EvidenceKind::Initiator)
                    .map(|e| e.request_id.as_str())
                    .collect();
                if producers_b.iter().any(|p| paired.contains(p)) {
                    if a.value != b.value {
                        expected.push(note(a.scope, &a.field, "dinâmico com origem equivalente"));
                    }
                } else if !producers_b.is_empty() {
                    unexpected.push(note(
                        a.scope,
                        &a.field,
                        &format!(
                            "origem diferente: no trace vem de {}, na captura vinha de {}",
                            producers_b.join(", "),
                            producers_a.join(", ")
                        ),
                    ));
                } else if a.value == b.value {
                    unexpected.push(note(
                        a.scope,
                        &a.field,
                        "valor congelado: igual ao capturado e ausente da resposta pareada",
                    ));
                } else {
                    unexpected.push(note(
                        a.scope,
                        &a.field,
                        "valor sem origem no trace (não veio de resposta anterior)",
                    ));
                }
            }
        }

        // 2) demais diferenças (constantes, entradas, ambiente, trechos)
        let a_origin = origins_a.get(pair.a.request_id.as_str());
        // campo opaco decodificado por adaptador: as partes nomeadas já foram avaliadas
        let adapted: std::collections::BTreeSet<&str> = a_origin
            .into_iter()
            .flat_map(|o| o.values.iter())
            .filter_map(|v| {
                v.parent
                    .as_deref()
                    .filter(|p| v.field.starts_with(&format!("{p}.")))
            })
            .collect();
        let composed = |f: &crate::compare::FieldDiff| {
            a_origin.is_some_and(|o| {
                o.values.iter().any(|v| {
                    key_of(v.scope, &v.field, v.occurrence)
                        == key_of(f.scope, &f.field, f.occurrence)
                        && client_composed(v)
                })
            })
        };
        for f in &pair.fields {
            let env = f.scope == ConsumedScope::Cookie
                || (f.scope == ConsumedScope::Header && env_header(&f.field));
            if handled.contains(&key_of(f.scope, &f.field, f.occurrence))
                || (f.scope == ConsumedScope::Body && adapted.contains(f.field.as_str()))
            {
                continue;
            }
            match f.class {
                FieldClass::Static | FieldClass::Redacted => {}
                _ if is_param(&f.field) => {
                    expected.push(note(f.scope, &f.field, "esperado (parâmetro do usuário)"));
                }
                FieldClass::Dynamic => {
                    if env {
                        expected.push(note(
                            f.scope,
                            &f.field,
                            "ambiente (cookie/cabeçalho da execução)",
                        ));
                    } else if f.origin.is_some()
                        || f.origin_label
                            .as_deref()
                            .is_some_and(|l| l.contains("runtime"))
                    {
                        // origem existe no trace e a captura não a declarava: aceita
                        expected.push(note(
                            f.scope,
                            &f.field,
                            "dinâmico com origem observada no trace",
                        ));
                    } else if !f.parts.is_empty() {
                        for p in f.parts.iter().filter(|p| p.class == FieldClass::Dynamic) {
                            if p.origin.is_some() {
                                expected.push(note(
                                    f.scope,
                                    &f.field,
                                    "trecho dinâmico com origem observada",
                                ));
                            } else if long_opaque(&p.a) && long_opaque(&p.b) {
                                expected.push(note(
                                    f.scope,
                                    &f.field,
                                    "trecho longo gerado no cliente",
                                ));
                            } else {
                                unexpected.push(note(
                                    f.scope,
                                    &f.field,
                                    "trecho dinâmico sem origem (deveria ser constante)",
                                ));
                            }
                        }
                    } else if composed(f)
                        && long_opaque(f.a.as_deref().unwrap_or(""))
                        && long_opaque(f.b.as_deref().unwrap_or(""))
                    {
                        expected.push(note(
                            f.scope,
                            &f.field,
                            "identificador gerado no cliente (composição marcada na captura)",
                        ));
                    } else {
                        unexpected.push(note(
                            f.scope,
                            &f.field,
                            "campo que deveria ser constante mudou (sem origem)",
                        ));
                    }
                }
                FieldClass::OnlyA | FieldClass::OnlyB => {
                    let side = if f.class == FieldClass::OnlyA {
                        "só na captura"
                    } else {
                        "só no trace"
                    };
                    if env {
                        expected.push(note(f.scope, &f.field, &format!("ambiente ({side})")));
                    } else {
                        unexpected.push(note(f.scope, &f.field, side));
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
            // sem resposta: falha de transporte, tratada abaixo
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
        if seen_b.contains(&r.id) {
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
    let idx_a = |id: &str| capture.requests.iter().position(|q| q.id == id);
    let paired_a: Vec<usize> = cmp
        .pairs
        .iter()
        .filter_map(|p| idx_a(&p.a.request_id))
        .collect();
    let (lo, hi) = (
        paired_a.iter().copied().min().unwrap_or(0),
        paired_a.iter().copied().max().unwrap_or(0),
    );
    let missing: Vec<String> = cmp
        .only_in_a
        .iter()
        .filter(|r| !r.method.eq_ignore_ascii_case("GET"))
        .filter(|r| idx_a(&r.request_id).is_some_and(|i| i > lo && i < hi))
        .map(|r| r.request_id.clone())
        .collect();

    // impressão do plano × recalculada a partir da captura e do alvo, só com os
    // parâmetros do plano (`plan.parameters`); o `parameters` de topo (inclusive
    // opcionais sobrescritos pelo usuário) não entra no hash. A versão do plano
    // protege traces de builds anteriores: sem `plan.version` atual, não compara.
    let target = target_note;
    let mut plan_mismatch = false;
    if !trace.session.notes.iter().any(|n| n == PLAN_PRESENT_NOTE) {
        warnings.push("plano ausente: execução não verificada contra o plano".to_string());
    } else {
        let version =
            note_value(trace, PLAN_VERSION_NOTE_PREFIX).and_then(|v| v.parse::<u32>().ok());
        if version != Some(PLAN_VERSION) {
            let message = match version {
                Some(v) if v > PLAN_VERSION => format!(
                    "plano de versão diferente (v{v}): gere o script de novo para verificar contra o plano"
                ),
                _ => {
                    let label = version.map_or_else(|| "v1".to_string(), |v| format!("v{v}"));
                    format!(
                        "plano de versão anterior ({label}): gere o script de novo para verificar contra o plano"
                    )
                }
            };
            warnings.push(message);
        } else if let Some(declared_hash) = note_value(trace, PLAN_HASH_NOTE_PREFIX) {
            if let Some(target) = &target {
                let names: Vec<String> = trace
                    .session
                    .notes
                    .iter()
                    .filter_map(|n| n.strip_prefix(PLAN_PARAM_NOTE_PREFIX))
                    .map(str::to_string)
                    .collect();
                match plan_hash(
                    capture,
                    capture_source,
                    target,
                    &options.compare.flow,
                    &names,
                ) {
                    Ok(h) if h == declared_hash => {}
                    Ok(h) => {
                        plan_mismatch = true;
                        warnings.push(format!(
                            "plano não confere: o trace declara o hash {declared_hash} e a captura com o alvo {target} dá {h}"
                        ));
                    }
                    Err(e) => warnings.push(format!("plano não verificado: {e}")),
                }
            } else {
                warnings.push("plano sem alvo: execução não verificada contra o plano".to_string());
            }
        } else {
            warnings.push("plano sem impressão".to_string());
        }
    }

    // veredito: primeiro problema, em ordem de passo
    let mut verdict = ValidationVerdict::Equivalent;
    let (mut step, mut reason) = (None, None);
    if plan_mismatch {
        verdict = ValidationVerdict::Diverges;
        step = Some(1);
        reason = Some("plano diferente do gerado a partir desta captura".to_string());
    } else if !trace.requests.is_empty() && cmp.pairs.is_empty() {
        let oa = single_app_origin(&ctx_a);
        let ob = single_app_origin(&ctx_b);
        verdict = ValidationVerdict::Diverges;
        step = Some(1);
        reason = Some(format!(
            "nenhum passo do trace foi pareado com a captura{}; use --map-origin <origem-captura>=<origem-trace>",
            match (oa, ob) {
                (Some(a), Some(b)) if a != b => format!(" (origens diferentes: {a} × {b})"),
                _ => String::new(),
            }
        ));
    }
    if verdict == ValidationVerdict::Equivalent {
        for s in &steps {
            let transport =
                trace_err(&s.trace_request_id) || matches!(s.status_trace, None | Some(0));
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
    }
    if verdict == ValidationVerdict::Equivalent && !missing.is_empty() {
        let first = &missing[0];
        let at = idx_a(first).unwrap_or(0);
        let next = cmp
            .pairs
            .iter()
            .filter(|p| idx_a(&p.a.request_id).is_some_and(|i| i > at))
            .filter_map(|p| step_of(&p.b.request_id))
            .min();
        verdict = ValidationVerdict::Diverges;
        step = next;
        reason = Some(format!("passo ausente no trace ({first})"));
    }
    // completude: alvo declarado e pareado, e complete=true
    if verdict == ValidationVerdict::Equivalent {
        let complete = note_value(trace, COMPLETE_NOTE_PREFIX) == Some("true");
        let target_paired = target
            .as_deref()
            .is_some_and(|t| cmp.pairs.iter().any(|p| p.a.request_id == t));
        let last = trace.requests.len().max(1);
        let why = if target.is_none() {
            Some("o trace não declara `target`".to_string())
        } else if !target_paired {
            Some(format!(
                "o alvo {} não está entre os passos pareados",
                target.as_deref().unwrap_or("?")
            ))
        } else if !complete {
            Some("o trace não declara `complete=true`".to_string())
        } else {
            None
        };
        if let Some(why) = why {
            verdict = ValidationVerdict::Incomplete;
            step = Some(last);
            reason = Some(why);
        }
    }
    let mapped = cmp
        .mapped_origin
        .as_ref()
        .map(|m| format!(" [origem mapeada: {} → {}]", m.from, m.to))
        .unwrap_or_default();
    let summary = match (verdict, step) {
        (ValidationVerdict::Equivalent, _) => format!("execução equivalente à captura{mapped}"),
        (ValidationVerdict::Diverges, Some(n)) => {
            format!(
                "diverge no passo {n} ({}){mapped}",
                reason.as_deref().unwrap_or("?")
            )
        }
        (ValidationVerdict::Diverges, None) => {
            format!("diverge ({}){mapped}", reason.as_deref().unwrap_or("?"))
        }
        (ValidationVerdict::Incomplete, Some(n)) => {
            format!(
                "incompleta: parou no passo {n} ({}){mapped}",
                reason.as_deref().unwrap_or("?")
            )
        }
        (ValidationVerdict::Incomplete, None) => format!("incompleta{mapped}"),
    };
    if trace.requests.is_empty() {
        return Validation {
            schema: "scrapelens.validate/1".to_string(),
            verdict: ValidationVerdict::Incomplete,
            step: Some(1),
            reason: Some("trace sem passos".to_string()),
            summary: "incompleta: parou no passo 1 (trace sem passos)".to_string(),
            steps,
            missing_in_trace: missing,
            mapped_origin: cmp.mapped_origin,
            warnings,
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
        warnings,
    }
}
