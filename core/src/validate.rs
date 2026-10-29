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
//! aviso "parâmetro inválido".

use std::collections::HashMap;

use serde::Serialize;

use crate::assess::{assess_session, AssessRules, VerdictKind};
use crate::compare::{compare_sessions, single_app_origin, CompareOptions, FieldClass, OriginMap};
use crate::error::{CoreError, Result};
use crate::export::priming::{to_python, PrimingOptions};
use crate::flow::{
    origins_in, ConsumedScope, FlowContext, OriginStatus, ValueOrigin, ValueOrigins,
};
use crate::model::SessionV1;
use crate::parse::trace::{
    COMPLETE_NOTE_PREFIX, PARAM_NOTE_PREFIX, PLAN_HASH_NOTE_PREFIX, TARGET_NOTE_PREFIX,
};
use crate::search::BodySource;

#[derive(Debug, Clone, Default)]
pub struct ValidateOptions {
    pub compare: CompareOptions,
    /// Opções do gerador de priming para recalcular o `plan.hash` (as mesmas do
    /// script, inclusive codificadores de adaptador).
    pub priming: PrimingOptions,
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

/// Impressão do plano de um alvo, recalculada a partir da captura pelo gerador
/// de priming (mesmas opções do script): SHA-256 de uma linha
/// `<requestId> <MÉTODO> <URL sem query nem fragmento>` por passo do plano, na
/// ordem, seguida de uma linha com os nomes de TODOS os parâmetros do script,
/// ordenados e separados por vírgula (linhas unidas por `\n`). É a mesma
/// definição de `trace_plan_hash` no script gerado.
pub fn plan_hash(
    capture: &SessionV1,
    source: &dyn BodySource,
    target: &str,
    opts: &PrimingOptions,
) -> Result<String> {
    let script = to_python(capture, source, target, opts)?;
    let (steps, params) = parse_plan(&script.text).ok_or_else(|| CoreError::Export {
        message: "plano do script gerado não reconhecido".to_string(),
    })?;
    let mut lines: Vec<String> = steps
        .iter()
        .map(|(id, method, url)| {
            let url = url.split('?').next().unwrap_or("");
            let url = url.split('#').next().unwrap_or("");
            format!("{id} {method} {url}")
        })
        .collect();
    let mut names = params;
    names.sort();
    lines.push(names.join(","));
    Ok(sha256_hex(lines.join("\n").as_bytes()))
}

/// Lê `PLAN = [...]` e `PARAMS = [...]` do script gerado (literais Python).
type PlanStep = (String, String, String);

fn parse_plan(text: &str) -> Option<(Vec<PlanStep>, Vec<String>)> {
    let section = |name: &str| -> Option<Vec<Vec<String>>> {
        let start = text.find(&format!("\n{name} = [\n"))? + name.len() + 6;
        let body = &text[start..];
        let end = body
            .find("\n]\n")
            .or_else(|| body.strip_prefix("]\n").map(|_| 0))?;
        let mut rows = Vec::new();
        for line in body[..end].lines() {
            let line = line.trim_start().strip_prefix('(')?;
            let mut items = Vec::new();
            let mut rest = line;
            while let Some(r) = rest.strip_prefix('\'') {
                let (lit, after) = py_string(r)?;
                items.push(lit);
                rest = after.trim_start_matches([',', ' ']);
                if !rest.starts_with('\'') {
                    break;
                }
            }
            rows.push(items);
        }
        Some(rows)
    };
    let steps = section("PLAN")?
        .into_iter()
        .map(|r| Some((r.first()?.clone(), r.get(1)?.clone(), r.get(2)?.clone())))
        .collect::<Option<Vec<_>>>()?;
    let params = section("PARAMS")?
        .into_iter()
        .map(|r| r.first().cloned())
        .collect::<Option<Vec<_>>>()?;
    Some((steps, params))
}

/// Lê um literal Python de aspas simples (já sem a aspa de abertura).
fn py_string(s: &str) -> Option<(String, &str)> {
    let mut out = String::new();
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\'' => return Some((out, &s[i + 1..])),
            '\\' => {
                let (_, e) = chars.next()?;
                match e {
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'x' | 'u' | 'U' => {
                        let n = match e {
                            'x' => 2,
                            'u' => 4,
                            _ => 8,
                        };
                        let mut code = 0u32;
                        for _ in 0..n {
                            code = code * 16 + chars.next()?.1.to_digit(16)?;
                        }
                        out.push(char::from_u32(code)?);
                    }
                    other => out.push(other),
                }
            }
            c => out.push(c),
        }
    }
    None
}

fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [
                t1.wrapping_add(t2),
                v[0],
                v[1],
                v[2],
                v[3].wrapping_add(t1),
                v[4],
                v[5],
                v[6],
            ];
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

fn note_value<'a>(trace: &'a SessionV1, prefix: &str) -> Option<&'a str> {
    trace
        .session
        .notes
        .iter()
        .find_map(|n| n.strip_prefix(prefix))
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

    // parâmetros declarados: só valem para campos sem origem e não constantes
    let declared: Vec<&str> = trace
        .session
        .notes
        .iter()
        .filter_map(|n| n.strip_prefix(PARAM_NOTE_PREFIX))
        .collect();
    let mut params: Vec<&str> = Vec::new();
    for name in &declared {
        let mut seen = false;
        let mut why: Option<&str> = None;
        for o in origins_a.values() {
            for v in o.values.iter().filter(|v| {
                matches!(v.scope, ConsumedScope::Body | ConsumedScope::Query)
                    && v.field.eq_ignore_ascii_case(name)
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
                "parâmetro inválido: `{name}` não existe nos passos pareados da captura"
            )),
            (true, Some(why)) => warnings.push(format!("parâmetro inválido: `{name}` {why}")),
            (true, None) => params.push(name),
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

    // impressão do plano (se declarada) × recalculada a partir da captura e do alvo
    let target = note_value(trace, TARGET_NOTE_PREFIX).map(str::to_string);
    if let (Some(declared_hash), Some(target)) = (note_value(trace, PLAN_HASH_NOTE_PREFIX), &target)
    {
        let mut popts = options.priming.clone();
        if popts.flow.adapters.is_empty() {
            popts.flow = options.compare.flow.clone();
        }
        match plan_hash(capture, capture_source, target, &popts) {
            Ok(h) if h == declared_hash => {}
            Ok(h) => warnings.push(format!(
                "plano não confere: o trace declara o hash {declared_hash} e a captura com o alvo {target} dá {h}"
            )),
            Err(e) => warnings.push(format!("plano não verificado: {e}")),
        }
    }

    // veredito: primeiro problema, em ordem de passo
    let mut verdict = ValidationVerdict::Equivalent;
    let (mut step, mut reason) = (None, None);
    if !trace.requests.is_empty() && cmp.pairs.is_empty() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let long = vec![b'a'; 1000];
        assert_eq!(
            sha256_hex(&long),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
    }

    #[test]
    fn python_literals_round_trip() {
        let (s, rest) = py_string("a\\'b\\\\c\\x41\\u00e9' tail").unwrap();
        assert_eq!(s, "a'b\\cAé");
        assert_eq!(rest, " tail");
    }
}
