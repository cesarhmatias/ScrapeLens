//! `site_profile`: reconhecimento do site a partir de uma sessão capturada
//! (`docs/16b-mcp-navegador.md` §5). Identifica proteções anti-bot, bloqueios e
//! exigências, **cada achado com evidência** (ids da Core) e nível de confiança,
//! e recomenda "Chrome normal basta" / "precisa de priming" / "candidato a
//! CloakBrowser" (ou "indeterminado").
//!
//! Princípios:
//! - assinaturas são dados com fonte (`signatures.json`); sem fonte, não entram;
//! - um marcador sozinho nunca é bloqueio (modelo de `core/src/assess.rs`);
//! - valores de cookie e de cabeçalho são redigidos (só enumerações
//!   documentadas, como `challenge`, aparecem);
//! - o que uma captura não prova (exigência de protocolo, cookie obrigatório) é
//!   dito como "observado", com o limite escrito;
//! - nada aqui abre rede nem executa a sessão.

mod detect;
mod recommend;
mod signatures;

use std::collections::BTreeMap;

use serde::Serialize;

use scrapelens_core::model::{CompletenessState, SessionV1};
use scrapelens_core::search::BodySource;

pub use signatures::{Signature, SignatureSet, SigKind, SourceKind, Weight, SIGNATURES_SCHEMA};

pub const PROFILE_SCHEMA: &str = "scrapelens.site-profile/1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Baixa,
    Media,
    Alta,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Baixa => "baixa",
            Confidence::Media => "media",
            Confidence::Alta => "alta",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub request_id: String,
    pub attempt_id: Option<String>,
    /// `set-cookie`, `request-cookie`, `response-header`, `request-header`,
    /// `url`, `query`, `request-body`, `response-body`, `status`.
    pub scope: String,
    pub field: Option<String>,
    /// Só enumerações documentadas; o resto vira `[redigido, N bytes]`.
    pub value: Option<String>,
    pub url: String,
    pub status: Option<u16>,
    /// `cdp`, `netlog`, `har`… (proveniência do dado na Core).
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceRef {
    pub kind: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    /// `protecao`, `desafio`, `captcha`, `bloqueio`, `cookie`, `token`,
    /// `protocolo`, `terceiro-bloqueado`.
    pub category: String,
    pub vendor: Option<String>,
    pub kind: String,
    pub signature_id: Option<String>,
    pub summary: String,
    pub confidence: Confidence,
    pub occurrences: usize,
    pub evidence: Vec<Evidence>,
    pub source: Option<SourceRef>,
    /// Desafio/bloqueio: houve depois uma resposta bem-sucedida na mesma rota
    /// (ou cookie de liberação)? `None` quando não se aplica.
    pub resolved_later: Option<bool>,
    pub limits: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RecommendationValue {
    #[serde(rename = "chrome-normal-basta")]
    ChromeNormalBasta,
    #[serde(rename = "precisa-de-priming")]
    PrecisaDePriming,
    #[serde(rename = "candidato-a-cloakbrowser")]
    CandidatoACloakbrowser,
    #[serde(rename = "indeterminado")]
    Indeterminado,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Recommendation {
    pub value: RecommendationValue,
    pub confidence: Confidence,
    pub reasons: Vec<String>,
    pub limits: Vec<String>,
    /// Ids dos achados que sustentam a recomendação.
    pub based_on: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Sample {
    pub requests: usize,
    pub documents: usize,
    pub app_requests: usize,
    pub partial: bool,
    /// Protocolo observado por origem (`https://host:porta` → `["h2"]`).
    pub protocols: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SiteProfile {
    pub schema: &'static str,
    pub session_id: String,
    pub sample: Sample,
    pub findings: Vec<Finding>,
    pub recommendation: Recommendation,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ProfileOptions {
    /// Máximo de evidências por achado.
    pub max_evidence: usize,
    /// Requisição alvo para rastrear tokens; `None` = as últimas da aplicação.
    pub target_request_id: Option<String>,
    /// Quantas requisições da aplicação passam por `flow::value_origins`.
    pub max_token_targets: usize,
    /// Limite de bytes lidos de cada corpo.
    pub body_limit: usize,
}

impl Default for ProfileOptions {
    fn default() -> Self {
        Self {
            max_evidence: 5,
            target_request_id: None,
            max_token_targets: 5,
            body_limit: 256 * 1024,
        }
    }
}

/// Perfil com a tabela de assinaturas embutida.
pub fn site_profile(
    session: &SessionV1,
    bodies: &dyn BodySource,
    options: &ProfileOptions,
) -> SiteProfile {
    site_profile_with(session, bodies, options, &SignatureSet::embedded())
}

pub fn site_profile_with(
    session: &SessionV1,
    bodies: &dyn BodySource,
    options: &ProfileOptions,
    signatures: &SignatureSet,
) -> SiteProfile {
    let mut warnings: Vec<String> = Vec::new();
    let mut findings = detect::detect(session, bodies, options, signatures, &mut warnings);
    // Ids estáveis por ordem de aparição.
    for (i, finding) in findings.iter_mut().enumerate() {
        finding.id = format!("F{:03}", i + 1);
    }
    let sample = detect::sample(session);
    let partial = session.session.completeness.state != CompletenessState::Complete;
    let recommendation = recommend::recommend(session, &sample, partial, &findings, signatures);
    SiteProfile {
        schema: PROFILE_SCHEMA,
        session_id: session.session.id.clone(),
        sample,
        findings,
        recommendation,
        warnings,
    }
}
