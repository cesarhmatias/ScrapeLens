//! `site_profile`: recognition of the site from a captured session
//! (`docs/16b-mcp-navegador.md` §5). Identifies anti-bot protections, blocks and
//! requirements, **each finding with evidence** (Core ids) and a confidence level,
//! and recommends "normal Chrome is enough" / "needs priming" / "candidate for
//! CloakBrowser" (or "indeterminate").
//!
//! Principles:
//! - signatures are data with a source (`signatures.json`); without a source, they are not used;
//! - a marker alone is never a block (model from `core/src/assess.rs`);
//! - cookie and header values are redacted (only documented enumerations,
//!   such as `challenge`, appear);
//! - what a capture does not prove (protocol requirement, mandatory cookie) is
//!   stated as "observed", with its limit written down;
//! - nothing here opens the network or runs the session.

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
    /// Only documented enumerations; the rest becomes `[redacted, N bytes]`.
    pub value: Option<String>,
    pub url: String,
    pub status: Option<u16>,
    /// `cdp`, `netlog`, `har`… (data provenance in Core).
    pub source: Option<String>,
    /// The evidence comes from a resource on ANOTHER host than the target site's
    /// documents: it does not attribute the protection to the target.
    pub third_party: bool,
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
    /// Challenge/block: was there later a successful response on the same route
    /// (or a clearance cookie)? `None` when not applicable.
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
    /// Ids of the findings that support the recommendation.
    pub based_on: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Sample {
    pub requests: usize,
    pub documents: usize,
    pub app_requests: usize,
    pub partial: bool,
    /// Protocol observed per origin (`https://host:port` → `["h2"]`).
    pub protocols: BTreeMap<String, Vec<String>>,
}

/// In what context the session was captured (`capture.chromeArgs` in `session.json`).
/// `None` = the session does not say (imported from HAR/NetLog, or captured before D7).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CaptureContext {
    /// `--disable-blink-features=AutomationControlled` at launch: the site saw
    /// `navigator.webdriver === false` even with CDP on (D7). An anti-bot challenge
    /// seen with this `true` does not come from the automation warning.
    pub automation_flag_suppressed: Option<bool>,
    pub headless: Option<bool>,
}

fn capture_context(session: &SessionV1) -> CaptureContext {
    let capture = session.session.capture.as_ref();
    let suppressed = capture.and_then(|c| c.chrome_args.as_ref()).map(|args| {
        args.iter().any(|arg| {
            arg.strip_prefix("--disable-blink-features=")
                .is_some_and(|values| values.split(',').any(|v| v.trim() == "AutomationControlled"))
        })
    });
    CaptureContext {
        automation_flag_suppressed: suppressed,
        headless: capture.and_then(|c| c.headless),
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SiteProfile {
    pub schema: &'static str,
    pub session_id: String,
    /// Capture context (automation warning suppressed? headless?).
    pub capture_context: CaptureContext,
    pub sample: Sample,
    pub findings: Vec<Finding>,
    pub recommendation: Recommendation,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ProfileOptions {
    /// Maximum evidence per finding.
    pub max_evidence: usize,
    /// Target request for tracing tokens; `None` = the last application requests.
    pub target_request_id: Option<String>,
    /// How many application requests go through `flow::value_origins`.
    pub max_token_targets: usize,
    /// Byte limit read from each body.
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

/// Profile with the embedded signature table.
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
    // Stable ids, in order of appearance.
    for (i, finding) in findings.iter_mut().enumerate() {
        finding.id = format!("F{:03}", i + 1);
    }
    let sample = detect::sample(session);
    let partial = session.session.completeness.state != CompletenessState::Complete;
    let recommendation = recommend::recommend(session, &sample, partial, &findings, signatures);
    SiteProfile {
        schema: PROFILE_SCHEMA,
        session_id: session.session.id.clone(),
        capture_context: capture_context(session),
        sample,
        findings,
        recommendation,
        warnings,
    }
}
