//! Signatures as DATA (`signatures.json`), each with a consulted source.
//! Without a source (`source.url` and `source.quote`), the signature is rejected on load.

use std::collections::BTreeSet;

use serde::Deserialize;

pub const SIGNATURES_SCHEMA: &str = "scrapelens.recon-signatures/1";
const EMBEDDED: &str = include_str!("../signatures.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigKind {
    Cookie,
    ResponseHeader,
    RequestHeader,
    Host,
    FormField,
    Path,
}

impl SigKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SigKind::Cookie => "cookie",
            SigKind::ResponseHeader => "response-header",
            SigKind::RequestHeader => "request-header",
            SigKind::Host => "script-host",
            SigKind::FormField => "form-field",
            SigKind::Path => "path",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Weight {
    /// The product is present; does not prove a block.
    Present,
    /// Per the vendor's own documentation, the response is a challenge/block.
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    Fornecedor,
    Secundaria,
    Projeto,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::Fornecedor => "fornecedor",
            SourceKind::Secundaria => "secundaria",
            SourceKind::Projeto => "projeto",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Source {
    pub kind: SourceKind,
    pub url: String,
    pub quote: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub id: String,
    pub vendor: String,
    pub kind: SigKind,
    pub category: String,
    pub weight: Weight,
    pub summary: String,
    pub source: Source,
    /// Cookie: exact names.
    #[serde(default)]
    pub names: Vec<String>,
    /// Cookie: prefixes.
    #[serde(default)]
    pub prefixes: Vec<String>,
    /// Header / form field: name.
    #[serde(default)]
    pub name: Option<String>,
    /// Header: matches only one of these values (lowercase).
    #[serde(default)]
    pub values: Vec<String>,
    /// Header: values that mean block/challenge.
    #[serde(default)]
    pub block_values: Vec<String>,
    /// Header: any value OUTSIDE this list means block/challenge.
    #[serde(default)]
    pub block_unless: Vec<String>,
    /// Header: documented HTTP status for each block value.
    #[serde(default)]
    pub value_status: std::collections::BTreeMap<String, u16>,
    /// Host: equal to / suffix of.
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub host_suffix: Option<String>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub path_contains: Option<String>,
    /// The cookie indicates that a challenge was solved in this browser.
    #[serde(default)]
    pub clearance: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct File {
    schema: String,
    signatures: Vec<Signature>,
}

#[derive(Debug, Clone)]
pub struct SignatureSet {
    pub signatures: Vec<Signature>,
}

impl SignatureSet {
    /// The table shipped with the crate.
    pub fn embedded() -> SignatureSet {
        SignatureSet::from_json(EMBEDDED).expect("embedded signatures.json is valid")
    }

    pub fn from_json(text: &str) -> Result<SignatureSet, String> {
        let file: File = serde_json::from_str(text).map_err(|e| format!("signatures.json: {e}"))?;
        if file.schema != SIGNATURES_SCHEMA {
            return Err(format!("unknown schema: {}", file.schema));
        }
        let set = SignatureSet {
            signatures: file.signatures,
        };
        set.validate()?;
        Ok(set)
    }

    pub fn validate(&self) -> Result<(), String> {
        let mut ids = BTreeSet::new();
        for s in &self.signatures {
            if !ids.insert(s.id.clone()) {
                return Err(format!("repeated id: {}", s.id));
            }
            if s.source.url.trim().is_empty() || s.source.quote.trim().is_empty() {
                return Err(format!("{}: signature without source (url and quote are required)", s.id));
            }
            let ok = match s.kind {
                SigKind::Cookie => !s.names.is_empty() || !s.prefixes.is_empty(),
                SigKind::ResponseHeader | SigKind::RequestHeader => s.name.is_some(),
                SigKind::Host => s.host.is_some() || s.host_suffix.is_some(),
                SigKind::FormField => s.name.is_some(),
                SigKind::Path => s.path_prefix.is_some(),
            };
            if !ok {
                return Err(format!("{}: required fields for type {:?} are missing", s.id, s.kind));
            }
            if s.weight == Weight::Block
                && s.block_values.is_empty()
                && s.block_unless.is_empty()
            {
                return Err(format!("{}: weight=block requires block_values or block_unless", s.id));
            }
        }
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&Signature> {
        self.signatures.iter().find(|s| s.id == id)
    }
}
