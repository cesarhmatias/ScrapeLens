//! Assinaturas como DADOS (`signatures.json`), cada uma com fonte consultada.
//! Sem fonte (`source.url` e `source.quote`), a assinatura é recusada na carga.

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
    /// O produto está presente; não prova bloqueio.
    Present,
    /// Pela própria documentação do fornecedor, a resposta é um desafio/bloqueio.
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
    /// Cookie: nomes exatos.
    #[serde(default)]
    pub names: Vec<String>,
    /// Cookie: prefixos.
    #[serde(default)]
    pub prefixes: Vec<String>,
    /// Cabeçalho / campo de formulário: nome.
    #[serde(default)]
    pub name: Option<String>,
    /// Cabeçalho: só casa com um destes valores (minúsculos).
    #[serde(default)]
    pub values: Vec<String>,
    /// Cabeçalho: valores que significam bloqueio/desafio.
    #[serde(default)]
    pub block_values: Vec<String>,
    /// Cabeçalho: qualquer valor FORA desta lista significa bloqueio/desafio.
    #[serde(default)]
    pub block_unless: Vec<String>,
    /// Cabeçalho: status HTTP documentado para cada valor de bloqueio.
    #[serde(default)]
    pub value_status: std::collections::BTreeMap<String, u16>,
    /// Host: igual a / sufixo de.
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub host_suffix: Option<String>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub path_contains: Option<String>,
    /// O cookie indica que um desafio foi resolvido neste navegador.
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
    /// A tabela entregue com o crate.
    pub fn embedded() -> SignatureSet {
        SignatureSet::from_json(EMBEDDED).expect("signatures.json embutido é válido")
    }

    pub fn from_json(text: &str) -> Result<SignatureSet, String> {
        let file: File = serde_json::from_str(text).map_err(|e| format!("signatures.json: {e}"))?;
        if file.schema != SIGNATURES_SCHEMA {
            return Err(format!("esquema desconhecido: {}", file.schema));
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
                return Err(format!("id repetido: {}", s.id));
            }
            if s.source.url.trim().is_empty() || s.source.quote.trim().is_empty() {
                return Err(format!("{}: assinatura sem fonte (url e citação são obrigatórias)", s.id));
            }
            let ok = match s.kind {
                SigKind::Cookie => !s.names.is_empty() || !s.prefixes.is_empty(),
                SigKind::ResponseHeader | SigKind::RequestHeader => s.name.is_some(),
                SigKind::Host => s.host.is_some() || s.host_suffix.is_some(),
                SigKind::FormField => s.name.is_some(),
                SigKind::Path => s.path_prefix.is_some(),
            };
            if !ok {
                return Err(format!("{}: campos obrigatórios do tipo {:?} ausentes", s.id, s.kind));
            }
            if s.weight == Weight::Block
                && s.block_values.is_empty()
                && s.block_unless.is_empty()
            {
                return Err(format!("{}: weight=block exige block_values ou block_unless", s.id));
            }
        }
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&Signature> {
        self.signatures.iter().find(|s| s.id == id)
    }
}
