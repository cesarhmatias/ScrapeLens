//! Ponto de extensão para decodificadores de protocolo (fora do core).
//!
//! O core não conhece nenhum protocolo: um [`ProtocolAdapter`] reivindica um
//! campo (`detect`), o decodifica em partes ordenadas com offsets no texto
//! original (`decode`) e o recodifica (`encode`). Sem registro, o
//! comportamento é o de sempre (substrings comuns). O registro é passado por
//! `FlowOptions.adapters` (e daí por `CompareOptions.flow` e pelas opções de
//! priming); não é serializado.

use std::fmt;
use std::sync::Arc;

use crate::error::Result;

/// Onde o campo foi lido; o adaptador decide só com isso e com o valor.
#[derive(Debug, Clone, Copy)]
pub struct AdapterContext<'a> {
    pub url: &'a str,
    pub method: &'a str,
    /// `true` para campo de requisição, `false` para resposta.
    pub request: bool,
    /// Tipo de mídia do corpo que contém o campo, quando conhecido.
    pub media: Option<&'a str>,
}

/// Papel de uma parte decodificada (a interpretação é do adaptador).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartRole {
    /// Cabeçalho, prefixo de comprimento, separador: estrutura sem valor de negócio.
    Structure,
    /// Nome de campo/propriedade.
    Name,
    /// Valor associado a um nome.
    Value,
    /// Delta/estado incremental.
    Delta,
    Other(String),
}

/// Trecho nomeado do campo. `offset`/`len` são em bytes do texto original
/// (o `value` pode ser o texto decodificado, ex. unescape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterPart {
    /// Nome interno relativo ao campo (`delta`, `p.v_placa`); o core prefixa o campo (`XML.delta`).
    pub name: String,
    pub value: String,
    pub offset: usize,
    pub len: usize,
    pub role: PartRole,
}

/// Estrutura genérica: partes em ordem do original, sem reordenar.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decoded {
    pub parts: Vec<AdapterPart>,
}

pub trait ProtocolAdapter: Send + Sync {
    /// Identificador estável (`natural-ajax`).
    fn id(&self) -> &str;
    /// Este adaptador reivindica o campo `field` com este valor?
    fn detect(&self, field: &str, value: &str, ctx: &AdapterContext<'_>) -> bool;
    /// Decodifica o valor; erro quando não obedece à gramática (o core volta
    /// ao comportamento sem adaptador e avisa).
    fn decode(&self, value: &str) -> Result<Decoded>;
    /// Recodifica, recalculando o que o protocolo exigir (ex. comprimentos).
    fn encode(&self, decoded: &Decoded) -> Result<String>;
    /// Nome curto da operação para rótulos (timeline), quando as partes comuns
    /// não bastam (ex. a operação do cabeçalho). Padrão: nenhum.
    fn label_hint(&self, _decoded: &Decoded) -> Option<String> {
        None
    }
}

/// Lista ordenada de adaptadores; o primeiro que reivindica o campo vence.
#[derive(Clone, Default)]
pub struct AdapterRegistry {
    adapters: Vec<Arc<dyn ProtocolAdapter>>,
}

impl fmt::Debug for AdapterRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.adapters.iter().map(|a| a.id()))
            .finish()
    }
}

impl AdapterRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, adapter: Arc<dyn ProtocolAdapter>) -> Self {
        self.adapters.push(adapter);
        self
    }

    pub fn register(&mut self, adapter: Arc<dyn ProtocolAdapter>) {
        self.adapters.push(adapter);
    }

    pub fn is_empty(&self) -> bool {
        self.adapters.is_empty()
    }

    pub fn get(&self, id: &str) -> Option<&Arc<dyn ProtocolAdapter>> {
        self.adapters.iter().find(|a| a.id() == id)
    }

    /// Primeiro adaptador que reivindica o campo.
    pub fn claim(
        &self,
        field: &str,
        value: &str,
        ctx: &AdapterContext<'_>,
    ) -> Option<&Arc<dyn ProtocolAdapter>> {
        self.adapters.iter().find(|a| a.detect(field, value, ctx))
    }
}
