//! Extension point for protocol decoders (outside the core).
//!
//! The core knows no protocol: a [`ProtocolAdapter`] claims a field (`detect`),
//! decodes it into ordered parts with offsets in the original text (`decode`)
//! and re-encodes it (`encode`). Without registration, the behavior is the usual
//! one (common substrings). The registry is passed through `FlowOptions.adapters`
//! (and from there through `CompareOptions.flow` and the priming options); it is
//! not serialized.

use std::fmt;
use std::sync::Arc;

use crate::error::Result;

/// Where the field was read; the adapter decides only from this and the value.
#[derive(Debug, Clone, Copy)]
pub struct AdapterContext<'a> {
    pub url: &'a str,
    pub method: &'a str,
    /// `true` for a request field, `false` for a response.
    pub request: bool,
    /// Media type of the body that contains the field, when known.
    pub media: Option<&'a str>,
}

/// Role of a decoded part (the interpretation belongs to the adapter).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartRole {
    /// Header, length prefix, separator: structure with no business value.
    Structure,
    /// Field/property name.
    Name,
    /// Value associated with a name.
    Value,
    /// Incremental delta/state.
    Delta,
    Other(String),
}

/// Named fragment of the field. `offset`/`len` are in bytes of the original text
/// (the `value` may be the decoded text, e.g. unescaped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterPart {
    /// Internal name relative to the field (`delta`, `p.v_placa`); the core prefixes the field (`XML.delta`).
    pub name: String,
    pub value: String,
    pub offset: usize,
    pub len: usize,
    pub role: PartRole,
}

/// Generic structure: parts in the order of the original, without reordering.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decoded {
    pub parts: Vec<AdapterPart>,
}

pub trait ProtocolAdapter: Send + Sync {
    /// Stable identifier (`natural-ajax`).
    fn id(&self) -> &str;
    /// Does this adapter claim the field `field` with this value?
    fn detect(&self, field: &str, value: &str, ctx: &AdapterContext<'_>) -> bool;
    /// Decodes the value; an error when it does not follow the grammar (the core
    /// falls back to the behavior without an adapter and warns).
    fn decode(&self, value: &str) -> Result<Decoded>;
    /// Re-encodes, recalculating whatever the protocol requires (e.g. lengths).
    fn encode(&self, decoded: &Decoded) -> Result<String>;
    /// Short name of the operation for labels (timeline), when the common parts
    /// are not enough (e.g. the operation in the header). Default: none.
    fn label_hint(&self, _decoded: &Decoded) -> Option<String> {
        None
    }
}

/// Ordered list of adapters; the first one that claims the field wins.
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

    /// Registered adapters, in precedence order.
    pub fn iter(&self) -> impl Iterator<Item = &Arc<dyn ProtocolAdapter>> {
        self.adapters.iter()
    }

    pub fn get(&self, id: &str) -> Option<&Arc<dyn ProtocolAdapter>> {
        self.adapters.iter().find(|a| a.id() == id)
    }

    /// First adapter that claims the field.
    pub fn claim(
        &self,
        field: &str,
        value: &str,
        ctx: &AdapterContext<'_>,
    ) -> Option<&Arc<dyn ProtocolAdapter>> {
        self.adapters.iter().find(|a| a.detect(field, value, ctx))
    }
}
