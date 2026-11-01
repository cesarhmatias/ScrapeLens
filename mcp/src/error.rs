//! Erros de ferramenta: viram `isError: true` com `{"error":{code,message}}`.

use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct ToolError {
    pub code: &'static str,
    pub message: String,
}

impl ToolError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new("invalid_argument", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new("not_found", message)
    }

    pub fn to_value(&self) -> Value {
        // A mensagem pode ecoar texto do agente (ids, caminhos): sem controle nem bidi.
        json!({"error": {"code": self.code, "message": crate::live::escape_display(&self.message)}})
    }
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl From<scrapelens_core::CoreError> for ToolError {
    fn from(error: scrapelens_core::CoreError) -> Self {
        ToolError::new("io", error.to_string())
    }
}

pub type ToolResult = Result<Value, ToolError>;
