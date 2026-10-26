use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, CoreError>;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("falha de I/O em {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("JSON inválido em {context}: {message}")]
    Json { context: String, message: String },

    #[error("formato não suportado: {message}")]
    UnsupportedFormat { message: String },

    #[error("schemaVersion {found} não suportado (esperado {expected})")]
    UnsupportedSchema { found: u32, expected: u32 },

    #[error("dado obrigatório ausente: {field}")]
    MissingField { field: String },

    #[error("caminho de anexo inválido: {name}")]
    InvalidAttachmentPath { name: String },

    #[error("limite excedido: {message}")]
    LimitExceeded { message: String },

    #[error("exportação impossível: {message}")]
    Export { message: String },
}

impl CoreError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        CoreError::Io {
            path: path.into(),
            source,
        }
    }

    pub fn json(context: impl Into<String>, error: serde_json::Error) -> Self {
        CoreError::Json {
            context: context.into(),
            message: error.to_string(),
        }
    }
}
