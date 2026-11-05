use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, CoreError>;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("I/O failure at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid JSON in {context}: {message}")]
    Json { context: String, message: String },

    #[error("unsupported format: {message}")]
    UnsupportedFormat { message: String },

    #[error("unsupported schemaVersion {found} (expected {expected})")]
    UnsupportedSchema { found: u32, expected: u32 },

    #[error("required data missing: {field}")]
    MissingField { field: String },

    #[error("invalid attachment path: {name}")]
    InvalidAttachmentPath { name: String },

    #[error("limit exceeded: {message}")]
    LimitExceeded { message: String },

    #[error("export impossible: {message}")]
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
