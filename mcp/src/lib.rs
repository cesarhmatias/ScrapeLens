//! Servidor MCP local e somente leitura do ScrapeLens. Contrato:
//! `docs/16-mcp-contrato.md`.

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod project;
pub mod registry;
pub mod server;
pub mod tools;

pub use config::Config;
pub use registry::Ctx;
