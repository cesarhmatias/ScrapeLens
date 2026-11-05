//! ScrapeLens local, read-only MCP server. Contract:
//! `docs/16-mcp-contract.md`.

#![forbid(unsafe_code)]

pub mod app;
pub mod cli;
pub mod config;
pub mod error;
pub mod live;
pub mod project;
pub mod registry;
pub mod server;
pub mod tools;

pub use config::Config;
pub use registry::Ctx;
