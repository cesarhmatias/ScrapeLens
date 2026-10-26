//! Importadores. Preenchido nas etapas seguintes.
use crate::error::Result;
use crate::model::SessionBundle;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InputFormat { OwnV1, Har, NetLog, Cdp }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport { pub format: Option<InputFormat>, pub warnings: Vec<crate::model::Warning> }

pub fn import_session_dir(_path: &std::path::Path) -> Result<SessionBundle> { todo!() }
pub fn import_har(_json: &[u8]) -> Result<SessionBundle> { todo!() }
pub fn import_netlog(_json: &[u8]) -> Result<SessionBundle> { todo!() }
