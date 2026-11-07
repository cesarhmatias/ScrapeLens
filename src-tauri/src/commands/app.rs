//! App information and the demo session.

use super::*;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub version: String,
    pub tauri: String,
    pub arch: String,
    pub platform: String,
    pub demo_fixture: bool,
    pub schema_version: u32,
}

pub(super) fn demo_session_value() -> Result<Value, String> {
    let raw = include_str!("../../../app/src/demo/session.v1.json");
    let value: Value =
        serde_json::from_str(raw).map_err(|error| format!("invalid demo fixture: {error}"))?;
    Ok(value)
}

#[tauri::command]
pub fn app_info() -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        tauri: tauri::VERSION.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        platform: std::env::consts::OS.to_string(),
        demo_fixture: true,
        schema_version: 1,
    }
}

/// Contract v1 fixture, always labeled as synthetic.
#[tauri::command]
pub fn demo_session() -> Result<SessionPayload, String> {
    let session = demo_session_value()?;
    Ok(SessionPayload {
        session,
        session_dir: None,
        session_token: None,
        synthetic: true,
        notice: None,
        cookie_import: None,
        pending: false,
    })
}
