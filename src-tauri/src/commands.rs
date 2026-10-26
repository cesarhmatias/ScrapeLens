//! Commands da ponte UI ↔ shell. Contrato v1: docs/03-contratos.md.
//!
//! Nota de integração: `start_session`, `import_har` e `import_netlog` ainda
//! devolvem a fixture sintética com `pending: true`; quando o core/ expuser
//! captura e parsers, só o corpo destes três commands muda — a assinatura
//! usada pela UI é estável.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;
use tauri::{AppHandle, State};

use crate::chrome::{self, ChromeInfo};
use crate::prefs;
use crate::AppState;

/// Resposta uniforme dos commands que carregam uma sessão.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionPayload {
    pub session: Value,
    pub session_dir: Option<String>,
    pub synthetic: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notice: Option<String>,
    pub pending: bool,
}

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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentPayload {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub bytes: u64,
}

fn demo_session_value() -> Result<Value, String> {
    let raw = include_str!("../../app/src/demo/session.v1.json");
    let value: Value = serde_json::from_str(raw).map_err(|error| format!("fixture demo inválida: {error}"))?;
    Ok(value)
}

fn demo_label(value: &mut Value) {
    if let Some(labels) = value
        .pointer_mut("/session/labels")
        .and_then(Value::as_array_mut)
    {
        let has = labels.iter().any(|item| item.as_str() == Some("synthetic-fixture"));
        if !has {
            labels.push(Value::String("synthetic-fixture".to_string()));
        }
    }
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

/// Fixture do contrato v1, sempre rotulada como sintética.
#[tauri::command]
pub fn demo_session() -> Result<SessionPayload, String> {
    let session = demo_session_value()?;
    Ok(SessionPayload {
        session,
        session_dir: None,
        synthetic: true,
        notice: None,
        pending: false,
    })
}

/// Abre uma sessão v1 real (pasta com session.json ou o arquivo direto).
/// Esta parte já é funcional e não depende do core para ler o documento.
#[tauri::command]
pub fn open_session(path: String, state: State<'_, AppState>) -> Result<SessionPayload, String> {
    let payload = read_session_payload(&path)?;
    *state.last_session_dir.lock().expect("session_dir lock") =
        payload.session_dir.as_ref().map(PathBuf::from);
    Ok(payload)
}

fn read_session_payload(path: &str) -> Result<SessionPayload, String> {
    let chosen = PathBuf::from(path);
    if !chosen.exists() {
        return Err(format!("caminho não encontrado: {path}"));
    }
    let (session_file, session_dir) = if chosen.is_dir() {
        (chosen.join("session.json"), chosen)
    } else {
        let parent = chosen
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| "o arquivo não tem pasta pai".to_string())?;
        (chosen, parent)
    };

    let raw = fs::read_to_string(&session_file)
        .map_err(|error| format!("não foi possível ler {}: {error}", session_file.display()))?;
    let session: Value =
        serde_json::from_str(&raw).map_err(|error| format!("session.json inválido: {error}"))?;

    let version = session
        .get("schemaVersion")
        .and_then(Value::as_u64)
        .ok_or_else(|| "session.json sem schemaVersion".to_string())?;
    if version != 1 {
        return Err(format!(
            "schemaVersion {version} não é suportado por este app (esperado: 1)"
        ));
    }
    if session.pointer("/session/id").and_then(Value::as_str).is_none() {
        return Err("session.json sem session.id".to_string());
    }

    let labels = session
        .pointer("/session/labels")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let synthetic = labels
        .iter()
        .any(|label| label.as_str() == Some("synthetic-fixture"));
    let partial = session
        .pointer("/session/completeness/state")
        .and_then(Value::as_str)
        .map(|state| state != "complete")
        .unwrap_or(true);
    let requests = session
        .get("requests")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);

    Ok(SessionPayload {
        session,
        session_dir: Some(session_dir.display().to_string()),
        synthetic,
        notice: Some(format!(
            "Sessão aberta: {requests} requisição(ões){}.",
            if partial { " · sessão parcial, como declarada pela fonte" } else { "" }
        )),
        pending: false,
    })
}

fn pending_demo(what: &str, path: &Path) -> Result<SessionPayload, String> {
    if !path.exists() {
        return Err(format!("arquivo não encontrado: {}", path.display()));
    }
    let mut session = demo_session_value()?;
    demo_label(&mut session);
    Ok(SessionPayload {
        session,
        session_dir: None,
        synthetic: true,
        notice: Some(format!(
            "Importador de {what} ainda não está conectado ao core/ Rust; o arquivo {} não foi interpretado. \
             Exibindo a sessão de demonstração sintética.",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("selecionado")
        )),
        pending: true,
    })
}

#[tauri::command]
pub fn import_har(path: String) -> Result<SessionPayload, String> {
    pending_demo("HAR", Path::new(&path))
}

#[tauri::command]
pub fn import_netlog(path: String) -> Result<SessionPayload, String> {
    pending_demo("NetLog", Path::new(&path))
}

/// Captura ao vivo: o command já existe e já devolve o contrato v1, mas o
/// launcher de Chrome/CDP/NetLog pertence ao core/. Nada é aberto aqui.
#[tauri::command]
pub fn start_session() -> Result<SessionPayload, String> {
    let mut session = demo_session_value()?;
    demo_label(&mut session);
    Ok(SessionPayload {
        session,
        session_dir: None,
        synthetic: true,
        notice: Some(
            "Captura ao vivo ainda não está conectada: o launcher de Chrome/CDP/NetLog é do core/. \
             Nenhum Chrome foi aberto; esta é a sessão de demonstração sintética."
                .to_string(),
        ),
        pending: true,
    })
}

#[tauri::command]
pub fn stop_session() -> Result<(), String> {
    Ok(())
}

#[tauri::command]
pub fn detect_chrome(state: State<'_, AppState>) -> ChromeInfo {
    let saved = state.chrome_path.lock().expect("chrome_path lock").clone();
    chrome::detect(saved.as_deref())
}

#[tauri::command]
pub fn set_chrome_path(
    path: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ChromeInfo, String> {
    let resolved = chrome::normalize_binary_path(Path::new(&path))
        .ok_or_else(|| format!("não encontrei o binário do Chrome em {path}"))?;
    if !resolved.is_file() {
        return Err(format!(
            "o caminho escolhido não é um executável: {}",
            resolved.display()
        ));
    }
    prefs::save_chrome_path(&app, &resolved)?;
    *state.chrome_path.lock().expect("chrome_path lock") = Some(resolved.clone());
    Ok(ChromeInfo {
        found: true,
        path: Some(resolved.display().to_string()),
        source: "manual".to_string(),
        candidates: chrome::candidates(),
    })
}

/// Lê uma prévia textual de anexo da sessão (limite rígido, sem sair da pasta).
#[tauri::command]
pub fn read_attachment(session_dir: String, name: String) -> Result<AttachmentPayload, String> {
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err("nome de anexo inválido".to_string());
    }
    let root = PathBuf::from(&session_dir).join("attachments");
    let target = root.join(&name);
    let metadata =
        fs::metadata(&target).map_err(|error| format!("anexo indisponível: {error}"))?;
    if metadata.len() > 1024 * 1024 {
        return Ok(AttachmentPayload {
            kind: "binary".to_string(),
            text: None,
            bytes: metadata.len(),
        });
    }
    let bytes = fs::read(&target).map_err(|error| format!("falha ao ler anexo: {error}"))?;
    match String::from_utf8(bytes) {
        Ok(text) => Ok(AttachmentPayload {
            kind: "text".to_string(),
            text: Some(text),
            bytes: metadata.len(),
        }),
        Err(_) => Ok(AttachmentPayload {
            kind: "binary".to_string(),
            text: None,
            bytes: metadata.len(),
        }),
    }
}

#[tauri::command]
pub fn reveal_path(path: String) -> Result<(), String> {
    let target = PathBuf::from(&path);
    if !target.exists() {
        return Err(format!("caminho não encontrado: {path}"));
    }
    #[cfg(target_os = "macos")]
    {
        let status = if target.is_dir() {
            std::process::Command::new("open").arg(&target).status()
        } else {
            std::process::Command::new("open").arg("-R").arg(&target).status()
        };
        match status {
            Ok(status) if status.success() => Ok(()),
            Ok(status) => Err(format!("open terminou com {status}")),
            Err(error) => Err(format!("não foi possível abrir o Finder: {error}")),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("revelar no Finder é exclusivo do macOS nesta versão".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_session_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "scrapelens-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(dir.join("attachments")).unwrap();
        dir
    }

    const MINIMAL_SESSION: &str = r#"{
      "schemaVersion": 1,
      "session": {
        "id": "test-session",
        "startedAt": "2026-10-26T20:00:00Z",
        "labels": ["synthetic-fixture"],
        "completeness": { "state": "partial", "reasons": ["fixture de teste"] }
      },
      "requests": []
    }"#;

    #[test]
    fn opens_a_v1_session_directory_and_flags_synthetic() {
        let dir = temp_session_dir("ok");
        fs::write(dir.join("session.json"), MINIMAL_SESSION).unwrap();
        let payload = read_session_payload(dir.to_str().unwrap()).unwrap();
        assert!(payload.synthetic);
        assert_eq!(payload.session["schemaVersion"], 1);
        assert_eq!(payload.session.pointer("/session/id").unwrap(), "test-session");
        assert!(payload.session_dir.is_some());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let dir = temp_session_dir("version");
        fs::write(
            dir.join("session.json"),
            MINIMAL_SESSION.replace("\"schemaVersion\": 1", "\"schemaVersion\": 2"),
        )
        .unwrap();
        let error = read_session_payload(dir.to_str().unwrap()).unwrap_err();
        assert!(error.contains("schemaVersion 2"), "{error}");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn rejects_missing_session_file() {
        let error = read_session_payload("/caminho/que/nao/existe/scrapelens").unwrap_err();
        assert!(error.contains("não encontrado"), "{error}");
    }

    #[test]
    fn attachment_preview_is_text_inside_attachments() {
        let dir = temp_session_dir("attachment");
        fs::write(dir.join("attachments/req.bin"), b"hello").unwrap();
        let payload = read_attachment(dir.to_str().unwrap().to_string(), "req.bin".to_string()).unwrap();
        assert_eq!(payload.kind, "text");
        assert_eq!(payload.text.as_deref(), Some("hello"));
        assert!(read_attachment(dir.to_str().unwrap().to_string(), "../escape".to_string()).is_err());
        fs::remove_dir_all(dir).ok();
    }
}
