//! Commands da ponte UI ↔ shell. Contrato v1: docs/03-contratos.md.
//!
//! Nota de integração: `start_session`, `import_har` e `import_netlog` chamam o
//! `scrapelens-core` (dependência crate, sem sidecar) e operam dados reais. A
//! captura abre o Chrome externo em `capture.rs`; o envelope `SessionPayload`
//! permanece estável para a UI.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{json, Value};
use tauri::{AppHandle, Manager, State};

use scrapelens_core::{store, ImportedSession};

use crate::capture::{self, CaptureConfig, CaptureSession, CaptureStatus};
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

fn sessions_root(app: &AppHandle) -> Result<PathBuf, String> {
    let root = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("sem diretório de dados do app: {error}"))?
        .join("sessions");
    store::ensure_private_dir(&root)
        .map_err(|error| format!("não foi possível criar {}: {error}", root.display()))?;
    Ok(root)
}

fn sanitize_dir_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches(['.', '-']).to_string();
    if trimmed.is_empty() {
        "session".to_string()
    } else {
        trimmed.chars().take(96).collect()
    }
}

fn unique_session_dir(root: &Path, base: &str) -> PathBuf {
    let mut candidate = root.join(base);
    let mut index = 2;
    while candidate.exists() {
        candidate = root.join(format!("{base}-{index}"));
        index += 1;
    }
    candidate
}

fn persist_imported(
    app: &AppHandle,
    imported: ImportedSession,
    label: &str,
) -> Result<SessionPayload, String> {
    let session_id = imported.bundle.session.session.id.clone();
    let root = sessions_root(app)?;
    let dir = unique_session_dir(&root, &sanitize_dir_name(&session_id));
    store::write_session_dir(&imported.bundle, &dir)
        .map_err(|error| format!("não foi possível gravar a sessão importada: {error}"))?;
    let value = serde_json::to_value(&imported.bundle.session)
        .map_err(|error| format!("sessão importada inválida: {error}"))?;
    let counts = &imported.bundle.session.session.completeness.counts;
    let warnings = imported.report.warnings.len();
    let completeness = &imported.bundle.session.session.completeness.state;
    Ok(SessionPayload {
        session: value,
        session_dir: Some(dir.display().to_string()),
        synthetic: false,
        notice: Some(format!(
            "{label} importada: {} requisição(ões), {} aviso(s), completude {:?}. Diretório: {}.",
            counts.requests,
            warnings,
            completeness,
            dir.display()
        )),
        pending: false,
    })
}

fn read_import_file(path: &str, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("{label} não encontrado em {path}: {error}"))?;
    if metadata.is_dir() {
        return Err(format!("{label}: {path} é um diretório, selecione um arquivo"));
    }
    if metadata.len() > 256 * 1024 * 1024 {
        return Err(format!(
            "{label} maior que 256 MiB ({} bytes); divida a captura ou use o formato de sessão v1",
            metadata.len()
        ));
    }
    fs::read(path).map_err(|error| format!("não foi possível ler {label} em {path}: {error}"))
}

#[tauri::command]
pub fn import_har(app: AppHandle, path: String) -> Result<SessionPayload, String> {
    let bytes = read_import_file(&path, "HAR")?;
    let imported = scrapelens_core::import_har(&bytes)
        .map_err(|error| format!("HAR inválido: {error}. Use um HAR 1.2 exportado pelo Chrome."))?;
    persist_imported(&app, imported, "HAR")
}

#[tauri::command]
pub fn import_netlog(app: AppHandle, path: String) -> Result<SessionPayload, String> {
    let bytes = read_import_file(&path, "NetLog")?;
    let imported = scrapelens_core::import_netlog(&bytes)
        .map_err(|error| format!("NetLog inválido: {error}. Use o JSON completo do Chrome."))?;
    persist_imported(&app, imported, "NetLog")
}

/// Inicia uma captura real com Chrome externo. O comando volta assim que o
/// CDP está pronto; a sessão v1 final é devolvida por `stop_session`.
#[tauri::command]
pub fn start_session(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<SessionPayload, String> {
    let mut slot = state.capture.lock().map_err(|_| "estado de captura indisponível")?;
    if slot.is_some() {
        return Err("Já existe uma captura em andamento. Clique em Encerrar antes de iniciar outra.".to_string());
    }

    let chrome_path = {
        let saved = state.chrome_path.lock().map_err(|_| "estado do Chrome indisponível")?.clone();
        chrome::detect(saved.as_deref())
            .path
            .map(PathBuf::from)
            .ok_or_else(|| {
                "Chrome não encontrado. Selecione o Google Chrome manualmente no aviso da tela ou no menu Arquivo."
                    .to_string()
            })?
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let session_id = format!("capture-{now}");
    let started_at = iso_now();
    let dir = unique_session_dir(&sessions_root(&app)?, &session_id);
    store::ensure_private_dir(&dir).map_err(|error| format!("diretório da sessão: {error}"))?;

    let config = CaptureConfig {
        chrome: chrome_path.clone(),
        session_dir: dir.clone(),
        start_url: std::env::var("SCRAPELENS_CAPTURE_URL").unwrap_or_else(|_| "about:blank".to_string()),
        headless: std::env::var("SCRAPELENS_CAPTURE_HEADLESS").as_deref() == Ok("1"),
        ignore_cert: std::env::var("SCRAPELENS_CAPTURE_IGNORE_CERT").as_deref() == Ok("1"),
    };

    let status = Arc::new(Mutex::new(CaptureStatus {
        recording: true,
        events: 0,
        chrome_pid: None,
        session_id: session_id.clone(),
        session_dir: dir.display().to_string(),
        started_at: started_at.clone(),
        page_url: config.start_url.clone(),
        last_error: None,
    }));
    let thread_status = status.clone();
    let (stop_tx, stop_rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::channel();
    let join = thread::spawn(move || capture::run(config, thread_status, stop_rx, ready_tx));

    match ready_rx.recv_timeout(Duration::from_secs(35)) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            let _ = join.join();
            let _ = std::fs::remove_dir_all(&dir);
            return Err(error);
        }
        Err(_) => {
            let _ = stop_tx.send(());
            let _ = join.join();
            let _ = std::fs::remove_dir_all(&dir);
            return Err("A captura não ficou pronta em 35 s. Verifique se o Chrome abriu e tente novamente.".to_string());
        }
    }

    *slot = Some(CaptureSession {
        id: session_id.clone(),
        dir: dir.clone(),
        started_at: started_at.clone(),
        stop: stop_tx,
        join,
        status,
    });

    Ok(SessionPayload {
        session: json!({
            "schemaVersion": 1,
            "session": {
                "id": session_id,
                "browser": { "name": "Chrome" },
                "startedAt": started_at,
                "completeness": {
                    "state": "partial",
                    "reasons": ["captura em andamento; a sessão final é gravada em stop_session"]
                },
                "labels": [],
                "notes": ["captura ao vivo em andamento"]
            },
            "requests": []
        }),
        session_dir: Some(dir.display().to_string()),
        synthetic: false,
        notice: Some(format!(
            "Captura iniciada com Chrome externo em {}. Navegue no Chrome e clique em Encerrar para gravar a sessão.",
            chrome_path.display()
        )),
        pending: false,
    })
}

/// Encerra a captura, aguarda o flush do NetLog, importa com o core e grava a
/// sessão v1. Devolve a sessão pronta para a UI.
#[tauri::command]
pub fn stop_session(state: State<'_, AppState>) -> Result<SessionPayload, String> {
    let capture = {
        let mut slot = state.capture.lock().map_err(|_| "estado de captura indisponível")?;
        slot.take()
    };
    let Some(capture) = capture else {
        return Err("Nenhuma captura em andamento para encerrar.".to_string());
    };
    let _ = capture.stop.send(());
    let payload = capture
        .join
        .join()
        .map_err(|_| "a thread de captura terminou inesperadamente".to_string())??;
    if let Ok(mut last) = state.last_session_dir.lock() {
        *last = Some(capture.dir.clone());
    }
    Ok(payload)
}

#[tauri::command]
pub fn capture_status(state: State<'_, AppState>) -> Option<CaptureStatus> {
    state
        .capture
        .lock()
        .ok()
        .and_then(|slot| slot.as_ref().map(|capture| capture.status.lock().map(|status| status.clone()).unwrap_or_default()))
}

fn iso_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let seconds = now.as_secs();
    let millis = now.subsec_millis();
    let days = (seconds / 86_400) as i64;
    let (year, month, day) = civil_from_days(days);
    let day_seconds = seconds % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        day_seconds / 3600,
        (day_seconds % 3600) / 60,
        day_seconds % 60
    )
}

/// Algoritmo civil_from_days (Howard Hinnant), sem dependência de chrono.
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };
    (year, month as u32, day as u32)
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

/// Gera a exportação cURL/Python de uma requisição da sessão persistida.
///
/// Roda fora da thread da UI: ler anexos e gerar texto pode ser pesado em
/// sessões grandes. O texto devolvido é a fonte da prévia, da cópia e do
/// arquivo salvo.
#[tauri::command]
pub async fn export_request(
    session_dir: String,
    request_id: String,
    format: String,
) -> Result<crate::export::ExportPreview, String> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::export::preview(Path::new(&session_dir), &request_id, &format)
    })
    .await
    .map_err(|error| format!("a geração da exportação falhou: {error}"))?
}

/// Grava o texto exportado em um arquivo novo (0600), recusando sobrescrita e
/// links simbólicos. O caminho vem do diálogo nativo de salvamento.
#[tauri::command]
pub async fn save_export_file(path: String, text: String) -> Result<crate::export::SavedFile, String> {
    tauri::async_runtime::spawn_blocking(move || crate::export::write_text_file(Path::new(&path), &text))
        .await
        .map_err(|error| format!("o salvamento falhou: {error}"))?
}

/// Contagens e avisos da sanitização, sem gravar nada.
#[tauri::command]
pub async fn preview_sanitized(session_dir: String) -> Result<crate::export::SanitizePreview, String> {
    tauri::async_runtime::spawn_blocking(move || crate::export::sanitize_preview(Path::new(&session_dir)))
        .await
        .map_err(|error| format!("a prévia da sanitização falhou: {error}"))?
}

/// Grava a sessão sanitizada em uma pasta nova escolhida pelo usuário.
#[tauri::command]
pub async fn save_sanitized(
    session_dir: String,
    destination: String,
) -> Result<crate::export::SanitizeSaved, String> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::export::sanitize_to(Path::new(&session_dir), Path::new(&destination))
    })
    .await
    .map_err(|error| format!("a sanitização falhou: {error}"))?
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
