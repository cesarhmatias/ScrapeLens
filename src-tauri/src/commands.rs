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
    use std::io::Read;
    let (file, total) = open_attachment(&session_dir, &name)?;
    if total > 1024 * 1024 {
        return Ok(AttachmentPayload {
            kind: "binary".to_string(),
            text: None,
            bytes: total,
        });
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("falha ao ler anexo: {error}"))?;
    match String::from_utf8(bytes) {
        Ok(text) => Ok(AttachmentPayload {
            kind: "text".to_string(),
            text: Some(text),
            bytes: total,
        }),
        Err(_) => Ok(AttachmentPayload {
            kind: "binary".to_string(),
            text: None,
            bytes: total,
        }),
    }
}

/// Abre um anexo só se for arquivo regular dentro de `attachments/`: recusa
/// link simbólico (no anexo ou na pasta) e confere, depois de aberto, que o
/// arquivo é o mesmo inode inspecionado e regular. O tamanho vem do arquivo aberto.
fn open_attachment(session_dir: &str, name: &str) -> Result<(fs::File, u64), String> {
    if name.is_empty() || name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err("nome de anexo inválido".to_string());
    }
    let root = PathBuf::from(session_dir).join("attachments");
    let root_meta =
        fs::symlink_metadata(&root).map_err(|error| format!("anexo indisponível: {error}"))?;
    if root_meta.file_type().is_symlink() {
        return Err("a pasta de anexos é um link simbólico; recusado".to_string());
    }
    let target = root.join(name);
    let before =
        fs::symlink_metadata(&target).map_err(|error| format!("anexo indisponível: {error}"))?;
    if before.file_type().is_symlink() {
        return Err(format!("o anexo {name} é um link simbólico; recusado"));
    }
    let file = fs::File::open(&target).map_err(|error| format!("falha ao abrir anexo: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("falha ao ler anexo: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.ino() != before.ino() || opened.dev() != before.dev() {
            return Err(format!("o anexo {name} mudou durante a abertura; recusado"));
        }
    }
    if !opened.is_file() {
        return Err(format!("o anexo {name} não é um arquivo regular"));
    }
    Ok((file, opened.len()))
}

/// Busca no payload via `scrapelens_core::search`, fora da thread da UI.
/// `max_matches` limita o resultado; o frontend não reimplementa a busca.
#[tauri::command]
pub async fn search_session(
    session_dir: String,
    text: String,
    scopes: Vec<String>,
    case_sensitive: bool,
    max_matches: Option<usize>,
) -> Result<scrapelens_core::search::SearchResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        run_search(&session_dir, &text, &scopes, case_sensitive, max_matches)
    })
    .await
    .map_err(|error| format!("a busca foi interrompida: {error}"))?
}

/// Bundle da última sessão pesquisada. Chave: pasta + (tamanho, mtime) de
/// `session.json` + mtime de `attachments/`; mudou, recarrega. Guarda uma só
/// sessão (abrir outra substitui) e descarta os brutos CDP/NetLog, que a busca
/// não usa.
struct CachedBundle {
    dir: PathBuf,
    fingerprint: Vec<Option<(u64, SystemTime)>>,
    bundle: Arc<scrapelens_core::SessionBundle>,
}

static BUNDLE_CACHE: Mutex<Option<CachedBundle>> = Mutex::new(None);
static BUNDLE_LOADS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn session_fingerprint(dir: &Path) -> Vec<Option<(u64, SystemTime)>> {
    ["session.json", "attachments"]
        .iter()
        .map(|name| {
            fs::metadata(dir.join(name))
                .ok()
                .and_then(|meta| Some((meta.len(), meta.modified().ok()?)))
        })
        .collect()
}

fn cached_bundle(dir: &Path) -> Result<Arc<scrapelens_core::SessionBundle>, String> {
    let mut guard = BUNDLE_CACHE.lock().map_err(|_| "cache de busca corrompido".to_string())?;
    let fingerprint = session_fingerprint(dir);
    if let Some(cached) = guard.as_ref() {
        if cached.dir == dir && cached.fingerprint == fingerprint {
            return Ok(cached.bundle.clone());
        }
    }
    *guard = None; // libera a sessão anterior antes de carregar a nova
    BUNDLE_LOADS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut bundle = scrapelens_core::import_session_dir(dir)
        .map_err(|error| format!("não foi possível ler a sessão: {error}"))?
        .bundle;
    bundle.cdp_events_jsonl = None;
    bundle.netlog_json = None;
    let bundle = Arc::new(bundle);
    *guard = Some(CachedBundle { dir: dir.to_path_buf(), fingerprint, bundle: bundle.clone() });
    Ok(bundle)
}

fn run_search(
    session_dir: &str,
    text: &str,
    scopes: &[String],
    case_sensitive: bool,
    max_matches: Option<usize>,
) -> Result<scrapelens_core::search::SearchResult, String> {
    use scrapelens_core::search::{search, Scope, SearchQuery};
    if text.is_empty() {
        return Err("digite um texto para buscar".to_string());
    }
    let mut parsed = Vec::new();
    for scope in scopes {
        parsed.push(Scope::parse(scope).ok_or_else(|| format!("escopo desconhecido: {scope}"))?);
    }
    let bundle = cached_bundle(Path::new(session_dir))?;
    let mut query = SearchQuery::new(text);
    query.scopes = parsed;
    query.case_sensitive = case_sensitive;
    query.max_matches = max_matches.unwrap_or(2000).clamp(1, 20_000);
    Ok(search(&bundle, &query))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BodyPayload {
    /// `text` (UTF-8 válido), `binary` (nunca renderizado; só prévia hex).
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Primeiros bytes em hexadecimal (limitado), só para `binary`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
    pub bytes: u64,
    /// Bytes efetivamente devolvidos em `text`; menor que `bytes` se cortado.
    pub shown_bytes: u64,
    pub cut: bool,
}

const HEX_PREVIEW_BYTES: usize = 256;

/// Lê um corpo anexado até `limit` bytes. Texto vira `String` (o frontend o
/// exibe em `<pre>`); o resto vira só tamanho e prévia hexadecimal.
#[tauri::command]
pub async fn read_body(session_dir: String, name: String, limit: Option<u64>) -> Result<BodyPayload, String> {
    tauri::async_runtime::spawn_blocking(move || read_body_blocking(&session_dir, &name, limit.unwrap_or(262_144)))
        .await
        .map_err(|error| format!("a leitura foi interrompida: {error}"))?
}

fn read_body_blocking(session_dir: &str, name: &str, limit: u64) -> Result<BodyPayload, String> {
    use std::io::Read;
    let (file, total) = open_attachment(session_dir, name)?;
    let mut buf = Vec::new();
    file.take(limit.min(16 * 1024 * 1024))
        .read_to_end(&mut buf)
        .map_err(|error| format!("falha ao ler anexo: {error}"))?;
    let cut = (buf.len() as u64) < total;
    // Corte no limite pode partir um caractere: aceita prefixo UTF-8 válido.
    let text = match std::str::from_utf8(&buf) {
        Ok(text) => Some(text.to_string()),
        Err(error) if cut && error.error_len().is_none() => {
            Some(String::from_utf8_lossy(&buf[..error.valid_up_to()]).into_owned())
        }
        Err(_) => None,
    };
    Ok(match text {
        Some(text) => BodyPayload {
            kind: "text".into(),
            shown_bytes: text.len() as u64,
            text: Some(text),
            hex: None,
            bytes: total,
            cut,
        },
        None => BodyPayload {
            kind: "binary".into(),
            text: None,
            hex: Some(
                buf.iter()
                    .take(HEX_PREVIEW_BYTES)
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
            bytes: total,
            shown_bytes: buf.len().min(HEX_PREVIEW_BYTES) as u64,
            cut: total > HEX_PREVIEW_BYTES as u64,
        },
    })
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

    static CACHE_TEST_LOCK: Mutex<()> = Mutex::new(());

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

    fn detran_session(name: &str) -> PathBuf {
        use scrapelens_core::correlate::CorrelationOptions;
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/detran-pb");
        let read = |file: &str| fs::read(fixtures.join(file)).unwrap();
        let imported = scrapelens_core::parse::import_capture_with_bodies(
            &read("detran-pb.cdp.jsonl"),
            &read("detran-pb.netlog.json"),
            Some(&read("detran-pb.cdp-bodies.jsonl")),
            CorrelationOptions::default(),
        )
        .unwrap();
        let dir = temp_session_dir(name);
        fs::remove_dir_all(&dir).ok();
        store::write_session_dir(&imported.bundle, &dir).unwrap();
        dir
    }

    #[test]
    fn search_session_finds_body_only_and_reports_partial() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = detran_session("search");
        let found = run_search(dir.to_str().unwrap(), "cmd_consultar_placa", &[], false, None).unwrap();
        assert_eq!(found.matches.len(), 2);
        assert!(found.matches.iter().all(|m| m.decoded && m.scope == scrapelens_core::search::Scope::RequestBody));
        assert!(found.partial && !found.partial_attempts.is_empty());
        let url_only = run_search(dir.to_str().unwrap(), "cmd_consultar_placa", &["url".into()], false, None).unwrap();
        assert!(url_only.matches.is_empty());
        let capped = run_search(dir.to_str().unwrap(), "cmd_consultar_placa", &[], false, Some(1)).unwrap();
        assert_eq!(capped.matches.len(), 1);
        assert!(capped.limit_reached);
        assert!(run_search(dir.to_str().unwrap(), "x", &["nope".into()], false, None).is_err());
        assert!(run_search(dir.to_str().unwrap(), "", &[], false, None).is_err());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn read_body_text_binary_and_cut() {
        let dir = temp_session_dir("body");
        let att = dir.join("attachments");
        fs::write(att.join("t.bin"), "áéíóú".repeat(100)).unwrap();
        fs::write(att.join("b.bin"), [0u8, 159, 146, 150, 255]).unwrap();
        let d = dir.to_str().unwrap();
        let text = read_body_blocking(d, "t.bin", 1000).unwrap();
        assert_eq!(text.kind, "text");
        assert!(!text.cut);
        let cut = read_body_blocking(d, "t.bin", 101).unwrap();
        assert!(cut.cut && cut.kind == "text" && cut.shown_bytes < 101);
        let bin = read_body_blocking(d, "b.bin", 1000).unwrap();
        assert_eq!(bin.kind, "binary");
        assert_eq!(bin.hex.as_deref(), Some("00 9f 92 96 ff"));
        assert!(bin.text.is_none());
        assert!(read_body_blocking(d, "../x", 10).is_err());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn bundle_cache_reuses_and_invalidates() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = detran_session("cache");
        let first = cached_bundle(&dir).unwrap();
        let second = cached_bundle(&dir).unwrap();
        assert!(Arc::ptr_eq(&first, &second), "segunda busca deve reutilizar o bundle");
        assert!(first.cdp_events_jsonl.is_none() && first.netlog_json.is_none());
        // arquivo mudou (tamanho/mtime) → recarrega
        let session_file = dir.join("session.json");
        let mut text = fs::read_to_string(&session_file).unwrap();
        text.push('\n');
        fs::write(&session_file, text).unwrap();
        let third = cached_bundle(&dir).unwrap();
        assert!(!Arc::ptr_eq(&first, &third));
        // outra sessão substitui a anterior
        let other = detran_session("cache-other");
        let fourth = cached_bundle(&other).unwrap();
        assert!(!Arc::ptr_eq(&third, &fourth));
        fs::remove_dir_all(dir).ok();
        fs::remove_dir_all(other).ok();
    }

    #[cfg(unix)]
    #[test]
    fn attachments_refuse_symlinks() {
        let dir = temp_session_dir("symlink");
        let outside = temp_session_dir("symlink-outside");
        fs::write(outside.join("secret.txt"), "segredo").unwrap();
        let att = dir.join("attachments");
        std::os::unix::fs::symlink(outside.join("secret.txt"), att.join("link.bin")).unwrap();
        fs::write(att.join("ok.bin"), "ok").unwrap();
        let d = dir.to_str().unwrap();
        assert!(read_body_blocking(d, "link.bin", 100).unwrap_err().contains("link simbólico"));
        assert!(read_attachment(d.to_string(), "link.bin".to_string()).unwrap_err().contains("link simbólico"));
        assert_eq!(read_body_blocking(d, "ok.bin", 100).unwrap().kind, "text");
        // pasta attachments/ como link
        let dir2 = temp_session_dir("symlink2");
        fs::remove_dir_all(dir2.join("attachments")).unwrap();
        std::os::unix::fs::symlink(&att, dir2.join("attachments")).unwrap();
        assert!(read_body_blocking(dir2.to_str().unwrap(), "ok.bin", 100).unwrap_err().contains("link simbólico"));
        // diretório no lugar de arquivo
        fs::create_dir(att.join("sub")).unwrap();
        assert!(read_body_blocking(d, "sub", 100).is_err());
        for d in [dir, dir2, outside] {
            fs::remove_dir_all(d).ok();
        }
    }

    /// Medição manual: `SL_LARGE_DIR=<sessão> cargo test --release -- --ignored large_search --nocapture`.
    #[test]
    #[ignore]
    fn large_search_timing() {
        let dir = std::env::var("SL_LARGE_DIR").expect("defina SL_LARGE_DIR");
        for round in 1..=3 {
            let start = std::time::Instant::now();
            let found = run_search(&dir, "zzzz", &[], false, None).unwrap();
            eprintln!("busca {round}: {:?}, {} achados, loads={}, rss_atual={}", start.elapsed(), found.matches.len(), BUNDLE_LOADS.load(std::sync::atomic::Ordering::SeqCst), String::from_utf8_lossy(&std::process::Command::new("ps").args(["-o", "rss=", "-p", &std::process::id().to_string()]).output().unwrap().stdout).trim());
        }
    }
}
