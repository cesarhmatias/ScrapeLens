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
use crate::cli::{self, CliAction};
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
pub async fn open_session(app: AppHandle, path: String) -> Result<SessionPayload, String> {
    run_loading(app, move |app| {
        let payload = read_session_payload(&path)?;
        let state = app.state::<AppState>();
        *state.last_session_dir.lock().expect("session_dir lock") =
            payload.session_dir.as_ref().map(PathBuf::from);
        Ok(payload)
    })
    .await
}

/// Liga um `AtomicBool` e o desliga ao sair (inclusive em erro ou pânico).
pub(crate) struct FlagGuard<'a>(&'a std::sync::atomic::AtomicBool);

impl<'a> FlagGuard<'a> {
    /// `None` se o sinal já estava ligado (outra operação em andamento).
    pub(crate) fn acquire(flag: &'a std::sync::atomic::AtomicBool) -> Option<Self> {
        use std::sync::atomic::Ordering;
        flag.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).ok().map(|_| Self(flag))
    }
}

impl Drop for FlagGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Abre/importa/encerra fora da thread principal (a leitura de 20 mil
/// requisições leva ~10 s) e recusa uma segunda operação em paralelo.
async fn run_loading<F>(app: AppHandle, work: F) -> Result<SessionPayload, String>
where
    F: FnOnce(&AppHandle) -> Result<SessionPayload, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let _guard = FlagGuard::acquire(&state.loading)
            .ok_or_else(|| "Já há uma sessão sendo aberta ou importada. Aguarde terminar.".to_string())?;
        work(&app)
    })
    .await
    .map_err(|error| format!("a operação foi interrompida: {error}"))?
}

fn read_session_payload(path: &str) -> Result<SessionPayload, String> {
    let chosen = PathBuf::from(path);
    if !chosen.exists() {
        return Err(format!("caminho não encontrado: {path}"));
    }
    // Pasta com session.json, ou um arquivo de sessão com qualquer nome
    // (absoluto, regular, sem symlink em nenhum componente).
    let session_dir = if chosen.is_dir() {
        if !chosen.join("session.json").is_file() {
            return Err(format!("session.json não encontrado em {}", chosen.display()));
        }
        chosen
    } else {
        cli::validate_absolute_regular_file(&chosen)?
    };
    header_payload(&session_dir, |requests, partial| {
        format!(
            "Sessão aberta: {requests} requisição(ões){}.",
            if partial { " · sessão parcial, como declarada pela fonte" } else { "" }
        )
    })
}

/// P5: lê a sessão tipada (cache `LazySession`, sem `Value`) e devolve só o
/// cabeçalho + contagem. As requisições vêm de `list_requests`/`get_request`.
pub(crate) fn header_payload(
    session_dir: &Path,
    notice: impl FnOnce(usize, bool) -> String,
) -> Result<SessionPayload, String> {
    let lazy = cached_session(session_dir)?;
    let session = &lazy.session;
    if session.schema_version != 1 {
        return Err(format!(
            "schemaVersion {} não é suportado por este app (esperado: 1)",
            session.schema_version
        ));
    }
    let header = crate::listing::header_of(session)?;
    let synthetic = session.session.labels.iter().any(|label| label == "synthetic-fixture");
    let partial = serde_json::to_value(session.session.completeness.state)
        .ok()
        .and_then(|v| v.as_str().map(|s| s != "complete"))
        .unwrap_or(true);
    let requests = header.request_count;
    Ok(SessionPayload {
        session: serde_json::to_value(&header).map_err(|error| format!("cabeçalho inválido: {error}"))?,
        session_dir: Some(session_dir.display().to_string()),
        synthetic,
        notice: Some(notice(requests, partial)),
        pending: false,
    })
}

/// Página de resumos (P5). `limit` até 2000; filtros rodam aqui, não no front.
#[tauri::command]
pub async fn list_requests(
    session_dir: String,
    offset: usize,
    limit: usize,
    filter: Option<crate::listing::ListFilter>,
) -> Result<crate::listing::RequestPage, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let lazy = cached_session(Path::new(&session_dir))?;
        let page = crate::listing::list_page(&lazy.session, offset, limit, &filter.unwrap_or_default());
        // Só no modo de teste: prova, sem ler a tela, que a lista veio pelo contrato paginado.
        if std::env::var("SCRAPELENS_TEST_MODE").as_deref() == Ok("1") {
            eprintln!(
                "scrapelens: list_requests offset={offset} items={} matched={} total={}",
                page.items.len(),
                page.matched,
                page.total
            );
        }
        Ok(page)
    })
    .await
    .map_err(|error| format!("a listagem foi interrompida: {error}"))?
}

/// Detalhe de uma requisição sob demanda (P5).
#[tauri::command]
pub async fn get_request(session_dir: String, id: String) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let lazy = cached_session(Path::new(&session_dir))?;
        let detail = crate::listing::detail(&lazy.session, &id)
            .ok_or_else(|| format!("requisição {id} não encontrada na sessão"))?;
        serde_json::to_value(&detail).map_err(|error| format!("detalhe inválido: {error}"))
    })
    .await
    .map_err(|error| format!("a leitura do detalhe foi interrompida: {error}"))?
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
    let counts = imported.bundle.session.session.completeness.counts.requests;
    let warnings = imported.report.warnings.len();
    let completeness = format!("{:?}", imported.bundle.session.session.completeness.state);
    drop(imported);
    let shown = dir.display().to_string();
    header_payload(&dir, move |_, _| {
        format!("{label} importada: {counts} requisição(ões), {warnings} aviso(s), completude {completeness}. Diretório: {shown}.")
    })
}

fn read_import_file(path: &str, label: &str) -> Result<Vec<u8>, String> {
    read_import_file_max(path, label, 256 * 1024 * 1024)
}

fn read_import_file_max(path: &str, label: &str, max: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    // O_NOFOLLOW + O_NONBLOCK (FIFO não trava); tipo e tamanho conferidos por fstat
    // no próprio descritor, e a leitura usa o mesmo descritor (sem TOCTOU).
    let handle = open_beneath_parent(Path::new(path))
        .map_err(|error| format!("{label} não pôde ser aberto em {path} (symlink é recusado): {error}"))?;
    let metadata = handle
        .metadata()
        .map_err(|error| format!("{label}: falha ao inspecionar {path}: {error}"))?;
    if metadata.is_dir() {
        return Err(format!("{label}: {path} é um diretório, selecione um arquivo"));
    }
    if !metadata.is_file() {
        return Err(format!("{label}: {path} não é um arquivo regular"));
    }
    if metadata.len() > max {
        return Err(format!(
            "{label} maior que {} MiB ({} bytes); divida a captura ou use o formato de sessão v1",
            max / (1024 * 1024),
            metadata.len()
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    handle
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("não foi possível ler {label} em {path}: {error}"))?;
    if bytes.len() as u64 > max {
        return Err(format!("{label} cresceu além de {} MiB durante a leitura", max / (1024 * 1024)));
    }
    Ok(bytes)
}

/// A9-B5: abre o diretório pai por descritor (O_DIRECTORY|O_NOFOLLOW) e o
/// arquivo com `openat` relativo a ele (O_NOFOLLOW|O_NONBLOCK). Trocar o pai por
/// symlink depois da validação faz a abertura falhar em vez de ler outro arquivo.
pub(crate) fn open_beneath_parent(path: &Path) -> std::io::Result<fs::File> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    let invalid = |msg: &str| std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.to_string());
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).ok_or_else(|| invalid("sem pasta pai"))?;
    let name = path.file_name().ok_or_else(|| invalid("sem nome de arquivo"))?;
    let parent_c = CString::new(parent.as_os_str().as_bytes()).map_err(|_| invalid("NUL no caminho"))?;
    let name_c = CString::new(name.as_bytes()).map_err(|_| invalid("NUL no nome"))?;
    let dir_fd = unsafe {
        libc::open(parent_c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
    };
    if dir_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let dir = unsafe { fs::File::from_raw_fd(dir_fd) };
    let fd = unsafe {
        use std::os::fd::AsRawFd;
        libc::openat(
            dir.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

/// Estado "starting": liga `recording` e avisa o menu; se o start não chegar a
/// `commit()`, desliga e reabilita o menu ao sair (erro, `?` ou pânico).
pub(crate) struct StartingGuard<'a, F: FnMut(bool)> {
    flag: &'a std::sync::atomic::AtomicBool,
    notify: F,
    committed: bool,
}

impl<'a, F: FnMut(bool)> StartingGuard<'a, F> {
    pub(crate) fn begin(flag: &'a std::sync::atomic::AtomicBool, mut notify: F) -> Self {
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        notify(true);
        Self { flag, notify, committed: false }
    }

    pub(crate) fn commit(&mut self) {
        self.committed = true;
    }
}

impl<F: FnMut(bool)> Drop for StartingGuard<'_, F> {
    fn drop(&mut self) {
        if !self.committed {
            self.flag.store(false, std::sync::atomic::Ordering::SeqCst);
            (self.notify)(false);
        }
    }
}

/// Importações ficam bloqueadas durante uma gravação (A8-B7).
pub(crate) fn ensure_not_recording(recording: bool) -> Result<(), String> {
    if recording {
        Err("Há uma captura em andamento. Encerre a gravação antes de importar.".to_string())
    } else {
        Ok(())
    }
}


#[tauri::command]
pub async fn import_har(app: AppHandle, path: String) -> Result<SessionPayload, String> {
    run_loading(app, move |app| {
        ensure_not_recording(app.state::<AppState>().recording.load(std::sync::atomic::Ordering::SeqCst))?;
        let bytes = read_import_file(&path, "HAR")?;
        let imported = scrapelens_core::import_har(&bytes)
            .map_err(|error| format!("HAR inválido: {error}. Use um HAR 1.2 exportado pelo Chrome."))?;
        persist_imported(app, imported, "HAR")
    })
    .await
}

#[tauri::command]
pub async fn import_netlog(app: AppHandle, path: String) -> Result<SessionPayload, String> {
    run_loading(app, move |app| {
        ensure_not_recording(app.state::<AppState>().recording.load(std::sync::atomic::Ordering::SeqCst))?;
        let bytes = read_import_file(&path, "NetLog")?;
        let imported = scrapelens_core::import_netlog(&bytes)
            .map_err(|error| format!("NetLog inválido: {error}. Use o JSON completo do Chrome."))?;
        persist_imported(app, imported, "NetLog")
    })
    .await
}

/// URL inicial sugerida na UI: preferência gravada, senão `SCRAPELENS_CAPTURE_URL`.
#[tauri::command]
pub fn capture_start_url(app: AppHandle) -> String {
    prefs::load_capture_start_url(&app).unwrap_or_else(|| {
        std::env::var("SCRAPELENS_CAPTURE_URL").unwrap_or_default()
    })
}

/// Persiste a URL inicial (vazia limpa a preferência). Só `http`/`https` quando não vazia.
#[tauri::command]
pub fn set_capture_start_url(app: AppHandle, url: String) -> Result<String, String> {
    let trimmed = url.trim().to_string();
    if !trimmed.is_empty() {
        cli::validate_http_url(&trimmed)?;
    }
    prefs::save_capture_start_url(&app, if trimmed.is_empty() { None } else { Some(trimmed.as_str()) })?;
    Ok(trimmed)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CliActionPayload {
    /// `import-har` | `import-netlog` | `open-capture` | `error` | `warning`.
    pub kind: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Consome a ação CLI de teste, ou o erro/aviso da CLI (no máximo uma vez por processo).
/// Só existe ação com `SCRAPELENS_TEST_MODE=1`.
#[tauri::command]
pub fn take_cli_action(state: State<'_, AppState>) -> Option<CliActionPayload> {
    if let Some((kind, message)) = state.cli_message.lock().ok()?.take() {
        return Some(CliActionPayload { kind, path: String::new(), message: Some(message) });
    }
    let action = state.pending_cli.lock().ok()?.take()?;
    let (kind, path) = match action {
        CliAction::ImportHar(path) => ("import-har", path),
        CliAction::ImportNetlog(path) => ("import-netlog", path),
        CliAction::OpenCapture(path) => ("open-capture", path),
    };
    Some(CliActionPayload { kind: kind.to_string(), path: path.display().to_string(), message: None })
}

/// Inicia uma captura real com Chrome externo. O comando volta assim que o
/// CDP está pronto; a sessão v1 final é devolvida por `stop_session`.
/// `start_url` (opcional): campo da UI; vazio → `about:blank`; só http/https.
#[tauri::command]
pub fn start_session(
    app: AppHandle,
    state: State<'_, AppState>,
    start_url: Option<String>,
) -> Result<SessionPayload, String> {
    // "starting" (A9-B8/A8-B7): menu desabilita ⌘⇧R e importações desde já;
    // se o start falhar, `StartingGuard` religa.
    if state.recording.load(std::sync::atomic::Ordering::SeqCst) {
        return Err("Já existe uma captura em andamento ou iniciando. Clique em Encerrar antes de iniciar outra.".to_string());
    }
    let menu_app = app.clone();
    let mut starting = StartingGuard::begin(&state.recording, move |recording| {
        crate::menu::set_recording_menu(&menu_app, recording)
    });
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

    let resolved_url = cli::resolve_capture_start_url(start_url.as_deref())?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let session_id = format!("capture-{now}");
    let started_at = iso_now();
    let dir = unique_session_dir(&sessions_root(&app)?, &session_id);
    store::ensure_private_dir(&dir).map_err(|error| format!("diretório da sessão: {error}"))?;

    let start_url_for_notice = resolved_url.clone();
    let config = CaptureConfig {
        chrome: chrome_path.clone(),
        session_dir: dir.clone(),
        start_url: resolved_url,
        headless: std::env::var("SCRAPELENS_CAPTURE_HEADLESS").as_deref() == Ok("1"),
        ignore_cert: std::env::var("SCRAPELENS_CAPTURE_IGNORE_CERT").as_deref() == Ok("1"),
        // Rede normal por padrão; as suítes de teste ligam só-loopback com
        // `SCRAPELENS_CAPTURE_NETWORK=loopback`.
        network: scrapelens_capture::NetworkMode::from_env(),
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
    drop(slot);
    starting.commit();

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
        notice: Some(if start_url_for_notice == "about:blank" {
            format!(
                "Captura iniciada com Chrome externo em {}. A captura começou em branco; navegue no Chrome ou informe a URL.",
                chrome_path.display()
            )
        } else {
            format!(
                "Captura iniciada com Chrome externo em {} · {}. Clique em Encerrar para gravar a sessão.",
                chrome_path.display(),
                start_url_for_notice
            )
        }),
        pending: false,
    })
}

/// Encerra a captura, aguarda o flush do NetLog, importa com o core e grava a
/// sessão v1. Devolve a sessão pronta para a UI.
#[tauri::command]
pub async fn stop_session(app: AppHandle) -> Result<SessionPayload, String> {
    // Fora da thread principal; não usa o sinal `loading` (encerrar nunca
    // espera uma abertura em andamento).
    tauri::async_runtime::spawn_blocking(move || stop_blocking(&app))
        .await
        .map_err(|error| format!("o encerramento foi interrompido: {error}"))?
}

fn stop_blocking(app: &AppHandle) -> Result<SessionPayload, String> {
    let state = app.state::<AppState>();
    let capture = {
        let mut slot = state.capture.lock().map_err(|_| "estado de captura indisponível")?;
        slot.take()
    };
    state.recording.store(false, std::sync::atomic::Ordering::SeqCst);
    crate::menu::set_recording_menu(app, false);
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

/// Abre um anexo regular de `attachments/` (recusa symlink e confere o inode
/// após abrir); a verificação vive em `store::open_regular_attachment`.
fn open_attachment(session_dir: &str, name: &str) -> Result<(fs::File, u64), String> {
    store::open_regular_attachment(Path::new(session_dir), name).map_err(|error| error.to_string())
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

/// Sessões preguiçosas (até duas) usadas por busca, origens, cadeia e comparação (anexos lidos um a um). Chave: pasta + (tamanho, mtime) de
/// `session.json` + mtime de `attachments/`; mudou, recarrega. Guarda uma só
/// sessão (abrir outra substitui) e não retém corpos nem os brutos CDP/NetLog.
struct CachedSession {
    dir: PathBuf,
    fingerprint: Vec<Option<(u64, SystemTime)>>,
    lazy: Arc<scrapelens_core::lazy::LazySession>,
}

/// Duas sessões em cache (a aberta e a comparada); a mais antiga sai primeiro.
static SESSION_CACHE: Mutex<Vec<CachedSession>> = Mutex::new(Vec::new());
static SESSION_LOADS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn session_fingerprint(path: &Path) -> Vec<Option<(u64, SystemTime)>> {
    let stat = |p: PathBuf| fs::metadata(p).ok().and_then(|meta| Some((meta.len(), meta.modified().ok()?)));
    if path.is_file() {
        let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
        return vec![stat(path.to_path_buf()), stat(parent.join("attachments"))];
    }
    ["session.json", "attachments"].iter().map(|name| stat(path.join(name))).collect()
}

/// Arquivo de sessão com qualquer nome: lido tipado em fluxo (sem `Value`),
/// aberto pelo pai sem seguir symlink; anexos relativos à pasta do arquivo.
fn open_session_file_lazy(file: &Path) -> Result<scrapelens_core::lazy::LazySession, String> {
    let handle = open_beneath_parent(file)
        .map_err(|error| format!("não foi possível abrir {} (symlink é recusado): {error}", file.display()))?;
    let meta = handle.metadata().map_err(|error| format!("falha ao inspecionar {}: {error}", file.display()))?;
    if !meta.is_file() {
        return Err(format!("{} não é um arquivo regular", file.display()));
    }
    let session: scrapelens_core::model::SessionV1 =
        serde_json::from_reader(std::io::BufReader::with_capacity(1 << 20, handle))
            .map_err(|error| format!("arquivo de sessão inválido: {error}"))?;
    let parent = file.parent().map(Path::to_path_buf).ok_or("o arquivo não tem pasta pai")?;
    Ok(scrapelens_core::lazy::LazySession::new(session, parent))
}

pub(crate) fn cached_session(dir: &Path) -> Result<Arc<scrapelens_core::lazy::LazySession>, String> {
    // Chave canônica: `./s`, `s` e symlinks para a mesma pasta compartilham a entrada.
    let canonical = fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let dir = canonical.as_path();
    let mut guard = SESSION_CACHE.lock().map_err(|_| "cache de busca corrompido".to_string())?;
    let fingerprint = session_fingerprint(dir);
    if let Some(index) = guard.iter().position(|cached| cached.dir == dir) {
        if guard[index].fingerprint == fingerprint {
            let hit = guard.remove(index);
            let lazy = hit.lazy.clone();
            guard.push(hit); // mais recente por último
            return Ok(lazy);
        }
        guard.remove(index); // arquivo mudou: recarrega
    }
    while guard.len() >= 2 {
        guard.remove(0); // libera a mais antiga antes de carregar outra
    }
    SESSION_LOADS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let lazy = if dir.is_file() {
        open_session_file_lazy(dir)?
    } else {
        scrapelens_core::open_session_dir_lazy(dir)
            .map_err(|error| format!("não foi possível ler a sessão: {error}"))?
            .0
    };
    let lazy = Arc::new(lazy);
    guard.push(CachedSession { dir: dir.to_path_buf(), fingerprint, lazy: lazy.clone() });
    Ok(lazy)
}

fn run_search(
    session_dir: &str,
    text: &str,
    scopes: &[String],
    case_sensitive: bool,
    max_matches: Option<usize>,
) -> Result<scrapelens_core::search::SearchResult, String> {
    use scrapelens_core::search::{Scope, SearchQuery};
    if text.is_empty() {
        return Err("digite um texto para buscar".to_string());
    }
    let mut parsed = Vec::new();
    for scope in scopes {
        parsed.push(Scope::parse(scope).ok_or_else(|| format!("escopo desconhecido: {scope}"))?);
    }
    let lazy = cached_session(Path::new(session_dir))?;
    let mut query = SearchQuery::new(text);
    query.scopes = parsed;
    query.case_sensitive = case_sensitive;
    query.max_matches = max_matches.unwrap_or(2000).clamp(1, 20_000);
    Ok(scrapelens_core::search::search_lazy(&lazy, &query))
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

/// Origem dos valores de uma requisição (`flow::value_origins`), fora da thread da UI.
#[tauri::command]
pub async fn request_origins(
    session_dir: String,
    request_id: String,
) -> Result<scrapelens_core::flow::ValueOrigins, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let lazy = cached_session(Path::new(&session_dir))?;
        scrapelens_core::flow::value_origins(
            &lazy.session,
            &scrapelens_core::search::LazyBodies(&lazy),
            &request_id,
            &crate::adapters::flow_options(),
        )
        .map_err(|error| format!("não foi possível calcular as origens: {error}"))
    })
    .await
    .map_err(|error| format!("o cálculo foi interrompido: {error}"))?
}

/// Cadeia de priming de uma requisição (`flow::priming_chain`).
#[tauri::command]
pub async fn request_chain(
    session_dir: String,
    request_id: String,
) -> Result<scrapelens_core::flow::PrimingChain, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let lazy = cached_session(Path::new(&session_dir))?;
        scrapelens_core::flow::priming_chain(
            &lazy.session,
            &scrapelens_core::search::LazyBodies(&lazy),
            &request_id,
            &crate::adapters::flow_options(),
        )
        .map_err(|error| format!("não foi possível calcular a cadeia: {error}"))
    })
    .await
    .map_err(|error| format!("o cálculo foi interrompido: {error}"))?
}

/// Visão estruturada (derivada) dos campos do corpo que um adaptador de protocolo reivindica.
#[tauri::command]
pub async fn adapter_view(
    session_dir: String,
    request_id: String,
    side: String,
) -> Result<crate::adapters::AdapterView, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let lazy = cached_session(Path::new(&session_dir))?;
        let request = lazy
            .session
            .requests
            .iter()
            .find(|r| r.id == request_id)
            .ok_or_else(|| format!("requisição {request_id} não encontrada na sessão"))?;
        crate::adapters::view(&lazy, request, &side)
    })
    .await
    .map_err(|error| format!("a leitura foi interrompida: {error}"))?
}

/// Linha do tempo da aplicação (`timeline::timeline`), com o registro de adaptadores do app.
#[tauri::command]
pub async fn session_timeline(session_dir: String) -> Result<scrapelens_core::timeline::Timeline, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let dir = Path::new(&session_dir);
        let rules = load_rules(dir)?;
        let lazy = cached_session(dir)?;
        Ok(scrapelens_core::timeline::timeline(
            &lazy.session,
            &scrapelens_core::search::LazyBodies(&lazy),
            &scrapelens_core::timeline::TimelineOptions { flow: crate::adapters::flow_options(), rules },
        ))
    })
    .await
    .map_err(|error| format!("o cálculo foi interrompido: {error}"))?
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationResult {
    /// Pasta nova (0700) com a sessão importada do trace; contém dados da execução.
    pub trace_dir: String,
    pub trace_requests: usize,
    pub validation: scrapelens_core::validate::Validation,
}

fn validation_root(app: &AppHandle) -> Result<PathBuf, String> {
    let data = app.path().app_data_dir().map_err(|error| format!("sem diretório de dados do app: {error}"))?;
    crate::validation::tmp_root(&data)
}

/// Descarta a sessão temporária do trace (fechar a tela de validação).
#[tauri::command]
pub fn discard_validation(app: AppHandle, trace_dir: String) -> Result<(), String> {
    crate::validation::discard(&validation_root(&app)?, Path::new(&trace_dir))
}

/// "Guardar esta execução": copia a sessão do trace para uma pasta nova e apaga a temporária.
#[tauri::command]
pub async fn keep_validation(app: AppHandle, trace_dir: String, destination: String) -> Result<String, String> {
    let root = validation_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        crate::validation::keep(&root, Path::new(&trace_dir), Path::new(&destination)).map(|p| p.display().to_string())
    })
    .await
    .map_err(|error| format!("o salvamento falhou: {error}"))?
}

/// Importa o trace de execução do script (`scrapelens.trace/1`) para uma pasta nova e valida
/// contra a sessão aberta. Nada é executado e nenhuma rede é usada.
#[tauri::command]
pub async fn validate_execution(
    app: AppHandle,
    session_dir: String,
    trace_path: String,
    map_origin: Option<String>,
) -> Result<ValidationResult, String> {
    let root = validation_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        validate_execution_blocking(&root, Path::new(&session_dir), &trace_path, map_origin.as_deref())
    })
    .await
    .map_err(|error| format!("a validação foi interrompida: {error}"))?
}

fn validate_execution_blocking(
    root: &Path,
    capture_dir: &Path,
    trace_path: &str,
    map_origin: Option<&str>,
) -> Result<ValidationResult, String> {
    use scrapelens_core::validate::{validate, ValidateOptions};
    let map = match map_origin.map(str::trim).filter(|m| !m.is_empty()) {
        None => None,
        Some(text) => Some(
            scrapelens_core::compare::OriginMap::parse(text)
                .ok_or_else(|| format!("mapeamento de origem inválido ({text}); use <origem-da-captura>=<origem-do-trace>, por exemplo https://sistema.gov.br=http://127.0.0.1:8080"))?,
        ),
    };
    let bytes = read_import_file_max(trace_path, "trace de execução", crate::validation::TRACE_MAX_BYTES)?;
    let imported = scrapelens_core::parse::import_trace(&bytes).map_err(|error| {
        format!("trace inválido: {error}. Use o arquivo gerado pelo script de priming com --trace (scrapelens.trace/1).")
    })?;
    let dir = unique_session_dir(root, &sanitize_dir_name(&imported.bundle.session.session.id));
    store::write_session_dir(&imported.bundle, &dir)
        .map_err(|error| format!("não foi possível gravar a sessão do trace: {error}"))?;
    let rules = load_rules(capture_dir)?;
    let capture = cached_session(capture_dir)?;
    let trace = cached_session(&dir)?;
    let mut options = ValidateOptions { rules, ..Default::default() };
    options.compare.flow = crate::adapters::flow_options();
    // o `plan.hash` é recalculado com os mesmos adaptadores da geração (o app gera e valida sempre com o adaptador)
    options.compare.map_origin = map;
    let validation = validate(
        &capture.session,
        &scrapelens_core::search::LazyBodies(&capture),
        &trace.session,
        &scrapelens_core::search::LazyBodies(&trace),
        &options,
    );
    Ok(ValidationResult {
        trace_dir: dir.display().to_string(),
        trace_requests: trace.session.requests.len(),
        validation,
    })
}

/// Sucesso da aplicação × HTTP (`assess::assess_session`). Regras opcionais em
/// `<sessao>/assess-rules.json`; regras inválidas viram erro acionável.
#[tauri::command]
pub async fn assess_session(session_dir: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || assess_blocking(Path::new(&session_dir)))
        .await
        .map_err(|error| format!("a avaliação foi interrompida: {error}"))?
}

/// Regras opcionais `<sessao>/assess-rules.json` (arquivo regular, até 256 KiB); padrão sem o arquivo.
fn load_rules(dir: &Path) -> Result<scrapelens_core::assess::AssessRules, String> {
    use scrapelens_core::assess::AssessRules;
    let rules_path = dir.join("assess-rules.json");
    match read_rules_file(&rules_path)? {
        Some(text) => AssessRules::from_json(&text).map_err(|_| {
            format!(
                "as regras em {} não são válidas (JSON, schema ou campos fora do esquema scrapelens.assess-rules/1); corrija ou remova o arquivo",
                rules_path.display()
            )
        }),
        None => Ok(AssessRules::default()),
    }
}

const RULES_MAX_BYTES: u64 = 256 * 1024;

/// Lê `assess-rules.json` só se for arquivo regular sem symlink (symlink_metadata + inode) e até 256 KiB.
/// `None` quando não existe.
fn read_rules_file(path: &Path) -> Result<Option<String>, String> {
    use std::io::Read;
    let before = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("não foi possível verificar {}: {error}", path.display())),
    };
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(format!("{} não é um arquivo regular (link simbólico recusado); remova-o", path.display()));
    }
    let file = fs::File::open(path).map_err(|error| format!("não foi possível ler {}: {error}", path.display()))?;
    let opened = file.metadata().map_err(|error| format!("não foi possível ler {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.ino() != before.ino() || opened.dev() != before.dev() {
            return Err(format!("{} mudou durante a abertura; recusado", path.display()));
        }
    }
    if !opened.is_file() || opened.len() > RULES_MAX_BYTES {
        return Err(format!("{} excede 256 KiB ou não é arquivo regular; reduza ou remova o arquivo", path.display()));
    }
    let mut bytes = Vec::new();
    file.take(RULES_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("não foi possível ler {}: {error}", path.display()))?;
    if bytes.len() as u64 > RULES_MAX_BYTES {
        return Err(format!("{} excede 256 KiB; reduza ou remova o arquivo", path.display()));
    }
    String::from_utf8(bytes).map(Some).map_err(|_| format!("{} não é UTF-8 válido; corrija ou remova o arquivo", path.display()))
}

pub(crate) fn assess_blocking(dir: &Path) -> Result<serde_json::Value, String> {
    use scrapelens_core::assess::assess_session;
    let rules_path = dir.join("assess-rules.json");
    let rules = load_rules(dir)?;
    let lazy = cached_session(dir)?;
    let outcomes = assess_session(&lazy.session, &scrapelens_core::search::LazyBodies(&lazy), &rules);
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for outcome in &outcomes {
        *counts.entry(outcome.verdict_kind.count_key().to_string()).or_default() += 1;
    }
    Ok(serde_json::json!({
        "schema": "scrapelens.assess/1",
        "rules": if rules_path.is_file() { rules_path.display().to_string() } else { "default".to_string() },
        "counts": counts,
        "warnings": rules.warnings(),
        "outcomes": outcomes,
    }))
}

/// Comparação mantida no Rust: a UI recebe só o resumo e pede páginas de pares
/// e os campos de um par sob demanda (evita dezenas de MB de JSON no IPC).
struct StoredComparison {
    id: u64,
    result: Arc<scrapelens_core::compare::SessionComparison>,
}

static COMPARISON: Mutex<Option<StoredComparison>> = Mutex::new(None);
static COMPARISON_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
const ONLY_LIST_CAP: usize = 200;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompareSummary {
    pub handle: u64,
    pub pairs: usize,
    /// Pares com algum campo que não é estático (candidatos ao filtro "só dinâmicos").
    pub dynamic_pairs: usize,
    pub counts: scrapelens_core::compare::PairCounts,
    pub parts_counts: scrapelens_core::compare::PartsCounts,
    pub redacted_fields: usize,
    pub ambiguities: Vec<String>,
    pub warnings: Vec<String>,
    pub only_in_a: Vec<scrapelens_core::compare::RequestRef>,
    pub only_in_a_total: usize,
    pub only_in_b: Vec<scrapelens_core::compare::RequestRef>,
    pub only_in_b_total: usize,
    /// Sobras de mesmo modelo nos dois lados (provável reordenação), limitadas.
    pub reordered: Vec<scrapelens_core::compare::ReorderedPair>,
    pub reordered_total: usize,
    /// Rodadas pareadas, rodadas sem par e requisição de entrada (docs/10 L6).
    pub rounds: Vec<scrapelens_core::compare::RoundInfo>,
    pub unpaired_rounds: Vec<scrapelens_core::compare::UnpairedRound>,
    pub entry_request: Option<String>,
    /// Proteção/estáticos fora do alinhamento: tipo + totais, com listas limitadas.
    pub groups: Vec<GroupSummary>,
    pub include_all: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupSummary {
    pub kind: String,
    pub a: Vec<scrapelens_core::compare::RequestRef>,
    pub a_total: usize,
    pub b: Vec<scrapelens_core::compare::RequestRef>,
    pub b_total: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairSummary {
    pub index: usize,
    /// Índice em `rounds`.
    pub round: usize,
    pub a: scrapelens_core::compare::RequestRef,
    pub b: scrapelens_core::compare::RequestRef,
    pub aligned_by: String,
    pub out_of_order: bool,
    pub counts: scrapelens_core::compare::PairCounts,
    pub parts_counts: scrapelens_core::compare::PartsCounts,
    pub field_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComparePage {
    /// Pares que passam no filtro (não só os desta página).
    pub total: usize,
    pub items: Vec<PairSummary>,
}

fn pair_is_dynamic(pair: &scrapelens_core::compare::PairComparison) -> bool {
    let c = &pair.counts;
    c.dynamic + c.only_a + c.only_b + c.redacted > 0
}

/// Compara a sessão aberta (A) com outra pasta (B), fora da thread da UI.
#[tauri::command]
pub async fn compare_open(
    dir_a: String,
    dir_b: String,
    include_all: Option<bool>,
    a_range: Option<String>,
    b_range: Option<String>,
) -> Result<CompareSummary, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let options = compare_options(include_all.unwrap_or(false), a_range.as_deref(), b_range.as_deref())?;
        open_comparison_with(&dir_a, &dir_b, options)
    })
        .await
        .map_err(|error| format!("a comparação foi interrompida: {error}"))?
}

/// Página de pares (resumos, sem campos).
#[tauri::command]
pub async fn compare_page(handle: u64, offset: usize, limit: usize, only_dynamic: bool) -> Result<ComparePage, String> {
    tauri::async_runtime::spawn_blocking(move || comparison_page(handle, offset, limit, only_dynamic))
        .await
        .map_err(|error| format!("a leitura foi interrompida: {error}"))?
}

/// Campos de um par (na ordem da fonte), carregados ao expandir.
#[tauri::command]
pub async fn compare_fields(handle: u64, index: usize) -> Result<Vec<scrapelens_core::compare::FieldDiff>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let result = stored_comparison(handle)?;
        result
            .pairs
            .get(index)
            .map(|pair| pair.fields.clone())
            .ok_or_else(|| format!("par {index} inexistente"))
    })
    .await
    .map_err(|error| format!("a leitura foi interrompida: {error}"))?
}

fn stored_comparison(handle: u64) -> Result<Arc<scrapelens_core::compare::SessionComparison>, String> {
    let guard = COMPARISON.lock().map_err(|_| "comparação corrompida".to_string())?;
    match guard.as_ref() {
        Some(stored) if stored.id == handle => Ok(stored.result.clone()),
        _ => Err("esta comparação foi substituída por outra; compare de novo".to_string()),
    }
}

fn comparison_page(handle: u64, offset: usize, limit: usize, only_dynamic: bool) -> Result<ComparePage, String> {
    let result = stored_comparison(handle)?;
    let limit = limit.clamp(1, 500);
    let mut total = 0usize;
    let mut items = Vec::new();
    for (index, pair) in result.pairs.iter().enumerate() {
        if only_dynamic && !pair_is_dynamic(pair) {
            continue;
        }
        if total >= offset && items.len() < limit {
            items.push(PairSummary {
                index,
                round: pair.round,
                a: pair.a.clone(),
                b: pair.b.clone(),
                aligned_by: pair.aligned_by.clone(),
                out_of_order: pair.out_of_order,
                counts: pair.counts.clone(),
                parts_counts: pair.parts_counts.clone(),
                field_count: pair.fields.len(),
            });
        }
        total += 1;
    }
    Ok(ComparePage { total, items })
}

/// Caminhos canonicalizados (resolve `./s`, `s` e symlinks): a mesma sessão por
/// dois caminhos é recusada.
fn compare_options(
    include_all: bool,
    a_range: Option<&str>,
    b_range: Option<&str>,
) -> Result<scrapelens_core::compare::CompareOptions, String> {
    use scrapelens_core::compare::RequestRange;
    let range = |label: &str, text: Option<&str>| -> Result<Option<RequestRange>, String> {
        match text.map(str::trim).filter(|t| !t.is_empty()) {
            None => Ok(None),
            Some(text) => RequestRange::parse(text)
                .map(Some)
                .ok_or_else(|| format!("faixa {label} inválida ({text}); use de:ate, por exemplo 10:50 ou har-0010:har-0050")),
        }
    };
    Ok(scrapelens_core::compare::CompareOptions {
        include_all,
        a_range: range("A", a_range)?,
        b_range: range("B", b_range)?,
        flow: crate::adapters::flow_options(),
        ..Default::default()
    })
}

#[cfg(test)]
fn open_comparison(dir_a: &str, dir_b: &str) -> Result<CompareSummary, String> {
    open_comparison_with(dir_a, dir_b, scrapelens_core::compare::CompareOptions::default())
}

fn open_comparison_with(
    dir_a: &str,
    dir_b: &str,
    options: scrapelens_core::compare::CompareOptions,
) -> Result<CompareSummary, String> {
    let canon = |label: &str, dir: &str| {
        fs::canonicalize(dir).map_err(|error| format!("sessão {label} inacessível ({dir}): {error}"))
    };
    let a_path = canon("A", dir_a)?;
    let b_path = canon("B", dir_b)?;
    if a_path == b_path {
        return Err(format!(
            "A e B são a mesma sessão ({}); escolha outra pasta para comparar",
            a_path.display()
        ));
    }
    let a = cached_session(&a_path)?;
    let b = cached_session(&b_path).map_err(|error| format!("sessão B: {error}"))?;
    let result = scrapelens_core::compare::compare_sessions(
        &a.session,
        &scrapelens_core::search::LazyBodies(&a),
        &b.session,
        &scrapelens_core::search::LazyBodies(&b),
        &options,
    );
    let id = COMPARISON_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let summary = CompareSummary {
        handle: id,
        pairs: result.pairs.len(),
        dynamic_pairs: result.pairs.iter().filter(|pair| pair_is_dynamic(pair)).count(),
        counts: result.counts.clone(),
        parts_counts: result.parts_counts.clone(),
        redacted_fields: result.redacted_fields,
        ambiguities: result.ambiguities.iter().take(ONLY_LIST_CAP).cloned().collect(),
        warnings: result.warnings.clone(),
        only_in_a: result.only_in_a.iter().take(ONLY_LIST_CAP).cloned().collect(),
        only_in_a_total: result.only_in_a.len(),
        only_in_b: result.only_in_b.iter().take(ONLY_LIST_CAP).cloned().collect(),
        only_in_b_total: result.only_in_b.len(),
        reordered: result.reordered.iter().take(ONLY_LIST_CAP).cloned().collect(),
        reordered_total: result.reordered.len(),
        rounds: result.rounds.clone(),
        unpaired_rounds: result.unpaired_rounds.clone(),
        entry_request: result.entry_request.clone(),
        groups: result
            .groups
            .iter()
            .map(|group| GroupSummary {
                kind: group.kind.clone(),
                a: group.a.iter().take(ONLY_LIST_CAP).cloned().collect(),
                a_total: group.a.len(),
                b: group.b.iter().take(ONLY_LIST_CAP).cloned().collect(),
                b_total: group.b.len(),
            })
            .collect(),
        include_all: options.include_all,
    };
    *COMPARISON.lock().map_err(|_| "comparação corrompida".to_string())? =
        Some(StoredComparison { id, result: Arc::new(result) });
    Ok(summary)
}

/// Script de priming (cadeia completa até a requisição); usa o codificador do adaptador
/// de protocolo quando ele reivindica o campo e informa isso na prévia.
fn priming_preview(dir: &Path, request_id: &str, lenient_parts: bool) -> Result<crate::export::ExportPreview, String> {
    let lazy = cached_session(dir)?;
    let request = lazy
        .session
        .requests
        .iter()
        .find(|r| r.id == request_id)
        .ok_or_else(|| format!("requisição {request_id} não encontrada na sessão"))?;
    let options = scrapelens_core::export::priming::PrimingOptions {
        flow: crate::adapters::flow_options(),
        adapter_encoders: crate::adapters::priming_encoders(),
        lenient_parts,
        ..Default::default()
    };
    let output = scrapelens_core::export::priming::to_python(
        &lazy.session,
        &scrapelens_core::search::LazyBodies(&lazy),
        request_id,
        &options,
    )
    .map_err(|error| format!("não foi possível gerar o script de priming: {error}"))?;
    let adapter = crate::adapters::script_uses_adapter(&output.text).map(str::to_string);
    Ok(crate::export::ExportPreview {
        session_id: lazy.session.session.id.clone(),
        request_id: request.id.clone(),
        request_method: request.method.clone(),
        request_url: request.url.clone(),
        protocol: request.protocol.as_str().to_string(),
        header_verification: request.request_headers.verification().as_str().to_string(),
        format: "priming".to_string(),
        text: output.text,
        warnings: output.warnings,
        skipped_headers: output.skipped_headers,
        body_included: output.body_included,
        body_note: output.body_note,
        body_state: request.request_body.state.as_str().to_string(),
        adapter,
    })
}

/// Prévia de exportação; com `annotate` calcula as origens (cache LazySession).
fn export_preview(
    dir: &Path,
    request_id: &str,
    format: &str,
    annotate: bool,
    lenient_parts: bool,
) -> Result<crate::export::ExportPreview, String> {
    if format == "priming" {
        return priming_preview(dir, request_id, lenient_parts);
    }
    let origins = annotate.then(|| {
        cached_session(dir).and_then(|lazy| {
            scrapelens_core::flow::value_origins(
                &lazy.session,
                &scrapelens_core::search::LazyBodies(&lazy),
                request_id,
                &crate::adapters::flow_options(),
            )
            .map_err(|error| error.to_string())
        })
    });
    crate::export::preview_with(dir, request_id, format, origins)
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
    annotate_origins: Option<bool>,
    lenient_parts: Option<bool>,
) -> Result<crate::export::ExportPreview, String> {
    tauri::async_runtime::spawn_blocking(move || {
        export_preview(Path::new(&session_dir), &request_id, &format, annotate_origins.unwrap_or(false), lenient_parts.unwrap_or(false))
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

    #[test]
    fn import_read_uses_fd_refusing_symlink_fifo_and_dir() {
        use std::os::unix::fs::symlink;
        let root = std::fs::canonicalize(std::env::temp_dir()).unwrap().join(format!(
            "scrapelens-fdread-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("a.har");
        std::fs::write(&file, b"{\"log\":{}}").unwrap();
        assert_eq!(read_import_file_max(file.to_str().unwrap(), "HAR", 1024).unwrap(), b"{\"log\":{}}");
        assert!(read_import_file_max(file.to_str().unwrap(), "HAR", 3).unwrap_err().contains("maior"));
        let link = root.join("l.har");
        symlink(&file, &link).unwrap();
        assert!(read_import_file_max(link.to_str().unwrap(), "HAR", 1024).is_err());
        let fifo = root.join("p.har");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        // FIFO sem escritor: O_NONBLOCK não trava; fstat recusa por não ser regular.
        assert!(read_import_file_max(fifo.to_str().unwrap(), "HAR", 1024).unwrap_err().contains("regular"));
        assert!(read_import_file_max(root.to_str().unwrap(), "HAR", 1024).unwrap_err().contains("diretório"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn import_open_fails_when_parent_is_swapped_for_symlink() {
        let root = std::fs::canonicalize(std::env::temp_dir()).unwrap().join(format!(
            "scrapelens-openat-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(root.join("dir")).unwrap();
        std::fs::create_dir_all(root.join("other")).unwrap();
        std::fs::write(root.join("dir/a.har"), b"good").unwrap();
        std::fs::write(root.join("other/a.har"), b"evil").unwrap();
        let path = root.join("dir/a.har");
        crate::cli::validate_absolute_regular_file(&path).unwrap();
        assert_eq!(read_import_file_max(path.to_str().unwrap(), "HAR", 64).unwrap(), b"good");
        // troca o pai por symlink depois da validação
        std::fs::rename(root.join("dir"), root.join("dir-old")).unwrap();
        std::os::unix::fs::symlink(root.join("other"), root.join("dir")).unwrap();
        assert!(read_import_file_max(path.to_str().unwrap(), "HAR", 64).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn second_open_is_refused_while_one_is_loading() {
        let flag = std::sync::atomic::AtomicBool::new(false);
        let first = FlagGuard::acquire(&flag).expect("primeira abertura");
        assert!(FlagGuard::acquire(&flag).is_none(), "segunda em paralelo deve ser recusada");
        drop(first);
        assert!(FlagGuard::acquire(&flag).is_some(), "liberado ao terminar");
        let result = std::panic::catch_unwind(|| {
            let _g = FlagGuard::acquire(&flag).unwrap();
            panic!("falha na abertura");
        });
        assert!(result.is_err());
        assert!(!flag.load(std::sync::atomic::Ordering::SeqCst), "pânico também libera");
    }

    #[test]
    fn starting_state_disables_menu_and_reenables_on_failure() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let flag = AtomicBool::new(false);
        let calls = std::cell::RefCell::new(Vec::new());
        {
            let _g = StartingGuard::begin(&flag, |r| calls.borrow_mut().push(r));
            assert!(flag.load(Ordering::SeqCst));
            assert!(crate::menu::blocked_while_recording("start-session", &flag));
            // start falha (sai sem commit)
        }
        assert!(!flag.load(Ordering::SeqCst));
        assert_eq!(*calls.borrow(), vec![true, false]);
        calls.borrow_mut().clear();
        {
            let mut g = StartingGuard::begin(&flag, |r| calls.borrow_mut().push(r));
            g.commit();
        }
        assert!(flag.load(Ordering::SeqCst), "start ok mantém gravando");
        assert_eq!(*calls.borrow(), vec![true]);
    }

    #[test]
    fn opens_session_file_with_any_name_but_not_symlink() {
        let root = std::fs::canonicalize(std::env::temp_dir()).unwrap().join(format!(
            "scrapelens-anyname-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("minha-captura.json");
        std::fs::write(&file, MINIMAL_SESSION).unwrap();
        let payload = read_session_payload(file.to_str().unwrap()).unwrap();
        assert_eq!(payload.session["requestCount"], 0);
        assert_eq!(payload.session.pointer("/session/id").unwrap(), "test-session");
        assert_eq!(payload.session_dir.as_deref(), file.to_str());
        let page = crate::listing::list_page(&cached_session(&file).unwrap().session, 0, 10, &Default::default());
        assert_eq!(page.total, 0);

        let link = root.join("atalho.json");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(read_session_payload(link.to_str().unwrap()).unwrap_err().contains("symlink"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn imports_are_refused_while_recording() {
        assert!(ensure_not_recording(true).unwrap_err().contains("Encerre"));
        assert!(ensure_not_recording(false).is_ok());
        assert_eq!(crate::menu::RECORDING_DISABLED_IDS, ["import-har", "import-netlog", "start-session"]);
    }

    #[test]
    fn menu_guard_never_waits_on_capture_lock() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let state = crate::AppState::default();
        // start_session segura o lock (até 35 s); o menu tem de responder já.
        let _held = state.capture.lock().unwrap();
        let started = std::time::Instant::now();
        assert!(!crate::menu::blocked_while_recording("start-session", &state.recording));
        state.recording.store(true, Ordering::SeqCst);
        assert!(crate::menu::blocked_while_recording("start-session", &state.recording));
        assert!(crate::menu::blocked_while_recording("import-har", &state.recording));
        assert!(!crate::menu::blocked_while_recording("stop-session", &state.recording));
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
        let _ = AtomicBool::new(false);
    }
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
        assert_eq!(payload.session["requestCount"], 0);
        assert_eq!(payload.session["requests"], serde_json::json!([]));
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
        fixture_session(name, "detran-pb", "detran-pb")
    }

    fn fixture_session(name: &str, folder: &str, stem: &str) -> PathBuf {
        use scrapelens_core::correlate::CorrelationOptions;
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures").join(folder);
        let read = |file: String| fs::read(fixtures.join(file)).unwrap();
        let imported = scrapelens_core::parse::import_capture_with_bodies(
            &read(format!("{stem}.cdp.jsonl")),
            &read(format!("{stem}.netlog.json")),
            Some(&read(format!("{stem}.cdp-bodies.jsonl"))),
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
        let first = cached_session(&dir).unwrap();
        let second = cached_session(&dir).unwrap();
        assert!(Arc::ptr_eq(&first, &second), "segunda busca deve reutilizar o bundle");
        // arquivo mudou (tamanho/mtime) → recarrega
        let session_file = dir.join("session.json");
        let mut text = fs::read_to_string(&session_file).unwrap();
        text.push('\n');
        fs::write(&session_file, text).unwrap();
        let third = cached_session(&dir).unwrap();
        assert!(!Arc::ptr_eq(&first, &third));
        // outra sessão substitui a anterior
        let other = detran_session("cache-other");
        let fourth = cached_session(&other).unwrap();
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
            eprintln!("busca {round}: {:?}, {} achados, loads={}, rss_atual={}", start.elapsed(), found.matches.len(), SESSION_LOADS.load(std::sync::atomic::Ordering::SeqCst), String::from_utf8_lossy(&std::process::Command::new("ps").args(["-o", "rss=", "-p", &std::process::id().to_string()]).output().unwrap().stdout).trim());
        }
    }

    #[test]
    fn origins_chain_and_compare_on_detran_fixtures() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let a = detran_session("flow-a");
        let b = fixture_session("flow-b", "detran-pb-b", "detran-pb-b");
        let lazy = cached_session(&a).unwrap();
        let source = scrapelens_core::search::LazyBodies(&lazy);
        let options = scrapelens_core::flow::FlowOptions::default();
        let origins = scrapelens_core::flow::value_origins(&lazy.session, &source, "cdp-r0011", &options).unwrap();
        assert!(origins.values.iter().any(|v| v.field == "JSESSIONID"));
        let chain = scrapelens_core::flow::priming_chain(&lazy.session, &source, "cdp-r0011", &options).unwrap();
        assert!(!chain.steps.is_empty() && !chain.protection.is_empty());
        let cmp = open_comparison(a.to_str().unwrap(), b.to_str().unwrap()).unwrap();
        assert!(cmp.counts.dynamic > 0 && cmp.pairs > 0);
        let page = comparison_page(cmp.handle, 0, 5, true).unwrap();
        assert!(page.total <= cmp.pairs && page.items.len() <= 5 && !page.items.is_empty());
        let all = comparison_page(cmp.handle, 0, 500, false).unwrap();
        assert_eq!(all.total, cmp.pairs);
        let fields = stored_comparison(cmp.handle).unwrap().pairs[page.items[0].index].fields.len();
        assert_eq!(fields, page.items[0].field_count);
        assert!(comparison_page(cmp.handle + 99, 0, 5, false).is_err());
        // a mesma sessão por caminhos diferentes (./, symlink) é recusada
        let same = a.to_str().unwrap().to_string();
        assert!(open_comparison(&same, &format!("{same}/../{}", a.file_name().unwrap().to_str().unwrap())).unwrap_err().contains("mesma sessão"));
        let link = std::env::temp_dir().join(format!("sl-link-{}", std::process::id()));
        std::os::unix::fs::symlink(&a, &link).unwrap();
        assert!(open_comparison(&same, link.to_str().unwrap()).unwrap_err().contains("mesma sessão"));
        fs::remove_file(&link).ok();
        // as duas sessões ficam em cache ao mesmo tempo
        let again = cached_session(&a).unwrap();
        assert!(Arc::ptr_eq(&lazy, &again));
        fs::remove_dir_all(a).ok();
        fs::remove_dir_all(b).ok();
    }

    #[test]
    fn assess_marks_blocked_responses_on_detran_fixture() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = detran_session("assess");
        let result = assess_blocking(&dir).unwrap();
        assert_eq!(result["schema"], "scrapelens.assess/1");
        let outcomes = result["outcomes"].as_array().unwrap();
        assert!(!outcomes.is_empty());
        assert!(outcomes.iter().any(|o| o["verdictKind"] == "app-ok"));
        // as chaves de `counts` são as mesmas do `verdictKind` (kebab-case)
        let counts = result["counts"].as_object().unwrap();
        assert!(!counts.is_empty());
        for (key, value) in counts {
            assert_eq!(value.as_u64().unwrap() as usize, outcomes.iter().filter(|o| o["verdictKind"] == key.as_str()).count(), "chave {key} fora do esquema");
            assert!(["app-ok", "app-error", "blocked", "indeterminado", "not-assessed"].contains(&key.as_str()), "chave inesperada: {key}");
        }
        // regras inválidas viram erro acionável
        fs::write(dir.join("assess-rules.json"), "{\"schema\":\"x\"}").unwrap();
        assert!(assess_blocking(&dir).unwrap_err().contains("corrija ou remova"));
        // o erro de parse não ecoa conteúdo do arquivo
        fs::write(dir.join("assess-rules.json"), "SEGREDO-NO-ARQUIVO").unwrap();
        assert!(!assess_blocking(&dir).unwrap_err().contains("SEGREDO"));
        // arquivo grande é recusado
        fs::write(dir.join("assess-rules.json"), vec![b' '; 256 * 1024 + 1]).unwrap();
        assert!(assess_blocking(&dir).unwrap_err().contains("256 KiB"));
        // symlink é recusado, sem ler o alvo
        let outside = dir.join("fora.json");
        fs::write(&outside, "{\"schema\":\"scrapelens.assess-rules/1\"}").unwrap();
        fs::remove_file(dir.join("assess-rules.json")).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("assess-rules.json")).unwrap();
        assert!(assess_blocking(&dir).unwrap_err().contains("link simbólico"));
        fs::remove_file(dir.join("assess-rules.json")).unwrap();
        // sem regras ou com regras sãs, sem avisos; regras que distorcem devolvem os avisos do core
        fs::remove_file(dir.join("assess-rules.json")).ok();
        assert_eq!(result["warnings"].as_array().unwrap().len(), 0);
        fs::write(
            dir.join("assess-rules.json"),
            "{\"schema\":\"scrapelens.assess-rules/1\",\"protectionPaths\":[\"/\"]}",
        )
        .unwrap();
        let warned = assess_blocking(&dir).unwrap();
        let warnings = warned["warnings"].as_array().unwrap();
        assert!(warnings.iter().any(|w| w.as_str().unwrap().contains("protectionPaths")), "{warnings:?}");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn annotated_export_adds_only_comments_on_detran() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = detran_session("annot");
        let d = Path::new(&dir);
        let plain = export_preview(d, "cdp-r0011", "curl", false, false).unwrap();
        let noted = export_preview(d, "cdp-r0011", "curl", true, false).unwrap();
        let strip = |text: &str| text.lines().filter(|l| !l.trim_start().starts_with('#')).collect::<Vec<_>>().join("\n");
        assert_eq!(strip(&plain.text), strip(&noted.text));
        assert!(noted.text.len() > plain.text.len(), "deve haver comentários de origem");
        assert!(noted.warnings.iter().all(|w| w.code != "export.origins_unavailable"));
        fs::remove_dir_all(dir).ok();
    }

    /// Gera as prévias reais (com e sem origens) para o harness de UI:
    /// `SL_SESSION=<pasta> SL_REQUEST=<id> SL_DUMP=<arquivo.json> cargo test -- --ignored dump_export_previews`.
    #[test]
    #[ignore]
    fn dump_export_previews() {
        let dir = std::env::var("SL_SESSION").expect("SL_SESSION");
        let request = std::env::var("SL_REQUEST").expect("SL_REQUEST");
        let out = std::env::var("SL_DUMP").expect("SL_DUMP");
        let mut all = serde_json::Map::new();
        for format in ["curl", "python"] {
            for annotate in [false, true] {
                let preview = export_preview(Path::new(&dir), &request, format, annotate, false).unwrap();
                all.insert(format!("{format}-{annotate}"), serde_json::to_value(&preview).unwrap());
            }
        }
        fs::write(out, serde_json::to_string_pretty(&all).unwrap()).unwrap();
    }

    /// Medição manual: `SL_LARGE_A=<sessão> SL_LARGE_B=<cópia> cargo test --release -- --ignored large_compare --nocapture`.
    #[test]
    #[ignore]
    fn large_compare_timing() {
        let rss = || {
            String::from_utf8_lossy(
                &std::process::Command::new("ps").args(["-o", "rss=", "-p", &std::process::id().to_string()]).output().unwrap().stdout,
            )
            .trim()
            .to_string()
        };
        let a = std::env::var("SL_LARGE_A").expect("SL_LARGE_A");
        let b = std::env::var("SL_LARGE_B").expect("SL_LARGE_B");
        let start = std::time::Instant::now();
        let summary = open_comparison(&a, &b).unwrap();
        let opened = start.elapsed();
        let filtered = comparison_page(summary.handle, 0, 50, summary.pairs > 500).unwrap();
        let first = start.elapsed();
        eprintln!("1a página com o filtro padrão (só dinâmicos se >500 pares): {} item(ns) de {}", filtered.items.len(), filtered.total);
        let page = comparison_page(summary.handle, 0, 50, false).unwrap();
        let fields = stored_comparison(summary.handle).unwrap().pairs[page.items[0].index].fields.len();
        eprintln!(
            "pares={} dinamicos={} resumo_json={}B pagina50_json={}B campos_do_1o_par={} abrir={:?} 1a_pagina={:?} rss_kb={}",
            summary.pairs,
            summary.dynamic_pairs,
            serde_json::to_string(&summary).unwrap().len(),
            serde_json::to_string(&page).unwrap().len(),
            fields,
            opened,
            first,
            rss()
        );
        let full = scrapelens_core::compare::compare_sessions(
            &cached_session(Path::new(&a)).unwrap().session,
            &scrapelens_core::search::LazyBodies(&cached_session(Path::new(&a)).unwrap()),
            &cached_session(Path::new(&b)).unwrap().session,
            &scrapelens_core::search::LazyBodies(&cached_session(Path::new(&b)).unwrap()),
            &scrapelens_core::compare::CompareOptions::default(),
        );
        eprintln!("json_completo_antigo={}B", serde_json::to_string(&full).unwrap().len());
    }

    #[test]
    fn compare_summary_carries_reordered_leftovers() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let a = detran_session("reorder-a");
        let b = fixture_session("reorder-b", "detran-pb-b", "detran-pb-b");
        // B com a 4ª requisição movida para o fim: sobra de mesmo modelo nos dois lados.
        let file = b.join("session.json");
        let mut doc: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        let requests = doc["requests"].as_array_mut().unwrap();
        let moved = requests.remove(3);
        requests.push(moved);
        fs::write(&file, serde_json::to_vec(&doc).unwrap()).unwrap();
        let summary = open_comparison(a.to_str().unwrap(), b.to_str().unwrap()).unwrap();
        assert_eq!(summary.reordered_total, 1);
        assert_eq!(summary.reordered[0].a.request_id, "cdp-r0004");
        assert!(summary.only_in_a.iter().any(|r| r.request_id == "cdp-r0004"));
        assert!(summary.only_in_b.iter().any(|r| r.request_id == "cdp-r0004"));
        fs::remove_dir_all(a).ok();
        fs::remove_dir_all(b).ok();
    }

    #[test]
    fn compare_options_parse_ranges_and_reject_garbage() {
        let ok = compare_options(true, Some("2:9"), Some(" ")).unwrap();
        assert!(ok.include_all && ok.a_range.is_some() && ok.b_range.is_none());
        assert!(compare_options(false, Some("semfaixa"), None).is_err());
    }

    #[test]
    fn real_shape_compare_reports_rounds_and_groups() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let har = |name: &str| {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/detran-pb-real-shape").join(name);
            let imported = scrapelens_core::import_har(&fs::read(path).unwrap()).unwrap();
            let dir = temp_session_dir(&format!("rs-{name}"));
            fs::remove_dir_all(&dir).ok();
            store::write_session_dir(&imported.bundle, &dir).unwrap();
            dir
        };
        let a = har("real-shape-1round.har");
        let b = har("real-shape-2rounds.har");
        let summary = open_comparison(a.to_str().unwrap(), b.to_str().unwrap()).unwrap();
        assert!(!summary.rounds.is_empty());
        assert!(!summary.unpaired_rounds.is_empty(), "a 2ª rodada de B fica sem par");
        assert!(summary.groups.iter().any(|g| g.kind == "protection"));
        let all = open_comparison_with(
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            compare_options(true, None, None).unwrap(),
        )
        .unwrap();
        assert!(all.include_all && all.groups.is_empty());
        fs::remove_dir_all(a).ok();
        fs::remove_dir_all(b).ok();
    }

    fn real_shape_session(name: &str) -> PathBuf {
        let har = fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/detran-pb-real-shape/real-shape-1round.har")).unwrap();
        let imported = scrapelens_core::parse::import_har(&har).unwrap();
        let dir = temp_session_dir(name);
        fs::remove_dir_all(&dir).ok();
        store::write_session_dir(&imported.bundle, &dir).unwrap();
        dir
    }

    #[test]
    fn natural_adapter_names_view_and_priming_encoder() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = real_shape_session("natural");
        let d = dir.to_str().unwrap();
        let lazy = cached_session(&dir).unwrap();
        // origens usam nomes internos do adaptador
        let origins = scrapelens_core::flow::value_origins(
            &lazy.session,
            &scrapelens_core::search::LazyBodies(&lazy),
            "har-0026",
            &crate::adapters::flow_options(),
        )
        .unwrap();
        let json = serde_json::to_string(&origins).unwrap();
        assert!(json.contains("XML.delta") || json.contains("XML.p."), "sem nomes internos do adaptador");
        // visão estruturada: bruto + partes nomeadas
        let request = lazy.session.requests.iter().find(|r| r.id == "har-0026").unwrap();
        let view = crate::adapters::view(&lazy, request, "request").unwrap();
        assert!(!view.fields.is_empty() && view.fields[0].error.is_none());
        assert!(view.fields[0].parts.iter().any(|p| p.name == "delta" || p.name.starts_with("p.")));
        assert!(!view.fields[0].raw.is_empty());
        assert!(crate::adapters::view(&lazy, request, "lado").is_err());
        // script de priming usa o codificador do adaptador e a prévia diz isso
        let preview = export_preview(&dir, "har-0026", "priming", false, false).unwrap();
        assert_eq!(preview.format, "priming");
        assert_eq!(preview.adapter.as_deref(), Some("natural-ajax"));
        // `--lenient-parts` é opção avançada: desligada por padrão, e ligada ela gera o script sem erro (nesta fixture o texto sai igual ao estrito)
        let lenient = export_preview(&dir, "har-0026", "priming", false, true).unwrap();
        assert_eq!(lenient.adapter.as_deref(), Some("natural-ajax"));
        let _ = d;
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn adapter_view_refuses_oversized_field_and_keeps_raw() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = real_shape_session("natural-big");
        let name = {
            let session: serde_json::Value = serde_json::from_slice(&fs::read(dir.join("session.json")).unwrap()).unwrap();
            let req = session["requests"].as_array().unwrap().iter().find(|r| r["id"] == "har-0026").unwrap();
            req["requestBody"]["attachment"].as_str().unwrap().to_string()
        };
        let big = format!("XML=v{}", "0".repeat(crate::adapters::MAX_FIELD_BYTES + 10));
        fs::write(dir.join("attachments").join(&name), big).unwrap();
        let lazy = cached_session(&dir).unwrap();
        let request = lazy.session.requests.iter().find(|r| r.id == "har-0026").unwrap();
        let view = crate::adapters::view(&lazy, request, "request").unwrap();
        assert_eq!(view.fields.len(), 1);
        let field = &view.fields[0];
        assert!(field.error.as_deref().unwrap().contains("campo grande demais para a visão do adaptador"));
        assert!(field.parts.is_empty());
        assert!(field.raw.starts_with("v000") && field.raw.len() < 70 * 1024, "bruto cortado, não inteiro");
        fs::remove_dir_all(dir).ok();
    }

    fn sim_trace(name: &str) -> String {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/busca-corpos").join(name).display().to_string()
    }

    #[test]
    fn timeline_and_validate_execution_on_real_shape_with_sim_traces() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let capture = real_shape_session("timeline-cap");
        // linha do tempo: eventos da aplicação com rótulo do adaptador e grupos recolhidos
        let rt = tauri::async_runtime::block_on(session_timeline(capture.display().to_string())).unwrap();
        assert!(rt.counts.events > 0 && rt.counts.protection > 0);
        let json = serde_json::to_value(&rt).unwrap();
        assert!(json["items"].as_array().unwrap().iter().any(|i| i["type"] == "group" && i["kind"] == "protection"));
        assert!(json["items"].as_array().unwrap().iter().any(|i| i["label"].as_str().is_some_and(|l| l.contains("cmd_consultar_placa"))), "rótulo event do adaptador");
        // validação: trace ok = equivalente; 403 = diverge, trace em pasta nova 0700
        let root = temp_session_dir("timeline-root");
        fs::remove_dir_all(&root).ok();
        fs::create_dir_all(&root).unwrap();
        let ok = validate_execution_blocking(&root, &capture, &sim_trace("trace-sim-ok.json"), None).unwrap();
        assert!(ok.validation.summary.starts_with("execução equivalente à captura"), "{}", ok.validation.summary);
        assert!(ok.validation.summary.contains("[origem mapeada:"));
        // trace fiel (plan.version 2): nenhum aviso de parâmetro ou de plano; só o de origem mapeada
        assert!(
            ok.validation.warnings.iter().all(|w| w.starts_with("origens de aplicação diferentes")),
            "a trace fiel não pode gerar avisos além do de origem mapeada: {:?}",
            ok.validation.warnings
        );
        assert!(
            !ok.validation.warnings.iter().any(|w| w.contains("parâmetro") || w.contains("plano")),
            "avisos espúrios de parâmetro/plano: {:?}",
            ok.validation.warnings
        );
        assert!(
            ok.validation.steps.iter().flat_map(|st| &st.expected).any(|n| n.reason.contains("parâmetro do usuário")),
            "placa/CPF informados viram esperado (parâmetro do usuário)"
        );
        let bad = validate_execution_blocking(&root, &capture, &sim_trace("trace-sim-403.json"), None).unwrap();
        assert!(bad.validation.summary.starts_with("diverge no passo 3"), "{}", bad.validation.summary);
        let down = validate_execution_blocking(&root, &capture, &sim_trace("trace-sim-incompleta.json"), None).unwrap();
        assert_eq!(serde_json::to_value(down.validation.verdict).unwrap(), "incomplete");
        assert!(down.validation.summary.starts_with("incompleta: parou no passo 1"), "{}", down.validation.summary);
        assert_ne!(ok.trace_dir, bad.trace_dir);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&bad.trace_dir).unwrap().permissions().mode() & 0o777, 0o700);
        // erros acionáveis
        let invalid = root.join("nao-e-trace.json");
        fs::write(&invalid, "{\"schema\":\"x\"}").unwrap();
        assert!(validate_execution_blocking(&root, &capture, invalid.to_str().unwrap(), None).unwrap_err().contains("trace inválido"));
        assert!(validate_execution_blocking(&root, &capture, &sim_trace("trace-sim-ok.json"), Some("sem-igual")).unwrap_err().contains("mapeamento de origem inválido"));
        assert!(validate_execution_blocking(&root, &capture, "/nao/existe.json", None).is_err());
        // trace acima de 64 MiB: erro acionável, sem ler nem criar sessão
        let huge = root.join("enorme.json");
        fs::File::create(&huge).unwrap().set_len(crate::validation::TRACE_MAX_BYTES + 1).unwrap();
        let before = fs::read_dir(&root).unwrap().count();
        let err = validate_execution_blocking(&root, &capture, huge.to_str().unwrap(), None).unwrap_err();
        assert!(err.contains("maior que 64 MiB"), "{err}");
        assert_eq!(fs::read_dir(&root).unwrap().count(), before);
        fs::remove_dir_all(capture).ok();
        fs::remove_dir_all(root).ok();
    }

    /// Dados reais da Rodada 9 para o harness de UI:
    /// `SL_SESSION=<pasta> SL_TRACES=<a.json,b.json> SL_DUMP=<dir> cargo test -- --ignored dump_round9_evidence`.
    #[test]
    #[ignore]
    fn dump_round9_evidence() {
        let dir = std::env::var("SL_SESSION").expect("SL_SESSION");
        let out = PathBuf::from(std::env::var("SL_DUMP").expect("SL_DUMP"));
        fs::create_dir_all(&out).unwrap();
        let t = tauri::async_runtime::block_on(session_timeline(dir.clone())).unwrap();
        fs::write(out.join("timeline.json"), serde_json::to_string(&t).unwrap()).unwrap();
        let root = out.join("traces");
        fs::create_dir_all(&root).unwrap();
        for (n, trace) in std::env::var("SL_TRACES").expect("SL_TRACES").split(',').enumerate() {
            let r = validate_execution_blocking(&root, Path::new(&dir), trace, None).unwrap();
            fs::write(out.join(format!("validate-{n}.json")), serde_json::to_string(&r).unwrap()).unwrap();
        }
    }

    /// Dados reais (adaptador Natural registrado) para o harness de UI:
    /// `SL_SESSION=<pasta> SL_DUMP=<dir> cargo test -- --ignored dump_adapter_evidence`.
    #[test]
    #[ignore]
    fn dump_adapter_evidence() {
        let dir = std::env::var("SL_SESSION").expect("SL_SESSION");
        let out = PathBuf::from(std::env::var("SL_DUMP").expect("SL_DUMP"));
        fs::create_dir_all(&out).unwrap();
        let lazy = cached_session(Path::new(&dir)).unwrap();
        let source = scrapelens_core::search::LazyBodies(&lazy);
        let opts = crate::adapters::flow_options();
        for request in &lazy.session.requests {
            let id = &request.id;
            let write = |name: &str, value: serde_json::Value| fs::write(out.join(format!("{id}.{name}.json")), serde_json::to_string(&value).unwrap()).unwrap();
            if let Ok(o) = scrapelens_core::flow::value_origins(&lazy.session, &source, id, &opts) { write("origins", serde_json::to_value(o).unwrap()); }
            if let Ok(c) = scrapelens_core::flow::priming_chain(&lazy.session, &source, id, &opts) { write("chain", serde_json::to_value(c).unwrap()); }
            for side in ["request", "response"] {
                if let Ok(v) = crate::adapters::view(&lazy, request, side) {
                    if !v.fields.is_empty() { write(side, serde_json::to_value(v).unwrap()); }
                }
            }
        }
        for id in ["har-0026"] {
            if let Ok(p) = priming_preview(Path::new(&dir), id, false) { fs::write(out.join(format!("{id}.priming.json")), serde_json::to_string(&p).unwrap()).unwrap(); }
        }
    }

    /// Prévia real da sanitização para o harness de UI:
    /// `SL_SESSION=<pasta> SL_DUMP=<arquivo.json> cargo test -- --ignored dump_sanitize_preview`.
    #[test]
    #[ignore]
    fn dump_sanitize_preview() {
        let dir = std::env::var("SL_SESSION").expect("SL_SESSION");
        let out = std::env::var("SL_DUMP").expect("SL_DUMP");
        let preview = crate::export::sanitize_preview(Path::new(&dir)).unwrap();
        fs::write(out, serde_json::to_string_pretty(&preview).unwrap()).unwrap();
    }
}
