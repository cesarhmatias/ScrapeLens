//! Captura ao vivo: Chrome externo com perfil dedicado + CDP + NetLog.
//!
//! Regras:
//! - perfil temporário próprio (nunca o perfil pessoal), removido no fim;
//! - depuração apenas em 127.0.0.1, porta efêmera;
//! - encerra somente o processo que este módulo iniciou;
//! - o NetLog é gravado no diretório da sessão e importado pelo core;
//! - nenhuma rede além da depuração local; nenhum certificado é instalado.
//!
//! Limitação conhecida: `--remote-allow-origins=*` é necessário para o
//! WebSocket do CDP; durante a captura, o endpoint em
//! `127.0.0.1:<porta efêmera>` aceita qualquer Origin. O risco fica limitado à
//! janela da captura e ao loopback, mas a sessão do Chrome inspecionado não deve
//! ser usada para navegar em páginas não confiáveis enquanto grava.

use std::collections::HashMap;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{json, Value};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{connect, Message, WebSocket};

use scrapelens_core::{correlate::CorrelationOptions, import_capture_labeled, store};

use crate::commands::SessionPayload;

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CaptureStatus {
    pub recording: bool,
    pub events: usize,
    pub chrome_pid: Option<u32>,
    pub session_id: String,
    pub session_dir: String,
    pub started_at: String,
    pub page_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

pub struct CaptureSession {
    pub id: String,
    pub dir: PathBuf,
    pub started_at: String,
    pub stop: Sender<()>,
    pub join: thread::JoinHandle<Result<SessionPayload, String>>,
    pub status: Arc<Mutex<CaptureStatus>>,
}

#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub chrome: PathBuf,
    pub session_dir: PathBuf,
    pub start_url: String,
    pub headless: bool,
    pub ignore_cert: bool,
}

pub fn run(
    config: CaptureConfig,
    status: Arc<Mutex<CaptureStatus>>,
    stop: Receiver<()>,
    ready: Sender<Result<(), String>>,
) -> Result<SessionPayload, String> {
    let outcome = run_inner(&config, &status, stop, &ready);
    if let Err(error) = &outcome {
        if let Ok(mut guard) = status.lock() {
            guard.last_error = Some(error.clone());
        }
    }
    if let Ok(mut guard) = status.lock() {
        guard.recording = false;
    }
    outcome
}

fn run_inner(
    config: &CaptureConfig,
    status: &Arc<Mutex<CaptureStatus>>,
    stop: Receiver<()>,
    ready: &Sender<Result<(), String>>,
) -> Result<SessionPayload, String> {
    let profile = std::env::temp_dir().join(format!(
        "scrapelens-chrome-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    std::fs::create_dir_all(&profile).map_err(|error| format!("perfil temporário: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o700));
    }

    store::ensure_private_dir(&config.session_dir)
        .map_err(|error| format!("diretório da sessão: {error}"))?;
    let netlog_path = config.session_dir.join("netlog.json");
    let cdp_path = config.session_dir.join("cdp-events.jsonl");
    let bodies_path = config.session_dir.join("cdp-bodies.jsonl");
    let bodies_file =
        open_private(&bodies_path).map_err(|error| format!("cdp-bodies.jsonl: {error}"))?;

    let mut chrome = ChromeProcess::new(spawn_chrome(config, &profile, &netlog_path)?);
    if let Ok(mut guard) = status.lock() {
        guard.chrome_pid = Some(chrome.child_mut().id());
        guard.page_url = config.start_url.clone();
    }

    let ws_url = match wait_for_devtools(chrome.child_mut(), &profile, Duration::from_secs(25)) {
        Ok(url) => url,
        Err(error) => {
            let _ = chrome.child_mut().kill();
            let _ = chrome.child_mut().wait();
            chrome.disarm();
            let _ = std::fs::remove_dir_all(&profile);
            let _ = ready.send(Err(error.clone()));
            return Err(error);
        }
    };

    let (mut socket, mut cdp) = match Cdp::connect(&ws_url, status.clone(), bodies_file) {
        Ok(pair) => pair,
        Err(error) => {
            let _ = chrome.child_mut().kill();
            let _ = chrome.child_mut().wait();
            chrome.disarm();
            let _ = std::fs::remove_dir_all(&profile);
            let _ = ready.send(Err(error.clone()));
            return Err(error);
        }
    };

    let setup = cdp.setup(&mut socket, &config.start_url);
    if let Err(error) = setup {
        let _ = chrome.child_mut().kill();
        let _ = chrome.child_mut().wait();
        chrome.disarm();
        let _ = std::fs::remove_dir_all(&profile);
        let _ = ready.send(Err(error.clone()));
        return Err(error);
    }
    let _ = ready.send(Ok(()));

    // Loop de gravação: todo evento Network.* é preservado na ordem do Chrome.
    let started = Instant::now();
    let mut flushed_pending = false;
    loop {
        if !flushed_pending {
            cdp.flush_pending_setups(&mut socket);
            flushed_pending = true;
        }
        if !cdp.pending_setup.is_empty() {
            cdp.flush_pending_setups(&mut socket);
        }
        if matches!(stop.try_recv(), Ok(()) | Err(TryRecvError::Disconnected)) {
            break;
        }
        if started.elapsed() > Duration::from_secs(30 * 60) {
            break;
        }
        match socket.read() {
            Ok(Message::Text(text)) => {
                if let Ok(value) = serde_json::from_str::<Value>(text.as_str()) {
                    cdp.record(&mut socket, &value);
                    cdp.flush_outbox(&mut socket);
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(Message::Ping(payload)) => {
                let _ = socket.send(Message::Pong(payload));
            }
            Ok(_) => {}
            Err(tungstenite::Error::Io(error))
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
    }

    // Dá uma janela curta para os getResponseBody/getRequestPostData em voo
    // voltarem antes de fechar; o que não voltar vira linha `unavailable`.
    cdp.drain_bodies(&mut socket, Duration::from_secs(3));
    cdp.finish_bodies();

    // Encerra o Chrome de forma graciosa para o NetLog ser finalizado.
    let close_started = Instant::now();
    let close_result = cdp.send(
        &mut socket,
        "Browser.close",
        json!({}),
        None,
        Duration::from_secs(2),
    );
    let _ = socket.close(None);
    let exit = wait_or_kill(chrome.child_mut(), Duration::from_secs(20));
    chrome.disarm();
    let shutdown = ShutdownReport {
        browser_close: close_result.map(|_| ()),
        exit,
        waited_ms: close_started.elapsed().as_millis() as u64,
    };
    eprintln!("capture shutdown: {shutdown:?}");
    let _ = std::fs::remove_dir_all(&profile);

    let cdp_bytes = cdp.events_text().into_bytes();
    if cdp_bytes.is_empty() {
        let _ = std::fs::write(&cdp_path, &cdp_bytes);
        let error = "Nenhum evento CDP foi gravado. A sessão não foi criada; verifique se o Chrome permaneceu aberto durante a captura.".to_string();
        let _ = ready.send(Err(error.clone()));
        return Err(error);
    }
    // O CDP e os corpos já são evidência: ficam em disco antes de qualquer
    // passo que possa falhar (um NetLog ruim nunca descarta a captura).
    write_private(&cdp_path, &cdp_bytes).map_err(|error| format!("cdp-events.jsonl: {error}"))?;

    let netlog_raw = std::fs::read(&netlog_path)
        .ok()
        .filter(|bytes| !bytes.is_empty());
    let (netlog, netlog_status) = prepare_netlog(netlog_raw.as_deref());
    if let NetlogStatus::Repaired { .. } | NetlogStatus::Unusable { .. } = &netlog_status {
        // Preserva o arquivo original do Chrome ao lado da sessão.
        if let Some(raw) = &netlog_raw {
            let _ = write_private(&config.session_dir.join("netlog.original.json"), raw);
        }
    }

    // Sem o arquivo de corpos (falha de gravação), o core avisa uma vez por sessão.
    let bodies_bytes = std::fs::read(&bodies_path).ok();
    let mut imported = import_capture_labeled(
        &cdp_bytes,
        &netlog,
        bodies_bytes.as_deref(),
        &["live-capture".to_string()],
        CorrelationOptions::default(),
    )
    .map_err(|error| format!("O core não conseguiu importar a captura: {error}"))?;
    mark_incomplete(&mut imported.bundle.session, &netlog_status, &shutdown);
    // Metadados da captura são do pipeline, não do parser: o core monta o
    // documento a partir do CDP e não sabe que este fluxo também gravou NetLog.
    match imported.bundle.session.session.capture.as_mut() {
        Some(capture) => {
            capture.mode = Some("cdp+netlog".to_string());
            capture.headless = Some(config.headless);
            capture.browser_binary = Some(config.chrome.display().to_string());
        }
        None => {
            imported.bundle.session.session.capture = Some(scrapelens_core::model::CaptureMeta {
                mode: Some("cdp+netlog".to_string()),
                browser_binary: Some(config.chrome.display().to_string()),
                headless: Some(config.headless),
                ..scrapelens_core::model::CaptureMeta::default()
            });
        }
    }
    store::write_session_dir(&imported.bundle, &config.session_dir)
        .map_err(|error| format!("Não foi possível gravar a sessão: {error}"))?;

    let session_value = serde_json::to_value(&imported.bundle.session)
        .map_err(|error| format!("Sessão inválida após importação: {error}"))?;
    let requests = imported.report.source_events_used;
    let warnings = imported.report.warnings.len();

    Ok(SessionPayload {
        session: session_value,
        session_dir: Some(config.session_dir.display().to_string()),
        synthetic: false,
        notice: Some(format!(
            "Sessão capturada e importada: {} evento(s) CDP+NetLog usados, {} aviso(s).",
            requests, warnings
        )),
        pending: false,
    })
}

fn spawn_chrome(config: &CaptureConfig, profile: &Path, netlog: &Path) -> Result<Child, String> {
    let mut args: Vec<String> = vec![
        format!("--user-data-dir={}", profile.display()),
        "--remote-debugging-port=0".to_string(),
        "--remote-debugging-address=127.0.0.1".to_string(),
        "--remote-allow-origins=*".to_string(),
        format!("--log-net-log={}", netlog.display()),
        "--net-log-capture-mode=Everything".to_string(),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--disable-background-networking".to_string(),
        "--disable-component-update".to_string(),
        "--disable-sync".to_string(),
        "--disable-default-apps".to_string(),
        "--disable-extensions".to_string(),
        "--metrics-recording-only".to_string(),
        "--no-service-autorun".to_string(),
        "--no-pings".to_string(),
        "--disable-breakpad".to_string(),
        "--disable-domain-reliability".to_string(),
        "--disable-client-side-phishing-detection".to_string(),
        "--disable-component-extensions-with-background-pages".to_string(),
        "--password-store=basic".to_string(),
        "--use-mock-keychain".to_string(),
        "--disable-search-engine-choice-screen".to_string(),
        "--disable-features=Translate,MediaRouter,OptimizationHints,InterestFeedContentSuggestions"
            .to_string(),
        "--enable-quic".to_string(),
        "--allow-insecure-localhost".to_string(),
        "--disable-popup-blocking".to_string(),
        "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost"
            .to_string(),
        "about:blank".to_string(),
    ];
    if config.headless {
        args.push("--headless=new".to_string());
    }
    if config.ignore_cert {
        args.push("--ignore-certificate-errors".to_string());
    }
    Command::new(&config.chrome)
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .map_err(|error| {
            format!(
                "Não foi possível abrir o Chrome em {}: {error}. Selecione o Chrome manualmente.",
                config.chrome.display()
            )
        })
}

fn wait_for_devtools(
    child: &mut Child,
    profile: &Path,
    timeout: Duration,
) -> Result<String, String> {
    let port_file = profile.join("DevToolsActivePort");
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(status) = child.try_wait() {
            if status.is_some() {
                return Err(
                    "O Chrome encerrou antes de abrir a depuração. Verifique se há outra instância usando o perfil ou selecione outro Chrome.".to_string(),
                );
            }
        }
        if let Ok(text) = std::fs::read_to_string(&port_file) {
            let mut lines = text.lines();
            if let (Some(port), Some(path)) = (lines.next(), lines.next()) {
                let path = if path.starts_with('/') {
                    path.to_string()
                } else {
                    format!("/{path}")
                };
                return Ok(format!("ws://127.0.0.1:{port}{path}"));
            }
        }
        thread::sleep(Duration::from_millis(120));
    }
    Err(
        "O Chrome não expôs a depuração em 25 s (DevToolsActivePort ausente). Nada foi capturado."
            .to_string(),
    )
}

#[derive(Debug, Clone)]
enum ChromeExit {
    /// O processo saiu sozinho depois de `Browser.close`.
    Graceful(#[allow(dead_code)] Option<i32>),
    /// Estourou o prazo e foi morto por este módulo (NetLog pode ficar truncado).
    Killed,
    Unknown,
}

#[derive(Debug, Clone)]
struct ShutdownReport {
    browser_close: Result<(), String>,
    exit: ChromeExit,
    waited_ms: u64,
}

/// Rede de segurança: só mata o Chrome se `run_inner` sair sem `disarm` (erro/panic).
struct ChromeProcess(Option<Child>);

impl ChromeProcess {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    fn child_mut(&mut self) -> &mut Child {
        self.0
            .as_mut()
            .expect("ChromeProcess já liberado após encerramento gracioso")
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ChromeProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn wait_or_kill(child: &mut Child, timeout: Duration) -> ChromeExit {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return ChromeExit::Graceful(status.code()),
            Ok(None) => {}
            Err(_) => return ChromeExit::Unknown,
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return ChromeExit::Killed;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

const CDP_TARGET_METHODS: &[&str] = &[
    "Target.attachedToTarget",
    "Target.detachedFromTarget",
    "Target.targetInfoChanged",
    "Target.attachFailed",
    "Capture.sessionSetup",
    "Capture.targetSetupTimeout",
];

/// Código de aviso importado pelo core (`cdp.target_setup_timeout`).
const CDP_TARGET_SETUP_TIMEOUT_WARNING: &str = "cdp.target_setup_timeout";

fn cdp_records_method(method: &str) -> bool {
    method.starts_with("Network.") || CDP_TARGET_METHODS.contains(&method)
}

#[derive(Debug, Clone)]
struct AttachedTarget {
    session_id: String,
    target_id: String,
    target_type: String,
}

struct Cdp {
    next_id: u64,
    page_session_id: String,
    events: Vec<String>,
    status: Arc<Mutex<CaptureStatus>>,
    bodies_by_session: HashMap<String, BodyCollector>,
    bodies_file: std::fs::File,
    in_flight: HashMap<u64, (String, BodyTag)>,
    outbox: Vec<(String, String)>,
    setup_done: HashMap<String, AttachedTarget>,
    /// Sessões que já passaram por `setup_attached_target` (distinto de visto em setup_phase).
    configured_sessions: std::collections::HashSet<String>,
    configured_target_primary: HashMap<String, String>,
    detached_sessions: std::collections::HashSet<String>,
    setup_in_progress: std::collections::HashSet<String>,
    wait_for_debugger: bool,
    /// Durante `setup()`, só grava Target.*; evita setup aninhado que bloqueia respostas CDP.
    setup_phase: bool,
    pending_setup: Vec<(AttachedTarget, bool)>,
    /// Alvos vistos via auto-attach durante `setup_phase` (antes de configurar).
    setup_seen: HashMap<String, AttachedTarget>,
    /// Profundidade de `send()` aguardando resposta (evita setup aninhado).
    command_depth: u32,
}

impl Cdp {
    fn connect(
        url: &str,
        status: Arc<Mutex<CaptureStatus>>,
        bodies_file: std::fs::File,
    ) -> Result<(WebSocket<MaybeTlsStream<std::net::TcpStream>>, Self), String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut last_error = String::new();
        while Instant::now() < deadline {
            match connect(url) {
                Ok((socket, _response)) => {
                    if let MaybeTlsStream::Plain(stream) = socket.get_ref() {
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
                    }
                    return Ok((
                        socket,
                        Self {
                            next_id: 0,
                            page_session_id: String::new(),
                            events: Vec::new(),
                            status,
                            bodies_by_session: HashMap::new(),
                            bodies_file: match bodies_file.try_clone() {
                                Ok(file) => file,
                                Err(error) => return Err(format!("cdp-bodies.jsonl: {error}")),
                            },
                            in_flight: HashMap::new(),
                            outbox: Vec::new(),
                            setup_done: HashMap::new(),
                            configured_sessions: std::collections::HashSet::new(),
                            configured_target_primary: HashMap::new(),
                            detached_sessions: std::collections::HashSet::new(),
                            setup_in_progress: std::collections::HashSet::new(),
                            wait_for_debugger: true,
                            setup_phase: false,
                            pending_setup: Vec::new(),
                            setup_seen: HashMap::new(),
                            command_depth: 0,
                        },
                    ));
                }
                Err(error) => {
                    last_error = error.to_string();
                    thread::sleep(Duration::from_millis(120));
                }
            }
        }
        Err(format!(
            "Não foi possível conectar ao CDP local: {last_error}"
        ))
    }

    fn auto_attach_params(&self, wait_on_start: bool) -> Value {
        json!({
            "autoAttach": true,
            "flatten": true,
            "waitForDebuggerOnStart": wait_on_start && self.wait_for_debugger,
        })
    }

    fn wire_command(
        &mut self,
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
        method: &str,
        params: Value,
        session: Option<&str>,
    ) -> Result<u64, String> {
        let id = self.next_id;
        self.next_id += 1;
        let mut message = json!({ "id": id, "method": method, "params": params });
        if let Some(session) = session {
            message["sessionId"] = json!(session);
        }
        socket
            .send(Message::Text(message.to_string().into()))
            .map_err(|error| format!("CDP send {method}: {error}"))?;
        Ok(id)
    }

    fn wait_for_wired_commands(
        &mut self,
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
        wired: &[(u64, &str)],
        timeout: Duration,
    ) -> Result<(), String> {
        if wired.is_empty() {
            return Ok(());
        }
        self.command_depth += 1;
        let pipeline_result = self.wait_for_wired_commands_inner(socket, wired, timeout);
        self.command_depth = self.command_depth.saturating_sub(1);
        if pipeline_result.is_ok() {
            self.flush_pending_setups(socket);
        }
        pipeline_result
    }

    fn wait_for_wired_commands_inner(
        &mut self,
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
        wired: &[(u64, &str)],
        timeout: Duration,
    ) -> Result<(), String> {
        let id_to_method: HashMap<u64, &str> = wired.iter().copied().collect();
        let mut pending: std::collections::HashSet<u64> = id_to_method.keys().copied().collect();
        let deadline = Instant::now() + timeout;
        while !pending.is_empty() {
            if Instant::now() >= deadline {
                let stuck = wired
                    .iter()
                    .find(|(id, _)| pending.contains(id))
                    .map(|(_, method)| *method)
                    .unwrap_or("?");
                return Err(format!("CDP timeout aguardando {stuck} (pipeline)"));
            }
            match socket.read() {
                Ok(Message::Text(text)) => {
                    let value: Value = serde_json::from_str(text.as_str())
                        .map_err(|error| format!("CDP JSON inválido: {error}"))?;
                    if let Some(id) = value.get("id").and_then(Value::as_u64) {
                        if pending.remove(&id) {
                            if value.get("error").is_some() {
                                return Err(format!(
                                    "CDP erro na pipeline (id {id}): {}",
                                    value.get("error").unwrap_or(&Value::Null)
                                ));
                            }
                            continue;
                        }
                    }
                    self.record(socket, &value);
                    self.flush_outbox(socket);
                }
                Ok(Message::Ping(payload)) => {
                    let _ = socket.send(Message::Pong(payload));
                }
                Ok(Message::Close(_)) => {
                    return Err("CDP fechou durante pipeline de setup".to_string());
                }
                Ok(_) => {}
                Err(tungstenite::Error::Io(error))
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(error) => return Err(format!("CDP read pipeline: {error}")),
            }
        }
        Ok(())
    }

    fn pump_socket(
        &mut self,
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
        window: Duration,
    ) {
        let deadline = Instant::now() + window;
        while Instant::now() < deadline {
            match socket.read() {
                Ok(Message::Text(text)) => {
                    if let Ok(value) = serde_json::from_str::<Value>(text.as_str()) {
                        self.record(socket, &value);
                        self.flush_outbox(socket);
                    }
                }
                Ok(Message::Ping(payload)) => {
                    let _ = socket.send(Message::Pong(payload));
                }
                Ok(Message::Close(_)) | Ok(_) => break,
                Err(tungstenite::Error::Io(error))
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(_) => break,
            }
        }
    }

    fn bodies_for(&mut self, session_id: &str) -> &mut BodyCollector {
        self.bodies_by_session
            .entry(session_id.to_string())
            .or_default()
    }

    fn command_from_setup_error(error: &str) -> String {
        if let Some(rest) = error.strip_prefix("CDP timeout aguardando ") {
            if let Some(method) = rest.strip_suffix(" (pipeline)") {
                return method.to_string();
            }
            return rest.to_string();
        }
        if let Some(rest) = error.strip_prefix("CDP send ") {
            if let Some((method, _)) = rest.split_once(':') {
                return method.to_string();
            }
        }
        if let Some(rest) = error.strip_prefix("CDP ") {
            if let Some((method, _)) = rest.split_once(':') {
                return method.to_string();
            }
        }
        error.to_string()
    }

    fn drop_recorded_network_for_session(&mut self, session_id: &str) {
        self.events.retain(|line| {
            let Ok(value) = serde_json::from_str::<Value>(line) else {
                return true;
            };
            if value.get("sessionId").and_then(Value::as_str) != Some(session_id) {
                return true;
            }
            !value
                .get("method")
                .and_then(Value::as_str)
                .is_some_and(|method| method.starts_with("Network."))
        });
    }

    fn push_target_setup_timeout(
        &mut self,
        attached: &AttachedTarget,
        error: String,
        parent_session_id: Option<&str>,
    ) {
        self.detached_sessions.insert(attached.session_id.clone());
        self.setup_in_progress.remove(&attached.session_id);
        self.drop_recorded_network_for_session(&attached.session_id);
        if self.configured_target_primary.get(&attached.target_id) == Some(&attached.session_id)
            && !self.configured_sessions.contains(&attached.session_id)
        {
            self.configured_target_primary.remove(&attached.target_id);
        }
        let command = Self::command_from_setup_error(&error);
        self.push_event_line(
            &attached.session_id,
            "Capture.targetSetupTimeout",
            &json!({
                "targetId": attached.target_id,
                "sessionId": attached.session_id,
                "command": command,
                "error": error,
                "warningCode": CDP_TARGET_SETUP_TIMEOUT_WARNING,
            }),
            parent_session_id,
        );
    }

    fn push_event_line(
        &mut self,
        session_id: &str,
        method: &str,
        params: &Value,
        parent_session_id: Option<&str>,
    ) {
        let mut line = json!({
            "sessionId": session_id,
            "method": method,
            "params": params,
        });
        if let Some(parent) = parent_session_id.filter(|p| !p.is_empty() && *p != session_id) {
            line["parentSessionId"] = json!(parent);
        }
        self.events.push(line.to_string());
        if let Ok(mut guard) = self.status.lock() {
            guard.events = self.events.len();
        }
    }

    fn skip_target_setup(target_type: &str) -> bool {
        matches!(target_type, "browser_ui" | "other")
    }

    fn recurse_auto_attach(target_type: &str) -> bool {
        matches!(
            target_type,
            "page" | "iframe" | "worker" | "service_worker"
        )
    }

    fn setup_duplicate_target_session(
        &mut self,
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
        attached: AttachedTarget,
        waiting_for_debugger: bool,
        parent_session_id: Option<&str>,
    ) -> Result<(), String> {
        if self.wait_for_debugger && waiting_for_debugger {
            let _ = self.send(
                socket,
                "Runtime.runIfWaitingForDebugger",
                json!({}),
                Some(&attached.session_id),
                Duration::from_secs(5),
            );
        }
        let _ = self.send(
            socket,
            "Target.detachFromTarget",
            json!({ "sessionId": attached.session_id }),
            None,
            Duration::from_secs(5),
        );
        self.detached_sessions.insert(attached.session_id.clone());
        self.configured_sessions
            .insert(attached.session_id.clone());
        self.push_event_line(
            &attached.session_id,
            "Capture.sessionSetup",
            &json!({
                "targetId": attached.target_id,
                "type": attached.target_type,
                "waitingForDebugger": waiting_for_debugger,
                "duplicateSession": true,
                "detached": true,
            }),
            parent_session_id,
        );
        Ok(())
    }

    fn setup_attached_target(
        &mut self,
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
        attached: AttachedTarget,
        waiting_for_debugger: bool,
        parent_session_id: Option<&str>,
    ) -> Result<(), String> {
        if self.configured_target_primary.get(&attached.target_id).is_some_and(|primary| {
            primary != &attached.session_id
        }) {
            return self.setup_duplicate_target_session(
                socket,
                attached,
                waiting_for_debugger,
                parent_session_id,
            );
        }
        if self.configured_sessions.contains(&attached.session_id) {
            if self.wait_for_debugger && waiting_for_debugger {
                let _ = self.send(
                    socket,
                    "Runtime.runIfWaitingForDebugger",
                    json!({}),
                    Some(&attached.session_id),
                    Duration::from_secs(5),
                );
            }
            return Ok(());
        }
        self.setup_in_progress
            .insert(attached.session_id.clone());
        self.setup_seen
            .insert(attached.session_id.clone(), attached.clone());
        let target_type = attached.target_type.clone();
        let mut resumed = false;
        if Self::skip_target_setup(&target_type) {
            if self.wait_for_debugger && waiting_for_debugger {
                let _ = self.send(
                    socket,
                    "Runtime.runIfWaitingForDebugger",
                    json!({}),
                    Some(&attached.session_id),
                    Duration::from_secs(5),
                );
                resumed = true;
            }
            self.setup_done
                .insert(attached.session_id.clone(), attached.clone());
            self.configured_sessions
                .insert(attached.session_id.clone());
            self.setup_in_progress.remove(&attached.session_id);
            self.push_event_line(
                &attached.session_id,
                "Capture.sessionSetup",
                &json!({
                    "targetId": attached.target_id,
                    "type": target_type,
                    "waitingForDebugger": waiting_for_debugger,
                    "resumedDebugger": resumed,
                    "skippedNetwork": true,
                }),
                parent_session_id,
            );
            return Ok(());
        }
        let sid = attached.session_id.as_str();
        let network_params = json!({
            "maxTotalBufferSize": 100_000_000,
            "maxResourceBufferSize": 50_000_000,
            "maxPostDataSize": MAX_BODY_BYTES
        });
        let pipelined = self.wait_for_debugger && waiting_for_debugger;
        if pipelined {
            let mut wired: Vec<(u64, &str)> = Vec::new();
            wired.push((
                self.wire_command(
                    socket,
                    "Network.enable",
                    network_params.clone(),
                    Some(sid),
                )?,
                "Network.enable",
            ));
            if target_type == "page" || target_type == "iframe" {
                wired.push((
                    self.wire_command(socket, "Page.enable", json!({}), Some(sid))?,
                    "Page.enable",
                ));
            }
            wired.push((
                self.wire_command(socket, "Runtime.enable", json!({}), Some(sid))?,
                "Runtime.enable",
            ));
            if Self::recurse_auto_attach(&target_type) {
                wired.push((
                    self.wire_command(
                        socket,
                        "Target.setAutoAttach",
                        self.auto_attach_params(true),
                        Some(sid),
                    )?,
                    "Target.setAutoAttach",
                ));
            }
            wired.push((
                self.wire_command(
                    socket,
                    "Runtime.runIfWaitingForDebugger",
                    json!({}),
                    Some(sid),
                )?,
                "Runtime.runIfWaitingForDebugger",
            ));
            self.wait_for_wired_commands(socket, &wired, Duration::from_secs(20))?;
            resumed = true;
        } else {
            if Self::recurse_auto_attach(&target_type) {
                self.send(
                    socket,
                    "Target.setAutoAttach",
                    self.auto_attach_params(true),
                    Some(sid),
                    Duration::from_secs(15),
                )?;
            }
            self.send(
                socket,
                "Network.enable",
                network_params,
                Some(sid),
                Duration::from_secs(10),
            )?;
            if target_type == "page" || target_type == "iframe" {
                let _ = self.send(
                    socket,
                    "Page.enable",
                    json!({}),
                    Some(sid),
                    Duration::from_secs(5),
                );
            }
            let _ = self.send(
                socket,
                "Runtime.enable",
                json!({}),
                Some(sid),
                Duration::from_secs(5),
            );
        }
        self.setup_done
            .insert(attached.session_id.clone(), attached.clone());
        self.configured_sessions
            .insert(attached.session_id.clone());
        self.setup_in_progress.remove(&attached.session_id);
        self.push_event_line(
            &attached.session_id,
            "Capture.sessionSetup",
            &json!({
                "targetId": attached.target_id,
                "type": target_type,
                "waitingForDebugger": waiting_for_debugger,
                "resumedDebugger": resumed,
                "pipelinedSetup": pipelined,
                "recursiveAutoAttach": Self::recurse_auto_attach(&target_type),
            }),
            parent_session_id,
        );
        Ok(())
    }

    fn session_for_recorded_event(
        &self,
        method: &str,
        wire: &Value,
        params: &Value,
    ) -> String {
        if method == "Target.attachedToTarget" {
            return params
                .get("sessionId")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
        }
        if method == "Target.targetInfoChanged" {
            if let Some(target_id) = params
                .get("targetInfo")
                .and_then(|info| info.get("targetId"))
                .and_then(Value::as_str)
            {
                for attached in self.setup_done.values().chain(self.setup_seen.values()) {
                    if attached.target_id == target_id {
                        return attached.session_id.clone();
                    }
                }
            }
        }
        wire
            .get("sessionId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    }

    fn handle_incoming_event(
        &mut self,
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
        value: &Value,
    ) {
        let Some(method) = value.get("method").and_then(Value::as_str) else {
            return;
        };
        if method == "Target.attachedToTarget" {
            if let Some(params) = value.get("params").and_then(Value::as_object) {
                let session_id = params
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let target = params.get("targetInfo").and_then(Value::as_object);
                let target_id = target
                    .and_then(|t| t.get("targetId"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let target_type = target
                    .and_then(|t| t.get("type"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                let waiting = params
                    .get("waitingForDebugger")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let attached = AttachedTarget {
                    session_id: session_id.clone(),
                    target_id: target_id.clone(),
                    target_type: target_type.clone(),
                };
                let parent_wire = value.get("sessionId").and_then(Value::as_str);
                if !Self::skip_target_setup(&target_type)
                    && !self.configured_target_primary.contains_key(&target_id)
                {
                    self.configured_target_primary.insert(
                        target_id.clone(),
                        session_id.clone(),
                    );
                }
                let duplicate = self.configured_target_primary.get(&target_id).is_some_and(
                    |primary| primary != &session_id,
                );
                if duplicate {
                    let _ = self.setup_duplicate_target_session(
                        socket,
                        attached.clone(),
                        waiting,
                        parent_wire,
                    );
                } else if self.setup_phase {
                    self.setup_seen
                        .insert(session_id.clone(), attached.clone());
                    if self.command_depth == 0 {
                        if let Err(error) = self.setup_attached_target(
                            socket,
                            attached.clone(),
                            waiting,
                            parent_wire,
                        ) {
                            self.push_target_setup_timeout(&attached, error, parent_wire);
                        }
                    } else {
                        self.pending_setup.push((attached, waiting));
                    }
                } else if !duplicate {
                    if let Err(error) = self.setup_attached_target(
                        socket,
                        attached.clone(),
                        waiting,
                        parent_wire,
                    ) {
                        self.push_target_setup_timeout(&attached, error, parent_wire);
                    }
                }
            }
        }
        if !cdp_records_method(method) {
            return;
        }
        let params = value.get("params").cloned().unwrap_or(Value::Null);
        let session_id = self.session_for_recorded_event(method, value, &params);
        if method.starts_with("Network.") && self.detached_sessions.contains(&session_id) {
            return;
        }
        let parent_session_id = if method == "Target.attachedToTarget" {
            value.get("sessionId").and_then(Value::as_str)
        } else {
            None
        };
        self.push_event_line(&session_id, method, &params, parent_session_id);
        if method.starts_with("Network.") {
            for command in self.bodies_for(&session_id).on_event(method, &params) {
                let id = self.next_id;
                self.next_id += 1;
                let message =
                    json!({ "id": id, "method": command.method, "params": command.params });
                self.in_flight
                    .insert(id, (session_id.clone(), command.tag));
                self.outbox
                    .push((session_id.clone(), message.to_string()));
            }
            self.write_body_lines();
        }
    }

    fn flush_pending_setups(
        &mut self,
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
    ) {
        for _ in 0..32 {
            let batch = std::mem::take(&mut self.pending_setup);
            if batch.is_empty() {
                break;
            }
            for (attached, waiting) in batch {
                if let Err(error) =
                    self.setup_attached_target(socket, attached.clone(), waiting, None)
                {
                    self.push_target_setup_timeout(&attached, error, None);
                }
            }
        }
    }

    fn setup(
        &mut self,
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
        start_url: &str,
    ) -> Result<(), String> {
        self.setup_phase = true;
        let setup_result = self.setup_inner(socket, start_url);
        self.setup_phase = false;
        if setup_result.is_ok() {
            self.pump_socket(socket, Duration::from_millis(400));
        }
        setup_result
    }

    /// Receita `cdp_multi_capture.mjs` (da972ef): auto-attach na raiz, fila de
    /// setup por sessão, `setAutoAttach` recursivo na página antes de navegar.
    fn setup_inner(
        &mut self,
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
        start_url: &str,
    ) -> Result<(), String> {
        self.send(
            socket,
            "Target.setDiscoverTargets",
            json!({ "discover": true }),
            None,
            Duration::from_secs(10),
        )?;
        self.send(
            socket,
            "Target.setAutoAttach",
            self.auto_attach_params(true),
            None,
            Duration::from_secs(25),
        )?;
        self.flush_pending_setups(socket);
        let url = if start_url.trim().is_empty() {
            "about:blank".to_string()
        } else {
            start_url.to_string()
        };
        let created = self.send(
            socket,
            "Target.createTarget",
            json!({ "url": "about:blank" }),
            None,
            Duration::from_secs(15),
        )?;
        let main_target = created
            .get("targetId")
            .and_then(Value::as_str)
            .ok_or_else(|| "CDP não devolveu targetId".to_string())?
            .to_string();
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            self.flush_pending_setups(socket);
            if let Some(page_session) = self
                .setup_seen
                .values()
                .find(|t| t.target_id == main_target && t.target_type == "page")
                .map(|t| t.session_id.clone())
            {
                self.page_session_id = page_session.clone();
                if !self.configured_sessions.contains(&page_session) {
                    let main_waiting = self
                        .pending_setup
                        .iter()
                        .find(|(t, _)| t.session_id == page_session)
                        .map(|(_, w)| *w)
                        .unwrap_or(false);
                    self.pending_setup
                        .retain(|(t, _)| t.session_id != page_session);
                    self.setup_attached_target(
                        socket,
                        AttachedTarget {
                            session_id: page_session.clone(),
                            target_id: main_target.clone(),
                            target_type: "page".to_string(),
                        },
                        main_waiting,
                        None,
                    )?;
                }
                self.send(
                    socket,
                    "Target.setAutoAttach",
                    self.auto_attach_params(true),
                    Some(&page_session),
                    Duration::from_secs(15),
                )?;
                self.send(
                    socket,
                    "Network.setCacheDisabled",
                    json!({ "cacheDisabled": true }),
                    Some(&page_session),
                    Duration::from_secs(5),
                )?;
                if url != "about:blank" {
                    self.send(
                        socket,
                        "Page.navigate",
                        json!({ "url": url }),
                        Some(&page_session),
                        Duration::from_secs(30),
                    )?;
                }
                break;
            }
            self.pump_socket(socket, Duration::from_millis(100));
        }
        if self.page_session_id.is_empty() {
            return Err(
                "A página inicial não anexou após createTarget (Target.attachedToTarget)"
                    .to_string(),
            );
        }
        let settle = Instant::now() + Duration::from_secs(5);
        while Instant::now() < settle {
            self.flush_pending_setups(socket);
            self.pump_socket(socket, Duration::from_millis(100));
        }
        Ok(())
    }

    fn send(
        &mut self,
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
        method: &str,
        params: Value,
        session: Option<&str>,
        timeout: Duration,
    ) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let mut message = json!({ "id": id, "method": method, "params": params });
        if let Some(session) = session {
            message["sessionId"] = json!(session);
        }
        socket
            .send(Message::Text(message.to_string().into()))
            .map_err(|error| format!("CDP send {method}: {error}"))?;
        self.command_depth += 1;
        let setup_result = (|| {
        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() >= deadline {
                return Err(format!("CDP timeout aguardando {method}"));
            }
            match socket.read() {
                Ok(Message::Text(text)) => {
                    let value: Value = serde_json::from_str(text.as_str())
                        .map_err(|error| format!("CDP JSON inválido: {error}"))?;
                    if value.get("id").and_then(Value::as_u64) == Some(id) {
                        if let Some(error) = value.get("error") {
                            return Err(format!("CDP {method}: {error}"));
                        }
                        return Ok(value.get("result").cloned().unwrap_or(Value::Null));
                    }
                    self.record(socket, &value);
                    self.flush_outbox(socket);
                }
                Ok(Message::Ping(payload)) => {
                    let _ = socket.send(Message::Pong(payload));
                }
                Ok(Message::Close(_)) => return Err(format!("CDP fechou durante {method}")),
                Ok(_) => {}
                Err(tungstenite::Error::Io(error))
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(error) => return Err(format!("CDP read {method}: {error}")),
            }
        }
        })();
        if setup_result.is_ok() && self.setup_phase {
            self.flush_pending_setups(socket);
        }
        self.command_depth = self.command_depth.saturating_sub(1);
        setup_result
    }

    fn record(
        &mut self,
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
        value: &Value,
    ) {
        if let Some(id) = value.get("id").and_then(Value::as_u64) {
            if let Some((session_id, tag)) = self.in_flight.remove(&id) {
                let outcome = match value.get("error") {
                    Some(error) => Err(error
                        .get("message")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .unwrap_or_else(|| error.to_string())),
                    None => Ok(value.get("result").cloned().unwrap_or(Value::Null)),
                };
                self.bodies_for(&session_id).on_result(tag, outcome);
                self.write_body_lines();
            }
            return;
        }
        self.handle_incoming_event(socket, value);
    }

    /// Envia sem esperar resposta os comandos de corpo enfileirados por
    /// `record`. Falha de envio vira `unavailable` na hora.
    fn flush_outbox(&mut self, socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>) {
        for (session_id, message) in std::mem::take(&mut self.outbox) {
            let id = serde_json::from_str::<Value>(&message)
                .ok()
                .and_then(|value| value.get("id").and_then(Value::as_u64));
            let mut payload: Value = serde_json::from_str(&message).unwrap_or(Value::Null);
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("sessionId".to_string(), json!(session_id));
            }
            let wire = payload.to_string();
            if let Err(error) = socket.send(Message::Text(wire.into())) {
                if let Some(id) = id {
                    if let Some((sid, tag)) = self.in_flight.remove(&id) {
                        self.bodies_for(&sid).on_result(
                            tag,
                            Err(format!("falha ao enviar comando ao CDP: {error}")),
                        );
                    }
                }
            }
        }
        self.write_body_lines();
    }

    /// Aguarda (até `window`) as respostas de corpo em voo.
    fn drain_bodies(
        &mut self,
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
        window: Duration,
    ) {
        let deadline = Instant::now() + window;
        while !self.in_flight.is_empty() && Instant::now() < deadline {
            match socket.read() {
                Ok(Message::Text(text)) => {
                    if let Ok(value) = serde_json::from_str::<Value>(text.as_str()) {
                        self.record(socket, &value);
                        self.flush_outbox(socket);
                    }
                }
                Ok(Message::Ping(payload)) => {
                    let _ = socket.send(Message::Pong(payload));
                }
                Ok(Message::Close(_)) => break,
                Ok(_) => {}
                Err(tungstenite::Error::Io(error))
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(_) => break,
            }
        }
    }

    /// Fecha a coleta: nada fica sem linha.
    fn finish_bodies(&mut self) {
        let leftover: Vec<(String, BodyTag)> =
            self.in_flight.drain().map(|(_, pair)| pair).collect();
        for (session_id, tag) in leftover {
            self.bodies_for(&session_id).on_result(
                tag,
                Err("captura encerrada antes de o CDP responder ao comando de corpo".to_string()),
            );
        }
        for collector in self.bodies_by_session.values_mut() {
            collector.finish();
        }
        self.write_body_lines();
        let _ = self.bodies_file.sync_all();
    }

    fn write_body_lines(&mut self) {
        for (session_id, collector) in &mut self.bodies_by_session {
            for line in collector.take_lines() {
                let mut value: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
                if let Some(map) = value.as_object_mut() {
                    map.insert("sessionId".to_string(), json!(session_id));
                }
                let out = format!("{}\n", value);
                let result = self
                    .bodies_file
                    .write_all(out.as_bytes());
                if let Err(error) = result {
                    if let Ok(mut guard) = self.status.lock() {
                        guard.last_error = Some(format!("cdp-bodies.jsonl: {error}"));
                    }
                }
            }
        }
    }

    fn events_text(&self) -> String {
        if self.events.is_empty() {
            return String::new();
        }
        let mut text = self.events.join("\n");
        text.push('\n');
        text
    }
}

const EMPTY_NETLOG: &[u8] = br#"{"constants":{},"events":[]}"#;

/// Estado do NetLog lido do disco depois do encerramento do Chrome.
#[derive(Debug, Clone, PartialEq)]
enum NetlogStatus {
    Complete,
    /// Truncado; reparado cortando no último evento completo.
    Repaired {
        original_bytes: usize,
        kept_bytes: usize,
    },
    /// Ausente, vazio ou irrecuperável: a sessão segue só com o CDP.
    Unusable {
        reason: String,
    },
}

fn is_valid_json(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde::de::IgnoredAny>(bytes).is_ok()
}

/// O Chrome grava um evento por linha em `"events":[`. Um arquivo cortado
/// termina em evento completo seguido de vírgula ou em linha parcial: corta no
/// último fim de linha, tira a vírgula e fecha `]}` (o `polledData` se perde).
fn repair_netlog(raw: &[u8]) -> Option<Vec<u8>> {
    let marker = raw
        .windows(10)
        .position(|w| w == b"\"events\":[" || w == b"\"events\": ")?;
    let mut end = raw.len();
    for _ in 0..16 {
        let mut candidate = raw[..end].to_vec();
        while candidate
            .last()
            .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b',')
        {
            candidate.pop();
        }
        candidate.extend_from_slice(b"]}");
        if is_valid_json(&candidate) {
            return Some(candidate);
        }
        // Recua uma linha; para antes de entrar nas constantes.
        end = raw[..end].iter().rposition(|byte| *byte == b'\n')?;
        if end <= marker {
            return None;
        }
    }
    None
}

fn prepare_netlog(raw: Option<&[u8]>) -> (Vec<u8>, NetlogStatus) {
    let Some(raw) = raw else {
        return (
            EMPTY_NETLOG.to_vec(),
            NetlogStatus::Unusable {
                reason: "NetLog ausente ou vazio".to_string(),
            },
        );
    };
    if is_valid_json(raw) {
        return (raw.to_vec(), NetlogStatus::Complete);
    }
    match repair_netlog(raw) {
        Some(fixed) => {
            let kept_bytes = fixed.len();
            (
                fixed,
                NetlogStatus::Repaired {
                    original_bytes: raw.len(),
                    kept_bytes,
                },
            )
        }
        None => (
            EMPTY_NETLOG.to_vec(),
            NetlogStatus::Unusable {
                reason: "NetLog truncado e irreparável".to_string(),
            },
        ),
    }
}

/// Registra na sessão tudo o que tornou a captura incompleta. Nunca em silêncio.
fn mark_incomplete(
    document: &mut scrapelens_core::model::SessionV1,
    netlog: &NetlogStatus,
    shutdown: &ShutdownReport,
) {
    let detail = json!({
        "browserClose": shutdown.browser_close.clone().err(),
        "chromeExit": format!("{:?}", shutdown.exit),
        "waitedMs": shutdown.waited_ms,
        "netlog": format!("{netlog:?}"),
    });
    let killed = matches!(shutdown.exit, ChromeExit::Killed);
    let (code, message) = match netlog {
        NetlogStatus::Complete if !killed => return,
        NetlogStatus::Complete => (
            "capture.chrome_killed",
            "O Chrome não encerrou no prazo e foi finalizado à força; o NetLog pode não refletir o fim da captura.".to_string(),
        ),
        NetlogStatus::Repaired { original_bytes, kept_bytes } => (
            "capture.netlog_incomplete",
            format!("O NetLog do Chrome estava truncado ({original_bytes} bytes); a sessão usa só os eventos completos ({kept_bytes} bytes). O original está em netlog.original.json."),
        ),
        NetlogStatus::Unusable { reason } => (
            "capture.netlog_unusable",
            format!("{reason}: a sessão foi importada só com CDP e corpos, sem evidência de NetLog. O original (se existir) está em netlog.original.json."),
        ),
    };
    document
        .session
        .completeness
        .add_reason(format!("{code}: {message}"));
    document
        .warnings
        .push(scrapelens_core::model::Warning::new(code, message).with_detail(detail));
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = open_private(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

// ---------------------------------------------------------------------------
// Corpos (docs/08-corpos-busca.md §1): coleta sem bloquear o loop de eventos.
// ---------------------------------------------------------------------------

/// Limite por corpo (bytes decodificados).
const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;
/// Orçamento total de corpos gravados por sessão.
const SESSION_BODY_BUDGET: usize = 256 * 1024 * 1024;

fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b'\r' | b'\n' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum BodyTag {
    Request {
        request_id: String,
        attempt: u32,
        timestamp: f64,
        /// `postData` lossy do evento, guardado quando `postDataEntries` veio
        /// incompleto: só é gravado (marcado) se `getRequestPostData` falhar.
        fallback_post_data: Option<String>,
        entries_incomplete: bool,
    },
    Response {
        request_id: String,
        attempt: u32,
        timestamp: f64,
        empty_evidence: Option<String>,
        charset: Option<String>,
    },
}

pub(crate) struct BodyCommand {
    method: &'static str,
    params: Value,
    tag: BodyTag,
}

#[derive(Default)]
struct RequestState {
    /// Quantidade de `requestWillBeSent` vistos (próximo attemptIndex).
    attempts: u32,
    /// A resposta da tentativa atual já tem linha (ou comando em voo).
    response_resolved: bool,
    status: Option<u64>,
    content_length_zero: bool,
    method: String,
    /// charset declarado pela resposta (Content-Type ou `response.charset`).
    charset: Option<String>,
}

#[derive(Default)]
pub(crate) struct BodyCollector {
    requests: HashMap<String, RequestState>,
    lines: Vec<String>,
    used: usize,
}

struct Row<'a> {
    request_id: &'a str,
    attempt: u32,
    kind: &'a str,
    source: &'a str,
    timestamp: f64,
    /// Transformações entre o fio e `data` (campo opcional `transformed`).
    transformed: Vec<String>,
}

impl<'a> Row<'a> {
    fn marked(mut self, marks: Vec<String>) -> Self {
        self.transformed = marks;
        self
    }
}

impl BodyCollector {
    pub(crate) fn take_lines(&mut self) -> Vec<String> {
        std::mem::take(&mut self.lines)
    }

    fn push(
        &mut self,
        row: Row,
        state: &str,
        encoding: Option<&str>,
        data: Option<String>,
        sizes: (Option<usize>, usize),
        reason: Option<String>,
    ) {
        let mut line = json!({
            "v": 1,
            "requestId": row.request_id,
            "attemptIndex": row.attempt,
            "kind": row.kind,
            "state": state,
            "encoding": encoding,
            "data": data,
            "originalSize": sizes.0,
            "capturedSize": sizes.1,
            "source": row.source,
            "reason": reason,
            "timestamp": row.timestamp,
        });
        if !row.transformed.is_empty() {
            line["transformed"] = json!(row.transformed);
        }
        self.lines.push(line.to_string());
    }

    fn unavailable(&mut self, row: Row, reason: impl Into<String>) {
        self.push(
            row,
            "unavailable",
            None,
            None,
            (None, 0),
            Some(reason.into()),
        );
    }

    /// Converte o corpo entregue pelo CDP em uma linha, aplicando limite por
    /// corpo, orçamento da sessão e a regra de `empty` só com evidência.
    fn emit_body(
        &mut self,
        row: Row,
        text: &str,
        base64_encoded: bool,
        empty_evidence: Option<&str>,
    ) {
        let decoded;
        let (bytes, size): (Option<&[u8]>, usize) = if base64_encoded {
            match b64_decode(text) {
                Some(bytes) => {
                    decoded = bytes;
                    (Some(&decoded[..]), decoded.len())
                }
                None => {
                    return self.unavailable(row, "CDP devolveu base64 inválido");
                }
            }
        } else {
            (None, text.len())
        };
        if size == 0 {
            return match empty_evidence {
                Some(evidence) => self.push(row, "empty", None, None, (Some(0), 0), Some(evidence.to_string())),
                None => self.unavailable(
                    row,
                    "CDP devolveu 0 bytes sem evidência de corpo vazio (sem 204/205/304 nem Content-Length: 0)",
                ),
            };
        }
        let keep = size.min(MAX_BODY_BYTES);
        if self.used + keep > SESSION_BODY_BUDGET {
            return self.push(
                row,
                "discarded",
                None,
                None,
                (Some(size), 0),
                Some("orçamento de corpos da sessão excedido".to_string()),
            );
        }
        let truncated = size > keep;
        // `data` é a string do CDP, byte a byte; só cortamos no limite.
        let (encoding, data) = match (base64_encoded, bytes) {
            (true, Some(bytes)) if truncated => ("base64", b64_encode(&bytes[..keep])),
            (true, _) => ("base64", text.to_string()),
            (false, _) if truncated => {
                let mut end = keep;
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                ("utf8", text[..end].to_string())
            }
            (false, _) => ("utf8", text.to_string()),
        };
        let captured = if encoding == "utf8" {
            data.len()
        } else if truncated {
            keep
        } else {
            size
        };
        self.used += captured;
        let reason = truncated.then(|| {
            format!("corpo acima do limite de {MAX_BODY_BYTES} bytes; gravado só o prefixo")
        });
        self.push(
            row,
            if truncated { "truncated" } else { "captured" },
            Some(encoding),
            Some(data),
            (Some(size), captured),
            reason,
        );
    }

    fn request_row<'a>(
        request_id: &'a str,
        attempt: u32,
        source: &'a str,
        timestamp: f64,
    ) -> Row<'a> {
        Row {
            request_id,
            attempt,
            kind: "request",
            source,
            timestamp,
            transformed: Vec::new(),
        }
    }

    fn response_row(request_id: &str, attempt: u32, timestamp: f64) -> Row<'_> {
        Row {
            request_id,
            attempt,
            kind: "response",
            source: "Network.getResponseBody",
            timestamp,
            transformed: Vec::new(),
        }
    }

    /// Resolve a resposta da tentativa atual como indisponível (uma vez só).
    fn resolve_response_unavailable(&mut self, request_id: &str, timestamp: f64, reason: String) {
        let Some(state) = self.requests.get_mut(request_id) else {
            return;
        };
        if state.attempts == 0 || state.response_resolved {
            return;
        }
        state.response_resolved = true;
        let attempt = state.attempts - 1;
        self.unavailable(Self::response_row(request_id, attempt, timestamp), reason);
    }

    pub(crate) fn on_event(&mut self, method: &str, params: &Value) -> Vec<BodyCommand> {
        let mut commands = Vec::new();
        let Some(request_id) = params.get("requestId").and_then(Value::as_str) else {
            return commands;
        };
        let timestamp = params
            .get("timestamp")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        match method {
            "Network.requestWillBeSent" => {
                let previous = self
                    .requests
                    .get(request_id)
                    .map(|s| (s.attempts, s.response_resolved));
                if let Some((attempts, resolved)) = previous {
                    if attempts > 0 && !resolved {
                        let reason = if params.get("redirectResponse").is_some_and(|v| !v.is_null())
                        {
                            "resposta de redirect: CDP não fornece corpo"
                        } else {
                            "tentativa substituída por novo requestWillBeSent sem redirectResponse; resposta não observada"
                        };
                        self.resolve_response_unavailable(
                            request_id,
                            timestamp,
                            reason.to_string(),
                        );
                    }
                }
                let request = params.get("request").unwrap_or(&Value::Null);
                let http_method = request
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or("GET")
                    .to_string();
                let state = self.requests.entry(request_id.to_string()).or_default();
                let attempt = state.attempts;
                state.attempts += 1;
                state.response_resolved = false;
                state.status = None;
                state.content_length_zero = false;
                state.charset = None;
                state.method = http_method.clone();
                let request_cl_zero = header_is_zero(request.get("headers"));
                self.request_body(
                    request_id,
                    attempt,
                    timestamp,
                    request,
                    &http_method,
                    request_cl_zero,
                    &mut commands,
                );
            }
            "Network.responseReceived" => {
                let response = params.get("response").unwrap_or(&Value::Null);
                let kind = params.get("type").and_then(Value::as_str).unwrap_or("");
                let mime = response
                    .get("mimeType")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if let Some(state) = self.requests.get_mut(request_id) {
                    state.status = response.get("status").and_then(Value::as_u64);
                    state.content_length_zero = header_is_zero(response.get("headers"));
                    state.charset = declared_charset(response);
                }
                if kind == "EventSource" || mime.eq_ignore_ascii_case("text/event-stream") {
                    self.resolve_response_unavailable(
                        request_id,
                        timestamp,
                        "SSE/streaming: CDP não fornece o corpo de um fluxo; mensagens chegam como eventos separados e não são gravadas".to_string(),
                    );
                }
            }
            "Network.webSocketCreated" => {
                let state = self.requests.entry(request_id.to_string()).or_default();
                if state.attempts == 0 {
                    state.attempts = 1;
                }
                self.resolve_response_unavailable(
                    request_id,
                    timestamp,
                    "WebSocket: não há corpo HTTP; frames (Network.webSocketFrame*) não são gravados".to_string(),
                );
            }
            "Network.loadingFinished" => {
                let Some(state) = self.requests.get_mut(request_id) else {
                    return commands;
                };
                if state.attempts == 0 || state.response_resolved {
                    return commands;
                }
                state.response_resolved = true;
                let attempt = state.attempts - 1;
                let charset = state.charset.clone();
                let evidence = match state.status {
                    Some(status @ (204 | 205 | 304)) => {
                        Some(format!("status {status} não tem corpo"))
                    }
                    _ if state.method.eq_ignore_ascii_case("HEAD") => {
                        Some("resposta a HEAD não tem corpo".to_string())
                    }
                    _ if state.content_length_zero => Some("Content-Length: 0".to_string()),
                    _ => None,
                };
                commands.push(BodyCommand {
                    method: "Network.getResponseBody",
                    params: json!({ "requestId": request_id }),
                    tag: BodyTag::Response {
                        request_id: request_id.to_string(),
                        attempt,
                        timestamp,
                        empty_evidence: evidence,
                        charset,
                    },
                });
            }
            "Network.loadingFailed" => {
                let text = params
                    .get("errorText")
                    .and_then(Value::as_str)
                    .unwrap_or("loadingFailed");
                let mut reason = format!("loadingFailed: {text}");
                if params.get("canceled").and_then(Value::as_bool) == Some(true) {
                    reason.push_str(" (cancelado)");
                }
                if let Some(blocked) = params.get("blockedReason").and_then(Value::as_str) {
                    reason.push_str(&format!(" [blockedReason: {blocked}]"));
                }
                self.resolve_response_unavailable(request_id, timestamp, reason);
            }
            _ => {}
        }
        commands
    }

    #[allow(clippy::too_many_arguments)]
    fn request_body(
        &mut self,
        request_id: &str,
        attempt: u32,
        timestamp: f64,
        request: &Value,
        http_method: &str,
        content_length_zero: bool,
        commands: &mut Vec<BodyCommand>,
    ) {
        let has_post_data = request
            .get("hasPostData")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        // `postDataEntries` primeiro: são os bytes exatos. `postData` é uma
        // string já convertida pelo Chrome (bytes inválidos viram U+FFFD).
        let cl_zero = content_length_zero.then_some("Content-Length: 0");
        let mut entries_incomplete = false;
        if let Some(entries) = request.get("postDataEntries").and_then(Value::as_array) {
            let mut bytes = Vec::new();
            let mut complete = !entries.is_empty();
            for entry in entries {
                match entry
                    .get("bytes")
                    .and_then(Value::as_str)
                    .and_then(b64_decode)
                {
                    Some(part) => bytes.extend_from_slice(&part),
                    None => complete = false,
                }
            }
            if complete {
                let row = Self::request_row(
                    request_id,
                    attempt,
                    "requestWillBeSent.postDataEntries",
                    timestamp,
                );
                return match String::from_utf8(bytes) {
                    Ok(text) => self.emit_body(row, &text, false, cl_zero),
                    Err(error) => self.emit_body(row, &b64_encode(error.as_bytes()), true, cl_zero),
                };
            }
            entries_incomplete = true;
        }
        let post_data = request.get("postData").and_then(Value::as_str);
        if has_post_data {
            // Entradas incompletas: o postData do evento é lossy; tenta os
            // bytes via CDP antes de aceitá-lo (marcado).
            if post_data.is_none() || entries_incomplete {
                commands.push(BodyCommand {
                    method: "Network.getRequestPostData",
                    params: json!({ "requestId": request_id }),
                    tag: BodyTag::Request {
                        request_id: request_id.to_string(),
                        attempt,
                        timestamp,
                        fallback_post_data: entries_incomplete
                            .then(|| post_data.map(str::to_string))
                            .flatten(),
                        entries_incomplete,
                    },
                });
                return;
            }
        }
        if let Some(text) = post_data {
            let mut row =
                Self::request_row(request_id, attempt, "requestWillBeSent.postData", timestamp);
            if entries_incomplete {
                row = row.marked(vec!["lossy-postData".to_string()]);
            }
            return self.emit_body(row, text, false, cl_zero);
        }
        if matches!(http_method.to_ascii_uppercase().as_str(), "GET" | "HEAD") {
            return;
        }
        let row = Self::request_row(request_id, attempt, "requestWillBeSent.postData", timestamp);
        if content_length_zero {
            self.push(
                row,
                "empty",
                None,
                None,
                (Some(0), 0),
                Some("Content-Length: 0".to_string()),
            );
        } else {
            self.unavailable(
                row,
                "CDP não informou corpo (sem postData, postDataEntries nem hasPostData)",
            );
        }
    }

    pub(crate) fn on_result(&mut self, tag: BodyTag, outcome: Result<Value, String>) {
        match tag {
            BodyTag::Request {
                request_id,
                attempt,
                timestamp,
                fallback_post_data,
                entries_incomplete,
            } => {
                let row = Self::request_row(
                    &request_id,
                    attempt,
                    "Network.getRequestPostData",
                    timestamp,
                );
                let fetched = match &outcome {
                    Ok(result) => result.get("postData").and_then(Value::as_str).map(|text| {
                        let b64 = result
                            .get("base64Encoded")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        (text.to_string(), b64)
                    }),
                    Err(_) => None,
                };
                if let Some((text, b64)) = fetched {
                    // Entradas incompletas + string não-base64: não há prova
                    // de que a string preserve os bytes.
                    let row = if entries_incomplete && !b64 {
                        row.marked(vec!["lossy-postData".to_string()])
                    } else {
                        row
                    };
                    self.emit_body(row, &text, b64, None);
                } else if let Some(text) = fallback_post_data {
                    let row = Self::request_row(
                        &request_id,
                        attempt,
                        "requestWillBeSent.postData",
                        timestamp,
                    )
                    .marked(vec!["lossy-postData".to_string()]);
                    self.emit_body(row, &text, false, None);
                } else {
                    match outcome {
                        Ok(_) => self
                            .unavailable(row, "Network.getRequestPostData não devolveu postData"),
                        Err(message) => {
                            self.unavailable(row, format!("Network.getRequestPostData: {message}"))
                        }
                    }
                }
            }
            BodyTag::Response {
                request_id,
                attempt,
                timestamp,
                empty_evidence,
                charset,
            } => {
                let row = Self::response_row(&request_id, attempt, timestamp);
                match outcome {
                    Ok(result) => match result.get("body").and_then(Value::as_str) {
                        Some(text) => {
                            let b64 = result
                                .get("base64Encoded")
                                .and_then(Value::as_bool)
                                .unwrap_or(false);
                            // getResponseBody entrega texto já decodificado pelo
                            // Chrome; os bytes do fio não são recuperáveis.
                            let row = if b64 {
                                row
                            } else {
                                row.marked(response_transforms(charset.as_deref()))
                            };
                            self.emit_body(row, text, b64, empty_evidence.as_deref());
                        }
                        None => self.unavailable(row, "Network.getResponseBody não devolveu body"),
                    },
                    Err(message) => {
                        self.unavailable(row, format!("Network.getResponseBody: {message}"))
                    }
                }
            }
        }
    }

    /// Fim da captura: respostas sem `loadingFinished`/`loadingFailed`.
    pub(crate) fn finish(&mut self) {
        let pending: Vec<String> = self
            .requests
            .iter()
            .filter(|(_, state)| state.attempts > 0 && !state.response_resolved)
            .map(|(id, _)| id.clone())
            .collect();
        for id in pending {
            self.resolve_response_unavailable(
                &id,
                0.0,
                "captura encerrada antes de loadingFinished/loadingFailed; resposta não coletada"
                    .to_string(),
            );
        }
    }
}

/// charset declarado pela resposta (Content-Type; senão `response.charset`).
fn declared_charset(response: &Value) -> Option<String> {
    let from_header = response
        .get("headers")
        .and_then(Value::as_object)
        .and_then(|map| {
            map.iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        })
        .and_then(|(_, value)| value.as_str())
        .and_then(|value| {
            value.split(';').skip(1).find_map(|part| {
                let (key, val) = part.split_once('=')?;
                key.trim()
                    .eq_ignore_ascii_case("charset")
                    .then(|| val.trim().trim_matches('"').to_ascii_lowercase())
            })
        });
    from_header
        .or_else(|| {
            response
                .get("charset")
                .and_then(Value::as_str)
                .map(str::to_ascii_lowercase)
        })
        .filter(|charset| !charset.is_empty())
}

fn response_transforms(charset: Option<&str>) -> Vec<String> {
    let mut marks = vec!["chrome-decoded".to_string()];
    if let Some(charset) = charset {
        if !matches!(charset, "utf-8" | "utf8") {
            marks.push(format!("charset:{charset}->utf-8"));
        }
    }
    marks
}

fn header_is_zero(headers: Option<&Value>) -> bool {
    headers
        .and_then(Value::as_object)
        .and_then(|map| {
            map.iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        })
        .and_then(|(_, value)| value.as_str())
        .is_some_and(|value| value.trim() == "0")
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(collector: &mut BodyCollector) -> Vec<Value> {
        collector
            .take_lines()
            .iter()
            .map(|line| serde_json::from_str(line).expect("linha JSON"))
            .collect()
    }

    fn will_be_sent(id: &str, method: &str, extra: Value, redirect: bool) -> Value {
        let mut request = json!({ "url": "http://127.0.0.1/x", "method": method, "headers": {} });
        for (key, value) in extra.as_object().unwrap() {
            request[key] = value.clone();
        }
        let mut params = json!({ "requestId": id, "request": request, "timestamp": 10.5 });
        if redirect {
            params["redirectResponse"] = json!({ "status": 302 });
        }
        params
    }

    fn finish_event(id: &str) -> Value {
        json!({ "requestId": id, "timestamp": 11.0 })
    }

    #[test]
    fn setup_error_maps_to_command_name() {
        assert_eq!(
            Cdp::command_from_setup_error("CDP timeout aguardando Network.enable (pipeline)"),
            "Network.enable"
        );
        assert_eq!(
            Cdp::command_from_setup_error("CDP timeout aguardando Target.setAutoAttach"),
            "Target.setAutoAttach"
        );
    }

    #[test]
    fn base64_roundtrip_all_lengths() {
        let data: Vec<u8> = (0..=255u8).collect();
        for len in 0..data.len() {
            let encoded = b64_encode(&data[..len]);
            assert_eq!(b64_decode(&encoded).unwrap(), &data[..len]);
        }
        assert_eq!(b64_encode(b"Man"), "TWFu");
        assert_eq!(b64_encode(b"Ma"), "TWE=");
        assert!(b64_decode("@@@").is_none());
    }

    #[test]
    fn form_post_body_is_captured_verbatim() {
        let mut c = BodyCollector::default();
        let post = "cmd_consultar_placa=1&placa=TST0T00&x=%C3%A9";
        let cmds = c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent(
                "1.1",
                "POST",
                json!({ "postData": post, "hasPostData": true }),
                false,
            ),
        );
        assert!(cmds.is_empty(), "postData presente não precisa de comando");
        let rows = lines(&mut c);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["state"], "captured");
        assert_eq!(rows[0]["kind"], "request");
        assert_eq!(rows[0]["attemptIndex"], 0);
        assert_eq!(rows[0]["encoding"], "utf8");
        assert_eq!(rows[0]["data"], post);
        assert_eq!(rows[0]["capturedSize"], post.len());
        assert_eq!(rows[0]["source"], "requestWillBeSent.postData");
    }

    #[test]
    fn binary_entries_become_base64_with_same_bytes() {
        let mut c = BodyCollector::default();
        let raw = [0xFFu8, 0xC0, 0x00, 0x80, 0x41];
        let params = will_be_sent(
            "2.1",
            "POST",
            json!({ "hasPostData": true, "postDataEntries": [{ "bytes": b64_encode(&raw[..2]) }, { "bytes": b64_encode(&raw[2..]) }] }),
            false,
        );
        assert!(c.on_event("Network.requestWillBeSent", &params).is_empty());
        let rows = lines(&mut c);
        assert_eq!(rows[0]["encoding"], "base64");
        assert_eq!(b64_decode(rows[0]["data"].as_str().unwrap()).unwrap(), raw);
        assert_eq!(rows[0]["source"], "requestWillBeSent.postDataEntries");

        // Com entries completas, o postData (lossy) é ignorado.
        let params = will_be_sent(
            "2.2",
            "POST",
            json!({ "postData": "\u{FFFD}\u{FFFD}", "hasPostData": true, "postDataEntries": [{ "bytes": b64_encode(b"a=\xC3\xA9") }] }),
            false,
        );
        c.on_event("Network.requestWillBeSent", &params);
        let rows = lines(&mut c);
        assert_eq!(rows[0]["encoding"], "utf8");
        assert_eq!(rows[0]["data"], "a=é");
        assert_eq!(rows[0]["source"], "requestWillBeSent.postDataEntries");
    }

    #[test]
    fn has_post_data_without_data_asks_cdp_and_failures_are_unavailable() {
        let mut c = BodyCollector::default();
        let cmds = c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("3.1", "POST", json!({ "hasPostData": true }), false),
        );
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].method, "Network.getRequestPostData");
        assert!(lines(&mut c).is_empty());
        c.on_result(
            cmds[0].tag.clone(),
            Err("No data found for resource with given identifier".into()),
        );
        let rows = lines(&mut c);
        assert_eq!(rows[0]["state"], "unavailable");
        assert!(rows[0]["reason"]
            .as_str()
            .unwrap()
            .contains("No data found"));
        assert_eq!(rows[0]["source"], "Network.getRequestPostData");

        let cmds = c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("3.2", "POST", json!({ "hasPostData": true }), false),
        );
        c.on_result(
            cmds[0].tag.clone(),
            Ok(json!({ "postData": b64_encode(&[0, 1, 2]), "base64Encoded": true })),
        );
        let rows = lines(&mut c);
        assert_eq!(rows[0]["state"], "captured");
        assert_eq!(rows[0]["encoding"], "base64");
    }

    #[test]
    fn redirect_marks_previous_response_unavailable_and_keeps_each_request_body() {
        let mut c = BodyCollector::default();
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("4.1", "POST", json!({ "postData": "a=1" }), false),
        );
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("4.1", "POST", json!({ "postData": "a=1" }), true),
        );
        let rows = lines(&mut c);
        assert_eq!(rows.len(), 3);
        assert_eq!(
            (rows[0]["kind"].as_str(), rows[0]["attemptIndex"].as_u64()),
            (Some("request"), Some(0))
        );
        assert_eq!(
            (rows[1]["kind"].as_str(), rows[1]["attemptIndex"].as_u64()),
            (Some("response"), Some(0))
        );
        assert_eq!(rows[1]["state"], "unavailable");
        assert_eq!(
            rows[1]["reason"],
            "resposta de redirect: CDP não fornece corpo"
        );
        assert_eq!(
            (rows[2]["kind"].as_str(), rows[2]["attemptIndex"].as_u64()),
            (Some("request"), Some(1))
        );
        assert_eq!(rows[2]["data"], "a=1");
        let cmds = c.on_event("Network.loadingFinished", &finish_event("4.1"));
        match &cmds[0].tag {
            BodyTag::Response { attempt, .. } => assert_eq!(*attempt, 1),
            other => panic!("tag inesperada: {other:?}"),
        }
        // loadingFinished repetido não gera segundo comando.
        assert!(c
            .on_event("Network.loadingFinished", &finish_event("4.1"))
            .is_empty());
    }

    #[test]
    fn response_over_limit_is_truncated_with_original_size() {
        let mut c = BodyCollector::default();
        let cmds = {
            c.on_event(
                "Network.requestWillBeSent",
                &will_be_sent("5.1", "GET", json!({}), false),
            );
            c.on_event("Network.loadingFinished", &finish_event("5.1"))
        };
        let body = "é".repeat(MAX_BODY_BYTES / 2 + 10); // 2 bytes por char, corta no meio de nada
        c.on_result(
            cmds[0].tag.clone(),
            Ok(json!({ "body": body, "base64Encoded": false })),
        );
        let rows = lines(&mut c);
        assert_eq!(rows[0]["state"], "truncated");
        assert_eq!(rows[0]["originalSize"], body.len());
        assert_eq!(rows[0]["capturedSize"], MAX_BODY_BYTES);
        assert_eq!(rows[0]["data"].as_str().unwrap().len(), MAX_BODY_BYTES);
        assert!(body.starts_with(rows[0]["data"].as_str().unwrap()));

        // Corte que cairia no meio de um caractere recua para a fronteira.
        let odd = format!("a{}", "é".repeat(MAX_BODY_BYTES / 2));
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("5.2", "GET", json!({}), false),
        );
        let cmds = c.on_event("Network.loadingFinished", &finish_event("5.2"));
        c.on_result(
            cmds[0].tag.clone(),
            Ok(json!({ "body": odd, "base64Encoded": false })),
        );
        let rows = lines(&mut c);
        assert_eq!(rows[0]["capturedSize"], MAX_BODY_BYTES - 1);

        // base64 truncado preserva os 5 MiB de bytes decodificados.
        let big = vec![7u8; MAX_BODY_BYTES + 3];
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("5.3", "GET", json!({}), false),
        );
        let cmds = c.on_event("Network.loadingFinished", &finish_event("5.3"));
        c.on_result(
            cmds[0].tag.clone(),
            Ok(json!({ "body": b64_encode(&big), "base64Encoded": true })),
        );
        let rows = lines(&mut c);
        assert_eq!(rows[0]["state"], "truncated");
        assert_eq!(rows[0]["originalSize"], big.len());
        assert_eq!(
            b64_decode(rows[0]["data"].as_str().unwrap()).unwrap().len(),
            MAX_BODY_BYTES
        );
    }

    #[test]
    fn session_budget_discards_following_bodies() {
        let mut c = BodyCollector::default();
        c.used = SESSION_BODY_BUDGET - 4;
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("6.1", "POST", json!({ "postData": "abcd" }), false),
        );
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("6.2", "POST", json!({ "postData": "e" }), false),
        );
        let rows = lines(&mut c);
        assert_eq!(rows[0]["state"], "captured");
        assert_eq!(rows[1]["state"], "discarded");
        assert_eq!(rows[1]["reason"], "orçamento de corpos da sessão excedido");
        assert_eq!(rows[1]["originalSize"], 1);
        assert!(rows[1]["data"].is_null());
    }

    #[test]
    fn failure_streaming_and_websocket_are_unavailable_with_reason() {
        let mut c = BodyCollector::default();
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("7.1", "GET", json!({}), false),
        );
        c.on_event("Network.loadingFailed", &json!({ "requestId": "7.1", "timestamp": 1.0, "errorText": "net::ERR_CONNECTION_REFUSED" }));
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("7.2", "GET", json!({}), false),
        );
        c.on_event("Network.responseReceived", &json!({ "requestId": "7.2", "type": "EventSource", "response": { "status": 200, "mimeType": "text/event-stream" } }));
        c.on_event(
            "Network.webSocketCreated",
            &json!({ "requestId": "7.3", "url": "ws://127.0.0.1/" }),
        );
        // loadingFinished depois de resolvido não gera comando.
        assert!(c
            .on_event("Network.loadingFinished", &finish_event("7.2"))
            .is_empty());
        let rows = lines(&mut c);
        assert_eq!(rows.len(), 3);
        assert!(rows
            .iter()
            .all(|row| row["state"] == "unavailable" && row["kind"] == "response"));
        assert!(rows[0]["reason"]
            .as_str()
            .unwrap()
            .contains("ERR_CONNECTION_REFUSED"));
        assert!(rows[1]["reason"].as_str().unwrap().contains("SSE"));
        assert!(rows[2]["reason"].as_str().unwrap().contains("WebSocket"));
    }

    #[test]
    fn empty_requires_evidence() {
        let mut c = BodyCollector::default();
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("8.1", "GET", json!({}), false),
        );
        c.on_event("Network.responseReceived", &json!({ "requestId": "8.1", "type": "XHR", "response": { "status": 204, "mimeType": "" } }));
        let cmds = c.on_event("Network.loadingFinished", &finish_event("8.1"));
        c.on_result(
            cmds[0].tag.clone(),
            Ok(json!({ "body": "", "base64Encoded": false })),
        );
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("8.2", "GET", json!({}), false),
        );
        c.on_event("Network.responseReceived", &json!({ "requestId": "8.2", "type": "XHR", "response": { "status": 200, "mimeType": "text/plain" } }));
        let cmds = c.on_event("Network.loadingFinished", &finish_event("8.2"));
        c.on_result(
            cmds[0].tag.clone(),
            Ok(json!({ "body": "", "base64Encoded": false })),
        );
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("8.3", "GET", json!({}), false),
        );
        c.on_event("Network.responseReceived", &json!({ "requestId": "8.3", "type": "XHR", "response": { "status": 200, "headers": { "Content-Length": "0" } } }));
        let cmds = c.on_event("Network.loadingFinished", &finish_event("8.3"));
        c.on_result(
            cmds[0].tag.clone(),
            Ok(json!({ "body": "", "base64Encoded": false })),
        );
        let rows = lines(&mut c);
        assert_eq!(rows[0]["state"], "empty");
        assert_eq!(rows[1]["state"], "unavailable");
        assert_eq!(rows[2]["state"], "empty");
        assert_eq!(rows[2]["reason"], "Content-Length: 0");
    }

    #[test]
    fn finish_covers_requests_without_loading_finished() {
        let mut c = BodyCollector::default();
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("9.1", "GET", json!({}), false),
        );
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("9.2", "POST", json!({}), false),
        );
        c.finish();
        let rows = lines(&mut c);
        // 9.2 ganha também a linha de requisição sem corpo informado.
        assert_eq!(
            rows.iter().filter(|row| row["kind"] == "response").count(),
            2
        );
        assert!(rows.iter().all(|row| row["state"] == "unavailable"));
        c.finish();
        assert!(lines(&mut c).is_empty(), "finish é idempotente");
    }

    #[test]
    fn response_text_is_marked_transformed_and_charset_is_named() {
        let mut c = BodyCollector::default();
        for (id, headers, body_b64) in [
            ("t.1", json!({}), false),
            (
                "t.2",
                json!({"Content-Type": "text/html; charset=ISO-8859-1"}),
                false,
            ),
            (
                "t.3",
                json!({"content-type": "text/plain; charset=\"utf-8\""}),
                false,
            ),
            (
                "t.4",
                json!({"Content-Type": "application/octet-stream"}),
                true,
            ),
        ] {
            c.on_event(
                "Network.requestWillBeSent",
                &will_be_sent(id, "GET", json!({}), false),
            );
            c.on_event(
                "Network.responseReceived",
                &json!({"requestId": id, "type": "Fetch", "response": {"status": 200, "headers": headers}}),
            );
            let cmds = c.on_event("Network.loadingFinished", &finish_event(id));
            let body = if body_b64 {
                b64_encode(&[0xFF, 1])
            } else {
                "São".to_string()
            };
            c.on_result(
                cmds[0].tag.clone(),
                Ok(json!({"body": body, "base64Encoded": body_b64})),
            );
        }
        let rows = lines(&mut c);
        assert_eq!(rows[0]["transformed"], json!(["chrome-decoded"]));
        assert_eq!(
            rows[1]["transformed"],
            json!(["chrome-decoded", "charset:iso-8859-1->utf-8"])
        );
        assert_eq!(rows[2]["transformed"], json!(["chrome-decoded"]));
        assert!(rows[3].get("transformed").is_none());
    }

    #[test]
    fn incomplete_entries_try_cdp_then_mark_lossy_fallback() {
        let incomplete = json!({
            "hasPostData": true,
            "postData": "a=\u{FFFD}",
            "postDataEntries": [{"type": "blob"}]
        });
        let mut c = BodyCollector::default();
        let cmds = c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("l.1", "POST", incomplete.clone(), false),
        );
        assert_eq!(cmds.len(), 1);
        assert!(lines(&mut c).is_empty());
        c.on_result(cmds[0].tag.clone(), Err("boom".into()));
        let rows = lines(&mut c);
        assert_eq!(rows[0]["state"], "captured");
        assert_eq!(rows[0]["transformed"], json!(["lossy-postData"]));
        assert_eq!(rows[0]["source"], "requestWillBeSent.postData");

        let cmds = c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("l.2", "POST", incomplete.clone(), false),
        );
        c.on_result(
            cmds[0].tag.clone(),
            Ok(json!({"postData": b64_encode(&[0xFF, 0]), "base64Encoded": true})),
        );
        let rows = lines(&mut c);
        assert_eq!(rows[0]["encoding"], "base64");
        assert!(rows[0].get("transformed").is_none());

        // Sem hasPostData, o postData lossy é gravado marcado, sem comando.
        let no_flag = json!({"postData": "x", "postDataEntries": [{"type": "blob"}]});
        assert!(c
            .on_event(
                "Network.requestWillBeSent",
                &will_be_sent("l.3", "POST", no_flag, false)
            )
            .is_empty());
        assert_eq!(lines(&mut c)[0]["transformed"], json!(["lossy-postData"]));
    }

    fn fixture(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../experiments/results/h1-page")
            .join(name);
        std::fs::read(path).expect("fixture de experiments/results/h1-page")
    }

    fn quiet_shutdown(exit: ChromeExit) -> ShutdownReport {
        ShutdownReport {
            browser_close: Ok(()),
            exit,
            waited_ms: 1,
        }
    }

    #[test]
    fn truncated_netlog_is_repaired_and_still_imports() {
        let full = fixture("chrome-netlog.json");
        let cdp = fixture("cdp-events.jsonl");
        assert_eq!(prepare_netlog(Some(&full)).1, NetlogStatus::Complete);
        let full_events = serde_json::from_slice::<Value>(&full).unwrap()["events"]
            .as_array()
            .unwrap()
            .len();
        // Cortes em pontos variados: fim de linha com vírgula e meio de linha.
        for fraction in [0.3_f64, 0.55, 0.8] {
            let mut cut = (full.len() as f64 * fraction) as usize;
            for variant in 0..2 {
                if variant == 1 {
                    cut += 7;
                }
                let (fixed, status) = prepare_netlog(Some(&full[..cut]));
                assert!(
                    matches!(status, NetlogStatus::Repaired { .. }),
                    "{fraction}/{variant}: {status:?}"
                );
                let events = serde_json::from_slice::<Value>(&fixed).unwrap()["events"]
                    .as_array()
                    .unwrap()
                    .len();
                assert!(events > 0 && events < full_events);
                let imported = scrapelens_core::import_capture_with_bodies(
                    &cdp,
                    &fixed,
                    None,
                    CorrelationOptions::default(),
                );
                assert!(
                    imported.is_ok(),
                    "import do NetLog reparado: {:?}",
                    imported.err()
                );
            }
        }
    }

    #[test]
    fn unusable_netlog_falls_back_to_cdp_only_import() {
        let cdp = fixture("cdp-events.jsonl");
        for raw in [None, Some(&b"{\"constants\":{\"a\":"[..])] {
            let (netlog, status) = prepare_netlog(raw);
            assert!(matches!(status, NetlogStatus::Unusable { .. }));
            let mut imported = scrapelens_core::import_capture_with_bodies(
                &cdp,
                &netlog,
                None,
                CorrelationOptions::default(),
            )
            .expect("CDP sem NetLog ainda importa");
            mark_incomplete(
                &mut imported.bundle.session,
                &status,
                &quiet_shutdown(ChromeExit::Graceful(Some(0))),
            );
            let session = &imported.bundle.session;
            assert!(session
                .warnings
                .iter()
                .any(|w| w.code == "capture.netlog_unusable"));
            assert!(session
                .session
                .completeness
                .reasons
                .iter()
                .any(|r| r.contains("capture.netlog_unusable")));
            assert!(!session.requests.is_empty());
        }
    }

    #[test]
    fn killed_chrome_adds_a_warning_even_with_valid_netlog() {
        let cdp = fixture("cdp-events.jsonl");
        let full = fixture("chrome-netlog.json");
        let mut imported = scrapelens_core::import_capture_with_bodies(
            &cdp,
            &full,
            None,
            CorrelationOptions::default(),
        )
        .unwrap();
        let before = imported.bundle.session.warnings.len();
        mark_incomplete(
            &mut imported.bundle.session,
            &NetlogStatus::Complete,
            &quiet_shutdown(ChromeExit::Graceful(Some(0))),
        );
        assert_eq!(imported.bundle.session.warnings.len(), before);
        mark_incomplete(
            &mut imported.bundle.session,
            &NetlogStatus::Complete,
            &quiet_shutdown(ChromeExit::Killed),
        );
        assert!(imported
            .bundle
            .session
            .warnings
            .iter()
            .any(|w| w.code == "capture.chrome_killed"));
    }

    #[cfg(unix)]
    #[test]
    fn bodies_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "scrapelens-bodies-{}-{}",
            std::process::id(),
            unix_millis()
        ));
        let file = open_private(&path).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        let _ = std::fs::remove_file(&path);
    }

    /// Teste manual do ciclo real: exige Chrome instalado e o testserver h1 em
    /// 127.0.0.1:8781. Rode com:
    ///   cargo test live_capture_cycle -- --ignored --nocapture
    #[test]
    #[ignore]
    fn live_capture_cycle() {
        let chrome = crate::chrome::detect(None)
            .path
            .expect("Chrome instalado para o teste de captura");
        let dir = std::env::temp_dir().join(format!("scrapelens-live-{}", unix_millis()));
        std::fs::create_dir_all(&dir).unwrap();
        let status = Arc::new(Mutex::new(CaptureStatus {
            recording: true,
            session_id: "live-test".to_string(),
            session_dir: dir.display().to_string(),
            ..CaptureStatus::default()
        }));
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let config = CaptureConfig {
            chrome: PathBuf::from(chrome),
            session_dir: dir.clone(),
            start_url: "http://127.0.0.1:8781/page".to_string(),
            headless: true,
            ignore_cert: false,
        };
        let status_thread = status.clone();
        let join = thread::spawn(move || run(config, status_thread, stop_rx, ready_tx));
        ready_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("captura pronta")
            .expect("captura iniciou");
        thread::sleep(Duration::from_secs(6));
        let _ = stop_tx.send(());
        let payload = join
            .join()
            .expect("thread da captura")
            .expect("captura importada");
        let requests = payload.session["requests"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(0);
        println!(
            "live capture: {} requisições, session_dir={:?}, notice={:?}",
            requests, payload.session_dir, payload.notice
        );
        assert!(requests > 0, "a captura precisa conter requisições reais");
        assert!(!payload.synthetic);
        println!("session.json: {}", dir.join("session.json").display());
    }

    /// Ciclo real dirigido por `experiments/bodies/run_bodies.py` (exige Chrome
    /// e o testserver h1 local). Variáveis: `SL_LIVE_START_URL`,
    /// `SL_LIVE_SESSION_DIR`, `SL_LIVE_STOP_FILE` (a captura para quando o
    /// arquivo existir).
    #[test]
    #[ignore]
    fn live_bodies_cycle() {
        let start_url = std::env::var("SL_LIVE_START_URL").expect("SL_LIVE_START_URL");
        let dir = PathBuf::from(std::env::var("SL_LIVE_SESSION_DIR").expect("SL_LIVE_SESSION_DIR"));
        let stop_file =
            PathBuf::from(std::env::var("SL_LIVE_STOP_FILE").expect("SL_LIVE_STOP_FILE"));
        let chrome = crate::chrome::detect(None).path.expect("Chrome instalado");
        let status = Arc::new(Mutex::new(CaptureStatus {
            recording: true,
            session_id: "live-bodies".to_string(),
            session_dir: dir.display().to_string(),
            ..CaptureStatus::default()
        }));
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let config = CaptureConfig {
            chrome: PathBuf::from(chrome),
            session_dir: dir,
            start_url,
            headless: true,
            ignore_cert: false,
        };
        let status_thread = status.clone();
        let join = thread::spawn(move || run(config, status_thread, stop_rx, ready_tx));
        ready_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("captura pronta")
            .expect("captura iniciou");
        let deadline = Instant::now() + Duration::from_secs(180);
        while !stop_file.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(200));
        }
        let _ = stop_tx.send(());
        let payload = join
            .join()
            .expect("thread da captura")
            .expect("captura importada");
        println!("live bodies: notice={:?}", payload.notice);
    }
}
