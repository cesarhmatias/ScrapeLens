//! Captura ao vivo: Chrome externo com perfil dedicado + CDP + NetLog.
//!
//! Regras:
//! - perfil temporário próprio (nunca o perfil pessoal), removido no fim;
//! - depuração apenas em 127.0.0.1, porta efêmera;
//! - encerra somente o processo que este módulo iniciou;
//! - o NetLog é gravado no diretório da sessão e importado pelo core;
//! - nenhuma rede além da depuração local; nenhum certificado é instalado.

use std::io::ErrorKind;
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

use scrapelens_core::{correlate::CorrelationOptions, import_capture, store};

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

    let mut child = spawn_chrome(config, &profile, &netlog_path)?;
    if let Ok(mut guard) = status.lock() {
        guard.chrome_pid = Some(child.id());
        guard.page_url = config.start_url.clone();
    }

    let ws_url = match wait_for_devtools(&mut child, &profile, Duration::from_secs(25)) {
        Ok(url) => url,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&profile);
            let _ = ready.send(Err(error.clone()));
            return Err(error);
        }
    };

    let (mut socket, mut cdp) = match Cdp::connect(&ws_url, status.clone()) {
        Ok(pair) => pair,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&profile);
            let _ = ready.send(Err(error.clone()));
            return Err(error);
        }
    };

    let setup = cdp.setup(&mut socket, &config.start_url);
    if let Err(error) = setup {
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&profile);
        let _ = ready.send(Err(error.clone()));
        return Err(error);
    }
    let _ = ready.send(Ok(()));

    // Loop de gravação: todo evento Network.* é preservado na ordem do Chrome.
    let started = Instant::now();
    loop {
        if matches!(stop.try_recv(), Ok(()) | Err(TryRecvError::Disconnected)) {
            break;
        }
        if started.elapsed() > Duration::from_secs(30 * 60) {
            break;
        }
        match socket.read() {
            Ok(Message::Text(text)) => {
                if let Ok(value) = serde_json::from_str::<Value>(text.as_str()) {
                    cdp.record(&value, text.as_str());
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

    // Encerra o Chrome de forma graciosa para o NetLog ser finalizado.
    let _ = cdp.send(&mut socket, "Browser.close", json!({}), None, Duration::from_secs(2));
    let _ = socket.close(None);
    wait_or_kill(&mut child, Duration::from_secs(10));
    let _ = std::fs::remove_dir_all(&profile);

    let cdp_bytes = cdp.events_text().into_bytes();
    if cdp_bytes.is_empty() {
        let _ = std::fs::write(&cdp_path, &cdp_bytes);
        let error = "Nenhum evento CDP foi gravado. A sessão não foi criada; verifique se o Chrome permaneceu aberto durante a captura.".to_string();
        let _ = ready.send(Err(error.clone()));
        return Err(error);
    }
    let netlog = std::fs::read(&netlog_path).map_err(|error| {
        format!("O Chrome não deixou o NetLog em {}: {error}", netlog_path.display())
    })?;
    if netlog.is_empty() {
        return Err("O Chrome gravou um NetLog vazio; a captura não pode ser verificada. A sessão não foi criada.".to_string());
    }

    let mut imported = import_capture(&cdp_bytes, &netlog, CorrelationOptions::default())
        .map_err(|error| format!("O core não conseguiu importar a captura: {error}"))?;
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
        "--disable-features=Translate,MediaRouter,OptimizationHints,InterestFeedContentSuggestions".to_string(),
        "--enable-quic".to_string(),
        "--allow-insecure-localhost".to_string(),
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

fn wait_for_devtools(child: &mut Child, profile: &Path, timeout: Duration) -> Result<String, String> {
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
                let path = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
                return Ok(format!("ws://127.0.0.1:{port}{path}"));
            }
        }
        thread::sleep(Duration::from_millis(120));
    }
    Err("O Chrome não expôs a depuração em 25 s (DevToolsActivePort ausente). Nada foi capturado.".to_string())
}

fn wait_or_kill(child: &mut Child, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(_) => return,
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

struct Cdp {
    next_id: u64,
    session_id: String,
    events: Vec<String>,
    status: Arc<Mutex<CaptureStatus>>,
}

impl Cdp {
    fn connect(
        url: &str,
        status: Arc<Mutex<CaptureStatus>>,
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
                            session_id: String::new(),
                            events: Vec::new(),
                            status,
                        },
                    ));
                }
                Err(error) => {
                    last_error = error.to_string();
                    thread::sleep(Duration::from_millis(120));
                }
            }
        }
        Err(format!("Não foi possível conectar ao CDP local: {last_error}"))
    }

    fn setup(
        &mut self,
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
        start_url: &str,
    ) -> Result<(), String> {
        let created = self.send(
            socket,
            "Target.createTarget",
            json!({ "url": "about:blank" }),
            None,
            Duration::from_secs(10),
        )?;
        let target = created
            .get("targetId")
            .and_then(Value::as_str)
            .ok_or_else(|| "CDP não devolveu targetId".to_string())?
            .to_string();
        let attached = self.send(
            socket,
            "Target.attachToTarget",
            json!({ "targetId": target, "flatten": true }),
            None,
            Duration::from_secs(10),
        )?;
        self.session_id = attached
            .get("sessionId")
            .and_then(Value::as_str)
            .ok_or_else(|| "CDP não devolveu sessionId".to_string())?
            .to_string();
        let session = Some(self.session_id.clone());
        self.send(socket, "Page.enable", json!({}), session.as_deref(), Duration::from_secs(10))?;
        self.send(
            socket,
            "Network.enable",
            json!({
                "maxTotalBufferSize": 100_000_000,
                "maxResourceBufferSize": 50_000_000,
                "maxPostDataSize": 5_000_000
            }),
            session.as_deref(),
            Duration::from_secs(10),
        )?;
        self.send(
            socket,
            "Network.setCacheDisabled",
            json!({ "cacheDisabled": true }),
            session.as_deref(),
            Duration::from_secs(5),
        )?;
        self.send(
            socket,
            "Network.setBypassServiceWorker",
            json!({ "bypass": true }),
            session.as_deref(),
            Duration::from_secs(5),
        )?;
        if !start_url.trim().is_empty() && start_url != "about:blank" {
            self.send(
                socket,
                "Page.navigate",
                json!({ "url": start_url }),
                session.as_deref(),
                Duration::from_secs(10),
            )?;
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
                    self.record(&value, text.as_str());
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
    }

    fn record(&mut self, value: &Value, raw: &str) {
        let Some(method) = value.get("method").and_then(Value::as_str) else {
            return;
        };
        if !method.starts_with("Network.") {
            return;
        }
        self.events.push(raw.to_string());
        if let Ok(mut guard) = self.status.lock() {
            guard.events = self.events.len();
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

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let payload = join.join().expect("thread da captura").expect("captura importada");
        let requests = payload.session["requests"].as_array().map(Vec::len).unwrap_or(0);
        println!(
            "live capture: {} requisições, session_dir={:?}, notice={:?}",
            requests, payload.session_dir, payload.notice
        );
        assert!(requests > 0, "a captura precisa conter requisições reais");
        assert!(!payload.synthetic);
        println!(
            "session.json: {}",
            dir.join("session.json").display()
        );
    }
}
