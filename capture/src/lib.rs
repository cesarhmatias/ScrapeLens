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

pub mod allowlist;
pub mod browser;
pub mod chrome;

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

/// Resultado de uma captura encerrada: a sessão importada (JSON do
/// `session.json`), onde ela ficou em disco e o aviso para a UI.
#[derive(Debug, Clone)]
pub struct CaptureOutcome {
    pub session: Value,
    pub session_dir: PathBuf,
    pub notice: String,
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
) -> Result<CaptureOutcome, String> {
    run_with_options(config, status, stop, ready, &RunOptions::default()).map(|(outcome, _)| outcome)
}

/// Opções da captura controlada (`browser::BrowserCapture`). O padrão é a
/// captura comum do App, sem alteração de comportamento.
#[derive(Default)]
pub(crate) struct RunOptions {
    /// Allowlist obrigatória no modo controlado: troca a regra fixa de
    /// loopback do resolvedor pelas regras da lista.
    pub allowlist: Option<allowlist::Allowlist>,
    /// Comandos (navegar) consumidos pelo laço de gravação.
    pub control: Option<Receiver<browser::Control>>,
    /// Preenchido antes de `ready`: endereço de depuração e versão.
    pub endpoint: Option<Arc<Mutex<Option<browser::Endpoint>>>>,
    /// Só avisa `ready` (e só publica o endereço CDP) depois que o nosso
    /// cliente está ligado no alvo inicial: `Network.enable` e
    /// `Target.setAutoAttach` com ACK de sucesso e nada pendente nele. Assim um
    /// cliente externo que receba o endereço não consegue agir antes de nós.
    pub require_initial_target_ready: bool,
}

/// Dados do encerramento que o App não usa, mas o modo controlado devolve.
#[derive(Debug, Clone, Default)]
pub(crate) struct RunReport {
    pub allowlist: Option<allowlist::AllowlistReport>,
    pub requests: usize,
    pub netlog: String,
    pub graceful: bool,
    pub waited_ms: u64,
    pub warnings: Vec<String>,
}

pub(crate) fn run_with_options(
    config: CaptureConfig,
    status: Arc<Mutex<CaptureStatus>>,
    stop: Receiver<()>,
    ready: Sender<Result<(), String>>,
    opts: &RunOptions,
) -> Result<(CaptureOutcome, RunReport), String> {
    let outcome = run_inner(&config, &status, stop, &ready, opts);
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
    opts: &RunOptions,
) -> Result<(CaptureOutcome, RunReport), String> {
    let profile = std::env::temp_dir().join(format!(
        "scrapelens-chrome-{}-{}",
        std::process::id(),
        unix_nanos()
    ));
    std::fs::create_dir_all(&profile).map_err(|error| format!("perfil temporário: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o700));
    }

    // A pasta da sessão não pode ser um symlink: tudo que gravamos nela iria
    // para o alvo do link.
    if std::fs::symlink_metadata(&config.session_dir)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        let _ = std::fs::remove_dir_all(&profile);
        return Err(format!(
            "diretório da sessão é um symlink e foi recusado: {}",
            config.session_dir.display()
        ));
    }
    store::ensure_private_dir(&config.session_dir)
        .map_err(|error| format!("diretório da sessão: {error}"))?;
    let netlog_path = config.session_dir.join("netlog.json");
    let cdp_path = config.session_dir.join("cdp-events.jsonl");
    let bodies_path = config.session_dir.join("cdp-bodies.jsonl");
    let bodies_file =
        open_private(&bodies_path).map_err(|error| format!("cdp-bodies.jsonl: {error}"))?;
    // O Chrome escreve o NetLog sozinho: cria o arquivo antes (0600, sem seguir
    // um symlink plantado) para ele abrir um arquivo nosso, não o alvo do link.
    drop(open_private(&netlog_path).map_err(|error| format!("netlog.json: {error}"))?);

    let resolver_rules = opts.allowlist.as_ref().map(allowlist::Allowlist::resolver_rules);
    let mut chrome = ChromeProcess::new(spawn_chrome(
        config,
        &profile,
        &netlog_path,
        resolver_rules.as_deref(),
    )?);
    // Marcador para limpar órfãos se este processo morrer por SIGKILL; o Drop
    // o remove em qualquer saída normal (sucesso, erro ou panic).
    let marker = OrphanMarker::create(
        &default_state_root(),
        chrome.child_mut().id(),
        &profile,
        None,
    );
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

    marker.set_port(port_from_ws_url(&ws_url));
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
    if opts.require_initial_target_ready {
        if let Err(reason) = cdp.wait_initial_target_ready(&mut socket, Duration::from_secs(15)) {
            let error = format!("o cliente de captura não ficou ligado na aba inicial: {reason}");
            let _ = chrome.child_mut().kill();
            let _ = chrome.child_mut().wait();
            chrome.disarm();
            let _ = std::fs::remove_dir_all(&profile);
            let _ = ready.send(Err(error.clone()));
            return Err(error);
        }
    }
    if let Some(endpoint) = &opts.endpoint {
        // Versão do navegador e endereço de depuração, antes de avisar `ready`.
        let version = cdp
            .send(
                &mut socket,
                "Browser.getVersion",
                json!({}),
                None,
                Duration::from_secs(5),
            )
            .ok();
        if let Ok(mut guard) = endpoint.lock() {
            *guard = Some(browser::Endpoint {
                http: port_from_ws_url(&ws_url).map(|p| format!("http://127.0.0.1:{p}")),
                browser_ws: ws_url.clone(),
                chrome_pid: chrome.child_mut().id(),
                page_target_id: cdp
                    .setup_seen
                    .get(&cdp.page_session_id)
                    .map(|t| t.target_id.clone()),
                product: version
                    .as_ref()
                    .and_then(|v| v.get("product"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                user_agent: version
                    .as_ref()
                    .and_then(|v| v.get("userAgent"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
            });
        }
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
        if let Some(control) = &opts.control {
            while let Ok(message) = control.try_recv() {
                cdp.handle_control(&mut socket, message);
            }
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
    // Antes de fechar: dá uma janela curta para ACKs atrasados do setup e só
    // então transforma o que continua sem resposta em aviso.
    cdp.pump_until_setup_settled(&mut socket, Duration::from_millis(1500));
    cdp.finalize_pending_setups();
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
    // Allowlist: o que o resolvedor negou e o que escapou dela vira aviso da
    // sessão (visível para quem só lê a sessão) e relatório do `stop_capture`.
    let allowlist_report = opts
        .allowlist
        .as_ref()
        .map(|list| list.report_from_events(&cdp.events, &imported.bundle.session));
    let mut report_warnings: Vec<String> = Vec::new();
    if let Some(report) = &allowlist_report {
        for blocked in &report.blocked_hosts {
            let message = format!(
                "a página tentou carregar {} ({} requisição(ões)); bloqueado pela allowlist; a proteção ou o recurso pode estar escondido",
                blocked.host, blocked.requests
            );
            imported.bundle.session.add_warning(
                scrapelens_core::model::Warning::info("capture.third_party_blocked", message.clone())
                    .with_detail(json!({ "host": blocked.host, "requests": blocked.requests })),
            );
            report_warnings.push(message);
        }
        for violation in &report.violations {
            // `violation.url` já vem sem consulta, fragmento, `;params` e userinfo.
            let message = format!(
                "requisição fora da allowlist: {} ({})",
                violation.url, violation.reason
            );
            imported.bundle.session.add_warning(
                scrapelens_core::model::Warning::new("capture.allowlist_violation", message.clone())
                    .with_entity(violation.request_id.clone()),
            );
            report_warnings.push(message);
        }
    }
    store::write_session_dir(&imported.bundle, &config.session_dir)
        .map_err(|error| format!("Não foi possível gravar a sessão: {error}"))?;

    let session_value = serde_json::to_value(&imported.bundle.session)
        .map_err(|error| format!("Sessão inválida após importação: {error}"))?;
    let requests = imported.report.source_events_used;
    let warnings = imported.report.warnings.len();

    let report = RunReport {
        allowlist: allowlist_report,
        requests: imported.bundle.session.requests.len(),
        netlog: match &netlog_status {
            NetlogStatus::Complete => "complete".to_string(),
            NetlogStatus::Repaired { .. } => "repaired".to_string(),
            NetlogStatus::Unusable { .. } => "unusable".to_string(),
        },
        graceful: matches!(shutdown.exit, ChromeExit::Graceful(_)) && shutdown.browser_close.is_ok(),
        waited_ms: shutdown.waited_ms,
        warnings: report_warnings,
    };
    Ok((
        CaptureOutcome {
            session: session_value,
            session_dir: config.session_dir.clone(),
            notice: format!(
                "Sessão capturada e importada: {} evento(s) CDP+NetLog usados, {} aviso(s).",
                requests, warnings
            ),
        },
        report,
    ))
}

fn spawn_chrome(
    config: &CaptureConfig,
    profile: &Path,
    netlog: &Path,
    resolver_rules: Option<&str>,
) -> Result<Child, String> {
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
        "--disable-popup-blocking".to_string(),
        "about:blank".to_string(),
    ];
    match resolver_rules {
        // Captura controlada: só os hosts da allowlist resolvem; nenhum
        // relaxamento de certificado.
        Some(rules) => args.insert(args.len() - 1, format!("--host-resolver-rules={rules}")),
        // Captura comum do App (testes em loopback): comportamento de sempre.
        None => {
            args.insert(args.len() - 1, "--allow-insecure-localhost".to_string());
            args.insert(
                args.len() - 1,
                "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost"
                    .to_string(),
            );
        }
    }
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

// ---------------------------------------------------------------------------
// Órfãos: Chrome e perfil temporário deixados por um SIGKILL do app.
// ---------------------------------------------------------------------------

const MARKER_PREFIX: &str = "capture-";
const PROFILE_PREFIX: &str = "scrapelens-chrome-";

/// Raiz de estado dos marcadores de captura (por usuário; o `temp_dir` do macOS
/// já é privado ao usuário). O App chama `cleanup_orphans(&default_state_root())`.
pub fn default_state_root() -> PathBuf {
    std::env::temp_dir().join("scrapelens-capture-state")
}

fn port_from_ws_url(url: &str) -> Option<u16> {
    let rest = url.split("://").nth(1)?;
    let host_port = rest.split('/').next()?;
    host_port.rsplit(':').next()?.parse().ok()
}

/// Marcador 0600 com o que é preciso para limpar uma captura abandonada.
struct OrphanMarker {
    path: Option<PathBuf>,
    chrome_pid: u32,
    profile: PathBuf,
}

impl OrphanMarker {
    fn create(root: &Path, chrome_pid: u32, profile: &Path, port: Option<u16>) -> Self {
        let mut marker = Self {
            path: None,
            chrome_pid,
            profile: profile.to_path_buf(),
        };
        if store::ensure_private_dir(root).is_ok() {
            let path = root.join(format!(
                "{MARKER_PREFIX}{}-{}.json",
                std::process::id(),
                unix_nanos()
            ));
            marker.path = Some(path);
            marker.write(port);
        }
        marker
    }

    fn write(&self, port: Option<u16>) {
        let Some(path) = &self.path else { return };
        let body = json!({
            "ownerPid": std::process::id(),
            "chromePid": self.chrome_pid,
            "profile": self.profile.display().to_string(),
            "port": port,
        });
        let _ = write_private(path, body.to_string().as_bytes());
    }

    fn set_port(&self, port: Option<u16>) {
        self.write(port);
    }
}

impl Drop for OrphanMarker {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Linha de comando do processo, ou `None` se ele não existe.
fn process_command(pid: u32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (output.status.success() && !text.is_empty()).then_some(text)
}

fn process_exists(pid: u32) -> bool {
    Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "pid="])
        .output()
        .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false)
}

fn signal(pid: u32, name: &str) {
    let _ = Command::new("kill")
        .args([name, &pid.to_string()])
        .stderr(Stdio::null())
        .status();
}

/// Pids cuja linha de comando contém exatamente `--user-data-dir=<profile>`
/// (o Chrome dedicado e seus auxiliares).
fn pids_using_profile(profile_flag: &str) -> Vec<u32> {
    let Ok(output) = Command::new("ps").args(["-axo", "pid=,command="]).output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let (pid, command) = line.split_once(char::is_whitespace)?;
            let pid: u32 = pid.parse().ok()?;
            (command.contains(profile_flag) && pid != std::process::id()).then_some(pid)
        })
        .collect()
}

/// Só apaga perfis que este módulo cria: dentro do `temp_dir` e com o prefixo
/// do app. Um marcador adulterado não consegue apontar para outro diretório.
fn is_app_profile(profile: &Path) -> bool {
    profile.parent() == Some(std::env::temp_dir().as_path())
        && profile
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(PROFILE_PREFIX))
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OrphanCleanup {
    /// Marcadores de capturas abandonadas que foram removidos.
    pub markers_removed: usize,
    /// Processos Chrome encerrados (só os que ainda usavam o perfil do marcador).
    pub processes_killed: usize,
    /// Perfis temporários apagados.
    pub profiles_removed: usize,
}

/// Limpa capturas abandonadas por um app que morreu sem encerrar o Chrome.
/// Para cada marcador em `state_root` cujo processo dono não existe mais:
/// encerra o Chrome do marcador somente se a linha de comando do PID ainda
/// contém o perfil dedicado (nunca um PID reaproveitado ou o Chrome do
/// usuário), apaga o perfil temporário do app e o marcador. Marcador de dono
/// vivo (inclusive este processo) não é tocado.
pub fn cleanup_orphans(state_root: &Path) -> OrphanCleanup {
    let mut report = OrphanCleanup::default();
    let Ok(entries) = std::fs::read_dir(state_root) else {
        return report;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_marker = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(MARKER_PREFIX) && n.ends_with(".json"));
        if !is_marker || path.is_symlink() {
            continue;
        }
        let Some(value) = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        else {
            continue;
        };
        let (Some(owner), Some(chrome_pid), Some(profile)) = (
            value.get("ownerPid").and_then(Value::as_u64),
            value.get("chromePid").and_then(Value::as_u64),
            value.get("profile").and_then(Value::as_str),
        ) else {
            continue;
        };
        let (owner, chrome_pid, profile) = (owner as u32, chrome_pid as u32, PathBuf::from(profile));
        if process_exists(owner) {
            continue;
        }
        if !is_app_profile(&profile) {
            // Marcador que não é nosso: some só o marcador, nada mais é tocado.
            let _ = std::fs::remove_file(&path);
            report.markers_removed += 1;
            continue;
        }
        let profile_flag = format!("--user-data-dir={}", profile.display());
        let ours = |pid: u32| process_command(pid).is_some_and(|c| c.contains(&profile_flag));
        let mut targets: Vec<u32> = Vec::new();
        if ours(chrome_pid) {
            targets.push(chrome_pid);
        }
        // Auxiliares do mesmo Chrome (renderers etc.) só entram se o principal era nosso.
        if !targets.is_empty() {
            for pid in pids_using_profile(&profile_flag) {
                if !targets.contains(&pid) {
                    targets.push(pid);
                }
            }
        }
        for pid in &targets {
            if ours(*pid) {
                signal(*pid, "-TERM");
            }
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && targets.iter().any(|p| ours(*p)) {
            thread::sleep(Duration::from_millis(100));
        }
        for pid in &targets {
            if ours(*pid) {
                signal(*pid, "-KILL");
            }
        }
        report.processes_killed += targets.len();
        if profile.exists() && std::fs::remove_dir_all(&profile).is_ok() {
            report.profiles_removed += 1;
        }
        let _ = std::fs::remove_file(&path);
        report.markers_removed += 1;
    }
    report
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
    "Capture.targetSetupAborted",
    "Capture.targetSetupError",
    "Target.targetDestroyed",
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
    /// Sessões que já passaram por `setup_attached_target` (comandos enviados).
    configured_sessions: std::collections::HashSet<String>,
    configured_target_primary: HashMap<String, String>,
    detached_sessions: std::collections::HashSet<String>,
    wait_for_debugger: bool,
    /// Alvos vistos via auto-attach (qualquer momento), por sessão.
    setup_seen: HashMap<String, AttachedTarget>,
    /// Comandos de setup enviados e ainda sem resposta, por id CDP. O setup
    /// nunca bloqueia: a resposta é tratada por `record` na ordem de chegada,
    /// por quem estiver lendo o socket.
    setup_pending: HashMap<u64, PendingSetupCommand>,
    /// `Page.loadEventFired` vistos na sessão da página principal.
    page_load_events: u64,
    /// ACKs de sucesso de comandos de setup, por (sessão, método).
    setup_acked: std::collections::HashSet<(String, String)>,
}

/// Comando de configuração de alvo aguardando ACK.
#[derive(Debug, Clone)]
struct PendingSetupCommand {
    target: AttachedTarget,
    method: String,
    sent_at: Instant,
    parent_session_id: Option<String>,
}

impl Cdp {
    fn new(status: Arc<Mutex<CaptureStatus>>, bodies_file: std::fs::File) -> Result<Self, String> {
        Ok(Self {
            next_id: 0,
            page_session_id: String::new(),
            events: Vec::new(),
            status,
            bodies_by_session: HashMap::new(),
            bodies_file: bodies_file
                .try_clone()
                .map_err(|error| format!("cdp-bodies.jsonl: {error}"))?,
            in_flight: HashMap::new(),
            outbox: Vec::new(),
            setup_done: HashMap::new(),
            configured_sessions: std::collections::HashSet::new(),
            configured_target_primary: HashMap::new(),
            detached_sessions: std::collections::HashSet::new(),
            wait_for_debugger: true,
            setup_seen: HashMap::new(),
            setup_pending: HashMap::new(),
            page_load_events: 0,
            setup_acked: std::collections::HashSet::new(),
        })
    }

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
                    return Self::new(status, bodies_file).map(|cdp| (socket, cdp));
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

    /// Envia um comando de setup sem esperar a resposta e registra-o como
    /// pendente. Resposta atrasada não gera aviso: só o que continuar sem ACK
    /// no encerramento vira `Capture.targetSetupTimeout`.
    fn wire_setup_command(
        &mut self,
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
        target: &AttachedTarget,
        method: &str,
        params: Value,
        parent_session_id: Option<&str>,
    ) -> Result<(), String> {
        let id = self.wire_command(socket, method, params, Some(&target.session_id))?;
        self.register_setup_command(id, target, method, parent_session_id);
        Ok(())
    }

    fn register_setup_command(
        &mut self,
        id: u64,
        target: &AttachedTarget,
        method: &str,
        parent_session_id: Option<&str>,
    ) {
        self.setup_pending.insert(
            id,
            PendingSetupCommand {
                target: target.clone(),
                method: method.to_string(),
                sent_at: Instant::now(),
                parent_session_id: parent_session_id.map(str::to_string),
            },
        );
    }

    /// Trata o ACK de um comando de setup. Devolve `true` se o id era de setup.
    /// ACK atrasado só remove o pendente; erro de comando essencial vira
    /// `Capture.targetSetupError` (diferente de "sem resposta").
    fn on_setup_response(&mut self, id: u64, value: &Value) -> bool {
        let Some(pending) = self.setup_pending.remove(&id) else {
            return false;
        };
        if value.get("error").is_none() {
            self.setup_acked
                .insert((pending.target.session_id.clone(), pending.method.clone()));
        }
        if let Some(error) = value.get("error") {
            let text = error
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| error.to_string());
            let gone = text.contains("not found") || text.contains("Target closed");
            if gone {
                self.push_target_setup_aborted(&pending.target, pending.parent_session_id.as_deref());
            } else if matches!(
                pending.method.as_str(),
                "Network.enable" | "Target.setAutoAttach" | "Runtime.runIfWaitingForDebugger"
            ) {
                self.push_event_line(
                    &pending.target.session_id,
                    "Capture.targetSetupError",
                    &json!({
                        "targetId": pending.target.target_id,
                        "sessionId": pending.target.session_id,
                        "type": pending.target.target_type,
                        "command": pending.method,
                        "error": text,
                    }),
                    pending.parent_session_id.as_deref(),
                );
            }
        }
        true
    }

    /// O nosso cliente está ligado no alvo inicial? (`Network.enable` e
    /// `Target.setAutoAttach` com ACK de sucesso, nenhum comando de setup
    /// pendente e a sessão configurada.) Erro = o que ainda falta.
    pub(crate) fn initial_target_gate(&self) -> Result<(), String> {
        let page = &self.page_session_id;
        if page.is_empty() {
            return Err("a aba inicial ainda não anexou".to_string());
        }
        if !self.configured_sessions.contains(page) {
            return Err("a aba inicial ainda não foi configurada".to_string());
        }
        if let Some(pending) = self.setup_pending.values().find(|p| &p.target.session_id == page) {
            return Err(format!("{} ainda sem resposta na aba inicial", pending.method));
        }
        for method in ["Network.enable", "Target.setAutoAttach"] {
            if !self.setup_acked.contains(&(page.clone(), method.to_string())) {
                return Err(format!("{method} sem confirmação na aba inicial"));
            }
        }
        Ok(())
    }

    /// Lê o soquete até o portão abrir ou o prazo acabar.
    fn wait_initial_target_ready(
        &mut self,
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
        timeout: Duration,
    ) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.initial_target_gate() {
                Ok(()) => return Ok(()),
                Err(reason) if Instant::now() >= deadline => return Err(reason),
                Err(_) => self.pump_socket(socket, Duration::from_millis(100)),
            }
        }
    }

    /// Alvo desanexado ou destruído: comandos pendentes dele não viram timeout.
    fn on_target_gone(&mut self, session_id: Option<&str>, target_id: Option<&str>) {
        let gone: Vec<u64> = self
            .setup_pending
            .iter()
            .filter(|(_, p)| {
                session_id.is_some_and(|s| p.target.session_id == s)
                    || target_id.is_some_and(|t| p.target.target_id == t)
            })
            .map(|(id, _)| *id)
            .collect();
        let mut seen = std::collections::HashSet::new();
        for id in gone {
            if let Some(pending) = self.setup_pending.remove(&id) {
                if seen.insert(pending.target.session_id.clone()) {
                    self.push_target_setup_aborted(
                        &pending.target,
                        pending.parent_session_id.as_deref(),
                    );
                }
            }
        }
    }

    fn push_target_setup_aborted(
        &mut self,
        attached: &AttachedTarget,
        parent_session_id: Option<&str>,
    ) {
        self.push_event_line(
            &attached.session_id,
            "Capture.targetSetupAborted",
            &json!({
                "targetId": attached.target_id,
                "sessionId": attached.session_id,
                "type": attached.target_type,
                "reason": "alvo encerrado durante a configuração",
            }),
            parent_session_id,
        );
    }

    /// Encerramento (antes do `Browser.close`): todo comando de setup ainda sem
    /// ACK, em qualquer sessão (inclusive a primária), vira aviso real.
    fn finalize_pending_setups(&mut self) {
        let mut pending: Vec<(u64, PendingSetupCommand)> = self.setup_pending.drain().collect();
        pending.sort_by_key(|(id, _)| *id);
        for (_, p) in pending {
            self.push_event_line(
                &p.target.session_id,
                "Capture.targetSetupTimeout",
                &json!({
                    "targetId": p.target.target_id,
                    "sessionId": p.target.session_id,
                    "type": p.target.target_type,
                    "command": p.method,
                    "pendingMs": p.sent_at.elapsed().as_millis() as u64,
                    "warningCode": CDP_TARGET_SETUP_TIMEOUT_WARNING,
                }),
                p.parent_session_id.as_deref(),
            );
        }
    }

    /// Lê o socket até não restar setup pendente ou esgotar `window`.
    fn pump_until_setup_settled(
        &mut self,
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
        window: Duration,
    ) {
        let deadline = Instant::now() + window;
        while !self.setup_pending.is_empty() && Instant::now() < deadline {
            self.pump_socket(socket, Duration::from_millis(100));
        }
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
        // Sessão extra do mesmo alvo: retoma (se pausada) e desanexa, sem rede.
        // Os ACKs não importam: nada aqui é setup de captura.
        if self.wait_for_debugger && waiting_for_debugger {
            self.wire_command(
                socket,
                "Runtime.runIfWaitingForDebugger",
                json!({}),
                Some(&attached.session_id),
            )?;
        }
        self.wire_command(
            socket,
            "Target.detachFromTarget",
            json!({ "sessionId": attached.session_id }),
            None,
        )?;
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

    /// Configura um alvo anexado sem bloquear: envia os comandos em pipeline,
    /// na mesma sessão, e deixa os ACKs para quem ler o socket (`record`).
    /// Alvo pausado: Network.enable → Page/Runtime.enable → setAutoAttach →
    /// runIfWaitingForDebugger (a rede já está ligada quando ele retoma, e o
    /// resume não espera resposta). Alvo não pausado: ordem do harness
    /// (setAutoAttach → Network.enable → Page/Runtime.enable).
    fn setup_attached_target(
        &mut self,
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
        attached: AttachedTarget,
        waiting_for_debugger: bool,
        parent_session_id: Option<&str>,
    ) -> Result<(), String> {
        match self.configured_target_primary.get(&attached.target_id) {
            Some(primary) if primary != &attached.session_id => {
                return self.setup_duplicate_target_session(
                    socket,
                    attached,
                    waiting_for_debugger,
                    parent_session_id,
                );
            }
            None if !Self::skip_target_setup(&attached.target_type) => {
                self.configured_target_primary.insert(
                    attached.target_id.clone(),
                    attached.session_id.clone(),
                );
            }
            _ => {}
        }
        if self.configured_sessions.contains(&attached.session_id) {
            return Ok(());
        }
        // Marca antes de enviar: evita reentrada se o envio falhar.
        self.configured_sessions
            .insert(attached.session_id.clone());
        self.setup_seen
            .insert(attached.session_id.clone(), attached.clone());
        let target_type = attached.target_type.clone();
        let resume = self.wait_for_debugger && waiting_for_debugger;
        if Self::skip_target_setup(&target_type) {
            if resume {
                self.wire_command(
                    socket,
                    "Runtime.runIfWaitingForDebugger",
                    json!({}),
                    Some(&attached.session_id),
                )?;
            }
            self.setup_done
                .insert(attached.session_id.clone(), attached.clone());
            self.push_event_line(
                &attached.session_id,
                "Capture.sessionSetup",
                &json!({
                    "targetId": attached.target_id,
                    "type": target_type,
                    "waitingForDebugger": waiting_for_debugger,
                    "resumedDebugger": resume,
                    "skippedNetwork": true,
                }),
                parent_session_id,
            );
            return Ok(());
        }
        let network_params = json!({
            "maxTotalBufferSize": 100_000_000,
            "maxResourceBufferSize": 50_000_000,
            "maxPostDataSize": MAX_BODY_BYTES
        });
        let recurse = Self::recurse_auto_attach(&target_type);
        let page_like = target_type == "page" || target_type == "iframe";
        let parent = parent_session_id;
        let auto_attach = self.auto_attach_params(true);
        let mut commands: Vec<(&str, Value)> = Vec::new();
        if resume {
            commands.push(("Network.enable", network_params));
            if page_like {
                commands.push(("Page.enable", json!({})));
            }
            commands.push(("Runtime.enable", json!({})));
            if recurse {
                commands.push(("Target.setAutoAttach", auto_attach));
            }
            commands.push(("Runtime.runIfWaitingForDebugger", json!({})));
        } else {
            if recurse {
                commands.push(("Target.setAutoAttach", auto_attach));
            }
            commands.push(("Network.enable", network_params));
            if page_like {
                commands.push(("Page.enable", json!({})));
            }
            commands.push(("Runtime.enable", json!({})));
        }
        for (method, params) in commands {
            self.wire_setup_command(socket, &attached, method, params, parent)?;
        }
        self.setup_done
            .insert(attached.session_id.clone(), attached.clone());
        self.push_event_line(
            &attached.session_id,
            "Capture.sessionSetup",
            &json!({
                "targetId": attached.target_id,
                "type": target_type,
                "waitingForDebugger": waiting_for_debugger,
                "resumedDebugger": resume,
                "pipelinedSetup": true,
                "recursiveAutoAttach": recurse,
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
        if method == "Target.detachedFromTarget" {
            let session_id = value
                .get("params")
                .and_then(|p| p.get("sessionId"))
                .and_then(Value::as_str);
            self.on_target_gone(session_id, None);
        }
        if method == "Page.loadEventFired"
            && !self.page_session_id.is_empty()
            && value.get("sessionId").and_then(Value::as_str) == Some(self.page_session_id.as_str())
        {
            self.page_load_events += 1;
        }
        if method == "Target.targetDestroyed" {
            let target_id = value
                .get("params")
                .and_then(|p| p.get("targetId"))
                .and_then(Value::as_str);
            self.on_target_gone(None, target_id);
        }
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
                if !Self::skip_target_setup(&target_type) {
                    self.configured_target_primary
                        .entry(target_id.clone())
                        .or_insert(session_id.clone());
                }
                let parent_wire = value.get("sessionId").and_then(Value::as_str);
                self.setup_seen
                    .insert(session_id.clone(), attached.clone());
                // Não bloqueia: só envia os comandos. Falha de envio (socket)
                // aparece como erro de leitura no laço de captura.
                let _ = self.setup_attached_target(socket, attached, waiting, parent_wire);
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

    fn setup(
        &mut self,
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
        start_url: &str,
    ) -> Result<(), String> {
        let setup_result = self.setup_inner(socket, start_url);
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
            if let Some(page_session) = self
                .setup_seen
                .values()
                .find(|t| t.target_id == main_target && t.target_type == "page")
                .map(|t| t.session_id.clone())
            {
                self.page_session_id = page_session.clone();
                if !self.configured_sessions.contains(&page_session) {
                    // O handler normalmente já configurou a página no attach;
                    // este ramo cobre só um attach que o handler não viu.
                    self.setup_attached_target(
                        socket,
                        AttachedTarget {
                            session_id: page_session.clone(),
                            target_id: main_target.clone(),
                            target_type: "page".to_string(),
                        },
                        false,
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
    }

    fn record(
        &mut self,
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
        value: &Value,
    ) {
        if let Some(id) = value.get("id").and_then(Value::as_u64) {
            if self.on_setup_response(id, value) {
                return;
            }
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

/// Escrita atômica e segura contra symlink: grava num arquivo novo de nome
/// único (`create_new` + `O_NOFOLLOW`, 0600) na mesma pasta e troca o destino com
/// `rename`, que substitui o próprio symlink (nunca escreve no alvo dele).
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("arquivo");
    let tmp = path.with_file_name(format!(".{name}.tmp-{}-{}", std::process::id(), unix_nanos()));
    let result = (|| {
        let mut file = open_new_private(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Cria um arquivo NOVO 0600 sem seguir symlink: `create_new` (O_EXCL) e
/// `O_NOFOLLOW`. Falha se o nome já existir (inclusive como symlink).
fn open_new_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

/// Abre o arquivo para escrita como NOVO, sem seguir symlink. Se o nome já
/// existir (arquivo antigo ou symlink plantado), REMOVE o nome (o link, nunca o
/// alvo) e cria de novo; uma corrida em que alguém replante o nome faz o
/// `create_new` falhar em vez de escrever fora.
fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    match open_new_private(path) {
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            std::fs::remove_file(path)?;
            open_new_private(path)
        }
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Corpos (docs/08-corpos-busca.md §1): coleta sem bloquear o loop de eventos.
// ---------------------------------------------------------------------------

/// Limite por corpo (bytes decodificados).
const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;
/// Orçamento total de corpos gravados por sessão.
const SESSION_BODY_BUDGET: usize = 256 * 1024 * 1024;

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

#[cfg(test)]
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

    fn test_cdp() -> Cdp {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "scrapelens-setup-test-{}-{}-{}.jsonl",
            std::process::id(),
            unix_nanos(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        let file = open_private(&path).unwrap();
        let cdp = Cdp::new(Arc::new(Mutex::new(CaptureStatus::default())), file).unwrap();
        let _ = std::fs::remove_file(&path);
        cdp
    }

    fn sw_target() -> AttachedTarget {
        AttachedTarget {
            session_id: "S1".into(),
            target_id: "T1".into(),
            target_type: "service_worker".into(),
        }
    }

    fn event_methods(cdp: &Cdp) -> Vec<String> {
        cdp.events
            .iter()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter_map(|v| v.get("method").and_then(Value::as_str).map(str::to_string))
            .collect()
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "scrapelens-fs-{tag}-{}-{}",
            std::process::id(),
            unix_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn open_private_does_not_follow_a_planted_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = scratch_dir("open");
        let outside = dir.join("FORA.txt");
        std::fs::write(&outside, "ORIGINAL\n").unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = dir.join("cdp-bodies.jsonl");
        symlink(&outside, &link).unwrap();
        let mut file = open_private(&link).unwrap();
        file.write_all(b"DADOS\n").unwrap();
        drop(file);
        // O alvo do link não foi tocado nem teve o modo alterado.
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "ORIGINAL\n");
        assert_eq!(std::fs::metadata(&outside).unwrap().permissions().mode() & 0o777, 0o644);
        // O nome virou um arquivo regular 0600 com os dados.
        let meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(meta.file_type().is_file() && !meta.file_type().is_symlink());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "DADOS\n");
        // `create_new` puro recusa o nome existente (inclusive symlink).
        assert!(open_new_private(&link).is_err());
        let dangling = dir.join("pendurado");
        symlink(dir.join("nao-existe"), &dangling).unwrap();
        assert!(open_new_private(&dangling).is_err(), "O_NOFOLLOW/O_EXCL recusa symlink");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_private_replaces_a_symlink_without_touching_its_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = scratch_dir("atomic");
        let outside = dir.join("FORA.txt");
        std::fs::write(&outside, "ORIGINAL\n").unwrap();
        let dest = dir.join("cdp-events.jsonl");
        symlink(&outside, &dest).unwrap();
        write_private(&dest, b"{\"method\":\"x\"}\n").unwrap();
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "ORIGINAL\n");
        let meta = std::fs::symlink_metadata(&dest).unwrap();
        assert!(meta.file_type().is_file());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "{\"method\":\"x\"}\n");
        // Nenhum temporário sobra.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_session_dir_that_is_a_symlink_is_refused_before_anything_runs() {
        let dir = scratch_dir("sessiondir");
        let real = dir.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = dir.join("sessao");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let (_stop_tx, stop_rx) = std::sync::mpsc::channel();
        let (ready_tx, _ready_rx) = std::sync::mpsc::channel();
        let config = CaptureConfig {
            chrome: PathBuf::from("/nao/roda/nada"),
            session_dir: link,
            start_url: String::new(),
            headless: true,
            ignore_cert: false,
        };
        let status = Arc::new(Mutex::new(CaptureStatus::default()));
        let error = run(config, status, stop_rx, ready_tx).unwrap_err();
        assert!(error.contains("symlink"), "{error}");
        assert!(std::fs::read_dir(&real).unwrap().next().is_none(), "nada pode ter sido gravado");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn initial_target_gate_requires_acked_network_enable_and_auto_attach() {
        let target = |session: &str| AttachedTarget {
            session_id: session.into(),
            target_id: format!("T-{session}"),
            target_type: "page".into(),
        };
        let mut cdp = test_cdp();
        assert!(cdp.initial_target_gate().unwrap_err().contains("não anexou"));
        cdp.page_session_id = "P".into();
        assert!(cdp.initial_target_gate().unwrap_err().contains("não foi configurada"));
        cdp.configured_sessions.insert("P".into());
        assert!(cdp
            .initial_target_gate()
            .unwrap_err()
            .contains("Network.enable sem confirmação"));
        // Comandos enviados, ACK ainda não chegou: portão fechado.
        cdp.register_setup_command(1, &target("P"), "Network.enable", None);
        cdp.register_setup_command(2, &target("P"), "Target.setAutoAttach", None);
        assert!(cdp.initial_target_gate().unwrap_err().contains("ainda sem resposta"));
        cdp.on_setup_response(1, &json!({ "id": 1, "result": {} }));
        assert!(cdp.initial_target_gate().is_err(), "falta o setAutoAttach");
        // Pendência de OUTRA sessão não segura o portão.
        cdp.register_setup_command(3, &target("W"), "Network.enable", None);
        cdp.on_setup_response(2, &json!({ "id": 2, "result": {} }));
        assert_eq!(cdp.initial_target_gate(), Ok(()));
    }

    #[test]
    fn initial_target_gate_stays_closed_when_network_enable_fails() {
        let target = AttachedTarget {
            session_id: "P".into(),
            target_id: "T".into(),
            target_type: "page".into(),
        };
        let mut cdp = test_cdp();
        cdp.page_session_id = "P".into();
        cdp.configured_sessions.insert("P".into());
        cdp.register_setup_command(1, &target, "Network.enable", None);
        cdp.register_setup_command(2, &target, "Target.setAutoAttach", None);
        cdp.on_setup_response(1, &json!({ "id": 1, "error": { "message": "boom" } }));
        cdp.on_setup_response(2, &json!({ "id": 2, "result": {} }));
        let reason = cdp.initial_target_gate().unwrap_err();
        assert!(reason.contains("Network.enable sem confirmação"), "{reason}");
    }

    #[test]
    fn late_setup_ack_produces_no_warning() {
        let mut cdp = test_cdp();
        cdp.register_setup_command(7, &sw_target(), "Network.enable", None);
        // ACK chega depois (atrasado), antes do encerramento.
        assert!(cdp.on_setup_response(7, &json!({ "id": 7, "result": {} })));
        cdp.finalize_pending_setups();
        assert!(event_methods(&cdp).is_empty(), "{:?}", event_methods(&cdp));
        // Id desconhecido não é de setup.
        assert!(!cdp.on_setup_response(99, &json!({ "id": 99, "result": {} })));
    }

    #[test]
    fn missing_ack_at_shutdown_warns_even_on_primary_session() {
        let mut cdp = test_cdp();
        let target = sw_target();
        cdp.configured_target_primary
            .insert(target.target_id.clone(), target.session_id.clone());
        cdp.register_setup_command(3, &target, "Target.setAutoAttach", Some("ROOT"));
        cdp.register_setup_command(4, &target, "Network.enable", None);
        assert!(cdp.on_setup_response(4, &json!({ "id": 4, "result": {} })));
        cdp.finalize_pending_setups();
        let lines: Vec<Value> = cdp
            .events
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["method"], "Capture.targetSetupTimeout");
        assert_eq!(lines[0]["params"]["command"], "Target.setAutoAttach");
        assert_eq!(lines[0]["params"]["type"], "service_worker");
        assert!(lines[0]["params"]["pendingMs"].is_u64());
        assert_eq!(lines[0]["parentSessionId"], "ROOT");
        assert!(cdp.setup_pending.is_empty());
    }

    #[test]
    fn target_destroyed_before_ack_is_aborted_not_timeout() {
        let mut cdp = test_cdp();
        let target = sw_target();
        cdp.register_setup_command(1, &target, "Network.enable", None);
        cdp.register_setup_command(2, &target, "Runtime.enable", None);
        cdp.on_target_gone(Some("S1"), None);
        cdp.finalize_pending_setups();
        assert_eq!(event_methods(&cdp), vec!["Capture.targetSetupAborted"]);
        let line: Value = serde_json::from_str(&cdp.events[0]).unwrap();
        assert_eq!(
            line["params"]["reason"],
            "alvo encerrado durante a configuração"
        );

        let mut cdp = test_cdp();
        cdp.register_setup_command(1, &target, "Network.enable", None);
        cdp.on_target_gone(None, Some("T1"));
        cdp.finalize_pending_setups();
        assert_eq!(event_methods(&cdp), vec!["Capture.targetSetupAborted"]);
    }

    #[test]
    fn setup_command_error_is_not_reported_as_no_response() {
        let mut cdp = test_cdp();
        let target = sw_target();
        // Page.enable não suportado: ignorado. Network.enable com erro real: evento próprio.
        cdp.register_setup_command(1, &target, "Page.enable", None);
        cdp.register_setup_command(2, &target, "Network.enable", None);
        cdp.register_setup_command(3, &target, "Runtime.enable", None);
        assert!(cdp.on_setup_response(1, &json!({ "id": 1, "error": { "message": "'Page.enable' wasn't found" } })));
        assert!(cdp.on_setup_response(2, &json!({ "id": 2, "error": { "message": "boom" } })));
        // Sessão sumiu: aborto, não timeout.
        assert!(cdp.on_setup_response(3, &json!({ "id": 3, "error": { "message": "Session with given id not found." } })));
        cdp.finalize_pending_setups();
        assert_eq!(
            event_methods(&cdp),
            vec!["Capture.targetSetupError", "Capture.targetSetupAborted"]
        );
    }

    // --- limpeza de órfãos -------------------------------------------------

    fn orphan_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "scrapelens-orphan-test-{tag}-{}-{}",
            std::process::id(),
            unix_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn app_profile(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "{PROFILE_PREFIX}test-{tag}-{}-{}",
            std::process::id(),
            unix_millis()
        ));
        std::fs::create_dir_all(dir.join("Default")).unwrap();
        dir
    }

    fn dead_pid() -> u32 {
        let mut child = Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        assert!(!process_exists(pid));
        pid
    }

    fn write_marker(root: &Path, name: &str, owner: u32, chrome: u32, profile: &Path) -> PathBuf {
        let path = root.join(format!("{MARKER_PREFIX}{name}.json"));
        let body = json!({
            "ownerPid": owner,
            "chromePid": chrome,
            "profile": profile.display().to_string(),
            "port": 9999,
        });
        write_private(&path, body.to_string().as_bytes()).unwrap();
        path
    }

    #[test]
    fn orphan_with_dead_pids_is_cleaned() {
        let root = orphan_root("dead");
        let profile = app_profile("dead");
        let marker = write_marker(&root, "a", dead_pid(), dead_pid(), &profile);
        let report = cleanup_orphans(&root);
        assert_eq!(report.markers_removed, 1);
        assert_eq!(report.processes_killed, 0);
        assert!(!profile.exists());
        assert!(!marker.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn live_pid_with_foreign_command_line_is_not_touched() {
        let root = orphan_root("foreign");
        let profile = app_profile("foreign");
        // Processo vivo cuja linha de comando NÃO contém o perfil (PID "reaproveitado").
        let mut other = Command::new("sleep").arg("30").spawn().unwrap();
        let marker = write_marker(&root, "b", dead_pid(), other.id(), &profile);
        let report = cleanup_orphans(&root);
        assert_eq!(report.processes_killed, 0);
        assert!(
            other.try_wait().unwrap().is_none(),
            "processo alheio foi encerrado"
        );
        assert!(process_exists(other.id()));
        // O perfil e o marcador do app são limpos mesmo assim.
        assert!(!profile.exists());
        assert!(!marker.exists());
        let _ = other.kill();
        let _ = other.wait();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn live_pid_using_the_dedicated_profile_is_terminated() {
        let root = orphan_root("ours");
        let profile = app_profile("ours");
        // Stand-in do Chrome: a linha de comando carrega o perfil dedicado.
        let mut fake = Command::new("sh")
            .args(["-c", "sleep 30; true", "fake-chrome"])
            .arg(format!("--user-data-dir={}", profile.display()))
            .spawn()
            .unwrap();
        let marker = write_marker(&root, "c", dead_pid(), fake.id(), &profile);
        let report = cleanup_orphans(&root);
        assert!(report.processes_killed >= 1);
        let exited = (0..30).any(|_| {
            if fake.try_wait().unwrap().is_some() {
                return true;
            }
            thread::sleep(Duration::from_millis(100));
            false
        });
        assert!(exited, "o Chrome do perfil dedicado devia ter sido encerrado");
        assert!(!profile.exists());
        assert!(!marker.exists());
        let _ = fake.kill();
        let _ = fake.wait();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn marker_of_a_live_owner_is_left_alone() {
        let root = orphan_root("alive");
        let profile = app_profile("alive");
        let marker = write_marker(&root, "d", std::process::id(), dead_pid(), &profile);
        let report = cleanup_orphans(&root);
        assert_eq!(report, OrphanCleanup::default());
        assert!(profile.exists());
        assert!(marker.exists());
        let _ = std::fs::remove_dir_all(&profile);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn marker_pointing_outside_app_profiles_never_deletes_the_directory() {
        let root = orphan_root("foreign-dir");
        let victim = orphan_root("victim");
        std::fs::write(victim.join("keep.txt"), b"x").unwrap();
        let marker = write_marker(&root, "e", dead_pid(), dead_pid(), &victim);
        cleanup_orphans(&root);
        assert!(victim.join("keep.txt").exists());
        assert!(!marker.exists());
        let _ = std::fs::remove_dir_all(&victim);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn orphan_marker_is_private_and_removed_on_drop() {
        let root = orphan_root("marker");
        let profile = app_profile("marker");
        let marker = OrphanMarker::create(&root, 4242, &profile, None);
        marker.set_port(Some(9222));
        let path = marker.path.clone().unwrap();
        let value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(value["chromePid"], 4242);
        assert_eq!(value["port"], 9222);
        assert_eq!(value["ownerPid"], std::process::id());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        drop(marker);
        assert!(!path.exists());
        assert_eq!(port_from_ws_url("ws://127.0.0.1:41234/devtools/browser/abc"), Some(41234));
        let _ = std::fs::remove_dir_all(&profile);
        let _ = std::fs::remove_dir_all(&root);
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
        let mut c = BodyCollector {
            used: SESSION_BODY_BUDGET - 4,
            ..BodyCollector::default()
        };
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
}
