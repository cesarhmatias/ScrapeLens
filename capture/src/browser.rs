//! Captura controlada para o MCP (`docs/16b-mcp-navegador.md` §3–§4).
//!
//! `BrowserCapture` abre o Chrome estável com perfil dedicado, CDP + NetLog e
//! **allowlist obrigatória**, aceita `navigate` e encerra de forma graciosa. A
//! thread de captura continua dona do soquete CDP; `navigate` é uma mensagem
//! num canal consumido pelo laço de gravação. A confirmação do usuário
//! (elicitação MCP) acontece na camada do servidor, antes de chamar esta API.

use std::path::PathBuf;
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};
use super::transport::{CdpTransport, Transport};

use super::allowlist::{Allowlist, AllowlistError, AllowlistReport, UrlDenied};
use super::chrome::{validate_chrome, ChromeError};
use super::{run_with_options, CaptureConfig, CaptureOutcome, CaptureStatus, Cdp, RunOptions, RunReport};

/// Texto fixo que o servidor MCP mostra na confirmação de `start_capture`.
pub const SENSITIVE_NOTICE: &str = "Esta captura grava cookies, cabeçalhos de autorização e corpos de requisição e resposta (NetLog em modo Everything + CDP). Os dados ficam na pasta da sessão; as ferramentas de leitura mascaram valores por padrão. Não digite credenciais no navegador da captura.";

/// Endereço de depuração do Chrome (loopback).
#[derive(Debug, Clone)]
pub(crate) struct Endpoint {
    pub http: Option<String>,
    pub browser_ws: String,
    pub chrome_pid: u32,
    pub page_target_id: Option<String>,
    pub product: Option<String>,
    pub user_agent: Option<String>,
}

/// Mensagens para o laço de gravação.
pub(crate) enum Control {
    Navigate {
        url: String,
        wait_load: bool,
        timeout: Duration,
        reply: Sender<Result<NavigateResult, NavigateError>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NavigateResult {
    pub frame_id: Option<String>,
    pub loader_id: Option<String>,
    pub loaded: bool,
    pub error_text: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BrowserCaptureConfig {
    pub chrome: PathBuf,
    pub session_dir: PathBuf,
    pub start_url: Option<String>,
    pub headless: bool,
    pub allowed_hosts: Vec<String>,
    pub third_party_hosts: Vec<String>,
    pub expose_cdp: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    Allowlist(AllowlistError),
    /// O navegador não é o Chrome estável da Google (`chrome::validate_chrome`).
    BrowserInvalid(ChromeError),
    StartUrlNotAllowed(UrlDenied),
    SessionDir(String),
    BrowserStart(String),
}

impl StartError {
    pub fn code(&self) -> &'static str {
        match self {
            StartError::Allowlist(e) => e.code(),
            StartError::BrowserInvalid(e) => e.code(),
            StartError::StartUrlNotAllowed(_) => "start_url_not_allowed",
            StartError::SessionDir(_) => "session_dir",
            StartError::BrowserStart(_) => "browser_start_failed",
        }
    }
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::Allowlist(e) => write!(f, "{e}"),
            StartError::BrowserInvalid(e) => write!(f, "{e}"),
            StartError::StartUrlNotAllowed(e) => write!(f, "start_url: {e}"),
            StartError::SessionDir(e) => write!(f, "diretório da sessão: {e}"),
            StartError::BrowserStart(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for StartError {}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CdpAccess {
    pub http: Option<String>,
    pub browser_ws: String,
    /// A aba da captura (a que `navigate` usa): o agente anexa a esta.
    pub page_target_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserInfo {
    pub path: String,
    pub version: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowlistInfo {
    pub allowed_hosts: Vec<String>,
    pub third_party_hosts: Vec<String>,
    pub resolver_rules: String,
}

/// Resposta de `start_capture`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartInfo {
    pub session_dir: String,
    pub chrome_pid: u32,
    pub browser: BrowserInfo,
    pub allowlist: AllowlistInfo,
    /// Só com `expose_cdp: true`.
    pub cdp: Option<CdpAccess>,
    pub sensitive_notice: &'static str,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NavigateError {
    UrlNotAllowed(UrlDenied),
    CaptureStopped,
    Failed(String),
    /// O navegador não respondeu dentro do prazo do `navigate` (travado ou
    /// parado). A captura continua; o agente pode tentar de novo ou encerrar.
    TimedOut,
}

impl NavigateError {
    pub fn code(&self) -> &'static str {
        match self {
            NavigateError::UrlNotAllowed(_) => "url_not_allowed",
            NavigateError::CaptureStopped => "capture_stopped",
            NavigateError::Failed(_) => "navigate_failed",
            NavigateError::TimedOut => "navigate_timeout",
        }
    }
}

impl std::fmt::Display for NavigateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NavigateError::UrlNotAllowed(e) => write!(f, "{e}"),
            NavigateError::CaptureStopped => write!(f, "a captura já foi encerrada"),
            NavigateError::Failed(e) => write!(f, "{e}"),
            NavigateError::TimedOut => write!(
                f,
                "o navegador não respondeu ao navigate dentro do prazo (travado ou parado)"
            ),
        }
    }
}

impl std::error::Error for NavigateError {}

/// Resposta de `stop_capture`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StopReport {
    pub session_dir: String,
    pub requests: usize,
    pub netlog: String,
    pub graceful: bool,
    pub waited_ms: u64,
    pub allowlist: AllowlistReport,
    pub warnings: Vec<String>,
    /// Sessão importada, para o chamador (o servidor MCP registra o handle).
    #[serde(skip)]
    pub outcome: Option<CaptureOutcome>,
}

pub struct BrowserCapture {
    allowlist: Allowlist,
    session_dir: PathBuf,
    control: Sender<Control>,
    stop: Sender<()>,
    join: Option<JoinHandle<Result<(CaptureOutcome, RunReport), String>>>,
    status: Arc<Mutex<CaptureStatus>>,
}

/// Início da mensagem de `Cdp::send` quando o prazo de uma resposta estoura.
pub(crate) const CDP_TIMEOUT_PREFIX: &str = "CDP timeout aguardando";

/// Piso do prazo de um `navigate`: o `Page.navigate` precisa de tempo para
/// confirmar mesmo quando o agente pede `timeout_ms` muito curto.
const MIN_NAVIGATE_BUDGET: Duration = Duration::from_secs(2);
/// Teto do `Page.navigate` (o prazo pedido nunca o estende).
const MAX_PAGE_NAVIGATE: Duration = Duration::from_secs(30);
/// Folga entre o prazo do laço e o do chamador.
const NAVIGATE_REPLY_MARGIN: Duration = Duration::from_secs(5);

/// Prazo total (comando + espera da carga) de um `navigate`.
fn navigate_budget(timeout: Duration) -> Duration {
    timeout.max(MIN_NAVIGATE_BUDGET)
}

impl BrowserCapture {
    /// Abre o Chrome. Sem allowlist válida não abre nada.
    pub fn start(config: BrowserCaptureConfig) -> Result<(BrowserCapture, StartInfo), StartError> {
        let allowlist = Allowlist::new(&config.allowed_hosts, &config.third_party_hosts)
            .map_err(StartError::Allowlist)?;
        let start_url = match config.start_url.as_deref().filter(|u| !u.trim().is_empty()) {
            Some(url) => {
                allowlist
                    .permits_url(url)
                    .map_err(StartError::StartUrlNotAllowed)?;
                url.to_string()
            }
            None => String::new(),
        };
        // Só o Chrome estável da Google, lido do bundle e da assinatura, sem
        // executar nada. O caminho validado (symlinks resolvidos) é o que roda.
        let validated = validate_chrome(&config.chrome).map_err(StartError::BrowserInvalid)?;
        let capture_config = CaptureConfig {
            chrome: validated.binary.clone(),
            session_dir: config.session_dir.clone(),
            start_url,
            headless: config.headless,
            ignore_cert: false,
            // Sem efeito: a captura controlada sempre leva a allowlist
            // (`resolver_rules`), que vale no lugar do modo. Se ela faltasse, a rede
            // ficaria restrita a loopback (falha fechada), nunca aberta.
            network: crate::NetworkMode::LoopbackOnly,
            cookie_source: None,
            initial_cookies: Vec::new(),
        };
        let status = Arc::new(Mutex::new(CaptureStatus {
            recording: true,
            session_dir: config.session_dir.display().to_string(),
            ..CaptureStatus::default()
        }));
        let (stop_tx, stop_rx) = channel();
        let (ready_tx, ready_rx) = channel();
        let (control_tx, control_rx) = channel();
        let endpoint: Arc<Mutex<Option<Endpoint>>> = Arc::new(Mutex::new(None));
        let opts = RunOptions {
            allowlist: Some(allowlist.clone()),
            control: Some(control_rx),
            endpoint: Some(endpoint.clone()),
            require_initial_target_ready: true,
            // Sem agente conectado, o Chrome não abre porta nenhuma (pipe); com
            // `expose_cdp` a porta, só em 127.0.0.1, é inerente ao recurso.
            transport: if config.expose_cdp {
                CdpTransport::Port
            } else {
                CdpTransport::Pipe
            },
        };
        let thread_status = status.clone();
        let join = thread::spawn(move || {
            run_with_options(capture_config, thread_status, stop_rx, ready_tx, &opts)
        });
        match ready_rx.recv_timeout(Duration::from_secs(90)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let _ = join.join();
                return Err(StartError::BrowserStart(error));
            }
            Err(_) => {
                let _ = stop_tx.send(());
                let _ = join.join();
                return Err(StartError::BrowserStart(
                    "o Chrome não ficou pronto em 90 s".to_string(),
                ));
            }
        }
        let endpoint = endpoint
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
            .ok_or_else(|| StartError::BrowserStart("endpoint de depuração ausente".to_string()))?;
        let info = StartInfo {
            session_dir: config.session_dir.display().to_string(),
            chrome_pid: endpoint.chrome_pid,
            browser: BrowserInfo {
                path: validated.binary.display().to_string(),
                version: endpoint.product.clone().or(Some(validated.version.clone())),
                user_agent: endpoint.user_agent.clone(),
            },
            allowlist: AllowlistInfo {
                allowed_hosts: allowlist.allowed_hosts(),
                third_party_hosts: allowlist.third_party_hosts(),
                resolver_rules: allowlist.resolver_rules(),
            },
            cdp: config.expose_cdp.then(|| CdpAccess {
                http: endpoint.http.clone(),
                browser_ws: endpoint.browser_ws.clone(),
                page_target_id: endpoint.page_target_id.clone(),
            }),
            sensitive_notice: SENSITIVE_NOTICE,
            warnings: Vec::new(),
        };
        Ok((
            BrowserCapture {
                allowlist,
                session_dir: config.session_dir,
                control: control_tx,
                stop: stop_tx,
                join: Some(join),
                status,
            },
            info,
        ))
    }

    /// Navega a aba principal. A URL é validada antes de qualquer envio.
    pub fn navigate(
        &self,
        url: &str,
        wait_load: bool,
        timeout: Duration,
    ) -> Result<NavigateResult, NavigateError> {
        let allowed = self
            .allowlist
            .permits_url(url)
            .map_err(NavigateError::UrlNotAllowed)?;
        let (reply_tx, reply_rx) = channel();
        self.control
            .send(Control::Navigate {
                url: allowed.url,
                wait_load,
                timeout,
                reply: reply_tx,
            })
            .map_err(|_| NavigateError::CaptureStopped)?;
        // O laço atende em até ~250 ms e `navigate_page` respeita o prazo
        // inteiro (R12); a margem cobre o atraso de uma tarefa em curso no laço.
        match reply_rx.recv_timeout(navigate_budget(timeout) + NAVIGATE_REPLY_MARGIN) {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(error)) => Err(error),
            Err(RecvTimeoutError::Timeout) => Err(NavigateError::TimedOut),
            Err(RecvTimeoutError::Disconnected) => Err(NavigateError::CaptureStopped),
        }
    }

    pub fn status(&self) -> CaptureStatus {
        self.status
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// Encerramento gracioso (`Browser.close`, espera, NetLog fechado) e
    /// importação da sessão.
    pub fn stop(mut self) -> Result<StopReport, String> {
        let _ = self.stop.send(());
        let join = self
            .join
            .take()
            .ok_or_else(|| "captura já encerrada".to_string())?;
        let (outcome, report) = join
            .join()
            .map_err(|_| "a thread de captura falhou".to_string())??;
        Ok(StopReport {
            session_dir: self.session_dir.display().to_string(),
            requests: report.requests,
            netlog: report.netlog,
            graceful: report.graceful,
            waited_ms: report.waited_ms,
            allowlist: report.allowlist.unwrap_or_default(),
            warnings: report.warnings,
            outcome: Some(outcome),
        })
    }
}

impl Drop for BrowserCapture {
    fn drop(&mut self) {
        // Sem `stop`: encerra do mesmo jeito (o laço trata o canal fechado
        // como parada) e espera a thread, para o Chrome não ficar solto.
        if let Some(join) = self.join.take() {
            let _ = self.stop.send(());
            let _ = join.join();
        }
    }
}

impl Cdp {
    /// Atende uma mensagem de controle dentro do laço de gravação.
    pub(super) fn handle_control(
        &mut self,
        socket: &mut Transport,
        message: Control,
    ) {
        match message {
            Control::Navigate {
                url,
                wait_load,
                timeout,
                reply,
            } => {
                let result = self.navigate_page(socket, &url, wait_load, timeout);
                let _ = reply.send(result);
            }
        }
    }

    fn navigate_page(
        &mut self,
        socket: &mut Transport,
        url: &str,
        wait_load: bool,
        timeout: Duration,
    ) -> Result<NavigateResult, NavigateError> {
        if self.page_session_id.is_empty() {
            return Err(NavigateError::Failed("a aba principal não está pronta".to_string()));
        }
        let page = self.page_session_id.clone();
        let before = self.page_load_events;
        // Um só prazo para o comando e a espera da carga: com o Chrome travado,
        // o `navigate(timeout_ms=3000)` volta em ~3 s, não em 30 s.
        let budget = navigate_budget(timeout);
        let started = Instant::now();
        let result = self.send(
            socket,
            "Page.navigate",
            json!({ "url": url }),
            Some(&page),
            budget.min(MAX_PAGE_NAVIGATE),
        )
        .map_err(|error| {
            // Prazo estourado (Chrome parado/travado) é `navigate_timeout`, não falha.
            if error.starts_with(CDP_TIMEOUT_PREFIX) {
                NavigateError::TimedOut
            } else {
                NavigateError::Failed(error)
            }
        })?;
        let text = |key: &str| result.get(key).and_then(Value::as_str).map(str::to_string);
        let error_text = text("errorText");
        let mut loaded = false;
        if error_text.is_none() && wait_load {
            let deadline = started + budget;
            while Instant::now() < deadline {
                if self.page_load_events > before {
                    loaded = true;
                    break;
                }
                self.pump_socket(socket, Duration::from_millis(100));
                // O canal fechou (Chrome saiu ou mensagem acima do teto): não há
                // mais evento de carga a esperar; sem isto o laço gira até o prazo.
                if socket.is_closed() && self.page_load_events <= before {
                    let why = socket
                        .abnormal_close_reason()
                        .map(|r| format!(" ({r})"))
                        .unwrap_or_default();
                    return Err(NavigateError::Failed(format!(
                        "o CDP fechou durante o navigate{why}; a captura terminou"
                    )));
                }
            }
            // Um último olhar: o evento pode ter chegado no último bombeamento.
            loaded = loaded || self.page_load_events > before;
        }
        Ok(NavigateResult {
            frame_id: text("frameId"),
            loader_id: text("loaderId"),
            loaded,
            error_text,
        })
    }
}

#[cfg(test)]
pub(crate) mod testsite {
    //! Servidor HTTP mínimo em loopback para os testes vivos (std apenas).
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;

    pub struct Reply {
        pub status: u16,
        pub headers: Vec<(String, String)>,
        pub body: String,
    }

    impl Reply {
        pub fn html(body: &str) -> Self {
            Reply {
                status: 200,
                headers: vec![("Content-Type".into(), "text/html; charset=utf-8".into())],
                body: body.to_string(),
            }
        }
        pub fn status(mut self, status: u16) -> Self {
            self.status = status;
            self
        }
        pub fn header(mut self, name: &str, value: &str) -> Self {
            self.headers.push((name.to_string(), value.to_string()));
            self
        }
    }

    pub struct TestSite {
        pub port: u16,
        /// `"MÉTODO caminho"` de cada requisição recebida, em ordem.
        pub seen: Arc<Mutex<Vec<String>>>,
    }

    impl TestSite {
        pub fn start<F>(route: F) -> TestSite
        where
            F: Fn(&str, &str) -> Reply + Send + Sync + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let port = listener.local_addr().unwrap().port();
            let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let route = Arc::new(route);
            let seen_thread = seen.clone();
            thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let route = route.clone();
                    let seen = seen_thread.clone();
                    thread::spawn(move || handle(stream, route, seen));
                }
            });
            TestSite { port, seen }
        }

        pub fn seen_paths(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }
    }

    fn handle<F>(mut stream: TcpStream, route: Arc<F>, seen: Arc<Mutex<Vec<String>>>)
    where
        F: Fn(&str, &str) -> Reply,
    {
        let mut buf = vec![0u8; 16 * 1024];
        let mut total = 0;
        loop {
            match stream.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => {
                    total += n;
                    if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") || total == buf.len() {
                        break;
                    }
                }
                Err(_) => return,
            }
        }
        let head = String::from_utf8_lossy(&buf[..total]).to_string();
        let mut parts = head.lines().next().unwrap_or("").split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("/").to_string();
        seen.lock().unwrap().push(format!("{method} {path}"));
        let reply = route(&method, &path);
        let reason = match reply.status {
            200 => "OK",
            403 => "Forbidden",
            404 => "Not Found",
            429 => "Too Many Requests",
            _ => "Status",
        };
        let mut out = format!("HTTP/1.1 {} {}\r\n", reply.status, reason);
        let mut has_len = false;
        for (name, value) in &reply.headers {
            if name.eq_ignore_ascii_case("content-length") {
                has_len = true;
            }
            out.push_str(&format!("{name}: {value}\r\n"));
        }
        if !has_len {
            out.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
        }
        out.push_str("Connection: close\r\n\r\n");
        out.push_str(&reply.body);
        let _ = stream.write_all(out.as_bytes());
        let _ = stream.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::testsite::{Reply, TestSite};
    use super::*;
    use std::path::Path;

    fn config(allowed: &[&str], start_url: Option<&str>) -> BrowserCaptureConfig {
        BrowserCaptureConfig {
            chrome: PathBuf::from("/nao/existe/chrome"),
            session_dir: std::env::temp_dir().join(format!(
                "scrapelens-bc-test-{}-{}",
                std::process::id(),
                super::super::unix_millis()
            )),
            start_url: start_url.map(str::to_string),
            headless: true,
            allowed_hosts: allowed.iter().map(|s| s.to_string()).collect(),
            third_party_hosts: Vec::new(),
            expose_cdp: false,
        }
    }

    #[test]
    fn start_without_allowlist_is_an_error_and_never_spawns() {
        let err = BrowserCapture::start(config(&[], None)).err().expect("erro");
        assert_eq!(err.code(), "allowlist_required");
        let err = BrowserCapture::start(config(&["*"], None)).err().expect("erro");
        assert_eq!(err.code(), "allowlist_too_broad");
        let err = BrowserCapture::start(config(&["http://exemplo.com"], None))
            .err()
            .expect("erro");
        assert_eq!(err.code(), "allowlist_invalid");
    }

    #[test]
    fn start_url_must_pass_the_allowlist() {
        let err = BrowserCapture::start(config(&["a.test"], Some("http://b.test/")))
            .err()
            .expect("erro");
        assert_eq!(err.code(), "start_url_not_allowed");
    }

    #[test]
    fn start_refuses_anything_that_is_not_the_stable_chrome() {
        // Inexistente, binário do sistema e script falso: `browser_invalid`, nada roda.
        let dir = std::env::temp_dir().join(format!("scrapelens-fakechrome-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("chrome");
        std::fs::write(&script, "#!/bin/sh\ntouch /tmp/sl-start-ran\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        for path in [
            PathBuf::from("/nao/existe/chrome"),
            PathBuf::from("/bin/echo"),
            script.clone(),
        ] {
            let mut cfg = config(&["a.test"], Some("http://a.test/"));
            cfg.chrome = path.clone();
            let err = BrowserCapture::start(cfg).err().expect("erro");
            assert_eq!(err.code(), "browser_invalid", "{path:?}: {err}");
        }
        assert!(!Path::new("/tmp/sl-start-ran").exists(), "o script falso não pode ter rodado");
        let _ = std::fs::remove_dir_all(dir);
    }

    fn chrome_or_skip() -> PathBuf {
        PathBuf::from(crate::chrome::detect(None).path.expect("Chrome instalado"))
    }

    /// `SL_LIVE_HEADED=1` roda os vivos que o aceitam com janela (no Linux, sob Xvfb).
    fn live_headless() -> bool {
        std::env::var("SL_LIVE_HEADED").as_deref() != Ok("1")
    }

    fn live_config(allowed: Vec<String>, name: &str, expose_cdp: bool) -> BrowserCaptureConfig {
        BrowserCaptureConfig {
            chrome: chrome_or_skip(),
            session_dir: std::env::temp_dir().join(format!(
                "scrapelens-bc-live-{name}-{}-{}",
                std::process::id(),
                super::super::unix_millis()
            )),
            start_url: None,
            headless: live_headless(),
            allowed_hosts: allowed,
            third_party_hosts: Vec::new(),
            expose_cdp,
        }
    }

    /// Ciclo vivo em loopback: allowlist nas duas camadas + encerramento
    /// gracioso. `cargo test --lib live_allowlist_cycle -- --ignored --nocapture`.
    ///
    /// Achado medido (Chrome 156): `MAP * ~NOTFOUND` também nega IP literal
    /// (`ERR_NAME_NOT_RESOLVED`); o que escapa do resolvedor é a PORTA de um
    /// host permitido, e isso só a camada 2 e o relatório pegam.
    #[test]
    #[ignore]
    fn live_allowlist_cycle() {
        use std::sync::atomic::{AtomicU16, Ordering};
        static PORT: AtomicU16 = AtomicU16::new(0);
        static PORT2: AtomicU16 = AtomicU16::new(0);
        let site2 = TestSite::start(|_m, _p| Reply::html("segundo servidor"));
        PORT2.store(site2.port, Ordering::SeqCst);
        let site = TestSite::start(|_m, path| match path {
            "/" => {
                let p = PORT.load(Ordering::SeqCst);
                let p2 = PORT2.load(Ordering::SeqCst);
                Reply::html(&format!(
                    "<html><body><h1>ok</h1>\
                     <img src='http://blocked.invalid.test:{p}/b.png'>\
                     <img src='http://127.0.0.1:{p}/ip.png'>\
                     <img src='http://127.1:{p}/ip-short.png'>\
                     <img src='http://2130706433:{p}/ip-decimal.png'>\
                     <img src='http://[::1]:{p}/ip-v6.png'>\
                     <img src='http://localhost:{p2}/other-port.png'></body></html>"
                ))
            }
            _ => Reply::html("x"),
        });
        PORT.store(site.port, Ordering::SeqCst);
        let port = site.port;
        let config = live_config(vec![format!("localhost:{port}")], "allowlist", true);
        let (capture, info) = BrowserCapture::start(config).expect("start");
        assert!(info.allowlist.resolver_rules.contains("EXCLUDE localhost"));
        let cdp = info.cdp.expect("cdp exposto");
        assert!(cdp.browser_ws.starts_with("ws://127.0.0.1:"));
        assert!(info.browser.version.as_deref().unwrap_or("").contains("Chrome"));

        // Camada 2: recusas antes de qualquer envio.
        for bad in [
            format!("http://127.0.0.1:{port}/"),
            "http://evil.test/".to_string(),
            format!("http://localhost:{}/", port.wrapping_add(1)),
            format!("http://localhost:{port}@evil.test/"),
            "file:///etc/passwd".to_string(),
        ] {
            let err = capture
                .navigate(&bad, true, Duration::from_secs(5))
                .expect_err(&bad);
            assert_eq!(err.code(), "url_not_allowed", "{bad}");
        }
        assert!(site.seen_paths().is_empty(), "nada pode ter chegado ao servidor");

        let result = capture
            .navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(20))
            .expect("navigate");
        assert!(result.loaded, "{result:?}");
        assert!(result.error_text.is_none());
        thread::sleep(Duration::from_millis(1000));

        let report = capture.stop().expect("stop");
        println!("allowlist: {:#?}", report.allowlist);
        println!("servidor viu: {:?}; segundo servidor viu: {:?}", site.seen_paths(), site2.seen_paths());
        assert!(report.graceful, "encerramento gracioso");
        assert_eq!(report.netlog, "complete");
        assert!(report.requests >= 1);
        let blocked: Vec<&str> = report
            .allowlist
            .blocked_hosts
            .iter()
            .map(|b| b.host.as_str())
            .collect();
        // Camada 1: nome fora da lista e IP literal (qualquer forma) não resolvem.
        assert!(blocked.contains(&"blocked.invalid.test"), "{blocked:?}");
        assert!(blocked.contains(&"127.0.0.1"), "{blocked:?}");
        for escaped in ["ip.png", "ip-short.png", "ip-decimal.png", "ip-v6.png", "b.png"] {
            assert!(
                !site.seen_paths().iter().any(|p| p.contains(escaped)),
                "{escaped} chegou ao servidor"
            );
        }
        // Lacuna medida: outra PORTA do host permitido passa pelo resolvedor.
        assert!(site2.seen_paths().iter().any(|p| p == "GET /other-port.png"));
        assert!(
            report
                .allowlist
                .violations
                .iter()
                .any(|v| v.url.contains("other-port.png") && v.reason.contains("porta")),
            "{:?}",
            report.allowlist
        );
        let session_json =
            std::fs::read_to_string(std::path::Path::new(&report.session_dir).join("session.json"))
                .expect("session.json");
        assert!(session_json.contains("capture.third_party_blocked"));
        assert!(session_json.contains("capture.allowlist_violation"));
    }

    /// Segundo cliente CDP (o agente) no mesmo Chrome, com auto-attach e
    /// `waitForDebuggerOnStart`. Mede se coexiste com o nosso cliente
    /// (`docs/16b-mcp-navegador.md` §3.5). `cooperative`: retoma os alvos
    /// pausados; senão nunca chama `runIfWaitingForDebugger`.
    fn second_cdp_client_scenario(cooperative: bool, name: &str) -> (bool, Vec<String>, String) {
        use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
        static PORT: AtomicU16 = AtomicU16::new(0);
        let site = TestSite::start(|_m, path| match path {
            "/idle" => Reply::html("<html><body>ocioso</body></html>"),
            "/" => Reply::html(
                "<html><body><h1>agente</h1><script>new Worker('/w.js');</script></body></html>",
            ),
            "/w.js" => Reply {
                status: 200,
                headers: vec![("Content-Type".into(), "application/javascript".into())],
                body: "fetch('/from-worker?m=wk').catch(()=>{});".to_string(),
            },
            _ => Reply::html("x"),
        });
        PORT.store(site.port, Ordering::SeqCst);
        let port = site.port;
        let config = live_config(vec![format!("localhost:{port}")], name, true);
        let (capture, info) = BrowserCapture::start(config).expect("start");
        let ws = info.cdp.expect("cdp").browser_ws;

        // O agente se conecta no meio da sessão: a página já está numa URL conhecida.
        let idle = capture
            .navigate(&format!("http://localhost:{port}/idle"), true, Duration::from_secs(20))
            .expect("navigate idle");
        assert!(idle.loaded);
        let running = Arc::new(AtomicBool::new(true));
        let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let client_running = running.clone();
        let client_log = log.clone();
        let idle_prefix = format!("http://localhost:{port}/idle");
        let (ready_tx, ready_rx) = channel::<()>();
        let client = thread::spawn(move || {
            let (mut socket, _) = tungstenite::connect(ws.as_str()).expect("segundo cliente");
            if let tungstenite::stream::MaybeTlsStream::Plain(stream) = socket.get_ref() {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
            }
            let mut next = 0u64;
            let mut send = |socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
                            method: &str,
                            params: Value,
                            session: Option<&str>| {
                next += 1;
                let mut msg = json!({ "id": next, "method": method, "params": params });
                if let Some(s) = session {
                    msg["sessionId"] = json!(s);
                }
                socket
                    .send(tungstenite::Message::Text(msg.to_string().into()))
                    .expect("send");
                next
            };
            // O alvo da página principal da captura.
            let id_targets = send(&mut socket, "Target.getTargets", json!({}), None);
            send(&mut socket, "Target.setDiscoverTargets", json!({ "discover": true }), None);
            let mut id_attach = 0u64;
            let mut announced = false;
            while client_running.load(Ordering::SeqCst) {
                let text = match socket.read() {
                    Ok(tungstenite::Message::Text(t)) => t.to_string(),
                    Ok(_) => continue,
                    Err(tungstenite::Error::Io(e))
                        if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) =>
                    {
                        continue
                    }
                    Err(_) => break,
                };
                let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
                if let Some(m) = v.get("method").and_then(Value::as_str) {
                    if m.starts_with("Target.") {
                        client_log.lock().unwrap().push(format!("evento {m} {} {}", v["params"]["targetInfo"]["type"], v["params"]["targetInfo"]["url"]));
                    }
                }
                if v.get("error").is_some() {
                    client_log.lock().unwrap().push(format!("segundo cliente: erro {}", v["error"]));
                }
                if v.get("id").and_then(Value::as_u64) == Some(id_targets) {
                    let target = v["result"]["targetInfos"]
                        .as_array()
                        .and_then(|a| {
                            a.iter().find(|t| {
                                t["type"] == "page"
                                    && t["url"].as_str().map(|u| u.starts_with(&idle_prefix)).unwrap_or(false)
                            })
                        })
                        .cloned();
                    if let Some(t) = target {
                        id_attach = send(
                            &mut socket,
                            "Target.attachToTarget",
                            json!({ "targetId": t["targetId"], "flatten": true }),
                            None,
                        );
                    }
                } else if v.get("id").and_then(Value::as_u64) == Some(id_attach) && id_attach != 0 {
                    let page_session = v["result"]["sessionId"].as_str().map(str::to_string);
                    if let Some(sid) = &page_session {
                        send(
                            &mut socket,
                            "Target.setAutoAttach",
                            json!({ "autoAttach": true, "flatten": true, "waitForDebuggerOnStart": true }),
                            Some(sid),
                        );
                        send(&mut socket, "Page.enable", json!({}), Some(sid));
                        send(&mut socket, "Network.enable", json!({}), Some(sid));
                        if !announced {
                            announced = true;
                            let _ = ready_tx.send(());
                        }
                    }
                } else if v["method"] == "Target.attachedToTarget" {
                    let kind = v["params"]["targetInfo"]["type"].as_str().unwrap_or("?").to_string();
                    let waiting = v["params"]["waitingForDebugger"].as_bool().unwrap_or(false);
                    client_log
                        .lock()
                        .unwrap()
                        .push(format!("segundo cliente: attached {kind} waiting={waiting}"));
                    if waiting && cooperative {
                        if let Some(sid) = v["params"]["sessionId"].as_str() {
                            send(&mut socket, "Runtime.runIfWaitingForDebugger", json!({}), Some(sid));
                        }
                    }
                }
            }
            let _ = socket.close(None);
        });
        ready_rx
            .recv_timeout(Duration::from_secs(15))
            .expect("segundo cliente anexou");

        thread::sleep(Duration::from_millis(500));
        let result = capture
            .navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(20))
            .expect("navigate");
        thread::sleep(Duration::from_millis(2500));
        running.store(false, Ordering::SeqCst);
        let _ = client.join();
        let report = capture.stop().expect("stop");
        let session_json =
            std::fs::read_to_string(std::path::Path::new(&report.session_dir).join("session.json"))
                .unwrap_or_default();
        let worker_in_session = session_json.contains("from-worker");
        let worker_hit = site.seen_paths().iter().any(|p| p.contains("/from-worker"));
        let summary = format!(
            "{name}: navigate.loaded={} graceful={} worker_chegou_ao_servidor={} worker_na_sessao={}",
            result.loaded, report.graceful, worker_hit, worker_in_session
        );
        println!("{summary}");
        let log_lines = log.lock().unwrap().clone();
        for l in &log_lines {
            println!("  {l}");
        }
        (result.loaded && report.graceful && worker_hit && worker_in_session, log_lines, summary)
    }

    /// Cenário A: o agente retoma os alvos que pausou. Esperado: nada trava e
    /// o worker é capturado pelo nosso cliente.
    #[test]
    #[ignore]
    fn second_cdp_client_cooperative() {
        let (ok, _log, summary) = second_cdp_client_scenario(true, "cooperativo");
        assert!(ok, "{summary}");
    }

    /// Cenário B: o agente pede `waitForDebuggerOnStart` e NUNCA retoma. O
    /// resultado é medido e impresso; só se exige que a captura não trave e
    /// encerre de forma graciosa.
    #[test]
    #[ignore]
    fn second_cdp_client_never_resumes() {
        let (_ok, _log, summary) = second_cdp_client_scenario(false, "nunca-retoma");
        println!("RESULTADO B: {summary}");
    }

    /// Gera três sessões reais (Chrome headless contra servidores em loopback
    /// que IMITAM sinais documentados) para o teste de ponta a ponta do crate
    /// `recon`: `plain`, `unsolved`, `solved`. Rodado por
    /// `recon/scripts/live_e2e.sh`. Variável: `SL_RECON_E2E_DIR`.
    #[test]
    #[ignore]
    fn live_recon_scenarios() {
        let root = PathBuf::from(
            std::env::var("SL_RECON_E2E_DIR").expect("SL_RECON_E2E_DIR (diretório de saída)"),
        );
        std::fs::create_dir_all(&root).unwrap();
        for scenario in ["plain", "unsolved", "solved"] {
            let site = TestSite::start(move |_m, path| {
                let route = path.split('?').next().unwrap_or("/");
                match (scenario, route, path.contains("r=1")) {
                    ("plain", "/", _) => Reply::html(
                        "<html><body><h1>ok</h1><script>fetch('/api/list').then(r=>r.text());</script></body></html>",
                    )
                    .header("cf-ray", "8abc123def456-GRU")
                    .header("Set-Cookie", "__cf_bm=SEGREDO-BM-1; Path=/; HttpOnly"),
                    ("plain", "/api/list", _) => Reply {
                        status: 200,
                        headers: vec![("Content-Type".into(), "application/json".into())],
                        body: "{\"itens\":[1,2,3]}".to_string(),
                    },
                    ("unsolved", "/", _) => Reply::html(
                        "<html><body>Verificando…<script src='https://turnstile.blocked.invalid.test/api.js'></script></body></html>",
                    )
                    .status(403)
                    .header("cf-mitigated", "challenge")
                    .header("cf-ray", "8abc123def456-GRU")
                    .header("Set-Cookie", "cf_chl_rc_ni=1; Path=/"),
                    ("solved", "/", false) => Reply::html(
                        "<html><body>Verificando…<script>setTimeout(()=>location.replace('/?r=1'),50)</script></body></html>",
                    )
                    .status(403)
                    .header("cf-mitigated", "challenge")
                    .header("cf-ray", "8abc123def456-GRU"),
                    ("solved", "/", true) => Reply::html(
                        "<html><body><h1>liberado</h1><script>fetch('/api/data').then(r=>r.text());</script></body></html>",
                    )
                    .header("cf-ray", "8abc123def457-GRU")
                    .header("Set-Cookie", "cf_clearance=SEGREDO-CLEARANCE-9; Path=/; HttpOnly"),
                    ("solved", "/api/data", _) => Reply {
                        status: 200,
                        headers: vec![("Content-Type".into(), "application/json".into())],
                        body: "{\"ok\":true}".to_string(),
                    },
                    _ => Reply::html("x").status(404),
                }
            });
            let port = site.port;
            let mut config = live_config(vec![format!("localhost:{port}")], scenario, false);
            config.session_dir = root.join(scenario);
            let (capture, _info) = BrowserCapture::start(config).expect("start");
            let result = capture
                .navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(20))
                .expect("navigate");
            println!("{scenario}: loaded={}", result.loaded);
            thread::sleep(Duration::from_millis(1800));
            let report = capture.stop().expect("stop");
            assert!(report.graceful, "{scenario}");
            println!("{scenario}: {} requisições; servidor viu {:?}", report.requests, site.seen_paths());
        }
    }

    /// O endereço CDP só é entregue com o nosso cliente ligado no alvo inicial:
    /// a PRIMEIRA ação de um agente externo (anexar à aba da captura e navegar,
    /// sem esperar nada) já é vista pela nossa captura, com os eventos `Network.*`
    /// da própria aba. Exigência do líder, derivada do achado 5 de
    /// `docs/16b-mcp-navegador.md` §3.5.
    #[test]
    #[ignore]
    fn agent_first_action_is_captured() {
        let site = TestSite::start(|_m, path| {
            if path.starts_with("/first") {
                Reply::html("<html><body><img src='/sub.png?m=agent-sub'></body></html>")
            } else {
                Reply::html("x")
            }
        });
        let port = site.port;
        let config = live_config(vec![format!("localhost:{port}")], "agent-first", true);
        let (capture, info) = BrowserCapture::start(config).expect("start");
        let access = info.cdp.expect("cdp exposto");
        let target_id = access.page_target_id.clone().expect("aba da captura");

        // Ação imediata do agente: anexa à aba da captura e navega.
        let (mut socket, _) = tungstenite::connect(access.browser_ws.as_str()).expect("agente");
        let mut call = |method: &str, params: Value, session: Option<&str>| -> Value {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(1);
            let id = NEXT.fetch_add(1, Ordering::SeqCst);
            let mut msg = json!({ "id": id, "method": method, "params": params });
            if let Some(s) = session {
                msg["sessionId"] = json!(s);
            }
            socket.send(tungstenite::Message::Text(msg.to_string().into())).expect("send");
            let deadline = Instant::now() + Duration::from_secs(15);
            while Instant::now() < deadline {
                if let Ok(tungstenite::Message::Text(t)) = socket.read() {
                    if let Ok(v) = serde_json::from_str::<Value>(&t) {
                        if v["id"].as_u64() == Some(id) {
                            return v;
                        }
                    }
                }
            }
            panic!("sem resposta de {method}");
        };
        let attached = call(
            "Target.attachToTarget",
            json!({ "targetId": target_id, "flatten": true }),
            None,
        );
        let session = attached["result"]["sessionId"].as_str().expect("sessão do agente").to_string();
        let nav = call(
            "Page.navigate",
            json!({ "url": format!("http://localhost:{port}/first?m=agent-first") }),
            Some(&session),
        );
        assert!(nav["result"]["errorText"].is_null(), "{nav}");
        thread::sleep(Duration::from_millis(2000));
        drop(socket);

        let report = capture.stop().expect("stop");
        assert!(report.graceful);
        let cdp_events = std::fs::read_to_string(
            std::path::Path::new(&report.session_dir).join("cdp-events.jsonl"),
        )
        .expect("cdp-events.jsonl");
        let seen_in_cdp = |needle: &str| {
            cdp_events
                .lines()
                .any(|l| l.contains("\"Network.requestWillBeSent\"") && l.contains(needle))
        };
        assert!(seen_in_cdp("m=agent-first"), "a navegação do agente não está no CDP da captura");
        assert!(seen_in_cdp("m=agent-sub"), "o subrecurso não está no CDP da captura");
        println!("servidor viu: {:?}", site.seen_paths());
    }

    /// Os 8 caminhos do PoC da revisão (`/tmp/rev25/poc-allow`): com
    /// `localhost:P1` aprovado, a página alcança `localhost:P2` por 302 de
    /// topo, `location=`, meta refresh, `window.open`, iframe, fetch,
    /// WebSocket e host em maiúsculas. Semântica oficial (docs/16b §2.2): o
    /// navegador impõe o HOST; a porta é só reportada. Cada um dos 8 precisa
    /// aparecer em `allowlist.violations`.
    #[test]
    #[ignore]
    fn live_port_gap_is_reported_on_all_paths() {
        use std::sync::atomic::{AtomicU16, Ordering};
        static P2: AtomicU16 = AtomicU16::new(0);
        let site2 = TestSite::start(|_m, _p| Reply::html("outra porta"));
        P2.store(site2.port, Ordering::SeqCst);
        let site = TestSite::start(|_m, path| {
            let p2 = P2.load(Ordering::SeqCst);
            match path {
                "/" => Reply::html(&format!(
                    "<html><body>ok\
                     <img src='http://LOCALHOST:{p2}/upper.png'>\
                     <iframe src='http://localhost:{p2}/iframe-other-port'></iframe>\
                     <script>try{{new WebSocket('ws://localhost:{p2}/ws-other-port')}}catch(e){{}}\
                     fetch('http://localhost:{p2}/fetch-other-port',{{mode:'no-cors'}});\
                     window.open('http://localhost:{p2}/popup-other-port');</script></body></html>"
                )),
                "/redir" => Reply::html("x")
                    .status(302)
                    .header("Location", &format!("http://localhost:{p2}/redirected-top-level")),
                "/jsloc" => Reply::html(&format!(
                    "<script>location='http://localhost:{p2}/js-location'</script>"
                )),
                "/meta" => Reply::html(&format!(
                    "<meta http-equiv=refresh content='0;url=http://localhost:{p2}/meta-refresh'>"
                )),
                _ => Reply::html("x"),
            }
        });
        let p1 = site.port;
        let config = live_config(vec![format!("localhost:{p1}")], "port-gap", false);
        let (capture, _info) = BrowserCapture::start(config).expect("start");
        for path in ["/", "/redir", "/jsloc", "/meta"] {
            let _ = capture.navigate(&format!("http://localhost:{p1}{path}"), true, Duration::from_secs(10));
            thread::sleep(Duration::from_millis(1500));
        }
        let report = capture.stop().expect("stop");
        let p2 = site2.port;
        println!("P2 viu: {:?}", site2.seen_paths());
        println!("violações: {:#?}", report.allowlist.violations.iter().map(|v| (&v.url, &v.reason)).collect::<Vec<_>>());
        let urls: Vec<String> = report.allowlist.violations.iter().map(|v| v.url.clone()).collect();
        for path in [
            "redirected-top-level",
            "js-location",
            "meta-refresh",
            "popup-other-port",
            "iframe-other-port",
            "fetch-other-port",
            "ws-other-port",
            "upper.png",
        ] {
            let scheme = if path == "ws-other-port" { "ws" } else { "http" };
            let expected = format!("{scheme}://localhost:{p2}/{path}");
            assert!(urls.contains(&expected), "caminho {path} não foi reportado: {urls:?}");
            let v = report.allowlist.violations.iter().find(|v| v.url == expected).unwrap();
            assert!(v.reason.contains(&format!("porta {p2}")), "{}", v.reason);
        }
        // A lacuna é real e documentada: o navegador deixou chegar (host liberado).
        for path in ["/redirected-top-level", "/js-location", "/meta-refresh", "/fetch-other-port", "/upper.png"] {
            assert!(
                site2.seen_paths().iter().any(|p| p == &format!("GET {path}")),
                "o PoC esperava que {path} chegasse a P2: {:?}",
                site2.seen_paths()
            );
        }
        // O que está na porta aprovada não é violação; avisos da sessão não vazam consulta.
        assert!(!urls.iter().any(|u| u.contains(&format!("localhost:{p1}"))));
        assert!(report.warnings.iter().all(|w| !w.contains('?') || w.contains("?…")));
        let session_json =
            std::fs::read_to_string(std::path::Path::new(&report.session_dir).join("session.json")).unwrap();
        assert!(session_json.contains("capture.allowlist_violation"));
    }

    /// PoC da revisão (`/tmp/rev25/poc-fs/poc_capture_symlink.py`): symlinks
    /// plantados na pasta da sessão, antes (`netlog.json`, `cdp-bodies.jsonl`) e
    /// durante a captura (`cdp-events.jsonl`), apontando para arquivos fora dela.
    /// Nenhum alvo pode receber dados nem mudar de modo.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_planted_symlinks_are_not_followed() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let site = TestSite::start(|_m, _p| Reply::html("<html><body>ok</body></html>"));
        let port = site.port;
        let mut config = live_config(vec![format!("localhost:{port}")], "symlinks", false);
        let dir = config.session_dir.clone();
        std::fs::create_dir_all(&dir).unwrap();
        let outside = std::env::temp_dir().join(format!("scrapelens-symlink-poc-{}", std::process::id()));
        std::fs::create_dir_all(&outside).unwrap();
        let targets: Vec<PathBuf> = ["netlog", "bodies", "events"].iter().map(|n| outside.join(n)).collect();
        for t in &targets {
            std::fs::write(t, "ORIGINAL\n").unwrap();
            std::fs::set_permissions(t, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        symlink(&targets[0], dir.join("netlog.json")).unwrap();
        symlink(&targets[1], dir.join("cdp-bodies.jsonl")).unwrap();
        config.session_dir = dir.clone();
        let (capture, _info) = BrowserCapture::start(config).expect("start");
        // Durante a captura: o arquivo final ainda não existe, planta o link.
        symlink(&targets[2], dir.join("cdp-events.jsonl")).unwrap();
        let _ = capture.navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(10));
        thread::sleep(Duration::from_millis(500));
        let report = capture.stop().expect("stop");
        for t in &targets {
            assert_eq!(std::fs::read_to_string(t).unwrap(), "ORIGINAL\n", "{t:?} recebeu dados");
            assert_eq!(std::fs::metadata(t).unwrap().permissions().mode() & 0o777, 0o644, "{t:?}");
        }
        for name in ["netlog.json", "cdp-bodies.jsonl", "cdp-events.jsonl"] {
            let meta = std::fs::symlink_metadata(dir.join(name)).unwrap();
            assert!(meta.file_type().is_file(), "{name} devia ser arquivo regular");
        }
        let events = std::fs::read_to_string(dir.join("cdp-events.jsonl")).unwrap();
        assert!(events.contains("Network.requestWillBeSent"));
        assert!(std::fs::metadata(dir.join("netlog.json")).unwrap().len() > 1000);
        assert!(report.requests >= 1);
        let _ = std::fs::remove_dir_all(outside);
    }

    /// PoC da revisão (`poc_netlog_race.py`, R3): um processo do mesmo usuário
    /// troca `netlog.json` da pasta da sessão por um symlink durante a captura.
    /// O Chrome agora grava o NetLog no perfil privado, então o alvo do link não
    /// pode receber nenhum byte, e o `netlog.json` final é um arquivo regular.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_netlog_swap_race_does_not_write_through_a_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let site = TestSite::start(|_m, _p| Reply::html("<html><body>ok</body></html>"));
        let port = site.port;
        let config = live_config(vec![format!("localhost:{port}")], "netlog-race", false);
        let dir = config.session_dir.clone();
        std::fs::create_dir_all(&dir).unwrap();
        let outside = std::env::temp_dir().join(format!("scrapelens-netlog-race-{}", std::process::id()));
        std::fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("VICTIM.txt");
        std::fs::write(&victim, "ORIGINAL\n").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let swaps = Arc::new(AtomicUsize::new(0));
        let attacker = {
            let (dir, victim, done, swaps) = (dir.clone(), victim.clone(), done.clone(), swaps.clone());
            thread::spawn(move || {
                let path = dir.join("netlog.json");
                while !done.load(Ordering::SeqCst) {
                    // O golpe do PoC, nas duas formas: o arquivo existe e não é
                    // link -> troca; o nome está livre -> planta o link (um
                    // Chrome que abrisse esse caminho gravaria no alvo).
                    match std::fs::symlink_metadata(&path) {
                        Ok(m) if !m.file_type().is_symlink() => {
                            if std::fs::remove_file(&path).is_ok() && symlink(&victim, &path).is_ok() {
                                swaps.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                        Err(e)
                            if e.kind() == std::io::ErrorKind::NotFound
                                && symlink(&victim, &path).is_ok() =>
                        {
                            swaps.fetch_add(1, Ordering::SeqCst);
                        }
                        _ => {}
                    }
                    thread::sleep(Duration::from_millis(2));
                }
            })
        };
        let (capture, _info) = BrowserCapture::start(config).expect("start");
        let _ = capture.navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(10));
        thread::sleep(Duration::from_millis(800));
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "ORIGINAL\n",
            "o NetLog vazou para o alvo do link DURANTE a captura"
        );
        // O atacante age durante a captura (como o PoC); depois do `stop` ele
        // só poderia fazer a gravação final falhar (recusa de link), nunca vazar.
        done.store(true, Ordering::SeqCst);
        attacker.join().unwrap();
        let report = capture.stop().expect("stop");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "ORIGINAL\n", "alvo alterado");
        assert_eq!(std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777, 0o644);
        let meta = std::fs::symlink_metadata(dir.join("netlog.json")).unwrap();
        assert!(meta.file_type().is_file(), "netlog.json final deve ser arquivo regular");
        assert!(meta.len() > 1000, "o NetLog chegou à sessão ({} bytes)", meta.len());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert!(report.requests >= 1);
        eprintln!("swaps tentados pelo atacante: {}", swaps.load(Ordering::SeqCst));
        let _ = std::fs::remove_dir_all(outside);
    }

    /// Primeiro caminho que existe (`lsof` fica em /usr/sbin no macOS e em /usr/bin no Linux).
    fn tool_path(candidates: &[&'static str]) -> &'static str {
        candidates.iter().copied().find(|p| std::path::Path::new(p).exists()).unwrap_or(candidates[0])
    }

    fn lsof_listen(pid: u32) -> String {
        let out = std::process::Command::new(tool_path(&["/usr/sbin/lsof", "/usr/bin/lsof"]))
            .args(["-nP", "-a", "-iTCP", "-sTCP:LISTEN", "-p", &pid.to_string()])
            .output()
            .expect("lsof");
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    fn process_args(pid: u32) -> String {
        let out = std::process::Command::new(tool_path(&["/bin/ps", "/usr/bin/ps"]))
            .args(["-o", "command=", "-p", &pid.to_string()])
            .output()
            .expect("ps");
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    /// Item 5 da revisão: sem `expose_cdp` o Chrome não abre porta nenhuma
    /// (`--remote-debugging-pipe`); com `expose_cdp` a porta escuta SÓ em
    /// 127.0.0.1 e recusa WebSocket de página web (Origin presente).
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_pipe_opens_no_port_and_exposed_port_is_loopback_only() {
        use std::io::{Read, Write};
        let site = TestSite::start(|_m, _p| Reply::html("<html><body>ok</body></html>"));
        let port = site.port;
        // 1. Pipe: nenhuma porta, nenhum --remote-debugging-port.
        let (capture, info) =
            BrowserCapture::start(live_config(vec![format!("localhost:{port}")], "pipe", false)).expect("start");
        assert!(info.cdp.is_none());
        let args = process_args(info.chrome_pid);
        assert!(args.contains("--remote-debugging-pipe"), "{args}");
        assert!(!args.contains("--remote-debugging-port"), "{args}");
        assert!(lsof_listen(info.chrome_pid).trim().is_empty(), "o Chrome abriu porta: {}", lsof_listen(info.chrome_pid));
        let nav = capture
            .navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(10))
            .expect("navigate");
        assert!(nav.loaded);
        let report = capture.stop().expect("stop");
        assert!(report.graceful && report.netlog == "complete");
        // 2. Porta exposta: só 127.0.0.1, sem --remote-allow-origins.
        let (capture, info) =
            BrowserCapture::start(live_config(vec![format!("localhost:{port}")], "port", true)).expect("start");
        let access = info.cdp.clone().expect("cdp exposto");
        let args = process_args(info.chrome_pid);
        assert!(args.contains("--remote-debugging-address=127.0.0.1"), "{args}");
        assert!(!args.contains("--remote-allow-origins"), "{args}");
        assert!(!args.contains("--remote-debugging-pipe"), "{args}");
        let listen = lsof_listen(info.chrome_pid);
        println!("lsof:\n{listen}");
        let names: Vec<&str> = listen.lines().skip(1).filter_map(|l| l.split_whitespace().nth(8)).collect();
        assert!(!names.is_empty(), "esperava uma porta de depuração: {listen}");
        for n in &names {
            assert!(n.starts_with("127.0.0.1:"), "escuta fora do loopback: {n}");
        }
        // WebSocket de uma página web (Origin) é recusado; sem Origin é aceito.
        let ws_path = access.browser_ws.split_once("127.0.0.1:").unwrap().1;
        let (port_s, path) = ws_path.split_once('/').unwrap();
        let handshake = |origin: Option<&str>| -> String {
            let mut s = std::net::TcpStream::connect(format!("127.0.0.1:{port_s}")).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let origin_line = origin.map(|o| format!("Origin: {o}\r\n")).unwrap_or_default();
            write!(
                s,
                "GET /{path} HTTP/1.1\r\nHost: 127.0.0.1:{port_s}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{origin_line}\r\n"
            )
            .unwrap();
            let mut buf = [0u8; 256];
            let n = s.read(&mut buf).unwrap_or(0);
            String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("").to_string()
        };
        let evil = handshake(Some("https://evil.example"));
        let plain = handshake(None);
        println!("com Origin: {evil:?}; sem Origin: {plain:?}");
        assert!(!evil.contains("101"), "página web conseguiu o WebSocket: {evil}");
        assert!(plain.contains("101"), "cliente sem Origin deve conectar: {plain}");
        let _ = capture.stop().expect("stop");
    }

    /// R9: um descritor herdado do lançador, SEM CLOEXEC, não pode chegar ao
    /// Chrome (nem ao processo principal nem aos helpers), com pipe ou com porta;
    /// no modo pipe, só o 3 e o 4 do CDP existem.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_inherited_fds_do_not_leak_into_chrome() {
        use std::ffi::CString;
        let site = TestSite::start(|_m, _p| Reply::html("<html><body>ok</body></html>"));
        let port = site.port;
        let secret = std::env::temp_dir().join(format!("launcher-secret-{}.log", std::process::id()));
        let c_path = CString::new(secret.to_str().unwrap()).unwrap();
        // SAFETY: `open` direto, sem O_CLOEXEC: reproduz o fd 7 do PoC.
        let leaked = unsafe { libc::open(c_path.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o600) };
        assert!(leaked >= 0);
        // Número alto e sem CLOEXEC (F_DUPFD), longe do 3 e do 4 do pipe.
        // SAFETY: `fcntl`/`close` sobre o fd recém-aberto.
        let leaked = unsafe {
            let high = libc::fcntl(leaked, libc::F_DUPFD, 20);
            libc::close(leaked);
            high
        };
        assert!(leaked >= 20);
        let children = |expose: bool, tag: &str| {
            let (capture, info) =
                BrowserCapture::start(live_config(vec![format!("localhost:{port}")], tag, expose)).expect("start");
            let nav = capture
                .navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(10))
                .expect("navigate");
            assert!(nav.loaded);
            // Processo principal e descendentes (helpers).
            let ps = std::process::Command::new(tool_path(&["/bin/ps", "/usr/bin/ps"])).args(["-axo", "pid=,ppid="]).output().unwrap();
            let ps = String::from_utf8_lossy(&ps.stdout).to_string();
            let mut pids = vec![info.chrome_pid];
            for line in ps.lines() {
                let mut it = line.split_whitespace().map(|v| v.parse::<u32>().unwrap_or(0));
                if let (Some(pid), Some(ppid)) = (it.next(), it.next()) {
                    if ppid == info.chrome_pid {
                        pids.push(pid);
                    }
                }
            }
            for pid in &pids {
                let out = std::process::Command::new(tool_path(&["/usr/sbin/lsof", "/usr/bin/lsof"])).args(["-n", "-P", "-p", &pid.to_string()]).output().unwrap();
                let text = String::from_utf8_lossy(&out.stdout).to_string();
                assert!(!text.contains("launcher-secret"), "fd vazou para o pid {pid} ({tag}):\n{text}");
            }
            let _ = capture.stop().expect("stop");
        };
        children(false, "fds-pipe");
        children(true, "fds-port");
        // SAFETY: fecha o fd aberto acima.
        unsafe { libc::close(leaked) };
        let _ = std::fs::remove_file(secret);
    }

    #[test]
    fn r12_navigate_budget_has_a_floor_and_never_adds_the_old_40_seconds() {
        assert_eq!(navigate_budget(Duration::from_millis(100)), MIN_NAVIGATE_BUDGET);
        assert_eq!(navigate_budget(Duration::from_secs(3)), Duration::from_secs(3));
        assert!(
            navigate_budget(Duration::from_secs(3)) + NAVIGATE_REPLY_MARGIN < Duration::from_secs(10),
            "o PoC levava 30,4 s com timeout_ms=3000"
        );
        assert_eq!(NavigateError::TimedOut.code(), "navigate_timeout");
    }

    /// R12 (PoC `poc_sigstop`): com o Chrome PARADO (SIGSTOP), `navigate` com
    /// `timeout_ms=3000` voltava em 30,4 s. Agora respeita o prazo.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_navigate_honours_its_timeout_when_chrome_is_frozen() {
        let site = TestSite::start(|_m, _p| Reply::html("<html><body>ok</body></html>"));
        let port = site.port;
        let (capture, info) =
            BrowserCapture::start(live_config(vec![format!("localhost:{port}")], "sigstop", false)).expect("start");
        let pid = info.chrome_pid as i32;
        // SAFETY: sinais para o processo que nós mesmos iniciamos.
        unsafe { libc::kill(pid, libc::SIGSTOP) };
        let started = Instant::now();
        let result = capture.navigate(&format!("http://localhost:{port}/"), true, Duration::from_millis(3000));
        let elapsed = started.elapsed();
        // SAFETY: idem; retoma antes de qualquer asserção, para o Chrome poder sair.
        unsafe { libc::kill(pid, libc::SIGCONT) };
        println!("navigate com Chrome parado: {result:?} em {elapsed:?}");
        assert!(
            matches!(result, Err(NavigateError::TimedOut)),
            "com o prazo estourado o código é navigate_timeout: {result:?}"
        );
        assert!(elapsed < Duration::from_secs(9), "levou {elapsed:?}; o prazo era 3 s + folga");
        let _ = capture.stop();
    }

    /// A3-B2 (PoC `r12_cap.py`): uma página permitida faz `console.log` de 140 MB.
    /// A mensagem passa do teto do pipe: a captura precisa sair INCOMPLETA com
    /// motivo explícito, e o `navigate` não pode esperar o prazo todo.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_oversized_pipe_message_marks_the_capture_incomplete() {
        oversized_message_marks_the_capture_incomplete(false, "oversize");
    }

    /// A4-B2: o mesmo no modo porta (`expose_cdp`, WebSocket).
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_oversized_websocket_message_marks_the_capture_incomplete() {
        oversized_message_marks_the_capture_incomplete(true, "oversize-ws");
    }

    #[cfg(unix)]
    fn oversized_message_marks_the_capture_incomplete(expose: bool, tag: &str) {
        let site = TestSite::start(|_m, path| {
            if path == "/favicon.ico" {
                return Reply::html("").status(404);
            }
            Reply::html("<html><body><script>console.log('x'.repeat(140e6))</script>ok</body></html>")
        });
        let port = site.port;
        let (capture, _info) =
            BrowserCapture::start(live_config(vec![format!("localhost:{port}")], tag, expose)).expect("start");
        let started = Instant::now();
        let nav = capture.navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(45));
        let elapsed = started.elapsed();
        println!("navigate: {nav:?} em {elapsed:?}");
        assert!(elapsed < Duration::from_secs(40), "esperou o prazo todo: {elapsed:?}");
        let report = capture.stop().expect("stop");
        println!("stop: graceful={} netlog={} warnings={:?}", report.graceful, report.netlog, report.warnings);
        assert!(!report.graceful);
        assert!(
            report.warnings.iter().any(|w| w.contains("cdp_transport_closed: frame_too_large")),
            "{:?}",
            report.warnings
        );
        let session_json =
            std::fs::read_to_string(std::path::Path::new(&report.session_dir).join("session.json")).unwrap();
        assert!(session_json.contains("cdp_transport_closed: frame_too_large"));
        let doc: serde_json::Value = serde_json::from_str(&session_json).unwrap();
        let state = doc["session"]["completeness"]["state"].as_str().unwrap_or("?").to_string();
        println!("completeness.state = {state}");
        assert_ne!(state, "complete", "a sessão não pode sair complete");
    }

    /// A4-B5 (PoC `n_newsurface.py`, dirswap): a pasta da sessão é trocada por um
    /// symlink para OUT durante a captura. O stop falha com erro claro, nada é
    /// gravado em OUT, os links de OUT não são removidos e os dados ficam no
    /// perfil temporário.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_swapped_session_dir_fails_the_stop_without_touching_outside() {
        use std::os::unix::fs::symlink;
        let site = TestSite::start(|_m, _p| Reply::html("<html><body>ok</body></html>"));
        let port = site.port;
        let config = live_config(vec![format!("localhost:{port}")], "dirswap", false);
        let dir = config.session_dir.clone();
        let (capture, _info) = BrowserCapture::start(config).expect("start");
        let _ = capture.navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(10));
        // Troca a pasta por um link para OUT (que contém links para um alvo).
        let out = std::env::temp_dir().join(format!("scrapelens-dirswap-out-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        std::fs::create_dir_all(&out).unwrap();
        let victim = out.join("VICTIM.txt");
        std::fs::write(&victim, "ORIGINAL\n").unwrap();
        for name in ["netlog.json", "session.json"] {
            symlink(&victim, out.join(name)).unwrap();
        }
        let moved = dir.with_file_name(format!("{}-orig", dir.file_name().unwrap().to_string_lossy()));
        std::fs::rename(&dir, &moved).unwrap();
        symlink(&out, &dir).unwrap();
        let result = capture.stop();
        let error = result.expect_err("o stop devia falhar com a pasta trocada");
        println!("erro: {error}");
        assert!(error.contains("pasta da sessão foi trocada"), "{error}");
        assert!(error.contains("agora é um link simbólico"), "{error}");
        assert!(error.contains("pasta de resgate"), "{error}");
        // OUT intacto: mesmos 3 nomes, links não removidos, alvo igual.
        let mut names: Vec<String> = std::fs::read_dir(&out)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        assert_eq!(names, ["VICTIM.txt", "netlog.json", "session.json"]);
        for name in ["netlog.json", "session.json"] {
            assert!(std::fs::symlink_metadata(out.join(name)).unwrap().file_type().is_symlink(), "{name} mexido");
        }
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "ORIGINAL\n");
        // Os dados ficaram na pasta de resgate citada no erro: só os arquivos da
        // captura, nada do perfil do Chrome.
        let rescue = rescue_dir_from(&error);
        assert!(rescue.join("cdp-events.jsonl").is_file(), "sem cdp-events em {}", rescue.display());
        assert!(rescue.join("netlog.json").is_file());
        assert_no_chrome_profile_data(&rescue);
        let _ = std::fs::remove_dir_all(&rescue);
        let _ = std::fs::remove_file(rescue.with_extension("json"));
        let _ = std::fs::remove_dir_all(out);
        let _ = std::fs::remove_dir_all(moved);
        let _ = std::fs::remove_file(dir);
    }

    /// Pasta de resgate citada no erro do stop.
    fn rescue_dir_from(error: &str) -> PathBuf {
        let after = error.split("pasta de resgate ").nth(1).expect("erro cita a pasta de resgate");
        PathBuf::from(after.split(" (0700").next().unwrap().trim())
    }

    /// O resgate só tem os arquivos da captura: nenhum dado do perfil do Chrome.
    fn assert_no_chrome_profile_data(dir: &std::path::Path) {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        for name in &names {
            assert!(
                ["cdp-bodies.jsonl", "cdp-events.jsonl", "motivo.txt", "netlog.json"].contains(&name.as_str()),
                "arquivo inesperado no resgate: {name} (todos: {names:?})"
            );
        }
        for forbidden in ["Cookies", "Login Data", "History", "Default", "Local State"] {
            assert!(!names.iter().any(|n| n == forbidden), "{forbidden} no resgate");
        }
    }

    /// A5-B2: uma falha de gravação com a pasta ainda nossa (aqui, um DIRETÓRIO no
    /// nome de `session.json`, que o core recusa) também resgata os dados, não
    /// apaga o perfil antes, e não deixa `.tmp-*` na pasta da sessão.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_any_write_failure_rescues_the_capture_files() {
        let site = TestSite::start(|_m, _p| Reply::html("<html><body>ok</body></html>"));
        let port = site.port;
        let config = live_config(vec![format!("localhost:{port}")], "writefail", false);
        let dir = config.session_dir.clone();
        let (capture, _info) = BrowserCapture::start(config).expect("start");
        let _ = capture.navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(10));
        std::fs::create_dir(dir.join("session.json")).unwrap();
        let error = capture.stop().expect_err("o core recusa um diretório no lugar de session.json");
        println!("erro: {error}");
        assert!(error.contains("pasta de resgate"), "{error}");
        let rescue = rescue_dir_from(&error);
        assert!(rescue.join("cdp-events.jsonl").is_file());
        assert!(rescue.join("netlog.json").is_file());
        assert!(rescue.join("cdp-bodies.jsonl").is_file(), "os corpos também são resgatados");
        assert!(rescue.join("motivo.txt").is_file());
        assert_no_chrome_profile_data(&rescue);
        // Sem `.tmp-*` perdido na pasta da sessão.
        let strays: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tmp-"))
            .collect();
        assert!(strays.is_empty(), "{strays:?}");
        // Marcador do resgate existe no state root.
        let marker = rescue.with_extension("json");
        assert!(marker.is_file(), "sem marcador {}", marker.display());
        let _ = std::fs::remove_dir_all(&rescue);
        let _ = std::fs::remove_file(marker);
    }

    /// Captura COMUM (`crate::run`) contra um servidor local acessado por um NOME que
    /// não é `127.0.0.1` nem `localhost` (`<nome>.localhost`, que o Chrome resolve
    /// para loopback sozinho). Devolve `(requisições do site vistas pelo servidor,
    /// status das requisições da sessão para o nome)`.
    #[cfg(unix)]
    fn run_common_capture(mode: crate::NetworkMode, tag: &str) -> (usize, Vec<u64>) {
        use std::sync::mpsc::channel;
        let site = TestSite::start(|_m, _p| Reply::html("<html><body>aberto</body></html>"));
        let port = site.port;
        let name = "sl-open-mode.localhost";
        let dir = std::env::temp_dir().join(format!(
            "scrapelens-open-{tag}-{}-{}",
            std::process::id(),
            super::super::unix_millis()
        ));
        let config = crate::CaptureConfig {
            chrome: chrome_or_skip(),
            session_dir: dir.clone(),
            start_url: format!("http://{name}:{port}/"),
            headless: true,
            ignore_cert: false,
            network: mode,
            cookie_source: None,
            initial_cookies: Vec::new(),
        };
        let status = Arc::new(Mutex::new(CaptureStatus::default()));
        let (stop_tx, stop_rx) = channel();
        let (ready_tx, ready_rx) = channel();
        let join = thread::spawn(move || crate::run(config, status, stop_rx, ready_tx));
        ready_rx
            .recv_timeout(Duration::from_secs(40))
            .expect("captura pronta")
            .expect("captura iniciou");
        // Espera o servidor ver a requisição (modo aberto) ou dá um prazo (loopback).
        let deadline = Instant::now() + Duration::from_secs(8);
        while site.seen_paths().is_empty() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(200));
        }
        thread::sleep(Duration::from_millis(800));
        let _ = stop_tx.send(());
        let outcome = join.join().expect("thread").expect("captura encerrou");
        let statuses = outcome.session["requests"]
            .as_array()
            .map(|requests| {
                requests
                    .iter()
                    .filter(|r| r["url"].as_str().is_some_and(|u| u.contains(name)))
                    .filter_map(|r| r["status"].as_u64())
                    .collect()
            })
            .unwrap_or_default();
        let _ = std::fs::remove_dir_all(dir);
        (site.seen_paths().len(), statuses)
    }

    /// Defeito do usuário: `Iniciar sessão` com `https://google.com.br` abria o Chrome
    /// com `DNS_PROBE_FINISHED_NXDOMAIN`, porque a captura comum levava
    /// `--host-resolver-rules=MAP * ~NOTFOUND…`. Sem acessar site real: um nome local
    /// resolvido pelo próprio Chrome carrega no modo aberto e NÃO no `LoopbackOnly`.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_open_mode_resolves_a_local_name_and_loopback_only_does_not() {
        let (seen_open, statuses_open) = run_common_capture(crate::NetworkMode::Open, "open");
        println!("Open: servidor viu {seen_open}, status {statuses_open:?}");
        assert!(seen_open >= 1, "o modo aberto devia chegar ao servidor pelo nome local");
        assert!(statuses_open.contains(&200), "{statuses_open:?}");

        let (seen_lo, statuses_lo) = run_common_capture(crate::NetworkMode::LoopbackOnly, "loopback");
        println!("LoopbackOnly: servidor viu {seen_lo}, status {statuses_lo:?}");
        assert_eq!(seen_lo, 0, "o nome local não podia resolver em LoopbackOnly");
        assert!(!statuses_lo.contains(&200), "{statuses_lo:?}");
    }

    /// Página-sonda local: grava `navigator.webdriver` no servidor (`/wd?webdriver=…`).
    #[cfg(unix)]
    fn webdriver_probe_site() -> TestSite {
        TestSite::start(|_m, path| {
            if path.starts_with("/wd") || path == "/favicon.ico" {
                return Reply::html("").status(204);
            }
            Reply::html(
                "<html><body><script>fetch('/wd?webdriver='+navigator.webdriver)</script>sonda</body></html>",
            )
        })
    }

    #[cfg(unix)]
    fn webdriver_seen(site: &TestSite) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let seen: Vec<String> = site
                .seen_paths()
                .into_iter()
                .filter_map(|p| p.split("/wd?webdriver=").nth(1).map(str::to_string))
                .collect();
            if !seen.is_empty() || Instant::now() >= deadline {
                return seen;
            }
            thread::sleep(Duration::from_millis(200));
        }
    }

    /// D7, captura COMUM completa (`run`/`run_with_options`) nos dois transportes: a
    /// página lê `navigator.webdriver === false` (sem a flag seria `true` com o CDP
    /// ligado) e a sessão registra a flag em `capture.chromeArgs`/`notes`.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_full_capture_hides_navigator_webdriver_on_both_transports() {
        use std::sync::mpsc::channel;
        for (transport, tag) in [(crate::transport::CdpTransport::Pipe, "pipe"), (crate::transport::CdpTransport::Port, "port")] {
            let site = webdriver_probe_site();
            let dir = std::env::temp_dir().join(format!(
                "scrapelens-d7-{tag}-{}-{}",
                std::process::id(),
                super::super::unix_millis()
            ));
            let config = crate::CaptureConfig {
                chrome: chrome_or_skip(),
                session_dir: dir.clone(),
                start_url: format!("http://127.0.0.1:{}/", site.port),
                headless: live_headless(),
                ignore_cert: false,
                network: crate::NetworkMode::LoopbackOnly,
                cookie_source: None,
                initial_cookies: Vec::new(),
            };
            let status = Arc::new(Mutex::new(CaptureStatus::default()));
            let (stop_tx, stop_rx) = channel();
            let (ready_tx, ready_rx) = channel();
            let opts = crate::RunOptions { transport, ..crate::RunOptions::default() };
            let join = thread::spawn(move || crate::run_with_options(config, status, stop_rx, ready_tx, &opts));
            ready_rx.recv_timeout(Duration::from_secs(40)).expect("pronta").expect("iniciou");
            let seen = webdriver_seen(&site);
            println!("{tag}: navigator.webdriver visto pela página = {seen:?}");
            assert_eq!(seen, ["false"], "{tag}: a captura completa devia esconder navigator.webdriver");
            let _ = stop_tx.send(());
            let (outcome, _) = join.join().expect("thread").expect("encerrou");
            let capture = &outcome.session["session"]["capture"];
            let args: Vec<&str> = capture["chromeArgs"].as_array().expect("chromeArgs").iter().filter_map(|v| v.as_str()).collect();
            assert!(args.contains(&"--disable-blink-features=AutomationControlled"), "{tag}: {args:?}");
            assert_eq!(args.contains(&"--remote-debugging-pipe"), tag == "pipe", "{tag}: {args:?}");
            assert!(capture["notes"].as_str().unwrap_or("").contains("AutomationControlled"), "{capture}");
            // O registro não vaza os caminhos temporários.
            assert!(args.iter().all(|a| !a.contains(&*dir.display().to_string())), "{args:?}");
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// Cookies importados (`CaptureConfig.initial_cookies`) chegam no PRIMEIRO
    /// pedido da navegação inicial, e o evento de auditoria entra no stream CDP
    /// sem os valores. Loopback, headless conforme `SL_LIVE_HEADED`.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_imported_cookies_are_sent_with_the_first_navigation() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::mpsc::channel;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let heads: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let heads_thread = heads.clone();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                let mut buf = vec![0u8; 16 * 1024];
                let mut total = 0;
                while total < buf.len() {
                    match stream.read(&mut buf[total..]) {
                        Ok(0) => break,
                        Ok(n) => {
                            total += n;
                            if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                heads_thread
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[..total]).to_string());
                let body = b"ok";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(body);
                let _ = stream.flush();
            }
        });

        let dir = std::env::temp_dir().join(format!(
            "scrapelens-cookies-live-{}-{}",
            std::process::id(),
            super::super::unix_millis()
        ));
        let cookie = crate::cookies::ImportedCookie {
            name: "sid".to_string(),
            value: "abc123".to_string(),
            domain: "127.0.0.1".to_string(),
            path: "/".to_string(),
            secure: false,
            http_only: false,
            same_site: Some("Lax".to_string()),
            expires: None,
        };
        let config = crate::CaptureConfig {
            chrome: chrome_or_skip(),
            session_dir: dir.clone(),
            start_url: format!("http://127.0.0.1:{port}/"),
            headless: live_headless(),
            ignore_cert: false,
            network: crate::NetworkMode::LoopbackOnly,
            cookie_source: None,
            initial_cookies: vec![cookie],
        };
        let status = Arc::new(Mutex::new(CaptureStatus::default()));
        let (stop_tx, stop_rx) = channel();
        let (ready_tx, ready_rx) = channel();
        let join = thread::spawn(move || crate::run(config, status, stop_rx, ready_tx));
        ready_rx.recv_timeout(Duration::from_secs(40)).expect("pronta").expect("iniciou");
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut saw_cookie = false;
        while Instant::now() < deadline && !saw_cookie {
            saw_cookie = heads
                .lock()
                .unwrap()
                .iter()
                .any(|head| head.lines().any(|line| line.eq_ignore_ascii_case("cookie: sid=abc123")));
            thread::sleep(Duration::from_millis(100));
        }
        assert!(saw_cookie, "o primeiro pedido devia levar o cookie importado: {:?}", heads.lock().unwrap());
        let _ = stop_tx.send(());
        let outcome = join.join().expect("thread").expect("encerrou");
        assert!(outcome.notice.contains("cookie(s) importado(s)"), "{}", outcome.notice);
        let events = std::fs::read_to_string(dir.join("cdp-events.jsonl")).unwrap();
        assert!(events.contains("Capture.cookiesImported"), "falta o evento de auditoria");
        assert!(events.contains("\"importedCount\":1"), "{events}");
        let audit = events
            .lines()
            .find(|line| line.contains("Capture.cookiesImported"))
            .expect("linha de auditoria");
        assert!(!audit.contains("abc123"), "o evento de auditoria não pode gravar o valor: {audit}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// D7, captura CONTROLADA do MCP (allowlist), pipe e `expose_cdp` (porta).
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_controlled_capture_hides_navigator_webdriver_on_both_transports() {
        for (expose, tag) in [(false, "pipe"), (true, "port")] {
            let site = webdriver_probe_site();
            let port = site.port;
            let (capture, _info) =
                BrowserCapture::start(live_config(vec![format!("localhost:{port}")], &format!("d7-{tag}"), expose)).expect("start");
            capture
                .navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(15))
                .expect("navigate");
            let seen = webdriver_seen(&site);
            println!("controlada {tag}: navigator.webdriver = {seen:?}");
            assert_eq!(seen, ["false"], "controlada/{tag}");
            let report = capture.stop().expect("stop");
            let session_json = std::fs::read_to_string(std::path::Path::new(&report.session_dir).join("session.json")).unwrap();
            assert!(session_json.contains("--disable-blink-features=AutomationControlled"), "{tag}");
        }
    }

    #[test]
    fn test_site_serves_and_records() {
        let site = TestSite::start(|_m, path| Reply::html(&format!("<p>{path}</p>")).header("X-T", "1"));
        let mut s = std::net::TcpStream::connect(("127.0.0.1", site.port)).unwrap();
        use std::io::{Read, Write};
        s.write_all(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        assert!(out.starts_with("HTTP/1.1 200 OK"));
        assert!(out.contains("X-T: 1"));
        assert_eq!(site.seen_paths(), vec!["GET /a"]);
    }
}
