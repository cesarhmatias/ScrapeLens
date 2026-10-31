//! Captura controlada para o MCP (`docs/16b-mcp-navegador.md` §3–§4).
//!
//! `BrowserCapture` abre o Chrome estável com perfil dedicado, CDP + NetLog e
//! **allowlist obrigatória**, aceita `navigate` e encerra de forma graciosa. A
//! thread de captura continua dona do soquete CDP; `navigate` é uma mensagem
//! num canal consumido pelo laço de gravação. A confirmação do usuário
//! (elicitação MCP) acontece na camada do servidor, antes de chamar esta API.

use std::path::PathBuf;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::WebSocket;

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
        reply: Sender<Result<NavigateResult, String>>,
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
}

impl NavigateError {
    pub fn code(&self) -> &'static str {
        match self {
            NavigateError::UrlNotAllowed(_) => "url_not_allowed",
            NavigateError::CaptureStopped => "capture_stopped",
            NavigateError::Failed(_) => "navigate_failed",
        }
    }
}

impl std::fmt::Display for NavigateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NavigateError::UrlNotAllowed(e) => write!(f, "{e}"),
            NavigateError::CaptureStopped => write!(f, "a captura já foi encerrada"),
            NavigateError::Failed(e) => write!(f, "{e}"),
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
        // O laço atende em até ~250 ms; a resposta chega depois da carga.
        match reply_rx.recv_timeout(timeout + Duration::from_secs(40)) {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(error)) => Err(NavigateError::Failed(error)),
            Err(_) => Err(NavigateError::CaptureStopped),
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
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
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
        socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
        url: &str,
        wait_load: bool,
        timeout: Duration,
    ) -> Result<NavigateResult, String> {
        if self.page_session_id.is_empty() {
            return Err("a aba principal não está pronta".to_string());
        }
        let page = self.page_session_id.clone();
        let before = self.page_load_events;
        let result = self.send(
            socket,
            "Page.navigate",
            json!({ "url": url }),
            Some(&page),
            Duration::from_secs(30),
        )?;
        let text = |key: &str| result.get(key).and_then(Value::as_str).map(str::to_string);
        let error_text = text("errorText");
        let mut loaded = false;
        if error_text.is_none() && wait_load {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                if self.page_load_events > before {
                    loaded = true;
                    break;
                }
                self.pump_socket(socket, Duration::from_millis(100));
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

    fn live_config(allowed: Vec<String>, name: &str, expose_cdp: bool) -> BrowserCaptureConfig {
        BrowserCaptureConfig {
            chrome: chrome_or_skip(),
            session_dir: std::env::temp_dir().join(format!(
                "scrapelens-bc-live-{name}-{}-{}",
                std::process::id(),
                super::super::unix_millis()
            )),
            start_url: None,
            headless: true,
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
            if let MaybeTlsStream::Plain(stream) = socket.get_ref() {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
            }
            let mut next = 0u64;
            let mut send = |socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
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
