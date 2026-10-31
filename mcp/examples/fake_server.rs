//! Servidor MCP com navegador FALSO, só para os testes ponta a ponta: usa a
//! `Allowlist` real, mas não abre Chrome nem rede. `stop` grava uma sessão
//! sintética (HAR com sinais de Cloudflare inventados, domínio `.invalid`).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scrapelens_capture::allowlist::{Allowlist, AllowlistReport};
use scrapelens_capture::browser::{
    AllowlistInfo, BrowserCaptureConfig, BrowserInfo, CdpAccess, NavigateError, NavigateResult,
    StartError, StartInfo, StopReport, SENSITIVE_NOTICE,
};
use scrapelens_capture::CaptureStatus;
use scrapelens_mcp::error::ToolError;
use scrapelens_mcp::live::{CaptureBackend, LiveCapture};
use serde_json::json;

struct FakeBackend;

struct FakeLive {
    allowlist: Allowlist,
    session_dir: PathBuf,
    pages: Mutex<Vec<String>>,
}

fn synthetic_har(pages: &[String]) -> Vec<u8> {
    let entry = |when: &str, url: &str, status: u16, resp: Vec<(&str, &str)>| {
        json!({
            "startedDateTime": when, "time": 10.0,
            "request": {"method": "GET", "url": url, "httpVersion": "HTTP/1.1",
                "headers": [{"name": "Accept", "value": "text/html"}],
                "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0},
            "response": {"status": status, "statusText": "", "httpVersion": "HTTP/1.1",
                "headers": resp.iter().map(|(n, v)| json!({"name": n, "value": v})).collect::<Vec<_>>(),
                "cookies": [], "redirectURL": "", "headersSize": -1, "bodySize": 0,
                "content": {"mimeType": "text/html", "size": 2, "text": "ok"}},
            "cache": {}, "timings": {"send": 0, "wait": 8, "receive": 2},
        })
    };
    let first = pages
        .first()
        .cloned()
        .unwrap_or_else(|| "http://site.invalid.test/".into());
    let entries = vec![
        entry(
            "2026-10-31T10:00:00.000Z",
            &format!("{first}?utm=SEGREDO-QUERY-1"),
            200,
            vec![
                ("content-type", "text/html"),
                ("cf-ray", "abc-GRU"),
                ("set-cookie", "__cf_bm=SEGREDO-BM-1; Path=/; HttpOnly"),
            ],
        ),
        entry(
            "2026-10-31T10:00:01.000Z",
            "http://site.invalid.test/area",
            403,
            vec![("content-type", "text/html"), ("cf-mitigated", "challenge")],
        ),
    ];
    json!({"log": {"version": "1.2", "creator": {"name": "fake", "version": "1"}, "pages": [], "entries": entries}})
        .to_string()
        .into_bytes()
}

impl LiveCapture for FakeLive {
    fn navigate(
        &self,
        url: &str,
        _wait: bool,
        _timeout: Duration,
    ) -> Result<NavigateResult, NavigateError> {
        let allowed = self
            .allowlist
            .permits_url(url)
            .map_err(NavigateError::UrlNotAllowed)?;
        self.pages.lock().unwrap().push(allowed.url);
        Ok(NavigateResult {
            frame_id: Some("F1".into()),
            loader_id: Some("L1".into()),
            loaded: true,
            error_text: None,
        })
    }

    fn status(&self) -> CaptureStatus {
        let pages = self.pages.lock().unwrap();
        CaptureStatus {
            recording: true,
            events: pages.len(),
            page_url: pages.last().cloned().unwrap_or_default() + "?token=SEGREDO-STATUS-1",
            session_dir: self.session_dir.display().to_string(),
            ..CaptureStatus::default()
        }
    }

    fn stop(self: Box<Self>) -> Result<StopReport, String> {
        // Teste de SIGTERM durante o stop: o encerramento demora a gravar.
        if let Some(ms) = std::env::var("FAKE_STOP_DELAY_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
        {
            std::thread::sleep(Duration::from_millis(ms));
        }
        let pages = self.pages.lock().unwrap().clone();
        let imported =
            scrapelens_core::import_har(&synthetic_har(&pages)).map_err(|e| e.to_string())?;
        scrapelens_core::store::write_session_dir(&imported.bundle, &self.session_dir)
            .map_err(|e| e.to_string())?;
        let mut report = AllowlistReport::default();
        report
            .blocked_hosts
            .push(scrapelens_capture::allowlist::BlockedHost {
                host: "challenges.invalid.test".into(),
                requests: 1,
                example_url: "http://challenges.invalid.test/api.js?k=SEGREDO-EXEMPLO-1".into(),
            });
        Ok(StopReport {
            session_dir: self.session_dir.display().to_string(),
            requests: imported.bundle.session.requests.len(),
            netlog: "complete".into(),
            graceful: true,
            waited_ms: 1,
            allowlist: report,
            warnings: vec![
                "violação: http://site.invalid.test:9/p;jsessionid=SEGREDO-VIOL?x=1&k=SEGREDO-VIOLQ#access_token=SEGREDO-VIOLF fora da allowlist".into(),
            ],
            outcome: None,
        })
    }
}

impl CaptureBackend for FakeBackend {
    fn resolve_chrome(&self, _binary_path: Option<&str>) -> Result<PathBuf, ToolError> {
        Ok(PathBuf::from("/fake/Google Chrome"))
    }

    fn start(
        &self,
        config: BrowserCaptureConfig,
    ) -> Result<(Box<dyn LiveCapture>, StartInfo), StartError> {
        let allowlist = Allowlist::new(&config.allowed_hosts, &config.third_party_hosts)
            .map_err(StartError::Allowlist)?;
        // Teste de encerramento durante o início: o "Chrome" demora a subir.
        if let Some(ms) = std::env::var("FAKE_START_DELAY_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
        {
            std::thread::sleep(Duration::from_millis(ms));
        }
        if let Some(url) = config.start_url.as_deref() {
            allowlist
                .permits_url(url)
                .map_err(StartError::StartUrlNotAllowed)?;
        }
        std::fs::create_dir_all(&config.session_dir)
            .map_err(|e| StartError::SessionDir(e.to_string()))?;
        let info = StartInfo {
            session_dir: config.session_dir.display().to_string(),
            chrome_pid: 4242,
            browser: BrowserInfo {
                path: config.chrome.display().to_string(),
                version: Some("Chrome/0 (falso)".into()),
                user_agent: None,
            },
            allowlist: AllowlistInfo {
                allowed_hosts: allowlist.allowed_hosts(),
                third_party_hosts: allowlist.third_party_hosts(),
                resolver_rules: allowlist.resolver_rules(),
            },
            cdp: config.expose_cdp.then(|| CdpAccess {
                http: Some("http://127.0.0.1:1".into()),
                browser_ws: "ws://127.0.0.1:1/devtools/browser/fake".into(),
                page_target_id: Some("T1".into()),
            }),
            sensitive_notice: SENSITIVE_NOTICE,
            warnings: vec![],
        };
        Ok((
            Box::new(FakeLive {
                allowlist,
                session_dir: config.session_dir,
                pages: Mutex::new(vec![]),
            }),
            info,
        ))
    }
}

#[tokio::main]
async fn main() {
    match scrapelens_mcp::cli::parse_args(std::env::args().skip(1).collect()) {
        Ok(config) => {
            let code = scrapelens_mcp::app::run(config, Arc::new(FakeBackend)).await;
            std::process::exit(code);
        }
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    }
}
