//! Capturas ao vivo controladas pelo servidor: o mapa `capture_id` → captura,
//! a validação do pedido, a decisão de confirmação e a saída mascarada.
//!
//! O navegador fica atrás de [`CaptureBackend`]/[`LiveCapture`]: o produto usa
//! `scrapelens-capture` ([`RealBackend`]); os testes usam um navegador falso.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use schemars::JsonSchema;
use scrapelens_capture::allowlist::Allowlist;
use scrapelens_capture::browser::{
    BrowserCapture, BrowserCaptureConfig, NavigateError, NavigateResult, StartError, StartInfo,
    StopReport, SENSITIVE_NOTICE,
};
use scrapelens_capture::CaptureStatus;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::config::valid_name;
use crate::error::ToolError;
use crate::registry::Ctx;

pub const DEFAULT_NAVIGATE_TIMEOUT_MS: u64 = 15_000;
pub const MAX_NAVIGATE_TIMEOUT_MS: u64 = 60_000;

// ---------------------------------------------------------------------------
// navegador atrás de um trait
// ---------------------------------------------------------------------------

pub trait LiveCapture: Send {
    fn navigate(
        &self,
        url: &str,
        wait_load: bool,
        timeout: Duration,
    ) -> Result<NavigateResult, NavigateError>;
    fn status(&self) -> CaptureStatus;
    /// Encerramento gracioso; grava a sessão em `session_dir`.
    fn stop(self: Box<Self>) -> Result<StopReport, String>;
}

pub trait CaptureBackend: Send + Sync {
    /// Chamado uma vez ao iniciar o servidor (limpeza de capturas órfãs de
    /// execuções anteriores que morreram sem encerrar o Chrome).
    fn startup(&self) {}

    /// Chrome que seria usado (`binary_path` explícito ou detecção).
    fn resolve_chrome(&self, binary_path: Option<&str>) -> Result<PathBuf, ToolError>;
    fn start(
        &self,
        config: BrowserCaptureConfig,
    ) -> Result<(Box<dyn LiveCapture>, StartInfo), StartError>;
}

pub struct RealBackend;

impl LiveCapture for BrowserCapture {
    fn navigate(
        &self,
        url: &str,
        wait_load: bool,
        timeout: Duration,
    ) -> Result<NavigateResult, NavigateError> {
        BrowserCapture::navigate(self, url, wait_load, timeout)
    }

    fn status(&self) -> CaptureStatus {
        BrowserCapture::status(self)
    }

    fn stop(self: Box<Self>) -> Result<StopReport, String> {
        BrowserCapture::stop(*self)
    }
}

impl CaptureBackend for RealBackend {
    fn startup(&self) {
        let report = scrapelens_capture::cleanup_orphans(&scrapelens_capture::default_state_root());
        if report.processes_killed + report.profiles_removed + report.markers_removed > 0 {
            eprintln!(
                "scrapelens-mcp: órfãos de execuções anteriores limpos (processos {}, perfis {}, marcadores {})",
                report.processes_killed, report.profiles_removed, report.markers_removed
            );
        }
    }

    fn resolve_chrome(&self, binary_path: Option<&str>) -> Result<PathBuf, ToolError> {
        use scrapelens_capture::chrome;
        let explicit = match binary_path.filter(|p| !p.trim().is_empty()) {
            Some(path) => Some(
                chrome::normalize_binary_path(std::path::Path::new(path)).ok_or_else(|| {
                    ToolError::new(
                        "browser_start_failed",
                        format!("binary_path não é um Chrome: {path}"),
                    )
                })?,
            ),
            None => None,
        };
        let info = chrome::detect(explicit.as_deref());
        info.path
            .filter(|_| info.found)
            .map(PathBuf::from)
            .ok_or_else(|| {
                ToolError::new(
                    "browser_start_failed",
                    "Chrome estável não encontrado; informe binary_path",
                )
            })
    }

    fn start(
        &self,
        config: BrowserCaptureConfig,
    ) -> Result<(Box<dyn LiveCapture>, StartInfo), StartError> {
        let (capture, info) = BrowserCapture::start(config)?;
        Ok((Box::new(capture), info))
    }
}

// ---------------------------------------------------------------------------
// parâmetros
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StartCaptureParams {
    /// Hosts onde o agente pode navegar (obrigatório, ao menos um). Nome exato,
    /// `*.dominio` ou IP literal explícito; porta opcional (`host:8080`).
    pub allowed_hosts: Vec<String>,
    /// Hosts adicionais que a página precisa carregar (CDN, desafios).
    pub third_party_hosts: Option<Vec<String>>,
    /// URL inicial (precisa passar na allowlist).
    pub start_url: Option<String>,
    /// Caminho do Chrome; padrão: detecção automática.
    pub binary_path: Option<String>,
    /// Chrome sem janela (padrão false).
    pub headless: Option<bool>,
    /// Entrega o endereço CDP em loopback ao agente (padrão false).
    pub expose_cdp: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct NavigateParams {
    pub capture_id: String,
    /// URL http(s) de um host permitido.
    pub url: String,
    /// `load` (padrão) ou `none`.
    pub wait: Option<String>,
    /// Prazo em ms (padrão 15000, máximo 60000).
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CaptureIdParams {
    pub capture_id: String,
}

/// Formulário da elicitação: o usuário marca explicitamente.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ConfirmStart {
    /// Marque para autorizar abrir o Chrome e capturar o tráfego descrito.
    pub confirmo: bool,
}
rmcp::elicit_safe!(ConfirmStart);

// ---------------------------------------------------------------------------
// confirmação
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirmation {
    Accepted,
    Declined(String),
    Cancelled,
    /// O cliente não suporta (ou não conseguiu fazer) a elicitação.
    Unavailable(String),
}

/// Aplica a política: sem aceite explícito não abre nada; sem elicitação só
/// passa com `--allow-unconfirmed-capture`. Devolve como foi confirmada.
pub fn decide(
    confirmation: &Confirmation,
    allow_unconfirmed: bool,
) -> Result<&'static str, ToolError> {
    match confirmation {
        Confirmation::Accepted => Ok("elicited"),
        Confirmation::Declined(why) => Err(ToolError::new(
            "confirmation_denied",
            format!("o usuário não confirmou: {why}. Nada foi aberto."),
        )),
        Confirmation::Cancelled => Err(ToolError::new(
            "confirmation_denied",
            "a confirmação foi cancelada ou expirou. Nada foi aberto.",
        )),
        Confirmation::Unavailable(why) if allow_unconfirmed => {
            let _ = why;
            Ok("unconfirmed-flag")
        }
        Confirmation::Unavailable(why) => Err(ToolError::new(
            "confirmation_unavailable",
            format!(
                "o cliente MCP não permite pedir confirmação ({why}); start_capture é recusado por padrão. Nada foi aberto. O operador pode iniciar o servidor com --allow-unconfirmed-capture."
            ),
        )),
    }
}

// ---------------------------------------------------------------------------
// mapa de capturas
// ---------------------------------------------------------------------------

struct Running {
    cap: Mutex<Option<Box<dyn LiveCapture>>>,
    /// Nome do diretório da sessão (handle das ferramentas de leitura).
    session_handle: String,
}

enum Slot {
    Starting,
    Running(Arc<Running>),
}

pub struct Prepared {
    pub capture_id: String,
    pub session_handle: String,
    pub config: BrowserCaptureConfig,
    pub message: String,
}

pub struct Manager {
    backend: Arc<dyn CaptureBackend>,
    slots: Mutex<HashMap<String, Slot>>,
    /// O servidor está encerrando: nada novo abre, e o que ainda estiver
    /// subindo é encerrado assim que o navegador responder.
    shutting_down: AtomicBool,
    /// `backend.start` em andamento (o Chrome pode existir antes de a captura
    /// ser registrada).
    starts_in_flight: AtomicUsize,
}

fn new_id() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    format!("cap-{:016x}", hasher.finish())
}

fn strip_path_fields(object: &mut Map<String, Value>) {
    object.remove("sessionDir");
}

impl Manager {
    pub fn new(backend: Arc<dyn CaptureBackend>) -> Self {
        Self {
            backend,
            slots: Mutex::new(HashMap::new()),
            shutting_down: AtomicBool::new(false),
            starts_in_flight: AtomicUsize::new(0),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Slot>> {
        self.slots.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Valida o pedido, reserva a única vaga e monta o texto da confirmação.
    /// Nada é aberto aqui.
    pub fn prepare(&self, ctx: &Ctx, params: StartCaptureParams) -> Result<Prepared, ToolError> {
        let third = params.third_party_hosts.clone().unwrap_or_default();
        let allowlist = Allowlist::new(&params.allowed_hosts, &third)
            .map_err(|e| ToolError::new(e.code(), e.to_string()))?;
        let start_url = params.start_url.clone().filter(|u| !u.trim().is_empty());
        if let Some(url) = &start_url {
            allowlist
                .permits_url(url)
                .map_err(|e| ToolError::new("start_url_not_allowed", format!("start_url: {e}")))?;
        }
        let chrome = self.backend.resolve_chrome(params.binary_path.as_deref())?;
        let headless = params.headless.unwrap_or(false);
        let expose_cdp = params.expose_cdp.unwrap_or(false);

        let mut slots = self.lock();
        if self.shutting_down.load(Ordering::SeqCst) {
            return Err(ToolError::new(
                "shutting_down",
                "o servidor está encerrando",
            ));
        }
        if !slots.is_empty() {
            return Err(ToolError::new(
                "capture_already_running",
                "já existe uma captura ativa (ou iniciando); encerre-a com stop_capture antes de iniciar outra",
            ));
        }
        let capture_id = new_id();
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let session_handle = format!("capture-{millis}");
        debug_assert!(valid_name(&session_handle));
        let session_dir = ctx.cfg.sessions_dir.join(&session_handle);
        if session_dir.exists() {
            return Err(ToolError::new(
                "exists",
                "diretório de sessão já existe; tente de novo",
            ));
        }
        slots.insert(capture_id.clone(), Slot::Starting);

        let list = |hosts: Vec<String>| {
            if hosts.is_empty() {
                "(nenhum)".to_string()
            } else {
                hosts.join(", ")
            }
        };
        let message = format!(
            "Um agente pediu para abrir o Chrome e capturar o tráfego de rede.\n\
             Hosts permitidos (navegar e agir): {}\n\
             Hosts de terceiros liberados: {}\n\
             URL inicial: {}\n\
             CDP entregue ao agente (controle do navegador): {}\n\
             Modo: {}\n\
             Binário do Chrome: {}\n\n\
             ATENÇÃO sobre portas: a porta só é verificada quando o agente usa navigate. Depois de carregada, a página pode alcançar QUALQUER porta dos hosts listados (por exemplo outros serviços locais em localhost). Liste só hosts em que isso seja aceitável.\n\n\
             {}\n\n\
             Marque \"confirmo\" para autorizar. Sem isso nada é aberto.",
            list(allowlist.allowed_hosts()),
            list(allowlist.third_party_hosts()),
            start_url
                .as_deref()
                .map(strip_query)
                .unwrap_or_else(|| "(nenhuma)".to_string()),
            if expose_cdp { "SIM" } else { "não" },
            if headless {
                "sem janela (headless)"
            } else {
                "com janela"
            },
            chrome.display(),
            SENSITIVE_NOTICE
        );
        Ok(Prepared {
            capture_id,
            session_handle,
            config: BrowserCaptureConfig {
                chrome,
                session_dir,
                start_url,
                headless,
                allowed_hosts: params.allowed_hosts,
                third_party_hosts: third,
                expose_cdp,
            },
            message,
        })
    }

    /// Libera a vaga reservada por `prepare` (confirmação negada ou falha).
    pub fn release(&self, capture_id: &str) {
        self.lock().remove(capture_id);
    }

    /// Abre o navegador (bloqueante) e registra a captura. Se o servidor
    /// começar a encerrar enquanto o Chrome sobe, a captura é encerrada aqui
    /// mesmo (o Chrome nunca fica órfão).
    pub fn start(&self, prepared: Prepared, how: &'static str) -> Result<Value, ToolError> {
        let Prepared {
            capture_id,
            session_handle,
            config,
            ..
        } = prepared;
        self.starts_in_flight.fetch_add(1, Ordering::SeqCst);
        let result = self.start_inner(&capture_id, &session_handle, config, how);
        self.starts_in_flight.fetch_sub(1, Ordering::SeqCst);
        if result.is_err() {
            self.release(&capture_id);
        }
        result
    }

    fn start_inner(
        &self,
        capture_id: &str,
        session_handle: &str,
        config: BrowserCaptureConfig,
        how: &'static str,
    ) -> Result<Value, ToolError> {
        if self.shutting_down.load(Ordering::SeqCst) {
            return Err(ToolError::new(
                "shutting_down",
                "o servidor está encerrando",
            ));
        }
        match self.backend.start(config) {
            Ok((cap, info)) => {
                let mut slots = self.lock();
                if self.shutting_down.load(Ordering::SeqCst) {
                    drop(slots);
                    // Subiu durante o encerramento: para agora, com a sessão gravada.
                    match cap.stop() {
                        Ok(_) => eprintln!(
                            "scrapelens-mcp: a captura que subia durante o encerramento foi parada"
                        ),
                        Err(error) => {
                            eprintln!("scrapelens-mcp: ao encerrar a captura que subia: {error}")
                        }
                    }
                    return Err(ToolError::new(
                        "shutting_down",
                        "o servidor encerrou durante o início; a captura foi parada",
                    ));
                }
                let running = Arc::new(Running {
                    cap: Mutex::new(Some(cap)),
                    session_handle: session_handle.to_string(),
                });
                slots.insert(capture_id.to_string(), Slot::Running(running));
                drop(slots);
                let mut object = match serde_json::to_value(&info) {
                    Ok(Value::Object(map)) => map,
                    _ => Map::new(),
                };
                strip_path_fields(&mut object);
                object.insert("captureId".into(), json!(capture_id));
                object.insert("sessionId".into(), json!(session_handle));
                object.insert("confirmation".into(), json!(how));
                Ok(Value::Object(object))
            }
            Err(error) => Err(ToolError::new(error.code(), error.to_string())),
        }
    }

    fn running(&self, capture_id: &str) -> Result<Arc<Running>, ToolError> {
        match self.lock().get(capture_id) {
            Some(Slot::Running(running)) => Ok(running.clone()),
            Some(Slot::Starting) => Err(ToolError::new(
                "capture_not_ready",
                "a captura ainda está sendo iniciada",
            )),
            None => Err(ToolError::new(
                "capture_not_found",
                format!("captura {capture_id:?} não existe (encerrada ou id inválido)"),
            )),
        }
    }

    pub fn navigate(&self, params: &NavigateParams) -> Result<Value, ToolError> {
        let wait_load = match params.wait.as_deref().unwrap_or("load") {
            "load" => true,
            "none" => false,
            other => {
                return Err(ToolError::invalid(format!(
                    "wait inválido: {other:?} (load|none)"
                )))
            }
        };
        let timeout_ms = params.timeout_ms.unwrap_or(DEFAULT_NAVIGATE_TIMEOUT_MS);
        if timeout_ms == 0 || timeout_ms > MAX_NAVIGATE_TIMEOUT_MS {
            return Err(ToolError::invalid(format!(
                "timeout_ms deve estar entre 1 e {MAX_NAVIGATE_TIMEOUT_MS}"
            )));
        }
        let running = self.running(&params.capture_id)?;
        let guard = running.cap.lock().unwrap_or_else(|e| e.into_inner());
        let cap = guard
            .as_ref()
            .ok_or_else(|| ToolError::new("capture_stopped", "a captura já foi encerrada"))?;
        let result = cap
            .navigate(&params.url, wait_load, Duration::from_millis(timeout_ms))
            .map_err(|e| ToolError::new(e.code(), e.to_string()))?;
        let mut object = match serde_json::to_value(&result) {
            Ok(Value::Object(map)) => map,
            _ => Map::new(),
        };
        object.insert("captureId".into(), json!(params.capture_id));
        Ok(Value::Object(object))
    }

    pub fn status(&self, capture_id: &str) -> Result<Value, ToolError> {
        let running = self.running(capture_id)?;
        let guard = running.cap.lock().unwrap_or_else(|e| e.into_inner());
        let cap = guard
            .as_ref()
            .ok_or_else(|| ToolError::new("capture_stopped", "a captura já foi encerrada"))?;
        let mut object = match serde_json::to_value(cap.status()) {
            Ok(Value::Object(map)) => map,
            _ => Map::new(),
        };
        strip_path_fields(&mut object);
        object.insert("captureId".into(), json!(capture_id));
        object.insert("sessionId".into(), json!(running.session_handle));
        let mut value = Value::Object(object);
        mask_urls(&mut value);
        Ok(value)
    }

    /// Encerra a captura (gracioso), grava a sessão e devolve o relatório
    /// mascarado. A captura sai do mapa em qualquer caso.
    pub fn stop(&self, ctx: &Ctx, capture_id: &str) -> Result<Value, ToolError> {
        let running = self.running(capture_id)?;
        self.lock().remove(capture_id);
        let cap = running
            .cap
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| ToolError::new("capture_stopped", "a captura já foi encerrada"))?;
        let report = cap.stop().map_err(|e| {
            ToolError::new("stop_failed", format!("falha ao encerrar a captura: {e}"))
        })?;
        let mut object = match serde_json::to_value(&report) {
            Ok(Value::Object(map)) => map,
            _ => Map::new(),
        };
        strip_path_fields(&mut object);
        object.insert("captureId".into(), json!(capture_id));
        object.insert("sessionId".into(), json!(running.session_handle));
        object.insert(
            "readable".into(),
            json!(ctx.open(&running.session_handle).is_ok()),
        );
        let mut value = Value::Object(object);
        mask_urls(&mut value);
        Ok(value)
    }

    /// Para todas as capturas (encerramento do servidor) e espera as que ainda
    /// estão subindo, que se encerram sozinhas ao ficar prontas. Devolve quantas
    /// foram paradas. Bloqueante.
    pub fn stop_all(&self, ctx: &Ctx) -> usize {
        self.shutting_down.store(true, Ordering::SeqCst);
        let ids: Vec<String> = self
            .lock()
            .iter()
            .filter(|(_, slot)| matches!(slot, Slot::Running(_)))
            .map(|(id, _)| id.clone())
            .collect();
        let mut stopped = 0;
        for id in ids {
            match self.stop(ctx, &id) {
                Ok(_) => stopped += 1,
                Err(error) => eprintln!("scrapelens-mcp: ao encerrar {id}: {error}"),
            }
        }
        // O Chrome que ainda sobe: `start` o encerra ao terminar. O limite é o
        // prazo de início da própria captura (90 s) com folga.
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        while self.starts_in_flight.load(Ordering::SeqCst) > 0
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        if self.starts_in_flight.load(Ordering::SeqCst) > 0 {
            eprintln!("scrapelens-mcp: um início de captura não terminou a tempo; o Chrome pode ter ficado ativo");
        }
        stopped
    }

    /// Chamado pelo servidor ao iniciar.
    pub fn startup(&self) {
        self.backend.startup();
    }

    pub fn active(&self) -> usize {
        self.lock().len()
    }
}

/// URL sem query nem fragmento (trocados por `?…`): nas saídas de captura não
/// há como saber quais parâmetros são segredo, então nenhum é mostrado.
pub fn strip_query(url: &str) -> String {
    match url.find(['?', '#']) {
        Some(at) => format!("{}?…", &url[..at]),
        None => url.to_string(),
    }
}

/// Texto livre sem query nem fragmento: depois de redigir o que o core
/// reconhece como credencial, todo `?…` e `#…` até um terminador vira `?…`/`#…`.
pub fn strip_text(text: &str) -> String {
    let text = scrapelens_core::export::sanitize::sanitize_text(
        text,
        &scrapelens_core::export::sanitize::SanitizeOptions::default(),
    );
    let is_end = |ch: char| {
        ch.is_whitespace() || matches!(ch, '"' | '\'' | '<' | '>' | '(' | ')' | ',' | '\\')
    };
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while !rest.is_empty() {
        let end = rest.find(is_end).unwrap_or(rest.len());
        if end == 0 {
            let ch = rest.chars().next().unwrap();
            out.push(ch);
            rest = &rest[ch.len_utf8()..];
            continue;
        }
        let (token, after) = rest.split_at(end);
        // Token que parece URL ou caminho: corta no primeiro `?`, `#` ou `;`
        // (query, fragmento, parâmetro de matriz); sobra só o caminho.
        let urlish = token.contains("://") || token.starts_with('/');
        match token.find(['?', '#', ';']).filter(|_| urlish) {
            Some(at) => {
                out.push_str(&token[..at]);
                out.push('…');
            }
            None => out.push_str(token),
        }
        rest = after;
    }
    out
}

/// Nas saídas de captura nenhuma string guarda query ou fragmento (campos de
/// URL, avisos e mensagens de erro).
fn mask_urls(value: &mut Value) {
    match value {
        Value::Object(map) => map.values_mut().for_each(mask_urls),
        Value::Array(list) => list.iter_mut().for_each(mask_urls),
        Value::String(text) if text.contains(['?', '#', '=']) || text.contains("://") => {
            *text = strip_text(text);
        }
        _ => {}
    }
}
