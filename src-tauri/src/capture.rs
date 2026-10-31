//! Adaptador fino entre o App (Tauri) e a crate `scrapelens-capture`.
//!
//! Toda a captura (Chrome com perfil dedicado, CDP + NetLog, allowlist, captura
//! controlada, limpeza de órfãos) vive em `capture/` (crate sem Tauri). Aqui
//! ficam só o que é do App: `SessionPayload` (resposta dos commands) e
//! `CaptureSession` (handle que o App guarda). `run()` e `CaptureConfig` têm o
//! mesmo comportamento de antes.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

pub use scrapelens_capture::{
    cleanup_orphans, default_state_root, CaptureConfig, CaptureStatus, OrphanCleanup,
};

use crate::commands::SessionPayload;

pub struct CaptureSession {
    pub id: String,
    pub dir: PathBuf,
    pub started_at: String,
    pub stop: Sender<()>,
    pub join: thread::JoinHandle<Result<SessionPayload, String>>,
    pub status: Arc<Mutex<CaptureStatus>>,
}

/// Roda a captura e entrega a sessão no formato que os commands devolvem.
pub fn run(
    config: CaptureConfig,
    status: Arc<Mutex<CaptureStatus>>,
    stop: Receiver<()>,
    ready: Sender<Result<(), String>>,
) -> Result<SessionPayload, String> {
    scrapelens_capture::run(config, status, stop, ready).map(|outcome| SessionPayload {
        session: outcome.session,
        session_dir: Some(outcome.session_dir.display().to_string()),
        synthetic: false,
        notice: Some(outcome.notice),
        pending: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// Teste manual do ciclo real: exige Chrome instalado e o testserver h1 em
    /// 127.0.0.1:8781. Rode com:
    ///   cargo test live_capture_cycle -- --ignored --nocapture
    #[test]
    #[ignore]
    fn live_capture_cycle() {
        let chrome = crate::chrome::detect(None)
            .path
            .expect("Chrome instalado para o teste de captura");
        let dir = std::env::temp_dir().join(format!("scrapelens-live-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)));
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
