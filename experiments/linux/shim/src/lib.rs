//! Substituto de `src-tauri` para o container Linux (docs/21-linux.md §6). O
//! `check_multi_target.py` dirige `cargo test live_bodies_cycle` dentro de `src-tauri`;
//! no Linux o Tauri (webkit2gtk) não é construído nesta rodada, então o container troca
//! `src-tauri` por esta crate, cujo teste faz EXATAMENTE o que o de `src-tauri/src/capture.rs`
//! faz (`scrapelens_capture::run`, headless, só loopback), sem a janela.
#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use scrapelens_capture::{run, CaptureConfig, CaptureStatus, NetworkMode};

    #[test]
    #[ignore]
    fn live_bodies_cycle() {
        let start_url = std::env::var("SL_LIVE_START_URL").expect("SL_LIVE_START_URL");
        let dir = PathBuf::from(std::env::var("SL_LIVE_SESSION_DIR").expect("SL_LIVE_SESSION_DIR"));
        let stop_file = PathBuf::from(std::env::var("SL_LIVE_STOP_FILE").expect("SL_LIVE_STOP_FILE"));
        let chrome = scrapelens_capture::chrome::detect(None).path.expect("Chrome ou Chromium instalado");
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
            network: NetworkMode::LoopbackOnly,
        };
        let status_thread = status.clone();
        let join = std::thread::spawn(move || run(config, status_thread, stop_rx, ready_tx));
        ready_rx.recv_timeout(Duration::from_secs(30)).expect("captura pronta").expect("captura iniciou");
        let deadline = Instant::now() + Duration::from_secs(180);
        while !stop_file.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
        }
        let _ = stop_tx.send(());
        let outcome = join.join().expect("thread da captura").expect("captura importada");
        println!("live bodies: notice={:?}", outcome.notice);
    }
}
