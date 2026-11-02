//! Gera uma sessão GRANDE e sintética por captura real em loopback, para medir a
//! memória de quem abre sessões grandes (docs/18-memoria-sessoes-grandes.md).
//!
//! Uso: `cargo run --release --example capture_big -- <pasta-da-sessao> <N-requisições>`
//!
//! Um servidor HTTP/1.1 em 127.0.0.1 (std, keep-alive) serve uma página que dispara
//! `N` `fetch` de `/r/<i>` (JSON de ~1,5 KiB, cookies de vez em quando, cabeçalhos
//! variados). O Chrome estável é controlado por `BrowserCapture` (CDP + NetLog), a
//! allowlist cobre só `localhost:<porta>`. Nada sai da máquina; os dados são
//! sintéticos (`bigfixture-*`), sem credenciais reais.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use scrapelens_capture::browser::{BrowserCapture, BrowserCaptureConfig};
use scrapelens_capture::chrome::resolve_stable_chrome;

fn body_for(i: usize) -> String {
    // ~1,5 KiB de JSON com campos que variam por requisição.
    let mut items = String::new();
    for k in 0..12 {
        items.push_str(&format!(
            "{{\"id\":{},\"name\":\"bigfixture-item-{}-{}\",\"tags\":[\"a{}\",\"b{}\"],\"ok\":{}}},",
            i * 12 + k,
            i,
            k,
            k % 3,
            k % 5,
            k % 2 == 0
        ));
    }
    format!("{{\"request\":{i},\"items\":[{}null]}}", items)
}

fn serve(stream: TcpStream, hits: Arc<AtomicUsize>, n: usize) {
    let _ = stream.set_nodelay(true);
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut out = stream;
    loop {
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
            return;
        }
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 || header == "\r\n" {
                break;
            }
        }
        let path = request_line.split_whitespace().nth(1).unwrap_or("/").to_string();
        let (status, ctype, extra, body) = if path == "/" {
            let html = format!(
                "<!doctype html><html><body><script>\
                 (async()=>{{const N={n};for(let i=0;i<N;i+=100){{await Promise.all(Array.from({{length:Math.min(100,N-i)}},(_, j)=>fetch('/r/'+(i+j)+'?v='+((i+j)%7)).then(r=>r.text())));}}document.title='done';}})();\
                 </script>ok</body></html>"
            );
            ("200 OK", "text/html; charset=utf-8", String::new(), html)
        } else if let Some(rest) = path.strip_prefix("/r/") {
            let i: usize = rest.split('?').next().and_then(|v| v.parse().ok()).unwrap_or(0);
            hits.fetch_add(1, Ordering::SeqCst);
            let cookie = if i % 50 == 0 {
                format!("Set-Cookie: bigsid{}=bigfixture-{}; Path=/; HttpOnly\r\n", i % 5, i)
            } else {
                String::new()
            };
            let extra = format!("{cookie}X-Request-Index: {i}\r\nCache-Control: no-store\r\n");
            ("200 OK", "application/json", extra, body_for(i))
        } else {
            ("404 Not Found", "text/plain", String::new(), "nao".to_string())
        };
        let head = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n{extra}Connection: keep-alive\r\n\r\n",
            body.len()
        );
        if out.write_all(head.as_bytes()).is_err() || out.write_all(body.as_bytes()).is_err() {
            return;
        }
        let _ = out.flush();
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(args.next().expect("uso: capture_big <pasta> <N>"));
    let n: usize = args.next().and_then(|v| v.parse().ok()).expect("N inválido");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    {
        let hits = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let hits = hits.clone();
                std::thread::spawn(move || serve(stream, hits, n));
            }
        });
    }
    let chrome = resolve_stable_chrome(None).expect("Chrome estável").binary;
    let (capture, _info) = BrowserCapture::start(BrowserCaptureConfig {
        chrome,
        session_dir: dir.clone(),
        start_url: None,
        headless: true,
        allowed_hosts: vec![format!("localhost:{port}")],
        third_party_hosts: Vec::new(),
        expose_cdp: false,
    })
    .expect("start");
    let started = Instant::now();
    let nav = capture.navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(60));
    eprintln!("navigate: {nav:?}");
    // Espera o servidor ter visto as N requisições (ou o prazo).
    let deadline = Instant::now() + Duration::from_secs(900);
    while hits.load(Ordering::SeqCst) < n && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
    }
    std::thread::sleep(Duration::from_secs(5));
    eprintln!("servidor viu {} requisições em {:?}", hits.load(Ordering::SeqCst), started.elapsed());
    let report = capture.stop().expect("stop");
    eprintln!(
        "stop: requests={} netlog={} graceful={} waitedMs={} warnings={}",
        report.requests,
        report.netlog,
        report.graceful,
        report.waited_ms,
        report.warnings.len()
    );
    println!("{}", report.session_dir);
    let _ = std::io::stdout().flush();
}
