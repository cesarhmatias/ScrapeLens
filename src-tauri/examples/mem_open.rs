//! Pico de RSS de abrir uma sessão grande pelo contrato do app (P5, docs/19).
//!
//! Uso (um modo por processo, para o pico ser só dele):
//!   cargo run --release --example mem_open -- paged <pasta-da-sessao>
//!   cargo run --release --example mem_open -- legacy <pasta-da-sessao>
//!
//! `paged`: o caminho novo — sessão tipada (`open_session_dir_lazy`, o mesmo
//! do `cached_session`), cabeçalho serializado, todas as páginas de
//! `list_requests` serializadas (o que o front recebe) e um `get_request`.
//! `legacy`: o caminho antigo — `read_to_string` + `serde_json::Value` +
//! serialização para o front-end (equivale ao `app-open-ipc` do docs/18).

use std::path::Path;
use std::time::Instant;

fn peak_mib() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    (usage.ru_maxrss as f64) / (1024.0 * 1024.0)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (mode, dir) = match (args.get(1), args.get(2)) {
        (Some(mode), Some(dir)) => (mode.as_str(), Path::new(dir)),
        _ => {
            eprintln!("uso: mem_open <paged|legacy> <pasta-da-sessao>");
            std::process::exit(2);
        }
    };
    let started = Instant::now();
    let base = peak_mib();
    match mode {
        "paged" => {
            let (lazy, _) = scrapelens_core::open_session_dir_lazy(dir).expect("abrir sessão");
            let after_open = peak_mib();
            let open_ms = started.elapsed().as_millis() as u64;
            let header = scrapelens_lib::listing::header_of(&lazy.session).expect("cabeçalho");
            let header_bytes = serde_json::to_vec(&header).unwrap().len();
            let filter = scrapelens_lib::listing::ListFilter::default();
            let mut wire = 0usize;
            let mut items = 0usize;
            let mut offset = 0usize;
            let page_size = scrapelens_lib::listing::MAX_PAGE;
            loop {
                let page = scrapelens_lib::listing::list_page(&lazy.session, offset, page_size, &filter);
                let bytes = serde_json::to_vec(&page).unwrap().len();
                wire += bytes;
                items += page.items.len();
                if page.items.is_empty() || offset + page_size >= page.matched {
                    break;
                }
                offset += page_size;
            }
            if std::env::var("MEM_OPEN_SAMPLE").is_ok() {
                let page = scrapelens_lib::listing::list_page(&lazy.session, 0, 1, &filter);
                eprintln!("{}", serde_json::to_string(&page.items).unwrap());
            }
            let id = lazy.session.requests.last().map(|r| r.id.clone()).unwrap_or_default();
            let detail = scrapelens_lib::listing::detail(&lazy.session, &id).expect("detalhe");
            let detail_bytes = serde_json::to_vec(&detail).unwrap().len();
            println!(
                "{}",
                serde_json::json!({
                    "mode": "paged",
                    "requests": lazy.session.requests.len(),
                    "basePeakMiB": base,
                    "openPeakMiB": after_open,
                    "openMs": open_ms,
                    "peakMiB": peak_mib(),
                    "headerBytes": header_bytes,
                    "listWireBytes": wire,
                    "listItems": items,
                    "bytesPerSummary": if items > 0 { wire / items } else { 0 },
                    "detailBytes": detail_bytes,
                    "ms": started.elapsed().as_millis() as u64,
                })
            );
        }
        "legacy" => {
            let raw = std::fs::read_to_string(dir.join("session.json")).expect("ler session.json");
            let value: serde_json::Value = serde_json::from_str(&raw).expect("JSON");
            let wire = serde_json::to_string(&value).unwrap().len();
            println!(
                "{}",
                serde_json::json!({
                    "mode": "legacy",
                    "basePeakMiB": base,
                    "peakMiB": peak_mib(),
                    "wireBytes": wire,
                    "ms": started.elapsed().as_millis() as u64,
                })
            );
        }
        other => {
            eprintln!("modo desconhecido: {other}");
            std::process::exit(2);
        }
    }
}
