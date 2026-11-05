//! RSS peak of opening a large session through the app contract (P5, docs/19).
//!
//! Usage (one mode per process, so the peak is its own):
//!   cargo run --release --example mem_open -- paged <session-folder>
//!   cargo run --release --example mem_open -- legacy <session-folder>
//!
//! `paged`: the new path — typed session (`open_session_dir_lazy`, the same as
//! `cached_session`), serialized header, every `list_requests` page serialized
//! (what the front-end receives) and one `get_request`.
//! `legacy`: the old path — `read_to_string` + `serde_json::Value` + serialization
//! for the front-end (equivalent to `app-open-ipc` in docs/18).

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
            eprintln!("usage: mem_open <paged|legacy> <session-folder>");
            std::process::exit(2);
        }
    };
    let started = Instant::now();
    let base = peak_mib();
    match mode {
        "paged" => {
            let (lazy, _) = scrapelens_core::open_session_dir_lazy(dir).expect("open session");
            let after_open = peak_mib();
            let open_ms = started.elapsed().as_millis() as u64;
            let header = scrapelens_lib::listing::header_of(&lazy.session).expect("header");
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
            let detail = scrapelens_lib::listing::detail(&lazy.session, &id).expect("detail");
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
                    "bytesPerSummary": wire.checked_div(items).unwrap_or(0),
                    "detailBytes": detail_bytes,
                    "ms": started.elapsed().as_millis() as u64,
                })
            );
        }
        "legacy" => {
            let raw = std::fs::read_to_string(dir.join("session.json")).expect("read session.json");
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
            eprintln!("unknown mode: {other}");
            std::process::exit(2);
        }
    }
}
