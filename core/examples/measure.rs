//! Manual memory/time measurement: `cargo run --release --example measure -- <session> eager|lazy [text]`.
//! Peak: `/usr/bin/time -l`; retained RSS: read via `ps` after opening.
use std::path::Path;
use std::time::Instant;

use scrapelens_core::search::{search, search_lazy, SearchQuery};

fn rss_mb() -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u64>()
        .unwrap_or(0)
        / 1024
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (dir, mode) = (Path::new(&args[1]), args[2].as_str());
    let text = args.get(3).map(String::as_str).unwrap_or("zzzz");
    let query = SearchQuery::new(text);
    let start = Instant::now();
    if mode == "lazy" {
        let (lazy, _) = scrapelens_core::open_session_dir_lazy(dir).unwrap();
        let open = start.elapsed();
        let retained = rss_mb();
        let t = Instant::now();
        let found = search_lazy(&lazy, &query);
        eprintln!(
            "lazy: open {open:?}, retained RSS {retained} MB, search {:?}, {} matches, end rss {} MB",
            t.elapsed(),
            found.matches.len(),
            rss_mb()
        );
    } else {
        let imported = scrapelens_core::import_session_dir(dir).unwrap();
        let open = start.elapsed();
        let retained = rss_mb();
        let t = Instant::now();
        let found = search(&imported.bundle, &query);
        eprintln!("eager: open {open:?}, retained RSS {retained} MB, search {:?}, {} matches, end rss {} MB", t.elapsed(), found.matches.len(), rss_mb());
    }
}
