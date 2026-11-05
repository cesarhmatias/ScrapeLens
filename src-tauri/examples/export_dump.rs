//! Evidence utility for export/sanitization (not part of the product).
//!
//! Calls the same bridge the Tauri commands use and prints one JSON line per
//! result, so the round's evidence can be recorded without opening the UI:
//!
//! ```sh
//! cargo run --quiet --example export_dump -- <session-folder> <request-id> [sanitized-destination]
//! ```
//!
//! Nothing is executed and no network is opened; the sanitized destination must be
//! a new folder (the source is never modified).

use std::path::{Path, PathBuf};

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args
        .next()
        .expect("usage: export_dump <session-folder> <request-id> [destination]");
    let request = args.next().expect("missing request id");
    let src = Path::new(&dir);

    for format in ["curl", "python"] {
        let preview = scrapelens_lib::export::preview(src, &request, format).expect("preview");
        println!(
            "PREVIEW {} {}",
            format,
            serde_json::to_string(&preview).expect("serialize preview")
        );
    }

    let sanitize = scrapelens_lib::export::sanitize_preview(src).expect("sanitization preview");
    println!(
        "SANITIZE_PREVIEW {}",
        serde_json::to_string(&sanitize).expect("serialize sanitization")
    );

    if let Some(destination) = args.next().map(PathBuf::from) {
        let saved = scrapelens_lib::export::sanitize_to(src, &destination).expect("sanitize");
        println!(
            "SANITIZE_SAVED {}",
            serde_json::to_string(&saved).expect("serialize result")
        );
    }
}
