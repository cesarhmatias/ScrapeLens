//! Utilitário de evidência da exportação/sanitização (não faz parte do produto).
//!
//! Chama a mesma ponte que os commands Tauri usam e imprime uma linha JSON por
//! resultado, para que a evidência da rodada possa ser gravada sem abrir a UI:
//!
//! ```sh
//! cargo run --quiet --example export_dump -- <pasta-da-sessão> <request-id> [destino-sanitizado]
//! ```
//!
//! Nada é executado e nenhuma rede é aberta; o destino sanitizado precisa ser
//! uma pasta nova (a origem nunca é alterada).

use std::path::{Path, PathBuf};

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args
        .next()
        .expect("uso: export_dump <pasta-da-sessão> <request-id> [destino]");
    let request = args.next().expect("request id ausente");
    let src = Path::new(&dir);

    for format in ["curl", "python"] {
        let preview = scrapelens_lib::export::preview(src, &request, format).expect("preview");
        println!(
            "PREVIEW {} {}",
            format,
            serde_json::to_string(&preview).expect("serializar prévia")
        );
    }

    let sanitize = scrapelens_lib::export::sanitize_preview(src).expect("prévia da sanitização");
    println!(
        "SANITIZE_PREVIEW {}",
        serde_json::to_string(&sanitize).expect("serializar sanitização")
    );

    if let Some(destination) = args.next().map(PathBuf::from) {
        let saved = scrapelens_lib::export::sanitize_to(src, &destination).expect("sanitizar");
        println!(
            "SANITIZE_SAVED {}",
            serde_json::to_string(&saved).expect("serializar resultado")
        );
    }
}
