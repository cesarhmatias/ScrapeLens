//! Mede, uma etapa por processo, o pico de RSS de abrir uma sessão grande.
//!
//! Uso: `memoria-sessao <etapa> <pasta-da-sessao>`; imprime uma linha JSON por
//! checkpoint (`rss` atual e `peak` até ali, em MiB) e uma linha final.
//! Etapas: base, app-open, app-open-ipc, import-eager, import-eager-pretty,
//! import-eager-sanitize, lazy, lazy-search, netlog-only, cdp-only, capture-full,
//! capture-write. Cada etapa roda num processo novo para o pico ser só dela.
//! Só lê a sessão; `capture-write` grava numa pasta temporária.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use scrapelens_core::correlate::CorrelationOptions;
use serde_json::{json, Value};

fn mib(bytes: u64) -> f64 {
    (bytes as f64 / (1024.0 * 1024.0) * 10.0).round() / 10.0
}

/// Pico de RSS do processo até agora (macOS: bytes; Linux: KiB).
fn peak_mib() -> f64 {
    // SAFETY: `getrusage` preenche a estrutura passada.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let raw = usage.ru_maxrss as u64;
    if cfg!(target_os = "macos") {
        mib(raw)
    } else {
        mib(raw * 1024)
    }
}

/// RSS atual (`ps`), em MiB.
fn rss_mib() -> f64 {
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok();
    out.and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u64>().ok())
        .map(|kib| mib(kib * 1024))
        .unwrap_or(0.0)
}

struct Meter {
    stage: String,
    started: Instant,
}

impl Meter {
    fn check(&self, what: &str) {
        println!(
            "{}",
            json!({"stage": self.stage, "step": what, "ms": self.started.elapsed().as_millis() as u64,
                   "rssMiB": rss_mib(), "peakMiB": peak_mib()})
        );
    }
}

/// Descarta os bytes e só os conta (o que importa é a memória, não o destino).
struct CountingSink(u64);

impl std::io::Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn file_size(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn dir_size(path: &Path) -> (u64, usize) {
    let mut total = 0;
    let mut count = 0;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    total += meta.len();
                    count += 1;
                }
            }
        }
    }
    (total, count)
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn main() {
    let mut args = std::env::args().skip(1);
    let stage = args.next().expect("uso: memoria-sessao <etapa> <pasta>");
    let dir = PathBuf::from(args.next().expect("pasta da sessão"));
    let m = Meter { stage: stage.clone(), started: Instant::now() };
    m.check("início");
    match stage.as_str() {
        "base" => {}
        // Composição do session.json: bytes serializados por campo da 1ª requisição
        // e média por campo (amostra de até 200 requisições).
        "shape" => {
            let imported = scrapelens_core::import_session_dir(&dir).unwrap();
            let requests = &imported.bundle.session.requests;
            let mut totals: std::collections::BTreeMap<String, u64> = Default::default();
            let sample = requests.len().min(200);
            for request in requests.iter().take(sample) {
                if let Value::Object(map) = serde_json::to_value(request).unwrap() {
                    for (key, value) in map {
                        *totals.entry(key).or_default() += serde_json::to_string(&value).unwrap().len() as u64;
                    }
                }
            }
            let per: std::collections::BTreeMap<String, u64> =
                totals.iter().map(|(k, v)| (k.clone(), v / sample as u64)).collect();
            println!("{}", json!({"sampled": sample, "bytesPerRequestByField": per,
                "totalPerRequest": per.values().sum::<u64>()}));
            if let Some(first) = requests.first() {
                if let Value::Object(map) = serde_json::to_value(first).unwrap() {
                    let attempt_fields: Vec<(String, usize)> = map
                        .get("attempts")
                        .and_then(|a| a.get(0))
                        .and_then(Value::as_object)
                        .map(|o| o.iter().map(|(k, v)| (k.clone(), v.to_string().len())).collect())
                        .unwrap_or_default();
                    println!("{}", json!({"attempt0Fields": attempt_fields}));
                }
            }
        }
        // Só validar que o netlog.json é JSON: DOM completo (o que o core faz hoje em
        // `import_session_dir`) contra validação em fluxo sem DOM (`IgnoredAny`).
        "validate-value" | "validate-ignored" => {
            let bytes = read(&dir.join("netlog.json"));
            m.check("ler netlog.json");
            let ok = if stage == "validate-value" {
                serde_json::from_slice::<Value>(&bytes).is_ok()
            } else {
                serde_json::from_slice::<serde::de::IgnoredAny>(&bytes).is_ok()
            };
            m.check("validar");
            println!("{}", json!({"valid": ok}));
        }
        // Aproximação da PROPOSTA para o `import_session_dir`: o mesmo trabalho, mas
        // com o netlog.json validado em fluxo (`IgnoredAny`) em vez de virar um DOM.
        "eager-ignored" => {
            let (lazy, _report) = scrapelens_core::open_session_dir_lazy(&dir).unwrap();
            m.check("sessão tipada (open_session_dir_lazy)");
            let cdp = read(&dir.join("cdp-events.jsonl"));
            let netlog = read(&dir.join("netlog.json"));
            m.check("bytes de cdp-events + netlog");
            let ok = serde_json::from_slice::<serde::de::IgnoredAny>(&netlog).is_ok();
            m.check("validação em fluxo do netlog");
            // Os anexos entram na memória como no `import_session_dir` (lidos um a um).
            let mut attachments: Vec<Vec<u8>> = Vec::new();
            if let Ok(entries) = std::fs::read_dir(dir.join("attachments")) {
                for entry in entries.flatten() {
                    attachments.push(std::fs::read(entry.path()).unwrap_or_default());
                }
            }
            m.check("anexos para a memória");
            println!("{}", json!({"valid": ok, "cdpMiB": mib(cdp.len() as u64), "attachments": attachments.len(),
                "requests": lazy.session.requests.len()}));
        }
        "sizes" => {
            let (att, n) = dir_size(&dir.join("attachments"));
            println!(
                "{}",
                json!({"sessionJsonMiB": mib(file_size(&dir.join("session.json"))),
                       "cdpEventsMiB": mib(file_size(&dir.join("cdp-events.jsonl"))),
                       "netlogMiB": mib(file_size(&dir.join("netlog.json"))),
                       "bodiesJsonlMiB": mib(file_size(&dir.join("cdp-bodies.jsonl"))),
                       "attachmentsMiB": mib(att), "attachmentFiles": n})
            );
        }
        // Mesmo caminho do App ao abrir (`read_session_payload`): texto inteiro + DOM.
        "app-open" | "app-open-ipc" => {
            let raw = std::fs::read_to_string(dir.join("session.json")).unwrap();
            m.check("read_to_string");
            let session: Value = serde_json::from_str(&raw).unwrap();
            m.check("serde_json::Value (DOM)");
            if stage == "app-open-ipc" {
                // O payload do comando é MOVIDO (sem clone) e serializado para o
                // front-end (IPC do Tauri), como em `SessionPayload`.
                #[derive(serde::Serialize)]
                struct Payload {
                    session: Value,
                    session_dir: String,
                }
                let payload = Payload { session, session_dir: dir.display().to_string() };
                let wire = serde_json::to_string(&payload).unwrap();
                m.check("serialização do IPC (payload movido)");
                println!("{}", json!({"wireMiB": mib(wire.len() as u64)}));
            }
        }
        // Mesmo caminho do servidor MCP na primeira chamada mascarada e do CLI `inspect`.
        // P7: consome o bundle e sanitiza no lugar (caminho do MCP e do CLI `sanitize`).
        "import-eager-sanitize-owned" => {
            let imported = scrapelens_core::import_session_dir(&dir).unwrap();
            m.check("import_session_dir (sessão + anexos em memória)");
            let sanitized = scrapelens_core::export::sanitize::sanitize_bundle_owned(
                imported.bundle,
                &scrapelens_core::export::sanitize::SanitizeOptions::default(),
            );
            m.check("sanitize_bundle_owned (no lugar)");
            println!("{}", json!({"sanitizedRequests": sanitized.bundle.session.requests.len()}));
        }
        "import-eager" | "import-eager-pretty" | "import-eager-stream" | "import-eager-sanitize" => {
            let imported = scrapelens_core::import_session_dir(&dir).unwrap();
            m.check("import_session_dir (sessão + anexos em memória)");
            println!(
                "{}",
                json!({"requests": imported.bundle.session.requests.len(),
                       "attachmentsInMemory": imported.bundle.attachments.len(),
                       "attachmentBytes": mib(imported.bundle.attachments.values().map(|b| b.len() as u64).sum())})
            );
            if stage == "import-eager-pretty" {
                let text = serde_json::to_string_pretty(&json!({
                    "session": imported.bundle.session, "report": imported.report}))
                .unwrap();
                m.check("to_string_pretty do CLI inspect");
                println!("{}", json!({"prettyMiB": mib(text.len() as u64)}));
            }
            if stage == "import-eager-stream" {
                // Proposta para o `inspect`: struct tipada + escrita em fluxo, sem `json!`
                // (que cria um DOM) e sem a `String` gigante.
                #[derive(serde::Serialize)]
                struct Out<'a> {
                    session: &'a scrapelens_core::SessionV1,
                    report: &'a scrapelens_core::ImportReport,
                }
                let mut sink = CountingSink(0);
                serde_json::to_writer_pretty(
                    &mut sink,
                    &Out { session: &imported.bundle.session, report: &imported.report },
                )
                .unwrap();
                m.check("to_writer_pretty em fluxo");
                println!("{}", json!({"prettyMiB": mib(sink.0)}));
            }
            if stage == "import-eager-sanitize" {
                let sanitized = scrapelens_core::export::sanitize::sanitize_bundle(
                    &imported.bundle,
                    &scrapelens_core::export::sanitize::SanitizeOptions::default(),
                );
                m.check("sanitize_bundle (cópia mascarada)");
                println!("{}", json!({"sanitizedRequests": sanitized.bundle.session.requests.len()}));
            }
        }
        // Mesmo caminho da busca do App: anexos sob demanda.
        "lazy" | "lazy-search" => {
            let (lazy, _report) = scrapelens_core::open_session_dir_lazy(&dir).unwrap();
            m.check("open_session_dir_lazy");
            if stage == "lazy-search" {
                use scrapelens_core::search::{search_lazy, SearchQuery};
                let result = search_lazy(&lazy, &SearchQuery::new("bigfixture-item-19999"));
                m.check("search_lazy (todos os escopos)");
                println!("{}", json!({"matches": result.matches.len()}));
            }
        }
        // Importação de uma captura (parse de CDP, NetLog, corpos e correlação).
        "netlog-only" => {
            let netlog = read(&dir.join("netlog.json"));
            m.check("ler netlog.json");
            let imported = scrapelens_core::import_netlog(&netlog).unwrap();
            m.check("import_netlog (parse)");
            println!("{}", json!({"requests": imported.bundle.session.requests.len()}));
        }
        "cdp-only" => {
            let cdp = read(&dir.join("cdp-events.jsonl"));
            m.check("ler cdp-events.jsonl");
            let imported = scrapelens_core::import_capture(
                &cdp,
                br#"{"constants":{},"events":[]}"#,
                CorrelationOptions::default(),
            )
            .unwrap();
            m.check("import_capture sem NetLog (parse CDP)");
            println!("{}", json!({"requests": imported.bundle.session.requests.len()}));
        }
        "capture-full" | "capture-write" => {
            let cdp = read(&dir.join("cdp-events.jsonl"));
            let netlog = read(&dir.join("netlog.json"));
            let bodies = std::fs::read(dir.join("cdp-bodies.jsonl")).ok();
            m.check("ler cdp + netlog + corpos");
            let imported = scrapelens_core::import_capture_labeled(
                &cdp,
                &netlog,
                bodies.as_deref(),
                &["bigfixture".to_string()],
                CorrelationOptions::default(),
            )
            .unwrap();
            m.check("import_capture_labeled (parse + correlação)");
            println!(
                "{}",
                json!({"requests": imported.bundle.session.requests.len(),
                       "attachments": imported.bundle.attachments.len()})
            );
            if stage == "capture-write" {
                let out = std::env::temp_dir().join(format!("memoria-sessao-out-{}", std::process::id()));
                scrapelens_core::store::write_session_dir(&imported.bundle, &out).unwrap();
                m.check("write_session_dir");
                let _ = std::fs::remove_dir_all(out);
            }
        }
        other => panic!("etapa desconhecida: {other}"),
    }
    println!("{}", json!({"stage": stage, "totalMs": m.started.elapsed().as_millis() as u64, "peakMiB": peak_mib()}));
}
