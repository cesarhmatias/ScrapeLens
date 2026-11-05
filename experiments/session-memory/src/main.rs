//! Measures, one stage per process, the peak RSS of opening a large session.
//!
//! Usage: `session-memory <stage> <session-dir>`; prints one JSON line per
//! checkpoint (current `rss` and `peak` up to that point, in MiB) and a final line.
//! Stages: base, app-open, app-open-ipc, import-eager, import-eager-pretty,
//! import-eager-sanitize, lazy, lazy-search, netlog-only, cdp-only, capture-full,
//! capture-write. Each stage runs in a new process so the peak belongs only to it.
//! Only reads the session; `capture-write` writes to a temporary directory.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use scrapelens_core::correlate::CorrelationOptions;
use serde_json::{json, Value};

fn mib(bytes: u64) -> f64 {
    (bytes as f64 / (1024.0 * 1024.0) * 10.0).round() / 10.0
}

/// Peak RSS of the process so far (macOS: bytes; Linux: KiB).
fn peak_mib() -> f64 {
    // SAFETY: `getrusage` fills the structure passed to it.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let raw = usage.ru_maxrss as u64;
    if cfg!(target_os = "macos") {
        mib(raw)
    } else {
        mib(raw * 1024)
    }
}

/// Current RSS (`ps`), in MiB.
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

/// Discards the bytes and only counts them (memory is what matters, not the destination).
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
    let stage = args.next().expect("usage: session-memory <stage> <session-dir>");
    let dir = PathBuf::from(args.next().expect("session directory"));
    let m = Meter { stage: stage.clone(), started: Instant::now() };
    m.check("start");
    match stage.as_str() {
        "base" => {}
        // Composition of session.json: serialized bytes per field of the 1st request
        // and the average per field (sample of up to 200 requests).
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
        // Only validate that netlog.json is JSON: full DOM (what the core does today in
        // `import_session_dir`) versus streaming validation without a DOM (`IgnoredAny`).
        "validate-value" | "validate-ignored" => {
            let bytes = read(&dir.join("netlog.json"));
            m.check("read netlog.json");
            let ok = if stage == "validate-value" {
                serde_json::from_slice::<Value>(&bytes).is_ok()
            } else {
                serde_json::from_slice::<serde::de::IgnoredAny>(&bytes).is_ok()
            };
            m.check("validate");
            println!("{}", json!({"valid": ok}));
        }
        // Approximation of the PROPOSAL for `import_session_dir`: the same work, but
        // with netlog.json validated as a stream (`IgnoredAny`) instead of becoming a DOM.
        "eager-ignored" => {
            let (lazy, _report) = scrapelens_core::open_session_dir_lazy(&dir).unwrap();
            m.check("typed session (open_session_dir_lazy)");
            let cdp = read(&dir.join("cdp-events.jsonl"));
            let netlog = read(&dir.join("netlog.json"));
            m.check("cdp-events + netlog bytes");
            let ok = serde_json::from_slice::<serde::de::IgnoredAny>(&netlog).is_ok();
            m.check("streaming validation of netlog");
            // Attachments enter memory as in `import_session_dir` (read one by one).
            let mut attachments: Vec<Vec<u8>> = Vec::new();
            if let Ok(entries) = std::fs::read_dir(dir.join("attachments")) {
                for entry in entries.flatten() {
                    attachments.push(std::fs::read(entry.path()).unwrap_or_default());
                }
            }
            m.check("attachments into memory");
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
        // Same path as the App on open (`read_session_payload`): whole text + DOM.
        "app-open" | "app-open-ipc" => {
            let raw = std::fs::read_to_string(dir.join("session.json")).unwrap();
            m.check("read_to_string");
            let session: Value = serde_json::from_str(&raw).unwrap();
            m.check("serde_json::Value (DOM)");
            if stage == "app-open-ipc" {
                // The command payload is MOVED (no clone) and serialized for the
                // front-end (Tauri IPC), as in `SessionPayload`.
                #[derive(serde::Serialize)]
                struct Payload {
                    session: Value,
                    session_dir: String,
                }
                let payload = Payload { session, session_dir: dir.display().to_string() };
                let wire = serde_json::to_string(&payload).unwrap();
                m.check("IPC serialization (payload moved)");
                println!("{}", json!({"wireMiB": mib(wire.len() as u64)}));
            }
        }
        // Same path as the MCP server on the first masked call and the `inspect` CLI.
        // P7: consumes the bundle and sanitizes in place (MCP and `sanitize` CLI path).
        "import-eager-sanitize-owned" => {
            let imported = scrapelens_core::import_session_dir(&dir).unwrap();
            m.check("import_session_dir (session + attachments in memory)");
            let sanitized = scrapelens_core::export::sanitize::sanitize_bundle_owned(
                imported.bundle,
                &scrapelens_core::export::sanitize::SanitizeOptions::default(),
            );
            m.check("sanitize_bundle_owned (in place)");
            println!("{}", json!({"sanitizedRequests": sanitized.bundle.session.requests.len()}));
        }
        "import-eager" | "import-eager-pretty" | "import-eager-stream" | "import-eager-sanitize" => {
            let imported = scrapelens_core::import_session_dir(&dir).unwrap();
            m.check("import_session_dir (session + attachments in memory)");
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
                m.check("to_string_pretty for the inspect CLI");
                println!("{}", json!({"prettyMiB": mib(text.len() as u64)}));
            }
            if stage == "import-eager-stream" {
                // Proposal for `inspect`: typed struct + streaming write, without `json!`
                // (which builds a DOM) and without the huge `String`.
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
                m.check("streaming to_writer_pretty");
                println!("{}", json!({"prettyMiB": mib(sink.0)}));
            }
            if stage == "import-eager-sanitize" {
                let sanitized = scrapelens_core::export::sanitize::sanitize_bundle(
                    &imported.bundle,
                    &scrapelens_core::export::sanitize::SanitizeOptions::default(),
                );
                m.check("sanitize_bundle (masked copy)");
                println!("{}", json!({"sanitizedRequests": sanitized.bundle.session.requests.len()}));
            }
        }
        // Same path as the App's search: attachments on demand.
        "lazy" | "lazy-search" => {
            let (lazy, _report) = scrapelens_core::open_session_dir_lazy(&dir).unwrap();
            m.check("open_session_dir_lazy");
            if stage == "lazy-search" {
                use scrapelens_core::search::{search_lazy, SearchQuery};
                let result = search_lazy(&lazy, &SearchQuery::new("bigfixture-item-19999"));
                m.check("search_lazy (all scopes)");
                println!("{}", json!({"matches": result.matches.len()}));
            }
        }
        // Import of a capture (CDP, NetLog, bodies and correlation parsing).
        "netlog-only" => {
            let netlog = read(&dir.join("netlog.json"));
            m.check("read netlog.json");
            let imported = scrapelens_core::import_netlog(&netlog).unwrap();
            m.check("import_netlog (parse)");
            println!("{}", json!({"requests": imported.bundle.session.requests.len()}));
        }
        "cdp-only" => {
            let cdp = read(&dir.join("cdp-events.jsonl"));
            m.check("read cdp-events.jsonl");
            let imported = scrapelens_core::import_capture(
                &cdp,
                br#"{"constants":{},"events":[]}"#,
                CorrelationOptions::default(),
            )
            .unwrap();
            m.check("import_capture without NetLog (CDP parse)");
            println!("{}", json!({"requests": imported.bundle.session.requests.len()}));
        }
        "capture-full" | "capture-write" => {
            let cdp = read(&dir.join("cdp-events.jsonl"));
            let netlog = read(&dir.join("netlog.json"));
            let bodies = std::fs::read(dir.join("cdp-bodies.jsonl")).ok();
            m.check("read cdp + netlog + bodies");
            let imported = scrapelens_core::import_capture_labeled(
                &cdp,
                &netlog,
                bodies.as_deref(),
                &["bigfixture".to_string()],
                CorrelationOptions::default(),
            )
            .unwrap();
            m.check("import_capture_labeled (parse + correlation)");
            println!(
                "{}",
                json!({"requests": imported.bundle.session.requests.len(),
                       "attachments": imported.bundle.attachments.len()})
            );
            if stage == "capture-write" {
                let out = std::env::temp_dir().join(format!("session-memory-out-{}", std::process::id()));
                scrapelens_core::store::write_session_dir(&imported.bundle, &out).unwrap();
                m.check("write_session_dir");
                let _ = std::fs::remove_dir_all(out);
            }
        }
        other => panic!("unknown stage: {other}"),
    }
    println!("{}", json!({"stage": stage, "totalMs": m.started.elapsed().as_millis() as u64, "peakMiB": peak_mib()}));
}
