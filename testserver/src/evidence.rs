//! JSONL evidence sink: one line per observed request, flushed immediately so
//! the file can be inspected while the servers are running.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide sequence so records from several sinks (h3 listens on two UDP
/// sockets) stay uniquely numbered and roughly time-ordered.
static SEQ: AtomicU64 = AtomicU64::new(0);
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde::Serialize;

use crate::SCHEMA;
use crate::http::{Req, Resp};

#[derive(Debug, Clone, Serialize)]
pub struct ResponseRecord {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub header_count: usize,
    pub body_len: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub schema: &'static str,
    pub seq: u64,
    pub ts_rfc3339: String,
    pub ts_unix_ms: u128,
    pub proto: &'static str,
    pub proto_wire: &'static str,
    pub decode_point: &'static str,
    pub server: String,
    pub conn: String,
    pub stream: Option<u64>,
    pub method: String,
    pub target: String,
    /// `?m=` value of the request target (multi-target probe pages, round 10).
    pub marker: Option<String>,
    pub authority: Option<String>,
    /// Decoded header list in order; duplicates preserved. Pseudo-headers are
    /// included at their decoded position (HTTP/2 and HTTP/3 only).
    pub headers: Vec<(String, String)>,
    pub pseudoheaders: Vec<(String, String)>,
    pub header_count: usize,
    /// Exact request head bytes, base64 (HTTP/1.1 only).
    pub raw_head_b64: Option<String>,
    /// Raw HPACK field block, base64 (HTTP/2 only; concatenated HEADERS +
    /// CONTINUATION payloads).
    pub header_block_b64: Option<String>,
    pub body_b64: Option<String>,
    pub body_len: usize,
    pub body_truncated: bool,
    pub body_framing: Option<String>,
    pub response: ResponseRecord,
    pub notes: Vec<String>,
}

pub struct Evidence {
    proto: &'static str,
    path: PathBuf,
    writer: Mutex<BufWriter<File>>,
}

/// Optional compact log for the multi-target probes (`/multi/...`).
static MULTI_LOG: OnceLock<Mutex<Option<BufWriter<File>>>> = OnceLock::new();

/// Turn on `{dir}/multi.jsonl`: one compact line per `/multi/` request, with the
/// `?m=` marker first so the capture experiment can grep by marker.
pub fn set_multi_log(dir: &Path) {
    let _ = std::fs::create_dir_all(dir);
    let path = dir.join("multi.jsonl");
    let writer = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok()
        .map(BufWriter::new);
    let _ = MULTI_LOG.set(Mutex::new(writer));
}

/// First `m=` value of a query string (`?m=popup-1&x=1` → `popup-1`).
pub fn marker_of(target: &str) -> Option<String> {
    let query = target.split_once('?')?.1;
    for part in query.split('&') {
        if let Some(v) = part.strip_prefix("m=") {
            let v = v.split('&').next().unwrap_or(v);
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn write_multi(server: &str, req: &Req, resp: &Resp, marker: Option<&str>) {
    let Some(log) = MULTI_LOG.get() else { return };
    if !req.path().starts_with("/multi") {
        return;
    }
    let body_text = std::str::from_utf8(&req.body).ok().map(str::to_string);
    let header_json: Vec<serde_json::Value> = req
        .headers
        .iter()
        .map(|(n, v)| serde_json::json!([n, v]))
        .collect();
    let response_text = std::str::from_utf8(&resp.body)
        .ok()
        .filter(|_| resp.body.len() <= 1024 && resp.body.first() == Some(&b'{'))
        .map(str::to_string);
    let response_sha = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&resp.body).iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    let rec = serde_json::json!({
        "schema": "scrapelens.testserver.multi/1",
        "ts_rfc3339": now().0,
        "marker": marker,
        "server": server,
        "conn": req.conn,
        "method": req.method,
        "target": req.target,
        "headers": header_json,
        "body_b64": if req.body.is_empty() { None } else { Some(b64(&req.body)) },
        "body_text": body_text,
        "body_len": req.body.len(),
        "response": {
            "status": resp.status,
            "body_len": resp.body.len(),
            "body_sha256": response_sha,
            "body": response_text,
        },
    });
    let mut line = rec.to_string();
    line.push('\n');
    let mut guard = log.lock().expect("multi log mutex poisoned");
    if let Some(w) = guard.as_mut() {
        let _ = w.write_all(line.as_bytes());
        let _ = w.flush();
    }
}

fn now() -> (String, u128) {
    let now = SystemTime::now();
    let ms = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let dt = chrono::DateTime::from_timestamp_millis(ms as i64).unwrap_or_else(chrono::Utc::now);
    (dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true), ms)
}

impl Evidence {
    /// Create (append) `{dir}/{proto}.jsonl`.
    pub fn open(dir: &Path, proto: &'static str) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let name = match proto {
            "http/1.1" => "h1.jsonl",
            "h2" => "h2.jsonl",
            "h3" => "h3.jsonl",
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unknown proto for evidence file: {other}"),
                ));
            }
        };
        let path = dir.join(name);
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            proto,
            path,
            writer: Mutex::new(BufWriter::new(file)),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn proto(&self) -> &'static str {
        self.proto
    }

    /// Append one request/response pair as a single JSONL line.
    pub fn record(&self, server: &str, req: &Req, resp: &Resp) -> std::io::Result<()> {
        let (ts_rfc3339, ts_unix_ms) = now();
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let marker = marker_of(&req.target);
        write_multi(server, req, resp, marker.as_deref());
        let rec = Record {
            schema: SCHEMA,
            seq,
            ts_rfc3339,
            ts_unix_ms,
            proto: req.proto.id(),
            proto_wire: req.proto.wire(),
            decode_point: req.proto.decode_point(),
            server: server.to_string(),
            conn: req.conn.clone(),
            stream: req.stream,
            method: req.method.clone(),
            target: req.target.clone(),
            marker,
            authority: req.authority.clone(),
            headers: req.headers.clone(),
            pseudoheaders: req.pseudoheaders(),
            header_count: req.headers.len(),
            raw_head_b64: req.raw_head.as_ref().map(|b| b64(b)),
            header_block_b64: req.header_block.as_ref().map(|b| b64(b)),
            body_b64: if req.body.is_empty() {
                None
            } else {
                Some(b64(&req.body))
            },
            body_len: req.body.len(),
            body_truncated: req.body_truncated,
            body_framing: req.body_framing.clone(),
            response: ResponseRecord {
                status: resp.status,
                headers: resp.headers.clone(),
                header_count: resp.headers.len(),
                body_len: resp.body.len(),
            },
            notes: req.notes.clone(),
        };
        let mut line = serde_json::to_string(&rec).map_err(std::io::Error::other)?;
        line.push('\n');
        let mut w = self.writer.lock().expect("evidence mutex poisoned");
        // One write per record: two h3 sockets may share the same evidence file.
        w.write_all(line.as_bytes())?;
        w.flush()
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
