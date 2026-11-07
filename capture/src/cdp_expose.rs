//! External CDP for `expose_cdp`: a mode-0600 unix socket in front of the pipe.
//!
//! Chrome opens no TCP port. Each message is one JSON object terminated by NUL,
//! the same framing as `--remote-debugging-pipe`. Refused calls never reach Chrome.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::{json, Value};

const MAX_FRAME: usize = 1024 * 1024;
const READ_SLICE: Duration = Duration::from_millis(200);

/// A command the socket accepted. The capture answers on `reply` with one JSON object.
pub(crate) struct UpstreamCmd {
    pub message: Value,
    pub reply: Sender<String>,
}

/// Response the capture owes an external client, keyed by the id we sent to Chrome.
pub(crate) struct ExternalPending {
    pub client_id: Value,
    pub reply: Sender<String>,
}

/// `true` when `value` is the response to a command we forwarded. The client's id
/// is restored and the text is sent on the waiting channel.
pub(crate) fn claim_external(pending: &mut HashMap<u64, ExternalPending>, value: &Value) -> bool {
    let Some(id) = value.get("id").and_then(Value::as_u64) else {
        return false;
    };
    let Some(wait) = pending.remove(&id) else {
        return false;
    };
    let mut out = value.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.insert("id".to_string(), wait.client_id);
    }
    let _ = wait.reply.send(out.to_string());
    true
}

fn denied_reason(method: &str, params: &Value) -> Option<&'static str> {
    if matches!(
        method,
        "Network.getAllCookies" | "Browser.setDownloadBehavior" | "Page.setDownloadBehavior"
    ) {
        return Some("that CDP method is not allowed");
    }
    if let Some(url) = params.get("url").and_then(Value::as_str) {
        let scheme = url.trim().to_ascii_lowercase();
        if scheme.starts_with("file:") || scheme.starts_with("chrome:") {
            return Some("that URL scheme is not allowed");
        }
    }
    None
}

pub(crate) struct Gate {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl Gate {
    /// Binds `directory/cdp.sock` at mode 0600 and serves it until drop.
    pub(crate) fn listen(directory: &Path, upstream: Sender<UpstreamCmd>) -> Result<Self, String> {
        if !directory.is_dir() {
            return Err("CDP socket directory is missing".to_string());
        }
        let path = directory.join("cdp.sock");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).map_err(|error| format!("CDP socket: {error}"))?;
        let mut perms = std::fs::metadata(&path)
            .map_err(|error| format!("CDP socket: {error}"))?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms).map_err(|error| format!("CDP socket: {error}"))?;
        let mode = std::fs::metadata(&path)
            .map_err(|error| format!("CDP socket: {error}"))?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o600 {
            let _ = std::fs::remove_file(&path);
            return Err(format!("CDP socket mode is {mode:o}, want 600"));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let join = thread::spawn(move || serve(listener, flag, upstream));
        Ok(Self {
            path,
            stop,
            join: Some(join),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

fn serve(listener: UnixListener, stop: Arc<AtomicBool>, upstream: Sender<UpstreamCmd>) {
    let _ = listener.set_nonblocking(true);
    let mut threads = Vec::new();
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let upstream = upstream.clone();
                let stop = stop.clone();
                threads.push(thread::spawn(move || handle_conn(stream, upstream, stop)));
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
    for thread in threads {
        let _ = thread.join();
    }
}

fn handle_conn(mut stream: UnixStream, upstream: Sender<UpstreamCmd>, stop: Arc<AtomicBool>) {
    let _ = stream.set_read_timeout(Some(READ_SLICE));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let mut buf = Vec::new();
    while !stop.load(Ordering::SeqCst) {
        let mut byte = [0u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == 0 => {
                let frame = std::mem::take(&mut buf);
                if !dispatch(&mut stream, &frame, &upstream) {
                    break;
                }
            }
            Ok(_) => {
                buf.push(byte[0]);
                if buf.len() > MAX_FRAME {
                    break;
                }
            }
            Err(error)
                if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {
            }
            Err(_) => break,
        }
    }
}

fn dispatch(stream: &mut UnixStream, frame: &[u8], upstream: &Sender<UpstreamCmd>) -> bool {
    let value: Value = match serde_json::from_slice(frame) {
        Ok(value) => value,
        Err(_) => {
            write_json(
                stream,
                &json!({"error": {"code": -32700, "message": "the CDP message is not JSON"}}),
            );
            return true;
        }
    };
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = value.get("method").and_then(Value::as_str) else {
        write_json(
            stream,
            &json!({"id": id, "error": {"code": -32600, "message": "the CDP message has no method"}}),
        );
        return true;
    };
    let params = value.get("params").cloned().unwrap_or(Value::Null);
    if let Some(reason) = denied_reason(method, &params) {
        write_json(
            stream,
            &json!({"id": id, "error": {"code": -32601, "message": reason}}),
        );
        return true;
    }
    let (reply_tx, reply_rx) = std::sync::mpsc::channel();
    if upstream
        .send(UpstreamCmd {
            message: value,
            reply: reply_tx,
        })
        .is_err()
    {
        write_json(
            stream,
            &json!({"id": id, "error": {"code": -32000, "message": "the capture is not accepting CDP"}}),
        );
        return false;
    }
    match reply_rx.recv_timeout(Duration::from_secs(30)) {
        Ok(text) => {
            let _ = stream.write_all(text.as_bytes());
            let _ = stream.write_all(&[0]);
            true
        }
        Err(_) => {
            write_json(
                stream,
                &json!({"id": id, "error": {"code": -32000, "message": "the CDP command was not answered"}}),
            );
            true
        }
    }
}

fn write_json(stream: &mut UnixStream, value: &Value) {
    let _ = stream.write_all(value.to_string().as_bytes());
    let _ = stream.write_all(&[0]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::FileTypeExt;
    use std::sync::{mpsc::channel, Mutex};

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "scrapelens-cdp-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn roundtrip(path: &Path, message: Value) -> Value {
        let mut stream = UnixStream::connect(path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(message.to_string().as_bytes()).unwrap();
        stream.write_all(&[0]).unwrap();
        let mut buf = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).unwrap();
            if byte[0] == 0 {
                break;
            }
            buf.push(byte[0]);
        }
        serde_json::from_slice(&buf).unwrap()
    }

    #[test]
    fn blocked_methods_and_schemes_never_reach_the_upstream_and_the_socket_is_0600() {
        let dir = temp_dir("gate");
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = channel::<UpstreamCmd>();
        let log = seen.clone();
        let worker = thread::spawn(move || {
            while let Ok(cmd) = rx.recv() {
                let method = cmd
                    .message
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                log.lock().unwrap().push(method);
                let id = cmd.message.get("id").cloned().unwrap_or(Value::Null);
                let _ = cmd
                    .reply
                    .send(json!({"id": id, "result": {"ok": true}}).to_string());
            }
        });
        let gate = Gate::listen(&dir, tx).unwrap();
        let meta = std::fs::metadata(gate.path()).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);

        for (method, params) in [
            ("Network.getAllCookies", json!({})),
            ("Browser.setDownloadBehavior", json!({"behavior": "allow"})),
            ("Page.setDownloadBehavior", json!({"behavior": "deny"})),
            ("Page.navigate", json!({"url": "file:///etc/passwd"})),
            ("Page.navigate", json!({"url": " FILE:///tmp/x"})),
            ("Target.createTarget", json!({"url": "chrome://settings"})),
            ("Target.createTarget", json!({"url": "Chrome://newtab"})),
        ] {
            let reply = roundtrip(
                gate.path(),
                json!({"id": 4, "method": method, "params": params}),
            );
            assert!(reply.get("result").is_none(), "{method}: {reply}");
            assert!(
                reply["error"]["message"]
                    .as_str()
                    .unwrap_or("")
                    .contains("not allowed"),
                "{reply}"
            );
        }
        assert!(
            seen.lock().unwrap().is_empty(),
            "refused calls reached Chrome: {:?}",
            seen.lock().unwrap()
        );

        let reply = roundtrip(
            gate.path(),
            json!({"id": 9, "method": "Runtime.evaluate", "params": {"expression": "1"}}),
        );
        assert_eq!(reply["id"], 9);
        assert_eq!(reply["result"]["ok"], true);
        let reply = roundtrip(
            gate.path(),
            json!({"id": 10, "method": "Page.navigate", "params": {"url": "http://a.test/"}}),
        );
        assert_eq!(reply["result"]["ok"], true);
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            ["Runtime.evaluate".to_string(), "Page.navigate".to_string()]
        );

        drop(gate);
        assert!(!dir.join("cdp.sock").exists());
        let _ = worker.join();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_external_response_keeps_the_client_id() {
        let mut pending = HashMap::new();
        let (tx, rx) = channel();
        pending.insert(
            3,
            ExternalPending {
                client_id: json!(7),
                reply: tx,
            },
        );
        let response = json!({"id": 3, "result": {"targetInfos": []}});
        assert!(claim_external(&mut pending, &response));
        assert!(pending.is_empty());
        let text = rx.recv().unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["id"], 7);
        assert!(value["result"]["targetInfos"].is_array());
        assert!(!claim_external(
            &mut HashMap::new(),
            &json!({"method": "Network.requestWillBeSent"})
        ));
    }
}
