//! External CDP for `expose_cdp`: a mode-0600 unix socket in front of the pipe.
//!
//! Chrome opens no TCP port. Each message is one JSON object terminated by NUL,
//! the same framing as `--remote-debugging-pipe`. The method allowlist and the
//! `file:` / `chrome:` check run here, before anything is forwarded. Events are
//! delivered later, and only for sessions this connection attached itself.

use std::collections::{HashMap, HashSet};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::{json, Value};

const MAX_FRAME: usize = 1024 * 1024;
const READ_SLICE: Duration = Duration::from_millis(200);

static NEXT_CLIENT: AtomicU64 = AtomicU64::new(1);

/// What the socket asks the capture thread to do. `Command.reply` is the same
/// channel as `Subscribe.events`: responses and forwarded events share it, so a
/// load event can arrive while no command is in flight.
pub(crate) enum Upstream {
    Subscribe {
        client: u64,
        events: Sender<String>,
    },
    Unsubscribe {
        client: u64,
    },
    Command {
        client: u64,
        message: Value,
        reply: Sender<String>,
    },
}

/// Response the capture owes an external client, keyed by the id we sent to Chrome.
pub(crate) struct ExternalPending {
    pub client_id: Value,
    pub reply: Sender<String>,
    pub client: u64,
    pub method: String,
}

struct AttachedClient {
    events: Sender<String>,
    sessions: HashSet<String>,
}

/// Sessions each socket connection attached, and the channel its events use.
#[derive(Default)]
pub(crate) struct ExternalFanout {
    clients: HashMap<u64, AttachedClient>,
}

impl ExternalFanout {
    pub(crate) fn subscribe(&mut self, client: u64, events: Sender<String>) {
        self.clients.insert(
            client,
            AttachedClient {
                events,
                sessions: HashSet::new(),
            },
        );
    }

    pub(crate) fn disconnect(&mut self, client: u64) {
        self.clients.remove(&client);
    }

    pub(crate) fn note_session(&mut self, client: u64, session: &str) {
        if session.is_empty() {
            return;
        }
        if let Some(slot) = self.clients.get_mut(&client) {
            slot.sessions.insert(session.to_string());
        }
    }

    pub(crate) fn owns(&self, client: u64, session: &str) -> bool {
        self.clients
            .get(&client)
            .map(|slot| slot.sessions.contains(session))
            .unwrap_or(false)
    }

    /// `true` when any socket client attached this session. Capture must not
    /// treat that session as its own (and must not detach it).
    pub(crate) fn owns_session(&self, session: &str) -> bool {
        self.clients
            .values()
            .any(|slot| slot.sessions.contains(session))
    }

    /// Push one Chrome event to every client that attached `sessionId`.
    /// `Network.*` never passes, including `Network.*ExtraInfo`. Events with no
    /// session (capture traffic, `Target.targetCreated`) do not pass either.
    pub(crate) fn forward_event(&mut self, value: &Value) {
        let Some(method) = value.get("method").and_then(Value::as_str) else {
            return;
        };
        if method.starts_with("Network.") {
            return;
        }
        let Some(session) = value.get("sessionId").and_then(Value::as_str) else {
            return;
        };
        if session.is_empty() {
            return;
        }
        let text = value.to_string();
        let mut dead = Vec::new();
        for (id, client) in &self.clients {
            if client.sessions.contains(session) && client.events.send(text.clone()).is_err() {
                dead.push(*id);
            }
        }
        for id in dead {
            self.clients.remove(&id);
        }
    }
}

/// `true` when `value` is the response to a command we forwarded. The client's id
/// is restored and the text is sent on the waiting channel. A successful
/// `Target.attachToTarget` registers `result.sessionId` before that send, so the
/// session is owned before the client can use it.
pub(crate) fn claim_external(
    fanout: &mut ExternalFanout,
    pending: &mut HashMap<u64, ExternalPending>,
    value: &Value,
) -> bool {
    let Some(id) = value.get("id").and_then(Value::as_u64) else {
        return false;
    };
    let Some(wait) = pending.remove(&id) else {
        return false;
    };
    if wait.method == "Target.attachToTarget" {
        if let Some(session) = value
            .get("result")
            .and_then(|result| result.get("sessionId"))
            .and_then(Value::as_str)
        {
            fanout.note_session(wait.client, session);
        }
    }
    let mut out = value.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.insert("id".to_string(), wait.client_id);
    }
    let _ = wait.reply.send(out.to_string());
    true
}

/// Session-scoped domains may only name a session this client attached.
/// A command that carries someone else's `sessionId` is refused too, so the
/// client cannot drive the capture's own session. `Browser.getVersion` and the
/// three `Target` methods may omit `sessionId`.
pub(crate) fn session_denied(
    fanout: &ExternalFanout,
    client: u64,
    message: &Value,
) -> Option<&'static str> {
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");
    let session = message.get("sessionId").and_then(Value::as_str);
    let scoped = match method.split_once('.') {
        Some(("Page" | "Runtime" | "DOM" | "Input" | "Accessibility", name)) => !name.is_empty(),
        _ => false,
    };
    match session {
        Some(id) if !fanout.owns(client, id) => {
            Some("that CDP session is not one this client attached")
        }
        None if scoped => Some("that CDP session is not one this client attached"),
        _ => None,
    }
}

fn method_allowed(method: &str) -> bool {
    let Some((domain, name)) = method.split_once('.') else {
        return false;
    };
    if name.is_empty() {
        return false;
    }
    match domain {
        "Page" | "Runtime" | "DOM" | "Input" | "Accessibility" => true,
        "Browser" => name == "getVersion",
        "Target" => matches!(name, "attachToTarget" | "getTargets" | "createTarget"),
        _ => false,
    }
}

fn denied_reason(method: &str, params: &Value) -> Option<&'static str> {
    if !method_allowed(method) {
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
    pub(crate) fn listen(directory: &Path, upstream: Sender<Upstream>) -> Result<Self, String> {
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

fn serve(listener: UnixListener, stop: Arc<AtomicBool>, upstream: Sender<Upstream>) {
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

struct UnsubscribeOnDrop {
    client: u64,
    upstream: Sender<Upstream>,
}

impl Drop for UnsubscribeOnDrop {
    fn drop(&mut self) {
        let _ = self.upstream.send(Upstream::Unsubscribe {
            client: self.client,
        });
    }
}

fn handle_conn(mut stream: UnixStream, upstream: Sender<Upstream>, stop: Arc<AtomicBool>) {
    let client = NEXT_CLIENT.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = std::sync::mpsc::channel();
    if upstream
        .send(Upstream::Subscribe {
            client,
            events: tx.clone(),
        })
        .is_err()
    {
        return;
    }
    let _leave = UnsubscribeOnDrop {
        client,
        upstream: upstream.clone(),
    };
    let _ = stream.set_read_timeout(Some(READ_SLICE));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let mut buf = Vec::new();
    while !stop.load(Ordering::SeqCst) {
        while let Ok(text) = rx.try_recv() {
            if write_frame(&mut stream, text.as_bytes()).is_err() {
                return;
            }
        }
        let mut byte = [0u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == 0 => {
                let frame = std::mem::take(&mut buf);
                if !submit(&mut stream, &frame, client, &tx, &upstream) {
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

fn submit(
    stream: &mut UnixStream,
    frame: &[u8],
    client: u64,
    reply: &Sender<String>,
    upstream: &Sender<Upstream>,
) -> bool {
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
    if upstream
        .send(Upstream::Command {
            client,
            message: value,
            reply: reply.clone(),
        })
        .is_err()
    {
        write_json(
            stream,
            &json!({"id": id, "error": {"code": -32000, "message": "the capture is not accepting CDP"}}),
        );
        return false;
    }
    true
}

fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> std::io::Result<()> {
    stream.write_all(bytes)?;
    stream.write_all(&[0])?;
    Ok(())
}

fn write_json(stream: &mut UnixStream, value: &Value) {
    let _ = write_frame(stream, value.to_string().as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::FileTypeExt;
    use std::sync::{mpsc::channel, Mutex};

    fn temp_dir(name: &str) -> PathBuf {
        // macOS rejects a unix socket path at SUN_LEN (104). `/tmp` stays under that;
        // `std::env::temp_dir()` on this host does not.
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = PathBuf::from(format!(
            "/tmp/slcdp-{}-{}-{}",
            name,
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
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

    fn answer(message: &Value) -> String {
        let id = message.get("id").cloned().unwrap_or(Value::Null);
        json!({"id": id, "result": {"ok": true}}).to_string()
    }

    #[test]
    fn blocked_methods_and_schemes_never_reach_the_upstream_and_the_socket_is_0600() {
        let dir = temp_dir("gate");
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = channel::<Upstream>();
        let log = seen.clone();
        let worker = thread::spawn(move || {
            while let Ok(msg) = rx.recv() {
                let Upstream::Command { message, reply, .. } = msg else {
                    continue;
                };
                let method = message
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                log.lock().unwrap().push(method);
                let _ = reply.send(answer(&message));
            }
        });
        let gate = Gate::listen(&dir, tx).unwrap();
        let meta = std::fs::metadata(gate.path()).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);

        for (method, params) in [
            ("Network.getAllCookies", json!({})),
            ("Network.enable", json!({})),
            ("Network.getResponseBody", json!({"requestId": "1"})),
            ("Browser.setDownloadBehavior", json!({"behavior": "allow"})),
            ("Browser.close", json!({})),
            ("Storage.getCookies", json!({})),
            ("Fetch.enable", json!({})),
            ("Target.setAutoAttach", json!({"autoAttach": true})),
            ("Target.closeTarget", json!({"targetId": "t"})),
            ("Target.setDiscoverTargets", json!({"discover": true})),
            ("Foo.bar", json!({})),
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

        let allowed = [
            "Runtime.evaluate",
            "Runtime.runIfWaitingForDebugger",
            "Page.navigate",
            "Page.setDownloadBehavior",
            "Browser.getVersion",
            "Target.attachToTarget",
            "Target.getTargets",
            "Target.createTarget",
            "DOM.getDocument",
            "Input.dispatchMouseEvent",
            "Accessibility.getFullAXTree",
        ];
        for (index, method) in allowed.iter().enumerate() {
            let params = match *method {
                "Page.navigate" | "Target.createTarget" => json!({"url": "http://a.test/"}),
                "Page.setDownloadBehavior" => json!({"behavior": "deny"}),
                "Runtime.evaluate" => json!({"expression": "1"}),
                _ => json!({}),
            };
            let reply = roundtrip(
                gate.path(),
                json!({"id": 9 + index, "method": method, "params": params}),
            );
            assert_eq!(reply["id"], 9 + index, "{method}: {reply}");
            assert_eq!(reply["result"]["ok"], true, "{method}: {reply}");
        }
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            allowed
                .iter()
                .map(|method| (*method).to_string())
                .collect::<Vec<_>>()
                .as_slice()
        );

        drop(gate);
        assert!(!dir.join("cdp.sock").exists());
        let _ = worker.join();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_subscribed_client_receives_a_frame_that_is_not_a_response() {
        let dir = temp_dir("event");
        let (tx, rx) = channel::<Upstream>();
        let worker = thread::spawn(move || {
            while let Ok(msg) = rx.recv() {
                if let Upstream::Subscribe { events, .. } = msg {
                    let _ = events.send(
                        json!({"method": "Page.loadEventFired", "sessionId": "s"}).to_string(),
                    );
                }
            }
        });
        let gate = Gate::listen(&dir, tx).unwrap();
        let mut stream = UnixStream::connect(gate.path()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).unwrap();
            if byte[0] == 0 {
                break;
            }
            buf.push(byte[0]);
        }
        let value: Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(value["method"], "Page.loadEventFired");
        drop(stream);
        drop(gate);
        let _ = worker.join();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_external_response_keeps_the_client_id() {
        let mut fanout = ExternalFanout::default();
        let mut pending = HashMap::new();
        let (tx, rx) = channel();
        pending.insert(
            3,
            ExternalPending {
                client_id: json!(7),
                reply: tx,
                client: 1,
                method: "Target.getTargets".to_string(),
            },
        );
        let response = json!({"id": 3, "result": {"targetInfos": []}});
        assert!(claim_external(&mut fanout, &mut pending, &response));
        assert!(pending.is_empty());
        let text = rx.recv().unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["id"], 7);
        assert!(value["result"]["targetInfos"].is_array());
        assert!(!claim_external(
            &mut ExternalFanout::default(),
            &mut HashMap::new(),
            &json!({"method": "Network.requestWillBeSent"})
        ));
    }

    #[test]
    fn events_follow_only_the_session_this_client_attached() {
        let mut fanout = ExternalFanout::default();
        let (tx, rx) = channel();
        fanout.subscribe(1, tx.clone());
        fanout.forward_event(&json!({"method": "Page.loadEventFired", "sessionId": "s1"}));
        assert!(rx.try_recv().is_err(), "nothing is forwarded before attach");

        let mut pending = HashMap::new();
        pending.insert(
            4,
            ExternalPending {
                client_id: json!(9),
                reply: tx,
                client: 1,
                method: "Target.attachToTarget".to_string(),
            },
        );
        assert!(claim_external(
            &mut fanout,
            &mut pending,
            &json!({"id": 4, "result": {"sessionId": "s1"}})
        ));
        let restored: Value = serde_json::from_str(&rx.recv().unwrap()).unwrap();
        assert_eq!(restored["id"], 9);
        assert_eq!(restored["result"]["sessionId"], "s1");

        fanout.forward_event(
            &json!({"method": "Page.loadEventFired", "sessionId": "s1", "params": {"timestamp": 1}}),
        );
        let event: Value = serde_json::from_str(&rx.recv().unwrap()).unwrap();
        assert_eq!(event["method"], "Page.loadEventFired");

        for dropped in [
            json!({"method": "Network.requestWillBeSentExtraInfo", "sessionId": "s1"}),
            json!({"method": "Network.requestWillBeSent", "sessionId": "s1"}),
            json!({"method": "Network.requestWillBeSentExtraInfo", "sessionId": "capture"}),
            json!({"method": "Page.loadEventFired", "sessionId": "capture"}),
            json!({"method": "Target.targetCreated", "params": {}}),
            json!({"method": "Page.loadEventFired"}),
        ] {
            fanout.forward_event(&dropped);
        }
        assert!(
            rx.try_recv().is_err(),
            "capture and Network events must not pass"
        );

        assert!(session_denied(
            &fanout,
            1,
            &json!({"method": "Page.navigate", "sessionId": "capture", "params": {"url": "http://a.test/"}})
        )
        .is_some());
        assert!(session_denied(
            &fanout,
            1,
            &json!({"method": "Input.dispatchMouseEvent", "params": {}})
        )
        .is_some());
        assert!(session_denied(
            &fanout,
            1,
            &json!({"method": "Runtime.runIfWaitingForDebugger"})
        )
        .is_some());
        assert!(session_denied(
            &fanout,
            1,
            &json!({"method": "Page.navigate", "sessionId": "s1", "params": {"url": "http://a.test/"}})
        )
        .is_none());
        assert!(session_denied(
            &fanout,
            1,
            &json!({"method": "Browser.getVersion", "params": {}})
        )
        .is_none());
        assert!(session_denied(
            &fanout,
            1,
            &json!({"method": "Runtime.evaluate", "sessionId": "s1", "params": {"expression": "document.cookie"}})
        )
        .is_none());
        assert!(session_denied(
            &fanout,
            2,
            &json!({"method": "Page.navigate", "sessionId": "s1"})
        )
        .is_some());
    }
}
