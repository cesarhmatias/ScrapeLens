//! Minimal MCP client over stdio (line-delimited JSON-RPC), independent of rmcp.
//! Answers the server's elicitations according to the chosen policy.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

use serde_json::{json, Value};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Elicit {
    /// The client does not declare the elicitation capability.
    Unsupported,
    /// Declares it and answers `accept` with `confirmo: true`.
    Accept,
    /// Declares it and answers `accept` without checking the box.
    AcceptUnchecked,
    /// Declares it and answers `decline`.
    Decline,
    /// Declares it and answers with a JSON-RPC error ("User rejected").
    RpcError,
    /// Declares it and answers `accept` with `content: {}` (box absent).
    AcceptEmpty,
    /// Declares it and answers `accept` with `confirmo: "true"` (string, not boolean).
    AcceptString,
    /// Declares it and answers `accept` with `confirmo: 1`.
    AcceptNumber,
}

pub struct Client {
    pub child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    next_id: u64,
    policy: Elicit,
    /// Every stdout line received (must be JSON-RPC).
    pub seen: Vec<String>,
    /// Elicitation messages received from the server.
    pub elicitations: Vec<String>,
}

/// Path to the server with a fake browser (the crate's example, built by
/// `cargo test`).
pub fn fake_server() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let debug_dir = exe.parent().unwrap().parent().unwrap();
    let path = debug_dir
        .join("examples")
        .join(format!("fake_server{}", std::env::consts::EXE_SUFFIX));
    assert!(
        path.is_file(),
        "fake_server example not built: {path:?} (run `cargo test`)"
    );
    path
}

/// The process guard: the server never outlives the `Client`, not even when the
/// test fails or panics. Closes stdin (graceful exit, which also ends a Chrome in
/// progress) and, if the server does not exit within 15 s, kills it and waits.
impl Drop for Client {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while std::time::Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Client {
    pub fn start(program: &std::path::Path, args: &[&str], policy: Elicit) -> Self {
        Self::start_env(program, args, policy, &[])
    }

    pub fn start_env(
        program: &std::path::Path,
        args: &[&str],
        policy: Elicit,
        env: &[(&str, &str)],
    ) -> Self {
        let mut child = Command::new(program)
            .args(args)
            .envs(env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let stdin = child.stdin.take();
        Self {
            child,
            stdin,
            lines,
            next_id: 0,
            policy,
            seen: Vec::new(),
            elicitations: Vec::new(),
        }
    }

    pub fn send(&mut self, value: Value) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{value}").unwrap();
        stdin.flush().unwrap();
    }

    fn answer_elicitation(&mut self, message: &Value) {
        self.elicitations.push(
            message["params"]["message"]
                .as_str()
                .unwrap_or("")
                .to_string(),
        );
        let result = match self.policy {
            Elicit::Accept => json!({"action": "accept", "content": {"confirmo": true}}),
            Elicit::AcceptUnchecked => json!({"action": "accept", "content": {"confirmo": false}}),
            Elicit::AcceptEmpty => json!({"action": "accept", "content": {}}),
            Elicit::AcceptString => json!({"action": "accept", "content": {"confirmo": "true"}}),
            Elicit::AcceptNumber => json!({"action": "accept", "content": {"confirmo": 1}}),
            Elicit::Decline | Elicit::Unsupported => json!({"action": "decline"}),
            Elicit::RpcError => {
                self.send(json!({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -1, "message": "User rejected"}}));
                return;
            }
        };
        self.send(json!({"jsonrpc": "2.0", "id": message["id"], "result": result}));
    }

    pub fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        loop {
            let line = self
                .lines
                .recv_timeout(Duration::from_secs(120))
                .expect("the server did not respond in time");
            self.seen.push(line.clone());
            let message: Value = serde_json::from_str(&line)
                .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {line}"));
            assert_eq!(
                message["jsonrpc"], "2.0",
                "stdout may only carry JSON-RPC: {line}"
            );
            if message["method"] == "elicitation/create" {
                self.answer_elicitation(&message);
                continue;
            }
            if message["id"] == json!(id) && message.get("method").is_none() {
                return message;
            }
        }
    }

    pub fn handshake(&mut self) -> Value {
        let capabilities = if self.policy == Elicit::Unsupported {
            json!({})
        } else {
            json!({"elicitation": {"form": {}}})
        };
        let init = self.request(
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": capabilities, "clientInfo": {"name": "e2e", "version": "0"}}),
        );
        self.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        init
    }

    /// Calls a tool and returns (isError, structuredContent).
    pub fn tool(&mut self, name: &str, arguments: Value) -> (bool, Value) {
        let reply = self.request("tools/call", json!({"name": name, "arguments": arguments}));
        let result = &reply["result"];
        assert!(result.is_object(), "no result: {reply}");
        let text: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text, result["structuredContent"], "{name}");
        (
            result["isError"] == json!(true),
            result["structuredContent"].clone(),
        )
    }

    /// Closes stdin and waits for the server to exit; returns (success, stderr).
    pub fn finish(mut self) -> (bool, String) {
        drop(self.stdin.take());
        let status = self.child.wait().unwrap();
        let mut stderr = String::new();
        std::io::Read::read_to_string(&mut self.child.stderr.take().unwrap(), &mut stderr).unwrap();
        (status.success(), stderr)
    }

    /// Sends a `tools/call` without waiting for the reply; returns the call id.
    pub fn call_nowait(&mut self, name: &str, arguments: Value) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": arguments}}));
        id
    }

    /// Reads until the next elicitation from the server and answers it per the policy.
    pub fn answer_next_elicitation(&mut self) {
        loop {
            let line = self
                .lines
                .recv_timeout(Duration::from_secs(60))
                .expect("no elicitation");
            self.seen.push(line.clone());
            let message: Value = serde_json::from_str(&line).unwrap();
            if message["method"] == "elicitation/create" {
                self.answer_elicitation(&message);
                return;
            }
        }
    }

    /// Reads until the next elicitation and returns it WITHOUT answering.
    pub fn take_elicitation(&mut self) -> Value {
        loop {
            let line = self
                .lines
                .recv_timeout(Duration::from_secs(60))
                .expect("no elicitation");
            self.seen.push(line.clone());
            let message: Value = serde_json::from_str(&line).unwrap();
            if message["method"] == "elicitation/create" {
                self.elicitations.push(
                    message["params"]["message"]
                        .as_str()
                        .unwrap_or("")
                        .to_string(),
                );
                return message;
            }
        }
    }

    /// Cancels an in-progress call (`notifications/cancelled`).
    pub fn cancel(&mut self, request_id: u64) {
        self.send(json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": request_id, "reason": "client gave up"}}));
    }

    /// Answers an elicitation with `accept` and `confirmo: true`.
    pub fn accept_elicitation(&mut self, message: &Value) {
        self.send(json!({"jsonrpc": "2.0", "id": message["id"], "result": {"action": "accept", "content": {"confirmo": true}}}));
    }

    pub fn close_stdin(&mut self) {
        drop(self.stdin.take());
    }
}
