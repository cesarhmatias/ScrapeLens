//! Cliente MCP mínimo por stdio (JSON-RPC em linhas), independente do rmcp.
//! Responde às elicitações do servidor conforme a política escolhida.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

use serde_json::{json, Value};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Elicit {
    /// O cliente não declara a capacidade de elicitação.
    Unsupported,
    /// Declara e responde `accept` com `confirmo: true`.
    Accept,
    /// Declara e responde `accept` mas sem marcar a caixa.
    AcceptUnchecked,
    /// Declara e responde `decline`.
    Decline,
}

pub struct Client {
    pub child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    next_id: u64,
    policy: Elicit,
    /// Toda linha de stdout recebida (precisa ser JSON-RPC).
    pub seen: Vec<String>,
    /// Mensagens de elicitação recebidas do servidor.
    pub elicitations: Vec<String>,
}

/// Caminho do servidor com navegador falso (exemplo do crate, construído pelo
/// `cargo test`).
pub fn fake_server() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let debug_dir = exe.parent().unwrap().parent().unwrap();
    let path = debug_dir
        .join("examples")
        .join(format!("fake_server{}", std::env::consts::EXE_SUFFIX));
    assert!(
        path.is_file(),
        "exemplo fake_server não construído: {path:?} (rode `cargo test`)"
    );
    path
}

impl Client {
    pub fn start(program: &std::path::Path, args: &[&str], policy: Elicit) -> Self {
        let mut child = Command::new(program)
            .args(args)
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
            Elicit::Decline | Elicit::Unsupported => json!({"action": "decline"}),
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
                .expect("o servidor não respondeu a tempo");
            self.seen.push(line.clone());
            let message: Value = serde_json::from_str(&line)
                .unwrap_or_else(|e| panic!("stdout não é JSON ({e}): {line}"));
            assert_eq!(
                message["jsonrpc"], "2.0",
                "stdout só pode trazer JSON-RPC: {line}"
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

    /// Chama uma ferramenta e devolve (isError, structuredContent).
    pub fn tool(&mut self, name: &str, arguments: Value) -> (bool, Value) {
        let reply = self.request("tools/call", json!({"name": name, "arguments": arguments}));
        let result = &reply["result"];
        assert!(result.is_object(), "sem result: {reply}");
        let text: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text, result["structuredContent"], "{name}");
        (
            result["isError"] == json!(true),
            result["structuredContent"].clone(),
        )
    }

    /// Fecha o stdin e espera o servidor sair; devolve (sucesso, stderr).
    pub fn finish(mut self) -> (bool, String) {
        drop(self.stdin.take());
        let status = self.child.wait().unwrap();
        let mut stderr = String::new();
        std::io::Read::read_to_string(&mut self.child.stderr.take().unwrap(), &mut stderr).unwrap();
        (status.success(), stderr)
    }

    pub fn close_stdin(&mut self) {
        drop(self.stdin.take());
    }
}
