//! Ponta a ponta: o binário real falando JSON-RPC por stdio.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

use common::*;
use serde_json::{json, Value};

struct Client {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    next_id: u64,
    /// Toda linha de stdout recebida (precisa ser JSON-RPC).
    seen: Vec<String>,
}

impl Client {
    fn start(args: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_scrapelens-mcp"))
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
            seen: Vec::new(),
        }
    }

    fn send(&mut self, value: Value) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{value}").unwrap();
        stdin.flush().unwrap();
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        loop {
            let line = self
                .lines
                .recv_timeout(Duration::from_secs(60))
                .expect("o servidor não respondeu a tempo");
            self.seen.push(line.clone());
            let message: Value = serde_json::from_str(&line)
                .unwrap_or_else(|e| panic!("stdout não é JSON ({e}): {line}"));
            assert_eq!(
                message["jsonrpc"], "2.0",
                "stdout só pode trazer JSON-RPC: {line}"
            );
            if message["id"] == json!(id) {
                return message;
            }
        }
    }

    fn handshake(&mut self) -> Value {
        let init = self.request(
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "0"}}),
        );
        self.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        init
    }

    /// Chama uma ferramenta e devolve (isError, structuredContent).
    fn tool(&mut self, name: &str, arguments: Value) -> (bool, Value) {
        let reply = self.request("tools/call", json!({"name": name, "arguments": arguments}));
        let result = &reply["result"];
        assert!(result.is_object(), "sem result: {reply}");
        // O texto repete o structuredContent.
        let text: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text, result["structuredContent"], "{name}");
        (
            result["isError"] == json!(true),
            result["structuredContent"].clone(),
        )
    }

    fn finish(mut self) -> String {
        drop(self.stdin.take());
        let status = self.child.wait().unwrap();
        assert!(
            status.success(),
            "o servidor deveria sair limpo no EOF: {status:?}"
        );
        let mut stderr = String::new();
        std::io::Read::read_to_string(&mut self.child.stderr.take().unwrap(), &mut stderr).unwrap();
        stderr
    }
}

#[test]
fn full_session_over_stdio() {
    let work = tempfile::tempdir().unwrap();
    let sessions = work.path().join("sessions");
    let out = work.path().join("out");
    let har_a = work.path().join("a.har");
    let har_b = work.path().join("b.har");
    std::fs::write(&har_a, flow_har("")).unwrap();
    std::fs::write(&har_b, flow_har("-v2")).unwrap();

    let mut client = Client::start(&[
        "--sessions-dir",
        sessions.to_str().unwrap(),
        "--out-dir",
        out.to_str().unwrap(),
    ]);
    let init = client.handshake();
    assert_eq!(init["result"]["serverInfo"]["name"], "scrapelens-mcp");
    assert!(init["result"]["capabilities"]["tools"].is_object());

    // tools/list: as nove ferramentas, com esquema e anotações.
    let listed = client.request("tools/list", json!({}));
    let tools = listed["result"]["tools"].as_array().unwrap();
    let mut names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "diff_requests",
            "diff_sessions",
            "get_body",
            "get_request",
            "import_session",
            "list_requests",
            "list_sessions",
            "search_bodies",
            "trace_value"
        ]
    );
    for tool in tools {
        assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
        let writes = tool["name"] == "import_session";
        assert_eq!(
            tool["annotations"]["readOnlyHint"],
            json!(!writes),
            "{}",
            tool["name"]
        );
        assert_eq!(tool["annotations"]["destructiveHint"], false);
    }

    // import_session → list_sessions → list_requests → get_request ...
    let (is_error, imported) = client.tool("import_session", json!({"path": har_a, "name": "a"}));
    assert!(!is_error, "{imported}");
    assert_eq!(imported["requests"], 5);
    let (_, _) = client.tool("import_session", json!({"path": har_b, "name": "b"}));
    let (_, list) = client.tool("list_sessions", json!({}));
    assert_eq!(list["total"], 2);
    let (_, requests) = client.tool(
        "list_requests",
        json!({"session_id": "a", "host": "api.fixture.invalid"}),
    );
    assert_eq!(requests["total"], 2);
    let (_, request) = client.tool(
        "get_request",
        json!({"session_id": "a", "request_id": "har-0003"}),
    );
    assert_eq!(request["request"]["headers"][0], json!(["X-Dup", "a"]));
    assert_no_secrets(&request, "get_request e2e");
    let (_, body) = client.tool(
        "get_body",
        json!({"session_id": "a", "request_id": "har-0003"}),
    );
    assert_eq!(
        body["masked"], "unsupported",
        "texto livre fica retido sem reveal"
    );
    let (_, json_body) = client.tool(
        "get_body",
        json!({"session_id": "a", "request_id": "har-0002"}),
    );
    assert_eq!(json_body["inline"], true);
    assert_no_secrets(&json_body, "get_body e2e");
    let (_, search) = client.tool(
        "search_bodies",
        json!({"session_id": "a", "query": "img.png", "scopes": ["url"]}),
    );
    assert_eq!(search["total"], 1);
    let (_, diff) = client.tool(
        "diff_requests",
        json!({"session_id": "a", "request_a": "har-0002", "request_b": "har-0003"}),
    );
    assert_eq!(diff["aId"], "har-0002");
    let (_, sessions_diff) = client.tool(
        "diff_sessions",
        json!({"session_id_a": "a", "session_id_b": "b", "limit": 3}),
    );
    assert!(sessions_diff["totalPairs"].as_u64().unwrap() >= 1);
    let (_, trace) = client.tool("trace_value", json!({"session_id": "a", "cookie": "sid"}));
    assert_eq!(trace["firstSetter"]["requestId"], "har-0001");
    assert_no_secrets(&trace, "trace e2e");

    // Erros de ferramenta voltam como resultado com isError, não como erro de protocolo.
    let (is_error, error) = client.tool(
        "get_request",
        json!({"session_id": "a", "request_id": "nope"}),
    );
    assert!(is_error);
    assert_eq!(error["error"]["code"], "not_found");
    // reveal sem --allow-reveal é recusado.
    let (is_error, error) = client.tool(
        "get_request",
        json!({"session_id": "a", "request_id": "har-0003", "reveal": true}),
    );
    assert!(is_error);
    assert_eq!(error["error"]["code"], "reveal_disabled");
    // Argumento inválido (campo obrigatório ausente): o rmcp responde com isError e o motivo.
    let bad = client.request(
        "tools/call",
        json!({"name": "get_request", "arguments": {"session_id": "a"}}),
    );
    assert_eq!(bad["result"]["isError"], true, "{bad}");
    assert!(bad["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("request_id"));

    // Nada além de JSON-RPC em stdout (cada linha foi validada em request()).
    assert!(!client.seen.is_empty());
    let stderr = client.finish();
    assert!(
        stderr.contains("scrapelens-mcp"),
        "banner em stderr: {stderr}"
    );
}

#[test]
fn reveal_works_when_the_server_allows_it() {
    let work = tempfile::tempdir().unwrap();
    let har = work.path().join("a.har");
    std::fs::write(&har, flow_har("")).unwrap();
    let mut client = Client::start(&[
        "--sessions-dir",
        work.path().join("s").to_str().unwrap(),
        "--allow-reveal",
    ]);
    client.handshake();
    client.tool("import_session", json!({"path": har, "name": "a"}));
    let (is_error, request) = client.tool(
        "get_request",
        json!({"session_id": "a", "request_id": "har-0003", "reveal": true}),
    );
    assert!(!is_error);
    assert!(request.to_string().contains(TOKEN));
    // Corpo grande vai para arquivo em --out-dir (padrão: <sessions>/.mcp-out).
    let (_, body) = client.tool(
        "get_body",
        json!({"session_id": "a", "request_id": "har-0003", "reveal": true}),
    );
    let path = std::path::PathBuf::from(body["path"].as_str().unwrap());
    assert!(
        path.starts_with(
            work.path()
                .join("s")
                .canonicalize()
                .unwrap()
                .join(".mcp-out")
        ),
        "{path:?}"
    );
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 100_000);
    // Padrão continua mascarado.
    let (_, masked) = client.tool(
        "get_request",
        json!({"session_id": "a", "request_id": "har-0003"}),
    );
    assert_no_secrets(&masked, "padrão mascarado");
    client.finish();
}

#[test]
fn server_refuses_to_start_without_sessions_dir() {
    let output = Command::new(env!("CARGO_BIN_EXE_scrapelens-mcp"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "stdout deve ficar vazio");
    assert!(String::from_utf8_lossy(&output.stderr).contains("--sessions-dir"));
}
