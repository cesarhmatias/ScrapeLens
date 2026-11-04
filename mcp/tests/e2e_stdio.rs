//! Ponta a ponta: o binário real falando JSON-RPC por stdio.

mod common;

use std::process::Command;

use common::client::{Client as C, Elicit};
use common::*;
use serde_json::json;

fn program() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_scrapelens-mcp"))
}

struct Client(C);

impl Client {
    fn start(args: &[&str]) -> Self {
        Client(C::start(&program(), args, Elicit::Unsupported))
    }
    fn handshake(&mut self) -> serde_json::Value {
        self.0.handshake()
    }
    fn request(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        self.0.request(method, params)
    }
    fn tool(&mut self, name: &str, arguments: serde_json::Value) -> (bool, serde_json::Value) {
        self.0.tool(name, arguments)
    }
    fn finish(self) -> String {
        let (ok, stderr) = self.0.finish();
        assert!(ok, "o servidor deveria sair limpo no EOF");
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

    // tools/list: as quinze ferramentas, com esquema e anotações.
    let listed = client.request("tools/list", json!({}));
    let tools = listed["result"]["tools"].as_array().unwrap();
    let mut names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "capture_status",
            "diff_requests",
            "diff_sessions",
            "export_session",
            "get_body",
            "get_request",
            "import_session",
            "list_requests",
            "list_sessions",
            "navigate",
            "search_bodies",
            "site_profile",
            "start_capture",
            "stop_capture",
            "trace_value"
        ]
    );
    for tool in tools {
        assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
        let writes = [
            "export_session",
            "import_session",
            "start_capture",
            "navigate",
            "stop_capture",
        ]
        .contains(&tool["name"].as_str().unwrap());
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
    assert!(!client.0.seen.is_empty());
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
