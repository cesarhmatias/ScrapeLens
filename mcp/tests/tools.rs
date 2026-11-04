//! Per-tool tests, calling the functions of `scrapelens_mcp::tools`
//! against a synthetic HAR and the repository fixtures (read-only).

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use common::*;
use scrapelens_mcp::tools::*;
use serde_json::{json, Value};

fn err_code(result: Result<Value, scrapelens_mcp::error::ToolError>) -> String {
    result.expect_err("an error was expected").code.to_string()
}

fn headers_of(view: &Value) -> Vec<(String, String)> {
    view["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| {
            (
                pair[0].as_str().unwrap().to_string(),
                pair[1].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

// ---- list_sessions / import_session --------------------------------------

#[test]
fn import_and_list_sessions() {
    let env = Env::new(false);
    let id = env.import_flow("flow", "");
    assert_eq!(id, "flow");
    let list = list_sessions(&env.ctx, p(json!({}))).unwrap();
    assert_eq!(list["total"], 1);
    let session = &list["sessions"][0];
    assert_eq!(session["sessionId"], "flow");
    assert_eq!(session["requests"], 5);
    assert_eq!(session["readOnly"], false);
    // Second import of the same content: idempotent.
    let path = env.dir.path().join("flow.har");
    let again = import_session(&env.ctx, p(json!({"path": path, "name": "flow"}))).unwrap();
    assert_eq!(again["alreadyImported"], true);
    // Same name, different content: refused.
    let other = env.write("other.har", &flow_har("-v2"));
    assert_eq!(
        err_code(import_session(
            &env.ctx,
            p(json!({"path": other, "name": "flow"}))
        )),
        "exists"
    );
}

#[test]
fn import_formats_and_errors() {
    let env = Env::new(false);
    // Repository HAR, repository NetLog, native session, CDP+NetLog capture.
    for (path, name, format) in [
        ("fixtures/aceite/sanitize/secret.har", "secret", "har"),
        ("fixtures/aceite/diff/session", "diffsession", "session"),
        ("experiments/results/h1-page", "h1page", "capture"),
    ] {
        let out = import_session(
            &env.ctx,
            p(json!({"path": repo(path).to_str().unwrap(), "name": name})),
        )
        .unwrap_or_else(|e| panic!("{path}: {e}"));
        assert_eq!(out["format"], format, "{path}");
        assert!(out["requests"].as_u64().unwrap() > 0, "{path}");
    }
    let netlog = repo("experiments/results/h1-page/chrome-netlog.json");
    let out = import_session(
        &env.ctx,
        p(json!({"path": netlog.to_str().unwrap(), "name": "netlogonly"})),
    )
    .unwrap();
    assert_eq!(out["format"], "netlog");

    // Errors.
    let bad = env.write("bad.txt", "isso não é JSON");
    assert_eq!(
        err_code(import_session(&env.ctx, p(json!({"path": bad})))),
        "import_failed"
    );
    assert_eq!(
        err_code(import_session(
            &env.ctx,
            p(json!({"path": "/nao/existe.har"}))
        )),
        "not_found"
    );
    assert_eq!(
        err_code(import_session(
            &env.ctx,
            p(json!({"path": bad, "format": "xml"}))
        )),
        "invalid_argument"
    );
}

#[test]
fn import_name_cannot_escape_the_sessions_dir() {
    let env = Env::new(false);
    let path = env.write("a.har", &flow_har(""));
    for name in ["../evil", "a/b", "..", ".hidden", "x\\y", ""] {
        assert_eq!(
            err_code(import_session(
                &env.ctx,
                p(json!({"path": path, "name": name}))
            )),
            "outside_allowed_dir",
            "{name:?}"
        );
    }
    assert!(!env.dir.path().join("evil").exists());
}

#[test]
fn import_enforces_size_limit() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = scrapelens_mcp::Config::new(&dir.path().join("s"), None, &[], false, 10).unwrap();
    let ctx = scrapelens_mcp::Ctx::new(cfg);
    let path = dir.path().join("a.har");
    std::fs::write(&path, flow_har("")).unwrap();
    assert_eq!(
        err_code(import_session(&ctx, p(json!({"path": path})))),
        "too_large"
    );
}

#[test]
fn session_ids_are_handles_never_paths() {
    let env = Env::new(false);
    env.import_flow("flow", "");
    for bad in ["../flow", "/etc/passwd", "flow/..", ".mcp-out"] {
        let code = err_code(list_requests(&env.ctx, p(json!({"session_id": bad}))));
        assert_eq!(code, "invalid_argument", "{bad}");
    }
    assert_eq!(
        err_code(list_requests(&env.ctx, p(json!({"session_id": "nope"})))),
        "not_found"
    );
}

#[test]
fn extra_sessions_dirs_are_read_only_and_listed() {
    let src = tempfile::tempdir().unwrap();
    let copy = src.path().join("copied");
    std::fs::create_dir_all(&copy).unwrap();
    let from = repo("fixtures/aceite/diff/session");
    std::fs::copy(from.join("session.json"), copy.join("session.json")).unwrap();
    std::fs::create_dir_all(copy.join("attachments")).unwrap();
    for entry in std::fs::read_dir(from.join("attachments"))
        .unwrap()
        .flatten()
    {
        std::fs::copy(
            entry.path(),
            copy.join("attachments").join(entry.file_name()),
        )
        .unwrap();
    }
    let env = Env::with_extra(false, &[src.path().to_path_buf()]);
    let list = list_sessions(&env.ctx, p(json!({}))).unwrap();
    assert_eq!(list["sessions"][0]["sessionId"], "copied");
    assert_eq!(list["sessions"][0]["readOnly"], true);
    let items = list_requests(&env.ctx, p(json!({"session_id": "copied"}))).unwrap();
    assert_eq!(items["total"], 2);
    // The import never writes to the extra directory.
    let before: Vec<_> = std::fs::read_dir(src.path()).unwrap().collect();
    env.import_flow("flow", "");
    assert_eq!(std::fs::read_dir(src.path()).unwrap().count(), before.len());
}

// ---- list_requests --------------------------------------------------------

#[test]
fn list_requests_filters_and_paginates() {
    let env = Env::new(false);
    env.import_flow("flow", "");
    let ls = |v: Value| list_requests(&env.ctx, p(v)).unwrap();
    let all = ls(json!({"session_id": "flow"}));
    assert_eq!(all["total"], 5);
    assert_eq!(all["items"][0]["requestId"], "har-0001");
    assert_eq!(
        ls(json!({"session_id": "flow", "host": "API.fixture.invalid"}))["total"],
        2
    );
    assert_eq!(
        ls(json!({"session_id": "flow", "method": "post"}))["total"],
        1
    );
    assert_eq!(
        ls(json!({"session_id": "flow", "status": "4xx"}))["total"],
        1
    );
    assert_eq!(ls(json!({"session_id": "flow", "status": 404}))["total"], 1);
    assert_eq!(
        ls(json!({"session_id": "flow", "status": "2xx"}))["total"],
        4
    );
    assert_eq!(
        ls(json!({"session_id": "flow", "status": "none"}))["total"],
        0
    );
    assert_eq!(ls(json!({"session_id": "flow", "text": "IMG"}))["total"], 1);
    // Pagination: 2 + 2 + 1, without repeating or skipping.
    let mut ids = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut args = json!({"session_id": "flow", "limit": 2});
        if let Some(cursor) = &cursor {
            args["cursor"] = json!(cursor);
        }
        let page = ls(args);
        ids.extend(
            page["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| i["requestId"].as_str().unwrap().to_string()),
        );
        match page["nextCursor"].as_str() {
            Some(next) => cursor = Some(next.to_string()),
            None => break,
        }
    }
    assert_eq!(
        ids,
        ["har-0001", "har-0002", "har-0003", "har-0004", "har-0005"]
    );
    assert_eq!(
        err_code(list_requests(
            &env.ctx,
            p(json!({"session_id": "flow", "limit": 500}))
        )),
        "invalid_argument"
    );
    assert_eq!(
        err_code(list_requests(
            &env.ctx,
            p(json!({"session_id": "flow", "status": "abc"}))
        )),
        "invalid_argument"
    );
    assert_eq!(
        err_code(list_requests(
            &env.ctx,
            p(json!({"session_id": "flow", "cursor": "zzz"}))
        )),
        "invalid_argument"
    );
}

// ---- get_request ----------------------------------------------------------

#[test]
fn get_request_keeps_header_order_duplicates_and_masks_secrets() {
    let env = Env::new(true);
    env.import_flow("flow", "");
    let masked = get_request(
        &env.ctx,
        p(json!({"session_id": "flow", "request_id": "har-0003"})),
    )
    .unwrap();
    assert_eq!(masked["revealed"], false);
    let names: Vec<_> = headers_of(&masked["request"])
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(
        names,
        ["X-Dup", "Authorization", "x-dup", "Cookie", "X-Dup"],
        "original order and duplicates"
    );
    let values = headers_of(&masked["request"]);
    assert_eq!(values[0].1, "a");
    assert_eq!(values[2].1, "b");
    assert_eq!(values[4].1, "c");
    assert_eq!(values[1].1, "[REDACTED]");
    assert_eq!(values[3].1, "[REDACTED]");
    assert_eq!(masked["request"]["orderState"], "sourceOrder");
    assert_eq!(masked["request"]["source"], "har");
    assert_eq!(masked["request"]["verification"], "unverified");
    assert_eq!(masked["origin"]["sources"], json!(["har"]));
    assert_no_secrets(&masked, "get_request mascarado");

    let revealed = get_request(
        &env.ctx,
        p(json!({"session_id": "flow", "request_id": "har-0003", "reveal": true})),
    )
    .unwrap();
    assert_eq!(revealed["revealed"], true);
    assert!(text(&revealed).contains(TOKEN));
    assert!(text(&revealed).contains(SID));

    // verbose: per-header provenance.
    let verbose = get_request(
        &env.ctx,
        p(json!({"session_id": "flow", "request_id": "har-0003", "verbose": true})),
    )
    .unwrap();
    assert_eq!(verbose["request"]["headers"][0]["name"], "X-Dup");
    assert_eq!(verbose["request"]["headers"][0]["source"], "har");

    // explicit attempt and errors
    let attempt = get_request(
        &env.ctx,
        p(json!({"session_id": "flow", "request_id": "har-0003", "attempt": "0"})),
    )
    .unwrap();
    assert_eq!(attempt["attemptId"], "har-0003-a1");
    assert_eq!(
        err_code(get_request(
            &env.ctx,
            p(json!({"session_id": "flow", "request_id": "nope"}))
        )),
        "not_found"
    );
    assert_eq!(
        err_code(get_request(
            &env.ctx,
            p(json!({"session_id": "flow", "request_id": "har-0003", "attempt": "9"}))
        )),
        "not_found"
    );
}

#[test]
fn reveal_requires_allow_reveal() {
    let env = Env::new(false);
    env.import_flow("flow", "");
    let code = err_code(get_request(
        &env.ctx,
        p(json!({"session_id": "flow", "request_id": "har-0003", "reveal": true})),
    ));
    assert_eq!(code, "reveal_disabled");
    for result in [
        list_requests(&env.ctx, p(json!({"session_id": "flow", "reveal": true}))),
        get_body(
            &env.ctx,
            p(json!({"session_id": "flow", "request_id": "har-0001", "reveal": true})),
        ),
        search_bodies(
            &env.ctx,
            p(json!({"session_id": "flow", "query": "x", "reveal": true})),
        ),
        trace_value(
            &env.ctx,
            p(json!({"session_id": "flow", "cookie": "sid", "reveal": true})),
        ),
        diff_requests_tool(
            &env.ctx,
            p(
                json!({"session_id": "flow", "request_a": "har-0001", "request_b": "har-0002", "reveal": true}),
            ),
        ),
        diff_sessions(
            &env.ctx,
            p(json!({"session_id_a": "flow", "session_id_b": "flow", "reveal": true})),
        ),
    ] {
        assert_eq!(err_code(result), "reveal_disabled");
    }
}

#[test]
fn headers_cookies_fixture_keeps_duplicates_and_mixed_case() {
    let env = Env::new(false);
    let path = repo("fixtures/aceite/headers-cookies/headers-cookies.har");
    import_session(
        &env.ctx,
        p(json!({"path": path.to_str().unwrap(), "name": "hc"})),
    )
    .unwrap();
    let request = get_request(
        &env.ctx,
        p(json!({"session_id": "hc", "request_id": "har-0001"})),
    )
    .unwrap();
    let names: Vec<_> = headers_of(&request["request"])
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(&names[..4], ["x-rep", "x-seq", "X-Rep", "x-seq"]);
    assert_eq!(names[4], "x-mixed-Case");
}

// ---- get_body -------------------------------------------------------------

#[test]
fn get_body_inline_large_binary_and_masking() {
    let env = Env::new(true);
    env.import_flow("flow", "");
    let body = |v: Value| get_body(&env.ctx, p(v)).unwrap();

    // Masked JSON: inline, without the token.
    let json_masked = body(json!({"session_id": "flow", "request_id": "har-0002"}));
    assert_eq!(json_masked["inline"], true);
    assert_eq!(json_masked["masked"], "redacted");
    assert_no_secrets(&json_masked, "get_body json");
    // Request body (password).
    let req_masked =
        body(json!({"session_id": "flow", "request_id": "har-0002", "part": "request"}));
    assert_no_secrets(&req_masked, "get_body request");

    // Masked HTML: retained, without content.
    let html = body(json!({"session_id": "flow", "request_id": "har-0001"}));
    assert_eq!(html["masked"], "unsupported");
    assert!(html.get("text").is_none());
    assert_eq!(html["inline"], false);
    assert!(html["hint"].as_str().unwrap().contains("reveal"));
    // With reveal: text.
    let html_open = body(json!({"session_id": "flow", "request_id": "har-0001", "reveal": true}));
    assert!(html_open["text"].as_str().unwrap().contains(CSRF));
    assert_eq!(html_open["revealed"], true);

    // Large body: goes to a file inside out-dir, 0600.
    let big = body(json!({"session_id": "flow", "request_id": "har-0003", "reveal": true}));
    assert_eq!(big["inline"], false);
    assert!(big.get("text").is_none());
    let path = std::path::PathBuf::from(big["path"].as_str().unwrap());
    let out_dir = env.dir.path().join("out").canonicalize().unwrap();
    assert!(path.starts_with(&out_dir), "{path:?}");
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 100_000);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(big["range"]["total"], 100_000);

    // A small range of the same body comes back inline.
    let slice = body(
        json!({"session_id": "flow", "request_id": "har-0003", "reveal": true, "offset": 10, "length": 5}),
    );
    assert_eq!(slice["inline"], true);
    assert_eq!(slice["text"], "AAAAA");
    assert_eq!(slice["range"]["offset"], 10);

    // Binary: always a .bin file.
    let bin = body(json!({"session_id": "flow", "request_id": "har-0004", "reveal": true}));
    assert_eq!(bin["encoding"], "binary");
    let bin_path = bin["path"].as_str().unwrap();
    assert!(bin_path.ends_with(".bin"), "{bin_path}");
    assert_eq!(std::fs::read(bin_path).unwrap().len(), 300);

    // No body: descriptor without inventing content.
    let none = body(json!({"session_id": "flow", "request_id": "har-0005"}));
    assert_eq!(none["inline"], false);
    assert!(none.get("path").is_none() && none.get("text").is_none());

    // Errors.
    assert_eq!(
        err_code(get_body(
            &env.ctx,
            p(json!({"session_id": "flow", "request_id": "har-0001", "part": "x"}))
        )),
        "invalid_argument"
    );
    assert_eq!(
        err_code(get_body(
            &env.ctx,
            p(
                json!({"session_id": "flow", "request_id": "har-0001", "max_inline_bytes": 99999999})
            )
        )),
        "invalid_argument"
    );
    assert_eq!(
        err_code(get_body(
            &env.ctx,
            p(
                json!({"session_id": "flow", "request_id": "har-0003", "offset": 999999999, "reveal": true})
            )
        )),
        "invalid_argument"
    );
}

#[test]
fn bodies_fixture_reports_truncated_and_empty_states() {
    let env = Env::new(false);
    let path = repo("fixtures/aceite/bodies/session");
    import_session(
        &env.ctx,
        p(json!({"path": path.to_str().unwrap(), "name": "bodies"})),
    )
    .unwrap();
    let truncated = get_body(
        &env.ctx,
        p(json!({"session_id": "bodies", "request_id": "har-0002"})),
    )
    .unwrap();
    assert_eq!(truncated["state"], "truncated");
    let empty = get_body(
        &env.ctx,
        p(json!({"session_id": "bodies", "request_id": "har-0003"})),
    )
    .unwrap();
    assert_eq!(empty["state"], "empty");
}

// ---- search_bodies --------------------------------------------------------

#[test]
fn search_bodies_masked_is_not_an_oracle() {
    let env = Env::new(true);
    env.import_flow("flow", "");
    let search = |v: Value| search_bodies(&env.ctx, p(v)).unwrap();
    let masked = search(json!({"session_id": "flow", "query": TOKEN}));
    assert_eq!(
        masked["total"], 0,
        "secret value is already redacted in the searched copy"
    );
    assert_no_secrets(&masked, "search mascarado");
    assert!(
        masked["skippedMasked"].as_u64().unwrap() >= 1,
        "HTML/free text not scanned"
    );

    let open = search(json!({"session_id": "flow", "query": TOKEN, "reveal": true}));
    assert!(open["total"].as_u64().unwrap() >= 2);
    let scopes: Vec<_> = open["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["scope"].as_str().unwrap().to_string())
        .collect();
    assert!(scopes.contains(&"responseBody".to_string()));
    assert!(scopes.contains(&"requestHeaders".to_string()));
    // short snippet, never the whole body
    for m in open["matches"].as_array().unwrap() {
        assert!(m["snippet"].as_str().unwrap().chars().count() < 400);
    }

    let by_url = search(json!({"session_id": "flow", "query": "img.png", "scopes": ["url"]}));
    assert_eq!(by_url["total"], 1);
    assert_eq!(by_url["matches"][0]["requestId"], "har-0004");

    // Pagination of the matches.
    let page =
        search(json!({"session_id": "flow", "query": "fixture", "scopes": ["url"], "limit": 2}));
    assert_eq!(page["matches"].as_array().unwrap().len(), 2);
    assert_eq!(page["hasMore"], true);
    assert!(page["nextCursor"].is_string());

    assert_eq!(
        err_code(search_bodies(
            &env.ctx,
            p(json!({"session_id": "flow", "query": "x", "scopes": ["nope"]}))
        )),
        "invalid_argument"
    );
    assert_eq!(
        err_code(search_bodies(
            &env.ctx,
            p(json!({"session_id": "flow", "query": ""}))
        )),
        "invalid_argument"
    );
}

// ---- diff_requests --------------------------------------------------------

#[test]
fn diff_requests_keeps_order_and_supports_ignore_and_cross_session() {
    let env = Env::new(true);
    env.import_flow("flow", "");
    env.import_flow("flow2", "-v2");
    let diff = diff_requests_tool(
        &env.ctx,
        p(json!({"session_id": "flow", "request_a": "har-0002", "request_b": "har-0003"})),
    )
    .unwrap();
    assert_eq!(diff["masked"], true);
    assert!(diff["maskNote"].is_string());
    assert_no_secrets(&diff, "diff_requests");
    assert!(diff["requestHeaders"]["added"].is_array());

    // Same request in two sessions; the Authorization header differs (masked → equal).
    let cross = diff_requests_tool(
        &env.ctx,
        p(json!({"session_id": "flow", "request_a": "har-0003", "request_b": "har-0003", "other_session_id": "flow2"})),
    )
    .unwrap();
    assert_eq!(cross["otherSessionId"], "flow2");
    let real = diff_requests_tool(
        &env.ctx,
        p(json!({"session_id": "flow", "request_a": "har-0003", "request_b": "har-0003", "other_session_id": "flow2", "reveal": true})),
    )
    .unwrap();
    let changed = real["requestHeaders"]["changed"].as_array().unwrap();
    assert!(
        changed.iter().any(|c| c["name"] == "Authorization"),
        "{changed:?}"
    );

    // ignore removes the name from the output and counts it.
    let ignored = diff_requests_tool(
        &env.ctx,
        p(json!({"session_id": "flow", "request_a": "har-0003", "request_b": "har-0003", "other_session_id": "flow2", "reveal": true, "ignore": ["authorization"]})),
    )
    .unwrap();
    assert!(ignored["ignored"].as_u64().unwrap() >= 1);
    assert!(!ignored["requestHeaders"]["changed"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "Authorization"));

    assert_eq!(
        err_code(diff_requests_tool(
            &env.ctx,
            p(json!({"session_id": "flow", "request_a": "x", "request_b": "har-0001"}))
        )),
        "not_found"
    );
}

#[test]
fn diff_fixture_session_has_header_changes() {
    let env = Env::new(false);
    let path = repo("fixtures/aceite/diff/session");
    import_session(
        &env.ctx,
        p(json!({"path": path.to_str().unwrap(), "name": "d"})),
    )
    .unwrap();
    let diff = diff_requests_tool(
        &env.ctx,
        p(json!({"session_id": "d", "request_a": "har-0001", "request_b": "har-0002"})),
    )
    .unwrap();
    assert_eq!(diff["aId"], "har-0001");
    assert_eq!(diff["bId"], "har-0002");
}

// ---- diff_sessions --------------------------------------------------------

#[test]
fn diff_sessions_pairs_requests_and_paginates() {
    let env = Env::new(true);
    env.import_flow("a", "");
    env.import_flow("b", "-v2");
    let diff = diff_sessions(
        &env.ctx,
        p(json!({"session_id_a": "a", "session_id_b": "b", "limit": 2})),
    )
    .unwrap();
    assert_eq!(diff["masked"], true);
    assert_eq!(diff["sessionIdA"], "a");
    assert!(diff["totalPairs"].as_u64().unwrap() >= 1);
    assert!(diff["pairs"].as_array().unwrap().len() <= 2);
    assert_no_secrets(&diff, "diff_sessions");
    let open = diff_sessions(
        &env.ctx,
        p(json!({"session_id_a": "a", "session_id_b": "b", "reveal": true})),
    )
    .unwrap();
    assert_eq!(open["masked"], false);
    // The repository fixtures also compare.
    let h = repo("fixtures/aceite/diff/session");
    import_session(
        &env.ctx,
        p(json!({"path": h.to_str().unwrap(), "name": "fx"})),
    )
    .unwrap();
    let same = diff_sessions(
        &env.ctx,
        p(json!({"session_id_a": "fx", "session_id_b": "fx"})),
    )
    .unwrap();
    assert!(same["totalPairs"].as_u64().unwrap() >= 1);
    assert_eq!(
        err_code(diff_sessions(
            &env.ctx,
            p(json!({"session_id_a": "a", "session_id_b": "zzz"}))
        )),
        "not_found"
    );
    assert_eq!(
        err_code(diff_sessions(
            &env.ctx,
            p(json!({"session_id_a": "a", "session_id_b": "b", "a_range": "oops"}))
        )),
        "invalid_argument"
    );
}

// ---- trace_value ----------------------------------------------------------

#[test]
fn trace_cookie_finds_first_setter_and_users_without_leaking_values() {
    let env = Env::new(true);
    env.import_flow("flow", "");
    let trace = trace_value(&env.ctx, p(json!({"session_id": "flow", "cookie": "sid"}))).unwrap();
    assert_eq!(trace["mode"], "cookie");
    assert_eq!(trace["firstSetter"]["requestId"], "har-0001");
    assert_eq!(trace["firstSetter"]["attributes"]["httpOnly"], true);
    let users: Vec<_> = trace["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["requestId"].as_str().unwrap())
        .collect();
    assert_eq!(users, ["har-0002", "har-0003"]);
    assert!(trace["users"]
        .as_array()
        .unwrap()
        .iter()
        .all(|u| u["sentValueEqualsFirstSetter"] == true));
    assert_no_secrets(&trace, "trace cookie");
    assert!(trace["firstSetter"].get("value").is_none());

    let open = trace_value(
        &env.ctx,
        p(json!({"session_id": "flow", "cookie": "sid", "reveal": true})),
    )
    .unwrap();
    assert_eq!(open["firstSetter"]["value"], SID);

    // Cookie without an observed setter: origin not invented.
    let orphan = trace_value(
        &env.ctx,
        p(json!({"session_id": "flow", "cookie": "ghost"})),
    )
    .unwrap();
    assert!(orphan["firstSetter"].is_null());
    assert!(text(&orphan["notes"]).contains("não é afirmada"));
}

#[test]
fn trace_literal_value_and_request_origins() {
    let env = Env::new(true);
    env.import_flow("flow", "");
    let trace = trace_value(
        &env.ctx,
        p(json!({"session_id": "flow", "value": TOKEN, "reveal": true})),
    )
    .unwrap();
    assert_eq!(trace["evidence"], "literal-match");
    assert_eq!(trace["firstProducer"]["requestId"], "har-0002");
    assert_eq!(trace["firstProducer"]["scope"], "responseBody");
    assert!(trace["consumers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["requestId"] == "har-0003" && c["scope"] == "requestHeaders"));
    assert_eq!(trace["value"], TOKEN, "with reveal the value is echoed");

    // Without reveal the `value` mode does not exist (neither for a short nor for an unknown value).
    for value in ["zzq", "zzq-not-in-session-0123"] {
        let denied = trace_value(&env.ctx, p(json!({"session_id": "flow", "value": value})));
        assert_eq!(err_code(denied), "reveal_required");
    }

    // Request mode: core origins, masked previews.
    let origins = trace_value(
        &env.ctx,
        p(json!({"session_id": "flow", "request_id": "har-0003"})),
    )
    .unwrap();
    assert_eq!(origins["mode"], "request");
    assert_eq!(origins["requestId"], "har-0003");
    let values = origins["values"].as_array().unwrap();
    assert!(!values.is_empty());
    assert!(values.iter().all(|v| v["value"] == "[REDACTED]"));
    assert_no_secrets(&origins, "trace request");
    let open = trace_value(
        &env.ctx,
        p(json!({"session_id": "flow", "request_id": "har-0003", "reveal": true})),
    )
    .unwrap();
    assert!(text(&open).contains(TOKEN));

    // Exactly one mode.
    assert_eq!(
        err_code(trace_value(&env.ctx, p(json!({"session_id": "flow"})))),
        "invalid_argument"
    );
    assert_eq!(
        err_code(trace_value(
            &env.ctx,
            p(json!({"session_id": "flow", "cookie": "a", "value": "b"}))
        )),
        "invalid_argument"
    );
}

// ---- policy: no secret without reveal ---------------------------------

#[test]
fn repository_secret_fixture_never_leaks_without_reveal() {
    let env = Env::new(false);
    let har = repo("fixtures/aceite/sanitize/secret.har");
    import_session(
        &env.ctx,
        p(json!({"path": har.to_str().unwrap(), "name": "sec"})),
    )
    .unwrap();
    let mut outputs = vec![
        list_requests(&env.ctx, p(json!({"session_id": "sec"}))).unwrap(),
        search_bodies(&env.ctx, p(json!({"session_id": "sec", "query": "SECRET"}))).unwrap(),
        diff_requests_tool(
            &env.ctx,
            p(json!({"session_id": "sec", "request_a": "har-0001", "request_b": "har-0002"})),
        )
        .unwrap(),
        diff_sessions(
            &env.ctx,
            p(json!({"session_id_a": "sec", "session_id_b": "sec"})),
        )
        .unwrap(),
        trace_value(&env.ctx, p(json!({"session_id": "sec", "cookie": "sid"}))).unwrap(),
        trace_value(
            &env.ctx,
            p(json!({"session_id": "sec", "request_id": "har-0001"})),
        )
        .unwrap(),
    ];
    for id in ["har-0001", "har-0002"] {
        outputs.push(
            get_request(
                &env.ctx,
                p(json!({"session_id": "sec", "request_id": id, "verbose": true})),
            )
            .unwrap(),
        );
        for part in ["request", "response"] {
            outputs.push(
                get_body(
                    &env.ctx,
                    p(json!({"session_id": "sec", "request_id": id, "part": part})),
                )
                .unwrap(),
            );
        }
    }
    for output in &outputs {
        let t = text(output);
        assert!(!t.contains("SECRET-"), "secret leaked from the fixture: {t}");
    }
}

#[test]
fn masked_request_hides_tokens_in_target_and_initiator_urls() {
    // The core sanitizer does not cover target/initiator; the server masks them.
    let env = Env::new(true);
    let work = tempfile::tempdir().unwrap();
    let dir = work.path().join("native");
    std::fs::create_dir_all(dir.join("attachments")).unwrap();
    let from = repo("fixtures/aceite/diff/session");
    let mut session: Value =
        serde_json::from_slice(&std::fs::read(from.join("session.json")).unwrap()).unwrap();
    session["requests"][0]["target"] =
        json!({"kind": "page", "url": "https://x.invalid/p?token=SECRET-TARGET-TOKEN"});
    session["requests"][0]["attempts"][0]["initiator"] =
        json!({"kind": "script", "url": "https://x.invalid/a.js?access_token=SECRET-INIT-TOKEN"});
    std::fs::write(
        dir.join("session.json"),
        serde_json::to_vec(&session).unwrap(),
    )
    .unwrap();
    for entry in std::fs::read_dir(from.join("attachments"))
        .unwrap()
        .flatten()
    {
        std::fs::copy(
            entry.path(),
            dir.join("attachments").join(entry.file_name()),
        )
        .unwrap();
    }
    import_session(
        &env.ctx,
        p(json!({"path": dir.to_str().unwrap(), "name": "native"})),
    )
    .unwrap();
    let masked = get_request(
        &env.ctx,
        p(json!({"session_id": "native", "request_id": "har-0001"})),
    )
    .unwrap();
    assert!(masked["target"]["url"]
        .as_str()
        .unwrap()
        .starts_with("https://x.invalid/p"));
    assert!(!text(&masked).contains("SECRET-"), "{masked}");
    let open = get_request(
        &env.ctx,
        p(json!({"session_id": "native", "request_id": "har-0001", "reveal": true})),
    )
    .unwrap();
    assert!(
        text(&open).contains("SECRET-TARGET-TOKEN") && text(&open).contains("SECRET-INIT-TOKEN")
    );
}

/// Native session with `startedAt` and `requests` out of order (as in a real
/// capture, where the list is by id and not by time).
fn shuffled_native(env: &Env) {
    let work = tempfile::tempdir().unwrap();
    let dir = work.path().join("shuffled");
    let har = env.write("shuf.har", &flow_har(""));
    let imported = scrapelens_core::import_har(&std::fs::read(har).unwrap()).unwrap();
    let mut session = serde_json::to_value(&imported.bundle.session).unwrap();
    let requests = session["requests"].as_array_mut().unwrap();
    for (i, request) in requests.iter_mut().enumerate() {
        for attempt in request["attempts"].as_array_mut().unwrap() {
            attempt["startedAt"] = json!(100.0 + i as f64);
        }
    }
    requests.reverse();
    scrapelens_core::store::write_session_dir(
        &scrapelens_core::SessionBundle {
            session: serde_json::from_value(session).unwrap(),
            ..imported.bundle.clone()
        },
        &dir,
    )
    .unwrap();
    import_session(
        &env.ctx,
        p(json!({"path": dir.to_str().unwrap(), "name": "shuffled"})),
    )
    .unwrap();
}

#[test]
fn trace_uses_chronological_order_not_session_order() {
    let env = Env::new(false);
    shuffled_native(&env);
    // The list follows the session order (reversed), but exposes startedAt.
    let list = list_requests(&env.ctx, p(json!({"session_id": "shuffled"}))).unwrap();
    assert_eq!(list["items"][0]["requestId"], "har-0005");
    assert_eq!(list["items"][0]["startedAt"], 104.0);

    let trace = trace_value(
        &env.ctx,
        p(json!({"session_id": "shuffled", "cookie": "sid"})),
    )
    .unwrap();
    assert_eq!(trace["firstSetter"]["requestId"], "har-0001");
    let users: Vec<_> = trace["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["requestId"].as_str().unwrap())
        .collect();
    assert_eq!(users, ["har-0002", "har-0003"]);
    assert!(trace["users"]
        .as_array()
        .unwrap()
        .iter()
        .all(|u| u["afterFirstSetter"] == true));
    assert!(text(&trace["notes"]).contains("cronológica"));

    // The value mode requires reveal; chronological order also applies to it.
    let open_env = Env::new(true);
    shuffled_native(&open_env);
    let literal = trace_value(
        &open_env.ctx,
        p(json!({"session_id": "shuffled", "value": "TOKEN-ABCDEFGH-0123", "reveal": true})),
    )
    .unwrap();
    assert_eq!(literal["firstProducer"]["requestId"], "har-0002");
}

#[test]
fn capture_outputs_drop_the_query_entirely() {
    // In capture outputs no URL parameter is shown (there is no way to
    // know which ones are secrets): query and fragment become "?…".
    assert_eq!(
        scrapelens_mcp::live::strip_query("http://a.test/p?k=SEGREDO#frag"),
        "http://a.test/p?…"
    );
    assert_eq!(
        scrapelens_mcp::live::strip_query("http://a.test/p#frag"),
        "http://a.test/p?…"
    );
    assert_eq!(
        scrapelens_mcp::live::strip_query("http://a.test/p"),
        "http://a.test/p"
    );
}

// ---- export_session -------------------------------------------------------

fn mode_of(path: &std::path::Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn export_session_is_sanitized_by_default_and_omits_raw_artifacts() {
    let env = Env::new(false);
    let id = env.import_flow("flow", "");
    // Raw artifacts with secrets at the source: the sanitized export does not carry them.
    let src = env.dir.path().join("sessions").join(&id);
    std::fs::write(
        src.join("cdp-events.jsonl"),
        format!("{{\"method\":\"Network.requestWillBeSent\",\"params\":{{\"cookie\":\"{SID}\"}}}}\n"),
    )
    .unwrap();
    std::fs::write(
        src.join("netlog.json"),
        format!("{{\"events\":[{{\"params\":{{\"headers\":\"Bearer {TOKEN}\"}}}}]}}"),
    )
    .unwrap();

    let out = export_session(&env.ctx, p(json!({"session_id": id}))).unwrap();
    assert_eq!(out["includeSensitive"], false);
    assert!(out["totalRedactions"].as_u64().unwrap() > 0);
    let dir = PathBuf::from(out["path"].as_str().unwrap());
    assert_eq!(
        dir.file_name().unwrap().to_str().unwrap(),
        "flow-sanitized"
    );
    assert_eq!(mode_of(&dir), 0o700);
    assert_eq!(mode_of(&dir.join("session.json")), 0o600);
    let session = std::fs::read_to_string(dir.join("session.json")).unwrap();
    for secret in MASKED_SECRETS {
        assert!(!session.contains(secret), "secret {secret} in the exported session.json");
    }
    assert!(!dir.join("cdp-events.jsonl").exists(), "raw artifact must not go into the sanitized export");
    assert!(!dir.join("netlog.json").exists());
    assert_eq!(out["rawArtifactsWritten"], json!([]));
    // A second export with the same name gets a suffix.
    let out2 = export_session(&env.ctx, p(json!({"session_id": id}))).unwrap();
    assert!(out2["path"].as_str().unwrap().ends_with("flow-sanitized-2"), "{out2}");
}

#[test]
fn export_session_include_sensitive_keeps_secrets_raw_artifacts_and_private_modes() {
    let env = Env::new(false);
    let id = env.import_flow("flow", "");
    let src = env.dir.path().join("sessions").join(&id);
    std::fs::write(
        src.join("cdp-events.jsonl"),
        format!("{{\"method\":\"Network.requestWillBeSent\",\"params\":{{\"cookie\":\"{SID}\"}}}}\n"),
    )
    .unwrap();
    std::fs::write(
        src.join("netlog.json"),
        format!("{{\"events\":[{{\"params\":{{\"headers\":\"Bearer {TOKEN}\"}}}}]}}"),
    )
    .unwrap();
    std::fs::write(src.join("cdp-bodies.jsonl"), format!("{PASSWORD}\n")).unwrap();

    let out = export_session(
        &env.ctx,
        p(json!({"session_id": id, "destination": "minha-exportacao", "include_sensitive": true})),
    )
    .unwrap();
    assert_eq!(out["includeSensitive"], true);
    assert_eq!(out["totalRedactions"], 0);
    let dir = PathBuf::from(out["path"].as_str().unwrap());
    assert_eq!(dir, env.ctx.cfg.out_dir.join("minha-exportacao"));
    assert_eq!(mode_of(&dir), 0o700);
    assert_eq!(mode_of(&dir.join("session.json")), 0o600);
    let session = std::fs::read_to_string(dir.join("session.json")).unwrap();
    assert!(session.contains(SID), "the full version keeps the cookie");
    assert!(session.contains(TOKEN), "the full version keeps the token");
    let cdp = std::fs::read_to_string(dir.join("cdp-events.jsonl")).unwrap();
    assert!(cdp.contains(SID));
    let netlog = std::fs::read_to_string(dir.join("netlog.json")).unwrap();
    assert!(netlog.contains(TOKEN));
    assert_eq!(
        std::fs::read_to_string(dir.join("cdp-bodies.jsonl")).unwrap(),
        format!("{PASSWORD}\n")
    );
    assert_eq!(
        out["rawArtifactsWritten"],
        json!(["cdp-events.jsonl", "netlog.json", "cdp-bodies.jsonl"])
    );
    for name in ["cdp-events.jsonl", "netlog.json", "cdp-bodies.jsonl"] {
        assert_eq!(mode_of(&dir.join(name)), 0o600, "{name}");
    }
    // The tool's JSON never carries the values.
    let text = out.to_string();
    for secret in [SID, TOKEN, PASSWORD] {
        assert!(!text.contains(secret), "{secret} in the export_session JSON");
    }
}

#[test]
fn export_session_refuses_unsafe_destinations() {
    let env = Env::new(false);
    let id = env.import_flow("flow", "");
    let src = env.dir.path().join("sessions").join(&id);

    // Inside the source session.
    assert_eq!(
        err_code(export_session(
            &env.ctx,
            p(json!({"session_id": id, "destination": src.join("x").to_str().unwrap()}))
        )),
        "outside_allowed_dir"
    );
    // Relative destination with separators.
    assert_eq!(
        err_code(export_session(
            &env.ctx,
            p(json!({"session_id": id, "destination": "a/b"}))
        )),
        "invalid_argument"
    );
    // Existing non-empty directory.
    let busy = env.dir.path().join("busy");
    std::fs::create_dir_all(&busy).unwrap();
    std::fs::write(busy.join("x"), "1").unwrap();
    assert_eq!(
        err_code(export_session(
            &env.ctx,
            p(json!({"session_id": id, "destination": busy.to_str().unwrap()}))
        )),
        "invalid_argument"
    );
    // Symlinked ancestor.
    #[cfg(unix)]
    {
        let link = env.dir.path().join("link");
        std::os::unix::fs::symlink(&busy, &link).unwrap();
        assert_eq!(
            err_code(export_session(
                &env.ctx,
                p(json!({"session_id": id, "destination": link.join("sub").to_str().unwrap()}))
            )),
            "outside_allowed_dir"
        );
    }
    // Nonexistent session.
    assert_eq!(
        err_code(export_session(
            &env.ctx,
            p(json!({"session_id": "nao-existe"}))
        )),
        "not_found"
    );
}
