//! Regressions from the MCP security review (docs/17): substring oracle,
//! confirmation, symlink spill, shutdown while the capture is starting.

mod common;

use std::os::unix::fs::PermissionsExt;

use common::client::{fake_server, Client, Elicit};
use common::*;
use scrapelens_mcp::tools::*;
use serde_json::{json, Value};

// ---- C1: trace_value is not a substring oracle -----------------------------------

fn total(out: &Value) -> u64 {
    out["producersTotal"].as_u64().unwrap() + out["consumersTotal"].as_u64().unwrap()
}

#[test]
fn trace_value_value_mode_requires_reveal_so_it_is_no_oracle() {
    let env = Env::new(true);
    env.import_flow("flow", "");
    // Without reveal the `value` mode ALWAYS refuses, whatever the value: finding or
    // not finding would reveal masked content (whole, a piece, a known structure).
    let basic = format!("Basic {}", base64_of("admin:4821"));
    for value in [
        TOKEN.to_string(),
        TOKEN[..10].to_string(),
        format!("Bearer {TOKEN}"),
        SID.to_string(),
        basic,
        "value-that-does-not-exist-anywhere".to_string(),
        "a".to_string(),
    ] {
        for reveal in [None, Some(false)] {
            let mut args = json!({"session_id": "flow", "value": value});
            if let Some(reveal) = reveal {
                args["reveal"] = json!(reveal);
            }
            let error = trace_value(&env.ctx, p(args)).unwrap_err();
            assert_eq!(error.code, "reveal_required", "{value}");
            assert!(!error.message.contains(&value) || value.len() < 3);
        }
    }
    // Reimporting the session changes nothing: there is no counter to reset nor response to compare.
    for n in 0..5 {
        env.import_flow(&format!("copy-{n}"), "");
        let error = trace_value(
            &env.ctx,
            p(json!({"session_id": format!("copy-{n}"), "value": TOKEN})),
        )
        .unwrap_err();
        assert_eq!(error.code, "reveal_required");
    }
    // With reveal (and --allow-reveal) the mode exists and finds pieces.
    let whole = trace_value(
        &env.ctx,
        p(json!({"session_id": "flow", "value": TOKEN, "reveal": true})),
    )
    .unwrap();
    assert_eq!(whole["firstProducer"]["requestId"], "har-0002");
    assert!(total(&whole) > 0);
    let part = trace_value(
        &env.ctx,
        p(json!({"session_id": "flow", "value": &TOKEN[..10], "reveal": true})),
    )
    .unwrap();
    assert!(total(&part) > 0);
    // Server without --allow-reveal: the mode is closed.
    let closed = Env::new(false);
    closed.import_flow("flow", "");
    let error = trace_value(
        &closed.ctx,
        p(json!({"session_id": "flow", "value": TOKEN, "reveal": true})),
    )
    .unwrap_err();
    assert_eq!(error.code, "reveal_disabled");
}

#[test]
fn cookie_and_request_modes_expose_nothing_derived_from_values_without_reveal() {
    let env = Env::new(true);
    env.import_flow("flow", "");
    let masked = trace_value(&env.ctx, p(json!({"session_id": "flow", "cookie": "sid"}))).unwrap();
    let out = text(&masked);
    assert!(!out.contains("valueLength"), "{out}");
    let by_request = trace_value(
        &env.ctx,
        p(json!({"session_id": "flow", "request_id": "har-0003"})),
    )
    .unwrap();
    assert!(!text(&by_request).contains("valueLength"));
    // Request_id mode: each value comes out without length, offset or range size.
    for item in by_request["values"].as_array().unwrap() {
        let map = item.as_object().unwrap();
        for key in ["length", "offset"] {
            assert!(!map.contains_key(key), "{key} em {item}");
        }
        for key in ["evidences", "partialComposition"] {
            for entry in map.get(key).and_then(Value::as_array).into_iter().flatten() {
                for field in ["consumedOffset", "consumedLength", "start", "length"] {
                    assert!(entry.get(field).is_none(), "{field} em {entry}");
                }
            }
        }
    }
    let revealed = trace_value(
        &env.ctx,
        p(json!({"session_id": "flow", "cookie": "sid", "reveal": true})),
    )
    .unwrap();
    assert!(text(&revealed).contains("valueLength"));
    let open = trace_value(
        &env.ctx,
        p(json!({"session_id": "flow", "request_id": "har-0003", "reveal": true})),
    )
    .unwrap();
    assert!(open["values"][0].get("length").is_some(), "with reveal the length comes back");
}

#[test]
fn other_tools_do_not_answer_about_redacted_content() {
    let env = Env::new(true);
    env.import_flow("flow", "");
    env.import_flow("flow2", "-v2");
    // search_bodies: a piece of a secret (even the whole one) finds nothing without reveal.
    for query in [
        &TOKEN[..8],
        TOKEN,
        &SID[..10],
        SID,
        PASSWORD,
        "Bearer",
        REFRESH,
    ] {
        let out =
            search_bodies(&env.ctx, p(json!({"session_id": "flow", "query": query}))).unwrap();
        let matches = out["matches"].as_array().unwrap();
        for m in matches {
            // may only find text that is not redacted (e.g. the word "Bearer" in the scheme)
            assert!(
                !m["snippet"]
                    .as_str()
                    .unwrap()
                    .contains(&query[..query.len().min(8)])
                    || query == "Bearer",
                "{query}: {m}"
            );
        }
        if query != "Bearer" {
            assert_eq!(out["total"], 0, "{query}");
        }
    }
    // retained body (HTML) is not searchable without reveal
    assert_eq!(
        search_bodies(
            &env.ctx,
            p(json!({"session_id": "flow", "query": &CSRF[..10]}))
        )
        .unwrap()["total"],
        0
    );
    // list_requests(text) only sees the already redacted URL: the value of the `key`
    // parameter (sensitive) is not searchable, the visible part of the URL is.
    let hidden =
        list_requests(&env.ctx, p(json!({"session_id": "flow", "text": "key=1"}))).unwrap();
    assert_eq!(hidden["total"], 0);
    let visible = list_requests(
        &env.ctx,
        p(json!({"session_id": "flow", "text": "data?key="})),
    )
    .unwrap();
    assert_eq!(visible["total"], 1);
    // diff: different redacted values appear equal; no raw data
    let diff = diff_requests_tool(
        &env.ctx,
        p(json!({"session_id": "flow", "request_a": "har-0003", "request_b": "har-0003", "other_session_id": "flow2"})),
    )
    .unwrap();
    assert_no_secrets(&diff, "diff_requests");
    assert!(
        !text(&diff).contains("v2"),
        "token difference must not appear: {diff}"
    );
}

// ---- A1: confirmation ----------------------------------------------------------------

#[test]
fn confirmation_from_denies_everything_except_an_explicit_true() {
    use rmcp::service::{ElicitationError, ServiceError};
    use scrapelens_mcp::live::{decide, ConfirmStart, Confirmation};
    use scrapelens_mcp::server::confirmation_from;
    let parse_error = || ElicitationError::ParseError {
        error: serde_json::from_str::<bool>("\"x\"").unwrap_err(),
        data: json!({"confirmo": "true"}),
    };
    let rpc_error = || {
        ElicitationError::Service(ServiceError::McpError(rmcp::ErrorData::internal_error(
            "User rejected",
            None,
        )))
    };
    let timeout = || {
        ElicitationError::Service(ServiceError::Timeout {
            timeout: std::time::Duration::from_secs(300),
        })
    };
    let cases: Vec<(&str, Result<Option<ConfirmStart>, ElicitationError>)> = vec![
        (
            "checkbox unchecked",
            Ok(Some(ConfirmStart { confirmo: false })),
        ),
        ("no content", Ok(None)),
        ("NoContent", Err(ElicitationError::NoContent)),
        ("declined", Err(ElicitationError::UserDeclined)),
        ("cancelled", Err(ElicitationError::UserCancelled)),
        ("JSON-RPC error", Err(rpc_error())),
        ("malformed", Err(parse_error())),
        ("timeout", Err(timeout())),
        (
            "connection dropped",
            Err(ElicitationError::Service(ServiceError::TransportClosed)),
        ),
    ];
    for (name, result) in cases {
        let confirmation = confirmation_from(result);
        for flag in [false, true] {
            let decided = decide(&confirmation, flag);
            assert_eq!(
                decided.unwrap_err().code,
                "confirmation_denied",
                "{name} flag={flag}: {confirmation:?}"
            );
        }
    }
    assert_eq!(
        confirmation_from(Ok(Some(ConfirmStart { confirmo: true }))),
        Confirmation::Accepted
    );
    // Only "the client did not declare elicitation" depends on the flag.
    let unsupported = confirmation_from(Err(ElicitationError::CapabilityNotSupported));
    assert_eq!(
        decide(&unsupported, false).unwrap_err().code,
        "confirmation_unavailable"
    );
    assert_eq!(decide(&unsupported, true).unwrap(), "unconfirmed-flag");
}

fn fake(work: &std::path::Path, policy: Elicit, extra: &[&str], env: &[(&str, &str)]) -> Client {
    let sessions = work.join("sessions");
    let mut args = vec!["--sessions-dir", sessions.to_str().unwrap()];
    args.extend_from_slice(extra);
    let mut client = Client::start_env(&fake_server(), &args, policy, env);
    client.handshake();
    client
}

fn start_args() -> Value {
    json!({"allowed_hosts": ["site.invalid.test"], "headless": true})
}

#[test]
fn malformed_or_failed_confirmation_never_opens_even_with_the_flag() {
    for policy in [
        Elicit::RpcError,
        Elicit::AcceptEmpty,
        Elicit::AcceptString,
        Elicit::AcceptNumber,
        Elicit::Decline,
        Elicit::AcceptUnchecked,
    ] {
        let work = tempfile::tempdir().unwrap();
        let mut client = fake(work.path(), policy, &["--allow-unconfirmed-capture"], &[]);
        let (is_error, out) = client.tool("start_capture", start_args());
        assert!(is_error, "{policy:?}: {out}");
        assert_eq!(
            out["error"]["code"], "confirmation_denied",
            "{policy:?}: {out}"
        );
        assert!(out.get("captureId").is_none());
        // The slot came back and no capture exists.
        let (_, list) = client.tool("list_sessions", json!({}));
        assert_eq!(list["total"], 0);
        client.finish();
    }
}

#[test]
fn confirmation_text_warns_that_the_port_is_only_enforced_on_navigate() {
    let work = tempfile::tempdir().unwrap();
    let mut client = fake(work.path(), Elicit::Accept, &[], &[]);
    client.tool("start_capture", start_args());
    let message = &client.elicitations[0];
    for needle in [
        "enforces the HOST on all ports",
        "PORT is only enforced",
        "navigate",
        "ANY port",
        "localhost",
    ] {
        assert!(message.contains(needle), "faltou {needle:?}: {message}");
    }
    client.finish();
}

// ---- M4: shutdown during start --------------------------------------------------

fn session_dirs(work: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(work.join("sessions"))
        .map(|d| {
            d.flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .starts_with("capture-")
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn eof_during_start_stops_the_browser_that_is_coming_up() {
    let work = tempfile::tempdir().unwrap();
    let mut client = fake(
        work.path(),
        Elicit::Accept,
        &[],
        &[("FAKE_START_DELAY_MS", "1500")],
    );
    client.call_nowait("start_capture", start_args());
    client.answer_next_elicitation();
    std::thread::sleep(std::time::Duration::from_millis(300)); // "Chrome" is still starting up
    client.close_stdin();
    let (ok, stderr) = client.finish();
    assert!(ok, "{stderr}");
    let dirs = session_dirs(work.path());
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    assert!(
        dirs[0].join("session.json").is_file(),
        "the capture that was starting was stopped and recorded"
    );
}

#[test]
fn sigterm_during_start_stops_the_browser_that_is_coming_up() {
    let work = tempfile::tempdir().unwrap();
    let mut client = fake(
        work.path(),
        Elicit::Accept,
        &[],
        &[("FAKE_START_DELAY_MS", "1500")],
    );
    client.call_nowait("start_capture", start_args());
    client.answer_next_elicitation();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let status = std::process::Command::new("kill")
        .args(["-TERM", &client.child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let exit = client.child.wait().unwrap();
    assert!(exit.success(), "{exit:?}");
    let dirs = session_dirs(work.path());
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    assert!(dirs[0].join("session.json").is_file());
}

// ---- P1: stop warnings without query/fragment/matrix ------------------------------------

#[test]
fn stop_capture_warnings_carry_no_url_parameters() {
    let work = tempfile::tempdir().unwrap();
    let mut client = fake(work.path(), Elicit::Accept, &[], &[]);
    let (_, started) = client.tool("start_capture", start_args());
    let (_, stopped) = client.tool("stop_capture", json!({"capture_id": started["captureId"]}));
    let warnings = text(&stopped["warnings"]);
    assert!(
        warnings.contains("site.invalid.test:9/p"),
        "the warning is still readable: {warnings}"
    );
    for secret in ["SEGREDO-VIOL", "SEGREDO-VIOLQ", "SEGREDO-VIOLF"] {
        assert!(
            !text(&stopped).contains(secret),
            "{secret} leaked: {stopped}"
        );
    }
    client.finish();
}

// ---- M5/B1/B2/B4: get_body spill -----------------------------------------------------

fn big_body_env() -> (Env, std::path::PathBuf) {
    let env = Env::new(true);
    env.import_flow("flow", "");
    let out = get_body(
        &env.ctx,
        p(json!({"session_id": "flow", "request_id": "har-0003", "reveal": true})),
    )
    .unwrap();
    let path = std::path::PathBuf::from(out["path"].as_str().unwrap());
    (env, path)
}

#[test]
fn spill_refuses_a_planted_symlink_and_writes_0600() {
    let (env, path) = big_body_env();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // Plants a symlink at the final name and another at what would be a predictable temporary.
    let outside = env.dir.path().join("outside.txt");
    std::fs::write(&outside, "ORIGINAL").unwrap();
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&outside, &path).unwrap();
    for planted in [".tmp-1", &format!(".tmp-{}", std::process::id())] {
        let _ = std::os::unix::fs::symlink(&outside, path.parent().unwrap().join(planted));
    }
    let again = get_body(
        &env.ctx,
        p(json!({"session_id": "flow", "request_id": "har-0003", "reveal": true})),
    )
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(&outside).unwrap(),
        "ORIGINAL",
        "the symlink target must not be written"
    );
    let new_path = std::path::PathBuf::from(again["path"].as_str().unwrap());
    assert_eq!(new_path, path);
    let meta = std::fs::symlink_metadata(&new_path).unwrap();
    assert!(
        meta.file_type().is_file(),
        "the link was replaced by a regular file"
    );
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert_eq!(meta.len(), 100_000);
}

#[test]
fn spill_refuses_symlinked_directories_without_touching_the_target() {
    let env = Env::new(true);
    env.import_flow("flow", "");
    let outside = env.dir.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755)).unwrap();
    // `bodies` is a symlink pointing outside
    std::os::unix::fs::symlink(&outside, env.dir.path().join("out").join("bodies")).unwrap();
    let err = get_body(
        &env.ctx,
        p(json!({"session_id": "flow", "request_id": "har-0003", "reveal": true})),
    )
    .unwrap_err();
    assert_eq!(err.code, "outside_allowed_dir");
    assert_eq!(
        std::fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
        0o755,
        "the target did not receive chmod"
    );
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
}

#[test]
fn concurrent_spills_do_not_mix_bytes_and_distinct_handles_do_not_collide() {
    let env = std::sync::Arc::new(Env::new(true));
    env.import_flow("x.y", "");
    env.import_flow("x-y", "-v2");
    let mut threads = Vec::new();
    for t in 0..8 {
        let env = env.clone();
        threads.push(std::thread::spawn(move || {
            let mut paths = Vec::new();
            for i in 0..10 {
                let handle = if (t + i) % 2 == 0 { "x.y" } else { "x-y" };
                let out = get_body(&env.ctx, p(json!({"session_id": handle, "request_id": "har-0003", "reveal": true, "offset": (i % 3) * 7, "length": 40_000}))).unwrap();
                paths.push((handle, i % 3, out["path"].as_str().unwrap().to_string()));
            }
            paths
        }));
    }
    let mut all = Vec::new();
    for t in threads {
        all.extend(t.join().unwrap());
    }
    for (_, _, path) in &all {
        assert_eq!(std::fs::read(path).unwrap().len(), 40_000, "{path}");
    }
    let dir = |h: &str| {
        all.iter()
            .find(|(x, _, _)| *x == h)
            .map(|(_, _, p)| std::path::Path::new(p).parent().unwrap().to_path_buf())
            .unwrap()
    };
    assert_ne!(
        dir("x.y"),
        dir("x-y"),
        "distinct handles do not share a spill directory"
    );
}

// ---- binary_path: only stable Chrome (uses the validator from capture/) ---------------------

#[test]
fn binary_path_that_is_not_chrome_is_refused_before_asking_the_user() {
    let work = tempfile::tempdir().unwrap();
    let sessions = work.path().join("sessions");
    let program = std::path::PathBuf::from(env!("CARGO_BIN_EXE_scrapelens-mcp"));
    let mut client = Client::start(
        &program,
        &["--sessions-dir", sessions.to_str().unwrap()],
        Elicit::Accept,
    );
    client.handshake();
    for bad in ["/bin/echo", "/usr/bin/true", "/does/not/exist"] {
        let (is_error, out) = client.tool(
            "start_capture",
            json!({"allowed_hosts": ["site.invalid.test"], "binary_path": bad}),
        );
        assert!(is_error, "{bad}: {out}");
        assert_eq!(out["error"]["code"], "browser_invalid", "{bad}: {out}");
    }
    assert!(
        client.elicitations.is_empty(),
        "nothing was asked of the user"
    );
    client.finish();
}

// ---- cancellation and late acceptance ------------------------------------------------------

#[test]
fn cancelling_then_accepting_late_opens_nothing_and_frees_the_slot() {
    let work = tempfile::tempdir().unwrap();
    let mut client = fake(work.path(), Elicit::Accept, &[], &[]);
    let id = client.call_nowait("start_capture", start_args());
    let late = client.take_elicitation();
    client.cancel(id);
    std::thread::sleep(std::time::Duration::from_millis(400));
    client.accept_elicitation(&late); // late acceptance: ignored
    std::thread::sleep(std::time::Duration::from_millis(400));
    assert!(
        session_dirs(work.path()).is_empty(),
        "nothing was opened: {:?}",
        session_dirs(work.path())
    );
    // The slot is free: a new request asks again and opens.
    let (is_error, started) = client.tool("start_capture", start_args());
    assert!(!is_error, "{started}");
    assert_eq!(client.elicitations.len(), 2);
    assert_eq!(session_dirs(work.path()).len(), 1);
    let (ok, stderr) = client.finish();
    assert!(ok, "{stderr}");
}

#[test]
fn cancelling_while_the_browser_comes_up_stops_it_and_frees_the_slot() {
    let work = tempfile::tempdir().unwrap();
    let mut client = fake(
        work.path(),
        Elicit::Accept,
        &[],
        &[("FAKE_START_DELAY_MS", "1200")],
    );
    let id = client.call_nowait("start_capture", start_args());
    client.answer_next_elicitation(); // confirmed; "Chrome" is slow to start
    std::thread::sleep(std::time::Duration::from_millis(300));
    client.cancel(id);
    // When the browser is ready, the capture is stopped and recorded; the slot comes back.
    let mut started = None;
    for _ in 0..40 {
        let (is_error, out) = client.tool("start_capture", start_args());
        if !is_error {
            started = Some(out);
            break;
        }
        assert_eq!(out["error"]["code"], "capture_already_running", "{out}");
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    assert!(started.is_some(), "the slot never came back");
    let dirs = session_dirs(work.path());
    assert_eq!(dirs.len(), 2, "{dirs:?}");
    let stopped: Vec<_> = dirs
        .iter()
        .filter(|d| d.join("session.json").is_file())
        .collect();
    assert_eq!(
        stopped.len(),
        1,
        "the first capture was stopped and recorded: {dirs:?}"
    );
    client.finish();
}
