//! Regressions from addendum 2 of the review (docs/17): R1, R4, R5, R7 (and, in the
//! following blocks, R10 and R14).

mod common;

use common::client::{fake_server, Client, Elicit};
use common::*;
use scrapelens_mcp::live::escape_display;
use scrapelens_mcp::tools::*;
use serde_json::{json, Value};

fn fake(work: &std::path::Path, policy: Elicit, extra: &[&str]) -> Client {
    let sessions = work.join("sessions");
    let mut args = vec!["--sessions-dir", sessions.to_str().unwrap()];
    args.extend_from_slice(extra);
    let mut client = Client::start_env(&fake_server(), &args, policy, &[]);
    client.handshake();
    client
}

// ---- R1: control characters don't inject fake lines into the confirmation ---------------

#[test]
fn escape_display_neutralises_control_and_bidi_characters() {
    assert_eq!(escape_display("a\nb"), "a\\u{000A}b");
    assert_eq!(escape_display("a\r\n\tb\u{1b}[31m"), "a\\u{000D}\\u{000A}\\u{0009}b\\u{001B}[31m");
    assert!(!escape_display("x\u{202E}y\u{2028}z\u{200B}").contains(['\u{202E}', '\u{2028}', '\u{200B}']));
    assert_eq!(escape_display("normal é 日本"), "normal é 日本");
}

#[test]
fn confirmation_text_never_carries_injected_lines() {
    let fake_line = "CONFIRMED-BY-USER";
    let work = tempfile::tempdir().unwrap();
    let mut client = fake(work.path(), Elicit::Accept, &[]);
    let (_, out) = client.tool(
        "start_capture",
        json!({
            "allowed_hosts": ["site.invalid.test"],
            "start_url": format!("http://site.invalid.test/a\n{fake_line}\r\nHosts permitidos: evil.test"),
            "headless": true,
        }),
    );
    for message in &client.elicitations {
        for line in message.lines() {
            assert!(
                !line.starts_with(fake_line) && !line.starts_with("Hosts permitidos: evil"),
                "linha injetada: {line:?}\n{message}"
            );
        }
    }
    // If something was opened, the capture is valid; otherwise it was refused before asking.
    let _ = out;
    client.finish();
}

// ---- R4: expose_cdp warns that the port has no authentication --------------------------------

#[test]
fn expose_cdp_confirmation_warns_about_unauthenticated_port() {
    let work = tempfile::tempdir().unwrap();
    let mut client = fake(work.path(), Elicit::Decline, &[]);
    client.tool(
        "start_capture",
        json!({"allowed_hosts": ["site.invalid.test"], "headless": true, "expose_cdp": true}),
    );
    let message = client.elicitations[0].clone();
    for needle in [
        "has no authentication",
        "any local process",
        "control the whole Chrome",
        "Runtime.evaluate",
        "not HttpOnly",
        "page data",
    ] {
        assert!(message.contains(needle), "missing {needle:?}: {message}");
    }
    client.finish();
    // Without expose_cdp, the warning doesn't appear.
    let work = tempfile::tempdir().unwrap();
    let mut client = fake(work.path(), Elicit::Decline, &[]);
    client.tool("start_capture", json!({"allowed_hosts": ["site.invalid.test"], "headless": true}));
    assert!(!client.elicitations[0].contains("has no authentication"));
    client.finish();
}

// ---- R7: multibyte values don't crash trace_value -------------------------------------

#[test]
fn trace_value_does_not_panic_on_multibyte_header_values() {
    let env = Env::new(true);
    let har = flow_har("").replace(
        "\"value\":\"text/html\"",
        "\"value\":\"éééééééééé日本語日本語\"",
    );
    let path = env.write("mb.har", &har);
    import_session(&env.ctx, p(json!({"path": path.to_str().unwrap(), "name": "mb"}))).unwrap();
    for value in [
        "éééééééééé日本語日本語".to_string(),
        "日本語日本語日本語日本語日本語日本語".to_string(),
        format!("Bearer {TOKEN}"),
        "Béarer-é-é-é-é-é-é-é".to_string(),
    ] {
        let out = trace_value(&env.ctx, p(json!({"session_id": "mb", "value": value, "reveal": true}))).unwrap();
        assert_eq!(out["mode"], "value");
    }
    let _: Value = Value::Null;
}

// ---- R14: scrub_output covers all forms, in every string ----------------------------

#[test]
fn scrub_output_masks_fragment_matrix_userinfo_bare_and_nested_forms() {
    let mut value = json!({
        "a": "GET /p?x=1#access_token=SEG-FRAG",
        "b": "https://admin:SEG-USERINFO@x.invalid/p",
        "c": "/h;jsessionid=SEG-MATRIX/y",
        "d": "5; token=SEG-BARE",
        "e": "/cb?redirect_uri=https%3A%2F%2Fa.invalid%2Fx%3Ftoken%3DSEG-NESTED",
        "f": ["text jwt=SEG-JWT end", {"g": "senha=SEG-SENHA&page=2"}],
        "h": "ok no secret: page=2",
    });
    scrub_output(&mut value);
    let out = value.to_string();
    for secret in ["SEG-FRAG", "SEG-USERINFO", "SEG-MATRIX", "SEG-BARE", "SEG-NESTED", "SEG-JWT", "SEG-SENHA"] {
        assert!(!out.contains(secret), "{secret} em {out}");
    }
    assert_eq!(value["h"], "ok no secret: page=2");
}

// ---- R10: SIGTERM during stop doesn't lose session.json ------------------------------

#[test]
fn sigterm_during_stop_still_writes_the_session() {
    let work = tempfile::tempdir().unwrap();
    let sessions = work.path().join("sessions");
    let mut client = Client::start_env(
        &fake_server(),
        &["--sessions-dir", sessions.to_str().unwrap()],
        Elicit::Accept,
        &[("FAKE_STOP_DELAY_MS", "1500")],
    );
    client.handshake();
    let (_, started) = client.tool(
        "start_capture",
        json!({"allowed_hosts": ["site.invalid.test"], "headless": true}),
    );
    let id = started["captureId"].as_str().unwrap().to_string();
    client.call_nowait("stop_capture", json!({"capture_id": id}));
    std::thread::sleep(std::time::Duration::from_millis(300)); // the stop is in progress
    let status = std::process::Command::new("kill")
        .args(["-TERM", &client.child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let exit = client.child.wait().unwrap();
    assert!(exit.success(), "{exit:?}");
    let dirs: Vec<_> = std::fs::read_dir(&sessions)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|path| path.file_name().is_some_and(|n| n.to_string_lossy().starts_with("capture-")))
        .collect();
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    assert!(
        dirs[0].join("session.json").is_file(),
        "the stop in progress finished and wrote before exiting"
    );
}

// ---- A3-B: error messages and invisible characters -------------------------------------

#[test]
fn error_messages_escape_bidi_and_invisible_characters() {
    let env = Env::new(true);
    let hostile = "sess\u{202E}ao\n\u{200B}x\u{061C}y\u{2800}z\u{E0041}";
    let error = open_failure(&env, hostile);
    let shown = error.to_value().to_string();
    for ch in ['\u{202E}', '\u{200B}', '\u{061C}', '\u{2800}', '\u{E0041}'] {
        assert!(!shown.contains(ch), "{ch:?} em {shown}");
    }
    assert!(!shown.contains("\\n\\u200b"), "{shown}");
    assert_eq!(escape_display("A\u{0301}"), "A\\u{0301}");
    for ch in ['\u{FE0F}', '\u{FFF9}', '\u{FFFC}', '\u{206F}', '\u{3164}'] {
        assert!(!escape_display(&format!("a{ch}b")).contains(ch), "{ch:?}");
    }
}

#[test]
fn escape_display_uses_unicode_categories_not_a_range_list() {
    // Mn, Me, Cf, Zs (except the plain space), Co, Cn, controls and selectors E0100–E01EF.
    for ch in [
        '\u{05B4}', '\u{064B}', '\u{0489}', '\u{0600}', '\u{070F}', '\u{115F}', '\u{1160}',
        '\u{1680}', '\u{17B4}', '\u{FFA0}', '\u{1D173}', '\u{13430}', '\u{1BCA0}', '\u{E0100}',
        '\u{E01EF}', '\u{E000}', '\u{F8FF}', '\u{0378}', '\u{10FFFF}', '\u{2007}', '\u{202F}',
        '\u{0085}', '\u{007F}', '\u{FE0F}',
    ] {
        let shown = escape_display(&format!("a{ch}b"));
        assert!(!shown.contains(ch), "U+{:04X} passou cru", ch as u32);
        assert!(shown.starts_with("a\\u{"), "{shown}");
    }
    // Plain text, accented (composed letters), CJK, emoji and the plain space are kept.
    assert_eq!(escape_display("ação – 日本語 😀 a b"), "ação – 日本語 😀 a b");
}

fn open_failure(env: &Env, handle: &str) -> scrapelens_mcp::error::ToolError {
    list_requests(&env.ctx, p(json!({"session_id": handle}))).unwrap_err()
}
