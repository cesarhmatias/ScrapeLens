//! End-to-end tests of the browser tools: the real server (`fake_server`,
//! same code as the product) with a fake browser, speaking JSON-RPC over stdio and
//! answering elicitations like a real client.

mod common;

use std::path::Path;

use common::client::{fake_server, Client, Elicit};
use common::*;
use serde_json::{json, Value};

const SECRETS: [&str; 5] = [
    "SEGREDO-QUERY-1",
    "SEGREDO-STATUS-1",
    "SEGREDO-EXEMPLO-1",
    CF_SECRET,
    "sessionDir",
];

fn start(dir: &Path, policy: Elicit, extra: &[&str]) -> Client {
    let sessions = dir.join("sessions");
    let mut args = vec!["--sessions-dir", sessions.to_str().unwrap()];
    args.extend_from_slice(extra);
    let mut client = Client::start(&fake_server(), &args, policy);
    client.handshake();
    client
}

fn start_args() -> Value {
    json!({"allowed_hosts": ["site.invalid.test"], "third_party_hosts": ["cdn.invalid.test"], "headless": true})
}

fn assert_clean(value: &Value, what: &str) {
    let text = value.to_string();
    for secret in SECRETS {
        assert!(!text.contains(secret), "{what}: leaked {secret}\n{text}");
    }
}

#[test]
fn start_with_accepted_confirmation_runs_the_whole_cycle() {
    let work = tempfile::tempdir().unwrap();
    let mut client = start(work.path(), Elicit::Accept, &[]);

    // The schema has no confirmation parameter that the model could fill in.
    let listed = client.request("tools/list", json!({}));
    let start_tool = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "start_capture")
        .unwrap();
    let props = start_tool["inputSchema"]["properties"].as_object().unwrap();
    assert!(props.keys().all(|k| !k.contains("confirm")), "{props:?}");
    assert!(props.contains_key("allowed_hosts"));

    let mut args = start_args();
    args["expose_cdp"] = json!(true);
    args["start_url"] = json!("http://site.invalid.test/");
    let (is_error, started) = client.tool("start_capture", args);
    assert!(!is_error, "{started}");
    let capture_id = started["captureId"].as_str().unwrap().to_string();
    assert!(capture_id.starts_with("cap-") && !capture_id.contains('/'));
    assert_eq!(started["confirmation"], "elicited");
    assert!(
        started.get("sessionDir").is_none(),
        "paths don't leave: {started}"
    );
    assert!(started["sessionId"]
        .as_str()
        .unwrap()
        .starts_with("capture-"));
    assert_eq!(
        started["cdp"]["pageTargetId"], "T1",
        "expose_cdp delivers the address"
    );

    // The confirmation text shows everything the user needs to know.
    assert_eq!(client.elicitations.len(), 1);
    let message = &client.elicitations[0];
    for needle in [
        "site.invalid.test",
        "cdn.invalid.test",
        "YES",
        "/fake/Google Chrome",
        "headless",
        "cookies",
        "http://site.invalid.test/",
    ] {
        assert!(message.contains(needle), "missing {needle:?} in: {message}");
    }

    // Only one capture at a time; the second one doesn't even ask for confirmation.
    let (is_error, second) = client.tool("start_capture", start_args());
    assert!(is_error);
    assert_eq!(second["error"]["code"], "capture_already_running");
    assert_eq!(client.elicitations.len(), 1);

    // navigate: inside the allowlist it passes; outside it is refused before sending.
    let (is_error, nav) = client.tool(
        "navigate",
        json!({"capture_id": capture_id, "url": "http://site.invalid.test/area?token=SEGREDO-STATUS-1"}),
    );
    assert!(!is_error, "{nav}");
    assert_eq!(nav["loaded"], true);
    for bad in [
        "http://evil.test/",
        "file:///etc/passwd",
        "http://site.invalid.test@evil.test/",
    ] {
        let (is_error, denied) =
            client.tool("navigate", json!({"capture_id": capture_id, "url": bad}));
        assert!(is_error, "{bad}");
        assert_eq!(
            denied["error"]["code"], "url_not_allowed",
            "{bad}: {denied}"
        );
    }
    let (is_error, bad_wait) = client.tool(
        "navigate",
        json!({"capture_id": capture_id, "url": "http://site.invalid.test/", "wait": "forever"}),
    );
    assert!(is_error);
    assert_eq!(bad_wait["error"]["code"], "invalid_argument");

    // capture_status: no path, and with the URL masked.
    let (_, status) = client.tool("capture_status", json!({"capture_id": capture_id}));
    assert_eq!(status["recording"], true);
    assert_clean(&status, "capture_status");
    assert_eq!(status["captureId"], json!(capture_id));

    // stop_capture: writes the session, readable by the read tools.
    let (is_error, stopped) = client.tool("stop_capture", json!({"capture_id": capture_id}));
    assert!(!is_error, "{stopped}");
    assert_clean(&stopped, "stop_capture");
    assert_eq!(stopped["readable"], true);
    assert_eq!(stopped["graceful"], true);
    assert_eq!(
        stopped["allowlist"]["blockedHosts"][0]["host"],
        "challenges.invalid.test"
    );
    let session_id = stopped["sessionId"].as_str().unwrap().to_string();
    let (_, list) = client.tool("list_sessions", json!({}));
    assert!(list["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["sessionId"] == json!(session_id)));
    let (is_error, requests) = client.tool("list_requests", json!({"session_id": session_id}));
    assert!(!is_error, "{requests}");
    assert_eq!(requests["total"], 2);
    assert_clean(&requests, "list_requests of the capture");

    // The capture left the map: nothing responds to it anymore, and another one fits.
    let (is_error, gone) = client.tool("capture_status", json!({"capture_id": capture_id}));
    assert!(is_error);
    assert_eq!(gone["error"]["code"], "capture_not_found");
    let (is_error, gone) = client.tool("stop_capture", json!({"capture_id": capture_id}));
    assert!(is_error);
    assert_eq!(gone["error"]["code"], "capture_not_found");
    let (is_error, again) = client.tool("start_capture", start_args());
    assert!(!is_error, "{again}");
    assert_eq!(client.elicitations.len(), 2);

    let (ok, stderr) = client.finish();
    assert!(ok, "{stderr}");
}

#[test]
fn site_profile_reads_the_captured_session_with_redaction() {
    let work = tempfile::tempdir().unwrap();
    let mut client = start(work.path(), Elicit::Accept, &[]);
    let (_, started) = client.tool("start_capture", start_args());
    let id = started["captureId"].as_str().unwrap().to_string();
    client.tool(
        "navigate",
        json!({"capture_id": id, "url": "http://site.invalid.test/"}),
    );
    let (_, stopped) = client.tool("stop_capture", json!({"capture_id": id}));
    let session_id = stopped["sessionId"].as_str().unwrap().to_string();

    let (is_error, profile) = client.tool("site_profile", json!({"session_id": session_id}));
    assert!(!is_error, "{profile}");
    assert_eq!(profile["schema"], "scrapelens.site-profile/1");
    assert_eq!(profile["sessionId"], json!(session_id));
    let findings = profile["findings"].as_array().unwrap();
    let sig = |id: &str| findings.iter().any(|f| f["signatureId"] == id);
    assert!(sig("cf-005"), "cf-mitigated: challenge");
    assert!(sig("cf-001"), "__cf_bm");
    assert_clean(&profile, "site_profile");
    // Every evidence id resolves in get_request.
    for finding in findings {
        for evidence in finding["evidence"].as_array().unwrap() {
            let request_id = evidence["requestId"].as_str().unwrap();
            let (is_error, _) = client.tool(
                "get_request",
                json!({"session_id": session_id, "request_id": request_id}),
            );
            assert!(!is_error, "{request_id} doesn't resolve");
        }
    }
    let (is_error, missing) = client.tool(
        "site_profile",
        json!({"session_id": session_id, "target_request_id": "nope"}),
    );
    assert!(is_error);
    assert_eq!(missing["error"]["code"], "not_found");
    let (is_error, _) = client.tool("site_profile", json!({"session_id": "does-not-exist"}));
    assert!(is_error);
    client.finish();
}

#[test]
fn declined_or_unchecked_confirmation_opens_nothing() {
    for policy in [Elicit::Decline, Elicit::AcceptUnchecked] {
        let work = tempfile::tempdir().unwrap();
        // Even with the flag: an explicit refusal from the user always applies.
        let mut client = start(work.path(), policy, &["--allow-unconfirmed-capture"]);
        let (is_error, out) = client.tool("start_capture", start_args());
        assert!(is_error, "{policy:?}: {out}");
        assert_eq!(out["error"]["code"], "confirmation_denied", "{policy:?}");
        assert_eq!(client.elicitations.len(), 1);
        // The slot was released and no capture exists.
        let (_, list) = client.tool("list_sessions", json!({}));
        assert_eq!(list["total"], 0);
        let (is_error, _) = client.tool(
            "navigate",
            json!({"capture_id": "cap-0", "url": "http://site.invalid.test/"}),
        );
        assert!(is_error);
        // An invalid request is refused without bothering the user.
        let (is_error, bad) = client.tool("start_capture", json!({"allowed_hosts": []}));
        assert!(is_error);
        assert_eq!(bad["error"]["code"], "allowlist_required");
        let (is_error, bad) = client.tool("start_capture", json!({"allowed_hosts": ["*"]}));
        assert!(is_error);
        assert_eq!(bad["error"]["code"], "allowlist_too_broad");
        let (is_error, bad) = client.tool(
            "start_capture",
            json!({"allowed_hosts": ["site.invalid.test"], "start_url": "http://evil.test/"}),
        );
        assert!(is_error);
        assert_eq!(bad["error"]["code"], "start_url_not_allowed");
        assert_eq!(client.elicitations.len(), 1, "no extra elicitation");
        client.finish();
    }
}

#[test]
fn client_without_elicitation_is_refused_unless_the_operator_allows_it() {
    let work = tempfile::tempdir().unwrap();
    let mut client = start(work.path(), Elicit::Unsupported, &[]);
    let (is_error, out) = client.tool("start_capture", start_args());
    assert!(is_error);
    assert_eq!(out["error"]["code"], "confirmation_unavailable");
    assert!(out["error"]["message"]
        .as_str()
        .unwrap()
        .contains("--allow-unconfirmed-capture"));
    assert!(client.elicitations.is_empty());
    client.finish();

    let work = tempfile::tempdir().unwrap();
    let mut client = start(
        work.path(),
        Elicit::Unsupported,
        &["--allow-unconfirmed-capture"],
    );
    let (is_error, out) = client.tool("start_capture", start_args());
    assert!(!is_error, "{out}");
    assert_eq!(out["confirmation"], "unconfirmed-flag");
    assert!(client.elicitations.is_empty());
    client.finish();
}

#[test]
fn closing_stdin_stops_active_captures_gracefully() {
    let work = tempfile::tempdir().unwrap();
    let mut client = start(work.path(), Elicit::Accept, &[]);
    let (_, started) = client.tool("start_capture", start_args());
    let session_id = started["sessionId"].as_str().unwrap().to_string();
    client.close_stdin();
    let (ok, stderr) = client.finish();
    assert!(ok, "{stderr}");
    assert!(stderr.contains("1 capture(s) stopped on exit"), "{stderr}");
    assert!(
        work.path()
            .join("sessions")
            .join(&session_id)
            .join("session.json")
            .is_file(),
        "the session was written on exit"
    );
}

#[cfg(unix)]
#[test]
fn sigterm_stops_active_captures_gracefully() {
    let work = tempfile::tempdir().unwrap();
    let mut client = start(work.path(), Elicit::Accept, &[]);
    let (_, started) = client.tool("start_capture", start_args());
    let session_id = started["sessionId"].as_str().unwrap().to_string();
    let pid = client.child.id().to_string();
    let status = std::process::Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .unwrap();
    assert!(status.success());
    let exit = client.child.wait().unwrap();
    assert!(exit.success(), "{exit:?}");
    assert!(work
        .path()
        .join("sessions")
        .join(&session_id)
        .join("session.json")
        .is_file());
}
