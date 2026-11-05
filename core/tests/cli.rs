//! CLI: import, inspection, export, diff and sanitization of files.

use std::process::Command;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_scrapelens-core"))
}

fn har_fixture() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/har-minimal.json")
}

#[test]
fn cli_import_inspect_export_diff_sanitize() {
    let root = tempfile::tempdir().unwrap();
    let session = root.path().join("har-session");

    let output = cli()
        .args(["import-har"])
        .arg(har_fixture())
        .args(["--out"])
        .arg(&session)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(session.join("session.json").exists());

    let inspect = cli().args(["inspect"]).arg(&session).output().unwrap();
    assert!(inspect.status.success());
    let json: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(json["session"]["schemaVersion"], 1);
    assert_eq!(json["session"]["requests"].as_array().unwrap().len(), 1);
    assert_eq!(
        json["session"]["requests"][0]["requestHeaders"]["headers"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|header| header["name"]
                .as_str()
                .is_some_and(|name| name.eq_ignore_ascii_case("x-rep")))
            .count(),
        2
    );

    let curl = cli()
        .args(["export-curl"])
        .arg(&session)
        .arg("har-0001")
        .output()
        .unwrap();
    assert!(curl.status.success());
    let text = String::from_utf8_lossy(&curl.stdout);
    assert!(text.contains("curl"));
    assert!(text.contains("--header 'x-rep: a'"));
    assert!(text.contains("--header 'X-Rep: b'"));
    assert!(text.contains("does NOT reproduce TLS"));

    let python = cli()
        .args(["export-python"])
        .arg(&session)
        .arg("har-0001")
        .output()
        .unwrap();
    assert!(python.status.success());
    assert!(String::from_utf8_lossy(&python.stdout).contains("http.client"));

    let diff = cli()
        .args(["diff"])
        .arg(&session)
        .args(["har-0001", "har-0001"])
        .output()
        .unwrap();
    assert!(diff.status.success());
    let diff: serde_json::Value = serde_json::from_slice(&diff.stdout).unwrap();
    assert_eq!(diff["requestHeaders"]["added"].as_array().unwrap().len(), 0);
    assert_eq!(
        diff["requestHeaders"]["removed"].as_array().unwrap().len(),
        0
    );
    assert_eq!(
        diff["requestHeaders"]["changed"].as_array().unwrap().len(),
        0
    );

    let sanitized = root.path().join("sanitized");
    let output = cli()
        .args(["sanitize"])
        .arg(&session)
        .arg(&sanitized)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(sanitized.join("session.json").exists());
    let sanitized_session: serde_json::Value =
        serde_json::from_slice(&std::fs::read(sanitized.join("session.json")).unwrap()).unwrap();
    assert!(sanitized_session["session"]["labels"]
        .as_array()
        .unwrap()
        .iter()
        .any(|label| label == "sanitized"));
}

#[test]
fn cli_reports_errors_without_panicking() {
    let output = cli().args(["inspect", "/does/not/exist"]).output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("error:"));
}

#[test]
fn cli_uses_help_for_usage() {
    let output = cli().arg("--help").output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("import-capture"));
}

#[test]
fn cli_assess_prints_rule_warnings() {
    let root = tempfile::tempdir().unwrap();
    let session = root.path().join("s");
    let out = cli()
        .arg("import-har")
        .arg(har_fixture())
        .arg("--out")
        .arg(&session)
        .output()
        .unwrap();
    assert!(out.status.success());
    let rules = root.path().join("rules.json");
    std::fs::write(
        &rules,
        r#"{"schema":"scrapelens.assess-rules/1","fields":[],"protectionMarkers":[],"protectionPaths":[],"blockedStatuses":[]}"#,
    )
    .unwrap();
    let out = cli()
        .arg("assess")
        .arg(&session)
        .arg("--rules")
        .arg(&rules)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("turn off all detections"));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["warnings"].as_array().unwrap().len(), 2);
    // Default rules: no warnings.
    let out = cli().arg("assess").arg(&session).output().unwrap();
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(json["warnings"].as_array().unwrap().is_empty());
}

/// P2 (docs/18): `inspect` writes to a stream with a borrowed struct; the output is BYTE FOR BYTE
/// the same as the old `json!` + `to_string_pretty` + `println!`.
#[test]
fn inspect_streaming_output_is_byte_identical_to_the_legacy_json_macro() {
    let root = tempfile::tempdir().unwrap();
    let session = root.path().join("s");
    let status = cli()
        .args(["import-har"])
        .arg(har_fixture())
        .args(["--out"])
        .arg(&session)
        .output()
        .unwrap();
    assert!(status.status.success());
    let real = cli().args(["inspect"]).arg(&session).output().unwrap();
    assert!(real.status.success());
    let imported = scrapelens_core::import_session_dir(&session).unwrap();
    let legacy = format!(
        "{}\n",
        serde_json::to_string_pretty(&serde_json::json!({
            "session": imported.bundle.session,
            "report": imported.report,
        }))
        .unwrap()
    );
    assert_eq!(String::from_utf8(real.stdout).unwrap(), legacy);
}
