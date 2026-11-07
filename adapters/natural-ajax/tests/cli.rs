//! Wrapper CLI: `origins`, `chain`, `compare` and `adapter-roundtrip` with the
//! adapter registered only with `--adapter natural-ajax`.

use std::path::{Path, PathBuf};
use std::process::Command;

fn core_binary() -> Option<PathBuf> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/release/scrapelens-core");
    path.is_file().then_some(path)
}

fn wrapper(core: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_natural-core"));
    cmd.env("SCRAPELENS_CORE_BIN", core);
    cmd
}

#[test]
fn flow_commands_show_internal_names_only_with_the_adapter() {
    let Some(core) = core_binary() else { return };
    let dir = tempfile::tempdir().unwrap();
    let session = dir.path().join("s");
    let har = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/detran-pb-real-shape/real-shape-1round.har");
    assert!(wrapper(&core)
        .arg("import-har")
        .arg(&har)
        .arg("--out")
        .arg(&session)
        .output()
        .unwrap()
        .status
        .success());
    // Last POST to the Connector.
    let inspect = wrapper(&core)
        .arg("inspect")
        .arg(&session)
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
    let id = json["session"]["requests"]
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find(|r| r["method"] == "POST" && r["url"].as_str().unwrap_or("").contains("Connector"))
        .and_then(|r| r["id"].as_str())
        .unwrap()
        .to_string();
    let names = |extra: &[&str]| -> Vec<String> {
        let out = wrapper(&core)
            .args(["origins"])
            .arg(&session)
            .arg(&id)
            .args(extra)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let j: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        j["values"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v["field"].as_str())
            .filter(|f| f.starts_with("XML."))
            .map(str::to_string)
            .collect()
    };
    let with = names(&["--adapter", "natural-ajax"]);
    assert!(with.iter().any(|n| n == "XML.delta"), "{with:?}");
    assert!(with.iter().any(|n| n == "XML.p.v_placa"), "{with:?}");
    assert!(!names(&["--sem-adaptador"]).iter().any(|n| n == "XML.delta"));
    // chain and compare accept the flag and reject unknown ids.
    for args in [
        vec![
            "chain".to_string(),
            session.display().to_string(),
            id.clone(),
        ],
        vec![
            "compare".to_string(),
            session.display().to_string(),
            session.display().to_string(),
        ],
    ] {
        let ok = wrapper(&core)
            .args(&args)
            .args(["--adapter", "natural-ajax"])
            .output()
            .unwrap();
        assert!(
            ok.status.success(),
            "{}",
            String::from_utf8_lossy(&ok.stderr)
        );
        let bad = wrapper(&core)
            .args(&args)
            .args(["--adapter", "outro"])
            .output()
            .unwrap();
        assert!(!bad.status.success());
    }
    // round-trip: JSON with fields/divergences, no values.
    let rt = wrapper(&core)
        .arg("adapter-roundtrip")
        .arg(&session)
        .output()
        .unwrap();
    let j: serde_json::Value = serde_json::from_slice(&rt.stdout).unwrap();
    assert_eq!(j["divergences"], 0);
    assert!(j["fields"].as_u64().unwrap() > 0);
    assert!(j["divergenceKinds"].is_object());
}

#[test]
fn wrapper_never_recurses_when_core_bin_points_to_itself() {
    let Some(core) = core_binary() else { return };
    let me = env!("CARGO_BIN_EXE_natural-core");
    let out = Command::new(me)
        .env("SCRAPELENS_CORE_BIN", me)
        .arg("--help")
        .output()
        .unwrap();
    // Falls through to the neighbouring core (or a clean error), never process recursion.
    let _ = core;
    assert!(out.status.code().is_some());
}

#[test]
fn wrapper_refuses_a_second_re_execution_level() {
    let me = env!("CARGO_BIN_EXE_natural-core");
    let out = Command::new(me)
        .env("NATURAL_CORE_DEPTH", "1")
        .arg("inspect")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("recursion"));
}

#[test]
fn timeline_subcommand_accepts_the_adapter_flag() {
    let Some(core) = core_binary() else { return };
    let dir = tempfile::tempdir().unwrap();
    let session = dir.path().join("s");
    let har = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/detran-pb-real-shape/real-shape-1round.har");
    assert!(wrapper(&core)
        .arg("import-har")
        .arg(&har)
        .arg("--out")
        .arg(&session)
        .output()
        .unwrap()
        .status
        .success());
    let with = wrapper(&core)
        .arg("timeline")
        .arg(&session)
        .args(["--adapter", "natural-ajax"])
        .output()
        .unwrap();
    assert!(
        with.status.success(),
        "{}",
        String::from_utf8_lossy(&with.stderr)
    );
    let text = String::from_utf8_lossy(&with.stdout);
    assert!(text.contains(" @ "), "`event @ page` labels missing");
    let bad = wrapper(&core)
        .arg("timeline")
        .arg(&session)
        .args(["--adapter", "outro"])
        .output()
        .unwrap();
    assert!(!bad.status.success());
}
