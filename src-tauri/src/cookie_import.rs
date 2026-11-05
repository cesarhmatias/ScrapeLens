//! Cookie import result of a live capture, read from the `Capture.cookiesImported` event
//! that the capture writes into `cdp-events.jsonl` (counts and the reason only, never
//! cookie values). Sessions written before the undecryptable fields existed carry no
//! such counts and produce no report, so they show exactly what they showed before.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde::Serialize;
use serde_json::Value;

/// The event is written right before the first navigation, after the setup events, so it
/// is among the first lines. The scan is bounded so opening a large session stays cheap.
const MAX_SCANNED_LINES: usize = 2000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CookieImportReport {
    /// `initialCookies` when the cookies were given in code; otherwise the browser label.
    pub source: String,
    pub domain: String,
    pub imported_count: u64,
    pub skipped_count: u64,
    pub undecryptable_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub undecryptable_reason: Option<String>,
}

/// Parses one event line. `None` when it is another event, or when it predates the fields.
pub fn report_from_event_line(line: &str) -> Option<CookieImportReport> {
    let value: Value = serde_json::from_str(line).ok()?;
    if value.get("method")?.as_str()? != "Capture.cookiesImported" {
        return None;
    }
    let params = value.get("params")?;
    // Without the undecryptable count the event is from an older capture: no report.
    let undecryptable_count = params.get("undecryptableCount")?.as_u64()?;
    Some(CookieImportReport {
        source: params.get("source")?.as_str()?.to_string(),
        domain: params.get("domain").and_then(Value::as_str).unwrap_or_default().to_string(),
        imported_count: params.get("importedCount").and_then(Value::as_u64).unwrap_or(0),
        skipped_count: params.get("skippedCount").and_then(Value::as_u64).unwrap_or(0),
        undecryptable_count,
        undecryptable_reason: params
            .get("undecryptableReason")
            .and_then(Value::as_str)
            .filter(|reason| !reason.is_empty())
            .map(str::to_string),
    })
}

/// Reads the import report of a session folder, if its capture recorded one.
pub fn read_report(session_dir: &Path) -> Option<CookieImportReport> {
    let file = File::open(session_dir.join("cdp-events.jsonl")).ok()?;
    BufReader::new(file)
        .lines()
        .take(MAX_SCANNED_LINES)
        .map_while(Result::ok)
        .find_map(|line| report_from_event_line(&line))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("sl-cookie-report-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const LOCKED: &str = r#"{"sessionId":"s","method":"Capture.cookiesImported","params":{"source":"Google Chrome — Default","domain":"example.test","importedCount":1,"skippedCount":0,"undecryptableCount":1,"undecryptableReason":"v11 cookie of Chromium: keyring is locked or has no entry for this browser: unlock it and try again (1)"}}"#;

    #[test]
    fn undecryptable_cookies_are_reported_with_count_and_reason() {
        let report = report_from_event_line(LOCKED).expect("report");
        assert_eq!(report.imported_count, 1);
        assert_eq!(report.undecryptable_count, 1);
        assert_eq!(report.domain, "example.test");
        assert!(report.undecryptable_reason.unwrap().contains("keyring is locked"));
    }

    #[test]
    fn zero_imported_from_a_browser_is_a_report_with_no_error() {
        let line = r#"{"method":"Capture.cookiesImported","params":{"source":"Brave — Default","domain":"example.test","importedCount":0,"skippedCount":3,"undecryptableCount":0}}"#;
        let report = report_from_event_line(line).expect("report");
        assert_eq!((report.imported_count, report.undecryptable_count), (0, 0));
        assert_eq!(report.undecryptable_reason, None);
    }

    #[test]
    fn events_from_older_captures_and_other_events_produce_no_report() {
        let old = r#"{"method":"Capture.cookiesImported","params":{"source":"Google Chrome — Default","domain":"x.test","importedCount":2,"skippedCount":0}}"#;
        assert!(report_from_event_line(old).is_none(), "no undecryptable field: nothing changes");
        assert!(report_from_event_line(r#"{"method":"Network.requestWillBeSent","params":{}}"#).is_none());
        assert!(report_from_event_line("not json").is_none());
    }

    #[test]
    fn reads_the_event_from_the_session_folder_and_ignores_missing_files() {
        let dir = temp_dir("read");
        assert!(read_report(&dir).is_none(), "no events file");
        let events = format!("{{\"method\":\"Network.x\",\"params\":{{}}}}\n{LOCKED}\n");
        std::fs::write(dir.join("cdp-events.jsonl"), events).unwrap();
        assert_eq!(read_report(&dir).unwrap().undecryptable_count, 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
