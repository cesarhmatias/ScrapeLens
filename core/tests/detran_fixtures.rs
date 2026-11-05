//! DETRAN-PB reference case (`fixtures/detran-pb/`).
//!
//! Synthetic fixtures with the shape of the real case: 13 requests, 8 POSTs to
//! the Connector, two queries with the same URL/method differentiated only by the
//! body. The NetLog `time` in them is in milliseconds, as in real Chrome; the unit
//! is calibrated by the CDP clock.

use std::path::PathBuf;

use scrapelens_core::correlate::CorrelationOptions;
use scrapelens_core::model::MatchState;
use scrapelens_core::parse::import_capture;

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/detran-pb")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn detran_fixtures_correlate_all_13_without_false_ambiguity() {
    let imported = import_capture(
        &fixture("detran-pb.cdp.jsonl"),
        &fixture("detran-pb.netlog.json"),
        CorrelationOptions::default(),
    )
    .expect("import of the DETRAN-PB capture");

    let session = &imported.bundle.session;
    assert_eq!(session.requests.len(), 13);
    assert_eq!(
        session
            .requests
            .iter()
            .filter(|request| request.match_state == MatchState::Matched)
            .count(),
        13,
        "all 13 requests must match the NetLog"
    );
    assert_eq!(
        session
            .requests
            .iter()
            .filter(|request| request.match_state == MatchState::Ambiguous)
            .count(),
        0,
        "distinct timestamps must not become a false ambiguity"
    );
    assert!(session
        .requests
        .iter()
        .all(|request| !request.netlog.source_ids.is_empty()));
    assert!(session
        .requests
        .iter()
        .all(|request| request.match_candidates.is_empty()));

    // The clock was calibrated by the fixtures in milliseconds (as Chrome does).
    assert!(session.warnings.iter().any(|warning| {
        warning.code == "netlog.time_unit_detected"
            && warning
                .detail
                .as_ref()
                .and_then(|detail| detail.get("unit"))
                .and_then(|unit| unit.as_str())
                == Some("milliseconds")
    }));

    // The two `cmd_consultar_placa` queries have the same URL/method; each one
    // matches a distinct source id, without choosing the "first look-alike".
    let connector_queries: Vec<_> = session
        .requests
        .iter()
        .filter(|request| request.method == "POST" && request.url.ends_with("/servlet/Connector"))
        .collect();
    assert_eq!(connector_queries.len(), 8, "8 POSTs to the Connector");
    let mut sources: Vec<u32> = connector_queries
        .iter()
        .filter_map(|request| request.netlog.source_ids.first().copied())
        .collect();
    sources.sort_unstable();
    sources.dedup();
    assert_eq!(
        sources.len(),
        connector_queries.len(),
        "each POST to the Connector must point to a distinct URL_REQUEST"
    );
}

#[test]
fn detran_netlog_without_cdp_warns_about_assumed_unit() {
    let imported = scrapelens_core::parse::import_netlog(&fixture("detran-pb.netlog.json"))
        .expect("isolated import of the NetLog");
    let warning = imported
        .report
        .warnings
        .iter()
        .find(|warning| warning.code == "netlog.time_unit_assumed")
        .expect("without CDP, the unit is assumed and this is reported");
    assert!(warning.message.contains("milliseconds"));
}
