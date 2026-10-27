//! Caso de referência DETRAN-PB (`fixtures/detran-pb/`).
//!
//! Fixtures sintéticas com a forma do caso real: 13 requisições, 8 POSTs no
//! Connector, duas consultas com mesma URL/método diferenciadas só pelo corpo.
//! O `time` do NetLog nelas está em milissegundos, como no Chrome real; a
//! unidade é calibrada pelo relógio do CDP.

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
    .expect("importação da captura DETRAN-PB");

    let session = &imported.bundle.session;
    assert_eq!(session.requests.len(), 13);
    assert_eq!(
        session
            .requests
            .iter()
            .filter(|request| request.match_state == MatchState::Matched)
            .count(),
        13,
        "todas as 13 requisições devem casar com o NetLog"
    );
    assert_eq!(
        session
            .requests
            .iter()
            .filter(|request| request.match_state == MatchState::Ambiguous)
            .count(),
        0,
        "timestamps distintos não podem virar ambiguidade falsa"
    );
    assert!(session
        .requests
        .iter()
        .all(|request| !request.netlog.source_ids.is_empty()));
    assert!(session
        .requests
        .iter()
        .all(|request| request.match_candidates.is_empty()));

    // O relógio foi calibrado pelas fixtures em milissegundos (como o Chrome).
    assert!(session.warnings.iter().any(|warning| {
        warning.code == "netlog.time_unit_detected"
            && warning
                .detail
                .as_ref()
                .and_then(|detail| detail.get("unit"))
                .and_then(|unit| unit.as_str())
                == Some("milliseconds")
    }));

    // As duas consultas `cmd_consultar_placa` têm URL/método iguais; cada uma
    // casa com um source id distinto, sem escolher o "primeiro parecido".
    let connector_queries: Vec<_> = session
        .requests
        .iter()
        .filter(|request| request.method == "POST" && request.url.ends_with("/servlet/Connector"))
        .collect();
    assert_eq!(connector_queries.len(), 8, "8 POSTs no Connector");
    let mut sources: Vec<u32> = connector_queries
        .iter()
        .filter_map(|request| request.netlog.source_ids.first().copied())
        .collect();
    sources.sort_unstable();
    sources.dedup();
    assert_eq!(
        sources.len(),
        connector_queries.len(),
        "cada POST do Connector deve apontar para um URL_REQUEST distinto"
    );
}

#[test]
fn detran_netlog_without_cdp_warns_about_assumed_unit() {
    let imported = scrapelens_core::parse::import_netlog(&fixture("detran-pb.netlog.json"))
        .expect("importação isolada do NetLog");
    let warning = imported
        .report
        .warnings
        .iter()
        .find(|warning| warning.code == "netlog.time_unit_assumed")
        .expect("sem CDP, a unidade é assumida e isso é reportado");
    assert!(warning.message.contains("milissegundos"));
}
