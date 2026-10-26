use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

use crate::error::{CoreError, Result};
use crate::model::{
    BodyState, SessionBundle, SessionV1, Warning, SCHEMA_VERSION,
};
use crate::parse::{ImportedSession, ImportReport, InputFormat};
use crate::store;

pub const MAX_ATTACHMENT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_TOTAL_ATTACHMENT_BYTES: u64 = 256 * 1024 * 1024;

const TOP_LEVEL_KEYS: &[&str] = &[
    "schemaVersion",
    "session",
    "requests",
    "connections",
    "streamSessions",
    "warnings",
];

/// Lê `session.json`, valida a versão e carrega os artefatos ao lado.
pub fn import_session_dir(dir: &Path) -> Result<ImportedSession> {
    let session_path = dir.join(store::SESSION_FILE);
    let bytes = store::read_file(&session_path).map_err(|error| match error {
        CoreError::Io { path: _, source } if source.kind() == std::io::ErrorKind::NotFound => {
            CoreError::MissingField {
                field: format!("{} em {}", store::SESSION_FILE, dir.display()),
            }
        }
        other => other,
    })?;

    let raw: Value = serde_json::from_slice(&bytes)
        .map_err(|error| CoreError::json(session_path.display().to_string(), error))?;
    let version = raw
        .get("schemaVersion")
        .and_then(Value::as_u64)
        .ok_or_else(|| CoreError::MissingField {
            field: "schemaVersion".to_string(),
        })?;
    if version != u64::from(SCHEMA_VERSION) {
        return Err(CoreError::UnsupportedSchema {
            found: version as u32,
            expected: SCHEMA_VERSION,
        });
    }

    let mut report = ImportReport::new(InputFormat::OwnV1);
    report.bytes_read = bytes.len();

    if let Some(object) = raw.as_object() {
        for key in object.keys() {
            if !TOP_LEVEL_KEYS.contains(&key.as_str()) {
                report.warn(
                    Warning::new(
                        "session.unknown_top_level_field",
                        format!("campo de topo desconhecido preservado no arquivo, ignorado no modelo: {key}"),
                    )
                    .with_detail(Value::String(key.clone())),
                );
            }
        }
    }

    let mut session: SessionV1 = serde_json::from_value(raw)
        .map_err(|error| CoreError::json(session_path.display().to_string(), error))?;
    if session.schema_version != SCHEMA_VERSION {
        return Err(CoreError::UnsupportedSchema {
            found: session.schema_version,
            expected: SCHEMA_VERSION,
        });
    }

    // Artefatos brutos: ausência é explícita, nunca silenciosa.
    let cdp_path = dir.join(store::CDP_EVENTS_FILE);
    let netlog_path = dir.join(store::NETLOG_FILE);
    let cdp_bytes = if cdp_path.exists() {
        let bytes = store::read_file(&cdp_path)?;
        report.bytes_read += bytes.len();
        validate_jsonl(&bytes, &mut report);
        Some(bytes)
    } else {
        None
    };
    let netlog_bytes = if netlog_path.exists() {
        let bytes = store::read_file(&netlog_path)?;
        report.bytes_read += bytes.len();
        if serde_json::from_slice::<Value>(&bytes).is_err() {
            report.warn(Warning::new(
                "session.netlog_invalid",
                "netlog.json existe, mas não é JSON válido; mantido como artefato bruto",
            ));
        }
        Some(bytes)
    } else {
        None
    };

    let expects_cdp = session
        .session
        .capture
        .as_ref()
        .and_then(|capture| capture.mode.as_deref())
        .map(|mode| mode.contains("cdp"))
        .unwrap_or(false);
    let expects_netlog = session
        .session
        .capture
        .as_ref()
        .and_then(|capture| capture.mode.as_deref())
        .map(|mode| mode.contains("netlog"))
        .unwrap_or(false);

    let mut missing_artifacts = Vec::new();
    if cdp_bytes.is_none() {
        let message = "cdp-events.jsonl ausente; eventos CDP não estarão disponíveis";
        if expects_cdp {
            missing_artifacts.push(message);
            report.warn(Warning::error("session.cdp_missing", message));
        } else {
            report.warn(Warning::info("session.cdp_missing", message));
        }
    }
    if netlog_bytes.is_none() {
        let message = "netlog.json ausente; correlação CDP×NetLog não poderá ser auditada";
        if expects_netlog {
            missing_artifacts.push(message);
            report.warn(Warning::error("session.netlog_missing", message));
        } else {
            report.warn(Warning::info("session.netlog_missing", message));
        }
    }
    for reason in missing_artifacts {
        session.session.completeness.add_reason(reason);
    }

    let attachment_refs = collect_attachment_refs(&session);
    let mut attachments = std::collections::BTreeMap::new();
    let mut total_loaded = 0u64;
    for name in attachment_refs {
        store::validate_attachment_name(&name)?;
        let path = store::attachment_path(dir, &name)?;
        if !path.exists() {
            report.attachments_missing += 1;
            let warning = Warning::new(
                "attachment.missing",
                format!("anexo referenciado não existe: {name}"),
            )
            .with_detail(Value::String(name.clone()));
            session.add_warning(warning.clone());
            report.warn(warning);
            continue;
        }
        let metadata = std::fs::metadata(&path).map_err(|error| CoreError::io(&path, error))?;
        if metadata.len() > MAX_ATTACHMENT_BYTES {
            report.warn(Warning::new(
                "attachment.too_large",
                format!(
                    "anexo {name} tem {} bytes (limite {}); não carregado",
                    metadata.len(),
                    MAX_ATTACHMENT_BYTES
                ),
            ));
            continue;
        }
        if total_loaded + metadata.len() > MAX_TOTAL_ATTACHMENT_BYTES {
            report.warn(Warning::new(
                "attachment.total_limit",
                "limite total de anexos atingido; anexos restantes não carregados",
            ));
            break;
        }
        let bytes = store::read_file(&path)?;
        total_loaded += bytes.len() as u64;
        report.bytes_read += bytes.len();
        report.attachments_loaded += 1;
        attachments.insert(name, bytes);
    }

    if let Ok(false) = store::is_private(dir) {
        report.warn(Warning::new(
            "store.permissions_loose",
            "diretório da sessão é legível por grupo/outros; exporte/regrave com permissões 0700",
        ));
    }

    // Anexos não referenciados não fazem parte do modelo, mas são mencionados.
    let attachments_dir = dir.join(store::ATTACHMENTS_DIR);
    if let Ok(entries) = std::fs::read_dir(&attachments_dir) {
        let referenced = collect_attachment_refs(&session);
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !referenced.contains(&name) {
                report.warn(Warning::info(
                    "attachment.unreferenced",
                    format!("arquivo em attachments/ não referenciado pelo modelo: {name}"),
                ));
            }
        }
    }

    for warning in &report.warnings {
        if !session
            .warnings
            .iter()
            .any(|existing| existing.code == warning.code && existing.message == warning.message)
        {
            session.warnings.push(warning.clone());
        }
    }
    session.recompute_completeness();
    session.session.completeness.counts.warnings = session.warnings.len();

    let bundle = SessionBundle {
        session,
        cdp_events_jsonl: cdp_bytes,
        netlog_json: netlog_bytes,
        attachments,
    };
    Ok(ImportedSession::new(bundle, report))
}

fn collect_attachment_refs(session: &SessionV1) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for request in &session.requests {
        for body in [
            &request.request_body,
            &request.response_body,
        ] {
            if matches!(body.state, BodyState::Captured | BodyState::Truncated) {
                if let Some(name) = &body.attachment {
                    names.insert(name.clone());
                }
            }
        }
        for attempt in &request.attempts {
            for body in [&attempt.request_body, &attempt.response_body] {
                if matches!(body.state, BodyState::Captured | BodyState::Truncated) {
                    if let Some(name) = &body.attachment {
                        names.insert(name.clone());
                    }
                }
            }
        }
    }
    names
}

fn validate_jsonl(bytes: &[u8], report: &mut ImportReport) {
    let text = String::from_utf8_lossy(bytes);
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        report.source_events += 1;
        if let Err(error) = serde_json::from_str::<Value>(line) {
            report.source_events_unknown += 1;
            report.warn(Warning::new(
                "cdp.jsonl_line_invalid",
                format!("linha {} de cdp-events.jsonl não é JSON válido: {error}", index + 1),
            ));
        } else {
            report.source_events_used += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        BrowserInfo, SessionMeta, SessionV1,
    };
    use crate::store::write_session_dir;

    fn write_session(root: &Path, session: SessionV1) -> std::path::PathBuf {
        let dir = root.join("session");
        let bundle = SessionBundle::new(session);
        write_session_dir(&bundle, &dir).unwrap();
        dir
    }

    fn session() -> SessionV1 {
        SessionV1::new(SessionMeta::new(
            "s-1",
            "2026-10-26T20:00:00Z",
            BrowserInfo {
                name: "Chrome".to_string(),
                version: Some("156.0.8078.48".to_string()),
                ..BrowserInfo::default()
            },
        ))
    }

    #[test]
    fn imports_valid_directory() {
        let root = tempfile::tempdir().unwrap();
        let mut s = session();
        s.session.labels.push(crate::model::LABEL_SYNTHETIC.to_string());
        s.recompute_completeness();
        let dir = write_session(root.path(), s);
        let imported = import_session_dir(&dir).unwrap();
        assert_eq!(imported.bundle.session.schema_version, 1);
        assert_eq!(imported.bundle.session.session.id, "s-1");
        assert_eq!(imported.report.format, InputFormat::OwnV1);
        assert!(imported.report.has_errors() == false);
    }

    #[test]
    fn missing_directory_is_explicit() {
        let root = tempfile::tempdir().unwrap();
        let error = import_session_dir(&root.path().join("nope")).unwrap_err();
        assert!(matches!(error, CoreError::MissingField { .. }));
    }

    #[test]
    fn rejects_unsupported_schema() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("s");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(store::SESSION_FILE),
            br#"{"schemaVersion":2,"session":{"id":"x","startedAt":"2026-01-01T00:00:00Z"},"requests":[]}"#,
        )
        .unwrap();
        let error = import_session_dir(&dir).unwrap_err();
        assert!(matches!(
            error,
            CoreError::UnsupportedSchema { found: 2, expected: 1 }
        ));
    }

    #[test]
    fn missing_artifacts_and_corrupt_jsonl_are_reported() {
        let root = tempfile::tempdir().unwrap();
        let dir = write_session(root.path(), session());
        std::fs::write(dir.join(store::CDP_EVENTS_FILE), b"{}\nnot json\n").unwrap();
        let imported = import_session_dir(&dir).unwrap();
        assert!(imported
            .report
            .warnings
            .iter()
            .any(|w| w.code == "cdp.jsonl_line_invalid"));
        assert!(imported
            .report
            .warnings
            .iter()
            .any(|w| w.code == "session.netlog_missing"));
    }

    #[test]
    fn referenced_missing_attachment_is_reported() {
        let root = tempfile::tempdir().unwrap();
        let mut s = session();
        let mut request = crate::model::LogicalRequest::new("r1", "https://a.test/", "GET");
        request.response_body = crate::model::Body::captured(
            "missing.bin",
            3,
            &crate::model::Provenance::default(),
        );
        s.requests.push(request);
        let dir = write_session(root.path(), s);
        let imported = import_session_dir(&dir).unwrap();
        assert_eq!(imported.report.attachments_missing, 1);
        assert!(imported
            .report
            .warnings
            .iter()
            .any(|w| w.code == "attachment.missing"));
    }

    #[test]
    fn refuses_attachment_path_traversal() {
        let root = tempfile::tempdir().unwrap();
        let mut s = session();
        let mut request = crate::model::LogicalRequest::new("r1", "https://a.test/", "GET");
        request.response_body = crate::model::Body::captured(
            "../escape.bin",
            3,
            &crate::model::Provenance::default(),
        );
        s.requests.push(request);
        let dir = write_session(root.path(), s);
        let error = import_session_dir(&dir).unwrap_err();
        assert!(matches!(error, CoreError::InvalidAttachmentPath { .. }));
    }
}
