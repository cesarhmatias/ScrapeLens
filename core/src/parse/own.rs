use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

use crate::error::{CoreError, Result};
use crate::model::{BodyState, SessionBundle, SessionV1, Warning, SCHEMA_VERSION};
use crate::parse::{ImportReport, ImportedSession, InputFormat};
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
    let mut report = ImportReport::new(InputFormat::OwnV1);
    let mut session = read_session_document(dir, &mut report)?;

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
            report.warn(Warning::error(
                "session.netlog_invalid",
                "netlog.json existe, mas não é JSON válido; mantido como artefato bruto",
            ));
            session
                .session
                .completeness
                .add_reason("netlog.json inválido");
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
            session
                .session
                .completeness
                .add_reason(format!("anexo ausente: {name}"));
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
            session
                .session
                .completeness
                .add_reason(format!("anexo acima do limite: {name}"));
            continue;
        }
        if total_loaded + metadata.len() > MAX_TOTAL_ATTACHMENT_BYTES {
            report.warn(Warning::new(
                "attachment.total_limit",
                "limite total de anexos atingido; anexos restantes não carregados",
            ));
            session
                .session
                .completeness
                .add_reason("limite total de anexos atingido");
            break;
        }
        let bytes = store::read_file(&path)?;
        total_loaded += bytes.len() as u64;
        report.bytes_read += bytes.len();
        report.attachments_loaded += 1;
        attachments.insert(name, bytes);
    }

    finalize_session(dir, &mut session, &mut report);

    let bundle = SessionBundle {
        session,
        cdp_events_jsonl: cdp_bytes,
        netlog_json: netlog_bytes,
        attachments,
    };
    Ok(ImportedSession::new(bundle, report))
}

/// Lê e valida `session.json` sem árvore `Value` intermediária: uma passada
/// só de cabeçalho (versão + chaves de topo, sem alocar os valores) e outra
/// direto para os tipos, ambas em streaming (o arquivo inteiro nunca vive em
/// memória como bytes).
fn read_session_document(dir: &Path, report: &mut ImportReport) -> Result<SessionV1> {
    use std::io::BufReader;
    let session_path = dir.join(store::SESSION_FILE);
    let open = || {
        std::fs::File::open(&session_path).map_err(|error| match error {
            e if e.kind() == std::io::ErrorKind::NotFound => CoreError::MissingField {
                field: format!("{} em {}", store::SESSION_FILE, dir.display()),
            },
            e => CoreError::io(&session_path, e),
        })
    };
    let file = open()?;
    report.bytes_read = file
        .metadata()
        .map(|meta| meta.len() as usize)
        .unwrap_or_default();
    let json_error = |error| CoreError::json(session_path.display().to_string(), error);

    let mut head_reader =
        serde_json::Deserializer::from_reader(BufReader::with_capacity(1 << 20, file));
    let head =
        serde::Deserializer::deserialize_map(&mut head_reader, HeadVisitor).map_err(json_error)?;
    let version = head
        .schema_version
        .and_then(|value| value.as_u64())
        .ok_or_else(|| CoreError::MissingField {
            field: "schemaVersion".to_string(),
        })?;
    if version != u64::from(SCHEMA_VERSION) {
        return Err(CoreError::UnsupportedSchema {
            found: version as u32,
            expected: SCHEMA_VERSION,
        });
    }
    for key in head.unknown_keys {
        report.warn(
            Warning::new(
                "session.unknown_top_level_field",
                format!(
                    "campo de topo desconhecido preservado no arquivo, ignorado no modelo: {key}"
                ),
            )
            .with_detail(Value::String(key)),
        );
    }

    let session: SessionV1 =
        serde_json::from_reader(BufReader::with_capacity(1 << 20, open()?)).map_err(json_error)?;
    if session.schema_version != SCHEMA_VERSION {
        return Err(CoreError::UnsupportedSchema {
            found: session.schema_version,
            expected: SCHEMA_VERSION,
        });
    }
    Ok(session)
}

struct Head {
    schema_version: Option<Value>,
    unknown_keys: Vec<String>,
}

struct HeadVisitor;

impl<'de> serde::de::Visitor<'de> for HeadVisitor {
    type Value = Head;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("um objeto JSON de sessão")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<Head, A::Error> {
        let mut head = Head {
            schema_version: None,
            unknown_keys: Vec::new(),
        };
        while let Some(key) = map.next_key::<String>()? {
            if key == "schemaVersion" {
                head.schema_version = Some(map.next_value::<Value>()?);
                continue;
            }
            map.next_value::<serde::de::IgnoredAny>()?;
            if !TOP_LEVEL_KEYS.contains(&key.as_str()) {
                head.unknown_keys.push(key);
            }
        }
        Ok(head)
    }
}

/// Passos finais comuns à importação eager e à lazy: permissões, anexos não
/// referenciados, avisos na sessão e completude.
fn finalize_session(dir: &Path, session: &mut SessionV1, report: &mut ImportReport) {
    if let Ok(false) = store::is_private(dir) {
        report.warn(Warning::new(
            "store.permissions_loose",
            "diretório da sessão é legível por grupo/outros; exporte/regrave com permissões 0700",
        ));
    }

    // Anexos não referenciados não fazem parte do modelo, mas são mencionados.
    let attachments_dir = dir.join(store::ATTACHMENTS_DIR);
    if let Ok(entries) = std::fs::read_dir(&attachments_dir) {
        let referenced = collect_attachment_refs(session);
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
    if let Some(version) = session.session.browser.version.clone() {
        crate::model::backfill_browser_version(session, &version);
    }
    session.recompute_completeness();
    session.session.completeness.counts.warnings = session.warnings.len();
}

/// Abre uma sessão sem carregar os bytes dos anexos (ver [`crate::lazy`]).
/// Não lê `cdp-events.jsonl`/`netlog.json` (só registra se existem) e não valida
/// o NetLog; cada anexo referenciado é só inspecionado (existência, link
/// simbólico, tamanho) e lido depois, por nome.
pub fn open_session_dir_lazy(dir: &Path) -> Result<(crate::lazy::LazySession, ImportReport)> {
    let mut report = ImportReport::new(InputFormat::OwnV1);
    let mut session = read_session_document(dir, &mut report)?;

    for (file, code, message) in [
        (
            store::CDP_EVENTS_FILE,
            "session.cdp_missing",
            "cdp-events.jsonl ausente; eventos CDP não estarão disponíveis",
        ),
        (
            store::NETLOG_FILE,
            "session.netlog_missing",
            "netlog.json ausente; correlação CDP×NetLog não poderá ser auditada",
        ),
    ] {
        if !dir.join(file).exists() {
            report.warn(Warning::info(code, message));
        }
    }

    for name in collect_attachment_refs(&session) {
        store::validate_attachment_name(&name)?;
        let path = store::attachment_path(dir, &name)?;
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => {
                report.attachments_missing += 1;
                let warning = Warning::new(
                    "attachment.missing",
                    format!("anexo referenciado não existe: {name}"),
                )
                .with_detail(Value::String(name.clone()));
                session.add_warning(warning.clone());
                session
                    .session
                    .completeness
                    .add_reason(format!("anexo ausente: {name}"));
                report.warn(warning);
                continue;
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            report.warn(Warning::new(
                "attachment.unsafe",
                format!("anexo {name} não é arquivo regular (ou é link simbólico); não será lido"),
            ));
            session
                .session
                .completeness
                .add_reason(format!("anexo recusado: {name}"));
        } else if metadata.len() > MAX_ATTACHMENT_BYTES {
            report.warn(Warning::new(
                "attachment.too_large",
                format!(
                    "anexo {name} tem {} bytes (limite {}); não será lido",
                    metadata.len(),
                    MAX_ATTACHMENT_BYTES
                ),
            ));
            session
                .session
                .completeness
                .add_reason(format!("anexo acima do limite: {name}"));
        }
    }
    finalize_session(dir, &mut session, &mut report);
    Ok((
        crate::lazy::LazySession::new(session, dir.to_path_buf()),
        report,
    ))
}

fn collect_attachment_refs(session: &SessionV1) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for request in &session.requests {
        for body in [&request.request_body, &request.response_body] {
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
                format!(
                    "linha {} de cdp-events.jsonl não é JSON válido: {error}",
                    index + 1
                ),
            ));
        } else {
            report.source_events_used += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BrowserInfo, SessionMeta, SessionV1};
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
        s.session
            .labels
            .push(crate::model::LABEL_SYNTHETIC.to_string());
        s.recompute_completeness();
        let dir = write_session(root.path(), s);
        let imported = import_session_dir(&dir).unwrap();
        assert_eq!(imported.bundle.session.schema_version, 1);
        assert_eq!(imported.bundle.session.session.id, "s-1");
        assert_eq!(imported.report.format, InputFormat::OwnV1);
        assert!(!imported.report.has_errors());
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
            CoreError::UnsupportedSchema {
                found: 2,
                expected: 1
            }
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
        request.response_body =
            crate::model::Body::captured("missing.bin", 3, &crate::model::Provenance::default());
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
        request.response_body =
            crate::model::Body::captured("../escape.bin", 3, &crate::model::Provenance::default());
        s.requests.push(request);
        let dir = write_session(root.path(), s);
        let error = import_session_dir(&dir).unwrap_err();
        assert!(matches!(error, CoreError::InvalidAttachmentPath { .. }));
    }
}
