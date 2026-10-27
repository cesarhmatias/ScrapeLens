//! Exportação (cURL/Python) e sessão sanitizada, reutilizando o core.
//!
//! Regras desta ponte:
//! - o texto exportado é gerado **no Rust** a partir da sessão persistida; a UI
//!   nunca monta nem edita o código exportado;
//! - nada é executado, nenhuma rede é aberta;
//! - escrita só em destino explicitamente escolhido pelo usuário, com
//!   `create_new` (recusa sobrescrita), sem links simbólicos e com 0600;
//! - a sessão original nunca é modificada.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;

use scrapelens_core::export::curl::to_curl;
use scrapelens_core::export::python::to_python;
use scrapelens_core::export::sanitize::{sanitize_bundle, SanitizeOptions, SanitizedExport};
use scrapelens_core::export::{ExportOptions, ExportOutput};
use scrapelens_core::model::{BodyState, LogicalRequest, SessionBundle, Warning};
use scrapelens_core::store;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Curl,
    Python,
}

impl Format {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "curl" => Ok(Self::Curl),
            "python" => Ok(Self::Python),
            other => Err(format!(
                "formato de exportação desconhecido: {other:?} (use \"curl\" ou \"python\")"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Curl => "curl",
            Self::Python => "python",
        }
    }
}

/// Resultado da geração: é exatamente o texto que a UI mostra, copia e salva.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportPreview {
    pub session_id: String,
    pub request_id: String,
    pub request_method: String,
    pub request_url: String,
    pub protocol: String,
    pub header_verification: String,
    pub format: String,
    pub text: String,
    pub warnings: Vec<Warning>,
    pub skipped_headers: Vec<String>,
    pub body_included: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_note: Option<String>,
    pub body_state: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedFile {
    pub path: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionCount {
    pub key: String,
    pub count: usize,
}

/// Prévia da sanitização: nada é gravado.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SanitizePreview {
    pub session_id: String,
    pub original_dir: String,
    pub suggested_destination: String,
    pub requests: usize,
    pub redactions: Vec<RedactionCount>,
    pub total_redactions: usize,
    pub warnings: Vec<Warning>,
    pub omitted_attachments: Vec<String>,
    pub attachments_kept: usize,
    pub raw_artifacts_dropped: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SanitizeSaved {
    pub path: String,
    pub session_id: String,
    pub requests: usize,
    pub total_redactions: usize,
    pub omitted_attachments: Vec<String>,
    pub attachments_kept: usize,
    pub raw_artifacts_dropped: Vec<String>,
    pub session_bytes: u64,
}

fn load(dir: &Path) -> Result<SessionBundle, String> {
    if !dir.exists() {
        return Err(format!("pasta da sessão não encontrada: {}", dir.display()));
    }
    if !dir.is_dir() {
        return Err(format!(
            "a exportação precisa da pasta da sessão (com session.json), não do arquivo: {}",
            dir.display()
        ));
    }
    scrapelens_core::import_session_dir(dir)
        .map(|imported| imported.bundle)
        .map_err(|error| format!("não foi possível ler a sessão: {error}"))
}

fn find_request<'a>(bundle: &'a SessionBundle, request_id: &str) -> Result<&'a LogicalRequest, String> {
    bundle
        .session
        .requests
        .iter()
        .find(|request| request.id == request_id)
        .ok_or_else(|| {
            format!(
                "requisição {request_id} não encontrada nesta sessão ({} requisição(ões) no arquivo)",
                bundle.session.requests.len()
            )
        })
}

/// Corpo só é exportado quando a fonte diz que ele foi capturado e os bytes
/// estão de fato no bundle. Estado indisponível continua indisponível.
fn body_bytes<'a>(
    request: &LogicalRequest,
    attachments: &'a BTreeMap<String, Vec<u8>>,
) -> Option<&'a [u8]> {
    match request.request_body.state {
        BodyState::Captured | BodyState::Truncated => request
            .request_body
            .attachment
            .as_ref()
            .and_then(|name| attachments.get(name))
            .map(Vec::as_slice),
        BodyState::Empty | BodyState::Unavailable | BodyState::Discarded => None,
    }
}

fn generate(request: &LogicalRequest, body: Option<&[u8]>, format: Format) -> Result<ExportOutput, String> {
    let options = ExportOptions::default();
    let output = match format {
        Format::Curl => to_curl(request, body, &options),
        Format::Python => to_python(request, body, &options),
    };
    output.map_err(|error| format!("não foi possível gerar a exportação: {error}"))
}

pub fn preview(dir: &Path, request_id: &str, format: &str) -> Result<ExportPreview, String> {
    let format = Format::parse(format)?;
    let bundle = load(dir)?;
    let request = find_request(&bundle, request_id)?;
    let body = body_bytes(request, &bundle.attachments);
    let output = generate(request, body, format)?;

    Ok(ExportPreview {
        session_id: bundle.session.session.id.clone(),
        request_id: request.id.clone(),
        request_method: request.method.clone(),
        request_url: request.url.clone(),
        protocol: request.protocol.as_str().to_string(),
        header_verification: request.request_headers.verification().as_str().to_string(),
        format: format.as_str().to_string(),
        text: output.text,
        warnings: output.warnings,
        skipped_headers: output.skipped_headers,
        body_included: output.body_included,
        body_note: output.body_note,
        body_state: request.request_body.state.as_str().to_string(),
    })
}

fn reject_symlink(path: &Path, label: &str) -> Result<(), String> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(format!("{label} é um link simbólico; escolha um caminho real"));
        }
    }
    Ok(())
}

/// Grava um arquivo novo com 0600; nunca sobrescreve nem segue link simbólico.
pub fn write_text_file(path: &Path, text: &str) -> Result<SavedFile, String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("destino sem pasta: {}", path.display()))?;
    reject_symlink(parent, "a pasta de destino")?;
    if !parent.is_dir() {
        return Err(format!("a pasta de destino não existe: {}", parent.display()));
    }
    if path.file_name().is_none() {
        return Err("o destino precisa de um nome de arquivo".to_string());
    }
    reject_symlink(path, "o arquivo de destino")?;
    if path.exists() {
        return Err(format!(
            "o arquivo já existe ({}); escolha outro nome para não sobrescrever",
            path.display()
        ));
    }

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("não foi possível criar {}: {error}", path.display()))?;
    file.write_all(text.as_bytes())
        .map_err(|error| format!("falha ao gravar {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("falha ao sincronizar {}: {error}", path.display()))?;

    Ok(SavedFile {
        path: path.display().to_string(),
        bytes: text.len() as u64,
    })
}

fn raw_artifacts(dir: &Path) -> Vec<String> {
    [store::CDP_EVENTS_FILE, store::NETLOG_FILE]
        .into_iter()
        .filter(|name| dir.join(name).exists())
        .map(str::to_string)
        .collect()
}

fn sanitized(dir: &Path) -> Result<(SessionBundle, SanitizedExport), String> {
    let bundle = load(dir)?;
    // Política conservadora do core: sem eventos brutos, corpos não
    // estruturados omitidos, placeholders padrão.
    let export = sanitize_bundle(&bundle, &SanitizeOptions::default());
    Ok((bundle, export))
}

pub fn sanitize_preview(dir: &Path) -> Result<SanitizePreview, String> {
    let (bundle, export) = sanitized(dir)?;
    let redactions: Vec<RedactionCount> = export
        .redactions
        .iter()
        .filter(|(_, count)| **count > 0)
        .map(|(key, count)| RedactionCount {
            key: key.clone(),
            count: *count,
        })
        .collect();
    let session_id = bundle.session.session.id.clone();
    let parent = dir.parent().unwrap_or(dir);
    let suggested_destination = parent
        .join(format!("{session_id}-sanitized"))
        .display()
        .to_string();

    Ok(SanitizePreview {
        session_id,
        original_dir: dir.display().to_string(),
        suggested_destination,
        requests: bundle.session.requests.len(),
        total_redactions: redactions.iter().map(|item| item.count).sum(),
        redactions,
        warnings: export.warnings,
        omitted_attachments: export.omitted_attachments,
        attachments_kept: export.bundle.attachments.len(),
        raw_artifacts_dropped: raw_artifacts(dir),
    })
}

/// Grava a sessão sanitizada em `destination`, que precisa ser uma pasta nova
/// (ou vazia) fora da origem. Em erro, remove o que esta chamada criou.
pub fn sanitize_to(src: &Path, destination: &Path) -> Result<SanitizeSaved, String> {
    let src_abs = fs::canonicalize(src)
        .map_err(|error| format!("pasta da sessão inválida ({}): {error}", src.display()))?;
    if !src_abs.is_dir() {
        return Err(format!("a origem não é uma pasta: {}", src.display()));
    }

    let file_name = destination
        .file_name()
        .ok_or_else(|| format!("destino sem nome de pasta: {}", destination.display()))?;
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    reject_symlink(parent, "a pasta escolhida")?;
    let parent_abs = fs::canonicalize(parent)
        .map_err(|error| format!("pasta de destino inválida ({}): {error}", parent.display()))?;
    let dest_abs = parent_abs.join(file_name);

    if dest_abs == src_abs {
        return Err("o destino é a própria sessão original; escolha uma pasta nova".to_string());
    }
    if dest_abs.starts_with(&src_abs) {
        return Err(
            "o destino está dentro da sessão original; escolha uma pasta fora dela para não misturar dados brutos e sanitizados"
                .to_string(),
        );
    }
    reject_symlink(&dest_abs, "o destino")?;

    let mut created = false;
    match fs::metadata(&dest_abs) {
        Ok(metadata) if !metadata.is_dir() => {
            return Err(format!(
                "o destino existe e não é uma pasta: {}",
                dest_abs.display()
            ));
        }
        Ok(_) => {
            let mut entries = fs::read_dir(&dest_abs)
                .map_err(|error| format!("não foi possível ler {}: {error}", dest_abs.display()))?;
            if entries.next().is_some() {
                return Err(format!(
                    "a pasta de destino não está vazia ({}); escolha uma pasta nova",
                    dest_abs.display()
                ));
            }
        }
        Err(_) => created = true,
    }

    store::ensure_private_dir(&dest_abs)
        .map_err(|error| format!("não foi possível criar {}: {error}", dest_abs.display()))?;

    let outcome = (|| -> Result<SanitizeSaved, String> {
        let (bundle, export) = sanitized(&src_abs)?;
        let raw_dropped = raw_artifacts(&src_abs);
        export
            .write_to(&dest_abs)
            .map_err(|error| format!("não foi possível gravar a sessão sanitizada: {error}"))?;
        let total_redactions = export.redactions.values().sum();
        let session_bytes = fs::metadata(dest_abs.join(store::SESSION_FILE))
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        Ok(SanitizeSaved {
            path: dest_abs.display().to_string(),
            session_id: bundle.session.session.id.clone(),
            requests: bundle.session.requests.len(),
            total_redactions,
            omitted_attachments: export.omitted_attachments,
            attachments_kept: export.bundle.attachments.len(),
            raw_artifacts_dropped: raw_dropped,
            session_bytes,
        })
    })();

    if outcome.is_err() && created {
        let _ = fs::remove_dir_all(&dest_abs);
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "scrapelens-export-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    const SESSION_JSON: &str = r#"{
      "schemaVersion": 1,
      "session": {
        "id": "export-fixture",
        "startedAt": "2026-10-27T10:00:00Z",
        "labels": ["synthetic-fixture"],
        "completeness": { "state": "complete", "counts": {} }
      },
      "requests": [
        {
          "id": "req-body",
          "url": "http://127.0.0.1:8781/echo?x=1",
          "method": "POST",
          "protocol": "h1",
          "status": 200,
          "requestHeaders": {
            "headers": [
              { "name": "Host", "value": "127.0.0.1:8781", "source": "capture", "method": "fixture", "verification": "verified" },
              { "name": "Cookie", "value": "sid=ZZSECRET-1; theme=dark", "source": "capture", "method": "fixture", "verification": "verified" },
              { "name": "X-Quote", "value": "a'b", "source": "capture", "method": "fixture", "verification": "verified" }
            ]
          },
          "requestBody": {
            "state": "captured",
            "attachment": "req-body.bin",
            "bytes": 7
          }
        },
        {
          "id": "req-no-body",
          "url": "http://127.0.0.1:8781/page",
          "method": "GET",
          "protocol": "h1",
          "status": 200,
          "requestHeaders": {
            "headers": [
              { "name": "Host", "value": "127.0.0.1:8781", "source": "capture", "method": "fixture", "verification": "verified" }
            ]
          },
          "requestBody": { "state": "unavailable", "note": "CDP não forneceu o corpo" }
        }
      ]
    }"#;

    fn fixture(name: &str) -> PathBuf {
        let dir = temp_dir(name);
        fs::write(dir.join("session.json"), SESSION_JSON).unwrap();
        fs::create_dir_all(dir.join("attachments")).unwrap();
        fs::write(dir.join("attachments/req-body.bin"), b"a=1&b=2").unwrap();
        dir
    }

    #[test]
    fn curl_includes_body_and_escapes_quotes() {
        let dir = fixture("curl");
        let preview = preview(&dir, "req-body", "curl").unwrap();
        assert!(preview.body_included, "{:?}", preview.body_note);
        assert!(preview.text.contains("--data-binary 'a=1&b=2'"), "{}", preview.text);
        // Aspas simples no valor não podem quebrar o comando: o shell recebe
        // `a'\''b` dentro do argumento delimitado por aspas simples.
        assert!(preview.text.contains("a'\\''b"), "{}", preview.text);
        assert_eq!(preview.body_state, "captured");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn python_preview_uses_same_source_without_executing() {
        let dir = fixture("python");
        let preview = preview(&dir, "req-body", "python").unwrap();
        assert_eq!(preview.format, "python");
        assert!(preview.text.contains("http.client"), "{}", preview.text);
        assert!(!preview.text.contains("requests.post"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unavailable_body_is_reported_not_invented() {
        let dir = fixture("no-body");
        let preview = preview(&dir, "req-no-body", "curl").unwrap();
        assert!(!preview.body_included);
        let note = preview.body_note.unwrap_or_default();
        assert!(
            note.to_lowercase().contains("não incluído") && note.contains("Unavailable"),
            "{note}"
        );
        assert!(!preview.text.contains("--data-binary"), "{}", preview.text);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unknown_request_and_missing_dir_are_actionable_errors() {
        let dir = fixture("missing");
        let error = preview(&dir, "req-inexistente", "curl").unwrap_err();
        assert!(error.contains("req-inexistente"), "{error}");
        assert!(error.contains("2 requisição"), "{error}");

        let gone = dir.join("nao-existe");
        let error = preview(&gone, "req-body", "curl").unwrap_err();
        assert!(error.contains("não encontrada"), "{error}");

        let error = preview(&dir, "req-body", "wget").unwrap_err();
        assert!(error.contains("desconhecido"), "{error}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_refuses_overwrite_and_symlink_with_0600() {
        let dir = temp_dir("save");
        let target = dir.join("export.sh");
        let saved = write_text_file(&target, "#!/bin/sh\necho ok\n").unwrap();
        assert_eq!(saved.bytes as usize, "#!/bin/sh\necho ok\n".len());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "modo {mode:o}");
        }

        let error = write_text_file(&target, "outra coisa").unwrap_err();
        assert!(error.contains("já existe"), "{error}");
        assert_eq!(fs::read_to_string(&target).unwrap(), "#!/bin/sh\necho ok\n");

        let link = dir.join("link.sh");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = write_text_file(&link, "x").unwrap_err();
        assert!(error.contains("link simbólico"), "{error}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sanitize_preview_reports_counts_without_writing() {
        let dir = fixture("preview");
        let before: Vec<_> = fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name()).collect();
        let preview = sanitize_preview(&dir).unwrap();
        assert_eq!(preview.requests, 2);
        assert!(preview.total_redactions >= 1, "{:?}", preview.redactions);
        assert!(!preview.suggested_destination.is_empty());
        let after: Vec<_> = fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(before, after, "prévia não pode escrever na origem");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sanitize_writes_new_private_dir_and_keeps_origin() {
        let dir = fixture("sanitize");
        let session_before = fs::read(dir.join("session.json")).unwrap();
        let dest = dir.parent().unwrap().join(format!(
            "{}-out",
            dir.file_name().unwrap().to_string_lossy()
        ));
        let saved = sanitize_to(&dir, &dest).unwrap();
        assert_eq!(
            fs::canonicalize(&saved.path).unwrap(),
            fs::canonicalize(&dest).unwrap()
        );
        assert!(saved.total_redactions >= 1);

        let sanitized = fs::read_to_string(dest.join("session.json")).unwrap();
        assert!(!sanitized.contains("ZZSECRET-1"), "cookie não redigido");
        assert!(sanitized.contains("[REDACTED]"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700, "modo {dir_mode:o}");
            let file_mode = fs::metadata(dest.join("session.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(file_mode, 0o600, "modo {file_mode:o}");
        }

        assert_eq!(fs::read(dir.join("session.json")).unwrap(), session_before);
        assert!(dir.join("attachments/req-body.bin").exists());
        fs::remove_dir_all(&dir).ok();
        fs::remove_dir_all(&dest).ok();
    }

    #[test]
    fn sanitize_refuses_origin_inside_origin_and_occupied_destination() {
        let dir = fixture("dest");
        let error = sanitize_to(&dir, &dir).unwrap_err();
        assert!(error.contains("própria sessão"), "{error}");

        let inside = dir.join("sanitized");
        let error = sanitize_to(&dir, &inside).unwrap_err();
        assert!(error.contains("dentro da sessão"), "{error}");
        assert!(!inside.exists());

        let occupied = temp_dir("occupied");
        fs::write(occupied.join("arquivo.txt"), b"x").unwrap();
        let error = sanitize_to(&dir, &occupied).unwrap_err();
        assert!(error.contains("não está vazia"), "{error}");
        assert!(occupied.join("arquivo.txt").exists());

        let link = dir.parent().unwrap().join(format!(
            "{}-link",
            dir.file_name().unwrap().to_string_lossy()
        ));
        std::os::unix::fs::symlink(&occupied, &link).unwrap();
        let error = sanitize_to(&dir, &link).unwrap_err();
        assert!(error.contains("link simbólico"), "{error}");

        fs::remove_file(&link).ok();
        fs::remove_dir_all(&occupied).ok();
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn saving_into_missing_parent_is_refused() {
        let dir = temp_dir("parent");
        let error = write_text_file(&dir.join("ausente/arq.sh"), "x").unwrap_err();
        assert!(error.contains("não existe"), "{error}");
        fs::remove_dir_all(&dir).ok();
    }
}
