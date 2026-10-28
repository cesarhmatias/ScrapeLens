//! Exportador cURL com quoting de shell correto.
//!
//! O comando gerado é para bash/zsh (`$'...'` quando há bytes de controle).
//! URLs, headers e payloads são dados não confiáveis: nomes de header são
//! validados, CR/LF/NUL são recusados e aspas são escapadas. Não há promessa de
//! replicar TLS, JA3/JA4, ordem de frames ou HPACK.

use crate::error::Result;
use crate::model::{LogicalRequest, Verification};

use super::{
    drop_content_length_without_body, export_url, exportable_headers, resolve_body, ExportOptions,
    ExportOutput,
};

pub fn to_curl(
    request: &LogicalRequest,
    body: Option<&[u8]>,
    options: &ExportOptions,
) -> Result<ExportOutput> {
    to_curl_with_origins(request, body, options, None)
}

/// Como [`to_curl`], anotando em comentário os campos "obter em runtime" (com a
/// origem) quando `origins` é dado. O código gerado não muda.
pub fn to_curl_with_origins(
    request: &LogicalRequest,
    body: Option<&[u8]>,
    options: &ExportOptions,
    origins: Option<&crate::flow::ValueOrigins>,
) -> Result<ExportOutput> {
    let url = export_url(request)?.to_string();
    let mut output = ExportOutput::new(String::new());
    let headers = exportable_headers(request, &mut output);
    let mut body = resolve_body(request, body, options, &mut output);
    if body.is_some_and(|bytes| bytes.contains(&0)) {
        // Bash não consegue passar NUL em argv; recusar é melhor que truncar.
        output.body_included = false;
        output.body_note = Some(
            "corpo contém NUL e não pode ser reproduzido por um argumento de shell; omitido"
                .to_string(),
        );
        output.warnings.push(crate::model::Warning::new(
            "export.body_nul",
            "corpo binário com NUL omitido do cURL; use a exportação Python ou o anexo original",
        ));
        body = None;
    }
    let headers = drop_content_length_without_body(headers, body.is_some(), &mut output);

    let verification = request.request_headers.verification();
    let mut text = String::new();
    text.push_str(&super::comment(&format!(
        "ScrapeLens — export cURL da requisição {}",
        request.id
    )));
    text.push_str(
        "# NÃO reproduz TLS nem fingerprint do navegador (JA3/JA4, frames, HPACK); apenas a requisição HTTP.\n",
    );
    text.push_str(&super::comment(&format!(
        "protocolo capturado: {} · verificação dos headers: {}",
        request.protocol.as_str(),
        verification.as_str()
    )));
    if verification == Verification::Unverified {
        text.push_str(
            "# ATENÇÃO: sequência de headers NÃO verificada; trate como não confiável.\n",
        );
    }
    if !output.skipped_headers.is_empty() {
        text.push_str(&super::comment(&format!(
            "{} header(s)/campo(s) não replicado(s):",
            output.skipped_headers.len()
        )));
        for skipped in &output.skipped_headers {
            text.push_str(&super::comment(&format!("  - {skipped}")));
        }
    }
    if let Some(note) = &output.body_note {
        text.push_str(&super::comment(&format!("corpo: {note}")));
    }
    if let Some(origins) = origins {
        for line in super::runtime_origin_notes(origins) {
            text.push_str(&super::comment(&line));
        }
    }
    if let Some(note) = super::redirect_url_note(request) {
        text.push_str(&super::comment(&format!("ATENÇÃO: {note}")));
    }
    text.push_str("# Contém credenciais/cookies se a sessão não foi sanitizada.\n");

    text.push_str("curl \\\n");
    text.push_str(&format!(
        "  --request {} \\\n",
        shell_quote(&request.method)
    ));
    text.push_str(&format!("  --url {} \\\n", shell_quote(&url)));
    for header in &headers {
        text.push_str(&format!(
            "  --header {} \\\n",
            shell_quote(&format!("{}: {}", header.name, header.value))
        ));
    }
    if let Some(body) = body {
        text.push_str(&format!("  --data-binary {} \\\n", shell_quote_bytes(body)));
    }
    // Remove a continuação final e adiciona quebra de linha.
    while text.ends_with(" \\\n") {
        text.truncate(text.len() - 3);
    }
    if !text.ends_with('\n') {
        text.push('\n');
    }
    output.text = text;
    Ok(output)
}

/// Aspas simples POSIX; `'` vira `'\''`. Controla NUL? NUL não é aceito em
/// argumento; quem chama já removeu. Para bytes de controle usa `$'...'`.
pub fn shell_quote(value: &str) -> String {
    if value.chars().any(|ch| ch.is_control() && ch != '\t') || value.contains('\t') {
        return shell_quote_ansi(value.as_bytes());
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Bytes em quoting ANSI-C do bash (`$'...'`), seguro para NUL e não-UTF8.
pub fn shell_quote_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "''".to_string();
    }
    let printable = bytes.iter().all(|byte| (0x20..=0x7e).contains(byte));
    if printable {
        if let Ok(text) = std::str::from_utf8(bytes) {
            return format!("'{}'", text.replace('\'', "'\\''"));
        }
    }
    shell_quote_ansi(bytes)
}

fn shell_quote_ansi(bytes: &[u8]) -> String {
    let mut out = String::from("$'");
    for byte in bytes {
        match byte {
            b'\'' => out.push_str("\\'"),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(*byte as char),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out.push('\'');
    out
}
