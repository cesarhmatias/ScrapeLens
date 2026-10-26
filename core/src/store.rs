use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use crate::error::{CoreError, Result};
use crate::model::SessionBundle;

pub const SESSION_FILE: &str = "session.json";
pub const CDP_EVENTS_FILE: &str = "cdp-events.jsonl";
pub const NETLOG_FILE: &str = "netlog.json";
pub const ATTACHMENTS_DIR: &str = "attachments";

/// Sessões pequenas mantêm fsync por anexo (durabilidade); capturas grandes
/// usam um único fsync de diretório, porque o custo por arquivo domina.
const ATTACHMENT_SYNC_LIMIT: usize = 256;

/// Nome de anexo aceito: relativo, sem `..`, sem separador de diretório e sem
/// byte nulo. Bloqueia traversal antes de qualquer leitura/escrita.
pub fn validate_attachment_name(name: &str) -> Result<()> {
    let path = Path::new(name);
    let invalid = name.is_empty()
        || name.len() > 255
        || name.contains('\0')
        || name.contains('\\')
        || path.is_absolute()
        || path.components().count() != 1
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)));

    if invalid {
        return Err(CoreError::InvalidAttachmentPath {
            name: name.to_string(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| CoreError::io(path, error))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

/// Cria (se necessário) o diretório da sessão com permissão 0700.
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path).map_err(|error| CoreError::io(path, error))?;
    }
    set_mode(path, 0o700)
}

fn write_atomic(path: &Path, bytes: &[u8], sync_data: bool) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| CoreError::InvalidAttachmentPath {
            name: path.to_string_lossy().to_string(),
        })?;
    let tmp = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));

    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .map_err(|error| CoreError::io(&tmp, error))?;
    file.write_all(bytes)
        .map_err(|error| CoreError::io(&tmp, error))?;
    if sync_data {
        file.sync_all()
            .map_err(|error| CoreError::io(&tmp, error))?;
    } else {
        file.flush().map_err(|error| CoreError::io(&tmp, error))?;
    }
    drop(file);

    set_mode(&tmp, 0o600)?;
    fs::rename(&tmp, path).map_err(|error| {
        let _ = fs::remove_file(&tmp);
        CoreError::io(path, error)
    })?;
    Ok(())
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<()> {
    let dir = File::open(path).map_err(|error| CoreError::io(path, error))?;
    dir.sync_all().map_err(|error| CoreError::io(path, error))
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> Result<()> {
    Ok(())
}

/// Grava uma sessão completa no layout v1 com permissões restritas:
/// diretório 0700, `session.json`/anexos 0600, escrita atômica por arquivo.
///
/// Anexos não recebem `fsync` individual: cada arquivo é fechado e renomeado
/// atomicamente, e o diretório é sincronizado uma vez ao final do lote. Em
/// capturas com dezenas de milhares de corpos pequenos, um `fsync` por anexo
/// dominava o tempo de importação (128 s para 20 mil anexos no aceite); o
/// `session.json` continua sendo sincronizado. O lote preserva a ordem
/// "artefatos/anexos antes do documento" para não deixar referência quebrada.
pub fn write_session_dir(bundle: &SessionBundle, dir: &Path) -> Result<()> {
    ensure_private_dir(dir)?;
    let attachments_dir = dir.join(ATTACHMENTS_DIR);
    ensure_private_dir(&attachments_dir)?;

    // Artefatos/anexos primeiro; session.json por último, para nunca deixar um
    // documento apontando para arquivos que ainda não existem.
    if let Some(bytes) = &bundle.cdp_events_jsonl {
        write_atomic(&dir.join(CDP_EVENTS_FILE), bytes, true)?;
    }
    if let Some(bytes) = &bundle.netlog_json {
        write_atomic(&dir.join(NETLOG_FILE), bytes, true)?;
    }

    // Lote: em sessões pequenas cada anexo é durável; em capturas grandes o
    // fsync é único por diretório no fim, não um por arquivo.
    let sync_each = bundle.attachments.len() <= ATTACHMENT_SYNC_LIMIT;
    for (name, bytes) in &bundle.attachments {
        validate_attachment_name(name)?;
        write_atomic(&attachments_dir.join(name), bytes, sync_each)?;
    }
    if !bundle.attachments.is_empty() {
        sync_dir(&attachments_dir)?;
    }

    let json = serde_json::to_vec_pretty(&bundle.session)
        .map_err(|error| CoreError::json("session.json", error))?;
    write_atomic(&dir.join(SESSION_FILE), &json, true)?;
    sync_dir(dir)?;
    Ok(())
}

pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|error| CoreError::io(path, error))
}

pub fn read_json(path: &Path) -> Result<serde_json::Value> {
    let bytes = read_file(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| CoreError::json(path.display().to_string(), error))
}

/// Verificação de permissões para avisar (não corrigir) sessões importadas
/// que estejam legíveis por grupo/outros.
#[cfg(unix)]
pub fn is_private(path: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode();
    Ok(mode & 0o077 == 0)
}

#[cfg(not(unix))]
pub fn is_private(_path: &Path) -> std::io::Result<bool> {
    Ok(true)
}

/// Caminho absoluto de um anexo dentro de uma sessão, validado contra traversal.
pub fn attachment_path(dir: &Path, name: &str) -> Result<PathBuf> {
    validate_attachment_name(name)?;
    Ok(dir.join(ATTACHMENTS_DIR).join(name))
}

/// Fecha o arquivo depois do flush e garante que o rename não deixe temporário.
pub fn cleanup_temp_files(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir).map_err(|error| CoreError::io(dir, error))? {
        let entry = entry.map_err(|error| CoreError::io(dir, error))?;
        let name = entry.file_name();
        if name.to_string_lossy().contains(".tmp-") {
            let path = entry.path();
            fs::remove_file(&path).map_err(|error| CoreError::io(&path, error))?;
        }
    }
    Ok(())
}

/// Lê bytes de um `File` recém-aberto sem depender do tamanho declarado. Usado
/// pelos testes de permissão.
pub fn read_existing(path: &Path) -> Result<(File, u64)> {
    let file = File::open(path).map_err(|error| CoreError::io(path, error))?;
    let len = file
        .metadata()
        .map_err(|error| CoreError::io(path, error))?
        .len();
    Ok((file, len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BrowserInfo, SessionMeta, SessionV1, SCHEMA_VERSION};

    #[test]
    fn rejects_path_traversal() {
        for name in ["../x", "a/b", "/abs", "a\\b", "", "..", "."] {
            assert!(validate_attachment_name(name).is_err(), "{name:?}");
        }
        assert!(validate_attachment_name("req-1.request.bin").is_ok());
        assert!(validate_attachment_name("a b.bin").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn writes_private_permissions_and_reads_back() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session");
        let session = SessionV1::new(SessionMeta::new(
            "s-1",
            "2026-10-26T20:00:00Z",
            BrowserInfo::default(),
        ));
        let mut bundle = SessionBundle::new(session);
        bundle.insert_attachment("req-1.request.bin", b"hello".to_vec());

        write_session_dir(&bundle, &dir).unwrap();

        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join(SESSION_FILE)), 0o600);
        assert_eq!(mode(&dir.join(ATTACHMENTS_DIR)), 0o700);
        assert_eq!(
            mode(&dir.join(ATTACHMENTS_DIR).join("req-1.request.bin")),
            0o600
        );

        let json = fs::read(dir.join(SESSION_FILE)).unwrap();
        let parsed: SessionV1 = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.schema_version, SCHEMA_VERSION);
        assert_eq!(
            fs::read(dir.join(ATTACHMENTS_DIR).join("req-1.request.bin")).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn writes_many_attachments_in_one_batch() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session");
        let session = SessionV1::new(SessionMeta::new(
            "s-many",
            "2026-10-26T20:00:00Z",
            BrowserInfo::default(),
        ));
        let mut bundle = SessionBundle::new(session);
        for index in 0..128 {
            bundle.insert_attachment(format!("a-{index:03}.bin"), vec![b'x'; 20]);
        }
        write_session_dir(&bundle, &dir).unwrap();
        assert_eq!(
            fs::read_dir(dir.join(ATTACHMENTS_DIR)).unwrap().count(),
            128
        );
        assert_eq!(
            fs::read(dir.join(ATTACHMENTS_DIR).join("a-127.bin")).unwrap(),
            vec![b'x'; 20]
        );
        let leftovers: Vec<_> = fs::read_dir(dir.join(ATTACHMENTS_DIR))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    #[ignore = "benchmark manual: cargo test --release -- --ignored writes_20k_small_attachments"]
    fn writes_20k_small_attachments_quickly() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session");
        let session = SessionV1::new(SessionMeta::new(
            "s-many",
            "2026-10-26T20:00:00Z",
            BrowserInfo::default(),
        ));
        let mut bundle = SessionBundle::new(session);
        for index in 0..20_000 {
            bundle.insert_attachment(format!("a-{index:05}.bin"), vec![b'x'; 20]);
        }
        let started = std::time::Instant::now();
        write_session_dir(&bundle, &dir).unwrap();
        let elapsed = started.elapsed();
        println!("20k anexos: {elapsed:?}");
        assert_eq!(
            std::fs::read_dir(dir.join(ATTACHMENTS_DIR))
                .unwrap()
                .count(),
            20_000
        );
        assert_eq!(
            std::fs::read(dir.join(ATTACHMENTS_DIR).join("a-19999.bin")).unwrap(),
            vec![b'x'; 20]
        );
    }

    #[test]
    fn write_is_atomic_over_existing_file() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("s");
        let session = SessionV1::new(SessionMeta::new(
            "s-1",
            "2026-10-26T20:00:00Z",
            BrowserInfo::default(),
        ));
        let mut bundle = SessionBundle::new(session);
        write_session_dir(&bundle, &dir).unwrap();
        bundle.session.session.id = "s-2".to_string();
        write_session_dir(&bundle, &dir).unwrap();
        let parsed: SessionV1 =
            serde_json::from_slice(&fs::read(dir.join(SESSION_FILE)).unwrap()).unwrap();
        assert_eq!(parsed.session.id, "s-2");
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
    }
}
