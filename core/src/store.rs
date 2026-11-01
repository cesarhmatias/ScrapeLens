use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use crate::error::{CoreError, Result};
use crate::model::SessionBundle;

#[cfg(unix)]
mod at;
#[cfg(unix)]
pub use at::write_session_dir_at;

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

/// Recusa symlink (e qualquer coisa que não seja arquivo regular) no destino.
fn refuse_non_regular_destination(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(CoreError::LimitExceeded {
            message: format!("{} é um link simbólico; recusado", path.display()),
        }),
        Ok(meta) if !meta.is_file() => Err(CoreError::LimitExceeded {
            message: format!(
                "{} existe e não é um arquivo regular; recusado",
                path.display()
            ),
        }),
        _ => Ok(()),
    }
}

fn write_atomic(path: &Path, bytes: &[u8], sync_data: bool) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| CoreError::InvalidAttachmentPath {
            name: path.to_string_lossy().to_string(),
        })?;
    // O destino nunca pode ser um symlink (a escrita sairia do diretório).
    refuse_non_regular_destination(path)?;
    // Temporário com nome imprevisível e criado com O_EXCL (`create_new`): se o
    // nome existir, mesmo como symlink, a abertura falha em vez de seguir o link.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = parent.join(format!(
        ".{file_name}.tmp-{}-{nanos}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .map_err(|error| CoreError::io(&tmp, error))?;
    let written = file
        .write_all(bytes)
        .map_err(|error| CoreError::io(&tmp, error))
        .and_then(|()| {
            if sync_data {
                file.sync_all().map_err(|error| CoreError::io(&tmp, error))
            } else {
                file.flush().map_err(|error| CoreError::io(&tmp, error))
            }
        });
    drop(file);
    if let Err(error) = written {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }

    set_mode(&tmp, 0o600)?;
    // Confere de novo logo antes do rename: o destino pode ter virado symlink.
    if let Err(error) = refuse_non_regular_destination(path) {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
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
    // Daqui em diante tudo é gravado sob o diretório canonicalizado: nenhum
    // componente do caminho pode ser trocado por symlink no meio da escrita.
    let dir = &dir
        .canonicalize()
        .map_err(|error| CoreError::io(dir, error))?;
    let attachments_dir = dir.join(ATTACHMENTS_DIR);
    // `attachments/` é criado por nós dentro da sessão: um symlink ali é recusado
    // antes de qualquer mkdir/chmod.
    if let Ok(meta) = fs::symlink_metadata(&attachments_dir) {
        if meta.file_type().is_symlink() {
            return Err(CoreError::LimitExceeded {
                message: format!(
                    "{} é um link simbólico; recusado",
                    attachments_dir.display()
                ),
            });
        }
    }
    ensure_private_dir(&attachments_dir)?;
    let canonical_attachments = attachments_dir
        .canonicalize()
        .map_err(|error| CoreError::io(&attachments_dir, error))?;
    if canonical_attachments.parent() != Some(dir.as_path()) {
        return Err(CoreError::LimitExceeded {
            message: format!(
                "{} resolve para fora da sessão; recusado",
                attachments_dir.display()
            ),
        });
    }

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

/// Abre um anexo para leitura recusando symlink (na pasta e no arquivo) e
/// qualquer coisa que não seja arquivo regular; confere que o arquivo aberto é
/// o mesmo que foi inspecionado (TOCTOU). Devolve o arquivo e o tamanho.
pub fn open_regular_attachment(dir: &Path, name: &str) -> Result<(File, u64)> {
    validate_attachment_name(name)?;
    let refused = |message: String| CoreError::LimitExceeded { message };
    let root = dir.join(ATTACHMENTS_DIR);
    let root_meta = fs::symlink_metadata(&root).map_err(|error| CoreError::io(&root, error))?;
    if root_meta.file_type().is_symlink() {
        return Err(refused(
            "a pasta de anexos é um link simbólico; recusado".into(),
        ));
    }
    let target = root.join(name);
    let before = fs::symlink_metadata(&target).map_err(|error| CoreError::io(&target, error))?;
    if before.file_type().is_symlink() {
        return Err(refused(format!(
            "o anexo {name} é um link simbólico; recusado"
        )));
    }
    let file = File::open(&target).map_err(|error| CoreError::io(&target, error))?;
    let opened = file
        .metadata()
        .map_err(|error| CoreError::io(&target, error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.ino() != before.ino() || opened.dev() != before.dev() {
            return Err(refused(format!(
                "o anexo {name} mudou durante a abertura; recusado"
            )));
        }
    }
    if !opened.is_file() {
        return Err(refused(format!("o anexo {name} não é um arquivo regular")));
    }
    Ok((file, opened.len()))
}

/// Lê no máximo `limit` bytes de um anexo (ver [`open_regular_attachment`]).
/// O segundo valor é `true` quando o arquivo é maior que o limite.
pub fn read_attachment_limited(dir: &Path, name: &str, limit: u64) -> Result<(Vec<u8>, bool)> {
    use std::io::Read;
    let (file, size) = open_regular_attachment(dir, name)?;
    let mut bytes = Vec::with_capacity(size.min(limit) as usize);
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| CoreError::io(dir.join(ATTACHMENTS_DIR).join(name), error))?;
    Ok((bytes, size > limit))
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
