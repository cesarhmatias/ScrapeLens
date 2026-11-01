//! Gravação de sessão RELATIVA a um descritor de diretório (`openat`,
//! `mkdirat`, `renameat`, `fstatat`, `unlinkat` com `O_NOFOLLOW`), via `rustix`
//! (sem `unsafe`).
//!
//! `write_session_dir` resolve o caminho do diretório da sessão uma vez
//! (canonicalize) e depois grava por caminho; um atacante local que troque um
//! componente do caminho entre a verificação e o uso ainda tem uma janela. Aqui
//! o chamador abre o diretório da sessão (ou o recebe de quem o criou com
//! `O_NOFOLLOW`) e passa o descritor: nenhuma operação resolve o caminho de novo,
//! e nenhum componente (o diretório de anexos, o temporário, o destino) é
//! seguido se for um link simbólico.

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{
    fchmod, fstat, fsync, mkdirat, openat, renameat, statat, unlinkat, AtFlags, FileType, Mode,
    OFlags,
};
use rustix::io::Errno;

use super::{
    validate_attachment_name, ATTACHMENTS_DIR, ATTACHMENT_SYNC_LIMIT, CDP_EVENTS_FILE, NETLOG_FILE,
    SESSION_FILE,
};
use crate::error::{CoreError, Result};
use crate::model::SessionBundle;

fn io_error(what: &str, errno: Errno) -> CoreError {
    CoreError::io(PathBuf::from(what), io::Error::from(errno))
}

fn refused(message: String) -> CoreError {
    CoreError::LimitExceeded { message }
}

/// `openat` relativo a `dir`, sempre com `O_CLOEXEC | O_NOFOLLOW`.
fn open_at(
    dir: BorrowedFd<'_>,
    name: &str,
    flags: OFlags,
    mode: Mode,
) -> std::result::Result<OwnedFd, Errno> {
    openat(dir, name, flags | OFlags::CLOEXEC | OFlags::NOFOLLOW, mode)
}

/// Tipo do destino sem seguir links: `None` se não existe.
fn lstat_type(dir: BorrowedFd<'_>, name: &str) -> Result<Option<FileType>> {
    match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => Ok(Some(FileType::from_raw_mode(st.st_mode))),
        Err(Errno::NOENT) => Ok(None),
        Err(errno) => Err(io_error(name, errno)),
    }
}

fn refuse_non_regular(dir: BorrowedFd<'_>, name: &str) -> Result<()> {
    match lstat_type(dir, name)? {
        None | Some(FileType::RegularFile) => Ok(()),
        Some(FileType::Symlink) => Err(refused(format!("{name} é um link simbólico; recusado"))),
        Some(_) => Err(refused(format!(
            "{name} existe e não é um arquivo regular; recusado"
        ))),
    }
}

fn unlink_quiet(dir: BorrowedFd<'_>, name: &str) {
    let _ = unlinkat(dir, name, AtFlags::empty());
}

/// Grava `bytes` em `dir/name` por temporário `O_EXCL` + `renameat`.
fn write_atomic_at(dir: BorrowedFd<'_>, name: &str, bytes: &[u8], sync_data: bool) -> Result<()> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    refuse_non_regular(dir, name)?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = format!(
        ".{name}.tmp-{}-{nanos}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    );
    let file = open_at(
        dir,
        &tmp,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|errno| io_error(&tmp, errno))?;
    let written = (|| -> Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            match rustix::io::write(&file, &bytes[offset..]) {
                Ok(n) => offset += n,
                Err(Errno::INTR) => continue,
                Err(errno) => return Err(io_error(&tmp, errno)),
            }
        }
        fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|errno| io_error(&tmp, errno))?;
        if sync_data {
            fsync(&file).map_err(|errno| io_error(&tmp, errno))?;
        }
        Ok(())
    })();
    drop(file);
    if let Err(error) = written {
        unlink_quiet(dir, &tmp);
        return Err(error);
    }
    // O destino pode ter virado symlink desde a primeira conferência.
    if let Err(error) = refuse_non_regular(dir, name) {
        unlink_quiet(dir, &tmp);
        return Err(error);
    }
    // `renameat` nunca segue o destino: substitui o próprio nome.
    if let Err(errno) = renameat(dir, tmp.as_str(), dir, name) {
        unlink_quiet(dir, &tmp);
        return Err(io_error(name, errno));
    }
    Ok(())
}

/// Abre (criando 0700 se preciso) um subdiretório sem seguir link simbólico.
fn open_subdir(dir: BorrowedFd<'_>, name: &str) -> Result<OwnedFd> {
    match mkdirat(dir, name, Mode::RWXU) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(errno) => return Err(io_error(name, errno)),
    }
    // `O_NOFOLLOW` + `O_DIRECTORY`: um symlink no lugar do diretório falha (ELOOP).
    let fd =
        open_at(dir, name, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).map_err(|errno| {
            if matches!(lstat_type(dir, name), Ok(Some(FileType::Symlink))) {
                refused(format!("{name} é um link simbólico; recusado"))
            } else {
                io_error(name, errno)
            }
        })?;
    fchmod(&fd, Mode::RWXU).map_err(|errno| io_error(name, errno))?;
    Ok(fd)
}

/// Como [`super::write_session_dir`], mas relativo a `dirfd` (o diretório da
/// sessão já aberto pelo chamador). Nenhum caminho é resolvido de novo: o
/// diretório de anexos, os temporários e os destinos são abertos com
/// `openat(..., O_NOFOLLOW)` e substituídos com `renameat`. O diretório recebe
/// 0700, os arquivos 0600; `session.json` é o último a ser gravado.
pub fn write_session_dir_at(dirfd: BorrowedFd<'_>, bundle: &SessionBundle) -> Result<()> {
    // O descritor tem de ser um diretório.
    let st = fstat(dirfd).map_err(|errno| io_error("<dirfd>", errno))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
        return Err(refused("o descritor da sessão não é um diretório".into()));
    }
    fchmod(dirfd, Mode::RWXU).map_err(|errno| io_error("<dirfd>", errno))?;

    let attachments = open_subdir(dirfd, ATTACHMENTS_DIR)?;
    let att = attachments.as_fd();

    if let Some(bytes) = &bundle.cdp_events_jsonl {
        write_atomic_at(dirfd, CDP_EVENTS_FILE, bytes, true)?;
    }
    if let Some(bytes) = &bundle.netlog_json {
        write_atomic_at(dirfd, NETLOG_FILE, bytes, true)?;
    }
    let sync_each = bundle.attachments.len() <= ATTACHMENT_SYNC_LIMIT;
    for (name, bytes) in &bundle.attachments {
        validate_attachment_name(name)?;
        write_atomic_at(att, name, bytes, sync_each)?;
    }
    if !bundle.attachments.is_empty() {
        fsync(att).map_err(|errno| io_error(ATTACHMENTS_DIR, errno))?;
    }
    let json = serde_json::to_vec_pretty(&bundle.session)
        .map_err(|error| CoreError::json("session.json", error))?;
    write_atomic_at(dirfd, SESSION_FILE, &json, true)?;
    fsync(dirfd).map_err(|errno| io_error("<dirfd>", errno))?;
    Ok(())
}
