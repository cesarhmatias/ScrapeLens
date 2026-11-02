//! Operações relativas a descritor de diretório (`openat`, `renameat`,
//! `unlinkat`...). Tudo aqui age sobre o diretório que o descritor aberto
//! representa, mesmo que o NOME dele seja trocado ou movido depois (A6-B5): não
//! existe janela de resolução de caminho entre uma escrita e a seguinte.
//!
//! Nomes de entrada nunca podem ter `/`, NUL, nem ser `.` ou `..`: o chamador
//! passa só o nome de uma entrada do próprio diretório.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryKind {
    File,
    Dir,
    Symlink,
    Other,
}

fn name_c(name: &str) -> io::Result<CString> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("nome de entrada inválido: {name:?}"),
        ));
    }
    CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nome com NUL"))
}

fn check(result: libc::c_int) -> io::Result<libc::c_int> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn to_file(fd: libc::c_int) -> File {
    // SAFETY: `fd` é um descritor novo, aberto agora e só nosso.
    unsafe { File::from_raw_fd(fd) }
}

/// Tipo da entrada SEM seguir symlink; `None` se não existe.
pub(crate) fn kind_of(dir: &File, name: &str) -> io::Result<Option<EntryKind>> {
    let cname = name_c(name)?;
    // SAFETY: `stat` é preenchido pelo `fstatat`; o descritor e o nome são válidos.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let result =
        unsafe { libc::fstatat(dir.as_raw_fd(), cname.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) };
    match check(result) {
        Ok(_) => Ok(Some(match stat.st_mode & libc::S_IFMT {
            libc::S_IFREG => EntryKind::File,
            libc::S_IFDIR => EntryKind::Dir,
            libc::S_IFLNK => EntryKind::Symlink,
            _ => EntryKind::Other,
        })),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Entradas do diretório (sem `.` e `..`), pelo descritor.
pub(crate) fn list(dir: &File) -> io::Result<Vec<(String, EntryKind)>> {
    // SAFETY: `dup` do descritor aberto; `fdopendir` assume a cópia e `closedir`
    // a fecha; `readdir` devolve entradas válidas até NULL.
    unsafe {
        let copy = check(libc::dup(dir.as_raw_fd()))?;
        let stream = libc::fdopendir(copy);
        if stream.is_null() {
            let error = io::Error::last_os_error();
            libc::close(copy);
            return Err(error);
        }
        libc::rewinddir(stream);
        let mut out = Vec::new();
        loop {
            let entry = libc::readdir(stream);
            if entry.is_null() {
                break;
            }
            let name = CStr::from_ptr((*entry).d_name.as_ptr()).to_string_lossy().to_string();
            if name == "." || name == ".." {
                continue;
            }
            let kind = match (*entry).d_type {
                libc::DT_REG => EntryKind::File,
                libc::DT_DIR => EntryKind::Dir,
                libc::DT_LNK => EntryKind::Symlink,
                _ => EntryKind::Other,
            };
            out.push((name, kind));
        }
        libc::closedir(stream);
        Ok(out)
    }
}

/// Remove o NOME (arquivo ou symlink; nunca segue o link nem apaga diretório).
pub(crate) fn unlink(dir: &File, name: &str) -> io::Result<()> {
    let cname = name_c(name)?;
    // SAFETY: descritor e nome válidos.
    check(unsafe { libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), 0) }).map(|_| ())
}

fn rmdir(dir: &File, name: &str) -> io::Result<()> {
    let cname = name_c(name)?;
    // SAFETY: descritor e nome válidos.
    check(unsafe { libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), libc::AT_REMOVEDIR) }).map(|_| ())
}

/// Abre o subdiretório sem seguir link.
pub(crate) fn open_dir_at(dir: &File, name: &str) -> io::Result<File> {
    let cname = name_c(name)?;
    // SAFETY: descritor e nome válidos.
    let fd = check(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            cname.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })?;
    Ok(to_file(fd))
}

fn mkdir_at(dir: &File, name: &str, mode: u32) -> io::Result<()> {
    let cname = name_c(name)?;
    // SAFETY: descritor e nome válidos.
    check(unsafe { libc::mkdirat(dir.as_raw_fd(), cname.as_ptr(), mode as libc::mode_t) }).map(|_| ())
}

fn rename_at(src: &File, from: &str, dst: &File, to: &str) -> io::Result<()> {
    let (cfrom, cto) = (name_c(from)?, name_c(to)?);
    // SAFETY: descritores e nomes válidos.
    check(unsafe { libc::renameat(src.as_raw_fd(), cfrom.as_ptr(), dst.as_raw_fd(), cto.as_ptr()) })
        .map(|_| ())
}

/// Cria um arquivo NOVO 0600 (O_EXCL, O_NOFOLLOW) no diretório do descritor.
/// Aberto para leitura e escrita: quem precisa reler pelo mesmo descritor (os
/// corpos, no resgate) clona o `File`.
pub(crate) fn create_new_at(dir: &File, name: &str) -> io::Result<File> {
    let cname = name_c(name)?;
    // SAFETY: descritor e nome válidos.
    let fd = check(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            cname.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    })?;
    Ok(to_file(fd))
}

/// Abre um arquivo para leitura sem seguir link.
pub(crate) fn open_read_at(dir: &File, name: &str) -> io::Result<File> {
    let cname = name_c(name)?;
    // SAFETY: descritor e nome válidos.
    let fd = check(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            cname.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })?;
    Ok(to_file(fd))
}

/// Cria `name` NOVO no diretório do descritor. Se o nome já existe (arquivo antigo
/// ou symlink plantado), remove o NOME (nunca o alvo) e cria de novo; se alguém o
/// replantar entre as duas chamadas, falha em vez de seguir o link. Relativo ao
/// descritor: nenhum caminho é resolvido.
pub(crate) fn create_replacing_at(dir: &File, name: &str) -> io::Result<File> {
    match create_new_at(dir, name) {
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            unlink(dir, name)?;
            create_new_at(dir, name)
        }
        other => other,
    }
}

fn unique_tmp(name: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(".{name}.tmp-{}-{nanos}", std::process::id())
}

/// Grava `bytes` em `<dir>/<name>` de forma atômica e relativa ao descritor:
/// temporário novo (`O_EXCL`) + `renameat`, que substitui o próprio nome (inclusive
/// um symlink) sem escrever no alvo dele. Nenhum caminho é resolvido.
pub(crate) fn write_private_at(dir: &File, name: &str, bytes: &[u8]) -> io::Result<()> {
    name_c(name)?;
    let tmp = unique_tmp(name);
    let result = (|| {
        let mut file = create_new_at(dir, &tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        rename_at(dir, &tmp, dir, name)
    })();
    if result.is_err() {
        let _ = unlink(dir, &tmp);
    }
    result
}

/// Copia um arquivo regular entre diretórios (plano B quando o `renameat` cruza
/// sistemas de arquivos: EXDEV). Ordem: copia, troca o nome, apaga a origem.
fn copy_file_at(src: &File, dst: &File, name: &str) -> io::Result<()> {
    let mut from = open_read_at(src, name)?;
    let mut bytes = Vec::new();
    from.read_to_end(&mut bytes)?;
    write_private_at(dst, name, &bytes)?;
    unlink(src, name)
}

/// Move a entrada `name` de `src` para `dst` (ambos descritores), substituindo o
/// que estiver no destino, sem seguir link em nenhum ponto. Devolve os nomes de
/// symlinks que existiam no destino e foram substituídos (nunca o alvo deles).
///
/// - arquivo: `renameat` (atômico); EXDEV copia;
/// - diretório: `renameat`; se o destino é um diretório não vazio ou o `rename`
///   cruza sistemas de arquivos, mescla entrada por entrada;
/// - um diretório no destino com o nome de um arquivo é erro (não apagamos pastas).
pub(crate) fn move_entry(src: &File, dst: &File, name: &str) -> io::Result<Vec<String>> {
    let mut replaced = Vec::new();
    let Some(kind) = kind_of(src, name)? else {
        return Ok(replaced);
    };
    let at_dst = kind_of(dst, name)?;
    if at_dst == Some(EntryKind::Symlink) {
        replaced.push(name.to_string());
        if kind == EntryKind::Dir {
            // `rename(dir, symlink)` falha; o NOME do link sai antes.
            unlink(dst, name)?;
        }
    }
    match kind {
        EntryKind::File | EntryKind::Other => match rename_at(src, name, dst, name) {
            Ok(()) => Ok(replaced),
            Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {
                copy_file_at(src, dst, name)?;
                Ok(replaced)
            }
            Err(error) => Err(error),
        },
        EntryKind::Symlink => Err(io::Error::other(format!(
            "{name}: link simbólico na origem; recusado"
        ))),
        EntryKind::Dir => match rename_at(src, name, dst, name) {
            Ok(()) => Ok(replaced),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOTEMPTY) | Some(libc::EEXIST) | Some(libc::EXDEV)
                ) =>
            {
                match mkdir_at(dst, name, 0o700) {
                    Ok(()) => {}
                    Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {}
                    Err(e) => return Err(e),
                }
                let from = open_dir_at(src, name)?;
                let to = open_dir_at(dst, name)?;
                for (child, _) in list(&from)? {
                    replaced.extend(move_entry(&from, &to, &child)?);
                }
                rmdir(src, name)?;
                Ok(replaced)
            }
            Err(error) => Err(error),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "scrapelens-fdio-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn open(path: &Path) -> File {
        File::open(path).unwrap()
    }

    fn names(path: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn names_with_separators_or_dots_are_refused() {
        let base = scratch("names");
        let dir = open(&base);
        for bad in ["", ".", "..", "a/b", "../x"] {
            assert!(kind_of(&dir, bad).is_err(), "{bad:?}");
            assert!(write_private_at(&dir, bad, b"x").is_err(), "{bad:?}");
        }
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn write_private_at_follows_the_descriptor_after_the_dir_is_moved() {
        let base = scratch("moved");
        let dir_path = base.join("sessao");
        std::fs::create_dir(&dir_path).unwrap();
        let handle = open(&dir_path);
        // Troca o nome por um link para OUT: a escrita vai para a pasta ORIGINAL.
        let out = base.join("OUT");
        std::fs::create_dir(&out).unwrap();
        let moved = base.join("sessao.moved");
        std::fs::rename(&dir_path, &moved).unwrap();
        symlink(&out, &dir_path).unwrap();
        write_private_at(&handle, "session.json", b"{}").unwrap();
        assert_eq!(names(&out), Vec::<String>::new(), "nada pode cair em OUT");
        assert_eq!(std::fs::read(moved.join("session.json")).unwrap(), b"{}");
        assert_eq!(std::fs::metadata(moved.join("session.json")).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn create_replacing_at_never_writes_through_a_planted_link_nor_into_a_swapped_dir() {
        let base = scratch("create");
        let dir_path = base.join("sessao");
        std::fs::create_dir(&dir_path).unwrap();
        let victim = base.join("VICTIM.txt");
        std::fs::write(&victim, "ORIGINAL\n").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        // 1. Symlink plantado no nome: o NOME é substituído, o alvo não é tocado.
        symlink(&victim, dir_path.join("cdp-bodies.jsonl")).unwrap();
        let handle = open(&dir_path);
        let mut file = create_replacing_at(&handle, "cdp-bodies.jsonl").unwrap();
        file.write_all(b"corpo\n").unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "ORIGINAL\n");
        assert_eq!(std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777, 0o644);
        let meta = std::fs::symlink_metadata(dir_path.join("cdp-bodies.jsonl")).unwrap();
        assert!(meta.file_type().is_file());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        // O mesmo descritor também LÊ (o resgate relê os corpos): clone + seek.
        let mut reader = file.try_clone().unwrap();
        std::io::Seek::seek(&mut reader, std::io::SeekFrom::Start(0)).unwrap();
        let mut back = String::new();
        reader.read_to_string(&mut back).unwrap();
        assert_eq!(back, "corpo\n");
        // 2. A pasta é trocada por um link para OUT ANTES da criação: o arquivo
        //    nasce na pasta ORIGINAL.
        let out = base.join("OUT");
        std::fs::create_dir(&out).unwrap();
        let moved = base.join("sessao.moved");
        std::fs::rename(&dir_path, &moved).unwrap();
        symlink(&out, &dir_path).unwrap();
        std::fs::remove_file(moved.join("cdp-bodies.jsonl")).unwrap();
        create_replacing_at(&handle, "cdp-bodies.jsonl").unwrap();
        assert_eq!(names(&out), Vec::<String>::new(), "nada em OUT");
        assert!(moved.join("cdp-bodies.jsonl").is_file());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn write_private_at_replaces_a_planted_symlink_without_touching_its_target() {
        let base = scratch("plant");
        let victim = base.join("VICTIM.txt");
        std::fs::write(&victim, "ORIGINAL\n").unwrap();
        symlink(&victim, base.join("netlog.json")).unwrap();
        write_private_at(&open(&base), "netlog.json", b"novo").unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "ORIGINAL\n");
        assert_eq!(std::fs::read(base.join("netlog.json")).unwrap(), b"novo");
        assert!(names(&base).iter().all(|n| !n.contains(".tmp-")));
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn move_entry_replaces_files_and_symlinks_and_reports_the_links() {
        let base = scratch("move");
        let (src, dst) = (base.join("stage"), base.join("sessao"));
        std::fs::create_dir(&src).unwrap();
        std::fs::create_dir(&dst).unwrap();
        let victim = base.join("VICTIM.txt");
        std::fs::write(&victim, "ORIGINAL\n").unwrap();
        std::fs::write(src.join("session.json"), "novo").unwrap();
        std::fs::write(src.join("netlog.json"), "novo-netlog").unwrap();
        symlink(&victim, dst.join("session.json")).unwrap();
        std::fs::write(dst.join("netlog.json"), "velho").unwrap();
        let (s, d) = (open(&src), open(&dst));
        assert_eq!(move_entry(&s, &d, "session.json").unwrap(), ["session.json"]);
        assert!(move_entry(&s, &d, "netlog.json").unwrap().is_empty());
        assert!(move_entry(&s, &d, "inexistente").unwrap().is_empty());
        assert_eq!(std::fs::read(dst.join("session.json")).unwrap(), b"novo");
        assert_eq!(std::fs::read(dst.join("netlog.json")).unwrap(), b"novo-netlog");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "ORIGINAL\n");
        assert!(!std::fs::symlink_metadata(dst.join("session.json")).unwrap().file_type().is_symlink());
        assert_eq!(names(&src), Vec::<String>::new());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn move_entry_handles_attachments_dirs_symlinked_or_populated() {
        let base = scratch("movedir");
        let (src, dst) = (base.join("stage"), base.join("sessao"));
        std::fs::create_dir_all(src.join("attachments")).unwrap();
        std::fs::create_dir(&dst).unwrap();
        std::fs::write(src.join("attachments/a.bin"), "A").unwrap();
        std::fs::write(src.join("attachments/b.bin"), "B").unwrap();
        // 1. `attachments` é um symlink para um diretório de fora.
        let outside = base.join("DIR-FORA");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("keep.txt"), "K").unwrap();
        symlink(&outside, dst.join("attachments")).unwrap();
        let (s, d) = (open(&src), open(&dst));
        assert_eq!(move_entry(&s, &d, "attachments").unwrap(), ["attachments"]);
        assert_eq!(names(&dst.join("attachments")), ["a.bin", "b.bin"]);
        assert_eq!(names(&outside), ["keep.txt"], "diretório de fora intacto");
        // 2. Destino já tem um `attachments` não vazio: mescla, substituindo iguais.
        std::fs::create_dir_all(src.join("attachments")).unwrap();
        std::fs::write(src.join("attachments/a.bin"), "A2").unwrap();
        std::fs::write(src.join("attachments/c.bin"), "C").unwrap();
        move_entry(&s, &d, "attachments").unwrap();
        assert_eq!(names(&dst.join("attachments")), ["a.bin", "b.bin", "c.bin"]);
        assert_eq!(std::fs::read(dst.join("attachments/a.bin")).unwrap(), b"A2");
        assert_eq!(names(&src), Vec::<String>::new());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn move_entry_into_a_moved_dir_never_lands_in_the_swapped_target() {
        let base = scratch("swapped");
        let (src, dst) = (base.join("stage"), base.join("sessao"));
        std::fs::create_dir(&src).unwrap();
        std::fs::create_dir(&dst).unwrap();
        std::fs::write(src.join("session.json"), "novo").unwrap();
        let d = open(&dst);
        let out = base.join("OUT");
        std::fs::create_dir(&out).unwrap();
        std::fs::rename(&dst, base.join("sessao.moved")).unwrap();
        symlink(&out, &dst).unwrap();
        move_entry(&open(&src), &d, "session.json").unwrap();
        assert_eq!(names(&out), Vec::<String>::new());
        assert_eq!(std::fs::read(base.join("sessao.moved/session.json")).unwrap(), b"novo");
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn move_entry_refuses_to_replace_a_directory_with_a_file() {
        let base = scratch("isdir");
        let (src, dst) = (base.join("stage"), base.join("sessao"));
        std::fs::create_dir(&src).unwrap();
        std::fs::create_dir_all(dst.join("session.json")).unwrap();
        std::fs::write(src.join("session.json"), "novo").unwrap();
        assert!(move_entry(&open(&src), &open(&dst), "session.json").is_err());
        assert!(dst.join("session.json").is_dir(), "a pasta do destino não é apagada");
        let _ = std::fs::remove_dir_all(base);
    }
}
