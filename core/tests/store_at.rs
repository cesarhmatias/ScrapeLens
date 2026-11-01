//! `write_session_dir_at`: gravação relativa a um descritor de diretório, sem
//! seguir link simbólico em nenhum componente e sem resolver o caminho de novo.

#![cfg(unix)]

use std::fs::{self, File};
use std::os::fd::AsFd;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use scrapelens_core::store::{write_session_dir_at, SESSION_FILE};

fn bundle() -> scrapelens_core::SessionBundle {
    let har = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/aceite/sanitize/secret.har"),
    )
    .unwrap();
    let imported = scrapelens_core::import_har(&har).unwrap();
    assert!(!imported.bundle.attachments.is_empty());
    imported.bundle
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn open_dir(path: &Path) -> File {
    File::open(path).unwrap()
}

#[test]
fn writes_the_whole_session_with_private_permissions_and_it_is_readable() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("sessao");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    let handle = open_dir(&dir);
    let bundle = bundle();
    write_session_dir_at(handle.as_fd(), &bundle).unwrap();
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join("attachments")), 0o700);
    assert_eq!(mode(&dir.join(SESSION_FILE)), 0o600);
    for name in bundle.attachments.keys() {
        assert_eq!(mode(&dir.join("attachments").join(name)), 0o600, "{name}");
    }
    // Sem temporários sobrando; a sessão volta pelo importador normal.
    let leftovers: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .chain(fs::read_dir(dir.join("attachments")).unwrap())
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    let back = scrapelens_core::import_session_dir(&dir).unwrap();
    assert_eq!(
        back.bundle.session.requests.len(),
        bundle.session.requests.len()
    );
    assert_eq!(back.bundle.attachments.len(), bundle.attachments.len());
}

#[test]
fn replacing_the_path_by_a_symlink_after_open_does_not_redirect_the_writes() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("sessao");
    let elsewhere = root.path().join("fora");
    fs::create_dir(&dir).unwrap();
    fs::create_dir(&elsewhere).unwrap();
    let handle = open_dir(&dir);
    // Troca o diretório por um link para outro lugar DEPOIS de abrir o descritor.
    let moved = root.path().join("sessao-original");
    fs::rename(&dir, &moved).unwrap();
    symlink(&elsewhere, &dir).unwrap();
    write_session_dir_at(handle.as_fd(), &bundle()).unwrap();
    assert!(moved.join(SESSION_FILE).is_file(), "gravou no inode aberto");
    assert_eq!(
        fs::read_dir(&elsewhere).unwrap().count(),
        0,
        "nada vazou para o link"
    );
}

#[test]
fn refuses_symlinked_attachments_dir_and_symlinked_destinations_leaving_targets_intact() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("alvo.txt");
    fs::write(&target, "ORIGINAL\n").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
    let outside_dir = root.path().join("fora");
    fs::create_dir(&outside_dir).unwrap();
    fs::set_permissions(&outside_dir, fs::Permissions::from_mode(0o755)).unwrap();

    // attachments/ é um link simbólico
    let a = root.path().join("a");
    fs::create_dir(&a).unwrap();
    symlink(&outside_dir, a.join("attachments")).unwrap();
    let error = write_session_dir_at(open_dir(&a).as_fd(), &bundle()).unwrap_err();
    assert!(error.to_string().contains("link simbólico"), "{error}");
    assert_eq!(fs::read_dir(&outside_dir).unwrap().count(), 0);
    assert_eq!(mode(&outside_dir), 0o755, "sem chmod no alvo do link");

    // session.json é um link simbólico
    let b = root.path().join("b");
    fs::create_dir(&b).unwrap();
    symlink(&target, b.join(SESSION_FILE)).unwrap();
    let error = write_session_dir_at(open_dir(&b).as_fd(), &bundle()).unwrap_err();
    assert!(error.to_string().contains("link simbólico"), "{error}");
    assert_eq!(fs::read_to_string(&target).unwrap(), "ORIGINAL\n");
    assert_eq!(mode(&target), 0o644);

    // um anexo é um link simbólico
    let c = root.path().join("c");
    fs::create_dir_all(c.join("attachments")).unwrap();
    let bundle = bundle();
    let first = bundle.attachments.keys().next().unwrap().clone();
    symlink(&target, c.join("attachments").join(&first)).unwrap();
    let error = write_session_dir_at(open_dir(&c).as_fd(), &bundle).unwrap_err();
    assert!(error.to_string().contains("link simbólico"), "{error}");
    assert_eq!(fs::read_to_string(&target).unwrap(), "ORIGINAL\n");

    // o temporário previsível plantado não é seguido
    let d = root.path().join("d");
    fs::create_dir(&d).unwrap();
    symlink(&target, d.join(format!(".{SESSION_FILE}.tmp-1-1-1"))).unwrap();
    write_session_dir_at(open_dir(&d).as_fd(), &bundle).unwrap();
    assert_eq!(fs::read_to_string(&target).unwrap(), "ORIGINAL\n");
}

#[test]
fn rejects_a_descriptor_that_is_not_a_directory() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("arquivo");
    fs::write(&file, "x").unwrap();
    let error = write_session_dir_at(File::open(&file).unwrap().as_fd(), &bundle()).unwrap_err();
    assert!(error.to_string().contains("não é um diretório"), "{error}");
}
