//! Regressão: `write_session_dir` nunca escreve fora do diretório da sessão por
//! causa de um symlink plantado (destino, temporário previsível, `attachments/`).

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use scrapelens_core::store::write_session_dir;

fn bundle() -> scrapelens_core::SessionBundle {
    let har = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/aceite/sanitize/secret.har"),
    )
    .unwrap();
    let imported = scrapelens_core::import_har(&har).unwrap();
    assert!(
        !imported.bundle.attachments.is_empty(),
        "pré-condição: há anexos"
    );
    imported.bundle
}

fn outside(root: &Path, name: &str) -> std::path::PathBuf {
    let path = root.join(name);
    fs::write(&path, "ORIGINAL\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    path
}

fn intact(path: &Path) {
    assert_eq!(
        fs::read_to_string(path).unwrap(),
        "ORIGINAL\n",
        "{path:?} foi sobrescrito"
    );
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o644,
        "{path:?} mudou de modo"
    );
}

#[test]
fn symlinked_destinations_are_refused_and_targets_stay_intact() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("sessao");
    fs::create_dir(&dir).unwrap();
    let target = outside(root.path(), "alvo-session.txt");
    symlink(&target, dir.join("session.json")).unwrap();
    let error = write_session_dir(&bundle(), &dir).unwrap_err();
    assert!(error.to_string().contains("link simbólico"), "{error}");
    intact(&target);

    let mut with_raw = bundle();
    with_raw.cdp_events_jsonl = Some(b"{}\n".to_vec());
    let dir2 = root.path().join("sessao2");
    fs::create_dir(&dir2).unwrap();
    let target2 = outside(root.path(), "alvo-cdp.txt");
    symlink(&target2, dir2.join("cdp-events.jsonl")).unwrap();
    assert!(write_session_dir(&with_raw, &dir2).is_err());
    intact(&target2);
}

#[test]
fn predictable_temp_name_symlink_is_never_followed() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("sessao");
    fs::create_dir(&dir).unwrap();
    let target = outside(root.path(), "alvo-tmp.txt");
    for name in [
        format!(".session.json.tmp-{}", std::process::id()),
        ".session.json.tmp-1".to_string(),
    ] {
        symlink(&target, dir.join(name)).unwrap();
    }
    write_session_dir(&bundle(), &dir).unwrap();
    intact(&target);
    let meta = fs::symlink_metadata(dir.join("session.json")).unwrap();
    assert!(meta.file_type().is_file());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
}

#[test]
fn symlinked_attachments_dir_and_files_are_refused() {
    let root = tempfile::tempdir().unwrap();
    // attachments/ -> diretório de fora
    let dir = root.path().join("sessao");
    fs::create_dir(&dir).unwrap();
    let ext = root.path().join("fora");
    fs::create_dir(&ext).unwrap();
    fs::set_permissions(&ext, fs::Permissions::from_mode(0o755)).unwrap();
    symlink(&ext, dir.join("attachments")).unwrap();
    assert!(write_session_dir(&bundle(), &dir).is_err());
    assert_eq!(
        fs::read_dir(&ext).unwrap().count(),
        0,
        "nada pode ser gravado fora"
    );
    assert_eq!(
        fs::metadata(&ext).unwrap().permissions().mode() & 0o777,
        0o755,
        "sem chmod no alvo"
    );

    // um anexo que já existe como symlink
    let dir2 = root.path().join("sessao2");
    fs::create_dir_all(dir2.join("attachments")).unwrap();
    let target = outside(root.path(), "alvo-anexo.txt");
    let b = bundle();
    let name = b.attachments.keys().next().unwrap().clone();
    symlink(&target, dir2.join("attachments").join(&name)).unwrap();
    assert!(write_session_dir(&b, &dir2).is_err());
    intact(&target);
}
