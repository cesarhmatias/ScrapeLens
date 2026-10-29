//! Sessões de trace da validação de execução: pasta temporária privada (0700), apagada ao fechar a
//! tela de validação, ao iniciar e ao encerrar o app. "Guardar esta execução" copia para uma pasta
//! nova escolhida pelo usuário e só então apaga a temporária.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use scrapelens_core::store;

/// Limite do arquivo de trace aceito na validação.
pub const TRACE_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Raiz temporária (dentro dos dados do app, privada).
pub fn tmp_root(app_data: &Path) -> Result<PathBuf, String> {
    let root = app_data.join("validate-tmp");
    store::ensure_private_dir(&root).map_err(|error| format!("não foi possível criar {}: {error}", root.display()))?;
    Ok(root)
}

/// Partida do app: apaga as execuções que ficaram sem `discard_validation` (crash, kill, saída forçada).
/// Só filhos imediatos da raiz; symlinks são removidos como links, nunca seguidos.
pub fn cleanup_on_start(app_data: &Path) {
    if let Ok(root) = tmp_root(app_data) {
        cleanup_all(&root);
    }
}

/// Apaga tudo o que sobrou na raiz temporária (início do app, encerramento).
pub fn cleanup_all(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_dir = fs::symlink_metadata(&path).map(|m| m.is_dir()).unwrap_or(false);
        let _ = if is_dir { fs::remove_dir_all(&path) } else { fs::remove_file(&path) };
    }
}

/// `dir` precisa ser uma pasta imediatamente dentro de `root` (nunca um symlink).
fn inside_root(root: &Path, dir: &Path) -> Result<PathBuf, String> {
    let meta = fs::symlink_metadata(dir).map_err(|error| format!("execução temporária inacessível ({}): {error}", dir.display()))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(format!("{} não é uma pasta de execução temporária", dir.display()));
    }
    let root_abs = fs::canonicalize(root).map_err(|error| format!("raiz temporária inacessível: {error}"))?;
    let dir_abs = fs::canonicalize(dir).map_err(|error| format!("execução temporária inacessível: {error}"))?;
    if dir_abs.parent() != Some(root_abs.as_path()) {
        return Err(format!("{} não pertence às execuções temporárias do app; recusado", dir.display()));
    }
    Ok(dir_abs)
}

/// Descarta a execução temporária; recusa qualquer pasta fora da raiz.
pub fn discard(root: &Path, dir: &Path) -> Result<(), String> {
    match fs::symlink_metadata(dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        _ => {}
    }
    let dir_abs = inside_root(root, dir)?;
    fs::remove_dir_all(&dir_abs).map_err(|error| format!("não foi possível apagar {}: {error}", dir_abs.display()))
}

fn copy_tree(from: &Path, to: &Path) -> Result<(), String> {
    fs::create_dir(to).map_err(|error| format!("não foi possível criar {}: {error}", to.display()))?;
    fs::set_permissions(to, fs::Permissions::from_mode(0o700)).map_err(|error| error.to_string())?;
    for entry in fs::read_dir(from).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let (src, dst) = (entry.path(), to.join(entry.file_name()));
        let meta = fs::symlink_metadata(&src).map_err(|error| error.to_string())?;
        if meta.file_type().is_symlink() {
            return Err(format!("{} é link simbólico; recusado", src.display()));
        }
        if meta.is_dir() {
            copy_tree(&src, &dst)?;
        } else {
            fs::copy(&src, &dst).map_err(|error| format!("não foi possível copiar {}: {error}", src.display()))?;
            fs::set_permissions(&dst, fs::Permissions::from_mode(0o600)).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

/// Copia a execução temporária para `destination` (pasta nova, fora da raiz) e apaga a temporária.
/// Devolve o caminho final. Em erro, remove a cópia parcial e mantém a temporária.
pub fn keep(root: &Path, dir: &Path, destination: &Path) -> Result<PathBuf, String> {
    let src = inside_root(root, dir)?;
    let name = destination.file_name().ok_or_else(|| format!("destino sem nome de pasta: {}", destination.display()))?;
    let parent = destination.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    // pasta pai (e ancestrais) sem symlink, como na sanitização
    for ancestor in parent.ancestors() {
        if ancestor.as_os_str().is_empty() || ancestor == Path::new("/var") || ancestor == Path::new("/tmp") || ancestor == Path::new("/etc") {
            continue;
        }
        if fs::symlink_metadata(ancestor).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
            return Err(format!("a pasta escolhida passa por um link simbólico ({}); escolha um caminho real", ancestor.display()));
        }
    }
    let parent_abs = fs::canonicalize(parent).map_err(|error| format!("pasta de destino inválida ({}): {error}", parent.display()))?;
    let dest = parent_abs.join(name);
    let root_abs = fs::canonicalize(root).map_err(|error| error.to_string())?;
    if dest.starts_with(&root_abs) {
        return Err("o destino está dentro da pasta temporária do app; escolha outra pasta".to_string());
    }
    if fs::symlink_metadata(&dest).is_ok() {
        return Err(format!("o destino já existe ({}); escolha uma pasta nova", dest.display()));
    }
    if let Err(error) = copy_tree(&src, &dest) {
        let _ = fs::remove_dir_all(&dest);
        return Err(error);
    }
    fs::remove_dir_all(&src).map_err(|error| format!("execução guardada em {}, mas a temporária não foi apagada: {error}", dest.display()))?;
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sl-validation-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::canonicalize(&dir).unwrap()
    }

    fn make_exec(root: &Path, name: &str) -> PathBuf {
        let dir = root.join(name);
        fs::create_dir_all(dir.join("attachments")).unwrap();
        fs::write(dir.join("session.json"), "{}").unwrap();
        fs::write(dir.join("attachments/a.bin"), "dado da execução").unwrap();
        dir
    }

    #[test]
    fn startup_removes_executions_left_without_discard() {
        let base = tmp("startup");
        // "sessão anterior" terminou sem discard_validation: pastas, arquivo solto e symlink para fora
        let root = tmp_root(&base).unwrap();
        make_exec(&root, "har-aaaa");
        make_exec(&root, "har-bbbb");
        fs::write(root.join("solto.json"), "x").unwrap();
        let outside = make_exec(&base, "dados-do-usuario");
        std::os::unix::fs::symlink(&outside, root.join("link-para-fora")).unwrap();
        assert_eq!(fs::read_dir(&root).unwrap().count(), 4);
        // nova partida
        cleanup_on_start(&base);
        assert!(root.is_dir(), "a raiz continua");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0, "todo filho da raiz foi apagado");
        assert!(outside.join("session.json").exists(), "o alvo do symlink não foi tocado");
        // sem raiz ainda: partida limpa cria a raiz privada
        let fresh = tmp("startup-fresh");
        cleanup_on_start(&fresh);
        assert_eq!(fs::metadata(fresh.join("validate-tmp")).unwrap().permissions().mode() & 0o777, 0o700);
        let _ = fs::remove_dir_all(&base);
        let _ = fs::remove_dir_all(&fresh);
    }

    #[test]
    fn discard_cleanup_and_keep() {
        let base = tmp("flow");
        let root = tmp_root(&base).unwrap();
        // descartar apaga a pasta; repetir é inofensivo
        let a = make_exec(&root, "a");
        discard(&root, &a).unwrap();
        assert!(!a.exists());
        discard(&root, &a).unwrap();
        // recusa pasta fora da raiz e symlink para fora
        let outside = make_exec(&base, "fora");
        assert!(discard(&root, &outside).unwrap_err().contains("não pertence"));
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        assert!(discard(&root, &root.join("link")).is_err());
        assert!(outside.join("session.json").exists(), "o alvo do symlink não pode ser apagado");
        // limpeza total (início/encerramento do app)
        make_exec(&root, "b");
        make_exec(&root, "c");
        cleanup_all(&root);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        assert!(outside.exists());
        // guardar: copia (0700/0600) e apaga a temporária
        let d = make_exec(&root, "d");
        let dest = base.join("guardada");
        let kept = keep(&root, &d, &dest).unwrap();
        assert_eq!(kept, dest);
        assert!(!d.exists());
        assert_eq!(fs::read_to_string(dest.join("attachments/a.bin")).unwrap(), "dado da execução");
        assert_eq!(fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(dest.join("session.json")).unwrap().permissions().mode() & 0o777, 0o600);
        // destino existente, dentro da raiz e origem fora da raiz são recusados; a temporária fica
        let e = make_exec(&root, "e");
        assert!(keep(&root, &e, &dest).unwrap_err().contains("já existe"));
        assert!(keep(&root, &e, &root.join("x")).unwrap_err().contains("dentro da pasta temporária"));
        assert!(keep(&root, &outside, &base.join("y")).is_err());
        assert!(e.exists() && !base.join("y").exists());
        let _ = fs::remove_dir_all(&base);
    }
}
