// Compila o módulo de produção intacto; não simula Tauri nem duplica exportadores.
#[path = "../../../src-tauri/src/export.rs"]
mod bridge;
use std::{fs, path::{Path, PathBuf}};
use serde_json::{json, Value};
use scrapelens_core::export::{curl, python, ExportOptions};

fn fixture(base: &Path) -> PathBuf {
    let dir=base.join("source");
    fs::create_dir_all(dir.join("attachments")).unwrap();
    let headers=json!({"headers":[
        {"name":"Cookie","value":"sid=INDEPENDENT_COOKIE","source":"capture","method":"synthetic-fixture","verification":"unverified"},
        {"name":"Authorization","value":"Bearer INDEPENDENT_AUTH","source":"capture","method":"synthetic-fixture","verification":"unverified"},
        {"name":"Content-Type","value":"application/json","source":"capture","method":"synthetic-fixture","verification":"unverified"},
        {"name":"X-Repeat","value":"first","source":"capture","method":"synthetic-fixture","verification":"unverified"},
        {"name":"X-Repeat","value":"second","source":"capture","method":"synthetic-fixture","verification":"unverified"},
        {"name":"X-Quote","value":"a'b;$(touch /NEVER-RUN)","source":"capture","method":"synthetic-fixture","verification":"unverified"}
    ]});
    let requests: Vec<Value>=["captured","unavailable","truncated","discarded","empty"].iter().map(|state|json!({
        "id":state,"url":"https://fixture.invalid/echo?sid=INDEPENDENT_URL","method":"POST","protocol":"h2","status":200,
        "requestHeaders":headers.clone(),"requestBody":{"state":state,"attachment":"body.json","contentType":"application/json","bytes":45}
    })).collect();
    let value=json!({"schemaVersion":1,"session":{"id":"independent-export","startedAt":"2026-10-27T15:00:00Z","labels":["synthetic-fixture"],"completeness":{"state":"complete","counts":{}}},"requests":requests});
    fs::write(dir.join("session.json"),serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    fs::write(dir.join("attachments/body.json"),br#"{"password":"INDEPENDENT_BODY","ok":"public"}"#).unwrap();
    fs::write(dir.join("cdp-events.jsonl"),b"{\"marker\":\"INDEPENDENT_RAW\"}\n").unwrap();
    fs::write(dir.join("netlog.json"),b"{\"marker\":\"INDEPENDENT_RAW\"}").unwrap();
    dir
}
fn contents(dir:&Path)->Vec<(PathBuf,Vec<u8>)> {
    let mut result=vec![];
    for e in fs::read_dir(dir).unwrap() {let p=e.unwrap().path();if p.is_dir(){result.extend(contents(&p));}else{result.push((p.clone(),fs::read(p).unwrap()));}}
    result.sort_by(|a,b|a.0.cmp(&b.0));result
}
#[test]
fn preview_matches_core_and_saved_file_for_both_formats() {
    let temp=tempfile::tempdir().unwrap();let src=fixture(temp.path());let before=contents(&src);
    let bundle=scrapelens_core::import_session_dir(&src).unwrap().bundle;
    let req=bundle.session.find_request("captured").unwrap();let body=bundle.attachment("body.json");
    for format in ["curl","python"] {
        let p=bridge::preview(&src,"captured",format).unwrap();
        let expected=if format=="curl"{curl::to_curl(req,body,&ExportOptions::default())}else{python::to_python(req,body,&ExportOptions::default())}.unwrap();
        assert_eq!(p.text,expected.text);assert!(p.body_included);assert_eq!(p.header_verification,"unverified");
        let path=temp.path().join(format!("code.{format}"));bridge::write_text_file(&path,&p.text).unwrap();
        assert_eq!(fs::read(&path).unwrap(),p.text.as_bytes());
        #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777,0o600);}
    }
    assert_eq!(contents(&src),before);
}
#[test]
fn states_are_explicit_and_do_not_export_stale_attachment() {
    let temp=tempfile::tempdir().unwrap();let src=fixture(temp.path());
    for state in ["unavailable","discarded","empty"] {
        let p=bridge::preview(&src,state,"curl").unwrap();assert!(!p.body_included);assert!(!p.text.contains("INDEPENDENT_BODY"));assert_eq!(p.body_state,state);assert!(p.body_note.is_some());
    }
    let p=bridge::preview(&src,"truncated","python").unwrap();assert!(p.body_included);assert!(p.body_note.unwrap().contains("truncado"));
}
#[test]
fn invalid_request_format_and_source_fail_without_writes() {
    let temp=tempfile::tempdir().unwrap();let src=fixture(temp.path());let before=contents(&src);
    assert!(bridge::preview(&src,"missing","curl").is_err());assert!(bridge::preview(&src,"captured","exe").is_err());
    assert!(bridge::preview(&src.join("missing"),"captured","curl").is_err());assert_eq!(contents(&src),before);
}
#[test]
fn sanitized_output_removes_markers_raw_events_and_preserves_original() {
    let temp=tempfile::tempdir().unwrap();let src=fixture(temp.path());let before=contents(&src);
    let preview=bridge::sanitize_preview(&src).unwrap();assert!(preview.total_redactions>0);assert_eq!(preview.raw_artifacts_dropped.len(),2);assert_eq!(contents(&src),before);
    let dest=temp.path().join("sanitized");let saved=bridge::sanitize_to(&src,&dest).unwrap();assert_eq!(saved.total_redactions,preview.total_redactions);
    assert!(!dest.join("netlog.json").exists());assert!(!dest.join("cdp-events.jsonl").exists());
    for (_,data) in contents(&dest){for marker in ["INDEPENDENT_COOKIE","INDEPENDENT_AUTH","INDEPENDENT_URL","INDEPENDENT_BODY","INDEPENDENT_RAW"] {assert!(!data.windows(marker.len()).any(|w|w==marker.as_bytes()));}}
    assert_eq!(scrapelens_core::import_session_dir(&dest).unwrap().bundle.session.requests.len(),5);
    #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;assert_eq!(fs::metadata(&dest).unwrap().permissions().mode()&0o777,0o700);for(p,_)in contents(&dest){assert_eq!(fs::metadata(p).unwrap().permissions().mode()&0o777,0o600);}}
    assert_eq!(contents(&src),before);
}
#[test]
fn occupied_source_descendant_and_direct_symlinks_are_refused() {
    let temp=tempfile::tempdir().unwrap();let src=fixture(temp.path());let before=contents(&src);
    assert!(bridge::sanitize_to(&src,&src).is_err());assert!(bridge::sanitize_to(&src,&src.join("nested")).is_err());
    let dest=temp.path().join("occupied");fs::create_dir(&dest).unwrap();fs::write(dest.join("keep"),b"KEEP").unwrap();
    assert!(bridge::sanitize_to(&src,&dest).is_err());assert_eq!(fs::read(dest.join("keep")).unwrap(),b"KEEP");
    #[cfg(unix)] {let link=temp.path().join("direct");std::os::unix::fs::symlink(&dest,&link).unwrap();assert!(bridge::sanitize_to(&src,&link).is_err());assert!(bridge::write_text_file(&link.join("out.sh"),"DATA").is_err());}
    assert_eq!(contents(&src),before);
}
#[test]
fn export_rejects_symlink_in_ancestor() {
    let temp=tempfile::tempdir().unwrap();let real=temp.path().join("real");fs::create_dir_all(real.join("sub")).unwrap();
    let alias=temp.path().join("alias");std::os::unix::fs::symlink(&real,&alias).unwrap();
    let result=bridge::write_text_file(&alias.join("sub/out.sh"),"SYNTHETIC");
    assert!(result.is_err(),"FINDING: gravação aceita link em ancestral alias/sub/out.sh");
    assert!(!real.join("sub/out.sh").exists());
}
#[test]
fn sanitization_rejects_symlink_in_ancestor() {
    let temp=tempfile::tempdir().unwrap();let src=fixture(temp.path());let real=temp.path().join("real");fs::create_dir_all(real.join("sub")).unwrap();
    let alias=temp.path().join("alias");std::os::unix::fs::symlink(&real,&alias).unwrap();
    let result=bridge::sanitize_to(&src,&alias.join("sub/output"));
    assert!(result.is_err(),"FINDING: sanitização aceita link em ancestral alias/sub/output");
    assert!(!real.join("sub/output").exists());
}

// Política de aliases (rodada 3, sobre 16015a1).
#[test]
fn symlink_policy_final_file_dangling_and_relative_aliases() {
    let temp=tempfile::tempdir().unwrap();let src=fixture(temp.path());
    let dir=temp.path().join("d");fs::create_dir(&dir).unwrap();
    // link no próprio arquivo de destino: apontando para alvo existente e pendente
    let victim=temp.path().join("victim");fs::write(&victim,b"KEEP").unwrap();
    std::os::unix::fs::symlink(&victim,dir.join("out.sh")).unwrap();
    assert!(bridge::write_text_file(&dir.join("out.sh"),"X").is_err());assert_eq!(fs::read(&victim).unwrap(),b"KEEP");
    std::os::unix::fs::symlink(temp.path().join("nowhere"),dir.join("dangling.sh")).unwrap();
    assert!(bridge::write_text_file(&dir.join("dangling.sh"),"X").is_err());assert!(!temp.path().join("nowhere").exists());
    // link para arquivo no lugar de pasta pai
    std::os::unix::fs::symlink(&victim,temp.path().join("filelink")).unwrap();
    assert!(bridge::write_text_file(&temp.path().join("filelink/out.sh"),"X").is_err());
    // link pendente como destino da sanitização
    std::os::unix::fs::symlink(temp.path().join("nowhere2"),temp.path().join("dangling-dir")).unwrap();
    assert!(bridge::sanitize_to(&src,&temp.path().join("dangling-dir")).is_err());assert!(!temp.path().join("nowhere2").exists());
    // ancestral relativo: ../alias/... a partir de um diretório real
    let real=temp.path().join("real");fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink("real",temp.path().join("rel")).unwrap();
    assert!(bridge::write_text_file(&dir.join("../rel/out.sh"),"X").is_err());assert!(!real.join("out.sh").exists());
    // controle: caminho real e com ".." sem link continua aceito
    assert!(bridge::write_text_file(&dir.join("../real/ok.sh"),"X").is_ok());
}
#[test]
fn symlink_policy_macos_system_aliases_only_at_root() {
    if !Path::new("/var").is_symlink() {return;}
    // /private/var direto e via /var, ambos reais: aceitos (alias de sistema permitido)
    for base in ["/private/var/tmp","/var/tmp"] {
        let dir=tempfile::tempdir_in(base).unwrap();
        let out=dir.path().join("out.sh");
        assert!(bridge::write_text_file(&out,"SYNTHETIC").is_ok(),"{base}");assert_eq!(fs::read(&out).unwrap(),b"SYNTHETIC");
    }
    // link criado pelo usuário dentro de /var/tmp continua recusado
    let dir=tempfile::tempdir_in("/var/tmp").unwrap();let real=dir.path().join("real");fs::create_dir(&real).unwrap();
    let alias=dir.path().join("alias");std::os::unix::fs::symlink(&real,&alias).unwrap();
    assert!(bridge::write_text_file(&alias.join("o.sh"),"X").is_err());assert!(!real.join("o.sh").exists());
}
