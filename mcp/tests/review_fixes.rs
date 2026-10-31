//! Regressões da revisão de segurança do MCP (docs/17): oráculo de substring,
//! confirmação, spill por symlink, encerramento durante o início da captura.

mod common;

use std::os::unix::fs::PermissionsExt;

use common::client::{fake_server, Client, Elicit};
use common::*;
use scrapelens_mcp::tools::*;
use serde_json::{json, Value};

// ---- C1: trace_value não é oráculo de substring -----------------------------------

fn total(out: &Value) -> u64 {
    out["producersTotal"].as_u64().unwrap() + out["consumersTotal"].as_u64().unwrap()
}

#[test]
fn trace_value_without_reveal_matches_only_whole_values() {
    let env = Env::new(true);
    env.import_flow("flow", "");
    let trace = |value: &str, reveal: bool| {
        trace_value(
            &env.ctx,
            p(json!({"session_id": "flow", "value": value, "reveal": reveal})),
        )
        .unwrap()
    };
    // Valor inteiro: casa (header Authorization sem o esquema, e campo JSON da resposta).
    let whole = trace(TOKEN, false);
    assert_eq!(whole["firstProducer"]["requestId"], "har-0002");
    assert!(whole["consumers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["requestId"] == "har-0003"));
    assert!(
        total(&trace(&format!("Bearer {TOKEN}"), false)) > 0,
        "header inteiro também"
    );
    // Qualquer pedaço NÃO casa, em nenhum modo de busca.
    for len in 1..TOKEN.len() {
        assert_eq!(total(&trace(&TOKEN[..len], false)), 0, "prefixo {len}");
        assert_eq!(total(&trace(&TOKEN[len..], false)), 0, "sufixo {len}");
        assert_eq!(
            total(&trace(&format!("Bearer {}", &TOKEN[..len]), false)),
            0
        );
    }
    // Reconstrução caractere a caractere (o PoC do revisor): nenhum candidato avança.
    let alphabet: Vec<char> = ('A'..='Z')
        .chain('a'..='z')
        .chain('0'..='9')
        .chain(['-', '_'])
        .collect();
    let mut known = String::from("Bearer ");
    let mut steps = 0;
    for _ in 0..TOKEN.len() {
        let next = alphabet
            .iter()
            .find(|c| total(&trace(&format!("{known}{c}"), false)) > 0);
        match next {
            Some(c) => {
                known.push(*c);
                steps += 1;
            }
            None => break,
        }
    }
    assert_eq!(steps, 0, "o oráculo reconstruiu: {known}");
    // Valor dentro de corpo HTML retido, e pedaço do cookie: também nada.
    assert_eq!(
        total(&trace(CSRF, false)),
        1,
        "CSRF inteiro só no header X-CSRF (HTML não é pesquisado)"
    );
    let html = trace(CSRF, false);
    assert!(html["consumers"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["scope"] == "requestHeaders"));
    assert!(text(&html["warnings"]).contains("não estruturado"));
    assert_eq!(total(&trace(&SID[..10], false)), 0);
    assert!(total(&trace(SID, false)) > 0, "cookie inteiro casa");
    // Com reveal o comportamento de substring continua disponível (é a opção explícita).
    assert!(total(&trace(&TOKEN[..10], true)) > 0);
    assert_eq!(trace(&TOKEN[..10], true)["revealed"], true);
}

#[test]
fn other_tools_do_not_answer_about_redacted_content() {
    let env = Env::new(true);
    env.import_flow("flow", "");
    env.import_flow("flow2", "-v2");
    // search_bodies: pedaço de segredo (mesmo inteiro) não acha nada sem reveal.
    for query in [
        &TOKEN[..8],
        TOKEN,
        &SID[..10],
        SID,
        PASSWORD,
        "Bearer",
        REFRESH,
    ] {
        let out =
            search_bodies(&env.ctx, p(json!({"session_id": "flow", "query": query}))).unwrap();
        let matches = out["matches"].as_array().unwrap();
        for m in matches {
            // só pode achar texto que não está redigido (ex.: a palavra "Bearer" no esquema)
            assert!(
                !m["snippet"]
                    .as_str()
                    .unwrap()
                    .contains(&query[..query.len().min(8)])
                    || query == "Bearer",
                "{query}: {m}"
            );
        }
        if query != "Bearer" {
            assert_eq!(out["total"], 0, "{query}");
        }
    }
    // corpo retido (HTML) não é pesquisável sem reveal
    assert_eq!(
        search_bodies(
            &env.ctx,
            p(json!({"session_id": "flow", "query": &CSRF[..10]}))
        )
        .unwrap()["total"],
        0
    );
    // list_requests(text) só enxerga a URL já redigida: o valor do parâmetro `key`
    // (sensível) não é pesquisável, a parte visível da URL é.
    let hidden =
        list_requests(&env.ctx, p(json!({"session_id": "flow", "text": "key=1"}))).unwrap();
    assert_eq!(hidden["total"], 0);
    let visible = list_requests(
        &env.ctx,
        p(json!({"session_id": "flow", "text": "data?key="})),
    )
    .unwrap();
    assert_eq!(visible["total"], 1);
    // diff: valores diferentes e redigidos aparecem iguais; nada de dado cru
    let diff = diff_requests_tool(
        &env.ctx,
        p(json!({"session_id": "flow", "request_a": "har-0003", "request_b": "har-0003", "other_session_id": "flow2"})),
    )
    .unwrap();
    assert_no_secrets(&diff, "diff_requests");
    assert!(
        !text(&diff).contains("v2"),
        "diferença de token não pode aparecer: {diff}"
    );
}

// ---- A1: confirmação ----------------------------------------------------------------

#[test]
fn confirmation_from_denies_everything_except_an_explicit_true() {
    use rmcp::service::{ElicitationError, ServiceError};
    use scrapelens_mcp::live::{decide, ConfirmStart, Confirmation};
    use scrapelens_mcp::server::confirmation_from;
    let parse_error = || ElicitationError::ParseError {
        error: serde_json::from_str::<bool>("\"x\"").unwrap_err(),
        data: json!({"confirmo": "true"}),
    };
    let rpc_error = || {
        ElicitationError::Service(ServiceError::McpError(rmcp::ErrorData::internal_error(
            "User rejected",
            None,
        )))
    };
    let timeout = || {
        ElicitationError::Service(ServiceError::Timeout {
            timeout: std::time::Duration::from_secs(300),
        })
    };
    let cases: Vec<(&str, Result<Option<ConfirmStart>, ElicitationError>)> = vec![
        (
            "caixa desmarcada",
            Ok(Some(ConfirmStart { confirmo: false })),
        ),
        ("sem conteúdo", Ok(None)),
        ("NoContent", Err(ElicitationError::NoContent)),
        ("recusou", Err(ElicitationError::UserDeclined)),
        ("cancelou", Err(ElicitationError::UserCancelled)),
        ("erro JSON-RPC", Err(rpc_error())),
        ("malformado", Err(parse_error())),
        ("prazo", Err(timeout())),
        (
            "conexão caída",
            Err(ElicitationError::Service(ServiceError::TransportClosed)),
        ),
    ];
    for (name, result) in cases {
        let confirmation = confirmation_from(result);
        for flag in [false, true] {
            let decided = decide(&confirmation, flag);
            assert_eq!(
                decided.unwrap_err().code,
                "confirmation_denied",
                "{name} flag={flag}: {confirmation:?}"
            );
        }
    }
    assert_eq!(
        confirmation_from(Ok(Some(ConfirmStart { confirmo: true }))),
        Confirmation::Accepted
    );
    // Só "o cliente não declarou elicitação" depende da flag.
    let unsupported = confirmation_from(Err(ElicitationError::CapabilityNotSupported));
    assert_eq!(
        decide(&unsupported, false).unwrap_err().code,
        "confirmation_unavailable"
    );
    assert_eq!(decide(&unsupported, true).unwrap(), "unconfirmed-flag");
}

fn fake(work: &std::path::Path, policy: Elicit, extra: &[&str], env: &[(&str, &str)]) -> Client {
    let sessions = work.join("sessions");
    let mut args = vec!["--sessions-dir", sessions.to_str().unwrap()];
    args.extend_from_slice(extra);
    let mut client = Client::start_env(&fake_server(), &args, policy, env);
    client.handshake();
    client
}

fn start_args() -> Value {
    json!({"allowed_hosts": ["site.invalid.test"], "headless": true})
}

#[test]
fn malformed_or_failed_confirmation_never_opens_even_with_the_flag() {
    for policy in [
        Elicit::RpcError,
        Elicit::AcceptEmpty,
        Elicit::AcceptString,
        Elicit::AcceptNumber,
        Elicit::Decline,
        Elicit::AcceptUnchecked,
    ] {
        let work = tempfile::tempdir().unwrap();
        let mut client = fake(work.path(), policy, &["--allow-unconfirmed-capture"], &[]);
        let (is_error, out) = client.tool("start_capture", start_args());
        assert!(is_error, "{policy:?}: {out}");
        assert_eq!(
            out["error"]["code"], "confirmation_denied",
            "{policy:?}: {out}"
        );
        assert!(out.get("captureId").is_none());
        // A vaga voltou e nenhuma captura existe.
        let (_, list) = client.tool("list_sessions", json!({}));
        assert_eq!(list["total"], 0);
        client.finish();
    }
}

#[test]
fn confirmation_text_warns_that_the_port_is_only_enforced_on_navigate() {
    let work = tempfile::tempdir().unwrap();
    let mut client = fake(work.path(), Elicit::Accept, &[], &[]);
    client.tool("start_capture", start_args());
    let message = &client.elicitations[0];
    for needle in [
        "porta só é verificada",
        "navigate",
        "QUALQUER porta",
        "localhost",
    ] {
        assert!(message.contains(needle), "faltou {needle:?}: {message}");
    }
    client.finish();
}

// ---- M4: encerrar durante o início --------------------------------------------------

fn session_dirs(work: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(work.join("sessions"))
        .map(|d| {
            d.flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .starts_with("capture-")
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn eof_during_start_stops_the_browser_that_is_coming_up() {
    let work = tempfile::tempdir().unwrap();
    let mut client = fake(
        work.path(),
        Elicit::Accept,
        &[],
        &[("FAKE_START_DELAY_MS", "1500")],
    );
    client.call_nowait("start_capture", start_args());
    client.answer_next_elicitation();
    std::thread::sleep(std::time::Duration::from_millis(300)); // o "Chrome" ainda está subindo
    client.close_stdin();
    let (ok, stderr) = client.finish();
    assert!(ok, "{stderr}");
    let dirs = session_dirs(work.path());
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    assert!(
        dirs[0].join("session.json").is_file(),
        "a captura que subia foi parada e gravada"
    );
}

#[test]
fn sigterm_during_start_stops_the_browser_that_is_coming_up() {
    let work = tempfile::tempdir().unwrap();
    let mut client = fake(
        work.path(),
        Elicit::Accept,
        &[],
        &[("FAKE_START_DELAY_MS", "1500")],
    );
    client.call_nowait("start_capture", start_args());
    client.answer_next_elicitation();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let status = std::process::Command::new("kill")
        .args(["-TERM", &client.child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let exit = client.child.wait().unwrap();
    assert!(exit.success(), "{exit:?}");
    let dirs = session_dirs(work.path());
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    assert!(dirs[0].join("session.json").is_file());
}

// ---- P1: avisos do stop sem query/fragmento/matriz ------------------------------------

#[test]
fn stop_capture_warnings_carry_no_url_parameters() {
    let work = tempfile::tempdir().unwrap();
    let mut client = fake(work.path(), Elicit::Accept, &[], &[]);
    let (_, started) = client.tool("start_capture", start_args());
    let (_, stopped) = client.tool("stop_capture", json!({"capture_id": started["captureId"]}));
    let warnings = text(&stopped["warnings"]);
    assert!(
        warnings.contains("site.invalid.test:9/p"),
        "o aviso continua legível: {warnings}"
    );
    for secret in ["SEGREDO-VIOL", "SEGREDO-VIOLQ", "SEGREDO-VIOLF"] {
        assert!(
            !text(&stopped).contains(secret),
            "{secret} vazou: {stopped}"
        );
    }
    client.finish();
}

// ---- M5/B1/B2/B4: spill do get_body -----------------------------------------------------

fn big_body_env() -> (Env, std::path::PathBuf) {
    let env = Env::new(true);
    env.import_flow("flow", "");
    let out = get_body(
        &env.ctx,
        p(json!({"session_id": "flow", "request_id": "har-0003", "reveal": true})),
    )
    .unwrap();
    let path = std::path::PathBuf::from(out["path"].as_str().unwrap());
    (env, path)
}

#[test]
fn spill_refuses_a_planted_symlink_and_writes_0600() {
    let (env, path) = big_body_env();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // Planta um symlink no nome final e outro no que seria um temporário previsível.
    let outside = env.dir.path().join("fora.txt");
    std::fs::write(&outside, "ORIGINAL").unwrap();
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&outside, &path).unwrap();
    for planted in [".tmp-1", &format!(".tmp-{}", std::process::id())] {
        let _ = std::os::unix::fs::symlink(&outside, path.parent().unwrap().join(planted));
    }
    let again = get_body(
        &env.ctx,
        p(json!({"session_id": "flow", "request_id": "har-0003", "reveal": true})),
    )
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(&outside).unwrap(),
        "ORIGINAL",
        "o alvo do symlink não pode ser escrito"
    );
    let new_path = std::path::PathBuf::from(again["path"].as_str().unwrap());
    assert_eq!(new_path, path);
    let meta = std::fs::symlink_metadata(&new_path).unwrap();
    assert!(
        meta.file_type().is_file(),
        "o link foi substituído por arquivo regular"
    );
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert_eq!(meta.len(), 100_000);
}

#[test]
fn spill_refuses_symlinked_directories_without_touching_the_target() {
    let env = Env::new(true);
    env.import_flow("flow", "");
    let outside = env.dir.path().join("fora");
    std::fs::create_dir(&outside).unwrap();
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755)).unwrap();
    // `bodies` é um symlink para fora
    std::os::unix::fs::symlink(&outside, env.dir.path().join("out").join("bodies")).unwrap();
    let err = get_body(
        &env.ctx,
        p(json!({"session_id": "flow", "request_id": "har-0003", "reveal": true})),
    )
    .unwrap_err();
    assert_eq!(err.code, "outside_allowed_dir");
    assert_eq!(
        std::fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
        0o755,
        "o alvo não recebeu chmod"
    );
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
}

#[test]
fn concurrent_spills_do_not_mix_bytes_and_distinct_handles_do_not_collide() {
    let env = std::sync::Arc::new(Env::new(true));
    env.import_flow("x.y", "");
    env.import_flow("x-y", "-v2");
    let mut threads = Vec::new();
    for t in 0..8 {
        let env = env.clone();
        threads.push(std::thread::spawn(move || {
            let mut paths = Vec::new();
            for i in 0..10 {
                let handle = if (t + i) % 2 == 0 { "x.y" } else { "x-y" };
                let out = get_body(&env.ctx, p(json!({"session_id": handle, "request_id": "har-0003", "reveal": true, "offset": (i % 3) * 7, "length": 40_000}))).unwrap();
                paths.push((handle, i % 3, out["path"].as_str().unwrap().to_string()));
            }
            paths
        }));
    }
    let mut all = Vec::new();
    for t in threads {
        all.extend(t.join().unwrap());
    }
    for (_, _, path) in &all {
        assert_eq!(std::fs::read(path).unwrap().len(), 40_000, "{path}");
    }
    let dir = |h: &str| {
        all.iter()
            .find(|(x, _, _)| *x == h)
            .map(|(_, _, p)| std::path::Path::new(p).parent().unwrap().to_path_buf())
            .unwrap()
    };
    assert_ne!(
        dir("x.y"),
        dir("x-y"),
        "handles distintos não compartilham diretório de spill"
    );
}

// ---- binary_path: só o Chrome estável (usa o validador do capture/) ---------------------

#[test]
fn binary_path_that_is_not_chrome_is_refused_before_asking_the_user() {
    let work = tempfile::tempdir().unwrap();
    let sessions = work.path().join("sessions");
    let program = std::path::PathBuf::from(env!("CARGO_BIN_EXE_scrapelens-mcp"));
    let mut client = Client::start(
        &program,
        &["--sessions-dir", sessions.to_str().unwrap()],
        Elicit::Accept,
    );
    client.handshake();
    for bad in ["/bin/echo", "/usr/bin/true", "/nao/existe"] {
        let (is_error, out) = client.tool(
            "start_capture",
            json!({"allowed_hosts": ["site.invalid.test"], "binary_path": bad}),
        );
        assert!(is_error, "{bad}: {out}");
        assert_eq!(out["error"]["code"], "browser_invalid", "{bad}: {out}");
    }
    assert!(
        client.elicitations.is_empty(),
        "nada foi perguntado ao usuário"
    );
    client.finish();
}

// ---- cancelamento e aceite tardio ------------------------------------------------------

#[test]
fn cancelling_then_accepting_late_opens_nothing_and_frees_the_slot() {
    let work = tempfile::tempdir().unwrap();
    let mut client = fake(work.path(), Elicit::Accept, &[], &[]);
    let id = client.call_nowait("start_capture", start_args());
    let late = client.take_elicitation();
    client.cancel(id);
    std::thread::sleep(std::time::Duration::from_millis(400));
    client.accept_elicitation(&late); // aceite tardio: ignorado
    std::thread::sleep(std::time::Duration::from_millis(400));
    assert!(
        session_dirs(work.path()).is_empty(),
        "nada foi aberto: {:?}",
        session_dirs(work.path())
    );
    // A vaga está livre: um novo pedido pergunta de novo e abre.
    let (is_error, started) = client.tool("start_capture", start_args());
    assert!(!is_error, "{started}");
    assert_eq!(client.elicitations.len(), 2);
    assert_eq!(session_dirs(work.path()).len(), 1);
    let (ok, stderr) = client.finish();
    assert!(ok, "{stderr}");
}

#[test]
fn cancelling_while_the_browser_comes_up_stops_it_and_frees_the_slot() {
    let work = tempfile::tempdir().unwrap();
    let mut client = fake(
        work.path(),
        Elicit::Accept,
        &[],
        &[("FAKE_START_DELAY_MS", "1200")],
    );
    let id = client.call_nowait("start_capture", start_args());
    client.answer_next_elicitation(); // confirmou; o "Chrome" demora a subir
    std::thread::sleep(std::time::Duration::from_millis(300));
    client.cancel(id);
    // Quando o navegador ficar pronto, a captura é parada e gravada; a vaga volta.
    let mut started = None;
    for _ in 0..40 {
        let (is_error, out) = client.tool("start_capture", start_args());
        if !is_error {
            started = Some(out);
            break;
        }
        assert_eq!(out["error"]["code"], "capture_already_running", "{out}");
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    assert!(started.is_some(), "a vaga nunca voltou");
    let dirs = session_dirs(work.path());
    assert_eq!(dirs.len(), 2, "{dirs:?}");
    let stopped: Vec<_> = dirs
        .iter()
        .filter(|d| d.join("session.json").is_file())
        .collect();
    assert_eq!(
        stopped.len(),
        1,
        "a primeira captura foi parada e gravada: {dirs:?}"
    );
    client.finish();
}
