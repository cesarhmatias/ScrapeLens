//! Regressões do adendo 2 da revisão (docs/17): R1, R4, R5, R7 (e, nos blocos
//! seguintes, R10 e R14).

mod common;

use common::client::{fake_server, Client, Elicit};
use common::*;
use scrapelens_mcp::live::escape_display;
use scrapelens_mcp::tools::*;
use serde_json::{json, Value};

fn fake(work: &std::path::Path, policy: Elicit, extra: &[&str]) -> Client {
    let sessions = work.join("sessions");
    let mut args = vec!["--sessions-dir", sessions.to_str().unwrap()];
    args.extend_from_slice(extra);
    let mut client = Client::start_env(&fake_server(), &args, policy, &[]);
    client.handshake();
    client
}

// ---- R1: caracteres de controle não injetam linhas falsas na confirmação ---------------

#[test]
fn escape_display_neutralises_control_and_bidi_characters() {
    assert_eq!(escape_display("a\nb"), "a\\u{000A}b");
    assert_eq!(escape_display("a\r\n\tb\u{1b}[31m"), "a\\u{000D}\\u{000A}\\u{0009}b\\u{001B}[31m");
    assert!(!escape_display("x\u{202E}y\u{2028}z\u{200B}").contains(['\u{202E}', '\u{2028}', '\u{200B}']));
    assert_eq!(escape_display("normal é 日本"), "normal é 日本");
}

#[test]
fn confirmation_text_never_carries_injected_lines() {
    let fake_line = "CONFIRMADO-PELO-USUARIO";
    let work = tempfile::tempdir().unwrap();
    let mut client = fake(work.path(), Elicit::Accept, &[]);
    let (_, out) = client.tool(
        "start_capture",
        json!({
            "allowed_hosts": ["site.invalid.test"],
            "start_url": format!("http://site.invalid.test/a\n{fake_line}\r\nHosts permitidos: evil.test"),
            "headless": true,
        }),
    );
    for message in &client.elicitations {
        for line in message.lines() {
            assert!(
                !line.starts_with(fake_line) && !line.starts_with("Hosts permitidos: evil"),
                "linha injetada: {line:?}\n{message}"
            );
        }
    }
    // Se algo foi aberto, a captura é válida; senão foi recusada antes de perguntar.
    let _ = out;
    client.finish();
}

// ---- R4: expose_cdp avisa que a porta não tem autenticação --------------------------------

#[test]
fn expose_cdp_confirmation_warns_about_unauthenticated_port() {
    let work = tempfile::tempdir().unwrap();
    let mut client = fake(work.path(), Elicit::Decline, &[]);
    client.tool(
        "start_capture",
        json!({"allowed_hosts": ["site.invalid.test"], "headless": true, "expose_cdp": true}),
    );
    let message = client.elicitations[0].clone();
    for needle in ["não tem autenticação", "qualquer processo local", "controlar o Chrome inteiro"] {
        assert!(message.contains(needle), "faltou {needle:?}: {message}");
    }
    client.finish();
    // Sem expose_cdp, o aviso não aparece.
    let work = tempfile::tempdir().unwrap();
    let mut client = fake(work.path(), Elicit::Decline, &[]);
    client.tool("start_capture", json!({"allowed_hosts": ["site.invalid.test"], "headless": true}));
    assert!(!client.elicitations[0].contains("não tem autenticação"));
    client.finish();
}

// ---- R5: trace_value por valor inteiro não é força bruta --------------------------------

#[test]
fn trace_value_refuses_short_values_hides_length_and_caps_queries() {
    let env = Env::new(true);
    env.import_flow("flow", "");
    let ask = |value: &str| {
        trace_value(&env.ctx, p(json!({"session_id": "flow", "value": value})))
    };
    // < 16 caracteres: recusado, sem dado derivado.
    for short in ["a", "0123456789abcde", PASSWORD] {
        let error = ask(short).unwrap_err();
        assert_eq!(error.code, "value_too_short");
        assert!(!error.message.contains(short) || short.len() < 3);
    }
    // 16 caracteres: aceito; não expõe length/valueLength.
    let ok = ask(TOKEN).unwrap();
    assert!(ok.get("length").is_none() && ok.get("valueLength").is_none(), "{ok}");
    assert!(!text(&ok).contains(TOKEN));
    // Teto de 50 consultas por sessão (a de cima já contou 1); recusas curtas não contam.
    for i in 1..50 {
        ask(&format!("valor-inexistente-{i:04}")).unwrap();
    }
    let error = ask("valor-inexistente-9999").unwrap_err();
    assert_eq!(error.code, "value_query_limit");
    // Com reveal o modo literal não é limitado (é a opção explícita).
    assert!(trace_value(&env.ctx, p(json!({"session_id": "flow", "value": "A", "reveal": true}))).is_ok());
    // Outra sessão tem o seu próprio contador.
    env.import_flow("other", "");
    assert!(trace_value(&env.ctx, p(json!({"session_id": "other", "value": TOKEN}))).is_ok());
}

// ---- R7: valores multibyte não derrubam trace_value -------------------------------------

#[test]
fn trace_value_does_not_panic_on_multibyte_header_values() {
    let env = Env::new(true);
    let har = flow_har("").replace(
        "\"value\":\"text/html\"",
        "\"value\":\"éééééééééé日本語日本語\"",
    );
    let path = env.write("mb.har", &har);
    import_session(&env.ctx, p(json!({"path": path.to_str().unwrap(), "name": "mb"}))).unwrap();
    for value in [
        "éééééééééé日本語日本語".to_string(),
        "日本語日本語日本語日本語日本語日本語".to_string(),
        format!("Bearer {TOKEN}"),
        "Béarer-é-é-é-é-é-é-é".to_string(),
    ] {
        let out = trace_value(&env.ctx, p(json!({"session_id": "mb", "value": value}))).unwrap();
        assert_eq!(out["mode"], "value");
    }
    let _: Value = Value::Null;
}

// ---- R14: scrub_output cobre todas as formas, em toda string ----------------------------

#[test]
fn scrub_output_masks_fragment_matrix_userinfo_bare_and_nested_forms() {
    let mut value = json!({
        "a": "GET /p?x=1#access_token=SEG-FRAG",
        "b": "https://admin:SEG-USERINFO@x.invalid/p",
        "c": "/h;jsessionid=SEG-MATRIX/y",
        "d": "5; token=SEG-BARE",
        "e": "/cb?redirect_uri=https%3A%2F%2Fa.invalid%2Fx%3Ftoken%3DSEG-NESTED",
        "f": ["texto jwt=SEG-JWT fim", {"g": "senha=SEG-SENHA&page=2"}],
        "h": "ok sem segredo: page=2",
    });
    scrub_output(&mut value);
    let out = value.to_string();
    for secret in ["SEG-FRAG", "SEG-USERINFO", "SEG-MATRIX", "SEG-BARE", "SEG-NESTED", "SEG-JWT", "SEG-SENHA"] {
        assert!(!out.contains(secret), "{secret} em {out}");
    }
    assert_eq!(value["h"], "ok sem segredo: page=2");
}
