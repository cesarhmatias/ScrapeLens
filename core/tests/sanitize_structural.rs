//! Desenho estrutural do sanitizador de texto (um tokenizador por nível):
//! fidelidade do caminho (A5-M1), `+`/`%2B`/`%2520`/`%2526`/`%2523` dentro de
//! credenciais aninhadas (A5-M2), valores entre aspas/parênteses e depois de
//! espaço (A5-B1) e um teste de propriedade com segredo marcado em posições
//! aleatórias e 0 a 3 níveis de codificação.

use scrapelens_core::export::sanitize::{
    sanitize_path_and_query, sanitize_text, sanitize_url, SanitizeOptions,
};

const P: &str = "%5BREDACTED%5D";

fn o() -> SanitizeOptions {
    SanitizeOptions::default()
}

// ---- A5-M1: um parâmetro de matriz redigido não come o resto do caminho ------------------

#[test]
fn matrix_param_redaction_keeps_the_following_path_segments() {
    let o = o();
    assert_eq!(
        sanitize_path_and_query("/a;jsessionid=SECRETX/b/c?x=1", &o),
        format!("/a;jsessionid={P}/b/c?x=1")
    );
    assert_eq!(
        sanitize_path_and_query("/users;token=SECRETX/profile/123?page=2", &o),
        format!("/users;token={P}/profile/123?page=2")
    );
    assert_eq!(
        sanitize_url("https://h/a;jsessionid=SECRETX/b/c?x=1", &o),
        format!("https://h/a;jsessionid={P}/b/c?x=1")
    );
    assert_eq!(
        sanitize_path_and_query("/a;v=2/b;token=SECRETX/c", &o),
        format!("/a;v=2/b;token={P}/c")
    );
    // `session` é nome sensível: um segmento `session=X` também é redigido (A6-M1),
    // mantendo o resto do caminho.
    assert_eq!(
        sanitize_path_and_query("/a;v=2/session=keep/b", &o),
        format!("/a;v=2/session={P}/b")
    );
    // O que não é segredo (inclusive `nome=valor` num segmento) fica igual.
    for same in ["/a;lang=en/x=1/y=2", "/a;v=1/b?page=2"] {
        assert_eq!(sanitize_path_and_query(same, &o), same);
    }
    // Valor aninhado que atravessa segmentos continua sendo visto.
    let out = sanitize_url("https://h/r;next=/cb%3Ftoken=SECRETX/z", &o);
    assert!(!out.contains("SECRETX") && out.ends_with("/z"), "{out}");
}

// ---- A5-M2: separadores que só aparecem depois da decodificação pertencem ao nível de baixo

#[test]
fn encoded_separators_inside_a_credential_do_not_cut_it() {
    let o = o();
    for secret_tail in [
        "ab%2BQPLUSx",   // %2B
        "ab%2520QSPx",   // %2520 → %20 → espaço no nível 2
        "ab%2526QAMPx",  // %2526 → %26 → &
        "ab%2523QHASHx", // %2523 → %23 → #
        "ab%253BQSEMIx", // ;
        "ab%2522QQUOTx", // "
        "AAA%2BBBB%2FCCC%3D%3Dx",
        "ab%252BQPLUS2x%252Fef",
    ] {
        let text = format!("next=%2Fcb%3Ftoken%3D{secret_tail}");
        let out = sanitize_text(&text, &o);
        let marker = secret_tail
            .rsplit(['B', 'P', 'C', 'D', 'T', 'H'])
            .next()
            .unwrap_or("");
        assert!(
            !out.contains("QPLUS")
                && !out.contains("QSP")
                && !out.contains("QAMP")
                && !out.contains("QHASH")
                && !out.contains("QSEMI")
                && !out.contains("QQUOT")
                && !out.contains("CCC")
                && !out.contains("%252Fef"),
            "{secret_tail}: {out} ({marker})"
        );
        let url = sanitize_url(
            &format!(
                "https://h/r?redirect_uri=https%3A%2F%2Fh%2Fcb%3Faccess_token%3D{secret_tail}&x=1"
            ),
            &o,
        );
        assert!(
            !url.contains("QPLUS")
                && !url.contains("QSP")
                && !url.contains("QAMP")
                && !url.contains("QHASH")
                && !url.contains("QSEMI")
                && !url.contains("QQUOT")
                && !url.contains("CCC"),
            "{secret_tail}: {url}"
        );
        assert!(
            url.ends_with("&x=1") || url.contains("&x=1"),
            "o resto da query fica: {url}"
        );
    }
}

// ---- A5-B1: valores entre aspas, parênteses ou depois de espaço ----------------------------

#[test]
fn quoted_parenthesised_and_spaced_values_are_redacted_whole() {
    let o = o();
    for (text, secret, keep) in [
        ("token=\"SEC1 with spaces\" fim", "SEC1", "fim"),
        ("token='SEC2 x y' fim", "SEC2", "fim"),
        ("token=(SEC3 a b) fim", "SEC3", "fim"),
        ("token= SEC4 fim", "SEC4", "fim"),
        ("token = SEC5 fim", "SEC5", "fim"),
        ("token =SEC6 fim", "SEC6", "fim"),
        ("token\t=SEC7 fim", "SEC7", "fim"),
        ("token=<SEC8> fim", "SEC8", "fim"),
        ("a=1 token=\"SEC9\" b=2", "SEC9", "b=2"),
        ("password= \"SEC10 x\"; ok=1", "SEC10", "ok=1"),
    ] {
        let out = sanitize_text(text, &o);
        assert!(!out.contains(secret), "{text} -> {out}");
        assert!(out.contains(keep), "{text} -> {out}");
        if secret == "SEC1" {
            assert!(!out.contains("spaces"), "{out}");
        }
    }
    // `a = b` e prosa continuam iguais.
    for same in ["a = b and x=1, y=2", "x=1", "abc==", "if (a==b) { c = d; }"] {
        assert_eq!(sanitize_text(same, &o), same);
    }
}

// ---- propriedade: segredo marcado em posições aleatórias, 0 a 3 níveis de codificação -------

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn pick<'a, T>(&mut self, list: &'a [T]) -> &'a T {
        &list[(self.next() as usize) % list.len()]
    }
}

/// Codifica um nível: tudo que não é alfanumérico vira `%XX`.
fn encode_level(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[test]
fn marked_secret_never_survives_and_the_rest_stays_equal() {
    let names = [
        "token",
        "access_token",
        "password",
        "jwt",
        "senha",
        "pwd",
        "passcode",
        "api_key",
        "jsessionid",
    ];
    let tails = [
        "",
        "&x=1",
        "&page=2&sort=asc",
        "#frag",
        " fim",
        ";p=1",
        "\" fim",
    ];
    let heads = [
        "",
        "GET /cb?",
        "redirect=",
        "next=",
        "X-Note: ",
        "u=1&",
        "a=b=",
        "/p;",
    ];
    // segredo com caracteres base64 que cada nível transforma em escapes
    let secrets = [
        "ZQ9kd2Xm",
        "AAA+ZQ9tail/ZQ9rest==",
        "ab-cd_ef.ZQ9gh",
        "x y ZQ9sp",
    ];
    let mut rng = Lcg(0x5eed_1234_abcd_ef01);
    let opts = o();
    let mut checked = 0;
    for round in 0..4000 {
        let name = *rng.pick(&names);
        let secret = *rng.pick(&secrets);
        // `x y …` só vale entre aspas; o restante é um valor corrido
        let quoted = secret.contains(' ');
        let levels = (rng.next() % 4) as usize; // 0..=3
        let value = if quoted {
            format!("\"{secret}\"")
        } else {
            secret.to_string()
        };
        let mut inner = format!("{name}={value}");
        // o nome/valor vai embrulhado em 0..=3 níveis de codificação
        let mut wrapped_head = String::new();
        for level in 0..levels {
            inner = encode_level(&inner);
            let _ = level;
        }
        // sempre um prefixo benigno e um sufixo benigno, que não podem mudar
        let head = *rng.pick(&heads);
        let tail = if levels > 0 && quoted {
            ""
        } else {
            *rng.pick(&tails)
        };
        if levels > 0 {
            // nível 1+ precisa de um parâmetro externo não sensível para carregar o valor
            wrapped_head = "carrier=".to_string();
        }
        let benign_prefix = "BENIGNPRE";
        let text = format!("{benign_prefix} {head}{wrapped_head}{inner}{tail} BENIGNPOST");
        let out = sanitize_text(&text, &opts);
        // O segredo (cada pedaço alfanumérico longo) nunca aparece, cru ou codificado.
        for needle in ["ZQ9kd2Xm", "ZQ9tail", "ZQ9rest", "ZQ9gh", "ZQ9sp"] {
            assert!(
                !out.contains(needle),
                "round {round}: {needle} em {out:?} (de {text:?})"
            );
        }
        // O resto do texto continua igual.
        assert!(out.starts_with("BENIGNPRE "), "round {round}: {out:?}");
        assert!(out.ends_with(" BENIGNPOST"), "round {round}: {out:?}");
        if head == "GET /cb?" {
            assert!(out.contains("GET /cb?"), "{out:?}");
        }
        // Idempotência: sanitizar o resultado de novo não muda nada.
        assert_eq!(
            sanitize_text(&out, &opts),
            out,
            "round {round}: não idempotente: {text:?}"
        );
        checked += 1;
    }
    assert_eq!(checked, 4000);
}

#[test]
fn marked_secret_in_urls_at_random_positions_and_levels() {
    let names = ["token", "access_token", "password", "jwt", "pwd"];
    let mut rng = Lcg(0xfeed_beef_0123_4567);
    let opts = o();
    for round in 0..3000 {
        let name = *rng.pick(&names);
        let secret = *rng.pick(&["ZQ9kd2Xm", "AAA+ZQ9tail/ZQ9rest==", "ab%2Bcd"]);
        let levels = (rng.next() % 4) as usize;
        let mut inner = format!("/cb?{name}={secret}&z=1");
        for _ in 0..levels {
            inner = encode_level(&inner);
        }
        let shape = rng.next() % 4;
        let url = match shape {
            0 => format!("https://h.invalid/r?benign=1&next={inner}&keep=yes"),
            1 => format!("https://h.invalid/r;next={inner}/tail?keep=yes"),
            2 => format!("https://h.invalid/p/q?{name}={secret}&keep=yes"),
            _ => format!("/r?benign=1&next={inner}&keep=yes"),
        };
        let out = if url.starts_with("http") {
            sanitize_url(&url, &opts)
        } else {
            sanitize_path_and_query(&url, &opts)
        };
        for needle in ["ZQ9kd2Xm", "ZQ9tail", "ZQ9rest"] {
            assert!(
                !out.contains(needle),
                "round {round}: {needle} em {out:?} (de {url:?})"
            );
        }
        assert!(
            out.contains("keep=yes"),
            "round {round}: perdeu o resto: {out:?} (de {url:?})"
        );
        assert!(
            out.contains("benign=1") || shape == 2 || shape == 1,
            "round {round}: {out:?}"
        );
        if shape == 1 {
            assert!(
                out.contains("/tail"),
                "round {round}: perdeu o caminho: {out:?}"
            );
        }
    }
}

#[test]
fn html_entity_equals_and_unicode_space_after_scheme() {
    let o = o();
    for (text, secret) in [
        ("token&#61;ENT1x", "ENT1x"),
        ("note token&#x3D;ENT2x fim", "ENT2x"),
        ("token&equals;ENT3x", "ENT3x"),
        (
            "auth bearer\tTABTOK02x; Basic\u{3000}WIDESP03x",
            "WIDESP03x",
        ),
        ("Bearer\u{a0}NBSPTOK04x", "NBSPTOK04x"),
    ] {
        let out = sanitize_text(text, &o);
        assert!(!out.contains(secret), "{text:?} -> {out:?}");
    }
    assert_eq!(sanitize_text("a &amp; b &#61; c", &o), "a &amp; b &#61; c");
}

#[test]
fn redaction_is_idempotent() {
    let o = o();
    for text in [
        "GET /cb?token=SEC1x&page=2 HTTP/1.1",
        "next=%2Fcb%3Ftoken%3Dab%2BSEC2x&z=1",
        "token=\"SEC3x y\" fim",
        "token=(SEC4x) Bearer abc.DEF.ghi5",
        "auth bearer\tSEC6x; Basic\u{3000}SEC7x",
        "https://u:SEC8x@h/p;jsessionid=SEC9x/q?access_token=SEC10x#frag",
    ] {
        let once = sanitize_text(text, &o);
        assert_eq!(sanitize_text(&once, &o), once, "{text}");
    }
}
