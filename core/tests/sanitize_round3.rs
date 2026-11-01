//! Regressão da terceira revisão (A3-M2, A3-B1, A3-B4): valores de parâmetros
//! não sensíveis são analisados recursivamente (URL, query aninhada, `nome=valor`),
//! com ou sem `%`; codificação dupla; Bearer/Basic em texto livre.

use scrapelens_core::export::sanitize::{sanitize_text, sanitize_url, SanitizeOptions};

fn opts() -> SanitizeOptions {
    SanitizeOptions::default()
}

fn assert_masked(text: &str, secrets: &[&str]) {
    let out = sanitize_text(text, &opts());
    for secret in secrets {
        assert!(!out.contains(secret), "{secret} sobrou em {text:?} -> {out:?}");
    }
}

#[test]
fn nested_values_of_non_sensitive_params_are_scanned_plain_or_encoded() {
    for (text, secret) in [
        ("next=/cb?token=SECR1x", "SECR1x"),
        ("redirect=https://h/cb?access_token=SECR2x&y=1", "SECR2x"),
        ("a=1&next=/cb?token=SECR3x", "SECR3x"),
        ("go next=/cb?token=SECR10x done", "SECR10x"),
        ("redirect=https://h.invalid/cb?access_token=SECR9x", "SECR9x"),
        ("{\"note\":\"next=/cb?token=SECR11x\"}", "SECR11x"),
        ("/cb?next=/x?access_token=SECR12x", "SECR12x"),
        ("next=%2Fcb?token=SECR13x", "SECR13x"),
        ("x=%41 y=/cb?token=SECR14x", "SECR14x"),
    ] {
        assert_masked(text, &[secret]);
    }
    // Refresh com url=… volta a ser redigido (regressão do 5cdac78).
    let out = sanitize_text("0;url=/d?pin=1234&page=2", &opts());
    assert!(!out.contains("1234"), "{out}");
    assert!(out.contains("page=2"), "{out}");
    // O que não é segredo continua legível.
    assert_eq!(sanitize_text("0;url=/d?page=2&q=abc", &opts()), "0;url=/d?page=2&q=abc");
    assert_eq!(sanitize_text("value=/a?b=c", &opts()), "value=/a?b=c");
}

#[test]
fn nested_values_in_urls_are_scanned_plain_or_encoded() {
    for (url, secret) in [
        ("https://h/r?next=/cb?token=URL1x", "URL1x"),
        ("https://h/r?c=%2Fcb%253Ftoken%253DURL2x", "URL2x"),
        ("https://h/r?d=https%3A%2F%2Fh%2Fcb%253Faccess_token%253DURL3x", "URL3x"),
        ("https://h/r?f=%2Fx%3Ftoken+%3DURL4x", "URL4x"),
        ("https://h/r?e=%2Fx%3Ftoken%3dURL5x", "URL5x"),
        ("https://h/r?g=%252Fx%253Ftoken%253DURL6x", "URL6x"),
        ("https://h/r?next=/a?n=/b?token=URL7x", "URL7x"),
    ] {
        let out = sanitize_url(url, &opts());
        assert!(!out.contains(secret), "{secret} sobrou em {url} -> {out}");
    }
    assert_eq!(
        sanitize_url("https://h/r?next=/cb?page=2&q=1", &opts()),
        "https://h/r?next=/cb?page=2&q=1"
    );
}

#[test]
fn double_and_triple_encoding_and_plus_before_encoded_equals() {
    for (text, secret) in [
        ("x%253D1%2526token%253DSECR4x", "SECR4x"),
        ("next=%2Fcb%253Ftoken%253DSECR5x", "SECR5x"),
        ("next=%252Fcb%253Ftoken%253DSECR6x", "SECR6x"),
        ("next=%2Fcb%3Ftoken%3dSECR7x", "SECR7x"),
        ("q=%2Fcb%3Ftoken%3DSECR8x+more", "SECR8x"),
        ("token+%3DSECR15x", "SECR15x"),
        ("f=%2Fx%3Ftoken+%3DSECR16x", "SECR16x"),
        ("c=%2Fcb%253Ftoken%253DSECR17x", "SECR17x"),
        ("X-Dbl: x%253D1%2526token%253DSECR18x", "SECR18x"),
        // 3 rodadas de codificação
        ("n=%25252Fcb%25253Ftoken%25253DSECR19x", "SECR19x"),
    ] {
        assert_masked(text, &[secret]);
    }
}

#[test]
fn bearer_and_basic_in_free_text_any_case_any_whitespace() {
    for (text, secret) in [
        ("bearer SEC4abcdef", "SEC4abcdef"),
        ("Authorization falhou: Bearer\tSEC5abcdef fim", "SEC5abcdef"),
        ("BASIC  \t YWRtaW46UElO", "YWRtaW46UElO"),
        ("Basic\tSEC9", "SEC9"),
        ("header Bearer\n\tSEC20abcdef", "SEC20abcdef"),
    ] {
        assert_masked(text, &[secret]);
    }
    // Prosa e texto já redigido não mudam.
    assert_eq!(sanitize_text("Basic authentication required", &opts()), "Basic authentication required");
    assert_eq!(sanitize_text("Bearer [REDACTED]", &opts()), "Bearer [REDACTED]");
    assert_eq!(sanitize_text("sem esquema aqui", &opts()), "sem esquema aqui");
    // UTF-8 não derruba a varredura.
    let _ = sanitize_text("bearer é日本語 e Basic\u{a0}日本語日本語", &opts());
}

#[test]
fn pathological_inputs_stay_linear_and_do_not_panic() {
    let start = std::time::Instant::now();
    let mut inputs = vec![
        "a=%3Fb%3Dc&".repeat(100_000),
        "a=%b=%b=%b=".repeat(100_000),
        format!("x={}", "%25".repeat(300_000)),
        "n=%3F%3D".repeat(150_000),
        "bearer ".repeat(100_000),
    ];
    inputs.push("%2525".repeat(200_000));
    for input in &inputs {
        let _ = sanitize_text(input, &opts());
        let _ = sanitize_url(&format!("https://h/r?{input}"), &opts());
    }
    assert!(start.elapsed().as_secs() < 30, "lento: {:?}", start.elapsed());
}
