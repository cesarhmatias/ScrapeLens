//! Regression from the third review (A3-M2, A3-B1, A3-B4): values of non-sensitive
//! parameters are analyzed recursively (URL, nested query, `name=value`), with or
//! without `%`; double encoding; Bearer/Basic in free text.

use scrapelens_core::export::sanitize::{sanitize_text, sanitize_url, SanitizeOptions};

fn opts() -> SanitizeOptions {
    SanitizeOptions::default()
}

fn assert_masked(text: &str, secrets: &[&str]) {
    let out = sanitize_text(text, &opts());
    for secret in secrets {
        assert!(!out.contains(secret), "{secret} survived in {text:?} -> {out:?}");
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
    // Refresh with url=… is redacted again (regression of 5cdac78).
    let out = sanitize_text("0;url=/d?pin=1234&page=2", &opts());
    assert!(!out.contains("1234"), "{out}");
    assert!(out.contains("page=2"), "{out}");
    // What is not a secret stays readable.
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
        assert!(!out.contains(secret), "{secret} survived in {url} -> {out}");
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
        // 3 encoding rounds
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
    // Prose and already-redacted text do not change.
    assert_eq!(sanitize_text("Basic authentication required", &opts()), "Basic authentication required");
    assert_eq!(sanitize_text("Bearer [REDACTED]", &opts()), "Bearer [REDACTED]");
    assert_eq!(sanitize_text("sem esquema aqui", &opts()), "sem esquema aqui");
    // UTF-8 does not break the scan.
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
    assert!(start.elapsed().as_secs() < 30, "slow: {:?}", start.elapsed());
}

// ---- A4-M1: mixed encoding and chains `a=b=token=X` --------------------------------------

#[test]
fn mixed_encoding_and_chained_equals_do_not_leak() {
    for (text, secret) in [
        ("next=%2Fcb%3Ftoken=MIX1x", "MIX1x"),
        ("redirect=https%3A%2F%2Fh%2Fcb%3Faccess_token=MIX2x&z=1", "MIX2x"),
        ("next=/cb%3Ftoken=MIX3x", "MIX3x"),
        ("X-Note3: next=%2Fcb%3Ftoken=MIX4x", "MIX4x"),
        ("{\"mix1\":\"next=%2Fcb%3Ftoken=MIX5x\"}", "MIX5x"),
        ("{\"mix2\":\"redirect=https%3A%2F%2Fh%2Fcb%3Faccess_token=MIXED02x\"}", "MIXED02x"),
        ("a=b=token=CH1x", "CH1x"),
        ("q=%3D=token=EQ6x", "EQ6x"),
        ("u=%2F?token=Q7x", "Q7x"),
        ("x=%41;token=SEMI3x", "SEMI3x"),
        ("x=%2F%3Fa%3Db&token=AMP1x", "AMP1x"),
        ("a=%2F%3F&b=1%3D&token=AMP4x", "AMP4x"),
        ("a=1%26token=AMP5x", "AMP5x"),
        ("a=1%23access_token=FRAG6x", "FRAG6x"),
        ("a=1%3Bjsessionid=SEMI7x", "SEMI7x"),
    ] {
        assert_masked(text, &[secret]);
    }
    for (url, secret) in [
        ("https://h/r;next=/cb%3Ftoken=URL8x", "URL8x"),
        ("https://h/r?a=b=token=URL6x", "URL6x"),
        ("https://h/r?x=%41&token=URL9x", "URL9x"),
        ("/p?next=%2Fcb%3Ftoken=PQ1x", "PQ1x"),
        ("https://h/r;next=%2Fcb%3Ftoken=URL10x", "URL10x"),
    ] {
        let out = sanitize_url(url, &opts());
        assert!(!out.contains(secret), "{secret} survived in {url} -> {out}");
        let pq = scrapelens_core::export::sanitize::sanitize_path_and_query(url, &opts());
        assert!(!pq.contains(secret), "{secret} survived (pq) in {url} -> {pq}");
    }
    // Nothing that was already readable is erased.
    assert_eq!(sanitize_text("a=1&b=2&page=3", &opts()), "a=1&b=2&page=3");
    assert_eq!(sanitize_text("next=%2Fcb%3Fpage%3D2", &opts()), "next=%2Fcb%3Fpage%3D2");
    assert_eq!(sanitize_text("q=%2Fshoes%3Fsort=asc", &opts()), "q=%2Fshoes%3Fsort=asc");
}
