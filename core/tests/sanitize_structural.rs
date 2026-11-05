//! Structural design of the text sanitizer (one tokenizer per level):
//! path fidelity (A5-M1), `+`/`%2B`/`%2520`/`%2526`/`%2523` inside nested
//! credentials (A5-M2), values in quotes/parentheses and after a space
//! (A5-B1), and a property test with a marked secret at random positions and
//! 0 to 3 encoding levels.

use scrapelens_core::export::sanitize::{
    sanitize_path_and_query, sanitize_text, sanitize_url, SanitizeOptions,
};

const P: &str = "%5BREDACTED%5D";

fn o() -> SanitizeOptions {
    SanitizeOptions::default()
}

// ---- A5-M1 / A7-B5 / A8-M1: the value of a sensitive name in a path runs up to `?` or the end -----

#[test]
fn sensitive_value_in_a_path_runs_to_the_query_and_non_sensitive_names_are_untouched() {
    let o = o();
    // Decision A8: a credential may contain `/`; security takes precedence over fidelity.
    // The rest of the PATH after the sensitive name goes along; the query stays.
    assert_eq!(
        sanitize_path_and_query("/a;jsessionid=SECRETX/b/c?x=1", &o),
        format!("/a;jsessionid={P}?x=1")
    );
    assert_eq!(
        sanitize_path_and_query("/users;token=SECRETX/profile/123?page=2", &o),
        format!("/users;token={P}?page=2")
    );
    assert_eq!(
        sanitize_url("https://h/a;jsessionid=SECRETX/b/c?x=1", &o),
        format!("https://h/a;jsessionid={P}?x=1")
    );
    assert_eq!(
        sanitize_path_and_query("/a;v=2/b;token=SECRETX/c", &o),
        format!("/a;v=2/b;token={P}")
    );
    assert_eq!(
        sanitize_path_and_query("/a;v=2/session=keep/b", &o),
        format!("/a;v=2/session={P}")
    );
    // Same result on the TEXT path (request line, header, JSON).
    assert_eq!(
        sanitize_text("GET /a;jsessionid=SECRETX/b/c?x=1 HTTP/1.1", &o),
        format!("GET /a;jsessionid={P}?x=1 HTTP/1.1")
    );
    assert_eq!(
        sanitize_text("/a;v=2/session=keep/b", &o),
        format!("/a;v=2/session={P}")
    );
    // A credential with slashes (base64) is redacted whole.
    for secret in [
        "GET /s;token=Zm9vYmFy/YmF6cXV4 HTTP/1.1",
        "/api/token=/secret1/value2",
        "?next=%2Fa%3Btoken%3DAbCdEfGh%2FIjKlMnOp",
        "/p?x=1/token=abc/def",
    ] {
        let out = sanitize_text(secret, &o);
        for tail in ["YmF6cXV4", "secret1", "value2", "IjKlMnOp", "/def"] {
            assert!(!out.contains(tail), "{tail} in {out} (from {secret})");
        }
    }
    // NON-sensitive names change nothing and the rest of the path is still examined.
    for same in ["/a;lang=en/x=1/y=2", "/a;v=1/b?page=2", "/a;v=2/b/c"] {
        assert_eq!(sanitize_path_and_query(same, &o), same);
    }
    let out = sanitize_url("https://h/r;next=/cb%3Ftoken=SECRETX/z", &o);
    assert!(!out.contains("SECRETX"), "{out}");
    let out = sanitize_text("/a;v=2/b/token=SECRETX", &o);
    assert!(
        out.starts_with("/a;v=2/b/token=") && !out.contains("SECRETX"),
        "{out}"
    );
}

// ---- A8-M2: linear cost for values with many slashes -----------------------------------

#[test]
fn many_slashes_cost_linear_time() {
    let o = o();
    let budget = if cfg!(debug_assertions) { 20_000 } else { 500 };
    for (label, input) in [
        ("A=/", "A=/".repeat(4_000_000 / 3)),
        (
            "/a;token= + (A×16 + /)*",
            format!("/a;token={}", "AAAAAAAAAAAAAAAA/".repeat(4_000_000 / 17)),
        ),
        ("/t=x/", "/t=x/".repeat(4_000_000 / 5)),
        (
            "a;token=x/",
            format!("/p{}", ";token=x/".repeat(4_000_000 / 9)),
        ),
    ] {
        for (kind, run) in [("text", 0), ("url", 1), ("pq", 2)] {
            let started = std::time::Instant::now();
            let _ = match run {
                0 => sanitize_text(&input, &o),
                1 => sanitize_url(&format!("https://h{input}"), &o),
                _ => sanitize_path_and_query(&input, &o),
            };
            let ms = started.elapsed().as_millis();
            assert!(ms < budget, "{label} {kind}: {ms} ms (limit {budget})");
        }
    }
}

// ---- A5-M2: separators that only appear after decoding belong to the lower level

#[test]
fn encoded_separators_inside_a_credential_do_not_cut_it() {
    let o = o();
    for secret_tail in [
        "ab%2BQPLUSx",   // %2B
        "ab%2520QSPx",   // %2520 → %20 → space at level 2
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
            "the rest of the query stays: {url}"
        );
    }
}

// ---- A5-B1: values in quotes, parentheses or after a space ----------------------------

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
    // `a = b` and prose stay the same.
    for same in ["a = b and x=1, y=2", "x=1", "abc==", "if (a==b) { c = d; }"] {
        assert_eq!(sanitize_text(same, &o), same);
    }
}

// ---- property: marked secret at random positions, 0 to 3 encoding levels -------

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

/// Encodes one level: everything that is not alphanumeric becomes `%XX`.
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
    // secret with base64 characters that each level turns into escapes
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
        // `x y …` only counts inside quotes; the rest is a bare value
        let quoted = secret.contains(' ');
        let levels = (rng.next() % 4) as usize; // 0..=3
        let value = if quoted {
            format!("\"{secret}\"")
        } else {
            secret.to_string()
        };
        let mut inner = format!("{name}={value}");
        // the name/value is wrapped in 0..=3 encoding levels
        let mut wrapped_head = String::new();
        for level in 0..levels {
            inner = encode_level(&inner);
            let _ = level;
        }
        // always a benign prefix and a benign suffix, which must not change
        let head = *rng.pick(&heads);
        let tail = if levels > 0 && quoted {
            ""
        } else {
            *rng.pick(&tails)
        };
        if levels > 0 {
            // level 1+ needs an external non-sensitive parameter to carry the value
            wrapped_head = "carrier=".to_string();
        }
        let benign_prefix = "BENIGNPRE";
        let text = format!("{benign_prefix} {head}{wrapped_head}{inner}{tail} BENIGNPOST");
        let out = sanitize_text(&text, &opts);
        // The secret (each long alphanumeric piece) never appears, raw or encoded.
        for needle in ["ZQ9kd2Xm", "ZQ9tail", "ZQ9rest", "ZQ9gh", "ZQ9sp"] {
            assert!(
                !out.contains(needle),
                "round {round}: {needle} in {out:?} (from {text:?})"
            );
        }
        // The rest of the text stays the same.
        assert!(out.starts_with("BENIGNPRE "), "round {round}: {out:?}");
        assert!(out.ends_with(" BENIGNPOST"), "round {round}: {out:?}");
        if head == "GET /cb?" {
            assert!(out.contains("GET /cb?"), "{out:?}");
        }
        // Idempotence: sanitizing the result again changes nothing.
        assert_eq!(
            sanitize_text(&out, &opts),
            out,
            "round {round}: not idempotent: {text:?}"
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
                "round {round}: {needle} in {out:?} (from {url:?})"
            );
        }
        assert!(
            out.contains("keep=yes"),
            "round {round}: lost the rest: {out:?} (from {url:?})"
        );
        assert!(
            out.contains("benign=1") || shape == 2 || shape == 1,
            "round {round}: {out:?}"
        );
        if shape == 1 {
            assert!(
                out.contains("/tail"),
                "round {round}: lost the path: {out:?}"
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

// ---- A7-B6: group above 1 MiB with %XX -------------------------------------------------

#[test]
fn oversize_group_is_redacted_only_when_a_sensitive_name_is_in_it_or_it_cannot_be_decided() {
    let o = o();
    // 3 MiB of `a=%3Fb%3Dc` (nothing sensitive): passes through intact, names included.
    let benign = format!("x={}", "a%3Fb%3Dc".repeat((3 << 20) / 9));
    assert!(benign.len() > (1 << 20));
    assert_eq!(sanitize_text(&benign, &o), benign);
    // Same size with an encoded sensitive name in the middle: the group is redacted.
    let sensitive = format!(
        "x={}token%3DSEC1x{}",
        "a%3Fb%3Dc".repeat((2 << 20) / 9),
        "a%3Fb%3Dc".repeat((2 << 20) / 9)
    );
    let out = sanitize_text(&sensitive, &o);
    assert!(!out.contains("SEC1x") && out.len() < 100, "{}", out.len());
    // Sensitive only at a deep level (3 encoding levels) is also seen.
    let deep = format!(
        "x={}%2525253Ftoken%2525253DSEC2x",
        "a%3Fb%3Dc".repeat((2 << 20) / 9)
    );
    let out = sanitize_text(&deep, &o);
    assert!(!out.contains("SEC2x") && out.len() < 100, "{}", out.len());
    // Cannot decide (an escape with 40 layers of `%25`, more than the round ceiling):
    // fails closed, even without a visible sensitive name.
    let undecidable = format!(
        "x={}%{}41",
        "a%3Fb%3Dc".repeat((2 << 20) / 9),
        "25".repeat(40)
    );
    let out = sanitize_text(&undecidable, &o);
    assert!(out.len() < 100, "{}", out.len());
    // %25 chain short enough to decide and with no sensitive name: intact.
    let decidable = format!("x={}", "%2541".repeat((2 << 20) / 5));
    assert_eq!(sanitize_text(&decidable, &o), decidable);
}
