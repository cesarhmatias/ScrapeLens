//! Deterministic fuzz of the Reviewer (round 30), incorporated into the repository.
//! Oracles: (1) a secret (marker "ZQ..") in a sensitive-name position never leaks;
//! (2) non-secret context bytes (PRE/SUF separated by spaces and the sibling
//! `&page=KEEP`) remain; (3) idempotence; (4) no panic.
//! Sizes: `FUZZ_N` (main; 3000 by default) and `SOUP_N` (soup, x3 functions;
//! 3000 by default); `SEED` changes the seed. The Reviewer's full round is
//! `FUZZ_N=150000 SOUP_N=100000 cargo test --release --test corpus_fuzz`.
//! At the 8-level ceiling the sanitizer FAILS CLOSED: the value runs to the end of the
//! level, so fidelity (sibling `&page=KEEP`) is only required below 8 levels.
use scrapelens_core::export::sanitize::{
    sanitize_path_and_query, sanitize_text, sanitize_url, SanitizeOptions,
};
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }
}

/// Encodes one level: reserved characters and `%` become %XX (hex in random case).
fn enc(s: &str, r: &mut Rng) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        let keep = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if keep {
            o.push(b as char)
        } else if r.below(2) == 0 {
            o.push_str(&format!("%{b:02X}"))
        } else {
            o.push_str(&format!("%{b:02x}"))
        }
    }
    o
}

fn encode_name(name: &str, r: &mut Rng) -> String {
    // random case and, sometimes, letters as %XX
    name.chars()
        .map(|c| {
            let c = if r.below(3) == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            };
            if c.is_ascii_alphabetic() && r.below(6) == 0 {
                format!("%{:02X}", c as u8)
            } else {
                c.to_string()
            }
        })
        .collect()
}

const NAMES: &[&str] = &[
    "token",
    "access_token",
    "refresh_token",
    "password",
    "sessionid",
    "jsessionid",
    "api_key",
    "client_secret",
    "x-csrf-token",
    "auth",
    "sig",
    "code",
    "state",
    "id_token",
    "apiKey",
    "sessionKey",
    "nonce",
    "pwd",
    "otp",
    "secret",
];

fn main_case(r: &mut Rng, i: usize) -> (String, &'static str, usize, String) {
    let marker = format!("ZQ{i}a");
    // value: alnum chunks separated by credential characters that get encoded at the value level
    let seps = [
        "", "+", "/", "=", "-", ".", "_", "~", " ", "&", "#", "%", ",", ";", "|", "\"", "(", "[",
        "{", "<", "\\", "'",
    ];
    let nparts = 1 + r.below(3);
    let mut raw_value = marker.clone();
    for j in 0..nparts {
        raw_value.push_str(r.pick(&seps));
        raw_value.push_str(&format!("ZQ{i}p{j}"));
    }
    let name = *r.pick(NAMES);
    let k = r.below(9); // encoding levels around it
                        // innermost level: `?name=value(enc)&page=KEEP`
    let inner = format!(
        "/cb?{}={}&page=KEEP{i}",
        encode_name(name, r),
        enc(&raw_value, r)
    );
    let mut nested = inner;
    for _ in 0..k {
        nested = enc(&nested, r);
    }
    let ctx = r.below(10);
    let pre = format!("PRE{i}w");
    let suf = format!("SUF{i}w");
    let (text, label) = match ctx {
        0 => (format!("{pre} next={nested} {suf}"), "text next="),
        1 => (
            format!("{pre} GET /r?a=1&next={nested}&b=2 HTTP/1.1 {suf}"),
            "startline",
        ),
        2 => (
            format!("{pre} {{\"u\":\"https://h/r?next={nested}\"}} {suf}"),
            "json-ish",
        ),
        3 => (format!("{pre} x=y={nested} {suf}"), "chain"),
        4 => (
            format!("{pre} https://h/r?next={nested}#f {suf}"),
            "url-in-text",
        ),
        5 => (format!("{pre} \"next={nested}\" {suf}"), "quoted"),
        6 => (format!("{pre} /a;next={nested}/z {suf}"), "matrix-text"),
        7 => (
            format!(
                "{pre} redirect=https%3A%2F%2Fh{} {suf}",
                enc(&format!("/x?next={nested}"), r)
            ),
            "redirect",
        ),
        8 => (format!("{pre} (next={nested}) {suf}"), "paren"),
        _ => (format!("{pre} next={nested}, {suf}"), "comma"),
    };
    (text, label, k, raw_value)
}

#[test]
fn deterministic_fuzz_has_no_leaks_panics_or_nonidempotent_outputs() {
    let o = SanitizeOptions::default();
    let n: usize = std::env::var("FUZZ_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3_000);
    let mut r = Rng(0x9E3779B97F4A7C15
        ^ std::env::var("SEED")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1));
    let mut leaks: BTreeMap<String, (usize, String)> = BTreeMap::new();
    let mut fidelity: BTreeMap<String, (usize, String)> = BTreeMap::new();
    let mut nonidem: BTreeMap<String, (usize, String)> = BTreeMap::new();
    let mut panics = 0usize;
    let mut by_sep: BTreeMap<String, usize> = BTreeMap::new();
    for i in 0..n {
        let (text, label, k, raw_value) = main_case(&mut r, i);
        let res = catch_unwind(AssertUnwindSafe(|| sanitize_text(&text, &o)));
        let Ok(out) = res else {
            panics += 1;
            println!("PANIC {text:?}");
            continue;
        };
        let key = format!("{label} k={k}");
        if out.contains("ZQ") {
            let e = leaks.entry(key.clone()).or_insert((0, String::new()));
            e.0 += 1;
            if e.1.is_empty() {
                e.1 = format!("{text:?} -> {out:?}");
            }
            // separator that cuts the value
            let sep: String = raw_value
                .chars()
                .filter(|c| !c.is_ascii_alphanumeric())
                .collect();
            *by_sep.entry(format!("{sep:?}")).or_default() += 1;
        }
        let pre = format!("PRE{i}w ");
        let suf = format!(" SUF{i}w");
        // `redirect` wraps one more encoding level
        let keep_required = k + usize::from(label == "redirect") < 8;
        if !out.starts_with(&pre)
            || !out.ends_with(&suf)
            || (keep_required && !out.contains(&format!("KEEP{i}")))
        {
            let e = fidelity.entry(key.clone()).or_insert((0, String::new()));
            e.0 += 1;
            if e.1.is_empty() {
                e.1 = format!("{text:?} -> {out:?}");
            }
        }
        let twice = sanitize_text(&out, &o);
        if twice != out {
            let e = nonidem.entry(key).or_insert((0, String::new()));
            e.0 += 1;
            if e.1.is_empty() {
                e.1 = format!("{out:?} -> {twice:?}");
            }
        }
    }
    // random soup: panic + idempotence on text/url/pq
    let atoms = [
        "%",
        "25",
        "3D",
        "3d",
        "2B",
        "C3",
        "FF",
        "=",
        "&",
        ";",
        "/",
        "?",
        "#",
        " ",
        "\"",
        "'",
        "(",
        ")",
        "[",
        "]",
        "{",
        "}",
        "<",
        ">",
        "token",
        "Token",
        "sid",
        "Bearer ",
        "basic ",
        "://",
        "@",
        "é",
        "\u{a0}",
        "\u{3000}",
        "😀",
        "%C3",
        "%A9",
        "%FF",
        "%E2%82",
        "&#61;",
        "&#x3D;",
        "&equals;",
        "[REDACTED]",
        "%5BREDACTED%5D",
        "%255BREDACTED%255D",
        "+",
        "\n",
        "\t",
        "a",
        "Z",
        "\\",
        ",",
        "|",
        ":",
        "%%",
        "%3",
        "%G",
    ];
    let m: usize = std::env::var("SOUP_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3_000);
    let mut soup_nonidem: BTreeMap<&str, (usize, String)> = BTreeMap::new();
    let mut soup_panics = 0;
    let mut soup_secret_leak = 0usize;
    let mut soup_leak_ex = String::new();
    for _ in 0..m {
        let len = 1 + r.below(24);
        let mut s = String::new();
        for _ in 0..len {
            s.push_str(r.pick(&atoms));
        }
        // marker in the raw `token=` value position, glued and followed by a space
        let with_secret = format!("{s}token=ZQs{}x {s}", r.below(1000));
        for (kind, f) in [
            (
                "text",
                sanitize_text as fn(&str, &SanitizeOptions) -> String,
            ),
            ("url", sanitize_url),
            ("pq", sanitize_path_and_query),
        ] {
            let input = if kind == "url" {
                format!("https://h/p?{s}")
            } else {
                s.clone()
            };
            match catch_unwind(AssertUnwindSafe(|| f(&input, &o))) {
                Err(_) => {
                    soup_panics += 1;
                    println!("SOUP PANIC {kind} {input:?}");
                }
                Ok(out) => {
                    let twice = f(&out, &o);
                    if twice != out {
                        let e = soup_nonidem.entry(kind).or_insert((0, String::new()));
                        e.0 += 1;
                        if e.1.is_empty() || input.len() < e.1.len() / 3 {
                            e.1 = format!("{input:?} -> {out:?} -> {twice:?}");
                        }
                    }
                }
            }
        }
        let out = sanitize_text(&with_secret, &o);
        if out.contains("ZQs") {
            soup_secret_leak += 1;
            if soup_leak_ex.is_empty() || with_secret.len() < soup_leak_ex.len() / 3 {
                soup_leak_ex = format!("{with_secret:?} -> {out:?}");
            }
        }
    }
    println!(
        "FUZZ main n={n} panics={panics} leaks={} fidelity={} nonidem={}",
        leaks.values().map(|v| v.0).sum::<usize>(),
        fidelity.values().map(|v| v.0).sum::<usize>(),
        nonidem.values().map(|v| v.0).sum::<usize>()
    );
    for (k, (c, ex)) in &leaks {
        println!("LEAK [{k}] {c} ex: {}", &ex[..ex.len().min(600)]);
    }
    for (k, c) in &by_sep {
        println!("LEAKSEP {k} {c}");
    }
    for (k, (c, ex)) in &fidelity {
        println!("FIDELITY [{k}] {c} ex: {}", &ex[..ex.len().min(600)]);
    }
    for (k, (c, ex)) in &nonidem {
        println!("NONIDEM [{k}] {c} ex: {}", &ex[..ex.len().min(600)]);
    }
    println!(
        "SOUP m={m}x3 panics={soup_panics} secret_leak={soup_secret_leak} nonidem={:?}",
        soup_nonidem
            .iter()
            .map(|(k, v)| (k, v.0))
            .collect::<Vec<_>>()
    );
    if !soup_leak_ex.is_empty() {
        println!("SOUP LEAK ex: {soup_leak_ex}");
    }
    for (k, (_, ex)) in &soup_nonidem {
        println!("SOUP NONIDEM {k} ex: {}", &ex[..ex.len().min(600)]);
    }
    assert_eq!(panics + soup_panics, 0, "panic");
    assert_eq!(
        leaks.values().map(|v| v.0).sum::<usize>(),
        0,
        "leaks: {leaks:?}"
    );
    assert_eq!(soup_secret_leak, 0, "leak in the soup: {soup_leak_ex}");
    assert!(fidelity.is_empty(), "fidelity loss: {fidelity:?}");
    assert!(nonidem.is_empty(), "not idempotent: {nonidem:?}");
    // Soup of random atoms: idempotence is a metric, not a guarantee (a sensitive name
    // followed by garbage that the 1st pass redacts may become `name+placeholder`
    // in the 2nd). Budget: less than 0.1% of cases.
    let soup_nonidem_total: usize = soup_nonidem.values().map(|v| v.0).sum();
    assert!(
        soup_nonidem_total * 1000 <= m * 3,
        "too many non-idempotent soup cases ({soup_nonidem_total} of {}): {soup_nonidem:?}",
        m * 3
    );
}
