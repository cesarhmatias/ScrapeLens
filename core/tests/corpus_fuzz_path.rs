//! Fuzz de CAMINHO do Revisor (rodada 12, adendo 8), incorporado ao repositório.
//! Vazamento = qualquer janela de 6 bytes do segredo (que não ocorra no resto da
//! entrada) aparece na saída. Fidelidade = a CONSULTA (`?page=N`) depois do segredo
//! some. Pela decisão A8 o resto do CAMINHO depois de um nome sensível é redigido junto
//! (limitação aceita), então só a consulta é exigida.
//! `PATH_FUZZ_N` (5000 por padrão) e `PATH_FUZZ_SEEDS` ("1,2") ajustam a rodada.
use scrapelens_core::export::sanitize::{sanitize_text, sanitize_url, SanitizeOptions};
use std::collections::BTreeMap;

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

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const NAMES: &[&str] = &[
    "token",
    "jsessionid",
    "session",
    "access_token",
    "sid",
    "password",
    "api_key",
    "auth",
    "secret",
    "id_token",
];
const WORDS: &[&str] = &[
    "next", "profile", "users", "a", "b", "c", "page", "v1", "api", "home",
];

fn gen(r: &mut Rng, alpha: &[u8], len: usize) -> String {
    (0..len)
        .map(|_| alpha[r.below(alpha.len())] as char)
        .collect()
}

fn secret(r: &mut Rng) -> (&'static str, String) {
    match r.below(6) {
        0 => {
            // base64 padrão aleatório (pode ter / e +), com padding às vezes
            let n = 8 + r.below(40);
            let mut s = gen(r, B64, n);
            if r.below(3) == 0 {
                s.push('=');
            }
            ("b64", s)
        }
        1 => {
            // base64 com barra garantida mas sem '+' (heurística fraca)
            let a = {
                let l = 4 + r.below(20);
                gen(r, ALNUM, l)
            };
            let b = {
                let l = 4 + r.below(14);
                gen(r, ALNUM, l)
            };
            ("b64slash", format!("{a}/{b}"))
        }
        2 => {
            // segredo com cara de caminho
            let a = {
                let l = 6 + r.below(8);
                gen(r, ALNUM, l)
            };
            let b = {
                let l = 6 + r.below(8);
                gen(r, ALNUM, l)
            };
            ("pathlike", format!("/{a}/{b}"))
        }
        3 => {
            let l = 10 + r.below(30);
            (
                "urlsafe",
                gen(
                    r,
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
                    l,
                ),
            )
        }
        4 => {
            let h = gen(r, ALNUM, 12);
            let p = gen(r, B64, 20);
            let s = gen(r, ALNUM, 10);
            ("jwtslash", format!("eyJ{h}.{p}.{s}"))
        }
        _ => {
            let a = {
                let l = 6 + r.below(10);
                gen(r, ALNUM, l)
            };
            ("plain", a)
        }
    }
}

fn pct(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn run(seed: u64, n: usize) -> (usize, usize) {
    let mut r = Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1);
    let o = SanitizeOptions::default();
    let mut leaks: BTreeMap<String, usize> = BTreeMap::new();
    let mut lost: BTreeMap<String, usize> = BTreeMap::new();
    let mut total: BTreeMap<String, usize> = BTreeMap::new();
    let mut samples: Vec<String> = Vec::new();
    for _ in 0..n {
        let name = *r.pick(NAMES);
        let (kind, sec) = secret(&mut r);
        let pre = format!("/{}/{}", r.pick(WORDS), r.pick(WORDS));
        let sep = if r.below(2) == 0 { ";" } else { "/" };
        let suffix = format!("/{}/{}?page={}", r.pick(WORDS), r.pick(WORDS), r.below(100));
        let core = format!("{pre}{sep}{name}={sec}{suffix}");
        let ctx = r.below(7);
        let (cname, input, url) = match ctx {
            0 => ("rawpath", core.clone(), true),
            1 => ("url", format!("https://h.invalid{core}"), true),
            2 => ("reqline", format!("GET {core} HTTP/1.1"), false),
            3 => ("json", format!("{{\"u\":\"{core}\",\"k\":1}}"), false),
            4 => ("hdr", format!("X-Path: {core}"), false),
            5 => (
                "nested",
                format!("https://h.invalid/cb?next={}&z=1", pct(&core)),
                true,
            ),
            _ => ("query", format!("/p?{name}={sec}&page=2"), true),
        };
        let mut outs = vec![sanitize_text(&input, &o)];
        if url {
            outs.push(sanitize_url(&input, &o));
        }
        let rest = if ctx == 5 {
            input.replacen(&pct(&sec), "\u{0}", 1)
        } else {
            input.replacen(&sec, "\u{0}", 1)
        };
        let key = format!("{cname}/{kind}");
        *total.entry(key.clone()).or_default() += 1;
        let sb = sec.as_bytes();
        let mut leaked = false;
        'w: for out in &outs {
            if sb.len() >= 6 {
                for w in sb.windows(6) {
                    let ws = std::str::from_utf8(w).unwrap();
                    // janela informativa: ignora as que são só '/' e palavras comuns
                    if rest.contains(ws) || pct(&core).contains(ws) && ctx == 5 && false {
                        continue;
                    }
                    if out.contains(ws) {
                        leaked = true;
                        if samples.len() < 25 {
                            samples.push(format!("{key}: IN={input}\n    OUT={out}"));
                        }
                        break 'w;
                    }
                }
            }
        }
        if leaked {
            *leaks.entry(key.clone()).or_default() += 1;
        }
        // fidelidade: o sufixo não secreto (só nos contextos de caminho cru)
        if ctx != 6 && ctx != 5 {
            let want = suffix
                .rsplit_once('?')
                .map(|(_, q)| format!("?{q}"))
                .unwrap();
            let want = want.as_str();
            if outs.iter().any(|o| !o.contains(want)) {
                *lost.entry(key.clone()).or_default() += 1;
            }
        }
    }
    let tl: usize = leaks.values().sum();
    let tf: usize = lost.values().sum();
    println!("PATHFUZZ seed={seed} n={n} leaks={tl} fidelity_lost={tf}");
    println!("-- leaks por contexto/tipo (total do grupo)");
    for (k, v) in &leaks {
        println!("  {k}: {v}/{}", total[k]);
    }
    println!("-- fidelidade perdida");
    for (k, v) in &lost {
        println!("  {k}: {v}/{}", total[k]);
    }
    println!("-- amostras");
    for s in samples.iter().take(12) {
        println!("  {s}");
    }
    (tl, tf)
}

#[test]
fn path_fuzz_has_no_leaks_and_keeps_the_query() {
    let n: usize = std::env::var("PATH_FUZZ_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5_000);
    let seeds = std::env::var("PATH_FUZZ_SEEDS").unwrap_or_else(|_| "1,2".to_string());
    for seed in seeds
        .split(',')
        .filter_map(|s| s.trim().parse::<u64>().ok())
    {
        let (leaks, lost) = run(seed, n);
        assert_eq!(leaks, 0, "semente {seed}: vazamentos");
        assert_eq!(lost, 0, "semente {seed}: perdeu a consulta");
    }
}
