//! CLI for the ScrapeLens reference test servers.
//!
//! Commands:
//!   gen-cert [--out DIR] [--force]
//!   serve [--only h1,h2,h3] [--evidence DIR] [--run-id ID] [--tls DIR]
//!         [--h1 ADDR] [--h2 ADDR] [--h3 ADDR] [--no-h3-on-h2-port]
//!   client-h2 URL [--header NAME:VALUE]... [--cert FILE]
//!   client-h3 URL [--header NAME:VALUE]... [--cert FILE] [--insecure]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use scrapelens_testserver::cert::{self, TlsFiles};
use scrapelens_testserver::evidence::Evidence;
use scrapelens_testserver::http::Proto;
use scrapelens_testserver::{
    H1_ADDR, H2_ADDR, H3_ADDR, SCHEMA, h1, h2cli, h2srv, h3cli, h3srv, util,
};

fn main() {
    cert::init_crypto();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match run(&args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    };
    std::process::exit(code);
}

fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let Some(cmd) = args.first().map(|s| s.as_str()) else {
        usage();
        return Ok(());
    };
    match cmd {
        "gen-cert" | "gencert" => gen_cert(&args[1..]),
        "serve" => serve(&args[1..]),
        "client-h2" => client_h2(&args[1..]),
        "client-h3" => client_h3(&args[1..]),
        "help" | "--help" | "-h" => {
            usage();
            Ok(())
        }
        other => Err(format!("unknown command {other:?}; try --help").into()),
    }
}

fn usage() {
    println!(
        "scrapelens-testserver {}\n\
         \n\
         Reference servers that record request header order at the decode point:\n\
         \x20 h1  http://127.0.0.1:8781   raw socket bytes\n\
         \x20 h2  https://127.0.0.1:8782  HPACK decoded list\n\
         \x20 h3  https://127.0.0.1:8783  QPACK decoded list (QUIC/UDP)\n\
         \n\
         Commands:\n\
         \x20 gen-cert   [--out DIR] [--force]      generate the self-signed fixture cert\n\
         \x20 serve      [--only h1,h2,h3] [...]    run servers and write JSONL evidence\n\
         \x20 client-h2  URL [--header K:V]...      ordered h2 request (trusts fixtures/tls CA)\n\
         \x20 client-h3  URL [--header K:V]... [--insecure]\n\
         \x20                                      ordered h3 request (trusts fixtures/tls CA)\n\
         \n\
         Endpoints (all protocols): GET /echo-order, GET /setcookie, POST /echo,\n\
         GET /page, GET /redirect?n=N, GET /healthz\n\
         \n\
         serve options:\n\
         \x20 --evidence DIR      evidence root (default: fixtures/evidence)\n\
         \x20 --run-id ID         subdirectory name (default: UTC timestamp)\n\
         \x20 --tls DIR           cert directory (default: fixtures/tls)\n\
         \x20 --h1/--h2/--h3 ADDR override listen addresses\n\
         \x20 --no-h3-on-h2-port disable the extra UDP listener on the h2 port\n\
         \x20                     (needed for Chrome --origin-to-force-quic-on)\n\
         \x20 --h3-qpack-table N QPACK dynamic table capacity advertised (default 0)\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn repo_fixtures() -> PathBuf {
    if let Ok(dir) = std::env::var("SCRAPELENS_FIXTURES_DIR") {
        return PathBuf::from(dir);
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest.join("../fixtures");
    if candidate.exists() {
        candidate
    } else {
        PathBuf::from("fixtures")
    }
}

fn gen_cert(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut out = repo_fixtures().join("tls");
    let mut force = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                out = PathBuf::from(args.get(i).ok_or("--out needs a value")?);
            }
            "--force" => force = true,
            other => return Err(format!("unknown gen-cert option {other:?}").into()),
        }
        i += 1;
    }
    let files = cert::ensure(&out, force)?;
    println!("{}", files.summary());
    println!(
        "chrome pin (base64 sha256 of SPKI): {}",
        files.spki_sha256_b64
    );
    Ok(())
}

fn serve(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut only: Vec<String> = vec!["h1".into(), "h2".into(), "h3".into()];
    let mut evidence_root = repo_fixtures().join("evidence");
    let mut run_id = util::stamp();
    let mut tls_dir = repo_fixtures().join("tls");
    let mut h1_addr: SocketAddr = H1_ADDR.parse()?;
    let mut h2_addr: SocketAddr = H2_ADDR.parse()?;
    let mut h3_addr: SocketAddr = H3_ADDR.parse()?;
    let mut h3_on_h2_port = true;
    let mut h3_qpack_table: u64 = 0;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--only" => {
                i += 1;
                only = args
                    .get(i)
                    .ok_or("--only needs a value")?
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "--evidence" => {
                i += 1;
                evidence_root = PathBuf::from(args.get(i).ok_or("--evidence needs a value")?);
            }
            "--run-id" => {
                i += 1;
                run_id = args.get(i).ok_or("--run-id needs a value")?.clone();
            }
            "--tls" => {
                i += 1;
                tls_dir = PathBuf::from(args.get(i).ok_or("--tls needs a value")?);
            }
            "--h1" => {
                i += 1;
                h1_addr = args.get(i).ok_or("--h1 needs a value")?.parse()?;
            }
            "--h2" => {
                i += 1;
                h2_addr = args.get(i).ok_or("--h2 needs a value")?.parse()?;
            }
            "--h3" => {
                i += 1;
                h3_addr = args.get(i).ok_or("--h3 needs a value")?.parse()?;
            }
            "--no-h3-on-h2-port" => h3_on_h2_port = false,
            "--h3-qpack-table" => {
                i += 1;
                h3_qpack_table = args
                    .get(i)
                    .ok_or("--h3-qpack-table needs a value")?
                    .parse()?;
            }
            other => return Err(format!("unknown serve option {other:?}").into()),
        }
        i += 1;
    }

    let tls = cert::ensure(&tls_dir, false)?;
    let run_dir = evidence_root.join(&run_id);
    std::fs::create_dir_all(&run_dir)?;

    let want = |name: &str| only.iter().any(|s| s == name);

    let run_meta = serde_json::json!({
        "schema": "scrapelens.testserver.run/1",
        "evidence_schema": SCHEMA,
        "run_id": run_id,
        "started_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "binary_version": env!("CARGO_PKG_VERSION"),
        "arch": std::env::consts::ARCH,
        "os": std::env::consts::OS,
        "addrs": {
            "h1": if want("h1") { h1_addr.to_string() } else { "disabled".into() },
            "h2": if want("h2") { h2_addr.to_string() } else { "disabled".into() },
            "h3": if want("h3") { h3_addr.to_string() } else { "disabled".into() },
            "h3_on_h2_port": if want("h3") && h3_on_h2_port && want("h2") { h2_addr.to_string() } else { "disabled".into() },
        },
        "tls": {
            "cert_pem": tls.cert_pem.display().to_string(),
            "key_pem": tls.key_pem.display().to_string(),
            "spki_sha256_b64": tls.spki_sha256_b64,
        },
        "h3_qpack_max_table_capacity": h3_qpack_table,
        "decode_points": {
            "http/1.1": Proto::H1.decode_point(),
            "h2": Proto::H2.decode_point(),
            "h3": Proto::H3.decode_point(),
        },
        "note": "synthetic local test data only; no telemetry, no external network",
    });
    std::fs::write(
        run_dir.join("run.json"),
        serde_json::to_vec_pretty(&run_meta)?,
    )?;

    println!("ScrapeLens reference test servers");
    println!("  evidence run: {}", run_dir.display());
    println!("  cert: {}", tls.cert_pem.display());
    println!(
        "  chrome pin: --ignore-certificate-errors-spki-list={}",
        tls.spki_sha256_b64
    );
    println!();

    let mut handles = Vec::new();

    if want("h1") {
        let ev = Arc::new(Evidence::open(&run_dir, "http/1.1")?);
        handles.push(thread::spawn(move || {
            if let Err(e) = h1::serve(h1_addr, ev.clone()) {
                eprintln!("h1 server stopped: {e}");
            }
        }));
    }

    if want("h2") {
        let ev = Arc::new(Evidence::open(&run_dir, "h2")?);
        let tls_cfg = cert::rustls_server_config(&tls)?;
        let advertise = if want("h3") {
            Some(h3_addr.port())
        } else {
            None
        };
        handles.push(thread::spawn(move || {
            if let Err(e) = h2srv::serve(h2_addr, ev.clone(), tls_cfg, advertise) {
                eprintln!("h2 server stopped: {e}");
            }
        }));
    }

    if want("h3") {
        let ev = Arc::new(Evidence::open(&run_dir, "h3")?);
        let tls_clone: TlsFiles = tls.clone();
        handles.push(thread::spawn(move || {
            if let Err(e) = h3srv::serve(h3_addr, ev.clone(), &tls_clone, h3_qpack_table) {
                eprintln!("h3 server stopped: {e}");
            }
        }));
        if h3_on_h2_port && want("h2") {
            let ev2 = Arc::new(Evidence::open(&run_dir, "h3")?);
            let tls2 = tls.clone();
            handles.push(thread::spawn(move || {
                if let Err(e) = h3srv::serve(h2_addr, ev2.clone(), &tls2, h3_qpack_table) {
                    eprintln!("h3 (alias on {h2_addr}) stopped: {e}");
                }
            }));
        }
    }

    println!("Endpoints: /echo-order /setcookie /echo /page /redirect /healthz");
    println!("Press Ctrl+C to stop. Evidence is flushed per request.");
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

fn parse_url(url: &str) -> Result<(SocketAddr, String), Box<dyn std::error::Error>> {
    let rest = url
        .strip_prefix("https://")
        .ok_or("only https:// URLs are supported")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let addr: SocketAddr = if authority.contains(':') {
        authority.parse()?
    } else {
        format!("{authority}:443").parse()?
    };
    Ok((addr, path.to_string()))
}

fn parse_headers(
    args: &[String],
) -> Result<(Vec<(String, String)>, Vec<String>), Box<dyn std::error::Error>> {
    let mut headers = Vec::new();
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--header" || args[i] == "-H" {
            i += 1;
            let raw = args.get(i).ok_or("--header needs NAME:VALUE")?;
            let (name, value) = raw
                .split_once(':')
                .ok_or_else(|| format!("bad header {raw:?}; expected NAME:VALUE"))?;
            headers.push((name.trim().to_string(), value.trim().to_string()));
        } else {
            rest.push(args[i].clone());
        }
        i += 1;
    }
    Ok((headers, rest))
}

fn client_h2(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let (headers, rest) = parse_headers(args)?;
    let url = rest.first().ok_or("client-h2 needs a URL")?;
    let (addr, path) = parse_url(url)?;
    let tls = cert::ensure(&repo_fixtures().join("tls"), false)?;
    let resp = h2cli::get(addr, &path, &headers, &tls)?;
    print_client_result(
        "h2",
        &resp.status,
        &resp.headers,
        &resp.body,
        Some(&resp.alpn),
    );
    Ok(())
}

fn client_h3(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let (headers, rest) = parse_headers(args)?;
    let url = rest.first().ok_or("client-h3 needs a URL")?;
    let (addr, path) = parse_url(url)?;
    let insecure = rest.iter().any(|a| a == "--insecure");
    let tls = cert::ensure(&repo_fixtures().join("tls"), false)?;
    let resp = h3cli::get(addr, &path, &headers, &tls, insecure)?;
    print_client_result("h3", &resp.status, &resp.headers, &resp.body, None);
    Ok(())
}

fn print_client_result(
    proto: &str,
    status: &u16,
    headers: &[(String, String)],
    body: &[u8],
    alpn: Option<&String>,
) {
    println!(
        "proto: {proto}{}",
        alpn.map(|a| format!(" (alpn {a})")).unwrap_or_default()
    );
    println!("status: {status}");
    println!("response headers in decode order ({}):", headers.len());
    for (i, (n, v)) in headers.iter().enumerate() {
        println!("  [{i}] {n}: {v}");
    }
    println!("body ({} bytes):", body.len());
    match std::str::from_utf8(body) {
        Ok(s) => println!("{s}"),
        Err(_) => println!("<{} non-UTF8 bytes>", body.len()),
    }
}
