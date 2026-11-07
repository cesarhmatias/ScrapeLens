// Harness for the real-Chrome flood check (experiments/relay-flood). Not a product binary.
// Real Relay + fake HTTP CONNECT upstream that records what it receives.
// stdin commands: owner <pid> | failures | upstream | quit. Replies are one line each.
use scrapelens_capture::proxy::ProxyLink;
use scrapelens_capture::relay::Relay;
use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

fn upstream() -> (u16, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let seen = s2.clone();
            thread::spawn(move || {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match c.read(&mut b) {
                        Ok(1) => head.push(b[0]),
                        _ => return,
                    }
                }
                let text = String::from_utf8_lossy(&head);
                let line = text.lines().next().unwrap_or("").to_string();
                let auth = text
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("proxy-authorization"))
                    .unwrap_or("NO-AUTH")
                    .to_string();
                seen.lock().unwrap().push(format!("{line} | {auth}"));
                let target_port: u16 = line.split_whitespace().nth(1).and_then(|t| t.rsplit(':').next()).and_then(|p| p.parse().ok()).unwrap_or(0);
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
                // Review: port 9 means the upstream closes right after the reply.
                if target_port == 9 { return; }
                // Review: forward every tunnel to a local web server, for a real browser.
                if let Ok(fw) = std::env::var("UPSTREAM_FORWARD") {
                    let Ok(mut f) = TcpStream::connect(fw) else { return };
                    let mut f2 = f.try_clone().unwrap();
                    let mut c2 = c.try_clone().unwrap();
                    thread::spawn(move || { let _ = std::io::copy(&mut c2, &mut f2); let _ = f2.shutdown(std::net::Shutdown::Write); });
                    let _ = std::io::copy(&mut f, &mut c);
                    let _ = c.shutdown(std::net::Shutdown::Write);
                    return;
                }
                let mut c2 = c.try_clone().unwrap();
                let _ = std::io::copy(&mut c, &mut c2);
            });
        }
    });
    (port, seen)
}

fn main() {
    // Review: the upstream can run as its own process, so it does not share the relay's descriptors.
    if std::env::var("UPSTREAM_ONLY").is_ok() {
        let (up, seen) = upstream();
        println!("PORT {up}");
        std::io::stdout().flush().unwrap();
        for line in std::io::stdin().lock().lines() {
            let _ = line;
            println!("{:?}", seen.lock().unwrap());
            std::io::stdout().flush().unwrap();
        }
        return;
    }
    let (up, seen) = match std::env::var("UPSTREAM_PORT") {
        Ok(p) => (p.parse().unwrap(), Arc::new(Mutex::new(Vec::new()))),
        Err(_) => upstream(),
    };
    let link = ProxyLink::parse(&format!("http://REVIEWUSER:REVIEWSECRET@127.0.0.1:{up}")).unwrap();
    let relay = Relay::start(&link, None).unwrap();
    println!("PORT {}", relay.port());
    std::io::stdout().flush().unwrap();
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some("owner") => {
                relay.set_owner_pid(parts.next().unwrap().parse().unwrap());
                println!("ok");
            }
            Some("failures") => println!("{:?}", relay.failures()),
            Some("upstream") => println!("{:?}", seen.lock().unwrap()),
            Some("store") => {
                // Review: session writes while the relay is under load, in this process's fd table.
                use scrapelens_core::model::{BrowserInfo, SessionMeta, SessionV1};
                let n: usize = parts.next().unwrap().parse().unwrap();
                let dir = parts.next().unwrap().to_string();
                let mut bundle = scrapelens_core::SessionBundle::new(SessionV1::new(SessionMeta::new("s", "2026-11-07T00:00:00Z", BrowserInfo::default())));
                for i in 0..8 { bundle.insert_attachment(format!("a-{i}.bin"), vec![b'x'; 64]); }
                let (mut ok, mut bad, mut first) = (0, 0, String::new());
                for i in 0..n {
                    match scrapelens_core::store::write_session_dir(&bundle, std::path::Path::new(&format!("{dir}/s{i}"))) {
                        Ok(()) => ok += 1,
                        Err(e) => { if first.is_empty() { first = e.to_string(); } bad += 1; }
                    }
                }
                println!("store ok={ok} err={bad} first={first:?}");
            }
            Some("threads") => println!("{}", thread_count()),
            Some("quit") | None => break,
            _ => println!("?"),
        }
        std::io::stdout().flush().unwrap();
    }
}

fn thread_count() -> String {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_dir("/proc/self/task").map(|d| d.count().to_string()).unwrap_or_default()
    }
    #[cfg(not(target_os = "linux"))]
    {
        "n/a".to_string()
    }
}
