//! Live proxy check: the controlled capture (stable Chrome, CDP + NetLog, allowlist)
//! through a proxy link, against the synthetic origin and upstream of `experiments/proxy`.
//!
//! Usage: `SCRAPELENS_PROXY_URL=socks5://user:pass@127.0.0.1:18702 \
//!         cargo run --example proxy_live -- <session-folder> <origin-port>`
//! The link comes from the environment, so the password is not on the command line.
//! Test only: loopback origin and a test upstream; nothing leaves the machine.

use std::path::PathBuf;
use std::time::Duration;

use scrapelens_capture::browser::{BrowserCapture, BrowserCaptureConfig};
use scrapelens_capture::chrome::resolve_stable_chrome;
use scrapelens_capture::proxy::ProxyLink;

fn main() {
    let mut args = std::env::args().skip(1);
    let session_dir = PathBuf::from(args.next().expect("session folder"));
    let port: u16 = args.next().expect("origin port").parse().expect("port");
    let raw = std::env::var("SCRAPELENS_PROXY_URL").expect("SCRAPELENS_PROXY_URL");
    let link = ProxyLink::parse(&raw).expect("valid proxy link");
    eprintln!("proxy: {link:?}");
    let chrome = resolve_stable_chrome(None).expect("stable Chrome").binary;
    let (capture, _info) = BrowserCapture::start(BrowserCaptureConfig {
        chrome,
        session_dir,
        start_url: None,
        headless: true,
        allowed_hosts: vec![format!("site-a.test:{port}"), format!("site-b.test:{port}")],
        third_party_hosts: Vec::new(),
        expose_cdp: false,
        proxy: Some(link),
    })
    .expect("start");
    let nav = capture.navigate(&format!("http://site-a.test:{port}/page"), true, Duration::from_secs(60));
    eprintln!("navigate: {:?}", nav.is_ok());
    std::thread::sleep(Duration::from_secs(8));
    let report = capture.stop().expect("stop");
    eprintln!("stop: requests={} netlog={} graceful={}", report.requests, report.netlog, report.graceful);
    println!("{}", report.session_dir);
}
