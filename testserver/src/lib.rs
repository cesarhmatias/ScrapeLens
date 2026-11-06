//! ScrapeLens reference test servers.
//!
//! Three local servers that observe the **decoded order** of request headers at
//! the earliest point available for each protocol:
//!
//! * `h1` — HTTP/1.1 on plain TCP: the exact bytes of the request head are kept
//!   (raw socket), so header order, casing and duplicates are preserved.
//! * `h2` — HTTP/2 over TLS: the HPACK field list as emitted by the decoder
//!   (`httlib-hpack`), in decode order, before any map/dictionary is built.
//! * `h3` — HTTP/3 over QUIC: the QPACK-decoded field list returned by
//!   `quiche`'s `h3::Event::Headers` as a `Vec<Header>`, in decode order.
//!
//! Every request is appended to an evidence JSONL file
//! (`{proto, timestamp, headers: [[name, value], ...], ...}`) with duplicates
//! preserved. Nothing here is a general purpose web server: it exists to
//! produce controlled, synthetic fidelity evidence for the ScrapeLens matrix.

pub mod cert;
pub mod endpoints;
pub mod evidence;
pub mod h1;
pub mod h2cli;
pub mod h2frame;
pub mod h2srv;
pub mod h3cli;
pub mod h3srv;
pub mod http;
pub mod proxy;
pub mod util;

pub const SCHEMA: &str = "scrapelens.testserver.evidence/1";
pub const H1_ADDR: &str = "127.0.0.1:8781";
pub const H2_ADDR: &str = "127.0.0.1:8782";
pub const H3_ADDR: &str = "127.0.0.1:8783";
