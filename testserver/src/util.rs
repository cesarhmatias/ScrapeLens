//! Small helpers shared by the servers and clients.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Monotonic connection-id source: `c1`, `c2`, ...
#[derive(Debug, Default)]
pub struct ConnIds(AtomicU64);

impl ConnIds {
    pub fn next(&self) -> String {
        format!("c{}", self.0.fetch_add(1, Ordering::SeqCst) + 1)
    }
}

pub fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

pub fn stamp() -> String {
    chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
}

/// Read investigative output goes to stderr with a stable, greppable prefix.
pub fn note(server: &str, msg: impl AsRef<str>) {
    eprintln!(
        "[scrapelens-testserver {} {}] {}",
        server,
        chrono::Utc::now().format("%H:%M:%S%.3f"),
        msg.as_ref()
    );
}
