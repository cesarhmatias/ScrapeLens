use std::sync::Arc;

use scrapelens_mcp::live::RealBackend;

/// Raises the open-files soft limit to the hard limit, up to what the platform accepts. The MCP
/// process runs next to a browser, and launchd's default soft limit (256 on macOS) is too low for it.
fn raise_open_files_limit() {
    #[cfg(target_os = "macos")]
    const CEILING: u64 = 10_240;
    #[cfg(not(target_os = "macos"))]
    const CEILING: u64 = 65_536;
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: `limit` is a valid rlimit for getrlimit to write into.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return;
    }
    let target = limit.rlim_max.min(CEILING);
    if target > limit.rlim_cur {
        let raised = libc::rlimit { rlim_cur: target, rlim_max: limit.rlim_max };
        // SAFETY: `raised` is a valid rlimit whose soft limit is not above its hard limit.
        unsafe {
            libc::setrlimit(libc::RLIMIT_NOFILE, &raised);
        }
    }
}

#[tokio::main]
async fn main() {
    raise_open_files_limit();
    let config = match scrapelens_mcp::cli::parse_args(std::env::args().skip(1).collect()) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };
    let code = scrapelens_mcp::app::run(config, Arc::new(RealBackend)).await;
    std::process::exit(code);
}
