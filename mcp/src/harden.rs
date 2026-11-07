//! Startup hardening for the MCP process.
//!
//! Linux: `PR_SET_DUMPABLE` to 0, so the process cannot be attached or dumped
//! by another user. Every supported Unix target: `RLIMIT_CORE` to 0.
//! The open-files soft limit is raised to the hard limit (review-013b L8): the process runs next to
//! a browser, and launchd's default soft limit on macOS (256) is too low for it.
//! The App process is outside this crate.

use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};

/// Called at process start. A second call is the same as the first.
pub fn harden_process() {
    let limit = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    let _ = setrlimit(Resource::Core, limit);
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{set_dumpable_behavior, DumpableBehavior};
        let _ = set_dumpable_behavior(DumpableBehavior::NotDumpable);
    }
    raise_open_files_limit();
}

/// Sets the open-files soft limit to the hard limit, up to what macOS and Linux accept for it.
fn raise_open_files_limit() {
    #[cfg(target_os = "macos")]
    const CEILING: u64 = 10_240;
    #[cfg(not(target_os = "macos"))]
    const CEILING: u64 = 65_536;
    let limit = getrlimit(Resource::Nofile);
    let target = match limit.maximum {
        Some(hard) => hard.min(CEILING),
        None => CEILING,
    };
    if limit.current.is_none_or(|soft| soft < target) {
        let _ = setrlimit(
            Resource::Nofile,
            Rlimit {
                current: Some(target),
                maximum: limit.maximum,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use rustix::process::getrlimit;

    use super::*;

    #[test]
    fn startup_raises_the_open_files_limit() {
        harden_process();
        let soft = getrlimit(Resource::Nofile).current.unwrap_or(u64::MAX);
        assert!(soft >= 1024, "soft limit {soft}");
    }

    #[test]
    fn startup_disables_core_dumps() {
        harden_process();
        let limit = getrlimit(Resource::Core);
        assert_eq!(limit.current, Some(0));
        assert_eq!(limit.maximum, Some(0));
        #[cfg(target_os = "linux")]
        {
            use rustix::process::{dumpable_behavior, DumpableBehavior};
            assert_eq!(
                dumpable_behavior().expect("dumpable"),
                DumpableBehavior::NotDumpable
            );
            // OrbStack 7.2 publishes CoreDumping and omits Dumpable.
            // PR_GET_DUMPABLE above is the check; a published line must be 0.
            let status = std::fs::read_to_string("/proc/self/status").expect("status");
            if let Some(line) = status.lines().find(|line| line.starts_with("Dumpable:")) {
                assert!(line.ends_with('0'), "{line}");
            }
        }
    }
}
