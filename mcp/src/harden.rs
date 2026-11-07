//! Startup hardening for the MCP process.
//!
//! Linux: `PR_SET_DUMPABLE` to 0, so the process cannot be attached or dumped
//! by another user. Every supported Unix target: `RLIMIT_CORE` to 0.
//! The App process is outside this crate.

use rustix::process::{setrlimit, Resource, Rlimit};

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
}

#[cfg(test)]
mod tests {
    use rustix::process::getrlimit;

    use super::*;

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
            let status = std::fs::read_to_string("/proc/self/status").expect("status");
            let line = status
                .lines()
                .find(|line| line.starts_with("Dumpable:"))
                .expect("Dumpable");
            assert!(line.ends_with('0'), "{line}");
        }
    }
}
