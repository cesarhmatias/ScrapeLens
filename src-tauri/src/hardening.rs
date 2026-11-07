//! Process hardening at the start of the App (T15).
//!
//! While a session is imported or captured, cookies, the proxy password and the cookie-key
//! material are in this process's memory. A core dump, or another process of the same user
//! attaching a debugger or reading `/proc/<pid>/mem`, would expose them. So the App sets:
//!
//! - `RLIMIT_CORE` to zero (both systems): no core file, and the limit cannot be raised again;
//! - `PR_SET_DUMPABLE` to zero (Linux): no ptrace attach or `/proc/<pid>/mem` access by other
//!   processes, which also keeps core dumps off.
//!
//! The open-files soft limit is raised as well (review-013b L8): a macOS app started from Finder
//! inherits launchd's soft limit, 256, which a real browser session exceeds.
//!
//! Nothing here stops the start-up: a failed call becomes a message for the log.

/// Applies the limits. Returns the calls that failed, for the log; an empty list means both held.
pub fn harden_process() -> Vec<String> {
    let mut problems = Vec::new();
    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `setrlimit` only reads the struct it is given, which lives for the call.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) } != 0 {
        problems.push(format!(
            "RLIMIT_CORE was not set: {}",
            std::io::Error::last_os_error()
        ));
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `prctl(PR_SET_DUMPABLE, 0)` takes an integer and no pointers.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            problems.push(format!(
                "PR_SET_DUMPABLE was not cleared: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    raise_open_files_limit();
    problems
}

/// Sets the open-files soft limit to the hard limit, up to what macOS and Linux accept for it.
/// Returns the soft limit in effect afterwards.
pub fn raise_open_files_limit() -> u64 {
    #[cfg(target_os = "macos")]
    const CEILING: u64 = 10_240;
    #[cfg(not(target_os = "macos"))]
    const CEILING: u64 = 65_536;
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: `limit` is a valid rlimit for getrlimit to write into.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return 0;
    }
    let target = limit.rlim_max.min(CEILING);
    if target > limit.rlim_cur {
        let raised = libc::rlimit { rlim_cur: target, rlim_max: limit.rlim_max };
        // SAFETY: `raised` is a valid rlimit whose soft limit is not above its hard limit.
        unsafe {
            libc::setrlimit(libc::RLIMIT_NOFILE, &raised);
        }
    }
    let mut now = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: as above.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut now) } == 0 {
        now.rlim_cur
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_dumps_are_off_and_cannot_be_raised_again() {
        assert!(harden_process().is_empty(), "every call must succeed");
        let mut limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: `getrlimit` writes into the struct it is given.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
        assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0));
    }

    #[test]
    fn the_open_files_limit_is_raised_to_a_usable_value() {
        assert!(raise_open_files_limit() >= 1024);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn other_processes_cannot_dump_or_attach() {
        harden_process();
        // SAFETY: `prctl(PR_GET_DUMPABLE)` takes no pointers.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
    }
}
