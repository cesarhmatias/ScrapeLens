//! netlog module for the capture crate; moved from lib.rs by T29.

pub(crate) const EMPTY_NETLOG: &[u8] = br#"{"constants":{},"events":[]}"#;

/// NetLog state read from disk after Chrome shut down.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum NetlogStatus {
    Complete,
    /// Truncated; repaired by cutting at the last complete event.
    Repaired {
        original_bytes: usize,
        kept_bytes: usize,
    },
    /// Missing, empty or unrecoverable: the session continues with CDP only.
    Unusable {
        reason: String,
    },
}

pub(crate) fn is_valid_json(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde::de::IgnoredAny>(bytes).is_ok()
}

/// Chrome writes one event per line in `"events":[`. A truncated file
/// ends with a complete event followed by a comma, or with a partial line: it cuts at the
/// last line break, removes the comma and closes `]}` (the `polledData` is lost).
pub(crate) fn repair_netlog(raw: &[u8]) -> Option<Vec<u8>> {
    let marker = raw
        .windows(10)
        .position(|w| w == b"\"events\":[" || w == b"\"events\": ")?;
    let mut end = raw.len();
    for _ in 0..16 {
        let mut candidate = raw[..end].to_vec();
        while candidate
            .last()
            .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b',')
        {
            candidate.pop();
        }
        candidate.extend_from_slice(b"]}");
        if is_valid_json(&candidate) {
            return Some(candidate);
        }
        // Steps back one line; stops before entering the constants.
        end = raw[..end].iter().rposition(|byte| *byte == b'\n')?;
        if end <= marker {
            return None;
        }
    }
    None
}

pub(crate) fn prepare_netlog(raw: Option<&[u8]>) -> (Vec<u8>, NetlogStatus) {
    let Some(raw) = raw else {
        return (
            EMPTY_NETLOG.to_vec(),
            NetlogStatus::Unusable {
                reason: "NetLog missing or empty".to_string(),
            },
        );
    };
    if is_valid_json(raw) {
        return (raw.to_vec(), NetlogStatus::Complete);
    }
    match repair_netlog(raw) {
        Some(fixed) => {
            let kept_bytes = fixed.len();
            (
                fixed,
                NetlogStatus::Repaired {
                    original_bytes: raw.len(),
                    kept_bytes,
                },
            )
        }
        None => (
            EMPTY_NETLOG.to_vec(),
            NetlogStatus::Unusable {
                reason: "NetLog truncated and unrepairable".to_string(),
            },
        ),
    }
}

