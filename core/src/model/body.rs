use serde::{Deserialize, Serialize};

use super::provenance::{Provenance, Verification};

/// Explicit body state. Never use the absence of a body to mean
/// "empty": `Unavailable` and `Discarded` are states distinct from `Empty`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BodyState {
    /// Body exists and was captured (may point to an attachment).
    Captured,
    /// Body is known to be empty (e.g. 204).
    Empty,
    /// Body existed but was cut at the capture limit.
    Truncated,
    /// Body was not obtained (e.g. the source does not provide it).
    Unavailable,
    /// Body was discarded on purpose (policy, sanitization, size).
    Discarded,
}

impl BodyState {
    pub fn as_str(self) -> &'static str {
        match self {
            BodyState::Captured => "captured",
            BodyState::Empty => "empty",
            BodyState::Truncated => "truncated",
            BodyState::Unavailable => "unavailable",
            BodyState::Discarded => "discarded",
        }
    }
}

/// Request or response body, with its own state and provenance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Body {
    pub state: BodyState,
    /// Relative name in `attachments/` (only when captured bytes exist).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment: Option<String>,
    /// Known/observed size in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// Offset at which the capture stopped, when truncated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// `Content-Encoding` of the body (gzip, br, ...), not the transport encoding
    /// of the JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Transformations applied before reaching here (e.g. `chrome-decoded`,
    /// `charset:iso-8859-1->utf-8`, `lossy-postData`). Non-empty = the bytes are
    /// not identical to the wire ones.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transformed: Vec<String>,
    #[serde(default)]
    pub provenance: Provenance,
}

impl Default for Body {
    fn default() -> Self {
        Self::unavailable("body not provided by the source")
    }
}

impl Body {
    pub fn captured(attachment: impl Into<String>, bytes: u64, provenance: &Provenance) -> Self {
        Self {
            state: BodyState::Captured,
            attachment: Some(attachment.into()),
            bytes: Some(bytes),
            provenance: provenance.clone(),
            ..Self::default_with_state(BodyState::Captured)
        }
    }

    pub fn empty(provenance: &Provenance) -> Self {
        Self {
            provenance: provenance.clone(),
            ..Self::default_with_state(BodyState::Empty)
        }
    }

    pub fn truncated(
        attachment: impl Into<String>,
        bytes: u64,
        truncated_at: u64,
        provenance: &Provenance,
    ) -> Self {
        Self {
            state: BodyState::Truncated,
            attachment: Some(attachment.into()),
            bytes: Some(bytes),
            truncated_at: Some(truncated_at),
            provenance: provenance.clone(),
            ..Self::default_with_state(BodyState::Truncated)
        }
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            state: BodyState::Unavailable,
            note: Some(reason.into()),
            provenance: Provenance::new(
                super::provenance::Source::Derived,
                "unavailable",
                Verification::Unverified,
            ),
            ..Self::default_with_state(BodyState::Unavailable)
        }
    }

    pub fn discarded(reason: impl Into<String>) -> Self {
        Self {
            state: BodyState::Discarded,
            note: Some(reason.into()),
            provenance: Provenance::new(
                super::provenance::Source::Derived,
                "discarded",
                Verification::Unverified,
            ),
            ..Self::default_with_state(BodyState::Discarded)
        }
    }

    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    pub fn with_content_encoding(mut self, encoding: impl Into<String>) -> Self {
        self.content_encoding = Some(encoding.into());
        self
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    pub fn has_bytes(&self) -> bool {
        matches!(self.state, BodyState::Captured | BodyState::Truncated)
            && self.attachment.is_some()
    }

    fn default_with_state(state: BodyState) -> Self {
        Self {
            state,
            attachment: None,
            bytes: None,
            truncated_at: None,
            content_type: None,
            content_encoding: None,
            note: None,
            transformed: Vec::new(),
            provenance: Provenance::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::provenance::Source;

    #[test]
    fn default_body_is_unavailable_not_empty() {
        let body = Body::default();
        assert_eq!(body.state, BodyState::Unavailable);
        assert!(!body.has_bytes());
    }

    #[test]
    fn captured_body_points_to_attachment() {
        let prov = Provenance::new(Source::Capture, "capture.body", Verification::Verified);
        let body = Body::captured("req-1.request.bin", 12, &prov)
            .with_content_type("application/octet-stream");
        assert_eq!(body.state, BodyState::Captured);
        assert_eq!(body.attachment.as_deref(), Some("req-1.request.bin"));
        assert_eq!(body.bytes, Some(12));
        assert!(body.has_bytes());
    }

    #[test]
    fn truncated_keeps_limit() {
        let prov = Provenance::new(Source::Capture, "capture.body", Verification::Partial);
        let body = Body::truncated("a.bin", 1024, 1024, &prov);
        assert_eq!(body.state, BodyState::Truncated);
        assert_eq!(body.truncated_at, Some(1024));
    }
}
