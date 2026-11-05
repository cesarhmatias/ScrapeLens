use serde::{Deserialize, Serialize};

use super::provenance::Provenance;

/// Internal pair of a `Cookie` field, with the original text of the pair.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CookiePairEntry {
    pub name: String,
    /// Value exactly as it came from the source (quotes preserved).
    pub value: String,
    /// The whole pair as it appeared (`name=value`), without the `; ` separator.
    pub raw: String,
    #[serde(flatten)]
    pub provenance: Provenance,
}

/// `Cookie` field of a request.
///
/// Preserves (a) the original value of each field in the source, (b) the parsed
/// internal pairs and (c) the split lines observed on the wire (h2/h3). Nothing
/// is merged: `wire_lines` may have N entries while `raw` has 1.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CookieField {
    /// Original value(s) of the `Cookie` field(s) in the source (0..N).
    #[serde(default)]
    pub raw: Vec<String>,
    /// Parsed internal pairs, in order of appearance.
    #[serde(default)]
    pub pairs: Vec<CookiePairEntry>,
    /// `Cookie:` lines observed on the wire, one per transmitted field.
    #[serde(default)]
    pub wire_lines: Vec<String>,
    /// Tokens that could not be parsed (never silently dropped).
    #[serde(default)]
    pub unparsed: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    #[serde(default)]
    pub provenance: Provenance,
}

impl CookieField {
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty() && self.pairs.is_empty() && self.wire_lines.is_empty()
    }

    /// Builds from the original `Cookie` values (one per field).
    pub fn from_header_values(values: &[String], provenance: &Provenance) -> Self {
        let mut field = Self {
            provenance: provenance.clone(),
            ..Self::default()
        };
        for value in values {
            field.raw.push(value.clone());
            field.parse_value_into_pairs(value, provenance);
        }
        field
    }

    fn parse_value_into_pairs(&mut self, value: &str, provenance: &Provenance) {
        for token in split_cookie_tokens(value) {
            if token.is_empty() {
                continue;
            }
            match token.find('=') {
                Some(idx) if idx > 0 => {
                    let name = token[..idx].trim().to_string();
                    let raw_value = token[idx + 1..].to_string();
                    self.pairs.push(CookiePairEntry {
                        name,
                        value: raw_value,
                        raw: token.to_string(),
                        provenance: provenance.clone(),
                    });
                }
                _ => {
                    self.notes.push(format!(
                        "cookie pair without '=' preserved in unparsed: {token:?}"
                    ));
                    self.unparsed.push(token.to_string());
                }
            }
        }
    }

    /// Adds pairs derived from another source (e.g. `request.cookies` from HAR)
    /// without touching the raw field.
    pub fn add_pairs_from_header(&mut self, value: &str, provenance: &Provenance) {
        self.parse_value_into_pairs(value, provenance);
    }

    /// Records a split line from the wire (h2/h3), preserving the order.
    pub fn push_wire_line(&mut self, line: &str) {
        self.wire_lines.push(line.to_string());
    }

    /// `true` when the wire shows more `Cookie` fields than the source.
    pub fn wire_is_fragmented(&self) -> bool {
        self.wire_lines.len() > self.raw.len() && self.raw.len() <= 1 && self.wire_lines.len() > 1
    }
}

/// Splits `a=1; b=2` into tokens, respecting quotes (a `;` inside quotes does not
/// separate pairs). Does not remove internal spaces from the value.
pub fn split_cookie_tokens(value: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    let mut escaped = false;
    for (idx, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            ';' if !in_quotes => {
                tokens.push(value[start..idx].trim());
                start = idx + 1;
            }
            _ => {}
        }
    }
    tokens.push(value[start..].trim());
    tokens
}

/// Parsed attributes of `Set-Cookie`. The raw value is always preserved in
/// [`SetCookieRecord`], even when parsing fails.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedSetCookie {
    pub name: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Original text of `Expires` (not reinterpreted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age: Option<i64>,
    #[serde(default)]
    pub secure: bool,
    #[serde(default)]
    pub http_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_site: Option<String>,
    #[serde(default)]
    pub partitioned: bool,
    /// Unrecognized or invalid attributes, preserved as text.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// A `Set-Cookie` line as received, with its parse alongside.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetCookieRecord {
    pub raw: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parsed: Option<ParsedSetCookie>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parse_error: Option<String>,
    #[serde(flatten)]
    pub provenance: Provenance,
}

impl SetCookieRecord {
    pub fn from_raw(raw: &str, provenance: &Provenance) -> Self {
        match parse_set_cookie(raw) {
            Ok(parsed) => Self {
                raw: raw.to_string(),
                parsed: Some(parsed),
                parse_error: None,
                provenance: provenance.clone(),
            },
            Err(error) => Self {
                raw: raw.to_string(),
                parsed: None,
                parse_error: Some(error),
                provenance: provenance.clone(),
            },
        }
    }

    pub fn name(&self) -> Option<&str> {
        self.parsed.as_ref().map(|parsed| parsed.name.as_str())
    }
}

pub fn parse_set_cookie(raw: &str) -> Result<ParsedSetCookie, String> {
    let tokens = split_cookie_tokens(raw);
    let first = tokens
        .first()
        .copied()
        .ok_or_else(|| "empty Set-Cookie line".to_string())?;
    let eq = first
        .find('=')
        .ok_or_else(|| format!("Set-Cookie without '=' in the name=value pair: {first:?}"))?;
    let name = first[..eq].trim();
    if name.is_empty() {
        return Err(format!("Set-Cookie with empty name: {first:?}"));
    }

    let mut parsed = ParsedSetCookie {
        name: name.to_string(),
        value: first[eq + 1..].to_string(),
        domain: None,
        path: None,
        expires: None,
        max_age: None,
        secure: false,
        http_only: false,
        same_site: None,
        partitioned: false,
        extensions: Vec::new(),
        notes: Vec::new(),
    };

    for token in tokens.iter().skip(1) {
        if token.is_empty() {
            continue;
        }
        let (attr, value) = match token.find('=') {
            Some(idx) => (token[..idx].trim(), Some(token[idx + 1..].to_string())),
            None => (*token, None),
        };
        let attr_lower = attr.to_ascii_lowercase();
        match attr_lower.as_str() {
            "domain" => parsed.domain = value,
            "path" => parsed.path = value,
            "expires" => parsed.expires = value,
            "max-age" => match value.as_deref().and_then(|v| v.trim().parse::<i64>().ok()) {
                Some(seconds) => parsed.max_age = Some(seconds),
                None => {
                    parsed.notes.push(format!(
                        "invalid Max-Age preserved as extension: {token:?}"
                    ));
                    parsed
                        .extensions
                        .push((attr.to_string(), value.unwrap_or_default()));
                }
            },
            "secure" => parsed.secure = true,
            "httponly" => parsed.http_only = true,
            "samesite" => parsed.same_site = value,
            "partitioned" => parsed.partitioned = true,
            "priority" => parsed
                .extensions
                .push(("Priority".to_string(), value.unwrap_or_default())),
            _ => parsed
                .extensions
                .push((attr.to_string(), value.unwrap_or_default())),
        }
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::provenance::{Source, Verification};

    fn prov() -> Provenance {
        Provenance::new(Source::Cdp, "headers", Verification::Verified)
    }

    #[test]
    fn parses_pairs_and_keeps_raw_values() {
        let field = CookieField::from_header_values(
            &["sl_a=1; sl_b=2; empty=; quoted=\"a;b\"".to_string()],
            &prov(),
        );
        assert_eq!(field.raw.len(), 1);
        assert_eq!(field.pairs.len(), 4);
        assert_eq!(field.pairs[0].name, "sl_a");
        assert_eq!(field.pairs[1].value, "2");
        assert_eq!(field.pairs[2].value, "");
        assert_eq!(field.pairs[3].value, "\"a;b\"");
        assert!(field.unparsed.is_empty());
    }

    #[test]
    fn keeps_fragmented_wire_lines_separate() {
        let mut field =
            CookieField::from_header_values(&["sl_a=1; sl_b=2; sl_c=3".to_string()], &prov());
        field.push_wire_line("sl_a=1");
        field.push_wire_line("sl_b=2");
        field.push_wire_line("sl_c=3");
        assert_eq!(field.raw.len(), 1);
        assert_eq!(field.pairs.len(), 3);
        assert_eq!(field.wire_lines.len(), 3);
        assert!(field.wire_is_fragmented());
    }

    #[test]
    fn unparsed_token_is_preserved() {
        let field = CookieField::from_header_values(&["justtoken; a=1".to_string()], &prov());
        assert_eq!(field.pairs.len(), 1);
        assert_eq!(field.unparsed, vec!["justtoken".to_string()]);
        assert_eq!(field.notes.len(), 1);
    }

    #[test]
    fn parses_set_cookie_with_expires_comma() {
        let raw = "sid=abc; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Path=/; HttpOnly; SameSite=Lax; Priority=High; X-Custom=1";
        let parsed = parse_set_cookie(raw).expect("parse");
        assert_eq!(parsed.name, "sid");
        assert_eq!(parsed.value, "abc");
        assert_eq!(
            parsed.expires.as_deref(),
            Some("Wed, 21 Oct 2015 07:28:00 GMT")
        );
        assert_eq!(parsed.path.as_deref(), Some("/"));
        assert!(parsed.http_only);
        assert_eq!(parsed.same_site.as_deref(), Some("Lax"));
        assert_eq!(parsed.extensions.len(), 2);
    }

    #[test]
    fn invalid_set_cookie_keeps_raw_and_error() {
        let record = SetCookieRecord::from_raw("no-equals-sign", &prov());
        assert_eq!(record.raw, "no-equals-sign");
        assert!(record.parsed.is_none());
        assert!(record.parse_error.is_some());
    }

    #[test]
    fn max_age_parsed_and_invalid_preserved() {
        let parsed = parse_set_cookie("a=1; Max-Age=3600").unwrap();
        assert_eq!(parsed.max_age, Some(3600));
        let parsed = parse_set_cookie("a=1; Max-Age=abc").unwrap();
        assert_eq!(parsed.max_age, None);
        assert_eq!(parsed.extensions[0].0, "Max-Age");
    }
}
