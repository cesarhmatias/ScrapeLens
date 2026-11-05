//! Extraction of `XML` fields (request and response) from HAR files.

use std::path::Path;

pub fn unescape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let Some(end) = rest.find(';').filter(|e| *e <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let entity = &rest[1..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32),
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

pub fn form_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => match u8::from_str_radix(&text[i + 1..i + 3], 16) {
                Ok(b) => {
                    out.push(b);
                    i += 2;
                }
                Err(_) => out.push(b'%'),
            },
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Contents of the `name="XML"` controls (textarea or input) of a page.
pub fn xml_controls(html: &str) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = lower[from..].find("<textarea") {
        let start = from + at;
        let Some(tag_end) = lower[start..].find('>').map(|e| start + e) else {
            break;
        };
        let tag = &lower[start..tag_end];
        let close = lower[tag_end..]
            .find("</textarea")
            .map(|e| tag_end + e)
            .unwrap_or(html.len());
        if tag.contains("name=\"xml\"") || tag.contains("name='xml'") || tag.contains("name=xml") {
            out.push(unescape_html(&html[tag_end + 1..close]));
        }
        from = close.max(start + 1);
    }
    out
}

/// All XML (request, response) of a HAR: `(requests, responses)`.
pub fn har_xml(path: &Path) -> Option<(Vec<String>, Vec<String>)> {
    let bytes = std::fs::read(path).ok()?;
    let har: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let entries = har.get("log")?.get("entries")?.as_array()?;
    let (mut requests, mut responses) = (Vec::new(), Vec::new());
    for entry in entries {
        let post = &entry["request"]["postData"];
        if let Some(params) = post["params"].as_array() {
            for p in params {
                if p["name"] == "XML" {
                    if let Some(v) = p["value"].as_str() {
                        requests.push(form_decode(v));
                    }
                }
            }
        } else if let Some(text) = post["text"].as_str() {
            for pair in text.split('&') {
                if let Some(v) = pair.strip_prefix("XML=") {
                    requests.push(form_decode(v));
                }
            }
        }
        let content = &entry["response"]["content"];
        if let Some(text) = content["text"].as_str() {
            let html = if content["encoding"] == "base64" {
                // No base64 in the dev-dependency: this project's HARs use text.
                continue;
            } else {
                text.to_string()
            };
            responses.extend(xml_controls(&html));
        }
    }
    Some((requests, responses))
}
