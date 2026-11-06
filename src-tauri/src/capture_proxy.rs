//! Proxy for live captures (App). The user gives one proxy link; the link's credentials
//! stay in memory until the app closes. What crosses to the UI, to events, to errors and
//! to the preferences file is only `scheme://host:port` and whether the link is
//! authenticated. Contract: `/Users/cesar/OpenBot/Shared/sl-proxy-contract.md` (App).

use scrapelens_capture::proxy::ProxyLink;
use serde::Serialize;

/// What the UI may show about a proxy. No username, no password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyInfo {
    pub server_url: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub authenticated: bool,
}

impl ProxyInfo {
    pub fn of(link: &ProxyLink) -> Self {
        ProxyInfo {
            server_url: link.server_url(),
            scheme: link.scheme().as_str().to_string(),
            host: link.host().to_string(),
            port: link.port(),
            authenticated: link.authenticated(),
        }
    }
}

/// The Proxy field's state: the saved server, the link kept in memory, and whether the
/// user must type the link again (the server is saved but its password is not kept).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyState {
    pub saved: Option<String>,
    pub active: Option<ProxyInfo>,
    pub needs_link: bool,
}

pub fn state(saved: Option<String>, active: Option<&ProxyLink>) -> ProxyState {
    let needs_link = match (&saved, active) {
        (Some(server), Some(link)) => link.server_url() != *server,
        (Some(_), None) => true,
        (None, _) => false,
    };
    ProxyState { saved, active: active.map(ProxyInfo::of), needs_link }
}

/// The link a capture starts with. The saved server is the authority: with no saved
/// proxy there is none; with one, the in-memory link must be for that same server.
pub fn resolve_for_start(saved: Option<&str>, active: Option<&ProxyLink>) -> Result<Option<ProxyLink>, String> {
    match saved {
        None => Ok(None),
        Some(server) => match active {
            Some(link) if link.server_url() == server => Ok(Some(link.clone())),
            _ => Err(format!(
                "The proxy {server} is saved, but the app does not keep its password between runs. Enter the proxy link again in the Proxy field, or clear the field, then start the capture."
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_LINK: &str = "http://reader:Sup3r-Secret@proxy.example:8080";

    fn link(input: &str) -> ProxyLink {
        ProxyLink::parse(input).expect("valid test link")
    }

    #[test]
    fn info_and_state_never_contain_the_credentials() {
        let active = link(SECRET_LINK);
        let info = serde_json::to_string(&ProxyInfo::of(&active)).unwrap();
        let state_json = serde_json::to_string(&state(Some("http://proxy.example:8080".into()), Some(&active))).unwrap();
        for text in [&info, &state_json] {
            assert!(!text.contains("Sup3r-Secret"), "{text}");
            assert!(!text.contains("reader"), "{text}");
            assert!(!text.contains("Sup3r"), "{text}");
        }
        assert!(info.contains("\"serverUrl\":\"http://proxy.example:8080\""), "{info}");
        assert!(info.contains("\"authenticated\":true"), "{info}");
    }

    #[test]
    fn no_saved_proxy_means_no_proxy_and_nothing_to_retype() {
        assert_eq!(resolve_for_start(None, None).unwrap(), None);
        let st = state(None, None);
        assert!(!st.needs_link);
        assert!(st.active.is_none() && st.saved.is_none());
    }

    #[test]
    fn saved_server_with_the_link_in_memory_starts_with_that_link() {
        let active = link(SECRET_LINK);
        let resolved = resolve_for_start(Some("http://proxy.example:8080"), Some(&active)).unwrap();
        assert_eq!(resolved, Some(active.clone()));
        let st = state(Some("http://proxy.example:8080".into()), Some(&active));
        assert!(!st.needs_link);
    }

    #[test]
    fn saved_server_after_a_restart_asks_for_the_link_again() {
        let err = resolve_for_start(Some("http://proxy.example:8080"), None).unwrap_err();
        assert!(err.contains("http://proxy.example:8080"), "{err}");
        assert!(err.contains("Enter the proxy link again"), "{err}");
        let st = state(Some("http://proxy.example:8080".into()), None);
        assert!(st.needs_link);
        assert!(st.active.is_none());
    }

    #[test]
    fn a_link_for_another_server_does_not_start_the_capture() {
        let other = link("http://other.example:3128");
        let err = resolve_for_start(Some("http://proxy.example:8080"), Some(&other)).unwrap_err();
        assert!(err.contains("proxy.example"), "{err}");
        assert!(state(Some("http://proxy.example:8080".into()), Some(&other)).needs_link);
    }

    #[test]
    fn unauthenticated_link_round_trips_without_a_flag() {
        let open = link("proxy.example:8080");
        let info = ProxyInfo::of(&open);
        assert_eq!(info.server_url, "http://proxy.example:8080");
        assert!(!info.authenticated);
        assert_eq!(resolve_for_start(Some("http://proxy.example:8080"), Some(&open)).unwrap(), Some(open));
    }
}
