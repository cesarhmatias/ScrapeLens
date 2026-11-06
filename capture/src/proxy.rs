//! The proxy link: the one generic link a user gives for a capture.
//!
//! Accepted forms (the contract lists them; nothing else is accepted):
//!
//! - `http://[user:pass@]host[:port]` (default port 80)
//! - `https://[user:pass@]host[:port]` (default port 443)
//! - `socks5://…` and `socks5h://…` (SOCKS5, remote DNS; default port 1080)
//! - `[user:pass@]host[:port]` with no scheme: the same as `http://`
//! - `host:port:user:pass`: the common provider format, the same as `http://user:pass@host:port`
//!
//! Credentials are percent-decoded. IPv6 literals go in brackets. Anything else is an
//! error, and no error ever contains the input: the input is where the password is.
//!
//! `Debug`, `Display` and every error message hide the username and the password.
//! The values are reachable only through [`ProxyLink::user`] and [`ProxyLink::password`],
//! which the relay uses for the upstream handshake and nothing else.

use std::fmt;
use std::net::Ipv6Addr;

/// A value that must never be printed. `Debug` and `Display` show `***`.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// The value. Only the upstream handshake may call this.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

/// The scheme of an accepted link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyScheme {
    Http,
    Https,
    Socks5,
    Socks5h,
}

impl ProxyScheme {
    /// The name the link and the session record use (`socks5h` stays `socks5h`).
    pub fn as_str(self) -> &'static str {
        match self {
            ProxyScheme::Http => "http",
            ProxyScheme::Https => "https",
            ProxyScheme::Socks5 => "socks5",
            ProxyScheme::Socks5h => "socks5h",
        }
    }

    /// The scheme Chrome receives. Chrome has no `socks5h`; its SOCKS5 already resolves
    /// names at the proxy (checked by `experiments/proxy`).
    pub fn chrome_scheme(self) -> &'static str {
        match self {
            ProxyScheme::Socks5h => "socks5",
            other => other.as_str(),
        }
    }

    fn default_port(self) -> u16 {
        match self {
            ProxyScheme::Http => 80,
            ProxyScheme::Https => 443,
            ProxyScheme::Socks5 | ProxyScheme::Socks5h => 1080,
        }
    }
}

/// Why a link was refused. None of these carries the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyError {
    Empty,
    ControlCharacter,
    UnsupportedScheme,
    Socks4NotSupported,
    PathNotAllowed,
    MissingHost,
    InvalidPort,
    InvalidFormat,
    InvalidEncoding,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ProxyError::Empty => "the proxy link is empty",
            ProxyError::ControlCharacter => "the proxy link contains a control character",
            ProxyError::UnsupportedScheme => {
                "unsupported proxy scheme: use http, https, socks5 or socks5h, or no scheme"
            }
            ProxyError::Socks4NotSupported => "socks4 is not supported: use socks5 or socks5h",
            ProxyError::PathNotAllowed => {
                "the proxy link must not have a path, query or fragment (percent-encode special characters in credentials)"
            }
            ProxyError::MissingHost => "the proxy link has no host",
            ProxyError::InvalidPort => "the proxy port must be a number from 1 to 65535",
            ProxyError::InvalidFormat => {
                "the proxy link is not recognized: use scheme://[user:password@]host:port or host:port:user:password"
            }
            ProxyError::InvalidEncoding => {
                "the proxy credentials are not valid percent-encoded UTF-8"
            }
        })
    }
}

impl std::error::Error for ProxyError {}

/// A parsed proxy link. Holds the credentials in memory only.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyLink {
    scheme: ProxyScheme,
    host: String,
    port: u16,
    user: Option<Secret>,
    password: Option<Secret>,
}

impl ProxyLink {
    /// Parses a link in any accepted form. Surrounding whitespace is ignored.
    pub fn parse(input: &str) -> Result<Self, ProxyError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(ProxyError::Empty);
        }
        if input.chars().any(char::is_control) {
            return Err(ProxyError::ControlCharacter);
        }
        match input.split_once("://") {
            Some((scheme, rest)) => {
                let scheme = match scheme.to_ascii_lowercase().as_str() {
                    "http" => ProxyScheme::Http,
                    "https" => ProxyScheme::Https,
                    "socks5" => ProxyScheme::Socks5,
                    "socks5h" => ProxyScheme::Socks5h,
                    "socks4" | "socks4a" => return Err(ProxyError::Socks4NotSupported),
                    _ => return Err(ProxyError::UnsupportedScheme),
                };
                parse_authority(scheme, authority_of(rest)?)
            }
            None if input.contains('@') => parse_authority(ProxyScheme::Http, input),
            None => parse_bare(input),
        }
    }

    pub fn scheme(&self) -> ProxyScheme {
        self.scheme
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// True when the link carried a username or a password.
    pub fn authenticated(&self) -> bool {
        self.user.is_some() || self.password.is_some()
    }

    pub(crate) fn user(&self) -> Option<&Secret> {
        self.user.as_ref()
    }

    pub(crate) fn password(&self) -> Option<&Secret> {
        self.password.as_ref()
    }

    /// `scheme://host:port` with no credentials, IPv6 in brackets. This is the only form
    /// of the address that may appear in events, session records, messages or exports.
    pub fn server_url(&self) -> String {
        format!("{}://{}", self.scheme.as_str(), host_port(&self.host, self.port))
    }

    /// The value for Chrome's `--proxy-server`, without credentials. Used only when the
    /// link has no credentials and the capture has no allowlist (the direct route).
    pub fn chrome_server_arg(&self) -> String {
        format!("{}://{}", self.scheme.chrome_scheme(), host_port(&self.host, self.port))
    }
}

impl fmt::Debug for ProxyLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyLink")
            .field("server", &self.server_url())
            .field("authenticated", &self.authenticated())
            .finish()
    }
}

impl fmt::Display for ProxyLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.server_url())
    }
}

fn host_port(host: &str, port: u16) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The part after `scheme://` up to the end of the authority. Only an empty path (or `/`)
/// is allowed after it.
fn authority_of(rest: &str) -> Result<&str, ProxyError> {
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    match &rest[end..] {
        "" | "/" => Ok(&rest[..end]),
        _ => Err(ProxyError::PathNotAllowed),
    }
}

fn parse_authority(scheme: ProxyScheme, authority: &str) -> Result<ProxyLink, ProxyError> {
    let (user, password, hostport) = match authority.rsplit_once('@') {
        Some((userinfo, hostport)) => {
            let (user, password) = split_credentials(userinfo)?;
            (Some(user), password, hostport)
        }
        None => (None, None, authority),
    };
    let (host, port) = parse_host_port(hostport, scheme.default_port())?;
    Ok(ProxyLink { scheme, host, port, user, password })
}

/// `user:password`, split at the first colon. The password may contain colons.
fn split_credentials(userinfo: &str) -> Result<(Secret, Option<Secret>), ProxyError> {
    let (user, password) = match userinfo.split_once(':') {
        Some((u, p)) => (u, Some(p)),
        None => (userinfo, None),
    };
    if user.is_empty() {
        return Err(ProxyError::InvalidFormat);
    }
    Ok((
        Secret(percent_decode(user)?),
        password.map(|p| percent_decode(p).map(Secret)).transpose()?,
    ))
}

/// A link with no scheme: `[user:pass@]host[:port]` or `host:port:user:pass`.
fn parse_bare(input: &str) -> Result<ProxyLink, ProxyError> {
    if input.starts_with('[') {
        return parse_authority(ProxyScheme::Http, input);
    }
    let parts: Vec<&str> = input.splitn(4, ':').collect();
    match parts.as_slice() {
        [_] | [_, _] => parse_authority(ProxyScheme::Http, input),
        [host, port, user, password] => {
            let port = parse_port(port)?;
            if host.is_empty() {
                return Err(ProxyError::MissingHost);
            }
            if user.is_empty() {
                return Err(ProxyError::InvalidFormat);
            }
            Ok(ProxyLink {
                scheme: ProxyScheme::Http,
                host: (*host).to_string(),
                port,
                user: Some(Secret(percent_decode(user)?)),
                password: Some(Secret(percent_decode(password)?)),
            })
        }
        _ => Err(ProxyError::InvalidFormat),
    }
}

/// `host` or `host:port` or `[ipv6]` or `[ipv6]:port`.
fn parse_host_port(hostport: &str, default_port: u16) -> Result<(String, u16), ProxyError> {
    if let Some(stripped) = hostport.strip_prefix('[') {
        let end = stripped.find(']').ok_or(ProxyError::InvalidFormat)?;
        let host = &stripped[..end];
        if host.parse::<Ipv6Addr>().is_err() {
            return Err(ProxyError::InvalidFormat);
        }
        let port = match &stripped[end + 1..] {
            "" => default_port,
            tail => parse_port(tail.strip_prefix(':').ok_or(ProxyError::InvalidFormat)?)?,
        };
        return Ok((host.to_string(), port));
    }
    if hostport.matches(':').count() > 1 {
        // A bare IPv6 address would be ambiguous: it must be bracketed.
        return Err(ProxyError::InvalidFormat);
    }
    let (host, port) = match hostport.split_once(':') {
        Some((h, p)) => (h, parse_port(p)?),
        None => (hostport, default_port),
    };
    if host.is_empty() {
        return Err(ProxyError::MissingHost);
    }
    if host.chars().any(|c| c.is_whitespace() || c == '/' || c == '[' || c == ']') {
        return Err(ProxyError::InvalidFormat);
    }
    Ok((host.to_string(), port))
}

fn parse_port(text: &str) -> Result<u16, ProxyError> {
    match text.parse::<u32>() {
        Ok(n) if (1..=65535).contains(&n) => Ok(n as u16),
        _ => Err(ProxyError::InvalidPort),
    }
}

/// Percent-decodes a credential. A malformed escape is an error, not a literal `%`.
fn percent_decode(text: &str) -> Result<String, ProxyError> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3).ok_or(ProxyError::InvalidEncoding)?;
            let hex = std::str::from_utf8(hex).map_err(|_| ProxyError::InvalidEncoding)?;
            let byte = u8::from_str_radix(hex, 16).map_err(|_| ProxyError::InvalidEncoding)?;
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| ProxyError::InvalidEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(input: &str) -> ProxyLink {
        ProxyLink::parse(input).unwrap_or_else(|e| panic!("{input:?} should parse: {e}"))
    }

    #[test]
    fn every_accepted_form_parses_to_its_scheme_host_and_port() {
        let http = ok("http://proxy.example:8080");
        assert_eq!((http.scheme(), http.host(), http.port()), (ProxyScheme::Http, "proxy.example", 8080));
        assert!(!http.authenticated());

        let https = ok("https://proxy.example");
        assert_eq!((https.scheme(), https.port()), (ProxyScheme::Https, 443));

        let socks = ok("socks5://u:p@h:1080");
        assert_eq!((socks.scheme(), socks.port()), (ProxyScheme::Socks5, 1080));
        assert!(socks.authenticated());

        let socks_h = ok("socks5h://h");
        assert_eq!((socks_h.scheme(), socks_h.port()), (ProxyScheme::Socks5h, 1080));

        let bare = ok("h.example:3128");
        assert_eq!((bare.scheme(), bare.port()), (ProxyScheme::Http, 3128));

        let bare_auth = ok("u:p@h.example");
        assert_eq!((bare_auth.scheme(), bare_auth.port(), bare_auth.authenticated()), (ProxyScheme::Http, 80, true));

        let provider = ok("h.example:8080:exp-user:pw-x");
        assert_eq!(provider.server_url(), "http://h.example:8080");
        assert!(provider.authenticated());
    }

    #[test]
    fn credentials_are_percent_decoded_and_split_at_the_right_separators() {
        let link = ok("socks5://us%40er:p%25ss@h:1080");
        assert_eq!(link.user().unwrap().expose(), "us@er");
        assert_eq!(link.password().unwrap().expose(), "p%ss");

        // Provider format: the password may contain colons; everything after the third
        // colon is the password.
        let provider = ok("h.example:8080:user:pa:ss");
        assert_eq!(provider.user().unwrap().expose(), "user");
        assert_eq!(provider.password().unwrap().expose(), "pa:ss");

        // Authority form: the userinfo ends at the last `@`.
        let at = ok("http://u:p@x@h.example:8080");
        assert_eq!(at.user().unwrap().expose(), "u");
        assert_eq!(at.password().unwrap().expose(), "p@x");
    }

    #[test]
    fn ipv6_literals_are_bracketed_and_default_ports_apply() {
        let v6 = ok("http://[::1]:3128");
        assert_eq!(v6.host(), "::1");
        assert_eq!(v6.server_url(), "http://[::1]:3128");
        let v6_default = ok("https://[2001:db8::1]");
        assert_eq!(v6_default.port(), 443);
        assert_eq!(ok("socks5://[::1]").port(), 1080);
    }

    #[test]
    fn a_trailing_slash_and_surrounding_whitespace_are_accepted() {
        assert_eq!(ok("  http://h.example:8080/  ").server_url(), "http://h.example:8080");
    }

    #[test]
    fn chrome_receives_socks5_for_socks5h_and_no_credentials() {
        let link = ok("socks5h://u:p@h.example:1080");
        assert_eq!(link.chrome_server_arg(), "socks5://h.example:1080");
        assert!(!link.chrome_server_arg().contains('u'));
    }

    #[test]
    fn every_refusal_is_its_own_error() {
        let cases = [
            ("", ProxyError::Empty),
            ("   ", ProxyError::Empty),
            ("ftp://h:21", ProxyError::UnsupportedScheme),
            ("socks4://h:1080", ProxyError::Socks4NotSupported),
            ("http://h:8080/path", ProxyError::PathNotAllowed),
            ("http://h:8080?x=1", ProxyError::PathNotAllowed),
            ("http://h:8080#frag", ProxyError::PathNotAllowed),
            ("http://h:0", ProxyError::InvalidPort),
            ("http://h:65536", ProxyError::InvalidPort),
            ("http://h:abc", ProxyError::InvalidPort),
            ("http://:8080", ProxyError::MissingHost),
            ("u:p@", ProxyError::MissingHost),
            ("http://h\n:1", ProxyError::ControlCharacter),
            ("h:1:u", ProxyError::InvalidFormat),
            ("[::1", ProxyError::InvalidFormat),
            ("::1", ProxyError::InvalidFormat),
            ("@h:1", ProxyError::InvalidFormat),
            ("h:1:u%zz:p", ProxyError::InvalidEncoding),
            ("h:1:u:p%", ProxyError::InvalidEncoding),
        ];
        for (input, expected) in cases {
            assert_eq!(ProxyLink::parse(input).unwrap_err(), expected, "case {expected:?}");
        }
    }

    #[test]
    fn no_output_of_a_link_shows_its_credentials() {
        const USER: &str = "uni-user-7";
        const PASSWORD: &str = "Pw-Unit-42!x";
        let links = [
            format!("http://{USER}:{PASSWORD}@proxy.example:8080"),
            format!("socks5://{USER}:{PASSWORD}@[::1]:1080"),
            format!("proxy.example:8080:{USER}:{PASSWORD}"),
        ];
        for raw in &links {
            let link = ok(raw);
            for shown in [format!("{link:?}"), format!("{link}"), format!("{:?}", link.user()), format!("{:?}", link.password())] {
                assert!(!shown.contains(USER) && !shown.contains(PASSWORD), "leak in {shown}");
            }
            assert!(!link.server_url().contains(USER) && !link.server_url().contains(PASSWORD));
            assert!(!link.chrome_server_arg().contains(USER) && !link.chrome_server_arg().contains(PASSWORD));
        }
        // Refusals never quote the input, so a broken link with a password stays hidden.
        let broken = format!("ftp://{USER}:{PASSWORD}@proxy.example:8080/x");
        let err = ProxyLink::parse(&broken).unwrap_err();
        for shown in [format!("{err:?}"), err.to_string()] {
            assert!(!shown.contains(USER) && !shown.contains(PASSWORD), "leak in {shown}");
        }
    }
}
