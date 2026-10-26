//! Minimal HTTP/2 client used by the demo and the integration tests.
//!
//! It sends an explicit, ordered field list (duplicates allowed) and reports the
//! response field list in the order the decoder produced it, so a test can
//! compare "what was sent" with "what the server recorded".

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use httlib_hpack::{Decoder, Encoder};
use rustls::pki_types::ServerName;

use crate::cert::TlsFiles;
use crate::h2frame::*;
use crate::http::lowercase_headers;

pub struct ClientResponse {
    pub status: u16,
    /// Response field list in decode order (pseudo-headers included).
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub alpn: String,
}

impl ClientResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub fn get(
    addr: SocketAddr,
    path: &str,
    extras: &[(String, String)],
    tls_files: &TlsFiles,
) -> Result<ClientResponse, Box<dyn std::error::Error>> {
    crate::cert::init_crypto();
    let config = crate::cert::rustls_client_config(tls_files)?;

    let tcp = TcpStream::connect(addr)?;
    tcp.set_nodelay(true)?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    let name = ServerName::try_from("localhost")?.to_owned();
    let tls = rustls::ClientConnection::new(config, name)?;
    let mut stream = rustls::StreamOwned::new(tls, tcp);
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock)?;
    }
    let alpn = stream
        .conn
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).to_string())
        .unwrap_or_else(|| "<none>".into());

    stream.write_all(PREFACE)?;
    stream.write_all(&settings_frame())?;
    stream.flush()?;

    let mut fields: Vec<(String, String)> = vec![
        (":method".into(), "GET".into()),
        (":scheme".into(), "https".into()),
        (":authority".into(), addr.to_string()),
        (":path".into(), path.into()),
        (
            "user-agent".into(),
            "scrapelens-testserver-client/0.1".into(),
        ),
    ];
    fields.extend(lowercase_headers(extras));
    let mut encoder = Encoder::default();
    let block = encode_headers(&mut encoder, &fields);
    write_frame(
        &mut stream,
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &block,
    )?;

    let mut decoder = Decoder::default();
    let mut resp_headers: Vec<(String, String)> = Vec::new();
    let mut body = Vec::new();
    let mut block_buf: Vec<u8> = Vec::new();
    let mut done = false;
    let deadline = Instant::now() + Duration::from_secs(10);

    while !done {
        if Instant::now() > deadline {
            return Err("h2 client timeout".into());
        }
        let frame = match read_frame(&mut stream) {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Err("h2 client read timeout".into());
            }
            Err(e) => return Err(e.into()),
        };
        match frame.ty {
            SETTINGS => {
                if frame.flags & FLAG_ACK == 0 {
                    for (id, value) in parse_settings(&frame.payload) {
                        if id == SETTINGS_INITIAL_WINDOW_SIZE {
                            let _ = value;
                        }
                    }
                    write_frame(&mut stream, SETTINGS, FLAG_ACK, 0, &[])?;
                }
            }
            PING => {
                if frame.flags & FLAG_ACK == 0 && frame.payload.len() == 8 {
                    write_frame(&mut stream, PING, FLAG_ACK, 0, &frame.payload)?;
                }
            }
            HEADERS | CONTINUATION => {
                block_buf.extend_from_slice(&frame.payload);
                if frame.end_headers() {
                    let decoded = decode_headers(&mut decoder, &block_buf)?;
                    resp_headers.extend(decoded);
                    block_buf.clear();
                }
                if frame.end_stream() {
                    done = true;
                }
            }
            DATA => {
                body.extend_from_slice(&frame.payload);
                if !frame.payload.is_empty() {
                    let inc = (frame.payload.len() as u32).to_be_bytes();
                    write_frame(&mut stream, WINDOW_UPDATE, 0, 0, &inc)?;
                    write_frame(&mut stream, WINDOW_UPDATE, 0, 1, &inc)?;
                }
                if frame.end_stream() {
                    done = true;
                }
            }
            RST_STREAM => {
                return Err(format!(
                    "stream reset by server (code {:?})",
                    frame
                        .payload
                        .get(..4)
                        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                )
                .into());
            }
            GOAWAY => break,
            _ => {}
        }
    }

    let status = resp_headers
        .iter()
        .find(|(n, _)| n == ":status")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    Ok(ClientResponse {
        status,
        headers: resp_headers,
        body,
        alpn,
    })
}

fn settings_frame() -> Vec<u8> {
    let payload = settings_payload(&[
        (SETTINGS_INITIAL_WINDOW_SIZE, 1 << 20),
        (SETTINGS_MAX_FRAME_SIZE, 16_384),
    ]);
    let mut out = Vec::with_capacity(9 + payload.len());
    let len = payload.len();
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.push(SETTINGS);
    out.push(0);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&payload);
    out
}
