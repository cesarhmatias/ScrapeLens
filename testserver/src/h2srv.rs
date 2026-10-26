//! HTTP/2 reference server.
//!
//! The reference for header order is the HPACK **decoded** field list, i.e. the
//! list that the decoder emits at the point of decoding: order and duplicates
//! are kept, pseudo-headers stay in their decoded position. Nothing is turned
//! into a map before it is recorded.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use httlib_hpack::{Decoder, Encoder};

use crate::endpoints::{self, MAX_BODY};
use crate::evidence::Evidence;
use crate::h2frame::*;
use crate::http::{Proto, Req, lowercase_headers};
use crate::util::{ConnIds, note};

const LOCAL_INITIAL_WINDOW: i64 = 1 << 20;
const LOCAL_MAX_FRAME: usize = 16_384;

pub fn serve(
    addr: SocketAddr,
    ev: Arc<Evidence>,
    tls: Arc<rustls::ServerConfig>,
    h3_port: Option<u16>,
) -> io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    serve_on(listener, ev, tls, h3_port)
}

/// Accept loop over an already-bound listener (used by tests with port 0).
pub fn serve_on(
    listener: TcpListener,
    ev: Arc<Evidence>,
    tls: Arc<rustls::ServerConfig>,
    h3_port: Option<u16>,
) -> io::Result<()> {
    let local = listener.local_addr()?;
    note(
        "h2",
        format!(
            "listening on https://{local} (ALPN h2, HPACK decode order) evidence={}",
            ev.path().display()
        ),
    );
    let ids = Arc::new(ConnIds::default());
    for incoming in listener.incoming() {
        let tcp = match incoming {
            Ok(s) => s,
            Err(e) => {
                note("h2", format!("accept failed: {e}"));
                continue;
            }
        };
        let ev = ev.clone();
        let tls = tls.clone();
        let conn = ids.next();
        thread::spawn(move || {
            if let Err(e) = tls_conn(tcp, ev, tls, conn.clone(), local, h3_port) {
                note("h2", format!("{conn}: closed ({e})"));
            }
        });
    }
    Ok(())
}

fn tls_conn(
    tcp: TcpStream,
    ev: Arc<Evidence>,
    tls: Arc<rustls::ServerConfig>,
    conn: String,
    local: SocketAddr,
    h3_port: Option<u16>,
) -> Result<(), Box<dyn std::error::Error>> {
    tcp.set_nodelay(true)?;
    tcp.set_read_timeout(Some(Duration::from_secs(120)))?;
    let peer = tcp
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into());
    let tls_conn = rustls::ServerConnection::new(tls)?;
    let mut stream = rustls::StreamOwned::new(tls_conn, tcp);
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock)?;
    }
    let alpn = stream
        .conn
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).to_string())
        .unwrap_or_else(|| "<none>".into());
    if stream.conn.alpn_protocol() != Some(b"h2") {
        return Err(format!("peer did not negotiate h2 (alpn={alpn})").into());
    }
    serve_stream(&mut stream, ev, conn, local.to_string(), peer, h3_port)
}

struct StreamState {
    block: Vec<u8>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    truncated: bool,
    end_headers: bool,
    end_stream: bool,
    send_window: i64,
    responded: bool,
}

impl StreamState {
    fn new(send_window: i64) -> Self {
        Self {
            block: Vec::new(),
            headers: Vec::new(),
            body: Vec::new(),
            truncated: false,
            end_headers: false,
            end_stream: false,
            send_window,
            responded: false,
        }
    }
}

pub struct H2Conn<'a, S: Read + Write> {
    io: &'a mut S,
    ev: Arc<Evidence>,
    server: String,
    conn: String,
    decoder: Decoder<'static>,
    encoder: Encoder<'static>,
    streams: HashMap<u32, StreamState>,
    pending: FrameQueue,
    alt_svc: Option<String>,
    conn_window: i64,
    peer_initial_window: i64,
    peer_max_frame: usize,
    goaway: bool,
}

pub fn serve_stream<S: Read + Write>(
    io: &mut S,
    ev: Arc<Evidence>,
    conn: String,
    server: String,
    _peer: String,
    h3_port: Option<u16>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut h2 = H2Conn {
        io,
        ev,
        server,
        conn,
        decoder: Decoder::default(),
        encoder: Encoder::default(),
        streams: HashMap::new(),
        pending: FrameQueue::new(),
        alt_svc: h3_port.map(|p| format!("h3=\":{p}\"; ma=86400")),
        conn_window: 65_535,
        peer_initial_window: 65_535,
        peer_max_frame: LOCAL_MAX_FRAME,
        goaway: false,
    };
    h2.run()
}

impl<'a, S: Read + Write> H2Conn<'a, S> {
    fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut preface = [0u8; 24];
        self.io.read_exact(&mut preface)?;
        if preface != PREFACE[..] {
            return Err("bad h2 preface".into());
        }
        let settings = settings_payload(&[
            (SETTINGS_HEADER_TABLE_SIZE, 4096),
            (SETTINGS_MAX_CONCURRENT_STREAMS, 100),
            (SETTINGS_INITIAL_WINDOW_SIZE, LOCAL_INITIAL_WINDOW as u32),
            (SETTINGS_MAX_HEADER_LIST_SIZE, 65536),
        ]);
        write_frame(self.io, SETTINGS, 0, 0, &settings)?;

        while !self.goaway {
            let frame = match self.next_frame() {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            };
            self.handle(frame)?;
        }
        Ok(())
    }

    fn next_frame(&mut self) -> io::Result<Option<Frame>> {
        if let Some(f) = self.pending.pop_front() {
            return Ok(Some(f));
        }
        read_frame(self.io)
    }

    fn handle(&mut self, f: Frame) -> io::Result<()> {
        match f.ty {
            SETTINGS => {
                if f.flags & FLAG_ACK == 0 {
                    for (id, value) in parse_settings(&f.payload) {
                        match id {
                            SETTINGS_INITIAL_WINDOW_SIZE => {
                                let new = value as i64;
                                let delta = new - self.peer_initial_window;
                                self.peer_initial_window = new;
                                for st in self.streams.values_mut() {
                                    st.send_window += delta;
                                }
                            }
                            SETTINGS_MAX_FRAME_SIZE => {
                                let v = value as usize;
                                if (16_384..=16_777_215).contains(&v) {
                                    self.peer_max_frame = v;
                                }
                            }
                            _ => {}
                        }
                    }
                    write_frame(self.io, SETTINGS, FLAG_ACK, 0, &[])?;
                }
            }
            WINDOW_UPDATE => {
                if f.payload.len() >= 4 {
                    let inc = (u32::from_be_bytes([
                        f.payload[0],
                        f.payload[1],
                        f.payload[2],
                        f.payload[3],
                    ]) & 0x7FFF_FFFF) as i64;
                    if f.stream == 0 {
                        self.conn_window += inc;
                    } else if let Some(st) = self.streams.get_mut(&f.stream) {
                        st.send_window += inc;
                    }
                }
            }
            PING => {
                if f.flags & FLAG_ACK == 0 && f.payload.len() == 8 {
                    write_frame(self.io, PING, FLAG_ACK, 0, &f.payload)?;
                }
            }
            HEADERS => {
                if f.stream == 0 || f.stream % 2 == 0 {
                    write_frame(
                        self.io,
                        GOAWAY,
                        0,
                        0,
                        &goaway_payload(PROTOCOL_ERROR, "bad stream id"),
                    )?;
                    self.goaway = true;
                    return Ok(());
                }
                let fragment = match header_fragment(&f) {
                    Ok(v) => v,
                    Err(e) => {
                        note("h2", format!("{}: bad HEADERS: {e}", self.conn));
                        write_frame(
                            self.io,
                            RST_STREAM,
                            0,
                            f.stream,
                            &PROTOCOL_ERROR.to_be_bytes(),
                        )?;
                        return Ok(());
                    }
                };
                let st = self
                    .streams
                    .entry(f.stream)
                    .or_insert_with(|| StreamState::new(self.peer_initial_window));
                st.block.extend_from_slice(&fragment);
                if f.end_headers() {
                    st.end_headers = true;
                }
                if f.end_stream() {
                    st.end_stream = true;
                }
                if st.block.len() > 512 * 1024 {
                    note("h2", format!("{}: header block too large", self.conn));
                    self.streams.remove(&f.stream);
                    write_frame(
                        self.io,
                        RST_STREAM,
                        0,
                        f.stream,
                        &PROTOCOL_ERROR.to_be_bytes(),
                    )?;
                    return Ok(());
                }
                if f.end_headers() {
                    self.on_end_headers(f.stream)?;
                }
            }
            CONTINUATION => {
                let Some(st) = self.streams.get_mut(&f.stream) else {
                    return Ok(());
                };
                st.block.extend_from_slice(&f.payload);
                if f.end_headers() {
                    st.end_headers = true;
                    self.on_end_headers(f.stream)?;
                }
            }
            DATA => {
                let payload_len = f.payload.len() as i64;
                let mut data = &f.payload[..];
                if f.flags & FLAG_PADDED != 0 && !data.is_empty() {
                    let pad = data[0] as usize;
                    let rest = &data[1..];
                    if pad <= rest.len() {
                        data = &rest[..rest.len() - pad];
                    } else {
                        data = &[];
                    }
                }
                let Some(st) = self.streams.get_mut(&f.stream) else {
                    return Ok(());
                };
                let room = MAX_BODY.saturating_sub(st.body.len());
                if data.len() > room {
                    st.body.extend_from_slice(&data[..room]);
                    st.truncated = true;
                } else {
                    st.body.extend_from_slice(data);
                }
                if f.end_stream() {
                    st.end_stream = true;
                }
                let done = st.end_stream;
                // Return flow-control credit for every consumed DATA byte.
                if payload_len > 0 {
                    let inc = (payload_len as u32).to_be_bytes();
                    write_frame(self.io, WINDOW_UPDATE, 0, 0, &inc)?;
                    write_frame(self.io, WINDOW_UPDATE, 0, f.stream, &inc)?;
                }
                if done {
                    self.finish(f.stream)?;
                }
            }
            RST_STREAM => {
                self.streams.remove(&f.stream);
            }
            GOAWAY => {
                self.goaway = true;
            }
            PRIORITY | PUSH_PROMISE => {
                // Ignored by design: priority/priority updates carry no header
                // information for this test.
            }
            _ => {}
        }
        Ok(())
    }

    fn on_end_headers(&mut self, sid: u32) -> io::Result<()> {
        let Some(st) = self.streams.get_mut(&sid) else {
            return Ok(());
        };
        let block = std::mem::take(&mut st.block);
        match decode_headers(&mut self.decoder, &block) {
            Ok(headers) => {
                st.headers = headers;
                // Keep the raw HPACK bytes in the request for evidence.
                st.block = block;
            }
            Err(e) => {
                note(
                    "h2",
                    format!("{}: HPACK decode failed on {sid}: {e}", self.conn),
                );
                write_frame(self.io, RST_STREAM, 0, sid, &PROTOCOL_ERROR.to_be_bytes())?;
                self.streams.remove(&sid);
                return Ok(());
            }
        }
        let done = self
            .streams
            .get(&sid)
            .map(|s| s.end_stream)
            .unwrap_or(false);
        if done {
            self.finish(sid)?;
        }
        Ok(())
    }

    fn finish(&mut self, sid: u32) -> io::Result<()> {
        let Some(mut st) = self.streams.remove(&sid) else {
            return Ok(());
        };
        if st.responded {
            return Ok(());
        }
        st.responded = true;

        let headers = std::mem::take(&mut st.headers);
        let method = header_value(&headers, ":method").unwrap_or_default();
        let target = header_value(&headers, ":path").unwrap_or_else(|| "/".into());
        let authority = header_value(&headers, ":authority");
        let block = std::mem::take(&mut st.block);
        let mut notes = Vec::new();
        for required in [":method", ":scheme", ":path"] {
            if header_value(&headers, required).is_none() {
                notes.push(format!("missing pseudo-header {required}"));
            }
        }
        if st.truncated {
            notes.push(format!("body truncated at {MAX_BODY} bytes"));
        }

        let req = Req {
            proto: Proto::H2,
            conn: self.conn.clone(),
            stream: Some(sid as u64),
            method: method.clone(),
            target: target.clone(),
            authority,
            headers,
            raw_head: None,
            header_block: Some(block),
            body: std::mem::take(&mut st.body),
            body_truncated: st.truncated,
            body_framing: None,
            notes,
        };
        let mut resp = endpoints::handle(&req);
        let body = if method.eq_ignore_ascii_case("HEAD") {
            Vec::new()
        } else {
            resp.body.clone()
        };
        let mut fields: Vec<(String, String)> =
            vec![(":status".to_string(), resp.status.to_string())];
        fields.extend(lowercase_headers(&resp.headers));
        fields.push((
            "server".to_string(),
            "scrapelens-testserver/0.1".to_string(),
        ));
        if let Some(alt) = &self.alt_svc {
            fields.push(("alt-svc".to_string(), alt.clone()));
        }
        fields.push(("content-length".to_string(), resp.body.len().to_string()));
        // Evidence keeps the exact field list sent, without the :status field.
        resp.headers = fields[1..].to_vec();
        self.ev
            .record(&self.server, &req, &resp)
            .map_err(|e| io::Error::other(format!("evidence write failed: {e}")))?;
        note(
            "h2",
            format!(
                "{} stream {sid} {method} {target} -> {} ({} headers)",
                self.conn,
                resp.status,
                req.headers.len()
            ),
        );

        let block = encode_headers(&mut self.encoder, &fields);
        self.send_header_block(sid, &block, body.is_empty())?;
        if !body.is_empty() {
            self.send_data(sid, &body)?;
        }
        Ok(())
    }

    fn send_header_block(&mut self, sid: u32, block: &[u8], end_stream: bool) -> io::Result<()> {
        let max = self.peer_max_frame.max(1);
        let mut chunks = block.chunks(max).peekable();
        let first = chunks.next().unwrap_or(&[]);
        let more = chunks.peek().is_some();
        write_frame(
            self.io,
            HEADERS,
            (if more { 0 } else { FLAG_END_HEADERS })
                | (if end_stream && !more {
                    FLAG_END_STREAM
                } else {
                    0
                }),
            sid,
            first,
        )?;
        while let Some(chunk) = chunks.next() {
            let last = chunks.peek().is_none();
            write_frame(
                self.io,
                CONTINUATION,
                if last { FLAG_END_HEADERS } else { 0 },
                sid,
                chunk,
            )?;
        }
        Ok(())
    }

    fn send_data(&mut self, sid: u32, body: &[u8]) -> io::Result<()> {
        let mut off = 0usize;
        let mut spins = 0;
        while off < body.len() {
            let stream_window = self
                .streams
                .get(&sid)
                .map(|s| s.send_window)
                .unwrap_or(self.peer_initial_window);
            let allowed = self
                .conn_window
                .min(stream_window)
                .min(self.peer_max_frame as i64)
                .min((body.len() - off) as i64);
            if allowed <= 0 {
                spins += 1;
                if spins > 10_000 {
                    return Err(io::Error::other("flow-control wait timed out"));
                }
                self.pump_for_window()?;
                continue;
            }
            let n = allowed as usize;
            let last = off + n == body.len();
            write_frame(
                self.io,
                DATA,
                if last { FLAG_END_STREAM } else { 0 },
                sid,
                &body[off..off + n],
            )?;
            self.conn_window -= n as i64;
            if let Some(st) = self.streams.get_mut(&sid) {
                st.send_window -= n as i64;
            }
            off += n;
        }
        Ok(())
    }

    /// Read ahead while the peer's flow-control window is empty. Window/ping
    /// frames are handled immediately, everything else is queued for the main
    /// loop (so other streams are not lost).
    fn pump_for_window(&mut self) -> io::Result<()> {
        let frame = match read_frame(self.io) {
            Ok(Some(f)) => f,
            Ok(None) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "eof while waiting for window",
                ));
            }
            Err(e) => return Err(e),
        };
        match frame.ty {
            WINDOW_UPDATE | PING | SETTINGS => {
                self.handle(frame)?;
            }
            GOAWAY => {
                self.goaway = true;
                return Err(io::Error::other("goaway while sending"));
            }
            _ => self.pending.push_back(frame),
        }
        Ok(())
    }
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.clone())
}

fn header_fragment(f: &Frame) -> Result<Vec<u8>, String> {
    let mut p = &f.payload[..];
    if f.flags & FLAG_PADDED != 0 {
        if p.is_empty() {
            return Err("padded HEADERS without pad length".into());
        }
        let pad = p[0] as usize;
        p = &p[1..];
        if pad > p.len() {
            return Err("padding larger than frame".into());
        }
        p = &p[..p.len() - pad];
    }
    if f.flags & FLAG_PRIORITY != 0 {
        if p.len() < 5 {
            return Err("priority flag without priority payload".into());
        }
        p = &p[5..];
    }
    Ok(p.to_vec())
}

fn goaway_payload(code: u32, msg: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + msg.len());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(msg.as_bytes());
    out
}
