//! Minimal HTTP/2 framing helpers (shared by the h2 server and the h2 client).
//!
//! Only what the reference tests need: frame read/write, SETTINGS payloads and
//! HPACK encode/decode through the `httlib-hpack` library. The decoder output
//! (`Vec<(name, value, flags)>`) is the reference point for header order.

use std::collections::VecDeque;
use std::io::{self, Read, Write};

use httlib_hpack::{Decoder, Encoder};

pub const DATA: u8 = 0x0;
pub const HEADERS: u8 = 0x1;
pub const PRIORITY: u8 = 0x2;
pub const RST_STREAM: u8 = 0x3;
pub const SETTINGS: u8 = 0x4;
pub const PUSH_PROMISE: u8 = 0x5;
pub const PING: u8 = 0x6;
pub const GOAWAY: u8 = 0x7;
pub const WINDOW_UPDATE: u8 = 0x8;
pub const CONTINUATION: u8 = 0x9;

pub const FLAG_END_STREAM: u8 = 0x1;
pub const FLAG_ACK: u8 = 0x1;
pub const FLAG_END_HEADERS: u8 = 0x4;
pub const FLAG_PADDED: u8 = 0x8;
pub const FLAG_PRIORITY: u8 = 0x20;

pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// SETTINGS identifiers.
pub const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
pub const SETTINGS_ENABLE_PUSH: u16 = 0x2;
pub const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
pub const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
pub const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
pub const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;

// Error codes.
pub const CANCEL: u32 = 0x8;
pub const PROTOCOL_ERROR: u32 = 0x1;

#[derive(Debug, Clone)]
pub struct Frame {
    pub ty: u8,
    pub flags: u8,
    pub stream: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(ty: u8, flags: u8, stream: u32, payload: Vec<u8>) -> Self {
        Self {
            ty,
            flags,
            stream,
            payload,
        }
    }

    pub fn end_stream(&self) -> bool {
        self.flags & FLAG_END_STREAM != 0
    }

    pub fn end_headers(&self) -> bool {
        self.flags & FLAG_END_HEADERS != 0
    }
}

pub fn write_frame<W: Write>(
    w: &mut W,
    ty: u8,
    flags: u8,
    stream: u32,
    payload: &[u8],
) -> io::Result<()> {
    let len = payload.len();
    if len > 0xFF_FFFF {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame payload too large",
        ));
    }
    let mut head = [0u8; 9];
    head[0] = (len >> 16) as u8;
    head[1] = (len >> 8) as u8;
    head[2] = len as u8;
    head[3] = ty;
    head[4] = flags;
    head[5..9].copy_from_slice(&(stream & 0x7FFF_FFFF).to_be_bytes());
    w.write_all(&head)?;
    w.write_all(payload)?;
    w.flush()
}

/// Read one frame; `Ok(None)` on a clean EOF at a frame boundary.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Option<Frame>> {
    let mut head = [0u8; 9];
    let mut got = 0;
    while got < 9 {
        match r.read(&mut head[got..]) {
            Ok(0) => {
                if got == 0 {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "eof inside frame header",
                ));
            }
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    let len = ((head[0] as usize) << 16) | ((head[1] as usize) << 8) | head[2] as usize;
    if len > 16 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {len}"),
        ));
    }
    let ty = head[3];
    let flags = head[4];
    let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7FFF_FFFF;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(Some(Frame {
        ty,
        flags,
        stream,
        payload,
    }))
}

pub fn settings_payload(pairs: &[(u16, u32)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(pairs.len() * 6);
    for (id, value) in pairs {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&value.to_be_bytes());
    }
    out
}

pub fn parse_settings(payload: &[u8]) -> Vec<(u16, u32)> {
    payload
        .chunks_exact(6)
        .map(|c| {
            (
                u16::from_be_bytes([c[0], c[1]]),
                u32::from_be_bytes([c[2], c[3], c[4], c[5]]),
            )
        })
        .collect()
}

/// Encode a header list with HPACK, preserving the given order and duplicates.
pub fn encode_headers(encoder: &mut Encoder, fields: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(fields.len() * 24);
    for (name, value) in fields {
        let flags = Encoder::BEST_FORMAT | Encoder::WITH_INDEXING;
        encoder
            .encode(
                (name.as_bytes().to_vec(), value.as_bytes().to_vec(), flags),
                &mut out,
            )
            .expect("HPACK encode");
    }
    out
}

/// Decode an HPACK field block. The returned vector is in decode order with
/// duplicates preserved; this is the reference used for evidence.
pub fn decode_headers(
    decoder: &mut Decoder<'static>,
    block: &[u8],
) -> Result<Vec<(String, String)>, String> {
    let mut buf = block.to_vec();
    let mut dst: Vec<(Vec<u8>, Vec<u8>, u8)> = Vec::with_capacity(64);
    decoder
        .decode(&mut buf, &mut dst)
        .map_err(|e| format!("{e:?}"))?;
    if !buf.is_empty() {
        return Err(format!("trailing bytes after HPACK block: {}", buf.len()));
    }
    Ok(dst
        .into_iter()
        .map(|(n, v, _flags)| {
            (
                String::from_utf8_lossy(&n).to_string(),
                String::from_utf8_lossy(&v).to_string(),
            )
        })
        .collect())
}

/// A tiny queue used while waiting for flow-control window updates.
pub type FrameQueue = VecDeque<Frame>;
