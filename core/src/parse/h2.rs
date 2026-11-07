//! HTTP/2 frames decoded from Chrome's `SSL_SOCKET_BYTES_SENT`/`RECEIVED`
//! plaintext, with HPACK state per connection and per direction.
//!
//! Chrome logs the bytes it hands to TLS (`Everything` NetLog). For an h2
//! connection that stream starts with the HTTP/2 preface and contains the real
//! HEADERS/CONTINUATION frames. This module records that order as additional
//! evidence; it does not replace `requestHeaders` or their verification state.
//!
//! The decoded values may contain credentials: the sanitizer drops this evidence
//! entirely.

use std::collections::BTreeMap;

use httlib_hpack::Decoder;

use crate::model::{
    H2ConnectionEvidence, H2Field, H2Setting, H2StreamEvidence, H2WindowUpdate, Provenance, Source,
    TlsHelloEvidence, Verification, Warning,
};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const MAX_BYTES: usize = 16 * 1024 * 1024;

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const WINDOW_UPDATE: u8 = 0x8;
const CONTINUATION: u8 = 0x9;

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Request,
    Response,
}

struct PendingBlock {
    stream_id: u32,
    bytes: Vec<u8>,
    end_stream: bool,
}

/// Decodes both directions for every SSL source. `sent` is client→server,
/// `received` is server→client; each direction keeps its own HPACK table.
pub fn decode_h2(
    sent: &BTreeMap<u32, Vec<u8>>,
    received: &BTreeMap<u32, Vec<u8>>,
) -> (Vec<H2ConnectionEvidence>, Vec<Warning>) {
    let mut sources = sent
        .keys()
        .chain(received.keys())
        .copied()
        .collect::<Vec<_>>();
    sources.sort_unstable();
    sources.dedup();

    let mut evidence = Vec::new();
    let mut warnings = Vec::new();
    for source in sources {
        let mut streams: BTreeMap<u32, H2StreamEvidence> = BTreeMap::new();
        let mut settings = Vec::new();
        let mut window_updates = Vec::new();
        let mut notes = Vec::new();

        let Some(sent_bytes) = sent.get(&source) else {
            continue;
        };
        if !sent_bytes.starts_with(PREFACE) {
            // `SSL_SOCKET_BYTES_SENT` holds the plaintext in h1 too. Only an h2
            // connection starts with the preface; an h1 request line is not a frame.
            continue;
        }
        let preface = true;
        if sent_bytes.len() > MAX_BYTES {
            warnings.push(Warning::new(
                "netlog.h2_bytes_too_large",
                format!(
                    "SSL source {source}: {} bytes of HTTP/2 plaintext left undecoded",
                    sent_bytes.len()
                ),
            ));
        } else {
            let mut decoder = Decoder::with_dynamic_size(65536);
            decode_direction(
                sent_bytes,
                Direction::Request,
                &mut decoder,
                &mut streams,
                &mut settings,
                &mut window_updates,
                source,
                &mut warnings,
            );
        }
        if let Some(bytes) = received.get(&source) {
            if bytes.len() > MAX_BYTES {
                warnings.push(Warning::new(
                    "netlog.h2_bytes_too_large",
                    format!(
                        "SSL source {source}: {} bytes of HTTP/2 plaintext left undecoded",
                        bytes.len()
                    ),
                ));
            } else {
                let mut decoder = Decoder::with_dynamic_size(65536);
                decode_direction(
                    bytes,
                    Direction::Response,
                    &mut decoder,
                    &mut streams,
                    &mut settings,
                    &mut window_updates,
                    source,
                    &mut warnings,
                );
            }
        }
        if streams.is_empty() && settings.is_empty() && window_updates.is_empty() {
            continue;
        }
        let mut provenance = Provenance::new(
            Source::NetLog,
            "netlog.ssl_bytes.hpack",
            Verification::Verified,
        )
        .with_note(
            "decoded from Chrome's plaintext SSL_SOCKET_BYTES_SENT/RECEIVED log; this is the bytes Chrome logged, not an independent TLS capture",
        )
        .with_source_id(source.to_string());
        provenance.notes.append(&mut notes);
        evidence.push(H2ConnectionEvidence {
            source_id: source,
            preface,
            settings,
            window_updates,
            streams: streams.into_values().collect(),
            provenance,
            notes: Vec::new(),
        });
    }
    (evidence, warnings)
}

#[allow(clippy::too_many_arguments)]
fn decode_direction(
    bytes: &[u8],
    direction: Direction,
    decoder: &mut Decoder<'static>,
    streams: &mut BTreeMap<u32, H2StreamEvidence>,
    settings: &mut Vec<H2Setting>,
    window_updates: &mut Vec<H2WindowUpdate>,
    source: u32,
    warnings: &mut Vec<Warning>,
) {
    let mut offset = if bytes.starts_with(PREFACE) {
        PREFACE.len()
    } else {
        0
    };
    let mut pending: Option<PendingBlock> = None;
    while offset + 9 <= bytes.len() {
        let len = ((bytes[offset] as usize) << 16)
            | ((bytes[offset + 1] as usize) << 8)
            | bytes[offset + 2] as usize;
        let ty = bytes[offset + 3];
        let flags = bytes[offset + 4];
        let stream_id = u32::from_be_bytes([
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
            bytes[offset + 8],
        ]) & 0x7FFF_FFFF;
        offset += 9;
        if offset + len > bytes.len() {
            warnings.push(Warning::new(
                "netlog.h2_frame_truncated",
                format!("SSL source {source}: frame type {ty} announces {len} bytes but the plaintext ends early"),
            ));
            return;
        }
        let payload = &bytes[offset..offset + len];
        offset += len;

        match ty {
            SETTINGS if flags == 0 => {
                if !payload.is_empty() && payload.len() % 6 == 0 {
                    for chunk in payload.chunks_exact(6) {
                        settings.push(H2Setting {
                            id: u16::from_be_bytes([chunk[0], chunk[1]]),
                            value: u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]),
                        });
                    }
                }
            }
            WINDOW_UPDATE if payload.len() == 4 => {
                let increment =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                        & 0x7FFF_FFFF;
                window_updates.push(H2WindowUpdate {
                    stream_id,
                    increment,
                });
            }
            DATA => {
                let stream = streams.entry(stream_id).or_default();
                stream.stream_id = stream_id;
                if direction == Direction::Request {
                    stream.request_end_stream |= flags & FLAG_END_STREAM != 0;
                } else {
                    stream.response_end_stream |= flags & FLAG_END_STREAM != 0;
                }
            }
            HEADERS | CONTINUATION => {
                let end_stream = flags & FLAG_END_STREAM != 0;
                let end_headers = flags & FLAG_END_HEADERS != 0;
                let Some(fragment) = header_fragment(ty, flags, payload) else {
                    warnings.push(Warning::new(
                        "netlog.h2_header_fragment_invalid",
                        format!(
                            "SSL source {source}: malformed HEADERS payload on stream {stream_id}"
                        ),
                    ));
                    return;
                };
                if ty == CONTINUATION {
                    let Some(open) = pending.as_ref() else {
                        warnings.push(Warning::new(
                            "netlog.h2_continuation_out_of_order",
                            format!("SSL source {source}: CONTINUATION for stream {stream_id} has no open HEADERS block"),
                        ));
                        return;
                    };
                    if open.stream_id != stream_id {
                        warnings.push(Warning::new(
                            "netlog.h2_continuation_out_of_order",
                            format!("SSL source {source}: CONTINUATION for stream {stream_id} does not follow the open block"),
                        ));
                        return;
                    }
                    {
                        let open = pending.as_mut().expect("open block");
                        open.bytes.extend_from_slice(&fragment);
                        open.end_stream |= end_stream;
                    }
                    if end_headers {
                        let done = pending.take().expect("pending block");
                        decode_block(
                            &done.bytes,
                            done.stream_id,
                            direction,
                            decoder,
                            streams,
                            done.end_stream,
                            source,
                            warnings,
                        );
                    }
                } else if pending.is_some() {
                    warnings.push(Warning::new(
                        "netlog.h2_headers_interleaved",
                        format!("SSL source {source}: HEADERS on stream {stream_id} while another block is open"),
                    ));
                    return;
                } else if end_headers {
                    decode_block(
                        &fragment, stream_id, direction, decoder, streams, end_stream, source,
                        warnings,
                    );
                } else {
                    pending = Some(PendingBlock {
                        stream_id,
                        bytes: fragment,
                        end_stream,
                    });
                }
            }
            RST_STREAM => {
                let stream = streams.entry(stream_id).or_default();
                stream.stream_id = stream_id;
                if direction == Direction::Request {
                    stream.request_end_stream = true;
                } else {
                    stream.response_end_stream = true;
                }
            }
            _ => {}
        }
    }
    if let Some(pending) = pending {
        warnings.push(Warning::new(
            "netlog.h2_headers_incomplete",
            format!(
                "SSL source {source}: HEADERS block for stream {} ended before END_HEADERS",
                pending.stream_id
            ),
        ));
    }
}

fn header_fragment(ty: u8, flags: u8, payload: &[u8]) -> Option<Vec<u8>> {
    let mut start = 0usize;
    let mut end = payload.len();
    if ty == HEADERS {
        if flags & FLAG_PADDED != 0 {
            let pad = *payload.first()? as usize;
            start += 1;
            if pad > payload.len().saturating_sub(start) {
                return None;
            }
            end = payload.len() - pad;
        }
        if flags & FLAG_PRIORITY != 0 {
            start += 5;
        }
    }
    if start > end {
        return None;
    }
    Some(payload[start..end].to_vec())
}

#[allow(clippy::too_many_arguments)]
fn decode_block(
    block: &[u8],
    stream_id: u32,
    direction: Direction,
    decoder: &mut Decoder<'static>,
    streams: &mut BTreeMap<u32, H2StreamEvidence>,
    end_stream: bool,
    source: u32,
    warnings: &mut Vec<Warning>,
) {
    let mut input = block.to_vec();
    let mut decoded: Vec<(Vec<u8>, Vec<u8>, u8)> = Vec::new();
    if let Err(error) = decoder.decode(&mut input, &mut decoded) {
        warnings.push(Warning::new(
            "netlog.h2_hpack_decode_failed",
            format!("SSL source {source}, stream {stream_id}: HPACK decode failed: {error:?}"),
        ));
        return;
    }
    if !input.is_empty() {
        warnings.push(Warning::new(
            "netlog.h2_hpack_trailing_bytes",
            format!(
                "SSL source {source}, stream {stream_id}: {} byte(s) left after the HPACK block",
                input.len()
            ),
        ));
    }
    let fields: Vec<H2Field> = decoded
        .into_iter()
        .map(|(name, value, _)| H2Field {
            name: String::from_utf8_lossy(&name).to_string(),
            value: String::from_utf8_lossy(&value).to_string(),
        })
        .collect();
    let stream = streams.entry(stream_id).or_default();
    stream.stream_id = stream_id;
    match direction {
        Direction::Request => {
            stream.request = fields;
            stream.request_end_stream |= end_stream;
        }
        Direction::Response => {
            stream.response = fields;
            stream.response_end_stream |= end_stream;
        }
    }
}

/// TLS ClientHello evidence, with JA4 computed per the FoxIO specification.
pub fn decode_client_hellos(hellos: &[(u32, Vec<u8>)]) -> Vec<TlsHelloEvidence> {
    let mut out = Vec::new();
    for (source_id, bytes) in hellos {
        match parse_client_hello(*source_id, bytes) {
            Some(evidence) => out.push(evidence),
            None => continue,
        }
    }
    out
}

struct ClientHello<'a> {
    legacy_version: u16,
    ciphers: Vec<u16>,
    extensions: Vec<(u16, &'a [u8])>,
    server_name: Option<String>,
    alpn: Vec<String>,
    supported_versions: Vec<u16>,
    signature_algorithms: Vec<u16>,
    groups: Vec<u16>,
}

fn parse_client_hello(source_id: u32, bytes: &[u8]) -> Option<TlsHelloEvidence> {
    let body = handshake_body(bytes)?;
    let hello = parse_hello(body)?;
    let version = hello_version(&hello);
    let version_code = version_code(version);
    let has_sni = hello.server_name.is_some();
    let alpn = alpn_pair(hello.alpn.first().map(String::as_str));
    let cipher_count = hello
        .ciphers
        .iter()
        .filter(|cipher| !is_grease(**cipher))
        .count()
        .min(99);
    let extension_count = hello
        .extensions
        .iter()
        .filter(|(kind, _)| !is_grease(*kind))
        .count()
        .min(99);
    let cipher_list: Vec<u16> = hello
        .ciphers
        .iter()
        .copied()
        .filter(|cipher| !is_grease(*cipher))
        .collect();
    let mut sorted_ciphers = cipher_list.clone();
    sorted_ciphers.sort_unstable();
    let ja4_b = if sorted_ciphers.is_empty() {
        "000000000000".to_string()
    } else {
        sha12(
            &sorted_ciphers
                .iter()
                .map(|c| format!("{c:04x}"))
                .collect::<Vec<_>>()
                .join(","),
        )
    };
    let mut extensions: Vec<u16> = hello
        .extensions
        .iter()
        .map(|(kind, _)| *kind)
        .filter(|kind| !is_grease(*kind) && *kind != 0 && *kind != 0x0010)
        .collect();
    extensions.sort_unstable();
    let ja4_c = if extensions.is_empty() {
        "000000000000".to_string()
    } else {
        let mut text = extensions
            .iter()
            .map(|kind| format!("{kind:04x}"))
            .collect::<Vec<_>>()
            .join(",");
        let signature_algorithms: Vec<u16> = hello
            .signature_algorithms
            .iter()
            .copied()
            .filter(|algorithm| !is_grease(*algorithm))
            .collect();
        if !signature_algorithms.is_empty() {
            text.push('_');
            text.push_str(
                &signature_algorithms
                    .iter()
                    .map(|algorithm| format!("{algorithm:04x}"))
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        sha12(&text)
    };
    let ja4 = format!(
        "t{version_code}{}{cipher_count:02}{extension_count:02}{alpn}_{ja4_b}_{ja4_c}",
        if has_sni { "d" } else { "i" }
    );
    Some(TlsHelloEvidence {
        source_id,
        version: version_name(version),
        sni: hello.server_name.clone(),
        alpn: hello.alpn.clone(),
        cipher_suites: cipher_list
            .iter()
            .map(|cipher| format!("{cipher:04x}"))
            .collect(),
        extensions: hello.extensions.iter().map(|(kind, _)| *kind).collect(),
        supported_versions: hello.supported_versions.clone(),
        signature_algorithms: hello.signature_algorithms.clone(),
        groups: hello.groups.clone(),
        ja4,
        provenance: Provenance::new(
            Source::NetLog,
            "netlog.ssl_handshake.client_hello",
            Verification::Verified,
        )
        .with_note(
            "ClientHello parsed from SSL_HANDSHAKE_MESSAGE_SENT; JA4 per FoxIO specification",
        )
        .with_source_id(source_id.to_string()),
    })
}

fn handshake_body(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.first().copied()? != 1 || bytes.len() < 4 {
        return None;
    }
    let length = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | bytes[3] as usize;
    bytes.get(4..4 + length)
}

fn parse_hello(body: &[u8]) -> Option<ClientHello<'_>> {
    let mut offset = 0usize;
    let legacy_version = read_u16(body, &mut offset)?;
    offset = offset.checked_add(32)?; // random
    let session_len = *body.get(offset)? as usize;
    offset = offset.checked_add(1 + session_len)?;
    let ciphers_len = read_u16(body, &mut offset)? as usize;
    let mut ciphers = Vec::new();
    let ciphers_end = offset.checked_add(ciphers_len)?;
    while offset + 2 <= ciphers_end {
        ciphers.push(read_u16(body, &mut offset)?);
    }
    offset = ciphers_end;
    let compression_len = *body.get(offset)? as usize;
    offset = offset.checked_add(1 + compression_len)?;
    let extensions_len = read_u16(body, &mut offset)? as usize;
    let extensions_end = offset.checked_add(extensions_len)?;
    let mut extensions = Vec::new();
    while offset + 4 <= extensions_end {
        let kind = read_u16(body, &mut offset)?;
        let length = read_u16(body, &mut offset)? as usize;
        let data = body.get(offset..offset + length)?;
        offset += length;
        extensions.push((kind, data));
    }
    let get = |kind: u16| {
        extensions
            .iter()
            .find(|(candidate, _)| *candidate == kind)
            .map(|(_, data)| *data)
    };
    let server_name = get(0).and_then(parse_sni);
    let alpn = get(0x0010).map(parse_alpn).unwrap_or_default();
    let supported_versions = get(0x002b)
        .map(parse_supported_versions)
        .unwrap_or_default();
    let signature_algorithms = get(0x000d).map(parse_u16_list).unwrap_or_default();
    let groups = get(0x000a).map(parse_u16_list).unwrap_or_default();
    Some(ClientHello {
        legacy_version,
        ciphers,
        extensions,
        server_name,
        alpn,
        supported_versions,
        signature_algorithms,
        groups,
    })
}

fn read_u16(bytes: &[u8], offset: &mut usize) -> Option<u16> {
    let value = u16::from_be_bytes([*bytes.get(*offset)?, *bytes.get(*offset + 1)?]);
    *offset += 2;
    Some(value)
}

fn parse_u16_list(data: &[u8]) -> Vec<u16> {
    let mut out = Vec::new();
    if data.len() < 2 {
        return out;
    }
    let length = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut offset = 2;
    while offset + 2 <= 2 + length && offset + 2 <= data.len() {
        out.push(u16::from_be_bytes([data[offset], data[offset + 1]]));
        offset += 2;
    }
    out
}

fn parse_supported_versions(data: &[u8]) -> Vec<u16> {
    let Some(length) = data.first().map(|byte| *byte as usize) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut offset = 1;
    while offset + 2 <= 1 + length && offset + 2 <= data.len() {
        out.push(u16::from_be_bytes([data[offset], data[offset + 1]]));
        offset += 2;
    }
    out
}

fn parse_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    let length = u16::from_be_bytes([data[0], data[1]]) as usize;
    let name_type = data[2];
    let name_length = u16::from_be_bytes([data[3], data[4]]) as usize;
    if name_type != 0 || 5 + name_length > data.len() || length < 3 + name_length {
        return None;
    }
    Some(String::from_utf8_lossy(&data[5..5 + name_length]).to_string())
}

fn parse_alpn(data: &[u8]) -> Vec<String> {
    if data.len() < 2 {
        return Vec::new();
    }
    let length = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut out = Vec::new();
    let mut offset = 2;
    let end = (2 + length).min(data.len());
    while offset < end {
        let item_len = data[offset] as usize;
        offset += 1;
        if offset + item_len > end {
            break;
        }
        out.push(String::from_utf8_lossy(&data[offset..offset + item_len]).to_string());
        offset += item_len;
    }
    out
}

fn hello_version(hello: &ClientHello<'_>) -> u16 {
    hello
        .supported_versions
        .iter()
        .copied()
        .filter(|version| !is_grease(*version))
        .max()
        .unwrap_or(hello.legacy_version)
}

fn version_code(version: u16) -> &'static str {
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    }
}

fn version_name(version: u16) -> String {
    match version {
        0x0304 => "TLS 1.3".to_string(),
        0x0303 => "TLS 1.2".to_string(),
        0x0302 => "TLS 1.1".to_string(),
        0x0301 => "TLS 1.0".to_string(),
        0x0300 => "SSL 3.0".to_string(),
        0x0002 => "SSL 2.0".to_string(),
        _ => format!("0x{version:04x}"),
    }
}

fn alpn_pair(value: Option<&str>) -> String {
    let Some(value) = value else {
        return "00".to_string();
    };
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return "00".to_string();
    }
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    let alnum = |byte: u8| byte.is_ascii_alphanumeric();
    if bytes.len() == 1 && alnum(first) {
        return format!("{}{}", first as char, first as char);
    }
    if alnum(first) && alnum(last) {
        return format!("{}{}", first as char, last as char);
    }
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{}{}",
        hex.chars().next().unwrap_or('0'),
        hex.chars().last().unwrap_or('0')
    )
}

fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a
}

fn sha12(text: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(text.as_bytes());
    digest
        .iter()
        .take(6)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16s(values: &[u16]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_be_bytes())
            .collect()
    }

    fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut out = kind.to_be_bytes().to_vec();
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    fn client_hello() -> Vec<u8> {
        let ciphers = [
            0x1301u16, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
            0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ];
        let mut sni = vec![0, 14, 0, 0, 11];
        sni.extend_from_slice(b"example.com");
        let alpn = [0, 3, 2, b'h', b'2'];
        let sig = u16s(&[
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ]);
        let mut sig_block = (sig.len() as u16).to_be_bytes().to_vec();
        sig_block.extend_from_slice(&sig);
        let supported = [6, 0xaa, 0xaa, 0x03, 0x04, 0x03, 0x03];
        let groups = [0, 2, 0, 0x1d];
        let extensions = [
            extension(0x001b, &[]),
            extension(0x0000, &sni),
            extension(0x0033, &[]),
            extension(0x0010, &alpn),
            extension(0x4469, &[]),
            extension(0x0017, &[]),
            extension(0x002d, &[]),
            extension(0x000d, &sig_block),
            extension(0x0005, &[]),
            extension(0x0023, &[]),
            extension(0x0012, &[]),
            extension(0x002b, &supported),
            extension(0xff01, &[]),
            extension(0x000b, &[]),
            extension(0x000a, &groups),
            extension(0x0015, &[]),
        ]
        .concat();
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
        body.extend_from_slice(&u16s(&ciphers));
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut handshake = vec![1];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);
        handshake
    }

    #[test]
    fn ja4_matches_the_published_example() {
        let evidence = decode_client_hellos(&[(1, client_hello())]);
        assert_eq!(evidence.len(), 1);
        let evidence = &evidence[0];
        assert_eq!(evidence.version, "TLS 1.3");
        assert_eq!(evidence.sni.as_deref(), Some("example.com"));
        assert_eq!(evidence.alpn, vec!["h2".to_string()]);
        assert_eq!(evidence.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
    }
}
