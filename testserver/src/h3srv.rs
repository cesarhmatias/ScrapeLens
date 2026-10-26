//! HTTP/3 reference server (QUIC + QPACK via quiche).
//!
//! The reference for header order is the field list returned by
//! `quiche::h3::Event::Headers { list, .. }`: a `Vec<Header>` produced by the
//! QPACK decoder in decode order, duplicates preserved. quiche does not expose
//! the raw QPACK field section, which is stated explicitly in the evidence
//! (`decode_point`).

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quiche::h3::NameValue;

use crate::cert::TlsFiles;
use crate::endpoints::{self, MAX_BODY};
use crate::evidence::Evidence;
use crate::http::{Proto, Req, Resp, lowercase_headers};
use crate::util::note;

const MAX_DATAGRAM_SIZE: usize = 1350;

struct StreamState {
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    truncated: bool,
    responded: bool,
}

struct PendingBody {
    body: Vec<u8>,
    off: usize,
}

struct Peer {
    name: String,
    conn: quiche::Connection,
    h3: Option<quiche::h3::Connection>,
    streams: HashMap<u64, StreamState>,
    pending: HashMap<u64, PendingBody>,
    peer: SocketAddr,
    /// Next QUIC timer deadline. `on_timeout()` must only be called when this
    /// deadline actually passes; calling it on every read timeout causes
    /// spurious loss detection and duplicate/evicted QPACK decoding.
    next_timeout: Option<Instant>,
}

pub fn serve(
    addr: SocketAddr,
    ev: Arc<Evidence>,
    tls: &TlsFiles,
    qpack_table: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(addr)?;
    serve_on(socket, ev, tls, qpack_table)
}

/// Event loop over an already-bound UDP socket (used by tests with port 0).
pub fn serve_on(
    socket: UdpSocket,
    ev: Arc<Evidence>,
    tls: &TlsFiles,
    qpack_table: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    socket.set_read_timeout(Some(Duration::from_millis(20)))?;
    let local = socket.local_addr()?;
    note(
        "h3",
        format!(
            "listening on https://{local} (QUIC/h3, QPACK decode order) evidence={}",
            ev.path().display()
        ),
    );

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.load_cert_chain_from_pem_file(tls.cert_pem.to_string_lossy().as_ref())?;
    config.load_priv_key_from_pem_file(tls.key_pem.to_string_lossy().as_ref())?;
    config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
    config.set_max_idle_timeout(30_000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(100_000_000);
    config.set_initial_max_stream_data_bidi_local(10_000_000);
    config.set_initial_max_stream_data_bidi_remote(10_000_000);
    config.set_initial_max_stream_data_uni(10_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);

    let mut h3_config = quiche::h3::Config::new()?;
    // QPACK dynamic table: disabled by default (0) on purpose. This server is a
    // header-order reference, and a zero-capacity table keeps every request
    // field section self-contained (static table + literals), so decoding never
    // depends on encoder-stream state. Order and duplicates are unaffected.
    //
    // With a non-zero capacity, Chrome 156 opens a dynamic table and quiche
    // 0.30 then fails the second request on the connection with
    // QpackDecompressionFailed (see README "Limites"). `--h3-qpack-table N`
    // exists to reproduce that.
    h3_config.set_qpack_max_table_capacity(qpack_table);
    h3_config.set_qpack_blocked_streams(if qpack_table > 0 { 16 } else { 0 });
    h3_config.set_max_field_section_size(256 * 1024);

    let mut peers: HashMap<quiche::ConnectionId<'static>, Peer> = HashMap::new();
    // Maps every destination connection ID a client used for an existing
    // connection (including the original one, before the handshake completes)
    // to the connection's own ID. Without this, retransmitted Initial packets
    // create duplicate connections and the QPACK decoder state gets mixed up.
    let mut aliases: HashMap<Vec<u8>, quiche::ConnectionId<'static>> = HashMap::new();
    let mut buf = [0u8; 65535];
    let mut out = [0u8; MAX_DATAGRAM_SIZE];
    let mut scid_counter: u64 = 0;

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let pkt = &mut buf[..len];
                let (key, created, client_dcid) = {
                    let hdr = match quiche::Header::from_slice(pkt, quiche::MAX_CONN_ID_LEN) {
                        Ok(h) => h,
                        Err(_) => continue,
                    };
                    let client_dcid = hdr.dcid.to_vec();
                    let existing = peers
                        .keys()
                        .find(|id| id.as_ref() == hdr.dcid.as_ref())
                        .cloned()
                        .or_else(|| aliases.get(hdr.dcid.as_ref()).cloned());
                    match existing {
                        Some(key) => (key, None, client_dcid),
                        None => {
                            if hdr.ty != quiche::Type::Initial {
                                continue;
                            }
                            if !quiche::version_is_supported(hdr.version) {
                                let n = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)?;
                                let _ = socket.send_to(&out[..n], from);
                                continue;
                            }
                            scid_counter += 1;
                            let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
                            scid[..8].copy_from_slice(&scid_counter.to_be_bytes());
                            scid[8..16]
                                .copy_from_slice(&(crate::util::now_ms() as u64).to_be_bytes());
                            (
                                quiche::ConnectionId::from_vec(scid.to_vec()),
                                Some(scid),
                                client_dcid,
                            )
                        }
                    }
                };

                if let Some(scid) = created {
                    // No Retry is performed, so the original destination
                    // connection ID must NOT be claimed here: a server that
                    // echoes original_destination_connection_id without having
                    // sent a Retry violates RFC 9000 §7.3 and the client closes.
                    let conn = quiche::accept(
                        &quiche::ConnectionId::from_ref(&scid),
                        None,
                        local,
                        from,
                        &mut config,
                    )?;
                    let name = format!("h3-{}", scid_counter);
                    note("h3", format!("new QUIC connection {name} from {from}"));
                    aliases.insert(client_dcid.clone(), key.clone());
                    peers.insert(
                        key.clone(),
                        Peer {
                            name,
                            conn,
                            h3: None,
                            streams: HashMap::new(),
                            pending: HashMap::new(),
                            peer: from,
                            next_timeout: None,
                        },
                    );
                }

                let peer = peers.get_mut(&key).expect("connection exists");
                let info = quiche::RecvInfo { to: local, from };
                if let Err(e) = peer.conn.recv(pkt, info) {
                    note("h3", format!("recv failed: {e:?}"));
                    continue;
                }
                peer.next_timeout = peer.conn.timeout().map(|d| Instant::now() + d);

                if peer.conn.is_established() && peer.h3.is_none() {
                    match quiche::h3::Connection::with_transport(&mut peer.conn, &h3_config) {
                        Ok(h3) => peer.h3 = Some(h3),
                        Err(e) => {
                            note("h3", format!("h3 setup failed: {e:?}"));
                            continue;
                        }
                    }
                }

                drive_h3(peer, &ev, &local);
                if !peer.conn.is_closed() {
                    peer.next_timeout = peer.conn.timeout().map(|d| Instant::now() + d);
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            }
            Err(e) => {
                note("h3", format!("recv_from failed: {e}"));
            }
        }

        // Timers (idle timeout, loss recovery) and pending output.
        for (_id, peer) in peers.iter_mut() {
            if let Some(deadline) = peer.next_timeout {
                if Instant::now() >= deadline {
                    peer.conn.on_timeout();
                    peer.next_timeout = peer.conn.timeout().map(|d| Instant::now() + d);
                }
            }
            drive_h3(peer, &ev, &local);
            loop {
                match peer.conn.send(&mut out) {
                    Ok((write, send_info)) => {
                        if socket.send_to(&out[..write], send_info.to).is_err() {
                            break;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        note("h3", format!("send failed: {e:?}"));
                        peer.conn.close(false, 0x1, b"send-failed").ok();
                        break;
                    }
                }
            }
        }

        let closed: Vec<quiche::ConnectionId<'static>> = peers
            .iter()
            .filter(|(_, p)| p.conn.is_closed())
            .map(|(id, _)| id.clone())
            .collect();
        for id in &closed {
            aliases.retain(|_, v| v != id);
        }
        peers.retain(|_id, p| {
            if p.conn.is_closed() {
                note(
                    "h3",
                    format!(
                        "connection closed peer={} (timed_out={})",
                        p.peer,
                        p.conn.is_timed_out()
                    ),
                );
                false
            } else {
                true
            }
        });
    }
}

fn drive_h3(peer: &mut Peer, ev: &Evidence, local: &SocketAddr) {
    let mut h3 = peer.h3.take();
    if let Some(h3c) = h3.as_mut() {
        handle_events(peer, h3c, ev, local);
        flush_bodies(peer, h3c);
    }
    peer.h3 = h3;
}

fn handle_events(
    peer: &mut Peer,
    h3: &mut quiche::h3::Connection,
    ev: &Evidence,
    local: &SocketAddr,
) {
    loop {
        match h3.poll(&mut peer.conn) {
            Ok((stream_id, quiche::h3::Event::Headers { list, more_frames })) => {
                let headers: Vec<(String, String)> = list
                    .iter()
                    .map(|h| {
                        (
                            String::from_utf8_lossy(h.name()).to_string(),
                            String::from_utf8_lossy(h.value()).to_string(),
                        )
                    })
                    .collect();
                let st = peer
                    .streams
                    .entry(stream_id)
                    .or_insert_with(|| StreamState {
                        headers: Vec::new(),
                        body: Vec::new(),
                        truncated: false,
                        responded: false,
                    });
                st.headers = headers;
                if !more_frames {
                    respond(peer, h3, stream_id, ev, local);
                }
            }
            Ok((stream_id, quiche::h3::Event::Data)) => {
                let mut body_buf = [0u8; 8192];
                loop {
                    match h3.recv_body(&mut peer.conn, stream_id, &mut body_buf) {
                        Ok(read) => {
                            let st = peer
                                .streams
                                .entry(stream_id)
                                .or_insert_with(|| StreamState {
                                    headers: Vec::new(),
                                    body: Vec::new(),
                                    truncated: false,
                                    responded: false,
                                });
                            let room = MAX_BODY.saturating_sub(st.body.len());
                            if read > room {
                                st.body.extend_from_slice(&body_buf[..room]);
                                st.truncated = true;
                            } else {
                                st.body.extend_from_slice(&body_buf[..read]);
                            }
                        }
                        Err(quiche::h3::Error::Done) => break,
                        Err(e) => {
                            note("h3", format!("recv_body {stream_id}: {e:?}"));
                            break;
                        }
                    }
                }
            }
            Ok((stream_id, quiche::h3::Event::Finished)) => {
                respond(peer, h3, stream_id, ev, local);
            }
            Ok((_stream_id, quiche::h3::Event::Reset(_))) => {}
            Ok((_id, quiche::h3::Event::PriorityUpdate)) => {}
            Ok((_id, quiche::h3::Event::GoAway)) => {}
            Err(quiche::h3::Error::Done) => break,
            Err(e) => {
                note("h3", format!("h3 poll error: {e:?}; closing connection"));
                peer.conn.close(false, 0x1, b"h3-poll-error").ok();
                break;
            }
        }
    }
}

fn respond(
    peer: &mut Peer,
    h3: &mut quiche::h3::Connection,
    stream_id: u64,
    ev: &Evidence,
    local: &SocketAddr,
) {
    let Some(st) = peer.streams.get_mut(&stream_id) else {
        return;
    };
    if st.responded || st.headers.is_empty() {
        return;
    }
    st.responded = true;

    let headers = std::mem::take(&mut st.headers);
    let body = std::mem::take(&mut st.body);
    let truncated = st.truncated;
    let method = headers
        .iter()
        .find(|(n, _)| n == ":method")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let target = headers
        .iter()
        .find(|(n, _)| n == ":path")
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| "/".into());
    let authority = headers
        .iter()
        .find(|(n, _)| n == ":authority")
        .map(|(_, v)| v.clone());
    let mut notes = Vec::new();
    if truncated {
        notes.push(format!("body truncated at {MAX_BODY} bytes"));
    }

    let req = Req {
        proto: Proto::H3,
        conn: peer.name.clone(),
        stream: Some(stream_id),
        method: method.clone(),
        target: target.clone(),
        authority,
        headers,
        raw_head: None,
        header_block: None,
        body,
        body_truncated: truncated,
        body_framing: None,
        notes,
    };
    let resp = endpoints::handle(&req);
    if let Err(e) = ev.record(&local.to_string(), &req, &resp) {
        note("h3", format!("evidence write failed: {e}"));
    }
    note(
        "h3",
        format!(
            "stream {stream_id} {method} {target} -> {} ({} headers)",
            resp.status,
            req.headers.len()
        ),
    );
    let head_only = method.eq_ignore_ascii_case("HEAD");
    send_response(peer, h3, stream_id, &resp, head_only);
}

fn send_response(
    peer: &mut Peer,
    h3: &mut quiche::h3::Connection,
    stream_id: u64,
    resp: &Resp,
    head_only: bool,
) {
    let mut headers: Vec<quiche::h3::Header> = Vec::with_capacity(resp.headers.len() + 3);
    headers.push(quiche::h3::Header::new(
        b":status",
        resp.status.to_string().as_bytes(),
    ));
    for (name, value) in lowercase_headers(&resp.headers) {
        headers.push(quiche::h3::Header::new(name.as_bytes(), value.as_bytes()));
    }
    headers.push(quiche::h3::Header::new(
        b"server",
        b"scrapelens-testserver/0.1",
    ));
    headers.push(quiche::h3::Header::new(
        b"content-length",
        resp.body.len().to_string().as_bytes(),
    ));
    let body = if head_only { &[][..] } else { &resp.body[..] };
    match h3.send_response(&mut peer.conn, stream_id, &headers, body.is_empty()) {
        Ok(()) => {}
        Err(e) => {
            note("h3", format!("send_response {stream_id}: {e:?}"));
            return;
        }
    }
    if !body.is_empty() {
        match h3.send_body(&mut peer.conn, stream_id, body, true) {
            Ok(n) if n < body.len() => {
                peer.pending.insert(
                    stream_id,
                    PendingBody {
                        body: body.to_vec(),
                        off: n,
                    },
                );
            }
            Ok(_) => {}
            Err(quiche::h3::Error::Done) | Err(quiche::h3::Error::StreamBlocked) => {
                peer.pending.insert(
                    stream_id,
                    PendingBody {
                        body: body.to_vec(),
                        off: 0,
                    },
                );
            }
            Err(e) => note("h3", format!("send_body {stream_id}: {e:?}")),
        }
    }
}

fn flush_bodies(peer: &mut Peer, h3: &mut quiche::h3::Connection) {
    let ids: Vec<u64> = peer.pending.keys().copied().collect();
    for sid in ids {
        let (chunk, off) = {
            let Some(p) = peer.pending.get(&sid) else {
                continue;
            };
            (p.body[p.off..].to_vec(), p.off)
        };
        match h3.send_body(&mut peer.conn, sid, &chunk, true) {
            Ok(n) => {
                let done = {
                    let Some(p) = peer.pending.get_mut(&sid) else {
                        continue;
                    };
                    p.off += n;
                    p.off >= p.body.len()
                };
                let _ = off;
                if done {
                    peer.pending.remove(&sid);
                }
            }
            Err(quiche::h3::Error::Done) | Err(quiche::h3::Error::StreamBlocked) => {}
            Err(e) => {
                note("h3", format!("flush send_body {sid}: {e:?}"));
                peer.pending.remove(&sid);
            }
        }
    }
}
