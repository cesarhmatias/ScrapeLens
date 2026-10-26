//! Minimal HTTP/3 client (quiche) used by the demo and the integration test.
//!
//! It sends an explicit, ordered h3 header list (duplicates allowed) and prints
//! the response field list in decode order, so the QPACK-decoded reference on
//! the server can be exercised without a browser.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use quiche::h3::NameValue;

use crate::cert::TlsFiles;

pub struct ClientResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
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
    peer: SocketAddr,
    path: &str,
    extras: &[(String, String)],
    tls: &TlsFiles,
    insecure: bool,
) -> Result<ClientResponse, Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(20)))?;
    let local = socket.local_addr()?;

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    if insecure {
        config.verify_peer(false);
    } else {
        config.load_verify_locations_from_file(tls.ca_pem.to_string_lossy().as_ref())?;
    }
    config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
    config.set_max_idle_timeout(10_000);
    config.set_max_recv_udp_payload_size(1350);
    config.set_max_send_udp_payload_size(1350);
    config.set_initial_max_data(50_000_000);
    config.set_initial_max_stream_data_bidi_local(10_000_000);
    config.set_initial_max_stream_data_bidi_remote(10_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(10);
    config.set_initial_max_streams_uni(10);
    config.set_disable_active_migration(true);

    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    let seed = format!(
        "scrapelens-{}",
        std::process::id() as u64 ^ crate::util::now_ms() as u64
    );
    let seed = seed.as_bytes();
    let n = seed.len().min(scid_bytes.len());
    scid_bytes[..n].copy_from_slice(&seed[..n]);
    let scid = quiche::ConnectionId::from_vec(scid_bytes.to_vec());
    let mut conn = quiche::connect(Some("localhost"), &scid, local, peer, &mut config)?;

    let mut h3_config = quiche::h3::Config::new()?;
    h3_config.set_qpack_max_table_capacity(4096);
    h3_config.set_qpack_blocked_streams(16);
    let mut h3: Option<quiche::h3::Connection> = None;

    let mut req: Vec<quiche::h3::Header> = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", peer.to_string().as_bytes()),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b"user-agent", b"scrapelens-testserver-client/0.1"),
    ];
    req.extend(
        extras
            .iter()
            .map(|(n, v)| quiche::h3::Header::new(n.as_bytes(), v.as_bytes())),
    );

    let mut sent = false;
    let mut resp_headers: Vec<(String, String)> = Vec::new();
    let mut body = Vec::new();
    let mut done = false;
    let mut buf = [0u8; 65535];
    let mut out = [0u8; 1350];
    let deadline = Instant::now() + Duration::from_secs(10);

    while !done {
        if Instant::now() > deadline {
            return Err("h3 client timeout".into());
        }
        loop {
            match conn.send(&mut out) {
                Ok((write, send_info)) => {
                    if socket.send_to(&out[..write], send_info.to).is_err() {
                        break;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(format!("quiche send: {e:?}").into()),
            }
        }

        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let info = quiche::RecvInfo { to: local, from };
                if let Err(e) = conn.recv(&mut buf[..len], info) {
                    if e != quiche::Error::Done {
                        return Err(format!("quiche recv: {e:?}").into());
                    }
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                conn.on_timeout();
            }
            Err(e) => return Err(e.into()),
        }

        if conn.is_closed() {
            return Err(format!(
                "connection closed early (timed_out={})",
                conn.is_timed_out()
            )
            .into());
        }

        if conn.is_established() && h3.is_none() {
            h3 = Some(quiche::h3::Connection::with_transport(
                &mut conn, &h3_config,
            )?);
        }

        if let Some(h3c) = h3.as_mut() {
            if !sent {
                h3c.send_request(&mut conn, &req, true)?;
                sent = true;
            }
            loop {
                match h3c.poll(&mut conn) {
                    Ok((_sid, quiche::h3::Event::Headers { list, .. })) => {
                        resp_headers = list
                            .iter()
                            .map(|h| {
                                (
                                    String::from_utf8_lossy(h.name()).to_string(),
                                    String::from_utf8_lossy(h.value()).to_string(),
                                )
                            })
                            .collect();
                    }
                    Ok((sid, quiche::h3::Event::Data)) => loop {
                        match h3c.recv_body(&mut conn, sid, &mut buf) {
                            Ok(n) => body.extend_from_slice(&buf[..n]),
                            Err(quiche::h3::Error::Done) => break,
                            Err(e) => return Err(format!("recv_body: {e:?}").into()),
                        }
                    },
                    Ok((_sid, quiche::h3::Event::Finished)) => {
                        done = true;
                        break;
                    }
                    Ok((_sid, quiche::h3::Event::Reset(code))) => {
                        return Err(format!("stream reset by server: {code}").into());
                    }
                    Ok((_sid, quiche::h3::Event::PriorityUpdate)) => {}
                    Ok((_sid, quiche::h3::Event::GoAway)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => return Err(format!("h3 poll: {e:?}").into()),
                }
            }
        }
    }

    let status = resp_headers
        .iter()
        .find(|(n, _)| n == ":status")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    conn.close(true, 0, b"bye").ok();
    loop {
        match conn.send(&mut out) {
            Ok((write, send_info)) => {
                if socket.send_to(&out[..write], send_info.to).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    Ok(ClientResponse {
        status,
        headers: resp_headers,
        body,
    })
}
