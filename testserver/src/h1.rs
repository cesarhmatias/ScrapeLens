//! HTTP/1.1 reference server: the request head is read as raw bytes, so the
//! recorded order, header-name casing and duplicates are exactly what arrived.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::endpoints::{self, MAX_BODY};
use crate::evidence::Evidence;
use crate::http::{Proto, Req, Resp};
use crate::util::{ConnIds, note};

const MAX_HEAD: usize = 256 * 1024;

pub fn serve(addr: SocketAddr, ev: Arc<Evidence>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    serve_on(listener, ev)
}

/// Accept loop over an already-bound listener (used by tests with port 0).
pub fn serve_on(listener: TcpListener, ev: Arc<Evidence>) -> std::io::Result<()> {
    let local = listener.local_addr()?;
    note(
        "h1",
        format!(
            "listening on http://{local} (raw socket order) evidence={}",
            ev.path().display()
        ),
    );
    let ids = Arc::new(ConnIds::default());
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                note("h1", format!("accept failed: {e}"));
                continue;
            }
        };
        let ev = ev.clone();
        let conn = ids.next();
        thread::spawn(move || {
            if let Err(e) = conn_loop(stream, ev, conn.clone(), local) {
                note("h1", format!("{conn}: closed ({e})"));
            }
        });
    }
    Ok(())
}

fn conn_loop(
    stream: TcpStream,
    ev: Arc<Evidence>,
    conn: String,
    local: SocketAddr,
) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into());
    let mut reader = BufReader::new(stream);
    let mut served: u64 = 0;

    loop {
        let head = match read_head(&mut reader)? {
            Some(h) => h,
            None => break,
        };
        let (method, target, version, headers, notes) = parse_head(&head);
        let mut notes = notes;
        if version != "HTTP/1.1" {
            notes.push(format!("request version {version}"));
        }

        let mut truncated = false;
        let mut body = Vec::new();
        let mut framing = "none".to_string();
        let mut close_after = version != "HTTP/1.1";

        // Connection persistence.
        if let Some((_, v)) = headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("connection"))
        {
            if v.to_ascii_lowercase().contains("close") {
                close_after = true;
            }
        }

        let te_chunked = headers.iter().any(|(n, v)| {
            n.eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
        });
        let content_length: Option<usize> = headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.trim().parse().ok());

        let expects_continue = headers.iter().any(|(n, v)| {
            n.eq_ignore_ascii_case("expect") && v.to_ascii_lowercase().contains("100-continue")
        });
        if expects_continue {
            let w = reader.get_mut();
            w.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
            w.flush()?;
        }

        if te_chunked {
            framing = "chunked".to_string();
            let (b, t) = read_chunked(&mut reader)?;
            body = b;
            truncated = t;
        } else if let Some(len) = content_length {
            framing = "content-length".to_string();
            let take = len.min(MAX_BODY);
            body.resize(take, 0);
            reader.read_exact(&mut body)?;
            if len > take {
                // Drain the rest so the connection framing stays valid, but
                // report the truncation truthfully.
                drain(&mut reader, len - take)?;
                truncated = true;
                notes.push(format!("body truncated: declared {len} bytes, kept {take}"));
            }
        } else if expects_continue {
            notes.push("Expect: 100-continue without body framing".into());
        }

        if te_chunked {
            if let Some(n) = content_length {
                notes.push(format!(
                    "both content-length ({n}) and chunked present; chunked used"
                ));
            }
        }

        let authority = headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.clone());

        let req = Req {
            proto: Proto::H1,
            conn: conn.clone(),
            stream: None,
            method: method.clone(),
            target: target.clone(),
            authority,
            headers,
            raw_head: Some(head),
            header_block: None,
            body,
            body_truncated: truncated,
            body_framing: Some(framing),
            notes: notes.clone(),
        };

        let mut resp = endpoints::handle(&req);
        // Record the response headers exactly as they go on the wire, in order
        // (transport headers included), so client-side and server-side lists can
        // be compared field by field.
        resp.headers.push((
            "server".to_string(),
            "scrapelens-testserver/0.1".to_string(),
        ));
        resp.headers
            .push(("content-length".to_string(), resp.body.len().to_string()));
        resp.headers.push((
            "connection".to_string(),
            if close_after || truncated {
                "close".to_string()
            } else {
                "keep-alive".to_string()
            },
        ));
        ev.record(&local.to_string(), &req, &resp)
            .map_err(|e| {
                note("h1", format!("{conn}: evidence write failed: {e}"));
                e
            })
            .ok();

        served += 1;
        note(
            "h1",
            format!(
                "{conn} #{served} {method} {target} -> {} ({} headers, {} body bytes, peer {peer})",
                resp.status,
                req.headers.len(),
                req.body.len()
            ),
        );

        let head_only = method.eq_ignore_ascii_case("HEAD");
        let keep_alive = !close_after && !truncated;
        write_response(reader.get_mut(), &resp, head_only)?;

        if !keep_alive {
            break;
        }
    }
    Ok(())
}

/// Read one request head, including the terminating empty line. `None` on a
/// clean EOF before any byte of a new request.
fn read_head<R: BufRead>(reader: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut head = Vec::new();
    let mut line = Vec::new();
    let mut first = true;
    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 {
            if first && head.is_empty() {
                return Ok(None);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof in request head",
            ));
        }
        first = false;
        head.extend_from_slice(&line);
        if head.len() > MAX_HEAD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request head too large",
            ));
        }
        // Empty line: "\r\n" or "\n".
        if line == b"\r\n" || line == b"\n" {
            return Ok(Some(head));
        }
    }
}

fn split_lines(head: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    let mut i = 0;
    while i < head.len() {
        if head[i] == b'\r' && head.get(i + 1) == Some(&b'\n') {
            out.push(std::mem::take(&mut cur));
            i += 2;
        } else if head[i] == b'\n' {
            out.push(std::mem::take(&mut cur));
            i += 1;
        } else {
            cur.push(head[i]);
            i += 1;
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn parse_head(head: &[u8]) -> (String, String, String, Vec<(String, String)>, Vec<String>) {
    let mut notes = Vec::new();
    let lines = split_lines(head);
    let mut headers = Vec::new();
    let mut method = String::new();
    let mut target = String::new();
    let mut version = String::new();

    for (idx, line) in lines.iter().enumerate() {
        if idx == 0 {
            let text = String::from_utf8_lossy(line);
            let parts: Vec<&str> = text.split_whitespace().collect();
            if parts.len() >= 3 {
                method = parts[0].to_string();
                target = parts[1].to_string();
                version = parts[2].to_string();
            } else {
                notes.push(format!("malformed request line: {text:?}"));
            }
            continue;
        }
        if line.is_empty() {
            continue;
        }
        match line.iter().position(|b| *b == b':') {
            Some(i) => {
                // Name exactly as sent (casing preserved); value with OWS trimmed.
                let name = String::from_utf8_lossy(&line[..i]).to_string();
                let mut v = &line[i + 1..];
                while let Some((first, rest)) = v.split_first() {
                    if *first == b' ' || *first == b'\t' {
                        v = rest;
                    } else {
                        break;
                    }
                }
                while let Some((last, rest)) = v.split_last() {
                    if *last == b' ' || *last == b'\t' {
                        v = rest;
                    } else {
                        break;
                    }
                }
                headers.push((name, String::from_utf8_lossy(v).to_string()));
            }
            None => notes.push(format!(
                "header line without colon: {:?}",
                String::from_utf8_lossy(line)
            )),
        }
    }
    (method, target, version, headers, notes)
}

fn read_chunked<R: BufRead>(reader: &mut R) -> std::io::Result<(Vec<u8>, bool)> {
    let mut body = Vec::new();
    let mut truncated = false;
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof in chunk size",
            ));
        }
        let text = String::from_utf8_lossy(&line);
        let size_text = text.trim().split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("bad chunk size: {size_text:?}"),
            )
        })?;
        if size == 0 {
            // Trailers until empty line.
            loop {
                line.clear();
                let n = reader.read_until(b'\n', &mut line)?;
                if n == 0 || line == b"\r\n" || line == b"\n" {
                    break;
                }
            }
            return Ok((body, truncated));
        }
        let take = size.min(MAX_BODY.saturating_sub(body.len()));
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk)?;
        body.extend_from_slice(&chunk[..take]);
        if take < size {
            truncated = true;
        }
        // Trailing CRLF of the chunk.
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf)?;
    }
}

fn drain<R: Read>(reader: &mut R, mut n: usize) -> std::io::Result<()> {
    let mut buf = [0u8; 16 * 1024];
    while n > 0 {
        let want = n.min(buf.len());
        let got = reader.read(&mut buf[..want])?;
        if got == 0 {
            return Ok(());
        }
        n -= got;
    }
    Ok(())
}

fn write_response(stream: &mut TcpStream, resp: &Resp, head_only: bool) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(256 + resp.body.len());
    out.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", resp.status, resp.reason()).as_bytes());
    for (name, value) in &resp.headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    if !head_only {
        out.extend_from_slice(&resp.body);
    }
    stream.write_all(&out)?;
    stream.flush()
}
