//! CDP transport: WebSocket on `127.0.0.1` (ephemeral port) or pipe
//! (`--remote-debugging-pipe`, no port at all).
//!
//! The pipe uses two descriptors inherited by Chrome: it READS commands on fd 3
//! and WRITES responses and events on fd 4, JSON messages terminated by NUL. Only
//! the process that created the pipes talks to the browser; there is no port for
//! another local process, and Chrome exits on its own when the pipe closes (even
//! if ScrapeLens dies by SIGKILL).

use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::net::TcpStream;
use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use tungstenite::stream::MaybeTlsStream;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::client::connect_with_config;
use tungstenite::{Message, WebSocket};

/// How our client talks to Chrome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CdpTransport {
    /// WebSocket on `127.0.0.1:<ephemeral port>` (required if the agent will also
    /// connect: `expose_cdp`).
    #[default]
    Port,
    /// `--remote-debugging-pipe`: no open port.
    Pipe,
}

impl CdpTransport {
    /// `SCRAPELENS_CDP_TRANSPORT=pipe|port` changes the default of the App's regular
    /// capture (a measurement instrument and a way back).
    pub fn from_env(default: CdpTransport) -> CdpTransport {
        Self::parse(std::env::var("SCRAPELENS_CDP_TRANSPORT").ok().as_deref(), default)
    }

    fn parse(value: Option<&str>, default: CdpTransport) -> CdpTransport {
        match value {
            Some("pipe") => CdpTransport::Pipe,
            Some("port") => CdpTransport::Port,
            _ => default,
        }
    }
}

pub(crate) enum Incoming {
    Text(String),
    Ping(Vec<u8>),
    Close,
    Other,
}

pub(crate) enum ReadError {
    /// Nothing arrived within the short read deadline.
    WouldBlock,
    Fatal(String),
}

pub(crate) enum Transport {
    Ws(WsTransport),
    Pipe(PipeTransport),
}

/// WebSocket of port mode. After any read error the socket is NEVER touched
/// again: tungstenite leaves the input buffer full after exceeding the limit, and
/// a new read brings the thread down with a `debug_assert` (A4-B2). The abnormal
/// reason (`frame_too_large`) is kept.
pub(crate) struct WsTransport {
    socket: Box<WebSocket<MaybeTlsStream<TcpStream>>>,
    dead: bool,
    abnormal: Option<&'static str>,
}

impl Transport {
    /// Connects to the browser's WebSocket, retrying for up to 10 s.
    pub(crate) fn connect_ws(url: &str) -> Result<Transport, String> {
        Self::connect_ws_with_limit(url, MAX_PIPE_MESSAGE_BYTES)
    }

    fn connect_ws_with_limit(url: &str, limit: usize) -> Result<Transport, String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut last_error = String::new();
        while Instant::now() < deadline {
            // Same cap as the pipe, for the message and the frame (the library default is
            // 64 MiB/16 MiB): the port and the pipe behave the same.
            let config = WebSocketConfig::default()
                .max_message_size(Some(limit))
                .max_frame_size(Some(limit));
            match connect_with_config(url, Some(config), 3) {
                Ok((socket, _response)) => {
                    if let MaybeTlsStream::Plain(stream) = socket.get_ref() {
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
                    }
                    return Ok(Transport::Ws(WsTransport {
                        socket: Box::new(socket),
                        dead: false,
                        abnormal: None,
                    }));
                }
                Err(error) => {
                    last_error = error.to_string();
                    thread::sleep(Duration::from_millis(120));
                }
            }
        }
        Err(format!("Could not connect to the local CDP: {last_error}"))
    }

    pub(crate) fn pipe(writer: File, reader: File) -> Transport {
        Transport::Pipe(PipeTransport::new(writer, reader))
    }

    pub(crate) fn read(&mut self) -> Result<Incoming, ReadError> {
        match self {
            Transport::Ws(ws) => {
                if ws.dead {
                    return Ok(Incoming::Close);
                }
                match ws.socket.read() {
                    Ok(Message::Text(text)) => Ok(Incoming::Text(text.to_string())),
                    Ok(Message::Ping(payload)) => Ok(Incoming::Ping(payload.to_vec())),
                    Ok(Message::Close(_)) => Ok(Incoming::Close),
                    Ok(_) => Ok(Incoming::Other),
                    Err(tungstenite::Error::Io(error))
                        if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                    {
                        Err(ReadError::WouldBlock)
                    }
                    Err(error) => {
                        ws.dead = true;
                        if matches!(error, tungstenite::Error::Capacity(_)) {
                            eprintln!("CDP: WebSocket message above the limit: {error}; transport closed");
                            ws.abnormal = Some("frame_too_large");
                        }
                        Err(ReadError::Fatal(error.to_string()))
                    }
                }
            }
            Transport::Pipe(pipe) => pipe.read(),
        }
    }

    pub(crate) fn send_text(&mut self, text: String) -> Result<(), String> {
        match self {
            Transport::Ws(ws) if ws.dead => Err("CDP WebSocket closed".to_string()),
            Transport::Ws(ws) => ws
                .socket
                .send(Message::Text(text.into()))
                .map_err(|error| error.to_string()),
            Transport::Pipe(pipe) => pipe.send(&text),
        }
    }

    /// Has the transport already closed (pipe EOF, limit exceeded, WebSocket that
    /// can no longer read)? Whoever waits for events uses this so as not to spin
    /// until the deadline.
    pub(crate) fn is_closed(&self) -> bool {
        match self {
            Transport::Ws(ws) => ws.dead || !ws.socket.can_read(),
            Transport::Pipe(pipe) => pipe.eof || pipe.too_large.load(Ordering::SeqCst),
        }
    }

    /// Reason for closing when it was NOT a normal end: today only
    /// `frame_too_large` (pipe message above the limit).
    pub(crate) fn abnormal_close_reason(&self) -> Option<&'static str> {
        match self {
            Transport::Pipe(pipe) if pipe.too_large.load(Ordering::SeqCst) => Some("frame_too_large"),
            Transport::Ws(ws) => ws.abnormal,
            _ => None,
        }
    }

    pub(crate) fn pong(&mut self, payload: Vec<u8>) {
        if let Transport::Ws(ws) = self {
            if !ws.dead {
                let _ = ws.socket.send(Message::Pong(payload.into()));
            }
        }
    }

    pub(crate) fn close(&mut self) {
        match self {
            Transport::Ws(ws) => {
                if !ws.dead {
                    let _ = ws.socket.close(None);
                }
            }
            Transport::Pipe(pipe) => pipe.close(),
        }
    }
}

enum PipeEvent {
    Text(String),
    Eof,
    /// A message exceeded the limit and reading stopped (R12).
    TooLarge,
}

/// Cap for one pipe message, in bytes (R12). The old WebSocket had 64 MiB; a
/// legitimate response stays below it (`maxResourceBufferSize` ≈ 67 MB of base64
/// only in the worst body case), so 128 MiB cuts nothing real and prevents a
/// faulty Chrome, or a hostile target, from filling memory with an endless
/// message.
pub(crate) const MAX_PIPE_MESSAGE_BYTES: usize = 128 * 1024 * 1024;

enum Frame {
    Message,
    Eof,
    TooLarge,
}

/// Reads a NUL-terminated message into `buf` without ever keeping more than `max`
/// bytes. End of stream in the middle of a message discards the piece (`Eof`).
fn read_frame<R: BufRead>(reader: &mut R, buf: &mut Vec<u8>, max: usize) -> std::io::Result<Frame> {
    buf.clear();
    loop {
        let available = match reader.fill_buf() {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if available.is_empty() {
            return Ok(Frame::Eof);
        }
        match available.iter().position(|&b| b == 0) {
            Some(end) => {
                if buf.len() + end > max {
                    return Ok(Frame::TooLarge);
                }
                buf.extend_from_slice(&available[..end]);
                reader.consume(end + 1);
                return Ok(Frame::Message);
            }
            None => {
                let len = available.len();
                if buf.len() + len > max {
                    return Ok(Frame::TooLarge);
                }
                buf.extend_from_slice(available);
                reader.consume(len);
            }
        }
    }
}

pub(crate) struct PipeTransport {
    writer: Option<File>,
    rx: Receiver<PipeEvent>,
    eof: bool,
    /// Set by the read thread as soon as a message exceeds the limit, without
    /// depending on someone consuming the event (A3-B2).
    too_large: Arc<AtomicBool>,
}

impl PipeTransport {
    fn new(writer: File, reader: File) -> PipeTransport {
        Self::with_limit(writer, reader, MAX_PIPE_MESSAGE_BYTES)
    }

    fn with_limit(writer: File, reader: File, max_message: usize) -> PipeTransport {
        let (tx, rx) = channel();
        let too_large = Arc::new(AtomicBool::new(false));
        let flag = too_large.clone();
        thread::spawn(move || {
            let mut reader = BufReader::new(reader);
            let mut buf: Vec<u8> = Vec::new();
            loop {
                match read_frame(&mut reader, &mut buf, max_message) {
                    Ok(Frame::Message) => {
                        let text = String::from_utf8_lossy(&buf).to_string();
                        if tx.send(PipeEvent::Text(text)).is_err() {
                            return;
                        }
                    }
                    Ok(Frame::TooLarge) => {
                        eprintln!("CDP: pipe message above {max_message} bytes; transport closed");
                        flag.store(true, Ordering::SeqCst);
                        let _ = tx.send(PipeEvent::TooLarge);
                        return;
                    }
                    Ok(Frame::Eof) | Err(_) => {
                        let _ = tx.send(PipeEvent::Eof);
                        return;
                    }
                }
            }
        });
        PipeTransport {
            writer: Some(writer),
            rx,
            eof: false,
            too_large,
        }
    }

    fn read(&mut self) -> Result<Incoming, ReadError> {
        if self.eof {
            return Ok(Incoming::Close);
        }
        match self.rx.recv_timeout(Duration::from_millis(250)) {
            Ok(PipeEvent::Text(text)) => Ok(Incoming::Text(text)),
            Ok(PipeEvent::Eof | PipeEvent::TooLarge) | Err(RecvTimeoutError::Disconnected) => {
                self.eof = true;
                Ok(Incoming::Close)
            }
            Err(RecvTimeoutError::Timeout) => Err(ReadError::WouldBlock),
        }
    }

    fn send(&mut self, text: &str) -> Result<(), String> {
        let writer = self.writer.as_mut().ok_or_else(|| "CDP pipe closed".to_string())?;
        let mut framed = Vec::with_capacity(text.len() + 1);
        framed.extend_from_slice(text.as_bytes());
        framed.push(0);
        writer
            .write_all(&framed)
            .and_then(|()| writer.flush())
            .map_err(|error| error.to_string())
    }

    fn close(&mut self) {
        // Closing the write end notifies Chrome (EOF on fd 3).
        self.writer = None;
    }
}

/// The four ends of two pipes: Chrome reads on fd 3 and writes on fd 4.
pub(crate) struct PipeEnds {
    /// From Chrome: becomes fd 3 in the child (it READS commands here).
    pub child_read: OwnedFd,
    /// From Chrome: becomes fd 4 in the child (it WRITES here).
    pub child_write: OwnedFd,
    pub parent_write: File,
    pub parent_read: File,
}

/// Duplicates the descriptor to a high number with FD_CLOEXEC and closes the
/// original (avoids colliding with the child's fds 3 and 4 and leaking to other
/// processes).
fn high_cloexec(fd: i32) -> std::io::Result<OwnedFd> {
    // SAFETY: `fd` is a valid descriptor just created by `pipe`.
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
    let error = std::io::Error::last_os_error();
    // SAFETY: closes the original, which is no longer used.
    unsafe { libc::close(fd) };
    if dup < 0 {
        return Err(error);
    }
    // SAFETY: `dup` is a new descriptor that is exclusively ours.
    Ok(unsafe { OwnedFd::from_raw_fd(dup) })
}

/// A `pipe()` with both ends already in CLOEXEC when the system allows it: on
/// Linux `pipe2(O_CLOEXEC)` is atomic (no window between `pipe()` and the `fcntl`
/// that a concurrent `exec` could inherit); on macOS there is no `pipe2`, so the
/// minimal window remains and is closed right away by `high_cloexec`
/// (docs/16b §2.1).
fn cloexec_pipe(fds: &mut [libc::c_int; 2]) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    // SAFETY: array of 2 integers, as `pipe2(2)` requires.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    #[cfg(not(target_os = "linux"))]
    // SAFETY: array of 2 integers, as `pipe(2)` requires.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn make_pipe_ends() -> std::io::Result<PipeEnds> {
    let mut to_chrome = [0i32; 2]; // [Chrome read, parent write]
    let mut from_chrome = [0i32; 2]; // [parent read, Chrome write]
    cloexec_pipe(&mut to_chrome)?;
    if let Err(error) = cloexec_pipe(&mut from_chrome) {
        // SAFETY: closes the first pair, which was left open.
        unsafe {
            libc::close(to_chrome[0]);
            libc::close(to_chrome[1]);
        }
        return Err(error);
    }
    let child_read = high_cloexec(to_chrome[0])?;
    let parent_write = high_cloexec(to_chrome[1])?;
    let parent_read = high_cloexec(from_chrome[0])?;
    let child_write = high_cloexec(from_chrome[1])?;
    Ok(PipeEnds {
        child_read,
        child_write,
        parent_write: File::from(parent_write),
        parent_read: File::from(parent_read),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_choice_parses_the_env_override() {
        assert_eq!(CdpTransport::parse(None, CdpTransport::Pipe), CdpTransport::Pipe);
        assert_eq!(CdpTransport::parse(Some("port"), CdpTransport::Pipe), CdpTransport::Port);
        assert_eq!(CdpTransport::parse(Some("pipe"), CdpTransport::Port), CdpTransport::Pipe);
        assert_eq!(CdpTransport::parse(Some("lixo"), CdpTransport::Pipe), CdpTransport::Pipe);
    }

    /// A fake "Chrome" on the pipe ends: reads NUL-terminated messages on its side
    /// and replies `{"eco":<message>}` + NUL; ends on EOF.
    fn fake_chrome(ends: PipeEnds) -> (Transport, thread::JoinHandle<Vec<String>>) {
        let PipeEnds { child_read, child_write, parent_write, parent_read } = ends;
        let handle = thread::spawn(move || {
            let mut reader = BufReader::new(File::from(child_read));
            let mut writer = File::from(child_write);
            let mut seen = Vec::new();
            let mut buf = Vec::new();
            loop {
                buf.clear();
                match reader.read_until(0, &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        buf.pop();
                        let text = String::from_utf8_lossy(&buf).to_string();
                        let reply = format!("{{\"eco\":{text}}}");
                        writer.write_all(reply.as_bytes()).unwrap();
                        writer.write_all(&[0]).unwrap();
                        seen.push(text);
                    }
                }
            }
            seen
        });
        (Transport::pipe(parent_write, parent_read), handle)
    }

    fn next_text(t: &mut Transport) -> String {
        for _ in 0..40 {
            match t.read() {
                Ok(Incoming::Text(s)) => return s,
                Err(ReadError::WouldBlock) => continue,
                Ok(Incoming::Close) => panic!("pipe fechou"),
                _ => continue,
            }
        }
        panic!("no message");
    }

    /// A4-B2: in port mode a message above the limit closes the transport with an
    /// explicit reason and NEVER touches the socket again (tungstenite brings the
    /// thread down with a `debug_assert` if it is read again after the overflow).
    #[test]
    fn a4_b2_websocket_message_cap_closes_with_a_reason_and_never_panics() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut ws = tungstenite::accept(stream).unwrap();
            ws.send(Message::Text("{\"ok\":1}".into())).unwrap();
            let _ = ws.send(Message::Text("y".repeat(64 * 1024).into()));
            thread::sleep(Duration::from_millis(400));
        });
        let mut t = Transport::connect_ws_with_limit(&format!("ws://127.0.0.1:{port}/"), 4096).unwrap();
        assert_eq!(next_text(&mut t), "{\"ok\":1}");
        let mut fatal = false;
        for _ in 0..40 {
            match t.read() {
                Err(ReadError::Fatal(_)) => {
                    fatal = true;
                    break;
                }
                Ok(Incoming::Text(text)) => panic!("message above the limit delivered: {} bytes", text.len()),
                _ => {}
            }
        }
        assert!(fatal, "expected a capacity error");
        assert_eq!(t.abnormal_close_reason(), Some("frame_too_large"));
        assert!(t.is_closed());
        // Reads, sends and closing after the overflow do not touch the socket.
        for _ in 0..3 {
            assert!(matches!(t.read(), Ok(Incoming::Close)));
        }
        assert!(t.send_text("{}".to_string()).is_err());
        t.close();
        server.join().unwrap();
    }

    #[test]
    fn r12_read_frame_enforces_the_message_cap_without_buffering_past_it() {
        use std::io::Cursor;
        let mut buf = Vec::new();
        // Within the limit, including exactly at the cap.
        let mut ok = Cursor::new(b"abcd\0ef\0".to_vec());
        assert!(matches!(read_frame(&mut ok, &mut buf, 4).unwrap(), Frame::Message));
        assert_eq!(buf, b"abcd");
        assert!(matches!(read_frame(&mut ok, &mut buf, 4).unwrap(), Frame::Message));
        assert_eq!(buf, b"ef");
        assert!(matches!(read_frame(&mut ok, &mut buf, 4).unwrap(), Frame::Eof));
        // One byte above the limit, with or without the NUL in sight.
        let mut over = Cursor::new(b"abcde\0".to_vec());
        assert!(matches!(read_frame(&mut over, &mut buf, 4).unwrap(), Frame::TooLarge));
        assert!(buf.len() <= 4, "never keeps more than the limit: {}", buf.len());
        // Endless message (no NUL): stops at the limit instead of growing.
        let endless = vec![b'x'; 1_000_000];
        let mut cursor = Cursor::new(endless);
        let mut reader = BufReader::with_capacity(8, &mut cursor);
        assert!(matches!(read_frame(&mut reader, &mut buf, 100).unwrap(), Frame::TooLarge));
        assert!(buf.len() <= 100, "{}", buf.len());
        // End of stream in the middle of a message: discards it.
        let mut cut = Cursor::new(b"parcial".to_vec());
        assert!(matches!(read_frame(&mut cut, &mut buf, 100).unwrap(), Frame::Eof));
    }

    #[test]
    fn r12_oversized_pipe_message_closes_the_transport_and_smaller_ones_still_pass() {
        let ends = make_pipe_ends().unwrap();
        let PipeEnds { child_read, child_write, parent_write, parent_read } = ends;
        let mut t = Transport::Pipe(PipeTransport::with_limit(parent_write, parent_read, 64));
        let handle = thread::spawn(move || {
            let _keep_open = File::from(child_read);
            let mut writer = File::from(child_write);
            writer.write_all(b"{\"ok\":1}\0").unwrap();
            // 200 bytes without NUL: exceeds the 64 limit. Stops at the read; the real
            // Chrome gets EPIPE when writing after that.
            let _ = writer.write_all(&[b'y'; 200]);
            let _ = writer.write_all(&[0]);
        });
        assert_eq!(next_text(&mut t), "{\"ok\":1}");
        let mut closed = false;
        for _ in 0..40 {
            match t.read() {
                Ok(Incoming::Close) => {
                    closed = true;
                    break;
                }
                Ok(Incoming::Text(text)) => panic!("message above the limit delivered: {} bytes", text.len()),
                _ => {}
            }
        }
        assert!(closed, "the transport should close when it exceeds the limit");
        // A3-B2: the reason is recorded and the transport declares itself closed.
        assert_eq!(t.abnormal_close_reason(), Some("frame_too_large"));
        assert!(t.is_closed());
        // Closed for good: it stays closed.
        assert!(matches!(t.read(), Ok(Incoming::Close)));
        handle.join().unwrap();
    }

    #[test]
    fn pipe_frames_messages_with_nul_in_both_directions_and_closes_on_eof() {
        let ends = make_pipe_ends().unwrap();
        // The parent's fds and the child's ends are NOT 3 or 4 (the child receives
        // them via dup2) and do not leak through exec (FD_CLOEXEC).
        use std::os::fd::AsRawFd;
        for fd in [ends.child_read.as_raw_fd(), ends.child_write.as_raw_fd(), ends.parent_write.as_raw_fd(), ends.parent_read.as_raw_fd()] {
            assert!(fd >= 10, "fd {fd}");
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags & libc::FD_CLOEXEC != 0, "fd {fd} without CLOEXEC");
        }
        let (mut t, child) = fake_chrome(ends);
        t.send_text("{\"id\":1,\"method\":\"A\"}".to_string()).unwrap();
        // A large message (bigger than a common pipe buffer) with accents.
        let big = format!("{{\"id\":2,\"p\":\"{}ç\"}}", "x".repeat(200_000));
        t.send_text(big.clone()).unwrap();
        assert_eq!(next_text(&mut t), "{\"eco\":{\"id\":1,\"method\":\"A\"}}");
        assert_eq!(next_text(&mut t), format!("{{\"eco\":{big}}}"));
        // Nothing to read: the short deadline becomes WouldBlock, not an error.
        assert!(matches!(t.read(), Err(ReadError::WouldBlock)));
        // Closing our write end gives EOF to the "Chrome", which ends and closes its own.
        t.close();
        let seen = child.join().unwrap();
        assert_eq!(seen.len(), 2);
        let mut closed = false;
        for _ in 0..40 {
            match t.read() {
                Ok(Incoming::Close) => {
                    closed = true;
                    break;
                }
                Err(ReadError::WouldBlock) => continue,
                _ => continue,
            }
        }
        assert!(closed, "Chrome's EOF should become Close");
        assert!(t.send_text("{}".to_string()).is_err(), "pipe already closed");
        // An EOF in the middle of a message is discarded, not turned into text.
        let ends = make_pipe_ends().unwrap();
        let PipeEnds { child_read, child_write, parent_write, parent_read } = ends;
        drop(child_read);
        let mut half = File::from(child_write);
        half.write_all(b"{\"incompleto\"").unwrap();
        drop(half);
        let mut t = Transport::pipe(parent_write, parent_read);
        let mut got_text = false;
        for _ in 0..40 {
            match t.read() {
                Ok(Incoming::Text(_)) => got_text = true,
                Ok(Incoming::Close) => break,
                _ => {}
            }
        }
        assert!(!got_text);
    }
}
