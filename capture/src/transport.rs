//! Transporte do CDP: WebSocket em `127.0.0.1` (porta efêmera) ou pipe
//! (`--remote-debugging-pipe`, sem porta alguma).
//!
//! O pipe usa dois descritores herdados pelo Chrome: ele LÊ comandos no fd 3 e
//! ESCREVE respostas e eventos no fd 4, mensagens JSON terminadas em NUL. Só
//! o processo que criou os pipes fala com o navegador; não há porta para outro
//! processo local, e o Chrome sai sozinho quando o pipe fecha (inclusive se o
//! ScrapeLens morrer por SIGKILL).

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

/// Como o nosso cliente fala com o Chrome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CdpTransport {
    /// WebSocket em `127.0.0.1:<porta efêmera>` (necessário se o agente também
    /// vai se conectar: `expose_cdp`).
    #[default]
    Port,
    /// `--remote-debugging-pipe`: nenhuma porta aberta.
    Pipe,
}

impl CdpTransport {
    /// `SCRAPELENS_CDP_TRANSPORT=pipe|port` troca o padrão da captura comum do
    /// App (instrumento de medição e de volta atrás).
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
    /// Nada chegou dentro do prazo curto de leitura.
    WouldBlock,
    Fatal(String),
}

pub(crate) enum Transport {
    Ws(WsTransport),
    Pipe(PipeTransport),
}

/// WebSocket do modo porta. Depois de qualquer erro de leitura o socket NUNCA
/// mais é tocado: o tungstenite deixa o buffer de entrada cheio depois de
/// estourar o limite e uma nova leitura derruba a thread com um `debug_assert`
/// (A4-B2). O motivo anormal (`frame_too_large`) fica guardado.
pub(crate) struct WsTransport {
    socket: Box<WebSocket<MaybeTlsStream<TcpStream>>>,
    dead: bool,
    abnormal: Option<&'static str>,
}

impl Transport {
    /// Conecta ao WebSocket do navegador, com tentativas por até 10 s.
    pub(crate) fn connect_ws(url: &str) -> Result<Transport, String> {
        Self::connect_ws_with_limit(url, MAX_PIPE_MESSAGE_BYTES)
    }

    fn connect_ws_with_limit(url: &str, limit: usize) -> Result<Transport, String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut last_error = String::new();
        while Instant::now() < deadline {
            // Mesmo teto do pipe, na mensagem e no quadro (o padrão da biblioteca
            // é 64 MiB/16 MiB): a porta e o pipe se comportam igual.
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
        Err(format!("Não foi possível conectar ao CDP local: {last_error}"))
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
                            eprintln!("CDP: mensagem do WebSocket acima do teto: {error}; transporte encerrado");
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
            Transport::Ws(ws) if ws.dead => Err("WebSocket do CDP fechado".to_string()),
            Transport::Ws(ws) => ws
                .socket
                .send(Message::Text(text.into()))
                .map_err(|error| error.to_string()),
            Transport::Pipe(pipe) => pipe.send(&text),
        }
    }

    /// O transporte já fechou (EOF do pipe, teto estourado, WebSocket sem leitura)?
    /// Quem espera por eventos usa isto para não girar até o prazo.
    pub(crate) fn is_closed(&self) -> bool {
        match self {
            Transport::Ws(ws) => ws.dead || !ws.socket.can_read(),
            Transport::Pipe(pipe) => pipe.eof || pipe.too_large.load(Ordering::SeqCst),
        }
    }

    /// Motivo do fechamento quando NÃO foi um fim normal: hoje só
    /// `frame_too_large` (mensagem do pipe acima do teto).
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
    /// Uma mensagem passou do teto e a leitura parou (R12).
    TooLarge,
}

/// Teto de uma mensagem do pipe, em bytes (R12). O WebSocket antigo tinha 64
/// MiB; uma resposta legítima fica abaixo (`maxResourceBufferSize` ≈ 67 MB de
/// base64 só no pior caso de corpo), então 128 MiB não corta nada real e impede
/// que um Chrome com defeito, ou um alvo hostil, encha a memória com uma
/// mensagem sem fim.
pub(crate) const MAX_PIPE_MESSAGE_BYTES: usize = 128 * 1024 * 1024;

enum Frame {
    Message,
    Eof,
    TooLarge,
}

/// Lê uma mensagem terminada em NUL para `buf` sem nunca guardar mais de `max`
/// bytes. Fim do fluxo no meio da mensagem descarta o pedaço (`Eof`).
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
    /// Ligado pela thread de leitura assim que uma mensagem passa do teto, sem
    /// depender de alguém consumir o evento (A3-B2).
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
                        eprintln!("CDP: mensagem do pipe acima de {max_message} bytes; transporte encerrado");
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
        let writer = self.writer.as_mut().ok_or_else(|| "pipe do CDP fechado".to_string())?;
        let mut framed = Vec::with_capacity(text.len() + 1);
        framed.extend_from_slice(text.as_bytes());
        framed.push(0);
        writer
            .write_all(&framed)
            .and_then(|()| writer.flush())
            .map_err(|error| error.to_string())
    }

    fn close(&mut self) {
        // Fechar a ponta de escrita avisa o Chrome (EOF no fd 3).
        self.writer = None;
    }
}

/// As quatro pontas de dois pipes: o Chrome lê no fd 3 e escreve no fd 4.
pub(crate) struct PipeEnds {
    /// Do Chrome: vira o fd 3 no filho (ele LÊ comandos aqui).
    pub child_read: OwnedFd,
    /// Do Chrome: vira o fd 4 no filho (ele ESCREVE aqui).
    pub child_write: OwnedFd,
    pub parent_write: File,
    pub parent_read: File,
}

/// Duplica o descritor para um número alto com FD_CLOEXEC e fecha o original
/// (evita colidir com os fds 3 e 4 do filho e vazar para outros processos).
fn high_cloexec(fd: i32) -> std::io::Result<OwnedFd> {
    // SAFETY: `fd` é um descritor válido recém-criado por `pipe`.
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
    let error = std::io::Error::last_os_error();
    // SAFETY: fecha o original, que não é mais usado.
    unsafe { libc::close(fd) };
    if dup < 0 {
        return Err(error);
    }
    // SAFETY: `dup` é um descritor novo e exclusivo nosso.
    Ok(unsafe { OwnedFd::from_raw_fd(dup) })
}

/// Um `pipe()` com as duas pontas já em CLOEXEC quando o sistema permite: no Linux
/// `pipe2(O_CLOEXEC)` é atômico (sem a janela entre `pipe()` e o `fcntl` que um
/// `exec` concorrente poderia herdar); no macOS não existe `pipe2`, então a janela
/// mínima continua e é fechada logo por `high_cloexec` (docs/16b §2.1).
fn cloexec_pipe(fds: &mut [libc::c_int; 2]) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    // SAFETY: array de 2 inteiros, como `pipe2(2)` exige.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    #[cfg(not(target_os = "linux"))]
    // SAFETY: array de 2 inteiros, como `pipe(2)` exige.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn make_pipe_ends() -> std::io::Result<PipeEnds> {
    let mut to_chrome = [0i32; 2]; // [leitura do Chrome, escrita do pai]
    let mut from_chrome = [0i32; 2]; // [leitura do pai, escrita do Chrome]
    cloexec_pipe(&mut to_chrome)?;
    if let Err(error) = cloexec_pipe(&mut from_chrome) {
        // SAFETY: fecha o primeiro par, que ficou aberto.
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

    /// Um "Chrome" de mentira nas pontas do pipe: lê mensagens terminadas em NUL
    /// no lado dele e responde `{"eco":<mensagem>}` + NUL; termina no EOF.
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
        panic!("sem mensagem");
    }

    /// A4-B2: no modo porta uma mensagem acima do teto fecha o transporte com
    /// motivo explícito e NUNCA mais toca o socket (o tungstenite derruba a thread
    /// com um `debug_assert` se for lido de novo depois do estouro).
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
                Ok(Incoming::Text(text)) => panic!("mensagem acima do teto entregue: {} bytes", text.len()),
                _ => {}
            }
        }
        assert!(fatal, "esperava erro de capacidade");
        assert_eq!(t.abnormal_close_reason(), Some("frame_too_large"));
        assert!(t.is_closed());
        // Leituras, envios e fechamento depois do estouro não tocam o socket.
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
        // Dentro do teto, incluindo exatamente no limite.
        let mut ok = Cursor::new(b"abcd\0ef\0".to_vec());
        assert!(matches!(read_frame(&mut ok, &mut buf, 4).unwrap(), Frame::Message));
        assert_eq!(buf, b"abcd");
        assert!(matches!(read_frame(&mut ok, &mut buf, 4).unwrap(), Frame::Message));
        assert_eq!(buf, b"ef");
        assert!(matches!(read_frame(&mut ok, &mut buf, 4).unwrap(), Frame::Eof));
        // Um byte acima do teto, com ou sem o NUL à vista.
        let mut over = Cursor::new(b"abcde\0".to_vec());
        assert!(matches!(read_frame(&mut over, &mut buf, 4).unwrap(), Frame::TooLarge));
        assert!(buf.len() <= 4, "nunca guarda além do teto: {}", buf.len());
        // Mensagem sem fim (sem NUL): para no teto, em vez de crescer.
        let endless = vec![b'x'; 1_000_000];
        let mut cursor = Cursor::new(endless);
        let mut reader = BufReader::with_capacity(8, &mut cursor);
        assert!(matches!(read_frame(&mut reader, &mut buf, 100).unwrap(), Frame::TooLarge));
        assert!(buf.len() <= 100, "{}", buf.len());
        // Fim do fluxo no meio de uma mensagem: descarta.
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
            // 200 bytes sem NUL: passa do teto de 64. Para na leitura; o Chrome
            // de verdade recebe EPIPE ao escrever depois disso.
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
                Ok(Incoming::Text(text)) => panic!("mensagem acima do teto entregue: {} bytes", text.len()),
                _ => {}
            }
        }
        assert!(closed, "o transporte devia fechar ao passar do teto");
        // A3-B2: o motivo fica registrado e o transporte se declara fechado.
        assert_eq!(t.abnormal_close_reason(), Some("frame_too_large"));
        assert!(t.is_closed());
        // Fechado de vez: continua fechado.
        assert!(matches!(t.read(), Ok(Incoming::Close)));
        handle.join().unwrap();
    }

    #[test]
    fn pipe_frames_messages_with_nul_in_both_directions_and_closes_on_eof() {
        let ends = make_pipe_ends().unwrap();
        // Os fds do pai e as pontas do filho NÃO são o 3 nem o 4 (o filho os
        // recebe por dup2) e não vazam por exec (FD_CLOEXEC).
        use std::os::fd::AsRawFd;
        for fd in [ends.child_read.as_raw_fd(), ends.child_write.as_raw_fd(), ends.parent_write.as_raw_fd(), ends.parent_read.as_raw_fd()] {
            assert!(fd >= 10, "fd {fd}");
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags & libc::FD_CLOEXEC != 0, "fd {fd} sem CLOEXEC");
        }
        let (mut t, child) = fake_chrome(ends);
        t.send_text("{\"id\":1,\"method\":\"A\"}".to_string()).unwrap();
        // Uma mensagem grande (maior que o buffer de um pipe comum) e com acentos.
        let big = format!("{{\"id\":2,\"p\":\"{}ç\"}}", "x".repeat(200_000));
        t.send_text(big.clone()).unwrap();
        assert_eq!(next_text(&mut t), "{\"eco\":{\"id\":1,\"method\":\"A\"}}");
        assert_eq!(next_text(&mut t), format!("{{\"eco\":{big}}}"));
        // Sem nada a ler: o prazo curto vira WouldBlock, não erro.
        assert!(matches!(t.read(), Err(ReadError::WouldBlock)));
        // Fechar a nossa ponta de escrita dá EOF ao "Chrome", que termina e fecha a dele.
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
        assert!(closed, "EOF do Chrome deve virar Close");
        assert!(t.send_text("{}".to_string()).is_err(), "pipe já fechado");
        // Um EOF no meio de uma mensagem é descartado, não vira texto.
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
