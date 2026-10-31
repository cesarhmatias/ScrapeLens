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
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use tungstenite::stream::MaybeTlsStream;
use tungstenite::{connect, Message, WebSocket};

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
    Ws(Box<WebSocket<MaybeTlsStream<TcpStream>>>),
    Pipe(PipeTransport),
}

impl Transport {
    /// Conecta ao WebSocket do navegador, com tentativas por até 10 s.
    pub(crate) fn connect_ws(url: &str) -> Result<Transport, String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut last_error = String::new();
        while Instant::now() < deadline {
            match connect(url) {
                Ok((socket, _response)) => {
                    if let MaybeTlsStream::Plain(stream) = socket.get_ref() {
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
                    }
                    return Ok(Transport::Ws(Box::new(socket)));
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
            Transport::Ws(socket) => match socket.read() {
                Ok(Message::Text(text)) => Ok(Incoming::Text(text.to_string())),
                Ok(Message::Ping(payload)) => Ok(Incoming::Ping(payload.to_vec())),
                Ok(Message::Close(_)) => Ok(Incoming::Close),
                Ok(_) => Ok(Incoming::Other),
                Err(tungstenite::Error::Io(error))
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    Err(ReadError::WouldBlock)
                }
                Err(error) => Err(ReadError::Fatal(error.to_string())),
            },
            Transport::Pipe(pipe) => pipe.read(),
        }
    }

    pub(crate) fn send_text(&mut self, text: String) -> Result<(), String> {
        match self {
            Transport::Ws(socket) => socket
                .send(Message::Text(text.into()))
                .map_err(|error| error.to_string()),
            Transport::Pipe(pipe) => pipe.send(&text),
        }
    }

    pub(crate) fn pong(&mut self, payload: Vec<u8>) {
        if let Transport::Ws(socket) = self {
            let _ = socket.send(Message::Pong(payload.into()));
        }
    }

    pub(crate) fn close(&mut self) {
        match self {
            Transport::Ws(socket) => {
                let _ = socket.close(None);
            }
            Transport::Pipe(pipe) => pipe.close(),
        }
    }
}

enum PipeEvent {
    Text(String),
    Eof,
}

pub(crate) struct PipeTransport {
    writer: Option<File>,
    rx: Receiver<PipeEvent>,
    eof: bool,
}

impl PipeTransport {
    fn new(writer: File, reader: File) -> PipeTransport {
        let (tx, rx) = channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(reader);
            let mut buf: Vec<u8> = Vec::new();
            loop {
                buf.clear();
                match reader.read_until(0, &mut buf) {
                    Ok(0) | Err(_) => {
                        let _ = tx.send(PipeEvent::Eof);
                        return;
                    }
                    Ok(_) => {
                        if buf.last() == Some(&0) {
                            buf.pop();
                        } else {
                            // Fim do fluxo no meio de uma mensagem: descarta.
                            let _ = tx.send(PipeEvent::Eof);
                            return;
                        }
                        let text = String::from_utf8_lossy(&buf).to_string();
                        if tx.send(PipeEvent::Text(text)).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        PipeTransport {
            writer: Some(writer),
            rx,
            eof: false,
        }
    }

    fn read(&mut self) -> Result<Incoming, ReadError> {
        if self.eof {
            return Ok(Incoming::Close);
        }
        match self.rx.recv_timeout(Duration::from_millis(250)) {
            Ok(PipeEvent::Text(text)) => Ok(Incoming::Text(text)),
            Ok(PipeEvent::Eof) | Err(RecvTimeoutError::Disconnected) => {
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

pub(crate) fn make_pipe_ends() -> std::io::Result<PipeEnds> {
    let mut to_chrome = [0i32; 2]; // [leitura do Chrome, escrita do pai]
    let mut from_chrome = [0i32; 2]; // [leitura do pai, escrita do Chrome]
    // SAFETY: arrays de 2 inteiros, como `pipe(2)` exige.
    if unsafe { libc::pipe(to_chrome.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: idem.
    if unsafe { libc::pipe(from_chrome.as_mut_ptr()) } != 0 {
        let error = std::io::Error::last_os_error();
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
