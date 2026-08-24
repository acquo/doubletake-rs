//! Receiver event channel, ported from upstream `event_channel.go`.
//!
//! The persistent RTSP connection opened to the eventPort in a SETUP
//! response. Its encryption state is independent of the control channel and
//! reverses the normal key direction: receiver commands use the Events-Write
//! key and sender responses use the Events-Read key.

use crate::error::{Error, Result};
use crate::pairing::hkdf_sha512;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use std::io::{Read, Write};
use std::net::TcpStream;

const EVENT_FRAME_SIZE_LIMIT: usize = 1024;
const EVENT_HEADER_SIZE_LIMIT: usize = 16 * 1024;
const EVENT_BODY_SIZE_LIMIT: usize = 1024 * 1024;

/// The sender side of the receiver's event channel.
pub struct EventChannel {
    stream: TcpStream,
    read_cipher: Option<ChaCha20Poly1305>,
    write_cipher: Option<ChaCha20Poly1305>,
    read_nonce: u64,
    write_nonce: u64,
    read_buf: Vec<u8>,
}

impl std::io::Read for EventChannel {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read_inner(buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    }
}

impl EventChannel {
    /// Connects to the receiver's event port.
    pub fn connect(host: &str, port: u16, encrypted: bool, shared_secret: &[u8]) -> Result<Self> {
        let stream =
            TcpStream::connect((host, port)).map_err(|e| Error::from_io("dial event channel", e))?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .map_err(|e| Error::from_io("set event read timeout", e))?;
        Self::new(stream, encrypted, shared_secret)
    }

    fn new(stream: TcpStream, encrypted: bool, shared_secret: &[u8]) -> Result<Self> {
        let mut channel = EventChannel {
            stream,
            read_cipher: None,
            write_cipher: None,
            read_nonce: 0,
            write_nonce: 0,
            read_buf: Vec::new(),
        };
        if encrypted {
            if shared_secret.is_empty() {
                return Err(Error::Protocol("encrypted event channel has no pair-verify shared secret".into()));
            }
            let read_key =
                hkdf_sha512(shared_secret, b"Events-Salt", b"Events-Write-Encryption-Key", 32);
            let write_key =
                hkdf_sha512(shared_secret, b"Events-Salt", b"Events-Read-Encryption-Key", 32);
            channel.read_cipher = Some(ChaCha20Poly1305::new(Key::from_slice(&read_key)));
            channel.write_cipher = Some(ChaCha20Poly1305::new(Key::from_slice(&write_key)));
        }
        Ok(channel)
    }

    /// Reads decrypted bytes; HAP frame boundaries are not message boundaries,
    /// so unread plaintext is retained for the next call.
    fn read_inner(&mut self, dst: &mut [u8]) -> Result<usize> {
        if dst.is_empty() {
            return Ok(0);
        }
        if self.read_cipher.is_none() {
            return self
                .stream
                .read(dst)
                .map_err(|e| Error::from_io("read event", e));
        }
        if self.read_buf.is_empty() {
            let mut size_bytes = [0u8; 2];
            self.stream
                .read_exact(&mut size_bytes)
                .map_err(|e| Error::from_io("read event frame size", e))?;
            let size = u16::from_le_bytes(size_bytes) as usize;
            if !(1..=EVENT_FRAME_SIZE_LIMIT).contains(&size) {
                return Err(Error::Protocol(format!("invalid event frame size {size}")));
            }
            let mut sealed = vec![0u8; size + 16];
            self.stream
                .read_exact(&mut sealed)
                .map_err(|e| Error::from_io("read event frame payload", e))?;
            let cipher = self.read_cipher.as_ref().expect("read cipher");
            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&self.read_nonce.to_le_bytes());
            self.read_nonce += 1;
            let plain = cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    chacha20poly1305::aead::Payload {
                        msg: sealed.as_slice(),
                        aad: &size_bytes,
                    },
                )
                .map_err(|e| Error::Crypto(format!("decrypt event frame: {e}")))?;
            self.read_buf = plain;
        }
        let n = dst.len().min(self.read_buf.len());
        dst[..n].copy_from_slice(&self.read_buf[..n]);
        self.read_buf.drain(..n);
        Ok(n)
    }

    /// Writes one logical plaintext buffer, splitting into HAP frames.
    pub fn write(&mut self, plain: &[u8]) -> Result<usize> {
        if self.write_cipher.is_none() {
            self.stream
                .write_all(plain)
                .map_err(|e| Error::from_io("write event", e))?;
            return Ok(plain.len());
        }
        let cipher = self.write_cipher.as_ref().expect("write cipher");
        let mut written = 0;
        let mut rest = plain;
        while !rest.is_empty() {
            let chunk = if rest.len() > EVENT_FRAME_SIZE_LIMIT {
                &rest[..EVENT_FRAME_SIZE_LIMIT]
            } else {
                rest
            };
            let size_bytes = (chunk.len() as u16).to_le_bytes();
            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&self.write_nonce.to_le_bytes());
            self.write_nonce += 1;
            let mut frame = size_bytes.to_vec();
            frame.extend_from_slice(
                &cipher
                    .encrypt(
                        Nonce::from_slice(&nonce),
                        chacha20poly1305::aead::Payload {
                            msg: chunk,
                            aad: &size_bytes,
                        },
                    )
                    .map_err(|e| Error::Crypto(format!("encrypt event frame: {e}")))?,
            );
            self.stream
                .write_all(&frame)
                .map_err(|e| Error::from_io("write event frame", e))?;
            written += chunk.len();
            rest = &rest[chunk.len()..];
        }
        Ok(written)
    }

    pub fn shutdown(&mut self) -> std::io::Result<()> {
        self.stream.shutdown(std::net::Shutdown::Both)
    }
}

/// A receiver-to-sender event command.
struct EventRequest {
    cseq: u64,
    body_length: usize,
}

/// Reads one CRLF-terminated line from the event stream with a size limit.
fn read_event_line(reader: &mut std::io::BufReader<EventChannel>, limit: usize) -> Result<String> {
    let mut data = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let n = reader
            .read(&mut byte)
            .map_err(|e| Error::from_io("read event line", e))?;
        if n == 0 {
            return Err(Error::Transport("event line EOF".into()));
        }
        data.push(byte[0]);
        if data.len() > limit {
            return Err(Error::Protocol(format!(
                "event headers exceed {EVENT_HEADER_SIZE_LIMIT} bytes"
            )));
        }
        if data.len() >= 2 && data[data.len() - 2] == b'\r' && data[data.len() - 1] == b'\n' {
            data.truncate(data.len() - 2);
            return Ok(String::from_utf8_lossy(&data).to_string());
        }
    }
}

/// Reads one receiver command from the event channel.
fn read_event_request(reader: &mut std::io::BufReader<EventChannel>) -> Result<EventRequest> {
    let request_line = read_event_line(reader, EVENT_HEADER_SIZE_LIMIT)?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() != 3 || parts[2] != "RTSP/1.0" {
        return Err(Error::Protocol(format!("invalid event request line {request_line:?}")));
    }
    let mut request = EventRequest {
        cseq: 0,
        body_length: 0,
    };
    let mut used = request_line.len() + 2;
    let mut has_cseq = false;
    loop {
        let line = read_event_line(reader, EVENT_HEADER_SIZE_LIMIT.saturating_sub(used))?;
        used += line.len() + 2;
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(Error::Protocol(format!("invalid event header {line:?}")));
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-length" => {
                let len: usize = value
                    .parse()
                    .map_err(|_| Error::Protocol(format!("invalid event content length {value:?}")))?;
                if len > EVENT_BODY_SIZE_LIMIT {
                    return Err(Error::Protocol(format!("invalid event content length {value:?}")));
                }
                request.body_length = len;
            }
            "cseq" => {
                request.cseq = value
                    .parse()
                    .map_err(|_| Error::Protocol(format!("invalid event CSeq {value:?}")))?;
                has_cseq = true;
            }
            _ => {}
        }
    }
    if !has_cseq {
        return Err(Error::Protocol("event request omitted CSeq".into()));
    }
    // Drain the body.
    let mut remaining = request.body_length;
    let mut buf = [0u8; 512];
    while remaining > 0 {
        let n = reader
            .read(&mut buf[..remaining.min(512)])
            .map_err(|e| Error::from_io("read event body", e))?;
        if n == 0 {
            break;
        }
        remaining -= n;
    }
    Ok(request)
}

/// Serves receiver-to-sender commands until the channel closes, acknowledging
/// each with `RTSP/1.0 200 OK`. Runs on a background thread.
pub fn serve_event_channel(channel: EventChannel) {
    std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(channel);
        loop {
            let request = match read_event_request(&mut reader) {
                Ok(r) => r,
                Err(_) => break,
            };
            let response = format!(
                "RTSP/1.0 200 OK\r\nCSeq: {}\r\nContent-Length: 0\r\n\r\n",
                request.cseq
            );
            if reader.get_mut().write(response.as_bytes()).is_err() {
                break;
            }
        }
    });
}
