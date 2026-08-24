//! The AirPlay control-channel client, ported from upstream `client.go`.
//!
//! Owns the RTSP connection, applies HAP encrypted framing after pair-verify,
//! and answers HTTP Digest challenges with retry.

use crate::digest::{self, DigestChallenge};
use crate::error::{Error, Result};
use crate::info::ReceiverInfo;
use crate::pairing::PairKeys;
use crate::transport::Response;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Session-wide bounds, mirroring the Go constants.
const MAX_RESPONSE_BODY: usize = 8 << 20;
const HAP_FRAME_CHUNK: usize = 1024;

/// The AirPlay control client.
#[derive(Debug)]
pub struct Client {
    pub host: String,
    pub port: u16,
    stream: TcpStream,
    cseq: u64,

    pub info: Option<ReceiverInfo>,
    pub pairing_id: String,
    pub session_id: String,
    pub pair_type: u8,
    pub pair_keys: Option<PairKeys>,

    /// Encryption state after pair-verify.
    encrypted: bool,
    enc_write_key: Vec<u8>,
    enc_read_key: Vec<u8>,
    enc_write_nonce: u64,
    enc_read_nonce: u64,

    /// FairPlay-derived stream keys.
    pub fp_key: Vec<u8>,
    pub fp_iv: Vec<u8>,
    pub fp_ekey: Vec<u8>,
    pub fp_m3: Vec<u8>,
    pub fp_aes_key: Vec<u8>,

    /// Stream encryption key/IV (from FP or pair-verify).
    pub stream_key: Vec<u8>,
    pub stream_iv: Vec<u8>,

    /// HTTP Digest credentials.
    auth_password: String,
    auth_challenge: Option<DigestChallenge>,
}

impl Client {
    /// Wraps an existing connection (used by tests and the mirror layer).
    pub fn connected(stream: TcpStream, host: &str, port: u16) -> Self {
        Client {
            host: host.to_string(),
            port,
            stream,
            cseq: 0,
            info: None,
            pairing_id: crate::uuid::generate_uuid(),
            session_id: crate::uuid::generate_uuid(),
            pair_type: crate::pairing::PAIRING_TYPE_SCREEN_CAPTURE,
            pair_keys: None,
            encrypted: false,
            enc_write_key: Vec::new(),
            enc_read_key: Vec::new(),
            enc_write_nonce: 0,
            enc_read_nonce: 0,
            fp_key: Vec::new(),
            fp_iv: Vec::new(),
            fp_ekey: Vec::new(),
            fp_m3: Vec::new(),
            fp_aes_key: Vec::new(),
            stream_key: Vec::new(),
            stream_iv: Vec::new(),
            auth_password: String::new(),
            auth_challenge: None,
        }
    }

    pub fn connect(host: &str, port: u16) -> Result<Self> {
        let stream = TcpStream::connect((host, port)).map_err(|e| Error::from_io("dial", e))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| Error::from_io("set read timeout", e))?;
        Ok(Client {
            host: host.to_string(),
            port,
            stream,
            cseq: 0,
            info: None,
            pairing_id: crate::uuid::generate_uuid(),
            session_id: crate::uuid::generate_uuid(),
            pair_type: crate::pairing::PAIRING_TYPE_SCREEN_CAPTURE,
            pair_keys: None,
            encrypted: false,
            enc_write_key: Vec::new(),
            enc_read_key: Vec::new(),
            enc_write_nonce: 0,
            enc_read_nonce: 0,
            fp_key: Vec::new(),
            fp_iv: Vec::new(),
            fp_ekey: Vec::new(),
            fp_m3: Vec::new(),
            fp_aes_key: Vec::new(),
            stream_key: Vec::new(),
            stream_iv: Vec::new(),
            auth_password: String::new(),
            auth_challenge: None,
        })
    }

    /// Configures the password used to answer HTTP Digest challenges.
    pub fn set_password(&mut self, password: &str) {
        self.auth_password = password.to_string();
    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    pub fn close(&mut self) -> std::io::Result<()> {
        self.stream.shutdown(std::net::Shutdown::Both)
    }

    /// Local IP of the control connection, used as the PTP peer address.
    pub fn local_ip(&self) -> Option<std::net::IpAddr> {
        self.stream.local_addr().ok().map(|a| a.ip())
    }

    /// Fetches and parses GET /info.
    pub fn get_info(&mut self) -> Result<ReceiverInfo> {
        let resp = self.http_request("GET", "/info", "application/x-apple-binary-plist", &[], &HashMap::new())?;
        let info: ReceiverInfo =
            plist::from_bytes(&resp).map_err(|e| Error::Protocol(format!("decode info plist: {e}")))?;
        self.info = Some(info.clone());
        Ok(info)
    }

    /// Enables HAP encryption with the pair-verify derived keys.
    pub fn enable_hap_encryption(&mut self, write_key: Vec<u8>, read_key: Vec<u8>) {
        self.enc_write_key = write_key;
        self.enc_read_key = read_key;
        self.enc_write_nonce = 0;
        self.enc_read_nonce = 0;
        self.encrypted = true;
    }

    /// httpRequest: RTSP/1.0 request returning the response body, with
    /// preemptive digest auth and one 401 retry.
    pub fn http_request(
        &mut self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
        extra_headers: &HashMap<String, String>,
    ) -> Result<Vec<u8>> {
        let resp = self.request_inner(method, path, content_type, body, extra_headers)?;
        Error::ok_body(Ok(resp))
    }

    /// rtspRequest: like httpRequest but returns headers too (for digest
    /// challenges, clock timestamps, etc.).
    pub fn rtsp_request(
        &mut self,
        method: &str,
        uri: &str,
        content_type: &str,
        body: &[u8],
        extra_headers: &HashMap<String, String>,
    ) -> Result<(Vec<u8>, HashMap<String, String>)> {
        let resp = self.request_inner(method, uri, content_type, body, extra_headers)?;
        let headers = resp.headers.clone();
        let body_out = Error::ok_body(Ok(resp))?;
        Ok((body_out, headers))
    }

    /// Raw request without session ID or HAP encryption (legacy raw flows).
    pub fn raw_request(
        &mut self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
        extra_headers: &HashMap<String, String>,
    ) -> Result<Vec<u8>> {
        let resp = <Self as crate::transport::Transport>::request_raw(
            self, method, path, content_type, body, extra_headers,
        )?;
        Ok(resp.body)
    }

    fn request_inner(
        &mut self,
        method: &str,
        uri: &str,
        content_type: &str,
        body: &[u8],
        extra_headers: &HashMap<String, String>,
    ) -> Result<Response> {
        let mut headers = extra_headers.clone();
        if let Some(hdr) = self.preemptive_auth_header(method, uri) {
            headers.insert("Authorization".into(), hdr);
        }
        let resp = self.request_once(method, uri, content_type, body, &headers)?;

        // 401 retry with a fresh digest challenge.
        if resp.status == 401 {
            if let Some(ch) = resp.headers.get("www-authenticate").and_then(|v| digest::parse_digest_challenge(v)) {
                self.auth_challenge = Some(ch);
                if self.auth_password.is_empty() {
                    log::warn!(
                        "{method} {uri} needs a code: receiver sent a Digest challenge (realm={:?}); set the receiver password",
                        self.auth_challenge.as_ref().map(|c| c.realm.as_str())
                    );
                    return Ok(resp);
                }
                let ch = self.auth_challenge.as_ref().expect("just set");
                let auth = digest::authorization_header(
                    digest::DIGEST_USERNAME,
                    &self.auth_password,
                    ch,
                    method,
                    uri,
                );
                let mut retry = extra_headers.clone();
                retry.insert("Authorization".into(), auth);
                return self.request_once(method, uri, content_type, body, &retry);
            }
        }
        Ok(resp)
    }

    fn preemptive_auth_header(&self, method: &str, uri: &str) -> Option<String> {
        let ch = self.auth_challenge.as_ref()?;
        if self.auth_password.is_empty() {
            return None;
        }
        Some(digest::authorization_header(
            digest::DIGEST_USERNAME,
            &self.auth_password,
            ch,
            method,
            uri,
        ))
    }

    fn request_once(
        &mut self,
        method: &str,
        uri: &str,
        content_type: &str,
        body: &[u8],
        extra_headers: &HashMap<String, String>,
    ) -> Result<Response> {
        self.cseq += 1;
        let mut buf = Vec::with_capacity(256 + body.len());
        buf.extend_from_slice(format!("{method} {uri} RTSP/1.0\r\n").as_bytes());
        buf.extend_from_slice(format!("CSeq: {}\r\n", self.cseq).as_bytes());
        buf.extend_from_slice(b"User-Agent: AirPlay/935.7.1\r\n");
        for (k, v) in extra_headers {
            buf.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        if !content_type.is_empty() && !body.is_empty() {
            buf.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
        }
        buf.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(body);

        if self.encrypted {
            buf = self.hap_encrypt(&buf);
        }
        self.stream
            .write_all(&buf)
            .map_err(|e| Error::from_io("write request", e))?;

        self.read_response()
    }

    /// HAP encrypted frame format: split plaintext into max-1024-byte chunks;
    /// each chunk is [2-byte LE length][encrypted(plaintext)+16-byte tag] with
    /// the length prefix as AAD.
    fn hap_encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        use chacha20poly1305::aead::Payload;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.enc_write_key));
        let mut result = Vec::with_capacity(data.len() + 16 + 4);
        let mut rest = data;
        while !rest.is_empty() {
            let chunk = if rest.len() > HAP_FRAME_CHUNK {
                &rest[..HAP_FRAME_CHUNK]
            } else {
                rest
            };
            rest = &rest[chunk.len()..];

            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&self.enc_write_nonce.to_le_bytes());
            let aad = (chunk.len() as u16).to_le_bytes();
            let sealed = cipher
                .encrypt(Nonce::from_slice(&nonce), Payload { msg: chunk, aad: &aad })
                .expect("chacha20 seal");
            result.extend_from_slice(&aad);
            result.extend_from_slice(&sealed);
            self.enc_write_nonce += 1;
        }
        result
    }

    fn read_response(&mut self) -> Result<Response> {
        if self.encrypted {
            self.read_encrypted_response()
        } else {
            self.read_plaintext_response()
        }
    }

    fn read_plaintext_response(&mut self) -> Result<Response> {
        let mut header = Vec::new();
        let mut one = [0u8; 1];
        loop {
            self.stream
                .read_exact(&mut one)
                .map_err(|e| Error::from_io("read response header", e))?;
            header.push(one[0]);
            if header.len() >= 4 && &header[header.len() - 4..] == b"\r\n\r\n" {
                break;
            }
            if header.len() > 16384 {
                return Err(Error::Protocol("response header too large".into()));
            }
        }
        let header_str = String::from_utf8_lossy(&header);
        let (status, content_length, headers) = crate::transport::parse_http_header(&header_str);
        if content_length > MAX_RESPONSE_BODY {
            return Err(Error::Protocol(format!(
                "Content-Length {content_length} exceeds the {MAX_RESPONSE_BODY} byte limit"
            )));
        }
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            self.stream
                .read_exact(&mut body)
                .map_err(|e| Error::from_io("read body", e))?;
        }
        Ok(Response {
            status,
            headers,
            body,
        })
    }

    fn read_encrypted_response(&mut self) -> Result<Response> {
        // Accumulate decrypted frames until headers + full body are present.
        let mut decrypted: Vec<u8> = Vec::new();
        while decrypted.len() < 4 || !decrypted.windows(4).any(|w| w == b"\r\n\r\n") {
            let frame = self.read_encrypted_frame()?;
            decrypted.extend_from_slice(&frame);
            if decrypted.len() > 16384 {
                return Err(Error::Protocol("encrypted response header too large".into()));
            }
        }
        let header_end = find_subslice(&decrypted, b"\r\n\r\n").expect("present") + 4;
        let header_str = String::from_utf8_lossy(&decrypted[..header_end]);
        let (status, content_length, headers) = crate::transport::parse_http_header(&header_str);
        if content_length > MAX_RESPONSE_BODY {
            return Err(Error::Protocol(format!(
                "Content-Length {content_length} exceeds the {MAX_RESPONSE_BODY} byte limit"
            )));
        }
        while decrypted.len() < header_end + content_length {
            let frame = self.read_encrypted_frame()?;
            decrypted.extend_from_slice(&frame);
        }
        let body = decrypted[header_end..header_end + content_length].to_vec();
        Ok(Response {
            status,
            headers,
            body,
        })
    }

    fn read_encrypted_frame(&mut self) -> Result<Vec<u8>> {
        let mut length_bytes = [0u8; 2];
        self.stream
            .read_exact(&mut length_bytes)
            .map_err(|e| Error::from_io("read frame length", e))?;
        let plaintext_len = u16::from_le_bytes(length_bytes) as usize;
        if plaintext_len == 0 || plaintext_len > HAP_FRAME_CHUNK {
            return Err(Error::Protocol(format!(
                "suspicious frame length {plaintext_len} (expected 1-1024)"
            )));
        }
        let mut sealed = vec![0u8; plaintext_len + 16];
        self.stream
            .read_exact(&mut sealed)
            .map_err(|e| Error::from_io("read frame ciphertext", e))?;

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.enc_read_key));
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.enc_read_nonce.to_le_bytes());
        self.enc_read_nonce += 1;
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: sealed.as_slice(),
                    aad: &length_bytes,
                },
            )
            .map_err(|e| Error::Crypto(format!("decrypt frame: {e}")))
    }

    /// Derives stream keys from the pair-verify channel keys (or random).
    pub fn derive_stream_keys(&mut self) -> Result<()> {
        if self.enc_write_key.is_empty() {
            let mut key = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
            let mut iv = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut iv);
            self.stream_key = key.to_vec();
            self.stream_iv = iv.to_vec();
            return Ok(());
        }
        self.stream_key = self.enc_write_key[..16].to_vec();
        self.stream_iv = self.enc_read_key[..16].to_vec();
        Ok(())
    }
}

impl crate::transport::Transport for Client {
    fn request(
        &mut self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
        extra_headers: &HashMap<String, String>,
    ) -> crate::Result<Response> {
        self.request_inner(method, path, content_type, body, extra_headers)
    }

    fn request_raw(
        &mut self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
        extra_headers: &HashMap<String, String>,
    ) -> crate::Result<Response> {
        self.cseq += 1;
        let mut buf = Vec::new();
        buf.extend_from_slice(format!("{method} {path} RTSP/1.0\r\n").as_bytes());
        buf.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
        buf.extend_from_slice(b"User-Agent: AirPlay/935.7.1\r\n");
        buf.extend_from_slice(b"X-Apple-ProtocolVersion: 1\r\n");
        for (k, v) in extra_headers {
            buf.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        buf.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        buf.extend_from_slice(format!("CSeq: {}\r\n", self.cseq).as_bytes());
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(body);
        self.stream
            .write_all(&buf)
            .map_err(|e| Error::from_io("write request", e))?;
        self.read_response()
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_subslice_works() {
        let data = b"abc\r\n\r\ndef";
        assert_eq!(find_subslice(data, b"\r\n\r\n"), Some(3));
    }

    #[test]
    fn hap_framing_roundtrip() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let write_stream = TcpStream::connect(addr).unwrap();
        let (read_stream, _) = listener.accept().unwrap();

        let mut writer = Client::connected(write_stream, "127.0.0.1", addr.port());
        let mut reader = Client::connected(read_stream, "127.0.0.1", addr.port());
        writer.enable_hap_encryption(vec![7u8; 32], vec![9u8; 32]);
        reader.enable_hap_encryption(vec![9u8; 32], vec![7u8; 32]);

        // Multi-chunk plaintext (2500 bytes > 1024 chunk limit).
        let plaintext: Vec<u8> = (0..2500u32).map(|i| (i % 251) as u8).collect();
        let framed = writer.hap_encrypt(&plaintext);
        writer.stream.write_all(&framed).unwrap();

        let mut received = Vec::new();
        while received.len() < plaintext.len() {
            let frame = reader.read_encrypted_frame().expect("frame");
            received.extend_from_slice(&frame);
        }
        assert_eq!(received, plaintext);
        // Nonces advanced independently.
        assert_eq!(writer.enc_write_nonce, 3);
        assert_eq!(reader.enc_read_nonce, 3);
    }

    #[test]
    fn digest_retry_flow() {
        // Fake receiver: challenge the first request, accept the second.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client_stream = TcpStream::connect(addr).unwrap();
        let (server_stream, _) = listener.accept().unwrap();
        let mut server = server_stream;

        let mut client = Client::connected(client_stream, "127.0.0.1", addr.port());
        client.set_password("s3cr3t");

        // Serve: read request, reply 401 with challenge, read again, reply 200.
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let n = server.read(&mut buf).unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).starts_with("SETUP "));
            let challenge = "Digest realm=\"airplay\", nonce=\"abc123\"";
            let _ = server.write_all(
                format!("RTSP/1.0 401 Unauthorized\r\nWWW-Authenticate: {challenge}\r\nContent-Length: 0\r\n\r\n").as_bytes(),
            );
            let n = server.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.contains("Authorization: Digest"), "retry must carry auth");
            let _ = server.write_all(b"RTSP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
        });

        let (body, _) = client
            .rtsp_request("SETUP", "rtsp://127.0.0.1/1", "text/plain", b"x", &HashMap::new())
            .expect("retry succeeds");
        assert_eq!(body, b"ok");
        assert!(client.auth_challenge.is_some());
    }
}
