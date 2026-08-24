//! Plaintext RTSP/HTTP transport for the AirPlay control connection.
//!
//! This is the transport used during pairing (which happens before HAP
//! encryption is enabled). The full client layer (`client.rs`) extends this
//! with digest caching and HAP encrypted framing in a later milestone.

use crate::error::{Error, Result};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// A parsed HTTP/RTSP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// Abstraction over the control-channel request/response cycle, so pairing
/// logic can be unit-tested with a mock and the real TCP transport later.
pub trait Transport {
    /// Sends an RTSP/1.0 request and returns the raw response.
    fn request(
        &mut self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
        extra_headers: &HashMap<String, String>,
    ) -> Result<Response>;

    /// Sends a raw (legacy) RTSP/1.0 request with the `X-Apple-ProtocolVersion`
    /// header, as used by the raw binary pair-verify protocol.
    fn request_raw(
        &mut self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
        extra_headers: &HashMap<String, String>,
    ) -> Result<Response>;
}

const USER_AGENT: &str = "AirPlay/935.7.1";
const MAX_RESPONSE_BODY: usize = 8 << 20;

/// A TCP transport speaking the AirPlay control protocol.
pub struct TcpTransport {
    stream: TcpStream,
    cseq: u32,
}

impl TcpTransport {
    pub fn connect(host: &str, port: u16) -> Result<Self> {
        let stream = TcpStream::connect((host, port)).map_err(|e| Error::from_io("dial", e))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| Error::from_io("set read timeout", e))?;
        Ok(TcpTransport { stream, cseq: 0 })
    }

    fn write_request(
        &mut self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
        extra_headers: &HashMap<String, String>,
        raw: bool,
    ) -> Result<()> {
        self.cseq += 1;
        let mut buf = Vec::with_capacity(256 + body.len());
        buf.extend_from_slice(format!("{method} {path} RTSP/1.0\r\n").as_bytes());
        if raw {
            // Legacy rawRequest: Content-Type first, protocol version, then CSeq
            // after Content-Length.
            buf.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
            buf.extend_from_slice(b"X-Apple-ProtocolVersion: 1\r\n");
        } else {
            buf.extend_from_slice(format!("CSeq: {}\r\n", self.cseq).as_bytes());
            buf.extend_from_slice(format!("User-Agent: {USER_AGENT}\r\n").as_bytes());
        }
        for (k, v) in extra_headers {
            buf.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        if !raw && !content_type.is_empty() && !body.is_empty() {
            buf.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
        }
        buf.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        if raw {
            buf.extend_from_slice(format!("CSeq: {}\r\n", self.cseq).as_bytes());
        }
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(body);
        self.stream
            .write_all(&buf)
            .map_err(|e| Error::from_io("write request", e))
    }

    fn read_response(&mut self) -> Result<Response> {
        // Read headers byte-by-byte until \r\n\r\n.
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
        let (status, content_length, headers) = parse_http_header(&header_str);
        validate_content_length(content_length)?;

        let mut body = Vec::new();
        if content_length > 0 {
            body.resize(content_length, 0);
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
}

impl Transport for TcpTransport {
    fn request(
        &mut self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
        extra_headers: &HashMap<String, String>,
    ) -> Result<Response> {
        self.write_request(method, path, content_type, body, extra_headers, false)?;
        self.read_response()
    }

    fn request_raw(
        &mut self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
        extra_headers: &HashMap<String, String>,
    ) -> Result<Response> {
        self.write_request(method, path, content_type, body, extra_headers, true)?;
        self.read_response()
    }
}

/// Parses an HTTP/RTSP response header block into (status, content-length,
/// headers). Header names are lowercased.
pub fn parse_http_header(header: &str) -> (u16, usize, HashMap<String, String>) {
    let mut headers = HashMap::new();
    let mut status: u16 = 0;

    let mut lines = header.split("\r\n");
    if let Some(first) = lines.next() {
        if let Some(rest) = first.strip_prefix("HTTP/1.1 ") {
            status = rest.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
        } else if let Some(rest) = first.strip_prefix("RTSP/1.0 ") {
            status = rest.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
        }
    }

    let mut content_length = 0usize;
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if key.is_empty() {
                continue;
            }
            if key == "content-length" {
                content_length = value.trim().parse().unwrap_or(0);
            }
            headers.insert(key, value);
        }
    }

    (status, content_length, headers)
}

fn validate_content_length(n: usize) -> Result<()> {
    if n > MAX_RESPONSE_BODY {
        return Err(Error::Protocol(format!(
            "Content-Length {n} exceeds the {} byte limit",
            MAX_RESPONSE_BODY
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_header() {
        let hdr = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Apple-ET: 32\r\n\r\n";
        let (status, len, headers) = parse_http_header(hdr);
        assert_eq!(status, 200);
        assert_eq!(len, 5);
        assert_eq!(headers["content-length"], "5");
        assert_eq!(headers["x-apple-et"], "32");
    }

    #[test]
    fn parses_rtsp_status() {
        let hdr = "RTSP/1.0 200 OK\r\n\r\n";
        let (status, len, _) = parse_http_header(hdr);
        assert_eq!(status, 200);
        assert_eq!(len, 0);
    }
}
