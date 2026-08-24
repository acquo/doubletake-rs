//! Shared error type for the AirPlay protocol layer.

use crate::transport::Response;

/// Errors produced by the protocol layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O or framing failure on the transport.
    #[error("transport: {0}")]
    Transport(String),
    /// A receiver responded with a non-2xx status.
    #[error("http {status}: body {body:?}")]
    HttpStatus { status: u16, body: Vec<u8> },
    /// Malformed or unexpected protocol data.
    #[error("protocol: {0}")]
    Protocol(String),
    /// Cryptographic operation failed (bad signature, auth tag, ...).
    #[error("crypto: {0}")]
    Crypto(String),
}

impl Error {
    /// Turns a raw response into a body, or an [`Error::HttpStatus`] for
    /// non-2xx responses, mirroring the Go `httpRequest` semantics.
    pub fn ok_body(resp: Result<Response>) -> Result<Vec<u8>> {
        let resp = resp?;
        if !(200..300).contains(&resp.status) {
            return Err(Error::HttpStatus {
                status: resp.status,
                body: resp.body,
            });
        }
        Ok(resp.body)
    }

    /// Convenience: maps an `io::Error` into [`Error::Transport`].
    pub fn from_io(context: &str, e: std::io::Error) -> Error {
        Error::Transport(format!("{context}: {e}"))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
