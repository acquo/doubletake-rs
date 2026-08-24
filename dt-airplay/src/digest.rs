//! RFC 2069 digest auth, mirroring `digest.go` from upstream doubletake.

use md5::{Digest, Md5};
use std::collections::HashMap;

/// Username AirPlay receivers expect in a Digest response. Receivers that
/// advertise realm="airplay" (mirroring receivers) use "AirPlay".
pub const DIGEST_USERNAME: &str = "AirPlay";

/// A parsed `WWW-Authenticate: Digest` challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestChallenge {
    pub realm: String,
    pub nonce: String,
}

/// Parses a WWW-Authenticate header of the form
/// `Digest realm="airplay", nonce="..."`.
///
/// Apple TV sends neither qop nor algorithm, so this is the RFC 2069 flavour:
/// no cnonce, no nc, response = MD5(HA1:nonce:HA2).
pub fn parse_digest_challenge(value: &str) -> Option<DigestChallenge> {
    let v = value.trim();
    if !v.len().ge(&"Digest".len()) || !v[.."Digest".len()].eq_ignore_ascii_case("Digest") {
        return None;
    }
    let params = parse_auth_params(&v["Digest".len()..]);
    let realm = params.get("realm")?;
    let nonce = params.get("nonce")?;
    Some(DigestChallenge {
        realm: realm.clone(),
        nonce: nonce.clone(),
    })
}

/// Splits a comma-separated list of `key="value"` (or bare `key=value`) auth
/// parameters. Quoted values are unquoted; commas inside quotes are kept.
fn parse_auth_params(s: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();

    let mut key = String::new();
    let mut val = String::new();
    let mut in_key = true;
    let mut in_quotes = false;

    let mut flush = |key: &mut String, val: &mut String, in_key: &mut bool| {
        let k = key.trim().to_ascii_lowercase();
        if !k.is_empty() {
            params.insert(k, val.trim().to_string());
        }
        key.clear();
        val.clear();
        *in_key = true;
    };

    for ch in s.chars() {
        match ch {
            '"' if in_quotes => in_quotes = false,
            _ if in_quotes => val.push(ch),
            '"' if !in_key => in_quotes = true,
            '=' if in_key => in_key = false,
            ',' => flush(&mut key, &mut val, &mut in_key),
            _ if in_key => key.push(ch),
            _ => val.push(ch),
        }
    }
    flush(&mut key, &mut val, &mut in_key);

    params
}

/// Computes the RFC 2069 digest response:
/// HA1 = MD5(username:realm:password)
/// HA2 = MD5(method:uri)
/// response = MD5(HA1:nonce:HA2)
pub fn digest_response(
    username: &str,
    realm: &str,
    password: &str,
    nonce: &str,
    method: &str,
    uri: &str,
) -> String {
    let ha1 = md5_hex(&format!("{username}:{realm}:{password}"));
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    md5_hex(&format!("{ha1}:{nonce}:{ha2}"))
}

fn md5_hex(s: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

/// Builds the `Authorization` header value that answers `ch`.
pub fn authorization_header(
    username: &str,
    password: &str,
    ch: &DigestChallenge,
    method: &str,
    uri: &str,
) -> String {
    format!(
        "Digest username=\"{username}\", realm=\"{}\", nonce=\"{}\", uri=\"{uri}\", response=\"{}\"",
        ch.realm,
        ch.nonce,
        digest_response(username, &ch.realm, password, &ch.nonce, method, uri)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 2617 §3.5 worked example, computed in the RFC 2069 flavour (no qop).
    /// Verified independently: HA1 = 939e7578ed9e3c518a452acee763bce9,
    /// HA2 = 39aff3a2bab6126f332b942af96d3366, response = MD5(HA1:nonce:HA2).
    #[test]
    fn rfc_vector() {
        let resp = digest_response(
            "Mufasa",
            "testrealm@host.com",
            "Circle Of Life",
            "dcd98b7102dd2f0e8b11d0f600bfb0c093",
            "GET",
            "/dir/index.html",
        );
        assert_eq!(resp, "670fd8c2df070c60b045671b8b24ff02");
    }

    #[test]
    fn parses_challenge() {
        let ch = parse_digest_challenge(
            r#"Digest realm="airplay", nonce="MTc4NTE4NjAxMCD20F7TBLQS+AiSlk1YQmKR""#,
        )
        .expect("parse");
        assert_eq!(ch.realm, "airplay");
        assert_eq!(ch.nonce, "MTc4NTE4NjAxMCD20F7TBLQS+AiSlk1YQmKR");
    }

    #[test]
    fn rejects_non_digest() {
        assert!(parse_digest_challenge("Basic realm=x").is_none());
    }

    #[test]
    fn header_builds_with_expected_response() {
        let ch = DigestChallenge {
            realm: "airplay".into(),
            nonce: "n0nce".into(),
        };
        let hdr = authorization_header("AirPlay", "s3cr3t", &ch, "SETUP", "rtsp://h/stream");
        assert!(hdr.starts_with("Digest username=\"AirPlay\""));
        let want = digest_response("AirPlay", "airplay", "s3cr3t", "n0nce", "SETUP", "rtsp://h/stream");
        assert!(hdr.contains(&format!("response=\"{want}\"")));
    }

    /// RFC 2069 nonce containing base64 characters that could confuse a naive
    /// comma split (the `+` and `/` are fine, but keep the quoted-value path).
    #[test]
    fn nonce_with_quoted_comma_kept() {
        let ch = parse_digest_challenge(r#"Digest realm="airplay", nonce="ab,c""#).expect("parse");
        assert_eq!(ch.nonce, "ab,c");
    }
}
