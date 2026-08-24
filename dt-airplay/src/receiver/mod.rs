//! AirPlay mirroring receiver (protocol/testing server), ported from
//! `internal/airplay/receiver_*.go` in the upstream Go doubletake.
//!
//! A Rust, no-GStreamer receiver for observing exactly what a real Apple
//! client (a MacBook Air) sends. The immediate purpose is to capture the
//! Apple audio SETUP descriptor + RTP packets so the sender side can replicate
//! the exact format the Android TV's "Luna" framework expects.

use crate::tlv8;

const LEGACY_AIRPLAY_SOURCE_VERSION: &str = "280.33";
const MODERN_AIRPLAY_SOURCE_VERSION: &str = "980.71.1";

pub mod pairing;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use plist::{Dictionary, Value};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const HEADER_LIMIT: usize = 32 * 1024;
const BODY_LIMIT: usize = 8 << 20;

// ---------- Feature / receiver profile constants (from receiver_server.go) ----------

const FEATURE_SCREEN: u64 = 1 << 8;
const FEATURE_AUDIO: u64 = 1 << 10;
const FEATURE_FPSAP25: u64 = 1 << 14;
const FEATURE_HOMEKIT_PAIRING: u64 = 1 << 17;
const FEATURE_SYSTEM_PAIRING: u64 = 1 << 43;
const FEATURE_TRANSIENT_PAIRING: u64 = 1 << 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverProfile {
    Modern,
    Roku,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverAuth {
    None,
    Pin,
    Password,
    Digest,
    Combined,
}

#[derive(Debug, Clone)]
pub struct ReceiverConfig {
    pub listen: String,
    pub profile: ReceiverProfile,
    pub auth: ReceiverAuth,
    pub code: String,
    pub name: String,
    pub model: String,
    pub device_id: String,
    pub debug: bool,
    /// If set, dump every audio SETUP plist to this file (appended).
    pub audio_dump_path: Option<std::path::PathBuf>,
}

impl Default for ReceiverConfig {
    fn default() -> Self {
        ReceiverConfig {
            listen: "0.0.0.0:7000".to_string(),
            profile: ReceiverProfile::Modern,
            auth: ReceiverAuth::None,
            code: String::new(),
            name: "Doubletake-RS".to_string(),
            model: "AppleTV-Test".to_string(),
            device_id: String::new(),
            debug: true,
            audio_dump_path: None,
        }
    }
}

struct ProfileSpec {
    name: String,
    model: String,
    source_version: String,
    features: u64,
    modern_setup: bool,
}

fn profile_spec(profile: ReceiverProfile) -> ProfileSpec {
    match profile {
        ReceiverProfile::Modern => ProfileSpec {
            name: "doubletake modern test receiver".to_string(),
            model: "AppleTV-Test".to_string(),
            source_version: MODERN_AIRPLAY_SOURCE_VERSION.to_string(),
            features: FEATURE_SCREEN
                | FEATURE_AUDIO
                | FEATURE_FPSAP25
                | FEATURE_HOMEKIT_PAIRING
                | (1 << 38)
                | FEATURE_SYSTEM_PAIRING
                | (1 << 46)
                | FEATURE_TRANSIENT_PAIRING,
            modern_setup: true,
        },
        ReceiverProfile::Roku => ProfileSpec {
            name: "doubletake Roku test receiver".to_string(),
            model: "3820R2".to_string(),
            source_version: LEGACY_AIRPLAY_SOURCE_VERSION.to_string(),
            features: 0x038bcf46007f8ad0,
            modern_setup: false,
        },
    }
}

pub struct ReceiverServer {
    cfg: ReceiverConfig,
    profile: ProfileSpec,
    listener: TcpListener,
    pub signing_key: SigningKey,
    verifying_key: VerifyingKey,
    identifier: String,
    started: Instant,
    connections: AtomicU64,

    /// Whether control-channel HAP encryption has been negotiated. Set once
    /// pair-verify completes. (Boolean, read/written from the control thread.)
    hap_enabled: Mutex<bool>,
    media: Mutex<Option<ReceiverMedia>>,
}

fn random_device_id() -> String {
    let mut b = [0u8; 6];
    OsRng.fill_bytes(&mut b);
    b[0] = (b[0] & 0xfe) | 0x02;
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    )
}

impl ReceiverServer {
    pub fn new(cfg: ReceiverConfig) -> std::io::Result<Self> {
        let profile = profile_spec(cfg.profile);
        let device_id = if cfg.device_id.is_empty() {
            random_device_id()
        } else {
            cfg.device_id.clone()
        };
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let listener = TcpListener::bind(&cfg.listen)?;
        Ok(ReceiverServer {
            cfg,
            profile,
            listener,
            signing_key,
            verifying_key,
            identifier: crate::uuid::generate_uuid(),
            started: Instant::now(),
            connections: AtomicU64::new(0),
            hap_enabled: Mutex::new(false),
            media: Mutex::new(None),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Picks the first usable non-loopback IPv4 on which a client can reach us.
    /// Used both for mDNS advertisement and for the SETUP endpoint binding.
    pub fn lan_ipv4(&self) -> std::io::Result<IpAddr> {
        // Prefer the route IP to the public internet (the LAN interface), which
        // is what a client on the same subnet will use to reach us.
        if let Some(ip) = net::lan_ipv4() {
            return Ok(ip);
        }
        // Fallback: a concrete bound IPv4 (never unspecified/loopback/link-local).
        if let Ok(addr) = self.listener.local_addr() {
            let ip = addr.ip();
            if ip.is_ipv4() && !ip.is_loopback() && !ip.is_unspecified() {
                return Ok(ip);
            }
        }
        Err(std::io::Error::other("no usable LAN IPv4 address"))
    }

    pub fn advertise(&self) -> std::io::Result<ServiceDaemon> {
        let ip = self.lan_ipv4()?;
        let port = self.listener.local_addr()?.port();
        let sd = ServiceDaemon::new()
            .map_err(|e| std::io::Error::other(format!("ServiceDaemon::new: {e}")))?;

        let features = self.profile.features;
        let txt = txt_for_airplay(
            features,
            &self.cfg.device_id,
            &self.cfg.model,
            &self.verifying_key,
            &self.cfg.name,
            &self.profile.source_version,
        );
        let service_type = "_airplay._tcp.local.";
        let host = "doubletake-rs.local.";
        let instance = ServiceInfo::new(
            service_type,
            &self.cfg.name,
            host,
            ip,
            port,
            Some(txt),
        )
        .map_err(|e| std::io::Error::other(format!("airplay ServiceInfo: {e}")))?;
        sd.register(instance)
            .map_err(|e| std::io::Error::other(format!("register airplay: {e}")))?;
        log::info!("[receiver] advertising _airplay._tcp {}:{} name={} features=0x{:x}", ip, port, self.cfg.name, features);
        Ok(sd)
    }

    /// Serve control connections forever. Spawns the media UDP endpoints lazily.
    pub fn serve(self: &std::sync::Arc<Self>) -> std::io::Result<()> {
        log::info!(
            "[receiver] listening on {} (profile={:?} auth={:?})",
            self.listener.local_addr()?,
            self.cfg.profile,
            self.cfg.auth
        );
        loop {
            let (conn, peer) = match self.listener.accept() {
                Ok(c) => c,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            self.connections.fetch_add(1, Ordering::SeqCst);
            let this = std::sync::Arc::clone(self);
            std::thread::spawn(move || {
                if let Err(e) = serve_control(&this, conn) {
                    log::info!("[receiver] control {} closed: {e}", peer);
                }
            });
        }
    }
}

// ---------- RTSP request/response parsing ----------

struct Request {
    method: String,
    uri: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct Response {
    status: u16,
    content_type: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Response {
    fn ok(body: Vec<u8>, content_type: &str) -> Self {
        Response {
            status: 200,
            content_type: content_type.to_string(),
            headers: HashMap::new(),
            body,
        }
    }
    fn empty(status: u16) -> Self {
        Response {
            status,
            content_type: String::new(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }
    fn text(status: u16, msg: &str) -> Self {
        Response {
            status,
            content_type: "text/plain".to_string(),
            headers: HashMap::new(),
            body: msg.as_bytes().to_vec(),
        }
    }
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        453 => "Not Enough Bandwidth",
        455 => "Method Not Valid in This State",
        500 => "Internal Server Error",
        _ => "Error",
    }
}

fn read_request(reader: &mut dyn Read) -> std::io::Result<Request> {
    let line = read_line(reader)?;
    if line.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "connection closed"));
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() != 3 || parts[2] != "RTSP/1.0" {
        return Err(std::io::Error::other(format!("invalid RTSP request line: {line:?}")));
    }
    let mut req = Request {
        method: parts[0].to_string(),
        uri: parts[1].to_string(),
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let mut content_length: usize = 0;
    loop {
        let hline = read_line(reader)?;
        if hline.is_empty() {
            break;
        }
        if let Some((name, value)) = hline.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if name == "content-length" {
                content_length = value
                    .parse()
                    .map_err(|_| std::io::Error::other(format!("bad content-length {value}")))?;
            }
            req.headers.insert(name, value);
        }
    }
    if content_length > 0 {
        let mut body = vec![0u8; content_length.min(BODY_LIMIT)];
        reader.read_exact(&mut body)?;
        req.body = body;
    }
    Ok(req)
}

fn read_line(reader: &mut dyn Read) -> std::io::Result<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if reader.read_exact(&mut byte).is_err() {
            if buf.is_empty() {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof"));
            }
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
        if buf.len() > HEADER_LIMIT {
            return Err(std::io::Error::other("header too large"));
        }
    }
    Ok(String::from_utf8_lossy(&buf)
        .trim_end_matches('\r')
        .to_string())
}

fn request_path(uri: &str) -> &str {
    if let Some(rest) = uri.strip_prefix("rtsp://") {
        if let Some(slash) = rest.find('/') {
            return &rest[slash..];
        }
    }
    uri
}

// ---------- plist helpers (mirroring mirror.rs helpers) ----------

fn p_dict() -> Value {
    Value::Dictionary(Dictionary::new())
}
fn d_insert(dict: &mut Value, key: &str, value: Value) {
    if let Some(map) = dict.as_dictionary_mut() {
        map.insert(key.to_string(), value);
    }
}
fn d_string(dict: &mut Value, key: &str, value: &str) {
    d_insert(dict, key, Value::String(value.to_string()));
}
fn d_int(dict: &mut Value, key: &str, value: i64) {
    d_insert(dict, key, Value::Integer(value.into()));
}
fn d_data(dict: &mut Value, key: &str, value: &[u8]) {
    d_insert(dict, key, Value::Data(value.to_vec()));
}
fn d_bool(dict: &mut Value, key: &str, value: bool) {
    d_insert(dict, key, Value::Boolean(value));
}
fn plist_int(v: &Value) -> i64 {
    v.as_signed_integer()
        .unwrap_or_else(|| v.as_real().map(|f| f as i64).unwrap_or(0))
}

// ---------- mDNS TXT ----------

fn txt_for_airplay(
    features: u64,
    device_id: &str,
    model: &str,
    verifying: &VerifyingKey,
    name: &str,
    source_version: &str,
) -> HashMap<String, String> {
    use base64::Engine;
    let lo = features as u32;
    let hi = (features >> 32) as u32;
    let features_str = format!("0x{hi:08x},0x{lo:08x}");
    let pk = base64::engine::general_purpose::STANDARD.encode(verifying.as_bytes());
    let mut t = HashMap::new();
    t.insert("deviceid".to_string(), device_id.to_string());
    t.insert("features".to_string(), features_str);
    t.insert("flags".to_string(), "0x4".to_string());
    t.insert("model".to_string(), model.to_string());
    t.insert("pk".to_string(), pk);
    t.insert("srcvers".to_string(), source_version.to_string());
    t.insert("vv".to_string(), "2".to_string());
    t.insert("protovers".to_string(), "1.1".to_string());
    t.insert("sf".to_string(), "0x4".to_string());
    t.insert("gid".to_string(), crate::uuid::generate_uuid());
    t.insert("pi".to_string(), format!("{:x}", features));
    t.insert("cn".to_string(), model.to_string());
    // name often advertised as instance; include as a spare key too.
    t.insert("n".to_string(), name.to_string());
    t
}

// ---------- top-level control-connection handler ----------

fn serve_control(s: &ReceiverServer, mut conn: TcpStream) -> std::io::Result<()> {
    let _ = conn.set_read_timeout(Some(Duration::from_secs(120)));
    loop {
        let req = match read_request(&mut conn) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let resp = dispatch(s, &req);
        write_response(&mut conn, &req, &resp)?;
        log::info!(
            "[receiver] {} {} -> {} (body={} enc={})",
            req.method,
            req.uri,
            resp.status,
            req.body.len(),
            *s.hap_enabled.lock().unwrap()
        );
    }
}

fn clock_headers(s: &ReceiverServer) -> HashMap<String, String> {
    let millis = s.started.elapsed().as_millis().max(1) as i64;
    let mut h = HashMap::new();
    h.insert("X-Apple-RequestReceivedTimestamp".into(), millis.to_string());
    h.insert("X-Apple-ProcessingTime".into(), "1".to_string());
    h
}

fn info_plist(s: &ReceiverServer) -> Response {
    let mut status: u64 = 4;
    if s.cfg.auth == ReceiverAuth::Pin {
        status |= 2; // PIN required for pairing
    }
    if matches!(s.cfg.auth, ReceiverAuth::Password | ReceiverAuth::Digest | ReceiverAuth::Combined) {
        status |= 1; // password required
    }

    let mut info = p_dict();
    d_string(&mut info, "name", &s.cfg.name);
    d_string(&mut info, "model", &s.cfg.model);
    d_string(&mut info, "manufacturer", "doubletake");
    d_string(&mut info, "deviceID", &s.cfg.device_id);
    d_string(&mut info, "macAddress", &s.cfg.device_id);
    d_string(&mut info, "protocolVersion", "1.1");
    d_string(&mut info, "sourceVersion", &s.profile.source_version);
    d_insert(&mut info, "features", Value::Integer(s.profile.features.into()));
    d_insert(&mut info, "statusFlags", Value::Integer((status as i64).into()));
    d_insert(&mut info, "pk", Value::Data(s.verifying_key.as_bytes().to_vec()));
    d_insert(&mut info, "initialVolume", Value::Real(0.0.into()));
    d_int(&mut info, "volumeControlType", 0);
    d_bool(&mut info, "keepAliveSendStatsAsBody", true);

    let mut display = p_dict();
    d_int(&mut display, "width", 1920);
    d_int(&mut display, "height", 1080);
    d_int(&mut display, "widthPixels", 1920);
    d_int(&mut display, "heightPixels", 1080);
    d_int(&mut display, "widthPixelsMax", 1920);
    d_int(&mut display, "heightPixelsMax", 1080);
    d_int(&mut display, "maxFPS", 60);
    d_string(&mut display, "uuid", &crate::uuid::generate_uuid());
    let mut displays = Value::Array(vec![display]);
    d_insert(&mut info, "displays", displays);

    let mut lat = p_dict();
    d_int(&mut lat, "type", 100);
    d_int(&mut lat, "ch", 2);
    d_int(&mut lat, "inputLatencyMicros", 0);
    d_int(&mut lat, "outputLatencyMicros", 0);
    d_insert(&mut info, "audioLatencies", Value::Array(vec![lat]));

    let mut buf = Vec::new();
    let _ = info.to_writer_binary(&mut buf);
    Response::ok(buf, "application/x-apple-binary-plist")
}

fn dispatch(s: &ReceiverServer, req: &Request) -> Response {
    let path = request_path(&req.uri);
    match (req.method.as_str(), path) {
        ("GET", "/info") => info_plist(s),
        ("POST", "/pair-pin-start") => {
            if s.cfg.auth != ReceiverAuth::Pin {
                return Response::empty(453);
            }
            log::info!("[receiver] pairing code: {}", s.cfg.code);
            Response::empty(200)
        }
        ("POST", "/pair-setup") => {
            log::info!("[receiver] pair-setup ({} bytes) — pairing stage not yet implemented", req.body.len());
            Response::text(404, "pair-setup not implemented")
        }
        ("POST", "/pair-verify") => {
            log::info!("[receiver] pair-verify ({} bytes) — not yet implemented", req.body.len());
            Response::text(455, "pair-verify not implemented")
        }
        ("POST", "/fp-setup") => {
            log::info!("[receiver] fp-setup ({} bytes) — not yet implemented", req.body.len());
            Response::text(404, "fp-setup not implemented")
        }
        ("SETUP", _) => {
            // KEY capture point: the SETUP body is the plist the client sends,
            // containing audioFormat / sampleRate / channels for the audio stream.
            log::info!("[receiver] SETUP ({} bytes)", req.body.len());
            if let Some(p) = &s.cfg.audio_dump_path {
                if let Some(parent) = p.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
                    let _ = writeln!(f, "=== SETUP {} bytes (method={} uri={}) ===", req.body.len(), req.method, req.uri);
                    let _ = f.write_all(&req.body);
                    let _ = writeln!(f);
                    log::info!("[receiver] dumped SETUP body to {:?}", p);
                }
            }
            Response::text(455, "SETUP not implemented")
        }
        ("RECORD", _) => {
            log::info!("[receiver] RECORD");
            Response::empty(200)
        }
        ("TEARDOWN", _) => Response::empty(200),
        _ => Response::empty(404),
    }
}

fn write_response(conn: &mut TcpStream, req: &Request, resp: &Response) -> std::io::Result<()> {
    let mut out = String::new();
    out.push_str(&format!("RTSP/1.0 {} {}\r\n", resp.status, status_text(resp.status)));
    if let Some(cseq) = req.headers.get("cseq") {
        out.push_str(&format!("CSeq: {cseq}\r\n"));
    }
    out.push_str("Server: doubletake-rs-receiver/1\r\n");
    for (name, value) in &resp.headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    if !resp.content_type.is_empty() && !resp.body.is_empty() {
        out.push_str(&format!("Content-Type: {}\r\n", resp.content_type));
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", resp.body.len()));
    conn.write_all(out.as_bytes())?;
    conn.write_all(&resp.body)?;
    conn.flush()?;
    Ok(())
}

// ---------- trivial interface enumeration (uses no extra crates) ----------

// ---------- minimal media placeholder (filled in next milestones) ----------

struct ReceiverMedia {
    _sock: UdpSocket,
}

// Re-exported so the example can start the server.
pub mod net {
    use std::net::{IpAddr, Ipv4Addr, UdpSocket};

    /// Returns the IPv4 of the interface that can reach the default gateway.
    /// On Windows this uses a UDP "connect" trick that does not send packets.
    pub fn lan_ipv4() -> Option<IpAddr> {
        // Try to find an IPv4 via a connected UDP socket to a well-known remote.
        // This only picks a route, never transmits.
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            if sock.connect("8.8.8.8:80").is_ok() {
                if let Ok(addr) = sock.local_addr() {
                    if let IpAddr::V4(v4) = addr.ip() {
                        if !v4.is_loopback() && !v4.is_unspecified() && !v4.is_link_local() && !v4.is_multicast() {
                            return Some(IpAddr::V4(v4));
                        }
                    }
                }
            }
        }
        None
    }

    #[allow(dead_code)]
    fn _unused() -> Ipv4Addr {
        Ipv4Addr::UNSPECIFIED
    }
}
