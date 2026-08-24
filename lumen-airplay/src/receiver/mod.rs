//! AirPlay mirroring receiver (protocol/testing server), ported from
//! `internal/airplay/receiver_*.go` in the upstream Go lumen.
//!
//! A Rust, no-GStreamer receiver for observing exactly what a real Apple
//! client (a MacBook Air) sends. The immediate purpose is to capture the
//! Apple audio SETUP descriptor + RTP packets so the sender side can replicate
//! the exact format the Android TV's "Luna" framework expects.

const LEGACY_AIRPLAY_SOURCE_VERSION: &str = "280.33";
const MODERN_AIRPLAY_SOURCE_VERSION: &str = "980.71.1";

pub mod pairing;
use pairing::{HapStream, ReceiverPairing, SessionKeys};

pub mod fairplay;
use fairplay::ReceiverFpsap;

pub mod media;
use media::ReceiverMedia;

use ed25519_dalek::{SigningKey, VerifyingKey};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use plist::{Dictionary, Value};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const HEADER_LIMIT: usize = 32 * 1024;
const BODY_LIMIT: usize = 8 << 20;

// ---------- Feature / receiver profile constants (from receiver_server.go) ----------

const FEATURE_FPSAP25: u64 = 1 << 14;
#[allow(dead_code)]
const FEATURE_SCREEN: u64 = 1 << 8;
#[allow(dead_code)]
const FEATURE_AUDIO: u64 = 1 << 10;
#[allow(dead_code)]
const FEATURE_HOMEKIT_PAIRING: u64 = 1 << 17;
#[allow(dead_code)]
const FEATURE_SYSTEM_PAIRING: u64 = 1 << 43;
#[allow(dead_code)]
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
            name: "Lumen".to_string(),
            model: "AppleTV-Test".to_string(),
            device_id: String::new(),
            debug: true,
            audio_dump_path: None,
        }
    }
}

struct ProfileSpec {
    source_version: String,
    features: u64,
    #[allow(dead_code)]
    modern_setup: bool,
}

fn profile_spec(profile: ReceiverProfile) -> ProfileSpec {
    match profile {
        ReceiverProfile::Modern => ProfileSpec {
            source_version: MODERN_AIRPLAY_SOURCE_VERSION.to_string(),
            // Advertise the broad feature mask that Apple's own devices use, so
            // macOS lists this receiver as a screen-mirroring target.
            features: 0x4A7FCFD5_38174FDE,
            modern_setup: true,
        },
        ReceiverProfile::Roku => ProfileSpec {
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
    #[allow(dead_code)]
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
    pub fn new(mut cfg: ReceiverConfig) -> std::io::Result<Self> {
        let profile = profile_spec(cfg.profile);
        if cfg.device_id.is_empty() {
            cfg.device_id = random_device_id();
        }
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
        let host = "lumen.local.";
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

        // macOS 13+ (Ventura) also requires `_raop._tcp` to list a device as a
        // screen-mirroring target, so advertise the audio-side service too.
        let raop_txt = txt_for_raop(&self.cfg.device_id, &self.cfg.model, &self.verifying_key);
        let raop_type = "_raop._tcp.local.";
        let raop_instance = ServiceInfo::new(
            raop_type,
            &self.cfg.name,
            host,
            ip,
            port,
            Some(raop_txt),
        )
        .map_err(|e| std::io::Error::other(format!("raop ServiceInfo: {e}")))?;
        sd.register(raop_instance)
            .map_err(|e| std::io::Error::other(format!("register raop: {e}")))?;

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
fn d_bool(dict: &mut Value, key: &str, value: bool) {
    d_insert(dict, key, Value::Boolean(value));
}

/// Extracts the `streams[].type` values a SETUP plist requests.
fn requested_setup_stream_types(body: &[u8]) -> Vec<i64> {
    let Ok(v) = plist::from_bytes::<Value>(body) else {
        return Vec::new();
    };
    let arr = v
        .as_dictionary()
        .and_then(|d| d.get("streams"))
        .and_then(|s| s.as_array())
        .or_else(|| v.as_array());
    let mut types = Vec::new();
    if let Some(arr) = arr {
        for item in arr {
            if let Some(t) = item
                .as_dictionary()
                .and_then(|d| d.get("type"))
                .and_then(|t| t.as_signed_integer())
            {
                types.push(t);
            }
        }
    }
    types
}

/// Short hex preview of a byte slice for diagnostics.
fn hex_preview(bytes: &[u8]) -> String {
    let n = bytes.len().min(48);
    bytes[..n]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Compact text summary of a plist for diagnostics.
fn summarize_plist(v: &Value) -> String {
    if let Some(d) = v.as_dictionary() {
        let parts: Vec<String> = d
            .iter()
            .map(|(k, val)| {
                let s = match val {
                    Value::Integer(i) => i.to_string(),
                    Value::String(s) => s.clone(),
                    Value::Array(a) => format!("[{} items]", a.len()),
                    Value::Data(d) => format!("{} bytes", d.len()),
                    Value::Boolean(b) => b.to_string(),
                    Value::Real(r) => r.to_string(),
                    _ => "?".to_string(),
                };
                format!("{k}={s}")
            })
            .collect();
        parts.join(" ")
    } else if let Some(a) = v.as_array() {
        format!("array [{}]", a.len())
    } else {
        format!("{v:?}")
    }
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
    let lo = features as u32;
    let hi = (features >> 32) as u32;
    let features_str = format!("0x{hi:08x},0x{lo:08x}");
    // Apple's `_airplay._tcp` `pk` TXT is the hex-encoded Ed25519 public key
    // (64 hex chars), NOT base64 — the MacBook filters devices with a bad pk.
    let pk = hex::encode(verifying.as_bytes());
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

/// `_raop._tcp` TXT records for the AirPlay audio-side discovery, which
/// macOS 13+ also consults when listing screen-mirroring targets.
fn txt_for_raop(
    device_id: &str,
    model: &str,
    verifying: &VerifyingKey,
) -> HashMap<String, String> {
    let mut t = HashMap::new();
    t.insert("am".into(), model.into());
    t.insert("md".into(), "0,1,2".into());
    t.insert("deviceid".into(), device_id.into());
    t.insert("features".into(), "0x00000000,0x00000500".into());
    t.insert("flags".into(), "0x4".into());
    t.insert("model".into(), model.into());
    t.insert("tp".into(), "UDP".into());
    t.insert("pk".into(), hex::encode(verifying.as_bytes()));
    t.insert("vv".into(), "2".into());
    t.insert("ch".into(), "2".into());
    t.insert("cn".into(), "0,1,2,3".into());
    t.insert("et".into(), "0,1,3,4".into());
    t.insert("sf".into(), "0x4".into());
    t.insert("sr".into(), "44100".into());
    t.insert("ss".into(), "16".into());
    t.insert("v".into(), "1".into());
    t
}

// ---------- top-level control-connection handler ----------

/// The control-channel transport: plaintext during pairing, then HAP-encrypted
/// once pair-verify completes.
enum CtrlStream {
    Plain(TcpStream),
    Hap(HapStream),
}

impl CtrlStream {
    fn from_tcp(conn: TcpStream) -> Self {
        CtrlStream::Plain(conn)
    }

    fn enable_hap(&mut self, read_key: &[u8], write_key: &[u8]) -> std::io::Result<()> {
        match self {
            CtrlStream::Plain(conn) => {
                let c = conn.try_clone()?;
                *self = CtrlStream::Hap(HapStream::new(c, read_key, write_key)?);
                Ok(())
            }
            CtrlStream::Hap(_) => Ok(()),
        }
    }
}

impl Read for CtrlStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            CtrlStream::Plain(c) => c.read(buf),
            CtrlStream::Hap(h) => h.read(buf),
        }
    }
}

impl Write for CtrlStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            CtrlStream::Plain(c) => c.write(buf),
            CtrlStream::Hap(h) => h.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            CtrlStream::Plain(c) => c.flush(),
            CtrlStream::Hap(h) => h.flush(),
        }
    }
}

/// Per-connection protocol state carried across the RTSP exchange.
struct ReceiverSession {
    pairing: ReceiverPairing,
    fairplay: Option<ReceiverFpsap>,
    #[allow(dead_code)]
    media: Option<ReceiverMedia>,
}

fn serve_control(s: &ReceiverServer, conn: TcpStream) -> std::io::Result<()> {
    let _ = conn.set_read_timeout(Some(Duration::from_secs(120)));
    let pairing = ReceiverPairing::new(&s.identifier, "Pair-Setup", s.signing_key.clone(), &s.cfg.code);
    let fairplay = if s.profile.features & FEATURE_FPSAP25 != 0 {
        Some(ReceiverFpsap::new())
    } else {
        None
    };
    let mut session = ReceiverSession {
        pairing,
        fairplay,
        media: None,
    };
    let mut io = CtrlStream::from_tcp(conn);
    loop {
        let req = match read_request(&mut io) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let (resp, enable_hap) = dispatch(s, &req, &mut session);
        write_response(&mut io, &req, &resp)?;
        if let Some(keys) = enable_hap {
            io.enable_hap(&keys.read_key, &keys.write_key)?;
            *s.hap_enabled.lock().unwrap() = true;
            log::info!("[receiver] control encryption enabled for {}", req.uri);
        }
        log::info!(
            "[receiver] {} {} -> {} (req={} resp={} enc={})",
            req.method,
            req.uri,
            resp.status,
            req.body.len(),
            resp.body.len(),
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
    d_string(&mut info, "manufacturer", "lumen");
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
    let displays = Value::Array(vec![display]);
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

fn dispatch(
    s: &ReceiverServer,
    req: &Request,
    session: &mut ReceiverSession,
) -> (Response, Option<SessionKeys>) {
    let path = request_path(&req.uri);
    // Session-stage requests (fp-setup / SETUP / RECORD / SET_PARAMETER /
    // TEARDOWN / feedback) must follow a completed pair-verify.
    let is_session_request = req.method == "SETUP"
        || req.method == "RECORD"
        || req.method == "SET_PARAMETER"
        || req.method == "TEARDOWN"
        || (req.method == "POST" && (path == "/fp-setup" || path == "/feedback"));
    if is_session_request && !session.pairing.is_verified() {
        return (Response::text(455, "pair-verify must complete first"), None);
    }

    match (req.method.as_str(), path) {
        ("GET", "/info") => (info_plist(s), None),
        ("POST", "/pair-pin-start") => {
            if s.cfg.auth != ReceiverAuth::Pin {
                return (Response::empty(453), None);
            }
            log::info!("[receiver] pairing code: {}", s.cfg.code);
            (Response::empty(200), None)
        }
        ("POST", "/pair-setup") => {
            log::info!("[receiver] pair-setup req: {}", hex_preview(&req.body));
            let body = session.pairing.pair_setup(&req.body);
            log::info!("[receiver] pair-setup resp: {}", hex_preview(&body));
            (Response::ok(body, "application/octet-stream"), None)
        }
        ("POST", "/pair-verify") => {
            log::info!("[receiver] pair-verify req: {}", hex_preview(&req.body));
            let (body, keys) = session.pairing.pair_verify(&req.body);
            log::info!("[receiver] pair-verify resp: {}", hex_preview(&body));
            (Response::ok(body, "application/octet-stream"), keys)
        }
        ("POST", "/fp-setup") => {
            let fairplay = match &mut session.fairplay {
                Some(f) if !f.complete() => f,
                _ => return (Response::text(404, "FairPlay SAP unavailable"), None),
            };
            if req.headers.get("x-apple-et").map(|v| v.as_str()) != Some("32") {
                return (Response::text(400, "fp-setup requires X-Apple-ET: 32"), None);
            }
            log::info!("[receiver] fp-setup ({} bytes)", req.body.len());
            match fairplay.exchange(&req.body) {
                Ok(body) => (Response::ok(body, "application/octet-stream"), None),
                Err(e) => {
                    log::info!("[receiver] fp-setup rejected: {e}");
                    (Response::text(400, &e.to_string()), None)
                }
            }
        }
        ("SETUP", _) => {
            if session.fairplay.as_ref().map(|f| !f.complete()).unwrap_or(false) {
                return (Response::text(455, "FairPlay SAP must complete before SETUP"), None);
            }
            log::info!("[receiver] SETUP ({} bytes)", req.body.len());
            // KEY capture point: the SETUP body is the plist the client sends,
            // containing audioFormat / sampleRate / channels for the audio stream.
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
                if let Ok(v) = plist::from_bytes::<Value>(&req.body) {
                    log::info!("[receiver] SETUP plist: {}", summarize_plist(&v));
                }
            }

            // Lazily allocate the media endpoints.
            if session.media.is_none() {
                let ip = match s.lan_ipv4() {
                    Ok(ip) => ip,
                    Err(e) => return (Response::text(500, &e.to_string()), None),
                };
                match ReceiverMedia::new(ip, s.cfg.audio_dump_path.clone()) {
                    Ok(m) => session.media = Some(m),
                    Err(e) => return (Response::text(500, &e.to_string()), None),
                }
            }
            let media = session.media.as_ref().unwrap();
            let ep = media.endpoints();

            let requested = requested_setup_stream_types(&req.body);
            let mut resp = p_dict();
            d_int(&mut resp, "eventPort", ep.event_port as i64);
            d_insert(&mut resp, "skipRecord", Value::Boolean(false));
            let mut tpi = p_dict();
            d_int(&mut tpi, "ClockID", 0x4454424c54414b45i64);
            d_string(&mut tpi, "ID", &s.identifier);
            d_int(&mut tpi, "DeviceType", 1);
            let lan_ip = s.lan_ipv4().map(|i| i.to_string()).unwrap_or_else(|_| "127.0.0.1".into());
            d_insert(&mut tpi, "Addresses", Value::Array(vec![Value::String(lan_ip)]));
            d_insert(&mut tpi, "SupportsClockPortMatchingOverride", Value::Boolean(true));
            d_insert(&mut resp, "timingPeerInfo", tpi);

            let types: Vec<i64> = if requested.is_empty() { vec![96, 110] } else { requested };
            let mut stream_responses: Vec<Value> = Vec::new();
            for t in types {
                match t {
                    96 => {
                        let mut a = p_dict();
                        d_int(&mut a, "type", 96);
                        d_int(&mut a, "dataPort", ep.audio_rtp_port as i64);
                        d_int(&mut a, "controlPort", ep.audio_rtcp_port as i64);
                        d_int(&mut a, "arrivalToRenderLatencyMs", 0);
                        let mut sc = p_dict();
                        let mut rtp = p_dict();
                        d_int(&mut rtp, "streamConnectionKeyPort", ep.audio_rtp_port as i64);
                        let mut rtcp = p_dict();
                        d_int(&mut rtcp, "streamConnectionKeyPort", ep.audio_rtcp_port as i64);
                        d_insert(&mut sc, "streamConnectionTypeRTP", rtp);
                        d_insert(&mut sc, "streamConnectionTypeRTCP", rtcp);
                        d_insert(&mut a, "streamConnections", sc);
                        stream_responses.push(a);
                    }
                    110 => {
                        let mut v = p_dict();
                        d_int(&mut v, "type", 110);
                        d_int(&mut v, "dataPort", ep.video_port as i64);
                        stream_responses.push(v);
                    }
                    _ => {}
                }
            }
            d_insert(&mut resp, "streams", Value::Array(stream_responses));

            let mut buf = Vec::new();
            let _ = resp.to_writer_binary(&mut buf);
            let mut r = Response::ok(buf, "application/x-apple-binary-plist");
            r.headers = clock_headers(s);
            (r, None)
        }
        ("RECORD", _) => {
            log::info!("[receiver] RECORD");
            let mut r = Response::empty(200);
            r.headers = clock_headers(s);
            (r, None)
        }
        ("SET_PARAMETER", _) => (Response::empty(200), None),
        ("POST", "/feedback") => {
            log::info!("[receiver] /feedback");
            let mut resp = p_dict();
            let mut stream = p_dict();
            d_int(&mut stream, "type", 96);
            d_int(&mut stream, "sr", 44100);
            d_insert(&mut resp, "streams", Value::Array(vec![stream]));
            let mut buf = Vec::new();
            let _ = resp.to_writer_binary(&mut buf);
            let mut r = Response::ok(buf, "application/x-apple-binary-plist");
            r.headers = clock_headers(s);
            (r, None)
        }
        ("TEARDOWN", _) => (Response::empty(200), None),
        _ => (Response::empty(404), None),
    }
}

fn write_response(conn: &mut impl Write, req: &Request, resp: &Response) -> std::io::Result<()> {
    let mut out = String::new();
    out.push_str(&format!("RTSP/1.0 {} {}\r\n", resp.status, status_text(resp.status)));
    if let Some(cseq) = req.headers.get("cseq") {
        out.push_str(&format!("CSeq: {cseq}\r\n"));
    }
    out.push_str("Server: lumen-receiver/1\r\n");
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
