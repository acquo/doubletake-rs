//! The mirroring session, ported from upstream `mirror.go`.
//!
//! Video frames travel over a TCP data channel with a 128-byte
//! APScreenProtocolHeader + AVCC payload (encrypted with AES-CTR or
//! ChaCha20-Poly1305), not RTP. Audio uses RTP but is out of scope here.

use crate::client::Client;
use crate::error::{Error, Result};
use crate::event_channel::serve_event_channel;
use crate::info::ReceiverInfo;
use crate::latency::{target_latency, CONSERVATIVE_PLAYOUT_LATENCY_NS};
use crate::mirror_cipher::{derive_chacha_key, derive_video_keys, MirrorCipher};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use plist::{Dictionary, Value};
use std::io::Write;
use std::net::{TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

pub const TIMING_PROTOCOL_NTP: &str = "NTP";
pub const TIMING_PROTOCOL_PTP: &str = "PTP";

const LEGACY_AIRPLAY_SOURCE_VERSION: &str = "280.33";
const MODERN_AIRPLAY_SOURCE_VERSION: &str = "980.71.1";
const SECONDS_FROM_1900_TO_1970: u64 = 2208988800;

static APP_START: OnceLock<Instant> = OnceLock::new();

fn app_start() -> Instant {
    *APP_START.get_or_init(Instant::now)
}

fn plist_dict() -> Value {
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

/// plistInt equivalent.
pub fn plist_int(v: &Value) -> i64 {
    v.as_signed_integer()
        .unwrap_or_else(|| v.as_real().map(|f| f as i64).unwrap_or(0))
}

fn plist_uint(v: &Value) -> u64 {
    plist_int(v) as u64
}

fn plist_dict_int(value: i64) -> Value {
    Value::Integer(value.into())
}

fn uuid_to_mac(id: &str) -> String {
    let hex: String = id.to_ascii_lowercase().chars().filter(|c| *c != '-').collect();
    if hex.len() < 12 {
        return "02:00:00:00:00:01".to_string();
    }
    let b: Vec<u8> = hex.as_bytes()[..12].to_vec();
    let parts: Vec<String> = b.chunks(2).map(|c| String::from_utf8_lossy(c).to_ascii_uppercase()).collect();
    let mut mac = parts.join(":");
    // Force locally-administered.
    mac.replace_range(..2, "02");
    mac
}

/// 64-bit NTP fixed-point timestamp: sec<<32 | frac.
pub fn compact_timestamp(d: Duration) -> u64 {
    let d = if d < Duration::ZERO { Duration::ZERO } else { d };
    let sec = d.as_secs();
    let nsec_frac = d.subsec_nanos() as u64;
    let frac = (nsec_frac << 32) / 1_000_000_000;
    (sec << 32) | frac
}

/// The media clock maps local monotonic time onto the receiver's PTP timeline.
#[derive(Debug, Default)]
pub struct MediaClock {
    anchor_local: Option<Instant>,
    anchor_timestamp: u64,
    timeline_id: u64,
}

impl MediaClock {
    pub fn configure_from_setup(
        &mut self,
        response: &Value,
        headers: &std::collections::HashMap<String, String>,
        received_at: Instant,
    ) -> Result<()> {
        let peer = match response.as_dictionary().and_then(|m| m.get("timingPeerInfo")) {
            Some(Value::Dictionary(m)) => m,
            _ => return Err(Error::Protocol("SETUP response omitted timingPeerInfo".into())),
        };
        let timeline_id = peer.get("ClockID").map(plist_uint).unwrap_or(0);
        if timeline_id == 0 {
            return Err(Error::Protocol("SETUP response omitted timingPeerInfo.ClockID".into()));
        }
        let (anchor, _, _) = receiver_clock_timestamp(headers)?;
        self.anchor_local = Some(received_at);
        self.anchor_timestamp = anchor;
        self.timeline_id = timeline_id;
        Ok(())
    }

    pub fn reanchor(
        &mut self,
        headers: &std::collections::HashMap<String, String>,
        received_at: Instant,
    ) -> Result<()> {
        let (anchor, _, _) = receiver_clock_timestamp(headers)?;
        self.anchor_timestamp = anchor;
        self.anchor_local = Some(received_at);
        Ok(())
    }

    pub fn now(&self, bias: Duration) -> Option<(u64, u64)> {
        let local = self.anchor_local?;
        if self.timeline_id == 0 {
            return None;
        }
        let ts = self.anchor_timestamp + compact_timestamp(local.elapsed() + bias);
        Some((ts, self.timeline_id))
    }
}

fn receiver_clock_timestamp(
    headers: &std::collections::HashMap<String, String>,
) -> Result<(u64, u64, u64)> {
    let received: u64 = headers
        .get("x-apple-requestreceivedtimestamp")
        .ok_or_else(|| Error::Protocol("invalid X-Apple-RequestReceivedTimestamp".into()))?
        .parse()
        .map_err(|_| Error::Protocol("invalid X-Apple-RequestReceivedTimestamp".into()))?;
    let processing: u64 = headers
        .get("x-apple-processingtime")
        .ok_or_else(|| Error::Protocol("invalid X-Apple-ProcessingTime".into()))?
        .parse()
        .map_err(|_| Error::Protocol("invalid X-Apple-ProcessingTime".into()))?;
    let total = Duration::from_millis(received + processing);
    Ok((compact_timestamp(total), received, processing))
}

/// A request plist shared by session/control/stream setups.
struct SetupRequest {
    device_id: String,
    session_uuid: String,
    source_version: String,
    timing_protocol: String,
    timing_port: u16,
    timing_peer_id: String,
    timing_peer_address: String,
    name: String,
}

impl SetupRequest {
    fn session_plist(&self) -> Value {
        let mut request = plist_dict();
        d_string(&mut request, "deviceID", &self.device_id);
        d_string(&mut request, "macAddress", &self.device_id);
        d_string(&mut request, "sessionUUID", &self.session_uuid);
        d_string(&mut request, "sourceVersion", &self.source_version);
        d_bool(&mut request, "isScreenMirroringSession", true);
        d_string(&mut request, "timingProtocol", &self.timing_protocol);
        d_string(&mut request, "osBuildVersion", "13F69");
        d_string(&mut request, "model", "Linux");
        d_string(&mut request, "name", &self.name);
        if self.timing_protocol == TIMING_PROTOCOL_NTP {
            d_int(&mut request, "timingPort", self.timing_port as i64);
        } else {
            let mut peer = plist_dict();
            d_string(&mut peer, "ID", &self.timing_peer_id);
            d_bool(&mut peer, "SupportsClockPortMatchingOverride", true);
            d_int(&mut peer, "DeviceType", 0);
            d_insert(
                &mut peer,
                "Addresses",
                Value::Array(vec![Value::String(self.timing_peer_address.clone())]),
            );
            d_insert(&mut request, "timingPeerInfo", peer.clone());
            d_insert(&mut request, "timingPeerList", Value::Array(vec![peer]));
        }
        request
    }

    fn control_plist(&self) -> Value {
        let mut request = self.session_plist();
        d_bool(&mut request, "updateSessionRequest", false);
        request
    }

    fn legacy_stream_plist(&self, stream: &Value) -> Value {
        let mut request = self.session_plist();
        d_insert(&mut request, "streams", Value::Array(vec![stream.clone()]));
        request
    }
}

fn stream_only_plist(stream: &Value) -> Value {
    let mut request = plist_dict();
    d_insert(&mut request, "streams", Value::Array(vec![stream.clone()]));
    request
}

/// Allocates `count` consecutive UDP ports, optionally within a range.
pub fn allocate_consecutive_udp_ports(count: usize, port_min: u16, port_max: u16) -> Result<Vec<UdpSocket>> {
    let bind = |port: u16| UdpSocket::bind(("0.0.0.0", port)).map_err(|e| Error::from_io("bind udp", e));
    if port_min == 0 && port_max == 0 {
        for _ in 0..20 {
            let first = bind(0)?;
            let base = first.local_addr().map_err(|e| Error::from_io("local addr", e))?.port();
            let mut conns = vec![first];
            let mut ok = true;
            for i in 1..count {
                match bind(base + i as u16) {
                    Ok(c) => conns.push(c),
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                return Ok(conns);
            }
        }
        return Err(Error::Protocol(format!(
            "could not allocate {count} consecutive UDP ports after 20 attempts"
        )));
    }
    if port_min == 0 || port_max == 0 || port_min > port_max {
        return Err(Error::Protocol(format!("invalid UDP port range {port_min}-{port_max}")));
    }
    let mut base = port_min;
    while base + count as u16 - 1 <= port_max {
        let first = match bind(base) {
            Ok(c) => c,
            Err(_) => {
                base += 1;
                continue;
            }
        };
        let actual = first.local_addr().map_err(|e| Error::from_io("local addr", e))?.port();
        let mut conns = vec![first];
        let mut ok = true;
        for i in 1..count {
            match bind(actual + i as u16) {
                Ok(c) => conns.push(c),
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            return Ok(conns);
        }
        base = actual + 1;
    }
    Err(Error::Protocol(format!(
        "no {count} consecutive free UDP ports in range {port_min}-{port_max}"
    )))
}

/// NTP timing responder for legacy receivers (probes the timing port during
/// SETUP).
fn ntp_timing_responder(socket: UdpSocket) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 128];
        let app_start = Instant::now();
        loop {
            let Ok((n, addr)) = socket.recv_from(&mut buf) else {
                return;
            };
            if n < 32 {
                continue;
            }
            let now = ntp_boot_timestamp(app_start);
            let mut reply = [0u8; 32];
            reply.copy_from_slice(&buf[..32]);
            reply[0] = 0x80;
            reply[1] = 0xd3;
            reply[8..16].copy_from_slice(&buf[24..32]);
            reply[16..24].copy_from_slice(&now.to_be_bytes());
            reply[24..32].copy_from_slice(&now.to_be_bytes());
            let _ = socket.send_to(&reply, addr);
        }
    });
}

fn ntp_boot_timestamp(app_start: Instant) -> u64 {
    let d = app_start.elapsed();
    let sec = d.as_secs() + SECONDS_FROM_1900_TO_1970;
    let frac = ((d.subsec_nanos() as u64) << 32) / 1_000_000_000;
    (sec << 32) | frac
}

/// 64-bit NTP fixed-point timestamp of the process start, anchored to the
/// 1900 epoch (used by the NTP timing responder and audio TimeAnnounce).
pub fn ntp_network_time() -> u64 {
    ntp_boot_timestamp(app_start())
}

/// An active screen mirroring session.
pub struct MirrorSession {
    pub client: Client,
    pub data_conn: TcpStream,
    pub session_uri: String,
    pub video_width: u32,
    pub video_height: u32,
    pub display_width: u32,
    pub display_height: u32,

    stream_cipher: Option<MirrorCipher>,
    chacha_cipher: Option<ChaCha20Poly1305>,
    chacha_nonce: u64,
    frame_seq: AtomicU32,
    last_frame_timestamp: u64,
    pub first_frame_sent: Arc<AtomicBool>,
    timestamp_bias: Duration,
    pub media_clock: Option<MediaClock>,

    /// Reserved timing socket; kept alive for the session's lifetime (the NTP
    /// responder holds its own clone, but the original must not be dropped
    /// while legacy receivers may still probe it).
    _timing_socket: Option<UdpSocket>,
    /// Local UDP socket for audio RTP data (kept for the session lifetime).
    pub audio_data_socket: Option<UdpSocket>,
    /// Local UDP socket for audio control/sync packets.
    pub audio_ctrl_socket: Option<UdpSocket>,
    /// Receiver's audio RTP data port.
    pub audio_data_port: u16,
    /// Receiver's audio control port.
    pub audio_ctrl_port: u16,
    /// Negotiated audio latency in 44.1 kHz samples.
    pub audio_latency_samples: u32,
}

/// Negotiates a mirroring session with the receiver.
pub fn setup_mirror_session(
    mut client: Client,
    no_encrypt: bool,
    _no_audio: bool,
    port_min: u16,
    port_max: u16,
) -> Result<MirrorSession> {
    let session_uuid = crate::uuid::generate_uuid();
    let client_device_id = uuid_to_mac(&client.session_id);
    let sender_name = crate::pairing::pairing_client_name();
    let modern_session = client.is_encrypted()
        && client
            .info
            .as_ref()
            .map_or(false, ReceiverInfo::uses_modern_pairing);
    let source_version = if modern_session {
        MODERN_AIRPLAY_SOURCE_VERSION
    } else {
        LEGACY_AIRPLAY_SOURCE_VERSION
    };
    let timing_protocol = if modern_session { TIMING_PROTOCOL_PTP } else { TIMING_PROTOCOL_NTP };
    let mut media_clock: Option<MediaClock> = if timing_protocol == TIMING_PROTOCOL_PTP {
        Some(MediaClock::default())
    } else {
        None
    };

    let mut setup = SetupRequest {
        device_id: client_device_id,
        session_uuid: session_uuid.clone(),
        source_version: source_version.to_string(),
        timing_protocol: timing_protocol.to_string(),
        timing_port: 0,
        timing_peer_id: String::new(),
        timing_peer_address: String::new(),
        name: sender_name,
    };
    if timing_protocol == TIMING_PROTOCOL_PTP {
        setup.timing_peer_id = crate::uuid::generate_uuid();
        setup.timing_peer_address = client
            .local_ip()
            .map(|ip| ip.to_string())
            .ok_or_else(|| Error::Protocol("determine PTP peer address".into()))?;
    }

    // Stream encryption keys.
    let (mut enc_key, mut enc_iv) = if !client.fp_key.is_empty() && !client.fp_iv.is_empty() {
        (client.fp_key.clone(), client.fp_iv.clone())
    } else {
        if client.stream_key.is_empty() {
            client.derive_stream_keys()?;
        }
        (client.stream_key.clone(), client.stream_iv.clone())
    };
    if no_encrypt {
        enc_key.clear();
        enc_iv.clear();
    }

    // Consecutive UDP ports: timing, audio control, audio data.
    let mut audio_ports = allocate_consecutive_udp_ports(3, port_min, port_max)?;
    let timing_socket = audio_ports.remove(0);
    let audio_ctrl_socket = audio_ports.remove(0);
    let audio_data_socket = audio_ports.remove(0);
    let audio_ctrl_port = audio_ctrl_socket
        .local_addr()
        .map_err(|e| Error::from_io("local addr", e))?
        .port();
    setup.timing_port = timing_socket
        .local_addr()
        .map_err(|e| Error::from_io("local addr", e))?
        .port();

    if timing_protocol == TIMING_PROTOCOL_NTP {
        let responder = timing_socket
            .try_clone()
            .map_err(|e| Error::from_io("clone udp", e))?;
        ntp_timing_responder(responder);
    }

    let session_latency = target_latency().max(receiver_playout_floor(&client));
    let audio_latency_samples = crate::latency::samples_for_44k1(session_latency);

    let audio_stream_connection_id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::Protocol(format!("clock: {e}")))?
        .as_nanos() as i64)
        & 0x7FFFFFFFFFFFFFFF;
    let audio_uri = format!("rtsp://{}:{}/{}", client.host, client.port, audio_stream_connection_id);

    let modern_control_setup = modern_session;

    let mut receiver_event_port = 0;
    let mut skip_record = false;

    let send_setup = |client: &mut Client,
                          uri: &str,
                          phase: &str,
                          request: &Value,
                          clock: &mut Option<MediaClock>|
     -> Result<(Value, std::collections::HashMap<String, String>, Instant)> {
        let mut body = Vec::new();
        request
            .to_writer_binary(&mut body)
            .map_err(|e| Error::Protocol(format!("marshal {phase} SETUP: {e}")))?;
        let (resp_body, headers) = client.rtsp_request(
            "SETUP",
            uri,
            "application/x-apple-binary-plist",
            &body,
            &std::collections::HashMap::new(),
        )?;
        let received_at = Instant::now();
        let response: Value = plist::from_bytes(&resp_body)
            .map_err(|e| Error::Protocol(format!("unmarshal {phase} SETUP response: {e}")))?;
        if let Some(clock) = clock {
            if timing_protocol == TIMING_PROTOCOL_PTP {
                clock.configure_from_setup(&response, &headers, received_at)?;
            }
        }
        Ok((response, headers, received_at))
    };

    let record_session = |client: &mut Client| -> Result<()> {
        let mut headers = std::collections::HashMap::new();
        headers.insert("Session".into(), session_uuid.clone());
        headers.insert("Range".into(), "npt=0-".into());
        headers.insert("RTP-Info".into(), "seq=0;rtptime=0".into());
        let (_, resp_headers) = client.rtsp_request("RECORD", &audio_uri, "", &[], &headers)?;
        if let Some(v) = resp_headers.get("audio-latency") {
            if let Ok(parsed) = v.parse::<u32>() {
                if parsed > 0 {
                    log::info!("receiver audio latency: {parsed} samples");
                }
            }
        }
        Ok(())
    };

    if modern_control_setup {
        // Phase 1: control-only SETUP.
        let control_plist = setup.control_plist();
        let (control_resp, _, _) = send_setup(&mut client, &audio_uri, "control", &control_plist, &mut media_clock)?;
        skip_record = control_resp
            .as_dictionary()
            .and_then(|m| m.get("skipRecord"))
            .map(|v| *v == Value::Boolean(true))
            .unwrap_or(false);
        receiver_event_port = plist_int(
            control_resp
                .as_dictionary()
                .and_then(|m| m.get("eventPort"))
                .unwrap_or(&plist_dict_int(0)),
        ) as u16;
        if receiver_event_port > 0 {
            connect_event_channel(&client, receiver_event_port)?;
        }
        if !skip_record {
            record_session(&mut client)?;
        }
    }

    // Audio stream descriptor (type 96).
    let mut audio_stream_desc = plist_dict();
    d_int(&mut audio_stream_desc, "type", 96);
    d_int(&mut audio_stream_desc, "streamConnectionID", audio_stream_connection_id);
    d_int(&mut audio_stream_desc, "ct", 2); // ALAC
    d_int(&mut audio_stream_desc, "spf", 352);
    d_int(&mut audio_stream_desc, "sr", 44100);
    d_int(&mut audio_stream_desc, "audioFormat", 0x40000); // ALAC audioFormat (matches upstream)
    d_string(&mut audio_stream_desc, "audioMode", "default");
    d_bool(&mut audio_stream_desc, "usingScreen", true);
    d_int(&mut audio_stream_desc, "latencyMin", 0);
    d_int(&mut audio_stream_desc, "latencyMax", audio_latency_samples as i64);
    d_int(&mut audio_stream_desc, "controlPort", audio_ctrl_port as i64);
    // This session always sends plaintext audio (no ChaCha path), so FEC is
    // used; advertise it like upstream does for legacy sessions.
    d_int(&mut audio_stream_desc, "redundantAudio", 2);

    let audio_setup_plist = if modern_control_setup {
        stream_only_plist(&audio_stream_desc)
    } else {
        let mut p = setup.legacy_stream_plist(&audio_stream_desc);
        if !client.fp_ekey.is_empty() && !client.fp_iv.is_empty() {
            d_int(&mut p, "et", 32);
            d_data(&mut p, "ekey", &client.fp_ekey);
            d_data(&mut p, "eiv", &client.fp_iv);
        }
        p
    };
    let (audio_resp, _, _) = send_setup(&mut client, &audio_uri, "audio stream", &audio_setup_plist, &mut media_clock)?;

    // Extract the receiver's audio RTP data/control ports (stream type 96).
    let mut audio_data_port = 0u16;
    let mut audio_ctrl_port_remote = 0u16;
    if let Some(streams) = audio_resp.as_dictionary().and_then(|m| m.get("streams")).and_then(Value::as_array) {
        for s in streams {
            if let Some(dict) = s.as_dictionary() {
                if plist_int(dict.get("type").unwrap_or(&plist_dict_int(0))) == 96 {
                    audio_data_port =
                        plist_int(dict.get("dataPort").unwrap_or(&plist_dict_int(0))) as u16;
                    audio_ctrl_port_remote =
                        plist_int(dict.get("controlPort").unwrap_or(&plist_dict_int(0))) as u16;
                    // Modern receivers nest the ports under streamConnections.
                    if let Some(conns) = dict.get("streamConnections").and_then(Value::as_dictionary) {
                        if let Some(rtp) = conns
                            .get("streamConnectionTypeRTP")
                            .and_then(Value::as_dictionary)
                        {
                            if let Some(p) = rtp.get("streamConnectionKeyPort") {
                                if plist_int(p) > 0 {
                                    audio_data_port = plist_int(p) as u16;
                                }
                            }
                        }
                        if let Some(rtcp) = conns
                            .get("streamConnectionTypeRTCP")
                            .and_then(Value::as_dictionary)
                        {
                            if let Some(p) = rtcp.get("streamConnectionKeyPort") {
                                if plist_int(p) > 0 {
                                    audio_ctrl_port_remote = plist_int(p) as u16;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    log::debug!("[SETUP] audio stream: dataPort={audio_data_port} controlPort={audio_ctrl_port_remote}");

    if !modern_control_setup {
        skip_record = audio_resp
            .as_dictionary()
            .and_then(|m| m.get("skipRecord"))
            .map(|v| *v == Value::Boolean(true))
            .unwrap_or(false);
        receiver_event_port = plist_int(
            audio_resp
                .as_dictionary()
                .and_then(|m| m.get("eventPort"))
                .unwrap_or(&plist_dict_int(0)),
        ) as u16;
        if receiver_event_port > 0 {
            connect_event_channel(&client, receiver_event_port)?;
        }
    }

    // Video stream (type 110).
    let video_stream_connection_id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::Protocol(format!("clock: {e}")))?
        .as_nanos() as i64)
        & 0x7FFFFFFFFFFFFFFF;
    let video_uri = format!("rtsp://{}:{}/{}", client.host, client.port, video_stream_connection_id);

    let mut video_stream_desc = plist_dict();
    d_int(&mut video_stream_desc, "type", 110);
    d_int(&mut video_stream_desc, "streamConnectionID", video_stream_connection_id);
    d_insert(
        &mut video_stream_desc,
        "timestampInfo",
        Value::Array(vec![
            dict_of("name", "SubSu"),
            dict_of("name", "BePxT"),
            dict_of("name", "AfPxT"),
            dict_of("name", "BefEn"),
            dict_of("name", "EmEnc"),
        ]),
    );
    if !enc_key.is_empty() {
        d_data(&mut video_stream_desc, "shk", &enc_key);
        d_data(&mut video_stream_desc, "shiv", &enc_iv);
    }

    let video_setup_plist = if modern_control_setup {
        stream_only_plist(&video_stream_desc)
    } else {
        let mut p = setup.legacy_stream_plist(&video_stream_desc);
        if !client.fp_ekey.is_empty() && !enc_key.is_empty() {
            d_data(&mut p, "ekey", &client.fp_ekey);
            d_data(&mut p, "eiv", &enc_iv);
        }
        p
    };
    let (video_resp, _, _) = send_setup(&mut client, &video_uri, "video stream", &video_setup_plist, &mut media_clock)?;

    if receiver_event_port == 0 {
        receiver_event_port = plist_int(
            video_resp
                .as_dictionary()
                .and_then(|m| m.get("eventPort"))
                .unwrap_or(&plist_dict_int(0)),
        ) as u16;
    }
    if receiver_event_port > 0 {
        connect_event_channel(&client, receiver_event_port)?;
    }

    // Video data port.
    let mut data_port = 0i64;
    if let Some(streams) = video_resp.as_dictionary().and_then(|m| m.get("streams")).and_then(Value::as_array) {
        for s in streams {
            if let Some(dict) = s.as_dictionary() {
                if plist_int(dict.get("type").unwrap_or(&plist_dict_int(0))) == 110 {
                    data_port = plist_int(dict.get("dataPort").unwrap_or(&plist_dict_int(0)));
                }
            }
        }
    }
    if data_port == 0 {
        return Err(Error::Protocol("no video data port in SETUP response".into()));
    }
    let data_conn = TcpStream::connect((client.host.as_str(), data_port as u16))
        .map_err(|e| Error::from_io("connect data port", e))?;
    data_conn
        .set_nodelay(true)
        .map_err(|e| Error::from_io("set nodelay", e))?;
    data_conn
        .set_write_timeout(Some(Duration::from_secs(2)))
        .ok();

    // Legacy receivers start the session only after both streams exist.
    if !modern_control_setup {
        if !skip_record {
            record_session(&mut client)?;
        }
    }

    // NOTE: no volume SET_PARAMETER here. 0 dB (full scale) would crank the
    // receiver's own volume to 100% on every connect; callers may send a
    // volume explicitly via `MirrorSession::set_volume_db`.

    // Stream cipher.
    let (stream_cipher, chacha_cipher) = if !enc_key.is_empty()
        && client.is_encrypted()
        && (client.pair_keys.as_ref().map_or(false, |k| !k.shared_secret.is_empty()) || !client.fp_aes_key.is_empty())
    {
        let ikm = if client.pair_keys.as_ref().map_or(false, |k| !k.shared_secret.is_empty()) {
            client.pair_keys.as_ref().unwrap().shared_secret.clone()
        } else {
            client.fp_aes_key.clone()
        };
        let chacha_key = derive_chacha_key(&ikm, video_stream_connection_id as u64)?;
        let aead = ChaCha20Poly1305::new(Key::from_slice(&chacha_key));
        (None, Some(aead))
    } else if !enc_key.is_empty() {
        let (cipher_key, cipher_iv) = derive_video_keys(&enc_key, video_stream_connection_id as u64);
        let mc = MirrorCipher::new(&cipher_key, &cipher_iv)?;
        (Some(mc), None)
    } else {
        (None, None)
    };

    let (display_width, display_height) = client.info.as_ref().map(ReceiverInfo::display_size).unwrap_or((0, 0));

    Ok(MirrorSession {
        client,
        data_conn,
        session_uri: audio_uri,
        video_width: 0,
        video_height: 0,
        display_width: display_width.max(0) as u32,
        display_height: display_height.max(0) as u32,
        stream_cipher,
        chacha_cipher,
        chacha_nonce: 0,
        frame_seq: AtomicU32::new(0),
        last_frame_timestamp: 0,
        first_frame_sent: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        timestamp_bias: session_latency,
        media_clock,
        _timing_socket: Some(timing_socket),
        audio_data_socket: Some(audio_data_socket),
        audio_ctrl_socket: Some(audio_ctrl_socket),
        audio_data_port,
        audio_ctrl_port: audio_ctrl_port_remote,
        audio_latency_samples,
    })
}

fn receiver_playout_floor(client: &Client) -> Duration {
    // Receivers without FairPlay SAP need a conservative playout lead.
    if client
        .info
        .as_ref()
        .map_or(false, ReceiverInfo::supports_fairplay_sap)
    {
        Duration::ZERO
    } else {
        Duration::from_nanos(CONSERVATIVE_PLAYOUT_LATENCY_NS as u64)
    }
}

/// Connects the sender side of the receiver's event channel and serves
/// receiver-to-sender commands on a background thread.
fn connect_event_channel(client: &Client, port: u16) -> Result<()> {
    let channel = crate::event_channel::EventChannel::connect(
        &client.host,
        port,
        client.is_encrypted(),
        client.pair_keys.as_ref().map(|k| k.shared_secret.as_slice()).unwrap_or(&[]),
    )?;
    serve_event_channel(channel);
    Ok(())
}

fn dict_of(key: &str, value: &str) -> Value {
    let mut d = plist_dict();
    d_string(&mut d, key, value);
    d
}

impl MirrorSession {
    /// Builds the RTP audio stream for this session, or `None` if the
    /// receiver provided no audio ports. The sockets are cloned so the
    /// session keeps its handles.
    pub fn make_audio_stream(&self) -> Result<Option<crate::audio::AudioStream>> {
        let (Some(data), Some(ctrl)) = (&self.audio_data_socket, &self.audio_ctrl_socket) else {
            return Ok(None);
        };
        if self.audio_data_port == 0 || self.audio_ctrl_port == 0 {
            return Ok(None);
        }
        let data_clone = data
            .try_clone()
            .map_err(|e| Error::from_io("clone audio data socket", e))?;
        let ctrl_clone = ctrl
            .try_clone()
            .map_err(|e| Error::from_io("clone audio ctrl socket", e))?;
        Ok(Some(crate::audio::AudioStream::new(
            &self.client.host,
            self.audio_data_port,
            self.audio_ctrl_port,
            data_clone,
            ctrl_clone,
            self.audio_latency_samples,
        )?))
    }

    /// Sets the receiver volume in dB (0 = full scale / 100% on most
    /// receivers; negative values attenuate). Sent twice like real senders.
    /// Callers should only use this when the user explicitly asked for a
    /// volume; the session no longer touches the receiver's volume by default.
    pub fn set_volume_db(&mut self, db: f64) -> Result<()> {
        let body = format!("volume: {db:.6}\r\n");
        let _ = self.client.rtsp_request(
            "SET_PARAMETER",
            &self.session_uri,
            "text/parameters",
            body.as_bytes(),
            &std::collections::HashMap::new(),
        );
        let _ = self.client.rtsp_request(
            "SET_PARAMETER",
            &self.session_uri,
            "text/parameters",
            body.as_bytes(),
            &std::collections::HashMap::new(),
        );
        Ok(())
    }

    /// One atomic timestamp/timeline pair for a VCL header.
    pub fn frame_time_now(&mut self) -> (u64, u64) {
        let bias = if self.timestamp_bias > Duration::ZERO {
            self.timestamp_bias
        } else {
            Duration::from_millis(5)
        };
        let (ts, timeline) = if let Some(clock) = &self.media_clock {
            if let Some((ts, timeline)) = clock.now(bias) {
                (ts, timeline)
            } else {
                (ntp_time_now(), 0)
            }
        } else {
            (ntp_time_now(), 0)
        };
        (self.monotonic_frame_time(ts), timeline)
    }

    fn monotonic_frame_time(&mut self, mut timestamp: u64) -> u64 {
        if timestamp <= self.last_frame_timestamp {
            timestamp = self.last_frame_timestamp + 1;
        }
        self.last_frame_timestamp = timestamp;
        timestamp
    }

    /// Sends an unencrypted SPS+PPS avcC codec frame.
    pub fn send_codec_frame(&mut self, payload: &[u8], ntp_timestamp: u64) -> Result<()> {
        self.frame_seq.fetch_add(1, Ordering::Relaxed);
        let mut header = [0u8; 128];
        header[..4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        header[4] = 0x01;
        header[5] = 0x00;
        header[6] = 0x16;
        header[7] = 0x01;
        header[8..16].copy_from_slice(&ntp_timestamp.to_le_bytes());

        let (disp_w, disp_h) = if self.display_width > 0 && self.display_height > 0 {
            (self.display_width, self.display_height)
        } else {
            (self.video_width, self.video_height)
        };
        put_float32_le(&mut header[16..20], self.video_width as f32);
        put_float32_le(&mut header[20..24], self.video_height as f32);
        put_float32_le(&mut header[40..44], self.video_width as f32);
        put_float32_le(&mut header[44..48], self.video_height as f32);
        put_float32_le(&mut header[56..60], disp_w as f32);
        put_float32_le(&mut header[60..64], disp_h as f32);

        self.data_conn
            .write_all(&header)
            .map_err(|e| Error::from_io("write codec header", e))?;
        self.data_conn
            .write_all(payload)
            .map_err(|e| Error::from_io("write codec payload", e))?;
        self.first_frame_sent.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Sends one encrypted VCL frame with the 128-byte mirroring header.
    pub fn send_frame(
        &mut self,
        au_data: &[u8],
        is_keyframe: bool,
        network_timestamp: u64,
        timeline_id: u64,
    ) -> Result<()> {
        self.frame_seq.fetch_add(1, Ordering::Relaxed);

        let payload_size = if self.chacha_cipher.is_some() {
            au_data.len() + 16
        } else {
            au_data.len()
        };

        let mut header = [0u8; 128];
        header[..4].copy_from_slice(&(payload_size as u32).to_le_bytes());
        header[4] = 0x00;
        header[5] = if is_keyframe { 0x10 } else { 0x00 };
        header[8..16].copy_from_slice(&network_timestamp.to_le_bytes());
        header[40..48].copy_from_slice(&timeline_id.to_le_bytes());

        let frame_payload: Vec<u8> = if let Some(cipher) = &self.chacha_cipher {
            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&self.chacha_nonce.to_le_bytes());
            self.chacha_nonce += 1;
            // The receiver authenticates the 128-byte header as AAD.
            cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    chacha20poly1305::aead::Payload {
                        msg: au_data,
                        aad: &header,
                    },
                )
                .map_err(|e| Error::Crypto(format!("chacha20 seal frame: {e}")))?
        } else if let Some(cipher) = &mut self.stream_cipher {
            cipher.encrypt_frame(au_data)
        } else {
            au_data.to_vec()
        };

        self.data_conn
            .write_all(&header)
            .map_err(|e| Error::from_io("write frame header", e))?;
        self.data_conn
            .write_all(&frame_payload)
            .map_err(|e| Error::from_io("write frame payload", e))?;
        Ok(())
    }

    /// Sends a periodic heartbeat frame on the data channel.
    pub fn send_heartbeat(&mut self) -> Result<()> {
        let mut header = [0u8; 128];
        header[4] = 0x02;
        header[6] = 0x1e;
        self.data_conn
            .write_all(&header)
            .map_err(|e| Error::from_io("write heartbeat", e))
    }

    /// Sends POST /feedback (used by the feedback loop and tests).
    pub fn send_feedback(&mut self) -> Result<()> {
        let (_, headers) = self
            .client
            .rtsp_request("POST", "/feedback", "", &[], &std::collections::HashMap::new())?;
        if let Some(clock) = &mut self.media_clock {
            let _ = clock.reanchor(&headers, Instant::now());
        }
        Ok(())
    }

    /// Teardown: sends RTSP TEARDOWN and closes connections.
    pub fn teardown(&mut self) -> Result<()> {
        let _ = self.client.rtsp_request("TEARDOWN", &self.session_uri, "", &[], &std::collections::HashMap::new());
        let _ = self.data_conn.shutdown(std::net::Shutdown::Both);
        Ok(())
    }
}

fn put_float32_le(dst: &mut [u8], value: f32) {
    dst[..4].copy_from_slice(&value.to_le_bytes());
}

fn ntp_time_now() -> u64 {
    // Boot-relative NTP time with a small forward bias (playout lead).
    compact_timestamp(app_start().elapsed() + Duration::from_millis(5))
}

impl Drop for MirrorSession {
    fn drop(&mut self) {
        let _ = self.data_conn.shutdown(std::net::Shutdown::Both);
    }
}
