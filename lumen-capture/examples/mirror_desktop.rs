//! Full mirror pipeline: DXGI desktop capture → OpenH264 → AirPlay mirror
//! session → receiver (Android TV / Apple TV / lumen-test-receiver).
//!
//! This is the Rust equivalent of the Go `lumen.exe -target <host>
//! -hwaccel openh264` command.
//!
//! Usage:
//!   cargo run -p lumen-capture --example mirror_desktop -- <host> [port] [pin] [options]
//!
//!   <host>   receiver IP or hostname (e.g. 192.168.1.107)
//!   [port]   AirPlay port (default 7000)
//!   [pin]    4-digit PIN shown on the receiver (optional if credentials
//!            are already saved; prompts interactively otherwise)
//!
//!   options:
//!     --pair          force re-pairing even if credentials exist
//!     --bitrate N     video bitrate in kbps (default 8000)
//!     --creds PATH    credential store path (default ~/.config/lumen/credentials.json)
//!     --no-encrypt    disable stream encryption (debugging only)
//!
//!   Ctrl+C stops the stream cleanly (teardown).

use lumen_airplay::client::Client;
use lumen_airplay::credentials::CredentialStore;
use lumen_airplay::fairplay::fairplay_setup;
use lumen_airplay::h264::{avcc_wrap, build_avcc_config, is_first_slice, nal_type, sps_dimensions, strip_start_code, H264Parser};
use lumen_airplay::mirror::{setup_mirror_session, MirrorSession};
use lumen_airplay::pairing::PairingSession;
use lumen_capture::dxgi::DesktopDuplicator;
use lumen_encode::mf::MediaFoundationEncoder;
use lumen_encode::openh264::{OpenH264Config, OpenH264Encoder};
use lumen_encode::x264::X264Encoder;
use lumen_encode::yuv::{bgra_to_i420, i420_to_nv12};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "usage: mirror_desktop <host> [port] [pin] [--pair] [--bitrate N] [--creds PATH] [--no-encrypt]"
        );
        std::process::exit(2);
    }
    let host = args[1].clone();
    let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(7000);
    let mut pin: Option<String> = None;
    let mut pin_file: Option<String> = None;
    let mut force_pair = false;
    let mut bitrate_kbps: u32 = 8000;
    let mut latency_ms: u64 = 100;
    let mut creds_path = CredentialStore::default_path();
    let mut no_encrypt = false;
    let mut no_audio = false;
    let mut volume_db: Option<f64> = None;
    let mut seconds: u64 = 0; // 0 = run until Ctrl+C
    let mut fps: u32 = 30;
    let mut threads: u16 = 8;
    let mut encoder_kind: String = "openh264".into();
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--pair" => force_pair = true,
            "--bitrate" => {
                i += 1;
                bitrate_kbps = args[i].parse()?;
            }
            "--latency-ms" => {
                i += 1;
                latency_ms = args[i].parse()?;
            }
            "--creds" => {
                i += 1;
                creds_path = args[i].clone().into();
            }
            "--no-encrypt" => no_encrypt = true,
            "--no-audio" => no_audio = true,
            "--volume-db" => {
                i += 1;
                volume_db = Some(args[i].parse()?);
            }
            "--seconds" => {
                i += 1;
                seconds = args[i].parse()?;
            }
            "--fps" => {
                i += 1;
                fps = args[i].parse()?;
            }
            "--threads" => {
                i += 1;
                threads = args[i].parse()?;
            }
            "--encoder" => {
                i += 1;
                encoder_kind = args[i].clone();
            }
            "--pin-file" => {
                i += 1;
                pin_file = Some(args[i].clone());
            }
            s if s.starts_with("--") => {
                eprintln!("unknown option: {s}");
                std::process::exit(2);
            }
            s if pin.is_none() => pin = Some(s.to_string()),
            _ => {
                eprintln!("unexpected argument: {}", args[i]);
                std::process::exit(2);
            }
        }
        i += 1;
    }
    lumen_airplay::latency::set_target_latency(std::time::Duration::from_millis(latency_ms));

    // 1. Control connection + receiver info.
    let mut client = Client::connect(&host, port)?;
    let info = client.get_info()?;
    println!("receiver: {} ({})", info.name, info.model);
    println!(
        "  features: 0x{:x} statusFlags: 0x{:x} fairplay_sap: {}",
        info.features,
        info.status_flags,
        info.supports_fairplay_sap()
    );

    // 2. Pairing: saved credentials when available, otherwise PIN. Some
    // third-party receivers (this TV) drop pairing records between sessions,
    // so a rejected reconnect falls back to PIN pairing automatically.
    let mut store = CredentialStore::new(&creds_path)?;
    let saved = store.lookup(&info.device_id).cloned();
    let mut pairing = PairingSession::with_info(client.pairing_id.clone(), info.clone());
    let mut pin_pair = force_pair;

    if !pin_pair {
        match saved.filter(|c| c.has_pairing_credentials()) {
            Some(c) => {
                println!("trying saved credentials for {}…", info.device_id);
                pairing.pairing_id = c.pairing_id.clone();
                pairing.keys.ed25519_seed = c.ed25519_seed.clone();
                pairing.keys.ed25519_public = c.ed25519_public.clone();
                match pairing.reconnect(&mut client) {
                    Ok(()) => println!("reconnect OK (encrypted={})", pairing.encrypted),
                    Err(e) => {
                        println!("saved credentials rejected ({e}); falling back to PIN pairing");
                        pairing = PairingSession::with_info(client.pairing_id.clone(), info.clone());
                        pin_pair = true;
                    }
                }
            }
            None => pin_pair = true,
        }
    }

    if pin_pair {
        // Trigger the receiver's on-screen PIN display FIRST, then ask the
        // user for the PIN (the TV shows the PIN while we wait for input).
        match pairing.start_pin_display(&mut client) {
            Ok(()) => println!("pair-pin-start: OK — check the TV for the PIN"),
            Err(e) => println!("pair-pin-start: {e} (continuing)"),
        }
        if pin.is_none() {
            // Optional: read the PIN from a file that an external process
            // (e.g. adb screenshot + OCR) writes after pair-pin-start. This
            // avoids the stdin dependency for automated pairing.
            if let Some(path) = &pin_file {
                println!("waiting for PIN in {path}…");
                for _ in 0..600 {
                    if let Ok(s) = std::fs::read_to_string(path) {
                        let t = s.trim().to_string();
                        if !t.is_empty() {
                            pin = Some(t);
                            break;
                        }
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
        if pin.is_none() {
            print!("Enter the PIN shown on the receiver: ");
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            pin = Some(line.trim().to_string());
        }
        let pin = pin.expect("pin");
        pairing.pair_with_pin(&mut client, &pin)?;
        println!("pairing OK (encrypted={})", pairing.encrypted);
        store.save(
            &info.device_id,
            &pairing.pairing_id,
            &pairing.keys.ed25519_public,
            &pairing.keys.ed25519_seed,
        )?;
        println!("credentials saved for {} -> {}", info.device_id, creds_path.display());
    }
    client.pair_keys = Some(pairing.keys.clone());
    if pairing.encrypted {
        client.enable_hap_encryption(pairing.enc_write_key.clone(), pairing.enc_read_key.clone());
    }

    // 3. FairPlay SAP on modern receivers.
    if info.supports_fairplay_sap() {
        let fp = fairplay_setup(&mut client, &info, &pairing.keys.shared_secret, true)?;
        client.fp_key = fp.stream_key.to_vec();
        client.fp_iv = fp.stream_iv.to_vec();
        client.fp_ekey = fp.ekey.to_vec();
        client.fp_m3 = fp.m3.to_vec();
        client.fp_aes_key = fp.raw_key.to_vec();
        println!("FairPlay SAP OK (ekey {} bytes)", fp.ekey.len());
    } else {
        println!("receiver does not advertise FairPlay SAP");
    }

    // 4. Mirror session (video only; audio skipped).
    let mut session = setup_mirror_session(client, no_encrypt, true, 0, 0)?;
    println!(
        "mirror session up: data port connected, session URI {}",
        session.session_uri
    );
    session.send_feedback()?;
    if let Some(db) = volume_db {
        session.set_volume_db(db)?;
        println!("receiver volume set to {db} dB");
    }

    // 5. Capture + encode + stream until Ctrl+C.
    let mut dup = DesktopDuplicator::new(0)?;
    println!("desktop: {}x{} (duplication ready)", dup.width, dup.height);

    let use_nvenc = encoder_kind == "nvenc";
    let use_mf = encoder_kind == "mf";
    let use_x264 = encoder_kind == "x264";
    let mut nvenc: Option<lumen_encode::H264Encoder> = None;
    let mut openh264: Option<OpenH264Encoder> = None;
    let mut mf: Option<MediaFoundationEncoder> = None;
    let mut x264: Option<X264Encoder> = None;

    if use_nvenc {
        let nv = std::sync::Arc::new(lumen_encode::NvEncoder::load()?);
        let (major, minor) = nv.major_minor();
        println!("NVENC API {major}.{minor} (preset defaults — driver 591.86 config bug)");
        let enc = lumen_encode::H264Encoder::new(
            nv,
            dup.device_raw(),
            dup.width,
            dup.height,
            fps,
            bitrate_kbps * 1000,
            lumen_encode::NV_ENC_BUFFER_FORMAT_ARGB,
        )?;
        println!("NVENC ready (per-frame register; note: cursor overlay not supported on this path)");
        nvenc = Some(enc);
    } else if use_mf {
        mf = Some(MediaFoundationEncoder::new(
            dup.width,
            dup.height,
            fps,
            bitrate_kbps * 1000,
        )?);
        println!("MediaFoundation H.264 MFT ready ({bitrate_kbps} kbps, {fps} fps)");
    } else if use_x264 {
        x264 = Some(X264Encoder::new(dup.width, dup.height, fps, bitrate_kbps * 1000)?);
        println!("x264 encoder ready ({bitrate_kbps} kbps, {fps} fps, ultrafast/zerolatency)");
    } else {
        openh264 = Some(OpenH264Encoder::new(OpenH264Config {
            bitrate_bps: bitrate_kbps * 1000,
            fps: fps as f32,
            threads, // explicit threads beat auto on complex content (32 -> 64 fps)
            skip_frames: true, // let the rate controller bound frame sizes
            ..Default::default()
        })?);
        println!("OpenH264 encoder ready ({bitrate_kbps} kbps, {fps} fps, {threads} threads)");
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    ctrlc::set_handler(move || {
        println!("\nCtrl+C — tearing down…");
        stop2.store(true, Ordering::Relaxed);
    })?;

    // 6. Audio: WASAPI loopback → ALAC verbatim → RTP, started after the first
    // video frame (the receiver ties audio to an active video stream).
    let first_frame = session.first_frame_sent.clone();
    let audio_stream = if !no_audio {
        println!(
            "audio ports from receiver: data={} ctrl={}",
            session.audio_data_port, session.audio_ctrl_port
        );
        match session.make_audio_stream()? {
            Some(as_) => Some(as_),
            None => {
                println!("receiver provided no audio ports — continuing without audio");
                None
            }
        }
    } else {
        None
    };
    let audio_stop = stop.clone();
    if let Some(as_) = audio_stream {
        let audio_thread = std::thread::Builder::new()
            .name("mirror-audio".into())
            .spawn(move || {
                let result = (|| -> Result<(), Box<dyn std::error::Error>> {
                    let capture = lumen_audio::start()?;
                    println!("WASAPI loopback audio capture started");
                    run_audio(as_, capture, first_frame, audio_stop)
                })();
                if let Err(e) = result {
                    println!("audio error: {e}");
                }
            })?;
        std::mem::forget(audio_thread); // detached; exits on Ctrl+C
    }

    let mut streamer = H264Streamer::new(&mut session);
    let mut last_heartbeat = Instant::now();
    let mut last_feedback = Instant::now();
    let mut last_frame_at = Instant::now();
    let mut idle_flushed = false;
    let start = Instant::now();

    // Frame pacing: encode at most `fps` frames/second. Bursty desktop updates
    // (e.g. a video playing) are throttled so encode work stays bounded.
    let frame_period = Duration::from_micros(1_000_000 / fps.max(1) as u64);
    let mut last_send = Instant::now() - frame_period;
    let mut stats = StageStats::default();

    while !stop.load(Ordering::Relaxed) && (seconds == 0 || start.elapsed().as_secs() < seconds) {
        let wait_t0 = Instant::now();
        let frame_opt = if use_nvenc {
            dup.acquire_frame(20)?.map(Acquired::Tex)
        } else {
            dup.acquire_frame_cpu(20)?.map(Acquired::Cpu)
        };
        match frame_opt {
            Some(acq) => {
                let wait_t1 = Instant::now();
                stats.wait_ms += wait_t1.duration_since(wait_t0).as_secs_f64() * 1000.0;
                stats.captured += 1;
                if wait_t1.saturating_duration_since(last_send) >= frame_period {
                    let enc_t0 = Instant::now();
                    let bytes = match acq {
                        Acquired::Tex(texture) => {
                            let enc = nvenc.as_mut().expect("nvenc");
                            let b = enc.encode_external_texture(
                                windows::core::Interface::as_raw(&texture)
                                    as *mut std::ffi::c_void,
                                streamer.frames_sent == 0,
                            )?;
                            dup.release_frame();
                            b
                        }
                        Acquired::Cpu(frame) => {
                            if let Some(enc) = &mut mf {
                                let (yy, uu, vv) = bgra_to_i420(
                                    &frame.bgra,
                                    frame.width as usize,
                                    frame.height as usize,
                                    frame.width as usize * 4,
                                );
                                let nv12 = i420_to_nv12(
                                    &yy, &uu, &vv, frame.width as usize, frame.height as usize,
                                );
                                enc.encode_nv12(&nv12, streamer.frames_sent == 0)?
                            } else if let Some(enc) = &mut x264 {
                                enc.encode_bgra(
                                    &frame.bgra,
                                    frame.width,
                                    frame.height,
                                    frame.width * 4,
                                    streamer.frames_sent == 0,
                                )?
                            } else {
                                let enc = openh264.as_mut().expect("openh264");
                                enc.encode_bgra(
                                    &frame.bgra,
                                    frame.width as usize,
                                    frame.height as usize,
                                    frame.width as usize * 4,
                                )?
                            }
                        }
                    };
                    let enc_t1 = Instant::now();
                    let send_t0 = Instant::now();
                    if !bytes.is_empty() {
                        streamer.push(&bytes)?;
                    }
                    let send_t1 = Instant::now();
                    stats.encode_ms += enc_t1.duration_since(enc_t0).as_secs_f64() * 1000.0;
                    stats.send_ms += send_t1.duration_since(send_t0).as_secs_f64() * 1000.0;
                    stats.encoded += 1;
                    last_send = wait_t1;
                    last_frame_at = wait_t1;
                    idle_flushed = false;
                } else {
                    stats.skipped += 1;
                    if let Acquired::Tex(_) = acq {
                        dup.release_frame();
                    }
                }
            }
            None => {
                // No new desktop frame. After a short idle, deliver the last
                // buffered frame so the TV isn't stuck one frame behind.
                if last_frame_at.elapsed() >= Duration::from_millis(50) && !idle_flushed {
                    streamer.flush_idle()?;
                    idle_flushed = true;
                }
                // Static desktop: keep the session alive with heartbeats.
                if last_heartbeat.elapsed() >= Duration::from_secs(1) {
                    streamer.heartbeat()?;
                    last_heartbeat = Instant::now();
                }
            }
        }
        if last_feedback.elapsed() >= Duration::from_secs(5) {
            streamer.feedback()?;
            last_feedback = Instant::now();
        }
        if streamer.frames_sent % 30 == 0 && streamer.frames_sent > 0 && streamer.last_report != streamer.frames_sent {
            let el = start.elapsed().as_secs_f64();
            println!(
                "streamed {} frames, {} bytes ({:.1} fps avg) | enc={:.1}ms send={:.1}ms wait={:.1}ms cap={} skip={}",
                streamer.frames_sent,
                streamer.bytes_sent,
                streamer.frames_sent as f64 / el.max(0.001),
                stats.encode_ms / stats.encoded.max(1) as f64,
                stats.send_ms / stats.encoded.max(1) as f64,
                stats.wait_ms / stats.captured.max(1) as f64,
                stats.encoded,
                stats.skipped
            );
            streamer.last_report = streamer.frames_sent;
        }
    }

    streamer.flush_idle()?;
    let el = start.elapsed();
    println!(
        "done: {} frames, {} bytes in {:.1}s ({:.1} fps avg)",
        streamer.frames_sent,
        streamer.bytes_sent,
        el.as_secs_f64(),
        streamer.frames_sent as f64 / el.as_secs_f64().max(0.001)
    );
    session.teardown()?;
    println!("teardown OK");
    Ok(())
}

/// Runs the audio stream: waits for the first video frame, then encodes
/// WASAPI loopback PCM as ALAC verbatim frames and sends them over RTP with
/// periodic NTP TimeAnnounce sync packets (port of upstream `StreamAudio`).
fn run_audio(
    mut audio: lumen_airplay::audio::AudioStream,
    capture: lumen_audio::LoopbackCapture,
    first_frame: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    // The receiver processes audio only in the context of an active video
    // stream; wait for the first video frame before starting.
    while !first_frame.load(Ordering::Relaxed) && !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(10));
    }
    if stop.load(Ordering::Relaxed) {
        return Ok(());
    }
    // Capture started before video did, so the channel holds a backlog of
    // audio accumulated while we waited for the first video frame. Drop it so
    // we begin streaming from the freshest sample and audio lines up with
    // video (port of upstream DrainStale).
    let mut drained = 0u64;
    while let Some(_) = capture.try_recv_frame() {
        drained += 1;
    }
    if drained > 0 {
        println!("audio: drained {drained} stale frames (~{}ms)", drained * 8);
    }
    let _ = audio.set_ctrl_nonblocking();

    // Apple starts each audio timeline at a random 32-bit RTP epoch.
    let mut rtp_time: u32 = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos() as u32)
        | 0x8000_0000;
    let mut seq: u16 = 1; // first frame = seq 1
    audio.rtp_time = rtp_time;

    // Establish the clock mapping before sending media (reset bit set).
    let net_time = lumen_airplay::mirror::ntp_network_time();
    audio.send_sync_packet(net_time, true)?;
    println!("audio started (rtp epoch {rtp_time})");

    // Encrypted (ChaCha) sessions send each frame once (no FEC); plaintext
    // sessions use upstream's burst-8 + interleaved retransmit.
    let use_fec = !audio.is_encrypted();
    const DEPTH: usize = 8;
    let mut retransmit: Vec<Option<(Vec<u8>, u32, u16)>> = vec![None; DEPTH];
    let mut idx = 0usize;
    let mut burst_done = false;
    let mut last_sync = Instant::now();
    let mut frames_sent: u64 = 0;

    while !stop.load(Ordering::Relaxed) {
        if last_sync.elapsed() >= Duration::from_secs(1) {
            let net = lumen_airplay::mirror::ntp_network_time();
            audio.send_sync_packet(net, false)?;
            last_sync = Instant::now();
        }
        audio.drain_control();

        let pcm = match capture.recv_frame() {
            Ok(p) => p,
            Err(_) => break, // capture thread gone
        };
        let payload = lumen_airplay::audio::encode_alac_verbatim(&pcm, lumen_airplay::audio::SPF as usize, 2);

        if use_fec {
            if !burst_done {
                audio.send_frame(&payload, rtp_time, seq)?;
                retransmit[idx] = Some((payload, rtp_time, seq));
                idx += 1;
                if idx >= DEPTH {
                    burst_done = true;
                    idx = 0;
                }
            } else {
                if let Some((old, old_rtp, old_seq)) = retransmit[idx].take() {
                    audio.send_frame(&old, old_rtp, old_seq)?;
                    retransmit[idx] = Some((old, old_rtp, old_seq));
                }
                audio.send_frame(&payload, rtp_time, seq)?;
                retransmit[idx] = Some((payload, rtp_time, seq));
                idx = (idx + 1) % DEPTH;
            }
        } else {
            audio.send_frame(&payload, rtp_time, seq)?;
        }

        seq = seq.wrapping_add(1);
        rtp_time = rtp_time.wrapping_add(lumen_airplay::audio::SPF);
        frames_sent += 1;
        if frames_sent % 100 == 0 {
            println!("audio: {frames_sent} frames sent");
        }
    }
    println!("audio stopped ({frames_sent} frames)");
    Ok(())
}

/// Per-stage timing accumulators for diagnosing frame-rate instability.
#[derive(Default)]
struct StageStats {
    captured: u64,
    encoded: u64,
    skipped: u64,
    wait_ms: f64,
    encode_ms: f64,
    send_ms: f64,
}

/// A captured frame from either the GPU-texture path (NVENC) or the CPU
/// readback path (OpenH264).
enum Acquired {
    Tex(windows::Win32::Graphics::Direct3D11::ID3D11Texture2D),
    Cpu(lumen_capture::dxgi::CpuFrame),
}

/// Incremental Annex-B → AVCC mirror streamer, ported from `mirror_pin.rs`.
struct H264Streamer<'a> {
    session: &'a mut MirrorSession,
    parser: H264Parser,
    latest_sps: Option<Vec<u8>>,
    latest_pps: Option<Vec<u8>>,
    vcl_buf: Vec<u8>,
    pending_keyframe: bool,
    codec_sent: bool,
    frames_sent: u64,
    bytes_sent: u64,
    last_report: u64,
}

impl<'a> H264Streamer<'a> {
    fn new(session: &'a mut MirrorSession) -> Self {
        H264Streamer {
            session,
            parser: H264Parser::new(),
            latest_sps: None,
            latest_pps: None,
            vcl_buf: Vec::new(),
            pending_keyframe: false,
            codec_sent: false,
            frames_sent: 0,
            bytes_sent: 0,
            last_report: 0,
        }
    }

    /// Periodic liveness frame on the data channel.
    fn heartbeat(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.session.send_heartbeat()?;
        Ok(())
    }

    /// Periodic POST /feedback (re-anchors the media clock).
    fn feedback(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.session.send_feedback()?;
        Ok(())
    }

    fn push(&mut self, annex_b: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let nals = self.parser.push(annex_b);
        self.process_nals(nals);
        Ok(())
    }

    /// Delivers any frame still buffered in the parser or VCL accumulator.
    /// Called when the desktop goes idle, so the last captured frame reaches
    /// the TV without waiting for the next desktop change.
    fn flush_idle(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let tail = self.parser.flush();
        self.process_nals(tail);
        self.flush_vcl()
    }

    fn process_nals(&mut self, nals: Vec<Vec<u8>>) {
        for nal in nals {
            let nt = nal_type(&nal);
            let raw = strip_start_code(&nal).to_vec();
            match nt {
                9 => {
                    let _ = self.flush_vcl(); // AUD
                }
                7 => {
                    let _ = self.flush_vcl();
                    self.latest_sps = Some(raw);
                }
                8 => self.latest_pps = Some(raw),
                6 => {} // SEI
                5 => {
                    if !self.vcl_buf.is_empty() && !self.pending_keyframe {
                        let _ = self.flush_vcl();
                    }
                    self.pending_keyframe = true;
                    self.vcl_buf.extend_from_slice(&avcc_wrap(&raw));
                }
                1..=4 => {
                    if !self.vcl_buf.is_empty() && self.pending_keyframe {
                        let _ = self.flush_vcl();
                    }
                    if !self.vcl_buf.is_empty() && !self.pending_keyframe && is_first_slice(&raw) {
                        let _ = self.flush_vcl();
                    }
                    self.vcl_buf.extend_from_slice(&avcc_wrap(&raw));
                }
                _ => {}
            }
        }
    }

    fn flush_vcl(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.vcl_buf.is_empty() {
            return Ok(());
        }
        let (ts, timeline) = self.session.frame_time_now();
        if self.pending_keyframe && !self.codec_sent {
            if let (Some(sps), Some(pps)) = (self.latest_sps.as_ref(), self.latest_pps.as_ref()) {
                if let Some((w, h)) = sps_dimensions(sps) {
                    self.session.video_width = w;
                    self.session.video_height = h;
                }
                let avcc = build_avcc_config(sps, pps);
                self.session.send_codec_frame(&avcc, ts)?;
                self.bytes_sent += avcc.len() as u64;
                self.codec_sent = true;
            }
        }
        let frame = std::mem::take(&mut self.vcl_buf);
        self.session.send_frame(&frame, self.pending_keyframe, ts, timeline)?;
        self.bytes_sent += frame.len() as u64;
        self.frames_sent += 1;
        self.pending_keyframe = false;
        self.codec_sent = false;
        Ok(())
    }
}
