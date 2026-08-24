//! Full mirror pipeline: DXGI desktop capture → OpenH264 → AirPlay mirror
//! session → receiver (Android TV / Apple TV / doubletake-test-receiver).
//!
//! This is the Rust equivalent of the Go `doubletake.exe -target <host>
//! -hwaccel openh264` command.
//!
//! Usage:
//!   cargo run -p dt-capture --example mirror_desktop -- <host> [port] [pin] [options]
//!
//!   <host>   receiver IP or hostname (e.g. 192.168.1.107)
//!   [port]   AirPlay port (default 7000)
//!   [pin]    4-digit PIN shown on the receiver (optional if credentials
//!            are already saved; prompts interactively otherwise)
//!
//!   options:
//!     --pair          force re-pairing even if credentials exist
//!     --bitrate N     video bitrate in kbps (default 8000)
//!     --creds PATH    credential store path (default ~/.config/doubletake/credentials.json)
//!     --no-encrypt    disable stream encryption (debugging only)
//!
//!   Ctrl+C stops the stream cleanly (teardown).

use dt_airplay::client::Client;
use dt_airplay::credentials::CredentialStore;
use dt_airplay::fairplay::fairplay_setup;
use dt_airplay::h264::{avcc_wrap, build_avcc_config, is_first_slice, nal_type, sps_dimensions, strip_start_code, H264Parser};
use dt_airplay::mirror::{setup_mirror_session, MirrorSession};
use dt_airplay::pairing::PairingSession;
use dt_capture::dxgi::DesktopDuplicator;
use dt_encode::openh264::{OpenH264Config, OpenH264Encoder};
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
    let mut force_pair = false;
    let mut bitrate_kbps: u32 = 8000;
    let mut latency_ms: u64 = 100;
    let mut creds_path = CredentialStore::default_path();
    let mut no_encrypt = false;
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
    dt_airplay::latency::set_target_latency(std::time::Duration::from_millis(latency_ms));

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

    // 5. Capture + encode + stream until Ctrl+C.
    let mut dup = DesktopDuplicator::new(0)?;
    println!("desktop: {}x{} (duplication ready)", dup.width, dup.height);
    let mut encoder = OpenH264Encoder::new(OpenH264Config {
        bitrate_bps: bitrate_kbps * 1000,
        fps: 30.0,
        ..Default::default()
    })?;
    println!("OpenH264 encoder ready ({bitrate_kbps} kbps, 30 fps)");

    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    ctrlc::set_handler(move || {
        println!("\nCtrl+C — tearing down…");
        stop2.store(true, Ordering::Relaxed);
    })?;

    let mut streamer = H264Streamer::new(&mut session);
    let mut last_heartbeat = Instant::now();
    let mut last_feedback = Instant::now();
    let mut last_frame_at = Instant::now();
    let mut idle_flushed = false;
    let start = Instant::now();

    while !stop.load(Ordering::Relaxed) {
        match dup.acquire_frame_cpu(1000)? {
            Some(frame) => {
                let bytes = encoder.encode_bgra(
                    &frame.bgra,
                    frame.width as usize,
                    frame.height as usize,
                    frame.width as usize * 4,
                )?;
                if !bytes.is_empty() {
                    streamer.push(&bytes)?;
                }
                last_frame_at = Instant::now();
                idle_flushed = false;
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
                "streamed {} frames, {} bytes ({:.1} fps avg)",
                streamer.frames_sent,
                streamer.bytes_sent,
                streamer.frames_sent as f64 / el.max(0.001)
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
