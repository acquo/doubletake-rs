//! Interop test: full mirror session against the Go `doubletake-test-receiver`.
//!
//! Usage:
//!   cargo run --example mirror_pin -- <host> <port> <pin> <h264-file> [credentials.json]
//!
//! Run the receiver with:
//!   doubletake-test-receiver.exe -auth pin -code 1234 -profile modern \
//!       -listen 127.0.0.1:7100 -debug -stats-interval 2s

use dt_airplay::client::Client;
use dt_airplay::fairplay::fairplay_setup;
use dt_airplay::h264::{build_avcc_config, nal_type, strip_start_code, sps_dimensions, H264Parser};
use dt_airplay::mirror::{setup_mirror_session, MirrorSession};
use dt_airplay::pairing::PairingSession;
use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!("usage: mirror_pin <host> <port> <pin> <h264-file> [credentials.json]");
        std::process::exit(2);
    }
    let host = args[1].clone();
    let port: u16 = args[2].parse()?;
    let pin = args[3].clone();
    let h264_path = args[4].clone();

    let mut client = Client::connect(&host, port)?;
    let info = client.get_info()?;
    println!("receiver: {} ({})", info.name, info.model);
    println!("  features: 0x{:x} statusFlags: 0x{:x}", info.features, info.status_flags);

    // Pair with PIN.
    let mut pairing = PairingSession::with_info(client.pairing_id.clone(), info.clone());
    match pairing.start_pin_display(&mut client) {
        Ok(()) => println!("pair-pin-start: OK"),
        Err(e) => println!("pair-pin-start: {e} (continuing)"),
    }
    pairing.pair_with_pin(&mut client, &pin)?;
    println!("pairing OK (encrypted={})", pairing.encrypted);
    client.pair_keys = Some(pairing.keys.clone());
    client.enable_hap_encryption(pairing.enc_write_key.clone(), pairing.enc_read_key.clone());

    // FairPlay SAP (modern receivers).
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

    // Mirror session (video only; audio skipped).
    let mut session = setup_mirror_session(client, false, true, 0, 0)?;
    println!("mirror session up: data port connected, session URI {}", session.session_uri);
    session.send_feedback()?;

    // Stream frames from the pre-encoded Annex-B file.
    let mut file = std::fs::File::open(&h264_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    stream_annex_b(&mut session, &data)?;
    println!("streaming complete");

    // A few heartbeats + feedback to prove liveness.
    for _ in 0..3 {
        session.send_heartbeat()?;
        session.send_feedback()?;
        std::thread::sleep(std::time::Duration::from_millis(300));
    }

    session.teardown()?;
    println!("teardown OK");
    Ok(())
}

/// Feeds an Annex-B H.264 stream through the mirror framing protocol.
fn stream_annex_b(session: &mut MirrorSession, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = H264Parser::new();
    let mut latest_sps: Option<Vec<u8>> = None;
    let mut latest_pps: Option<Vec<u8>> = None;
    let mut vcl_buf: Vec<u8> = Vec::new();
    let mut pending_keyframe = false;
    let mut codec_sent = false;

    for chunk in data.chunks(64 * 1024) {
        let nals = parser.push(chunk);
        for nal in nals {
            let nt = nal_type(&nal);
            let raw = strip_start_code(&nal).to_vec();
            match nt {
                9 => flush_vcl(session, &mut vcl_buf, &latest_sps, &latest_pps, &mut pending_keyframe, &mut codec_sent)?, // AUD
                7 => {
                    flush_vcl(session, &mut vcl_buf, &latest_sps, &latest_pps, &mut pending_keyframe, &mut codec_sent)?;
                    latest_sps = Some(raw);
                }
                8 => latest_pps = Some(raw),
                6 => {} // SEI
                5 => {
                    if !vcl_buf.is_empty() && !pending_keyframe {
                        flush_vcl(session, &mut vcl_buf, &latest_sps, &latest_pps, &mut pending_keyframe, &mut codec_sent)?;
                    }
                    pending_keyframe = true;
                    vcl_buf.extend_from_slice(&dt_airplay::h264::avcc_wrap(&raw));
                }
                1..=4 => {
                    if !vcl_buf.is_empty() && pending_keyframe {
                        flush_vcl(session, &mut vcl_buf, &latest_sps, &latest_pps, &mut pending_keyframe, &mut codec_sent)?;
                    }
                    // New AU (first slice) without an AUD → flush the previous frame.
                    if !vcl_buf.is_empty() && !pending_keyframe && dt_airplay::h264::is_first_slice(&raw) {
                        flush_vcl(session, &mut vcl_buf, &latest_sps, &latest_pps, &mut pending_keyframe, &mut codec_sent)?;
                    }
                    vcl_buf.extend_from_slice(&dt_airplay::h264::avcc_wrap(&raw));
                }
                _ => {}
            }
        }
    }
    flush_vcl(session, &mut vcl_buf, &latest_sps, &latest_pps, &mut pending_keyframe, &mut codec_sent)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn flush_vcl(
    session: &mut MirrorSession,
    vcl_buf: &mut Vec<u8>,
    latest_sps: &Option<Vec<u8>>,
    latest_pps: &Option<Vec<u8>>,
    pending_keyframe: &mut bool,
    codec_sent: &mut bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if vcl_buf.is_empty() {
        return Ok(());
    }
    let (ts, timeline) = session.frame_time_now();
    if *pending_keyframe && !*codec_sent {
        if let (Some(sps), Some(pps)) = (latest_sps, latest_pps) {
            if let Some((w, h)) = sps_dimensions(sps) {
                session.video_width = w;
                session.video_height = h;
            }
            let avcc = build_avcc_config(sps, pps);
            session.send_codec_frame(&avcc, ts)?;
            *codec_sent = true;
        }
    }
    let frame = std::mem::take(vcl_buf);
    session.send_frame(&frame, *pending_keyframe, ts, timeline)?;
    *pending_keyframe = false;
    *codec_sent = false;
    Ok(())
}
