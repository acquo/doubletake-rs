//! Audio-path interop test: pair + mirror session + RTP ALAC frames to a
//! receiver, WITHOUT desktop capture (verifies the audio SETUP port parsing
//! and the RTP/sync packet flow against `lumen-test-receiver`).
//!
//! Usage: mirror_audio_test <host> <port> <pin> [frames]
//! Receiver: lumen-test-receiver.exe -auth pin -code 1234 -profile roku
//!           -listen 127.0.0.1:7100 -debug -stats-interval 2s
//! Check the receiver stats line for `audio=N/B`.

use lumen_airplay::audio::{encode_alac_verbatim, SPF};
use lumen_airplay::client::Client;
use lumen_airplay::mirror::{ntp_network_time, setup_mirror_session};
use lumen_airplay::pairing::PairingSession;
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: mirror_audio_test <host> <port> <pin> [frames]");
        std::process::exit(2);
    }
    let host = args[1].clone();
    let port: u16 = args[2].parse()?;
    let pin = args[3].clone();
    let frames_to_send: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(400);

    let mut client = Client::connect(&host, port)?;
    let info = client.get_info()?;
    println!("receiver: {} ({})", info.name, info.model);

    let mut pairing = PairingSession::with_info(client.pairing_id.clone(), info.clone());
    let _ = pairing.start_pin_display(&mut client);
    pairing.pair_with_pin(&mut client, &pin)?;
    client.pair_keys = Some(pairing.keys.clone());
    client.enable_hap_encryption(pairing.enc_write_key.clone(), pairing.enc_read_key.clone());
    println!("pairing OK");

    if info.supports_fairplay_sap() {
        let fp = lumen_airplay::fairplay::fairplay_setup(&mut client, &info, &pairing.keys.shared_secret, true)?;
        client.fp_key = fp.stream_key.to_vec();
        client.fp_iv = fp.stream_iv.to_vec();
        client.fp_ekey = fp.ekey.to_vec();
        client.fp_m3 = fp.m3.to_vec();
        client.fp_aes_key = fp.raw_key.to_vec();
    }

    let session = setup_mirror_session(client, false, true, 0, 0)?;
    println!("mirror session up (audio ports: data={} ctrl={})", session.audio_data_port, session.audio_ctrl_port);
    let Some(mut audio) = session.make_audio_stream()? else {
        eprintln!("FAIL: receiver provided no audio ports — audio path cannot be tested");
        std::process::exit(1);
    };
    let _ = audio.set_ctrl_nonblocking();
    println!("audio stream ready (latency {} samples)", session.audio_latency_samples);

    // Synthetic silence frames, RTP epoch + seq as upstream.
    let mut rtp_time: u32 = 0x1234_5678;
    let mut seq: u16 = 1;
    audio.rtp_time = rtp_time;
    let pcm = vec![0i16; SPF as usize * 2];
    let payload = encode_alac_verbatim(&pcm, SPF as usize, 2);
    println!("ALAC frame: {} bytes", payload.len());

    audio.send_sync_packet(ntp_network_time(), true)?;
    println!("initial sync sent");

    let start = Instant::now();
    let mut last_sync = Instant::now();
    for i in 0..frames_to_send {
        audio.send_frame(&payload, rtp_time, seq)?;
        seq = seq.wrapping_add(1);
        rtp_time = rtp_time.wrapping_add(SPF);
        if last_sync.elapsed() >= Duration::from_secs(1) {
            audio.send_sync_packet(ntp_network_time(), false)?;
            last_sync = Instant::now();
        }
        if i % 100 == 0 {
            println!("sent {}/{} frames", i + 1, frames_to_send);
        }
        std::thread::sleep(Duration::from_millis(2)); // ~440 frames/s ≈ 44.1k
    }
    println!(
        "done: {frames_to_send} audio frames in {:.1}s — check receiver stats for audio=N/B",
        start.elapsed().as_secs_f64()
    );
    Ok(())
}
