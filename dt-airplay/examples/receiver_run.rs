//! Runs the Rust AirPlay receiver: advertises `_airplay._tcp` via mDNS and
//! accepts an Apple mirroring client. This is the no-GStreamer, Rust
//! replacement for "set up UxPlay" — its purpose is to observe exactly what a
//! real MacBook Air sends (audio SETUP descriptor + RTP) so the sender side can
//! replicate the format the Android TV's "Luna" framework expects.
//!
//! Usage:
//!   RUST_LOG=info cargo run --release --example receiver_run
//!   # with a dump of every SETUP plist:
//!   RUST_LOG=info cargo run --release --example receiver_run -- --audiocapture setups.bin
//!
//! On the MacBook, open Control Center > Screen Mirroring (or AirPlay) and pick
//! "Doubletake-RS".

use dt_airplay::receiver::{ReceiverAuth, ReceiverConfig, ReceiverProfile, ReceiverServer};
use std::path::PathBuf;
use std::sync::Arc;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut args = std::env::args().skip(1);
    let mut listen = "0.0.0.0:7000".to_string();
    let mut profile = ReceiverProfile::Modern;
    let mut auth = ReceiverAuth::None;
    let mut code = String::new();
    let mut name = "Doubletake-RS".to_string();
    let mut audio_capture: Option<PathBuf> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => listen = args.next().unwrap_or(listen),
            "--profile" => {
                profile = match args.next().as_deref() {
                    Some("roku") => ReceiverProfile::Roku,
                    _ => ReceiverProfile::Modern,
                }
            }
            "--auth" => {
                auth = match args.next().as_deref() {
                    Some("pin") => ReceiverAuth::Pin,
                    Some("password") => ReceiverAuth::Password,
                    Some("digest") => ReceiverAuth::Digest,
                    Some("combined") => ReceiverAuth::Combined,
                    _ => ReceiverAuth::None,
                }
            }
            "--code" => code = args.next().unwrap_or_default(),
            "--name" => name = args.next().unwrap_or(name),
            "--audiocapture" => audio_capture = args.next().map(PathBuf::from),
            other => {
                eprintln!("unknown arg: {other}");
                std::process::exit(2);
            }
        }
    }

    let cfg = ReceiverConfig {
        listen,
        profile,
        auth,
        code,
        name,
        audio_dump_path: audio_capture,
        ..ReceiverConfig::default()
    };

    let server = Arc::new(ReceiverServer::new(cfg).expect("create receiver"));
    let daemon = server.advertise().expect("advertise mDNS");

    // Print the addresses we advertise so the user can also reach us directly.
    println!(
        "[receiver] listening for control on {:?}",
        server.local_addr()
    );
    println!(
        "[receiver] mDNS _airplay._tcp advertised; on the MacBook mirror to '{}'",
        server
            .lan_ipv4()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string())
    );

    let _guard = daemon; // keep the mDNS daemon alive

    if let Err(e) = server.serve() {
        eprintln!("[receiver] serve error: {e}");
        std::process::exit(1);
    }
}
