//! Interop test: pair against the Go `lumen-test-receiver` binary.
//!
//! Usage:
//!   cargo run --example pair_pin -- <host> <port> <pin> [mode] [credentials.json]
//!
//! mode: "pin" (default) or "transient" (PIN-less / raw legacy pairing).
//!
//! Run the receiver with:
//!   lumen-test-receiver.exe -auth pin -code 1234 -profile modern \
//!       -listen 127.0.0.1:7100 -debug

use lumen_airplay::credentials::CredentialStore;
use lumen_airplay::info::ReceiverInfo;
use lumen_airplay::pairing::PairingSession;
use lumen_airplay::transport::{TcpTransport, Transport};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: pair_pin <host> <port> <pin> [mode] [credentials.json]");
        std::process::exit(2);
    }
    let host = args[1].clone();
    let port: u16 = args[2].parse()?;
    let pin = args[3].clone();
    let mode = args.get(4).map(String::as_str).unwrap_or("pin");
    let cred_path = args
        .get(5)
        .cloned()
        .unwrap_or_else(|| CredentialStore::default_path().to_string_lossy().into_owned());

    let mut transport = TcpTransport::connect(&host, port)?;
    let mut session = PairingSession::new(lumen_airplay::uuid::generate_uuid());

    // GET /info
    let resp = transport.request("GET", "/info", "application/x-apple-binary-plist", &[], &HashMap::new())?;
    if resp.status != 200 {
        eprintln!("GET /info -> HTTP {}", resp.status);
        std::process::exit(1);
    }
    let info: ReceiverInfo =
        plist::from_bytes(&resp.body).map_err(|e| format!("decode /info: {e}"))?;
    println!("receiver: {} ({})", info.name, info.model);
    println!("  deviceID: {}", info.device_id);
    println!("  features: 0x{:x}  statusFlags: 0x{:x}", info.features, info.status_flags);
    println!("  pk: {} bytes", info.pk.as_slice().len());
    println!("  legacy pairing preferred: {}", info.prefers_legacy_pairing());
    session.info = Some(info.clone());

    match mode {
        "pin" => {
            // pair-pin-start (non-fatal: some receivers return 453 to accept async)
            match session.start_pin_display(&mut transport) {
                Ok(()) => println!("pair-pin-start: OK"),
                Err(e) => println!("pair-pin-start: {e} (continuing)"),
            }
            session.pair_with_pin(&mut transport, &pin)?;
            println!("PIN pairing OK!");
        }
        "transient" => {
            session.pair_transient(&mut transport)?;
            println!("transient pairing OK!");
        }
        other => {
            eprintln!("unknown mode: {other} (use pin or transient)");
            std::process::exit(2);
        }
    }

    println!("  encrypted channel: {}", session.encrypted);
    println!("  shared secret: {} bytes", session.keys.shared_secret.len());
    println!(
        "  write key: {}…",
        hex::encode(&session.enc_write_key[..8.min(session.enc_write_key.len())])
    );

    // Save credentials (Go-compatible credentials.json).
    let mut store = CredentialStore::new(&cred_path)?;
    store.save(
        &info.device_id,
        &session.pairing_id,
        &session.keys.ed25519_public,
        &session.keys.ed25519_seed,
    )?;
    println!("credentials saved for {} -> {}", info.device_id, cred_path);

    Ok(())
}
