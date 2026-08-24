//! Triggers the receiver's on-screen pairing PIN and holds it so it can be
//! read (e.g. via adb screenshot), then exits.
//!
//! Usage: pin_hold <host> [port]

use dt_airplay::client::Client;
use dt_airplay::pairing::PairingSession;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let host = args.get(1).cloned().unwrap_or_else(|| "192.168.1.107".into());
    let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(7000);

    let mut client = Client::connect(&host, port)?;
    let info = client.get_info()?;
    println!("receiver: {} ({})", info.name, info.model);

    let mut pairing = PairingSession::with_info(client.pairing_id.clone(), info.clone());
    match pairing.start_pin_display(&mut client) {
        Ok(()) => println!("pin displayed — holding 45s for capture"),
        Err(e) => println!("pin display: {e} (continuing)"),
    }
    std::thread::sleep(Duration::from_secs(45));
    println!("done");
    Ok(())
}
