//! Small smoke test that browses `_airplay._tcp.local.` on the local network
//! and prints each discovered service. Run this while `receiver_run` is up to
//! confirm the advertisement is actually being sent (which is what a MacBook's
//! AirPlay menu would discover).
//!
//! Usage: RUST_LOG=info cargo run --example mdns_probe

use mdns_sd::{ServiceDaemon, ServiceEvent};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let sd = ServiceDaemon::new().expect("mdns daemon");
    let receiver = sd.browse("_airplay._tcp.local.").expect("browse");

    println!("[probe] browsing _airplay._tcp.local. for 6s ...");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(6);
    let mut found = 0;
    while std::time::Instant::now() < deadline {
        match receiver.recv_timeout(std::time::Duration::from_millis(500)) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                found += 1;
                println!("[probe] FOUND: name={} host={} port={} addrs={:?}",
                    info.get_fullname(), info.get_hostname(), info.get_port(), info.get_addresses());
                println!("       txt={:?}", info.get_properties());
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
    println!("[probe] done, found {found} service(s)");
}
