//! Receiver media endpoints: binds the UDP/TCP ports advertised in SETUP
//! responses and drains the audio RTP stream to a capture file. Ported
//! (simplified) from `internal/airplay/receiver_media.go`, focused on the
//! audio-format capture use case rather than full event/video accounting.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, Copy)]
pub struct MediaEndpoints {
    pub event_port: u16,
    pub video_port: u16,
    pub audio_rtp_port: u16,
    pub audio_rtcp_port: u16,
    pub timing_port: u16,
}

pub struct ReceiverMedia {
    event_listener: TcpListener,
    video_listener: TcpListener,
    audio_rtp: UdpSocket,
    audio_rtcp: UdpSocket,
    timing: UdpSocket,
    endpoints: MediaEndpoints,
    stop: Arc<AtomicBool>,
}

impl ReceiverMedia {
    /// Binds all media endpoints on the given IP (an IPv4 literal) with
    /// ephemeral ports, then starts the drain loops. To be reachable on the
    /// interface the client used for control (loopback or LAN), we bind to
    /// `0.0.0.0` so both are accepted.
    pub fn new(_ip: IpAddr, audio_dump: Option<PathBuf>) -> std::io::Result<Self> {
        let any = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
        let event_listener = TcpListener::bind(SocketAddr::new(any, 0))?;
        let video_listener = TcpListener::bind(SocketAddr::new(any, 0))?;
        let audio_rtp = UdpSocket::bind(SocketAddr::new(any, 0))?;
        let audio_rtcp = UdpSocket::bind(SocketAddr::new(any, 0))?;
        let timing = UdpSocket::bind(SocketAddr::new(any, 0))?;

        let endpoints = MediaEndpoints {
            event_port: event_listener.local_addr()?.port(),
            video_port: video_listener.local_addr()?.port(),
            audio_rtp_port: audio_rtp.local_addr()?.port(),
            audio_rtcp_port: audio_rtcp.local_addr()?.port(),
            timing_port: timing.local_addr()?.port(),
        };

        let stop = Arc::new(AtomicBool::new(false));

        // Video channel: bound and drained (frames discarded).
        {
            let listener = video_listener.try_clone()?;
            let stop = stop.clone();
            std::thread::spawn(move || accept_drain_tcp(listener, stop, "video"));
        }
        // Event channel: bound and drained (we do not run the force-key-frame
        // command channel for the capture use case).
        {
            let listener = event_listener.try_clone()?;
            let stop = stop.clone();
            std::thread::spawn(move || accept_drain_tcp(listener, stop, "event"));
        }
        // Audio RTP: dump every datagram to a dedicated capture file.
        {
            let sock = audio_rtp.try_clone()?;
            // Use a separate file next to the SETUP dump to avoid interleaving.
            let dump = audio_dump.as_ref().map(|p| {
                let mut pb = p.clone();
                let stem = pb
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "audio".into());
                let ext = pb.extension().map(|s| s.to_string_lossy().to_string());
                pb.set_file_name(match ext {
                    Some(e) => format!("{stem}_rtp.{e}"),
                    None => format!("{stem}_rtp"),
                });
                pb
            });
            let stop = stop.clone();
            log::info!("[receiver] audio RTP port={} dump={:?}", audio_rtp.local_addr()?.port(), dump);
            std::thread::spawn(move || drain_audio(sock, dump, stop, true));
        }
        // Audio RTCP: drained.
        {
            let sock = audio_rtcp.try_clone()?;
            let stop = stop.clone();
            std::thread::spawn(move || drain_audio(sock, None, stop, false));
        }
        // Timing: drained.
        {
            let sock = timing.try_clone()?;
            let stop = stop.clone();
            std::thread::spawn(move || drain_udp_discard(sock, stop));
        }

        Ok(ReceiverMedia {
            event_listener,
            video_listener,
            audio_rtp,
            audio_rtcp,
            timing,
            endpoints,
            stop,
        })
    }

    pub fn endpoints(&self) -> MediaEndpoints {
        self.endpoints
    }
}

impl Drop for ReceiverMedia {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.event_listener.set_nonblocking(false);
        let _ = self.video_listener.set_nonblocking(false);
        let _ = self.audio_rtp.set_read_timeout(Some(std::time::Duration::from_millis(200)));
        let _ = self.audio_rtcp.set_read_timeout(Some(std::time::Duration::from_millis(200)));
        let _ = self.timing.set_read_timeout(Some(std::time::Duration::from_millis(200)));
    }
}

fn accept_drain_tcp(listener: TcpListener, stop: Arc<AtomicBool>, name: &str) {
    for conn in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        match conn {
            Ok(mut c) => {
                let mut buf = [0u8; 64 * 1024];
                while !stop.load(Ordering::SeqCst) {
                    match c.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            }
            Err(_) => return,
        }
    }
    let _ = name;
}

fn drain_audio(sock: UdpSocket, dump: Option<PathBuf>, stop: Arc<AtomicBool>, write_dump: bool) {
    if let Some(path) = &dump {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let mut buf = [0u8; 4096];
    let mut logged = 0usize;
    let mut total = 0usize;
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        match sock.recv_from(&mut buf) {
            Ok((n, _addr)) => {
                total += 1;
                if write_dump {
                    if let Some(path) = &dump {
                        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                            // Frame header: 2-byte big-endian length + raw RTP datagram.
                            let _ = f.write_all(&(n as u16).to_be_bytes());
                            let _ = f.write_all(&buf[..n]);
                        }
                    }
                    if logged < 8 {
                        log::info!("[receiver] audio RTP packet {} bytes: {:02x?}", n, &buf[..n.min(28)]);
                        logged += 1;
                    }
                    if total % 50 == 0 {
                        log::info!("[receiver] audio RTP received {} total", total);
                    }
                }
            }
            Err(_) => continue,
        }
    }
}

fn drain_udp_discard(sock: UdpSocket, stop: Arc<AtomicBool>) {
    let mut buf = [0u8; 4096];
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        match sock.recv_from(&mut buf) {
            Ok(_) => {}
            Err(_) => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn audio_socket_receives_loopback() {
        let any = Ipv4Addr::UNSPECIFIED;
        let sock = UdpSocket::bind(SocketAddr::from((any, 0))).unwrap();
        let port = sock.local_addr().unwrap().port();
        let clone = sock.try_clone().unwrap();
        clone.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let received = Arc::new(AtomicBool::new(false));
        let r2 = received.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 128];
            if let Ok((n, _)) = clone.recv_from(&mut buf) {
                if n > 0 {
                    r2.store(true, Ordering::SeqCst);
                }
            }
        });
        let sender = UdpSocket::bind(SocketAddr::from((any, 0))).unwrap();
        sender
            .send_to(b"hello", SocketAddr::from(([127, 0, 0, 1], port)))
            .unwrap();
        std::thread::sleep(Duration::from_millis(400));
        assert!(
            received.load(Ordering::SeqCst),
            "UDP socket bind(0.0.0.0) + try_clone did not receive a loopback datagram"
        );
    }

    #[test]
    fn receiver_media_audio_dump_receives() {
        let base = std::env::temp_dir().join("lumen_media_rtp_test.bin");
        let _ = std::fs::remove_file(&base);
        let derived = std::env::temp_dir().join("lumen_media_rtp_test_rtp.bin");
        let _ = std::fs::remove_file(&derived);
        let m = ReceiverMedia::new(IpAddr::V4(Ipv4Addr::LOCALHOST), Some(base.clone())).unwrap();
        let port = m.endpoints().audio_rtp_port;
        let sender = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).unwrap();
        sender
            .send_to(b"\x80\x60testrtp", SocketAddr::from(([127, 0, 0, 1], port)))
            .unwrap();
        std::thread::sleep(Duration::from_millis(600));
        let exists = derived.exists();
        let len = if exists { std::fs::metadata(&derived).unwrap().len() } else { 0 };
        eprintln!("media test: port={port} derived={:?} exists={exists} len={len}", derived);
        assert!(exists, "audio dump (derived) not created (port={port})");
        assert!(len > 0, "audio dump empty (port={port}, len={len})");
    }
}

