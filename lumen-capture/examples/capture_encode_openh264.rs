//! M2 pipeline: DXGI desktop duplication → CPU readback → OpenH264 software
//! H.264 → Annex-B file.
//!
//! Usage:
//!   cargo run -p lumen-capture --example capture_encode_openh264 -- [seconds] [out.h264] [bitrate_kbps]
//! Verify:
//!   ffprobe out.h264
//!   ffplay out.h264

use lumen_capture::dxgi::DesktopDuplicator;
use lumen_encode::openh264::{OpenH264Config, OpenH264Encoder};
use std::io::Write;
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let seconds: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
    let out_path = args.get(2).cloned().unwrap_or_else(|| "capture_openh264.h264".into());
    let bitrate_kbps: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(8000);

    let mut dup = DesktopDuplicator::new(0)?;
    println!("desktop: {}x{} (duplication ready)", dup.width, dup.height);

    let mut encoder = OpenH264Encoder::new(OpenH264Config {
        bitrate_bps: bitrate_kbps * 1000,
        ..Default::default()
    })?;
    println!("OpenH264 encoder ready ({bitrate_kbps} kbps, ScreenContentRealTime)");

    let mut out = std::fs::File::create(&out_path)?;
    let start = Instant::now();
    let mut frame_count: u64 = 0;
    let mut bytes_total: u64 = 0;

    while start.elapsed() < Duration::from_secs(seconds) {
        match dup.acquire_frame_cpu(100)? {
            Some(frame) => {
                let bytes = encoder.encode_bgra(
                    &frame.bgra,
                    frame.width as usize,
                    frame.height as usize,
                    frame.width as usize * 4,
                )?;
                if !bytes.is_empty() {
                    out.write_all(&bytes)?;
                    bytes_total += bytes.len() as u64;
                }
                frame_count += 1;
                if frame_count % 30 == 0 || frame_count <= 3 {
                    println!(
                        "frame {frame_count}: {} bytes (total {bytes_total})",
                        bytes.len()
                    );
                }
            }
            None => {} // no new desktop frame within timeout
        }
    }

    println!(
        "done: {frame_count} frames, {bytes_total} bytes -> {out_path} ({:.1} fps avg)",
        frame_count as f64 / start.elapsed().as_secs_f64()
    );
    Ok(())
}
