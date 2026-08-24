//! M1 pipeline: DXGI desktop duplication → NVENC D3D11 zero-copy → H.264 file.
//!
//! Usage: cargo run --example capture_encode -- [seconds] [output.h264]
//! Verify with: ffplay output.h264

use dt_capture::dxgi::DesktopDuplicator;
use dt_encode::nvenc::NvEncoder;
use dt_encode::{H264Encoder, NV_ENC_BUFFER_FORMAT_ARGB};
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let seconds: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
    let out_path = args.get(2).cloned().unwrap_or_else(|| "capture.h264".into());

    // Capture: D3D11 device + desktop duplication.
    let mut dup = DesktopDuplicator::new(0)?;
    println!(
        "desktop: {}x{} (duplication ready)",
        dup.width, dup.height
    );

    // Encoder on the SAME D3D11 device (zero-copy requirement).
    let nv = Arc::new(NvEncoder::load()?);
    let (major, minor) = nv.major_minor();
    println!("NVENC API {}.{}", major, minor);
    let mut encoder = H264Encoder::new(
        nv,
        dup.device_raw(),
        dup.width,
        dup.height,
        30,
        8_000_000,
        NV_ENC_BUFFER_FORMAT_ARGB,
    )?;
    println!("H.264 encoder initialized (CBR 8 Mbps, 30 fps)");

    let mut out = std::fs::File::create(&out_path)?;
    let start = Instant::now();
    let mut frame_count: u64 = 0;
    let mut bytes_total: u64 = 0;
    let mut registered = false;

    while start.elapsed() < Duration::from_secs(seconds) {
        match dup.acquire_frame(100)? {
            Some(texture) => {
                let raw = windows::core::Interface::as_raw(&texture) as *mut std::ffi::c_void;
                if !registered {
                    encoder.register_texture(raw)?;
                    registered = true;
                    println!("D3D11 texture registered with NVENC (zero-copy path)");
                }
                // Refresh the registered surface each frame.
                let bytes = encoder.encode_frame(frame_count == 0)?;
                if !bytes.is_empty() {
                    out.write_all(&bytes)?;
                    bytes_total += bytes.len() as u64;
                }
                frame_count += 1;
                dup.release_frame();
                if frame_count % 30 == 0 || frame_count <= 3 {
                    println!(
                        "frame {frame_count}: {} bytes (total {})",
                        bytes.len(),
                        bytes_total
                    );
                }
            }
            None => {} // no new frame within timeout
        }
    }

    println!(
        "done: {frame_count} frames, {bytes_total} bytes -> {out_path} ({:.1} fps avg)",
        frame_count as f64 / start.elapsed().as_secs_f64()
    );
    Ok(())
}
