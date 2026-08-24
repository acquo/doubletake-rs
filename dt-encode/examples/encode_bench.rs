//! Benchmarks OpenH264 encode throughput at a given resolution across a few
//! configs (threads / complexity). Synthetic BGRA frames, no capture.
//!
//! Usage: encode_bench [width] [height] [frames]

use dt_encode::openh264::{OpenH264Config, OpenH264Encoder};
use std::time::Instant;

fn bench(w: usize, h: usize, frames: usize, config: OpenH264Config, label: &str) {
    let mut encoder = match OpenH264Encoder::new(config) {
        Ok(e) => e,
        Err(e) => {
            println!("{label}: init failed: {e}");
            return;
        }
    };
    // Synthetic moving pattern so frames aren't identical.
    let mut frame = vec![0u8; w * h * 4];
    let start = Instant::now();
    let mut bytes = 0usize;
    for i in 0..frames {
        let shift = (i % 64) as u8;
        for chunk in frame.chunks_mut(4096) {
            for v in chunk.iter_mut() {
                *v = v.wrapping_add(shift);
            }
        }
        match encoder.encode_bgra(&frame, w, h, w * 4) {
            Ok(b) => bytes += b.len(),
            Err(e) => {
                println!("{label}: encode error: {e}");
                return;
            }
        }
    }
    let el = start.elapsed().as_secs_f64();
    println!(
        "{label}: {frames} frames in {el:.2}s = {:.1} fps, {:.1} MB total",
        frames as f64 / el,
        bytes as f64 / 1e6
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let w: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1920);
    let h: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1080);
    let frames: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(120);

    println!("=== OpenH264 encode bench: {w}x{h}, {frames} frames ===");

    bench(w, h, frames, OpenH264Config { threads: 0, ..Default::default() }, "screen/medium/threads=auto");
    bench(w, h, frames, OpenH264Config { threads: 8, max_slice_len: Some(4096), ..Default::default() }, "screen/medium/threads=8");
    bench(
        w, h, frames,
        OpenH264Config { threads: 0, complexity: dt_encode::openh264::Complexity::Low, ..Default::default() },
        "screen/low/threads=auto",
    );
    bench(
        w, h, frames,
        OpenH264Config {
            threads: 8,
            complexity: dt_encode::openh264::Complexity::Low,
            skip_frames: true,
            ..Default::default()
        },
        "screen/low/threads=8/slice4096",
    );
    bench(
        w, h, frames,
        OpenH264Config {
            threads: 0,
            usage_type: dt_encode::openh264::UsageType::CameraVideoRealTime,
            complexity: dt_encode::openh264::Complexity::Low,
            ..Default::default()
        },
        "camera/low/threads=auto",
    );
}

