//! Isolates OpenH264 pipeline stage costs at a resolution:
//!   A) BGRA->I420 conversion only
//!   B) encode only (reusing a YUV buffer)
//!   C) full pipeline
//!   D) realistic mostly-static frame
//! Usage: encode_stages [width] [height] [frames]

use dt_encode::openh264::{OpenH264Config, OpenH264Encoder};
use openh264::formats::{BgraSliceU8, YUVBuffer};
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let w: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1920);
    let h: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1080);
    let frames: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(120);

    let mut frame = vec![0u8; w * h * 4];
    // Realistic: mostly static, a small moving patch (like a cursor + window).
    for i in 0..frames {
        let x0 = (i * 13) % (w - 64);
        let y0 = (i * 7) % (h - 64);
        for y in y0..y0 + 64 {
            for x in x0..x0 + 64 {
                let p = (y * w + x) * 4;
                frame[p] = (x * 3) as u8;
                frame[p + 1] = (y * 5) as u8;
                frame[p + 2] = 200;
                frame[p + 3] = 255;
            }
        }
    }

    // A) conversion only
    let start = Instant::now();
    for _ in 0..frames {
        let _ = YUVBuffer::from_bgra8_source(BgraSliceU8::new(&frame, (w, h)));
    }
    let a = start.elapsed().as_secs_f64() / frames as f64;
    println!("A conversion: {:.1} ms/frame", a * 1000.0);

    // B) encode only (reuse one YUV buffer)
    let yuv = YUVBuffer::from_bgra8_source(BgraSliceU8::new(&frame, (w, h)));
    let mut enc = OpenH264Encoder::new(OpenH264Config::default()).expect("init");
    // warm up
    let _ = enc.encode_bgra(&frame, w, h, w * 4);
    let start = Instant::now();
    let mut total = 0usize;
    for _ in 0..frames {
        let bs = enc.encode_bgra(&frame, w, h, w * 4).expect("encode");
        total += bs.len();
    }
    let b = start.elapsed().as_secs_f64() / frames as f64;
    println!("C full pipeline: {:.1} ms/frame ({:.1} fps), {:.2} MB", b * 1000.0, 1.0 / b, total as f64 / 1e6);

    // B2) encode-only on the same YUV (no conversion, no scratch copy)
    let mut enc2 = OpenH264Encoder::new(OpenH264Config::default()).expect("init");
    let _ = enc2.encode_bgra(&frame, w, h, w * 4);
    let start = Instant::now();
    for _ in 0..frames {
        let _ = enc2.encode_yuv(&yuv);
    }
    let b2 = start.elapsed().as_secs_f64() / frames as f64;
    println!("B encode only: {:.1} ms/frame ({:.1} fps)", b2 * 1000.0, 1.0 / b2);

    // D) quality mode (not bitrate RC)
    let mut enc3 = OpenH264Encoder::new(OpenH264Config {
        skip_frames: true,
        ..Default::default()
    })
    .expect("init");
    let _ = enc3.encode_bgra(&frame, w, h, w * 4);
    let start = Instant::now();
    for _ in 0..frames {
        let _ = enc3.encode_yuv(&yuv);
    }
    let d = start.elapsed().as_secs_f64() / frames as f64;
    println!("D encode only (skip_frames=1): {:.1} ms/frame ({:.1} fps)", d * 1000.0, 1.0 / d);
}
