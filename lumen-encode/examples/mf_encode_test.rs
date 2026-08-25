//! Smoke test: initializes the MediaFoundation H.264 encoder, encodes a
//! synthetic NV12 gradient for a second, and writes the H.264 output so it can
//! be validated with `ffprobe`.
//!
//! Usage: cargo run --release -p lumen-encode --example mf_encode_test

use lumen_encode::mf::MediaFoundationEncoder;
use lumen_encode::yuv::{bgra_to_i420, i420_to_nv12};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let w = 640usize;
    let h = 480usize;
    let fps = 30u32;
    let bitrate = 2_000_000u32;

    let mut enc = MediaFoundationEncoder::new(w as u32, h as u32, fps, bitrate)?;
    println!("MediaFoundation H.264 MFT initialized {w}x{h}@{fps} ({bitrate} bps)");

    // Synthetic 128x64 BGRA (scaled to w/h) frame: a move gradient.
    let small_w = 128usize;
    let small_h = 64usize;
    let mut bgra = vec![0u8; small_w * small_h * 4];
    for y in 0..small_h {
        for x in 0..small_w {
            let p = (y * small_w + x) * 4;
            bgra[p] = ((x * 255) / small_w) as u8; // B
            bgra[p + 1] = ((y * 255) / small_h) as u8; // G
            bgra[p + 2] = (((x + y) * 255) / (small_w + small_h)) as u8; // R
            bgra[p + 3] = 255;
        }
    }
    // Scale the small frame up (nearest) to w*h.
    let mut full_bgra = vec![0u8; w * h * 4];
    for y in 0..h {
        let sy = y * small_h / h;
        for x in 0..w {
            let sx = x * small_w / w;
            let src = (sy * small_w + sx) * 4;
            let dst = (y * w + x) * 4;
            full_bgra[dst..dst + 4].copy_from_slice(&bgra[src..src + 4]);
        }
    }
    let (yy, uu, vv) = bgra_to_i420(&full_bgra, w, h, w * 4);
    let nv12 = i420_to_nv12(&yy, &uu, &vv, w, h);

    let frame_bytes = w * h * 3 / 2;
    assert_eq!(nv12.len(), frame_bytes);

    let mut h264 = Vec::new();
    for i in 0..fps {
        let force_idr = i == 0;
        let bytes = enc.encode_nv12(&nv12, force_idr)?;
        if !bytes.is_empty() {
            h264.extend_from_slice(&bytes);
        }
    }
    std::fs::write("mf_test.h264", &h264)?;
    println!("wrote {} bytes H.264 -> mf_test.h264", h264.len());
    if h264.is_empty() {
        eprintln!("WARNING: encoder produced no output");
    } else {
        println!("first 16 bytes: {:02x?}", &h264[..16.min(h264.len())]);
    }
    Ok(())
}
