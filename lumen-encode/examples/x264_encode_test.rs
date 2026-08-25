//! Smoke test for the x264 backend: encode a synthetic BGRA gradient, write the
//! H.264, and let ffprobe validate it (expect baseline/4:2:0 for TV compat).
//! Usage: cargo run --release -p lumen-encode --example x264_encode_test

use lumen_encode::x264::X264Encoder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let w = 640usize;
    let h = 480usize;
    let mut enc = X264Encoder::new(w as u32, h as u32, 30, 2_000_000)?;
    println!("x264 initialized {w}x{h}@30");

    let mut bgra = vec![0u8; w * h * 4];
    for y in 0..h {
        for x in 0..w {
            let p = (y * w + x) * 4;
            bgra[p] = ((x * 255) / w) as u8;
            bgra[p + 1] = ((y * 255) / h) as u8;
            bgra[p + 2] = (((x + y) * 255) / (w + h)) as u8;
            bgra[p + 3] = 255;
        }
    }
    let mut h264 = Vec::new();
    for _ in 0..30 {
        let bytes = enc.encode_bgra(&bgra, w as u32, h as u32, (w * 4) as u32, false)?;
        h264.extend_from_slice(&bytes);
    }
    std::fs::write("x264_test.h264", &h264)?;
    println!("wrote {} bytes H.264 -> x264_test.h264", h264.len());
    Ok(())
}
