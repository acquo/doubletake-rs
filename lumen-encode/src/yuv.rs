//! YUV 4:2:0 color conversion helpers shared by the software (x264, OpenH264)
//! and MediaFoundation / QSV backends.
//!
//! Desktop duplication hands us B8G8R8A8 (BGRA) frames. The encoders want a
//! planar 4:2:0 layout (I420 / NV12), so we convert on the CPU.

/// Converts a packed BGRA frame (row-major, stride bytes) to I420.
///
/// Returns `(y, u, v)` each row-major planar. `u`/`v` are 1/4 the plane size
/// (4:2:0 subsampling). Width/height must be even for 4:2:0.
pub fn bgra_to_i420(
    bgra: &[u8],
    width: usize,
    height: usize,
    stride: usize,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let w = width & !1; // round down to even for 4:2:0
    let h = height & !1;
    assert!(bgra.len() >= stride * height, "bgra buffer too small");
    assert!(stride >= width * 4, "stride smaller than a row");

    let frame_size = w * h;
    let mut y = vec![0u8; frame_size];
    let mut u = vec![0u8; (w / 2) * (h / 2)];
    let mut v = vec![0u8; (w / 2) * (h / 2)];

    for row in 0..h {
        let src_row = &bgra[row * stride..row * stride + w * 4];
        let y_row = &mut y[row * w..(row + 1) * w];
        for col in 0..w {
            let p = col * 4;
            let b = src_row[p] as f32;
            let g = src_row[p + 1] as f32;
            let r = src_row[p + 2] as f32;
            // BT.601 studio range.
            y_row[col] = clamp((0.257 * r + 0.504 * g + 0.098 * b) + 16.0);
        }
    }
    for row in 0..(h / 2) {
        for col in 0..(w / 2) {
            // Average the 2x2 source block for the chroma sample.
            let mut rr = 0.0;
            let mut gg = 0.0;
            let mut bb = 0.0;
            for dy in 0..2 {
                for dx in 0..2 {
                    let p = ((row * 2 + dy) * stride + (col * 2 + dx) * 4) as usize;
                    bb += bgra[p] as f32;
                    gg += bgra[p + 1] as f32;
                    rr += bgra[p + 2] as f32;
                }
            }
            rr *= 0.25;
            gg *= 0.25;
            bb *= 0.25;
            let idx = row * (w / 2) + col;
            u[idx] = clamp(-0.148 * rr - 0.291 * gg + 0.439 * bb + 128.0);
            v[idx] = clamp(0.439 * rr - 0.368 * gg - 0.071 * bb + 128.0);
        }
    }
    (y, u, v)
}

/// Interleaves I420 `(y,u,v)` planes into NV12 (`y` + interleaved `uv`).
pub fn i420_to_nv12(
    y: &[u8],
    u: &[u8],
    v: &[u8],
    width: usize,
    height: usize,
) -> Vec<u8> {
    let frame_size = width * height;
    let mut nv12 = vec![0u8; frame_size + (frame_size / 2)];
    nv12[..frame_size].copy_from_slice(y);
    let n = (frame_size / 2) / 2; // chroma sample count
    let mut o = frame_size;
    for i in 0..n {
        nv12[o] = u[i];
        nv12[o + 1] = v[i];
        o += 2;
    }
    nv12
}

fn clamp(v: f32) -> u8 {
    if v < 0.0 {
        0
    } else if v > 255.0 {
        255
    } else {
        v as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bgra_to_i420_sizes() {
        let w = 8;
        let h = 8;
        let stride = w * 4;
        let bgra = vec![0u8; stride * h];
        let (y, u, v) = bgra_to_i420(&bgra, w, h, stride);
        assert_eq!(y.len(), w * h);
        assert_eq!(u.len(), (w / 2) * (h / 2));
        assert_eq!(v.len(), (w / 2) * (h / 2));
    }

    #[test]
    fn nv12_interleave_size() {
        let nv12 = i420_to_nv12(&vec![0u8; 16], &vec![0u8; 4], &vec![0u8; 4], 4, 4);
        assert_eq!(nv12.len(), 16 + 8);
    }
}
