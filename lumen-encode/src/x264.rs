//! x264 software encoder backend. Uses the `x264` Rust crate (which links the
//! system libx264) and feeds the desktop's BGRA frames directly via
//! `Image::bgra`, so no manual YUV conversion is needed here.
//!
//! NOTE: The `x264`/`x264-sys` crates probe pkg-config for libx264. On this
//! machine it resolves to the GStreamer-bundled libx264 (0.164.13) when
//! `PKG_CONFIG_PATH` is set to its pkgconfig dir.

use crate::yuv::bgra_to_i420;
use x264::{Colorspace, Encoder, Image, Plane, Preset, Setup, Tune};

#[derive(thiserror::Error, Debug)]
pub enum X264Error {
    #[error("x264: {0}")]
    X264(String),
}

pub struct X264Encoder {
    enc: Encoder,
    #[allow(dead_code)]
    width: u32,
    #[allow(dead_code)]
    height: u32,
    pts: i64,
}

impl X264Encoder {
    /// Opens a low-latency ultrafast x264 encoder that outputs 4:2:0.
    pub fn new(width: u32, height: u32, fps: u32, bitrate_bps: u32) -> Result<Self, X264Error> {
        let setup = Setup::preset(Preset::Ultrafast, Tune::None, false, true)
            .fps(fps.max(1), 1)
            .bitrate((bitrate_bps / 1000).max(1) as i32)
            .baseline(); // 4:2:0 output (TV/Apple-compatible)
        let enc = setup
            .build(Colorspace::I420, width as i32, height as i32)
            .map_err(|e| X264Error::X264(format!("open encoder: {e:?}")))?;
        Ok(X264Encoder {
            enc,
            width,
            height,
            pts: 0,
        })
    }

    /// Encodes one tightly-packed BGRA frame (width*height*4 bytes) into H.264
    /// Annex-B 4:2:0 bytes (converts BGRA -> I420 internally).
    pub fn encode_bgra(
        &mut self,
        bgra: &[u8],
        width: u32,
        height: u32,
        stride: u32,
        _force_idr: bool,
    ) -> Result<Vec<u8>, X264Error> {
        let w = width as usize;
        let h = height as usize;
        let expected = (w * h * 4) as usize;
        if bgra.len() < expected {
            return Err(X264Error::X264(format!(
                "bgra buffer {} bytes, need {expected}",
                bgra.len()
            )));
        }
        let (yy, uu, vv) = bgra_to_i420(bgra, w, h, stride as usize);
        let planes = [
            Plane {
                stride: w as i32,
                data: &yy,
            },
            Plane {
                stride: (w / 2) as i32,
                data: &uu,
            },
            Plane {
                stride: (w / 2) as i32,
                data: &vv,
            },
        ];
        let image = Image::new(Colorspace::I420, w as i32, h as i32, &planes);
        let (data, _pic) = self
            .enc
            .encode(self.pts, image)
            .map_err(|e| X264Error::X264(format!("encode: {e:?}")))?;
        self.pts += 1;
        Ok(data.entirety().to_vec())
    }
}
