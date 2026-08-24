//! OpenH264 software H.264 encoder path.
//!
//! Alternative to the NVENC zero-copy path: takes packed BGRA8 frames (e.g.
//! DXGI staging readback), converts them to I420 (SIMD inside the `openh264`
//! crate) and returns an Annex-B H.264 byte stream.
//!
//! This is the fully-configurable path — bitrate, GOP, profile and level are
//! all settable, which the NVENC path currently cannot do on driver 591.86.

use openh264::encoder::{
    BitRate, Encoder, EncoderConfig, FrameRate, IntraFramePeriod, RateControlMode, VuiConfig,
};
use openh264::formats::{BgraSliceU8, YUVBuffer};
use openh264::OpenH264API;

pub use openh264::encoder::{Complexity, Level, Profile, UsageType};

/// Configuration for [`OpenH264Encoder`].
#[derive(Clone, Debug)]
pub struct OpenH264Config {
    /// Target bitrate in bits per second.
    pub bitrate_bps: u32,
    /// Nominal frame rate in Hz (used by the rate controller).
    pub fps: f32,
    /// Usage scenario (screen mirroring → `ScreenContentRealTime`).
    pub usage_type: UsageType,
    /// H.264 profile (defaults to Baseline for maximum decoder compatibility).
    pub profile: Option<Profile>,
    /// H.264 level (defaults to 4.0 = 1080p30).
    pub level: Option<Level>,
    /// Speed/quality tradeoff.
    pub complexity: Complexity,
    /// Whether the encoder may drop frames to hit the bitrate target.
    pub skip_frames: bool,
    /// Periodic intra-frame interval in frames (0 = let the encoder decide).
    pub intra_period_frames: u32,
    /// Number of encoder threads (0 = auto).
    pub threads: u16,
    /// Optional max NAL size (slice size limit).
    pub max_slice_len: Option<u32>,
}

impl Default for OpenH264Config {
    fn default() -> Self {
        Self {
            bitrate_bps: 8_000_000,
            fps: 30.0,
            usage_type: UsageType::ScreenContentRealTime,
            profile: Some(Profile::Baseline),
            level: Some(Level::Level_4_0),
            complexity: Complexity::Medium,
            skip_frames: false,
            intra_period_frames: 0,
            threads: 0,
            max_slice_len: None,
        }
    }
}

/// OpenH264 encoder over packed BGRA8 frames.
///
/// Dimensions are cropped to even values internally (I420 needs even sizes).
pub struct OpenH264Encoder {
    inner: Encoder,
    /// Scratch buffer for row-pitch de-padding / odd-dimension cropping.
    scratch: Vec<u8>,
    scratch_cap: usize,
}

impl OpenH264Encoder {
    /// Creates a new encoder. Fails if OpenH264 could not be initialized.
    ///
    /// # Errors
    ///
    /// Propagates OpenH264 initialization failures.
    pub fn new(config: OpenH264Config) -> Result<Self, openh264::Error> {
        let mut cfg = EncoderConfig::new()
            .bitrate(BitRate::from_bps(config.bitrate_bps))
            .max_frame_rate(FrameRate::from_hz(config.fps))
            .usage_type(config.usage_type)
            .rate_control_mode(RateControlMode::Bitrate)
            .skip_frames(config.skip_frames)
            .complexity(config.complexity)
            .num_threads(config.threads)
            .intra_frame_period(IntraFramePeriod::from_num_frames(config.intra_period_frames))
            // The crate's RGB→YUV conversion uses BT.601 limited range, so
            // signal exactly that in the SPS VUI.
            .vui(VuiConfig::bt601());
        if let Some(p) = config.profile {
            cfg = cfg.profile(p);
        }
        if let Some(l) = config.level {
            cfg = cfg.level(l);
        }
        if let Some(m) = config.max_slice_len {
            cfg = cfg.max_slice_len(m);
        }

        let inner = Encoder::with_api_config(OpenH264API::from_source(), cfg)?;
        Ok(Self {
            inner,
            scratch: Vec::new(),
            scratch_cap: 0,
        })
    }

    /// Encodes one BGRA8 frame and returns the Annex-B H.264 bytes for it.
    ///
    /// `bgra` is `width * height` pixels in `[B,G,R,A]` byte order, with
    /// `row_pitch` bytes per row (may be larger than `width * 4`). Odd
    /// dimensions are cropped by one pixel before encoding.
    ///
    /// # Errors
    ///
    /// Propagates OpenH264 encode failures.
    pub fn encode_bgra(
        &mut self,
        bgra: &[u8],
        width: usize,
        height: usize,
        row_pitch: usize,
    ) -> Result<Vec<u8>, openh264::Error> {
        let ew = width & !1;
        let eh = height & !1;
        assert!(ew > 0 && eh > 0, "frame too small to encode: {width}x{height}");

        let tight_pitch = ew * 4;
        let need_scratch = row_pitch != tight_pitch || ew != width || eh != height;
        let data: &[u8] = if need_scratch {
            let needed = tight_pitch * eh;
            if self.scratch_cap < needed {
                self.scratch = vec![0u8; needed];
                self.scratch_cap = needed;
            }
            for y in 0..eh {
                let src = &bgra[y * row_pitch..y * row_pitch + tight_pitch];
                let dst = &mut self.scratch[y * tight_pitch..(y + 1) * tight_pitch];
                dst.copy_from_slice(src);
            }
            &self.scratch[..needed]
        } else {
            bgra
        };

        let bgra_src = BgraSliceU8::new(data, (ew, eh));
        let yuv = YUVBuffer::from_bgra8_source(bgra_src);
        let bitstream = self.inner.encode(&yuv)?;
        Ok(bitstream.to_vec())
    }

    /// Forces the next encoded frame to be an IDR (keyframe).
    pub fn force_keyframe(&mut self) {
        self.inner.force_intra_frame();
    }

    /// Encodes a pre-converted I420 frame (skips the BGRA conversion).
    ///
    /// Useful for benchmarking and for feeding frames that were converted on
    /// another thread.
    pub fn encode_yuv(&mut self, yuv: &YUVBuffer) -> Result<Vec<u8>, openh264::Error> {
        let bitstream = self.inner.encode(yuv)?;
        Ok(bitstream.to_vec())
    }
}

/// Finds an Annex-B start code (`00 00 01` or `00 00 00 01`) at or after
/// `from`, returning its index and length.
fn find_start_code(data: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut i = from;
    while i + 3 < data.len() {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 0 && data[i + 3] == 1 {
            return Some((i, 4));
        }
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            return Some((i, 3));
        }
        i += 1;
    }
    None
}

/// Splits an Annex-B byte stream into NAL units, each including its start code.
pub fn annexb_nals(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let Some((mut pos, mut len)) = find_start_code(data, 0) else {
        return out;
    };
    loop {
        let Some((next, next_len)) = find_start_code(data, pos + len) else {
            out.push(data[pos..].to_vec());
            break;
        };
        out.push(data[pos..next].to_vec());
        pos = next;
        len = next_len;
    }
    out
}

/// Strips the Annex-B start code prefix from a NAL.
pub fn strip_start_code(nal: &[u8]) -> &[u8] {
    if nal.len() > 4 && nal[..4] == [0, 0, 0, 1] {
        return &nal[4..];
    }
    if nal.len() > 3 && nal[..3] == [0, 0, 1] {
        return &nal[3..];
    }
    nal
}

/// Extracts the raw SPS and PPS NALs (start codes stripped) from an Annex-B
/// stream. Returns `None` if either is missing.
pub fn extract_sps_pps(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut sps = None;
    let mut pps = None;
    for nal in annexb_nals(data) {
        let raw = strip_start_code(&nal);
        if raw.is_empty() {
            continue;
        }
        match raw[0] & 0x1f {
            7 => sps = Some(raw.to_vec()),
            8 => pps = Some(raw.to_vec()),
            _ => {}
        }
    }
    Some((sps?, pps?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_bgra(width: usize, height: usize) -> Vec<u8> {
        let mut bgra = vec![0u8; width * height * 4];
        for y in 0..height {
            for x in 0..width {
                let i = (y * width + x) * 4;
                bgra[i] = (x * 7) as u8; // B
                bgra[i + 1] = (y * 13) as u8; // G
                bgra[i + 2] = ((x + y) * 3) as u8; // R
                bgra[i + 3] = 255; // A
            }
        }
        bgra
    }

    #[test]
    fn encodes_synthetic_frame() {
        let mut enc = OpenH264Encoder::new(OpenH264Config::default()).expect("init");
        let frame = test_bgra(64, 64);
        let bytes = enc.encode_bgra(&frame, 64, 64, 64 * 4).expect("encode");

        // Annex-B output: starts with a start code, and carries SPS+PPS.
        assert!(bytes.len() > 16, "expected a real bitstream, got {} bytes", bytes.len());
        assert!(find_start_code(&bytes, 0).is_some(), "expected Annex-B start code");
        let (sps, pps) = extract_sps_pps(&bytes).expect("SPS+PPS on first frame");
        assert_eq!(sps[0] & 0x1f, 7);
        assert_eq!(pps[0] & 0x1f, 8);

        // Second frame must encode too (delta frame).
        let bytes2 = enc.encode_bgra(&frame, 64, 64, 64 * 4).expect("encode 2");
        assert!(!bytes2.is_empty());
    }

    #[test]
    fn crops_odd_dimensions() {
        let mut enc = OpenH264Encoder::new(OpenH264Config::default()).expect("init");
        // 63x65 with a padded row pitch of 64*4: must crop to 62x64 and
        // de-pad without panicking.
        let w = 63usize;
        let h = 65usize;
        let pitch = 64 * 4;
        let mut padded = vec![0u8; pitch * h];
        for y in 0..h {
            let row = &mut padded[y * pitch..y * pitch + w * 4];
            row.copy_from_slice(&test_bgra(w, 1)[..w * 4]);
        }
        let bytes = enc.encode_bgra(&padded, w, h, pitch).expect("encode");
        assert!(find_start_code(&bytes, 0).is_some());
    }

    #[test]
    fn pitch_depadding_matches_tight() {
        let mut a = OpenH264Encoder::new(OpenH264Config::default()).expect("init");
        let mut b = OpenH264Encoder::new(OpenH264Config::default()).expect("init");
        let frame = test_bgra(64, 32);

        let tight = a.encode_bgra(&frame, 64, 32, 64 * 4).expect("tight");
        // Same pixels, pitch padded to 320 bytes/row (64*4 + 64 slack).
        let pitch = 320usize;
        let mut padded = vec![0u8; pitch * 32];
        for y in 0..32 {
            padded[y * pitch..y * pitch + 64 * 4].copy_from_slice(&frame[y * 64 * 4..(y + 1) * 64 * 4]);
        }
        let depadded = b.encode_bgra(&padded, 64, 32, pitch).expect("padded");
        assert_eq!(tight, depadded, "pitch de-padding must not change output");
    }

    #[test]
    fn keyframe_forcing_emits_idr() {
        let mut enc = OpenH264Encoder::new(OpenH264Config::default()).expect("init");
        let frame = test_bgra(32, 32);
        enc.encode_bgra(&frame, 32, 32, 32 * 4).expect("first");
        enc.force_keyframe();
        let bytes = enc.encode_bgra(&frame, 32, 32, 32 * 4).expect("key");
        let types: Vec<u8> = annexb_nals(&bytes)
            .iter()
            .map(|n| strip_start_code(n)[0] & 0x1f)
            .filter(|t| *t == 5 || *t == 1)
            .collect();
        assert!(types.contains(&5), "expected an IDR NAL after force_keyframe, got {types:?}");
    }
}
