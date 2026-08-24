//! H.264 stream parsing helpers, ported from `mirror.go`.
//!
//! Incremental Annex-B / AVCC NAL extraction, SPS dimension parsing, and the
//! AVCDecoderConfigurationRecord (avcC) builder.

/// Extracts NAL units from an Annex-B stream incrementally. Returns units
/// including their start codes (matching the Go parser's output).
pub struct H264Parser {
    buf: Vec<u8>,
}

impl H264Parser {
    pub fn new() -> Self {
        H264Parser {
            buf: Vec::with_capacity(512 * 1024),
        }
    }

    pub fn push(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        self.buf.extend_from_slice(data);
        if has_start_code(&self.buf) {
            self.push_annex_b()
        } else {
            self.push_avcc()
        }
    }

    fn push_annex_b(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let Some(start) = find_start_code(&self.buf, 0) else {
                if self.buf.len() > 1024 * 1024 {
                    let keep = self.buf.len() - 128 * 1024;
                    self.buf.drain(..keep);
                }
                break;
            };
            let Some(next) = find_start_code(&self.buf, start + 3) else {
                if start > 0 {
                    self.buf.drain(..start);
                }
                break;
            };
            out.push(self.buf[start..next].to_vec());
            self.buf.drain(..next);
        }
        out
    }

    fn push_avcc(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 4 {
                break;
            }
            let nal_len =
                u32::from_be_bytes(self.buf[..4].try_into().expect("4 bytes")) as usize;
            if nal_len == 0 || nal_len > 16 * 1024 * 1024 {
                self.buf.clear();
                break;
            }
            if self.buf.len() < 4 + nal_len {
                break;
            }
            let mut nal = vec![0u8; 4 + nal_len];
            nal[..4].copy_from_slice(&1u32.to_be_bytes());
            nal[4..].copy_from_slice(&self.buf[4..4 + nal_len]);
            out.push(nal);
            self.buf.drain(..4 + nal_len);
        }
        out
    }
}

pub fn has_start_code(b: &[u8]) -> bool {
    find_start_code(b, 0).is_some()
}

pub fn find_start_code(b: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 3 < b.len() {
        if b[i] == 0x00 && b[i + 1] == 0x00 {
            if b[i + 2] == 0x01 {
                return Some(i);
            }
            if i + 3 < b.len() && b[i + 2] == 0x00 && b[i + 3] == 0x01 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Strips the Annex-B start code prefix.
pub fn strip_start_code(nal: &[u8]) -> &[u8] {
    if nal.len() > 4 && nal[..4] == [0, 0, 0, 1] {
        return &nal[4..];
    }
    if nal.len() > 3 && nal[..3] == [0, 0, 1] {
        return &nal[3..];
    }
    nal
}

/// Prepends a 4-byte big-endian length (AVCC format).
pub fn avcc_wrap(raw: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(4 + raw.len());
    b.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    b.extend_from_slice(raw);
    b
}

/// H.264 NAL unit type from a NAL that may begin with a start code.
pub fn nal_type(nal: &[u8]) -> u8 {
    let mut i = 0;
    while i + 1 < nal.len() {
        if nal[i] == 0x01 && i >= 2 && nal[i - 1] == 0x00 && nal[i - 2] == 0x00 {
            if i + 1 < nal.len() {
                return nal[i + 1] & 0x1f;
            }
        }
        i += 1;
    }
    0
}

/// True if the raw NAL (without start code) is the first slice of a new
/// access unit (first_mb_in_slice == 0).
pub fn is_first_slice(raw: &[u8]) -> bool {
    raw.len() >= 2 && raw[1] & 0x80 != 0
}

/// Builds an AVCDecoderConfigurationRecord (avcC) from raw SPS and PPS,
/// including the 4-byte trailer observed in iPhone captures.
pub fn build_avcc_config(sps: &[u8], pps: &[u8]) -> Vec<u8> {
    let avcc_len = 6 + 2 + sps.len() + 1 + 2 + pps.len();
    let mut payload = vec![0u8; avcc_len + 4];
    payload[0] = 0x01; // configurationVersion
    payload[1] = sps[1]; // AVCProfileIndication
    payload[2] = sps[2]; // profile_compatibility
    payload[3] = sps[3]; // AVCLevelIndication
    payload[4] = 0xff; // lengthSizeMinusOne = 3
    payload[5] = 0xe1; // numSequenceParameterSets = 1
    payload[6..8].copy_from_slice(&(sps.len() as u16).to_be_bytes());
    payload[8..8 + sps.len()].copy_from_slice(sps);
    let off = 8 + sps.len();
    payload[off] = 0x01; // numPictureParameterSets = 1
    payload[off + 1..off + 3].copy_from_slice(&(pps.len() as u16).to_be_bytes());
    payload[off + 3..off + 3 + pps.len()].copy_from_slice(pps);
    payload[avcc_len] = 0x02; // trailer
    payload
}

/// Parses an H.264 SPS NAL (raw, including the 1-byte NAL header, without a
/// start code) and returns the coded picture width and height. Assumes 4:2:0.
pub fn sps_dimensions(sps: &[u8]) -> Option<(u32, u32)> {
    if sps.len() < 4 || sps[0] & 0x1f != 7 {
        return None;
    }
    let rbsp = strip_emulation_prevention(&sps[1..]);
    let mut r = BitReader::new(&rbsp);

    let profile_idc = r.read_bits(8)?;
    r.read_bits(8)?; // constraint flags + reserved
    r.read_bits(8)?; // level_idc
    r.read_ue()?; // seq_parameter_set_id

    match profile_idc {
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135 => {
            let chroma_format_idc = r.read_ue()?;
            if chroma_format_idc == 3 {
                r.read_bit()?; // separate_colour_plane_flag
            }
            r.read_ue()?; // bit_depth_luma_minus8
            r.read_ue()?; // bit_depth_chroma_minus8
            r.read_bit()?; // qpprime_y_zero_transform_bypass_flag
            if r.read_bit()? == 1 {
                let n = if chroma_format_idc == 3 { 12 } else { 8 };
                for i in 0..n {
                    if r.read_bit()? == 1 {
                        let size = if i >= 6 { 64 } else { 16 };
                        let mut last_scale = 8i64;
                        let mut next_scale = 8i64;
                        for _ in 0..size {
                            if next_scale != 0 {
                                next_scale = (last_scale + r.read_se()? + 256) % 256;
                            }
                            if next_scale != 0 {
                                last_scale = next_scale;
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    r.read_ue()?; // log2_max_frame_num_minus4
    let pic_order_cnt_type = r.read_ue()?;
    if pic_order_cnt_type == 0 {
        r.read_ue()?; // log2_max_pic_order_cnt_lsb_minus4
    } else if pic_order_cnt_type == 1 {
        r.read_bit()?; // delta_pic_order_always_zero_flag
        r.read_se()?; // offset_for_non_ref_pic
        r.read_se()?; // offset_for_top_to_bottom_field
        let n = r.read_ue()?;
        for _ in 0..n {
            r.read_se()?;
        }
    }
    r.read_ue()?; // max_num_ref_frames
    r.read_bit()?; // gaps_in_frame_num_value_allowed_flag

    let pic_width_in_mbs_minus1 = r.read_ue()?;
    let pic_height_in_map_units_minus1 = r.read_ue()?;
    let frame_mbs_only_flag = r.read_bit()?;
    if frame_mbs_only_flag == 0 {
        r.read_bit()?; // mb_adaptive_frame_field_flag
    }
    r.read_bit()?; // direct_8x8_inference_flag

    let mut crop_left = 0u64;
    let mut crop_right = 0u64;
    let mut crop_top = 0u64;
    let mut crop_bottom = 0u64;
    if r.read_bit()? == 1 {
        crop_left = r.read_ue()?;
        crop_right = r.read_ue()?;
        crop_top = r.read_ue()?;
        crop_bottom = r.read_ue()?;
    }
    if r.err {
        return None;
    }

    let w = (pic_width_in_mbs_minus1 + 1) * 16;
    let h = (2 - frame_mbs_only_flag as u64) * (pic_height_in_map_units_minus1 + 1) * 16;
    let crop_unit_x = 2u64;
    let crop_unit_y = 2u64 * (2 - frame_mbs_only_flag as u64);
    let w = w.saturating_sub((crop_left + crop_right) * crop_unit_x);
    let h = h.saturating_sub((crop_top + crop_bottom) * crop_unit_y);
    if w == 0 || h == 0 {
        return None;
    }
    Some((w as u32, h as u32))
}

/// Removes H.264 emulation prevention bytes (00 00 03 → 00 00).
fn strip_emulation_prevention(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut zeros = 0;
    let mut i = 0;
    while i < b.len() {
        if zeros >= 2 && b[i] == 0x03 && i + 1 < b.len() && b[i + 1] <= 0x03 {
            zeros = 0;
            i += 1;
            continue;
        }
        if b[i] == 0 {
            zeros += 1;
        } else {
            zeros = 0;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// Bit reader over an RBSP byte slice.
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    err: bool,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader { data, pos: 0, err: false }
    }

    fn read_bit(&mut self) -> Option<u64> {
        if self.pos >= self.data.len() * 8 {
            self.err = true;
            return None;
        }
        let b = self.data[self.pos >> 3];
        let bit = (b >> (7 - (self.pos & 7))) & 1;
        self.pos += 1;
        Some(bit as u64)
    }

    fn read_bits(&mut self, n: usize) -> Option<u64> {
        let mut v = 0u64;
        for _ in 0..n {
            v = (v << 1) | self.read_bit()?;
        }
        Some(v)
    }

    /// Unsigned Exp-Golomb.
    fn read_ue(&mut self) -> Option<u64> {
        let mut zeros = 0;
        loop {
            match self.read_bit() {
                Some(0) => zeros += 1,
                Some(_) => break,
                None => return None,
            }
            if zeros > 31 {
                self.err = true;
                return None;
            }
        }
        if zeros == 0 {
            return Some(0);
        }
        let rest = self.read_bits(zeros)?;
        Some((1u64 << zeros) - 1 + rest)
    }

    /// Signed Exp-Golomb.
    fn read_se(&mut self) -> Option<i64> {
        let k = self.read_ue()?;
        if k & 1 != 0 {
            Some(((k + 1) / 2) as i64)
        } else {
            Some(-((k / 2) as i64))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn annex_b_parsing() {
        // 00 00 00 01 [type 7 SPS] 00 00 01 [type 8 PPS] 00 00 01 [type 5 IDR]
        // plus a trailing filler NAL so the IDR is flushed (the parser only
        // returns NALs whose end start code has been seen).
        let mut stream = vec![0u8; 0];
        stream.extend_from_slice(&[0, 0, 0, 1, 0x67, 1, 2, 3]);
        stream.extend_from_slice(&[0, 0, 1, 0x68, 4, 5]);
        stream.extend_from_slice(&[0, 0, 1, 0x65, 6, 7, 8]);
        stream.extend_from_slice(&[0, 0, 1, 0x61, 0]);

        let mut parser = H264Parser::new();
        let nals = parser.push(&stream);
        assert_eq!(nals.len(), 3);
        assert_eq!(nal_type(&nals[0]), 7);
        assert_eq!(nal_type(&nals[1]), 8);
        assert_eq!(nal_type(&nals[2]), 5);
        assert_eq!(strip_start_code(&nals[0]), &[0x67, 1, 2, 3]);
    }

    #[test]
    fn avcc_parsing() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&3u32.to_be_bytes());
        stream.extend_from_slice(&[0x65, 1, 2]);
        let mut parser = H264Parser::new();
        let nals = parser.push(&stream);
        assert_eq!(nals.len(), 1);
        // AVCC parser re-wraps with 4-byte length prefix.
        assert_eq!(strip_start_code(&nals[0]), &[0x65, 1, 2]);
    }

    #[test]
    fn avcc_config_builder() {
        let sps = [0x67, 0x42, 0xc0, 0x1e, 0xda, 0x02, 0x80, 0xb7];
        let pps = [0x68, 0xce, 0x06, 0xe2];
        let avcc = build_avcc_config(&sps, &pps);
        assert_eq!(avcc[0], 0x01);
        assert_eq!(avcc[1], sps[1]);
        assert_eq!(avcc[4], 0xff);
        assert_eq!(avcc[5], 0xe1);
        // SPS length field.
        assert_eq!(u16::from_be_bytes(avcc[6..8].try_into().unwrap()) as usize, sps.len());
        // 4-byte trailer: 02 00 00 00.
        assert_eq!(avcc[avcc.len() - 4], 0x02);
        assert_eq!(&avcc[avcc.len() - 3..], &[0, 0, 0]);
    }

    #[test]
    fn sps_dimensions_basic() {
        // Real 1920x1080 baseline SPS captured from ffmpeg/libx264.
        let sps = hex::decode("6742c028d900780227e5c044000003000400000300083c60c92000").unwrap();
        let (w, h) = sps_dimensions(&sps).expect("parse sps");
        assert_eq!((w, h), (1920, 1080));
    }
}
