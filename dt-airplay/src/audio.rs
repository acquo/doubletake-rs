//! AirPlay audio: ALAC "verbatim" frame encoding + RTP audio streaming.
//!
//! Ported from upstream `audio.go`. Audio travels over UDP RTP (payload type
//! 96) with the raw ALAC frame as payload; a separate control port carries
//! periodic NTP TimeAnnounce sync packets that map the RTP clock onto the
//! network clock so the receiver can sync audio with video.

use crate::error::{Error, Result};
use std::io::Error as IoError;
use std::net::{SocketAddr, UdpSocket};

/// Samples per ALAC frame (matches the SETUP stream descriptor `spf`).
pub const SPF: u32 = 352;
/// RTP payload type for AirPlay mirroring audio (Apple senders never set M).
pub const RTP_PAYLOAD_TYPE: u8 = 96;
/// Sync packet payload type for legacy NTP timing sessions.
pub const AUDIO_SYNC_PAYLOAD_TYPE_NTP: u8 = 0xd4;

/// Encodes interleaved S16LE stereo PCM as an ALAC "verbatim" (uncompressed)
/// frame: a minimal bit-level element header followed by the raw samples.
///
/// Frame layout (stereo, 16-bit), MSB-first bitstream:
/// ```text
/// tag(3)     = 1  (TYPE_CPE for stereo, 0 = TYPE_SCE mono)
/// elementInstance(4) = 0
/// unused(12) = 0
/// hasSize(1) = 1  (include 32-bit sample count)
/// extraBytes(2) = 0 (16-bit, no shift)
/// verbatim(1) = 1
/// numSamples(32) = frame_size
/// per sample: left(16) BE, right(16) BE
/// endTag(3)  = 7  (TYPE_END)
/// ```
pub fn encode_alac_verbatim(pcm: &[i16], frame_size: usize, channels: usize) -> Vec<u8> {
    // Element header (23 bits) + numSamples (32) + samples + end tag (3).
    let max_bits = 23 + 32 + frame_size * channels * 16 + 3;
    let mut out = vec![0u8; max_bits / 8 + 1];
    let mut bw = BitWriter::new(&mut out);

    bw.write(if channels == 2 { 1 } else { 0 }, 3); // element type
    bw.write(0, 4); // elementInstanceTag
    bw.write(0, 12); // unused
    bw.write(1, 1); // hasSize
    bw.write(0, 2); // extraBytes (16-bit)
    bw.write(1, 1); // verbatim
    bw.write(frame_size as u32, 32); // numSamples

    for &sample in pcm.iter().take(frame_size * channels) {
        bw.write(sample as u16 as u32, 16);
    }
    bw.write(7, 3); // TYPE_END

    let n = bw.flush();
    drop(bw);
    out.truncate(n);
    out
}

/// MSB-first bit writer (port of Go `bitWriter`).
struct BitWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
    bit_buf: u32,
    bit_pos: usize,
}

impl<'a> BitWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        BitWriter {
            buf,
            pos: 0,
            bit_buf: 0,
            bit_pos: 0,
        }
    }

    fn write(&mut self, val: u32, mut nbits: u32) {
        let mut val = val & if nbits == 32 { u32::MAX } else { (1u32 << nbits) - 1 };
        while nbits > 0 {
            let space = (8 - self.bit_pos) as u32;
            if nbits <= space {
                self.bit_buf |= (val & ((1u32 << nbits) - 1)) << (space - nbits);
                self.bit_pos += nbits as usize;
                if self.bit_pos == 8 {
                    self.buf[self.pos] = self.bit_buf as u8;
                    self.pos += 1;
                    self.bit_buf = 0;
                    self.bit_pos = 0;
                }
                return;
            }
            let shift = nbits - space;
            self.bit_buf |= (val >> shift) & ((1u32 << space) - 1);
            self.buf[self.pos] = self.bit_buf as u8;
            self.pos += 1;
            self.bit_buf = 0;
            self.bit_pos = 0;
            nbits = shift;
            val &= (1u32 << shift) - 1;
        }
    }

    fn flush(&mut self) -> usize {
        if self.bit_pos > 0 {
            self.buf[self.pos] = self.bit_buf as u8;
            self.pos += 1;
        }
        self.pos
    }
}

/// The RTP audio channel to the receiver.
pub struct AudioStream {
    data_socket: UdpSocket,
    ctrl_socket: UdpSocket,
    remote_data: SocketAddr,
    remote_ctrl: SocketAddr,
    /// Audio latency in samples (sync packets announce the position `latency`
    /// samples before `rtp_time`).
    latency_samples: u32,
    /// Current RTP timestamp (44.1 kHz clock).
    pub rtp_time: u32,
}

impl AudioStream {
    /// Creates the audio stream state bound to the local data/control sockets.
    pub fn new(
        host: &str,
        data_port: u16,
        ctrl_port: u16,
        data_socket: UdpSocket,
        ctrl_socket: UdpSocket,
        latency_samples: u32,
    ) -> Result<Self> {
        let remote_data = format!("{host}:{data_port}")
            .parse()
            .map_err(|e| Error::Protocol(format!("invalid audio data addr: {e}")))?;
        let remote_ctrl = format!("{host}:{ctrl_port}")
            .parse()
            .map_err(|e| Error::Protocol(format!("invalid audio ctrl addr: {e}")))?;
        Ok(AudioStream {
            data_socket,
            ctrl_socket,
            remote_data,
            remote_ctrl,
            latency_samples,
            rtp_time: 0,
        })
    }

    /// Sends one RTP audio packet: 12-byte header (PT=96, SSRC=0) + the raw
    /// ALAC frame payload.
    pub fn send_frame(&mut self, payload: &[u8], rtp_time: u32, seq: u16) -> Result<()> {
        let mut pkt = Vec::with_capacity(12 + payload.len());
        pkt.push(0x80);
        pkt.push(RTP_PAYLOAD_TYPE);
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&rtp_time.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes()); // SSRC = 0 (Apple mirroring)
        pkt.extend_from_slice(payload);
        self.data_socket
            .send_to(&pkt, self.remote_data)
            .map_err(|e| Error::from_io("audio rtp send", e))?;
        // Advance the clock only forward (modular, like upstream); retransmits
        // carry old timestamps and must not move the position backwards.
        if (rtp_time.wrapping_sub(self.rtp_time) as i32) >= 0 {
            self.rtp_time = rtp_time;
        }
        Ok(())
    }

    /// Sends an NTP TimeAnnounce sync packet on the control port (legacy
    /// receivers). The first announce sets the reset bit (0x90).
    pub fn send_sync_packet(&mut self, network_time: u64, is_first: bool) -> Result<()> {
        let mut pkt = [0u8; 20];
        pkt[0] = if is_first { 0x90 } else { 0x80 };
        pkt[1] = AUDIO_SYNC_PAYLOAD_TYPE_NTP;
        pkt[2..4].copy_from_slice(&4u16.to_be_bytes()); // constant seq in captures
        let sync_rtp = self.rtp_time.wrapping_sub(self.latency_samples);
        pkt[4..8].copy_from_slice(&sync_rtp.to_be_bytes());
        pkt[8..16].copy_from_slice(&network_time.to_be_bytes());
        pkt[16..20].copy_from_slice(&self.rtp_time.to_be_bytes());
        self.ctrl_socket
            .send_to(&pkt, self.remote_ctrl)
            .map_err(|e| Error::from_io("audio sync send", e))?;
        Ok(())
    }

    /// Reads one pending control packet (resend requests), draining the
    /// socket non-blockingly. Returns the packet bytes if any.
    pub fn drain_control(&self) -> Option<Vec<u8>> {
        let mut buf = [0u8; 1024];
        loop {
            match self.ctrl_socket.recv_from(&mut buf) {
                Ok((n, _)) => {
                    log::debug!("audio control packet: {} bytes", n);
                    // Receivers rarely request resends over UDP; ignored.
                    if n == 0 {
                        return None;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => return None,
                Err(_) => return None,
            }
        }
    }

    /// Configures the control socket for non-blocking reads.
    pub fn set_ctrl_nonblocking(&self) -> Result<()> {
        self.ctrl_socket
            .set_nonblocking(true)
            .map_err(|e| Error::from_io("audio ctrl nonblocking", e))?;
        Ok(())
    }
}

impl From<IoError> for Error {
    fn from(e: IoError) -> Self {
        Error::from_io("audio", e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbatim_header_and_samples() {
        // Two frames of silence, stereo. Expected bytes verified against the
        // upstream Go `encodeALACVerbatim` output (run from audio.go):
        //   20 00 12 00 00 00 04 00 00 00 00 00 00 00 01 c0
        let pcm = vec![0i16; 2 * 2];
        let frame = encode_alac_verbatim(&pcm, 2, 2);
        assert_eq!(
            frame,
            vec![0x20, 0x00, 0x12, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc0]
        );
    }

    #[test]
    fn verbatim_known_sample() {
        // One frame: left = 0x1234, right = 0x5678. Expected bytes verified
        // against the upstream Go output (S16LE input 34 12 78 56):
        //   20 00 12 00 00 00 02 24 68 ac f1 c0
        let pcm = [0x1234i16, 0x5678i16];
        let frame = encode_alac_verbatim(&pcm, 1, 2);
        assert_eq!(frame, vec![0x20, 0x00, 0x12, 0x00, 0x00, 0x00, 0x02, 0x24, 0x68, 0xac, 0xf1, 0xc0]);
    }

    #[test]
    fn rtp_packet_layout() {
        let (data, ctrl) = (UdpSocket::bind("127.0.0.1:0").unwrap(), UdpSocket::bind("127.0.0.1:0").unwrap());
        let (rx_data, rx_ctrl) = (UdpSocket::bind("127.0.0.1:0").unwrap(), UdpSocket::bind("127.0.0.1:0").unwrap());
        let mut as_ = AudioStream::new(
            "127.0.0.1",
            rx_data.local_addr().unwrap().port(),
            rx_ctrl.local_addr().unwrap().port(),
            data,
            ctrl,
            100,
        )
        .unwrap();
        as_.set_ctrl_nonblocking().unwrap();

        let payload = [0xde, 0xad, 0xbe, 0xef];
        as_.send_frame(&payload, 12345, 7).unwrap();
        let mut buf = [0u8; 64];
        let (n, _) = rx_data.recv_from(&mut buf).unwrap();
        assert_eq!(n, 16);
        assert_eq!(buf[0], 0x80);
        assert_eq!(buf[1], 96);
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 7);
        assert_eq!(u32::from_be_bytes(buf[4..8].try_into().unwrap()), 12345);
        assert_eq!(u32::from_be_bytes(buf[8..12].try_into().unwrap()), 0);
        assert_eq!(&buf[12..16], &payload);

        // Sync packet: 20 bytes, reset bit on first.
        as_.send_sync_packet(0x1122334455667788, true).unwrap();
        let (n, _) = rx_ctrl.recv_from(&mut buf).unwrap();
        assert_eq!(n, 20);
        assert_eq!(buf[0], 0x90);
        assert_eq!(buf[1], 0xd4);
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 4);
        assert_eq!(u32::from_be_bytes(buf[4..8].try_into().unwrap()), 12345 - 100);
        assert_eq!(u64::from_be_bytes(buf[8..16].try_into().unwrap()), 0x1122334455667788);
        assert_eq!(u32::from_be_bytes(buf[16..20].try_into().unwrap()), 12345);
    }
}
