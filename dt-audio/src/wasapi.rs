//! WASAPI loopback capture via the `windows` crate.
//!
//! Requests 44.1 kHz / 16-bit / stereo from the audio engine (Windows 10+
//! shared mode resamples to the endpoint's mix format automatically); when
//! the engine rejects that format, falls back to the device mix format and
//! resamples to 44.1 kHz in software with linear interpolation.

use std::sync::mpsc::{channel, Receiver, Sender};
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::Media::Audio::{
    eConsole, eRender, AUDCLNT_BUFFERFLAGS_SILENT, AUDCLNT_SHAREMODE_SHARED,
    AUDCLNT_STREAMFLAGS_EVENTCALLBACK, AUDCLNT_STREAMFLAGS_LOOPBACK, IAudioCaptureClient,
    IAudioClient, IMMDeviceEnumerator, MMDeviceEnumerator, WAVEFORMATEX, WAVEFORMATEXTENSIBLE,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, CLSCTX_ALL,
    COINIT_MULTITHREADED,
};
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};

/// KSDATAFORMAT_SUBTYPE_PCM
const SUBTYPE_PCM: windows::core::GUID =
    windows::core::GUID::from_u128(0x00000001_0000_0010_8000_00aa00389b71);
/// KSDATAFORMAT_SUBTYPE_IEEE_FLOAT
const SUBTYPE_IEEE_FLOAT: windows::core::GUID =
    windows::core::GUID::from_u128(0x00000003_0000_0010_8000_00aa00389b71);

pub const SAMPLE_RATE: u32 = 44100;
pub const CHANNELS: usize = 2;
/// Samples per ALAC frame (matches the AirPlay `spf` descriptor).
pub const FRAME_SAMPLES: usize = 352;

const WAVE_FORMAT_IEEE_FLOAT: u16 = 0x0003;
const WAVE_FORMAT_EXTENSIBLE: u16 = 0xFFFE;

#[derive(Debug, thiserror::Error)]
pub enum AudioError {
    #[error("windows: {0}")]
    Windows(#[from] windows::core::Error),
    #[error("capture thread exited")]
    ThreadGone,
}

/// An open loopback capture. Frames arrive on [`LoopbackCapture::rx`].
pub struct LoopbackCapture {
    rx: Receiver<Vec<i16>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LoopbackCapture {
    /// Receives one frame of `FRAME_SAMPLES * CHANNELS` interleaved i16
    /// (blocking).
    pub fn recv_frame(&self) -> Result<Vec<i16>, AudioError> {
        self.rx.recv().map_err(|_| AudioError::ThreadGone)
    }

    /// Receives one frame if immediately available (non-blocking).
    pub fn try_recv_frame(&self) -> Option<Vec<i16>> {
        self.rx.try_recv().ok()
    }
}

impl Drop for LoopbackCapture {
    fn drop(&mut self) {
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Starts capturing the default render device's loopback output.
pub fn start() -> Result<LoopbackCapture, AudioError> {
    let (tx, rx) = channel();
    let thread = std::thread::Builder::new()
        .name("dt-audio-wasapi".into())
        .spawn(move || {
            if let Err(e) = run(tx) {
                log::error!("WASAPI capture failed: {e}");
            }
        })
        .map_err(|e| AudioError::Windows(windows::core::Error::from(e)))?;
    Ok(LoopbackCapture {
        rx,
        thread: Some(thread),
    })
}

fn run(tx: Sender<Vec<i16>>) -> Result<(), AudioError> {
    unsafe {
        // MTA so the capture thread can drive COM objects directly.
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }
    let result = run_inner(tx);
    unsafe { CoUninitialize() };
    result
}

fn run_inner(tx: Sender<Vec<i16>>) -> Result<(), AudioError> {
    let enumerator: IMMDeviceEnumerator =
        unsafe { CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)? };
    let device = unsafe { enumerator.GetDefaultAudioEndpoint(eRender, eConsole)? };
    let client: IAudioClient = unsafe { device.Activate(CLSCTX_ALL, None)? };

    // Preferred format: 44.1 kHz S16 stereo.
    let mut preferred = WAVEFORMATEXTENSIBLE::default();
    preferred.Format.wFormatTag = WAVE_FORMAT_EXTENSIBLE;
    preferred.Format.nChannels = CHANNELS as u16;
    preferred.Format.nSamplesPerSec = SAMPLE_RATE;
    preferred.Format.wBitsPerSample = 16;
    preferred.Format.nBlockAlign = (CHANNELS * 2) as u16;
    preferred.Format.nAvgBytesPerSec = SAMPLE_RATE * preferred.Format.nBlockAlign as u32;
    preferred.Format.cbSize = 22;
    preferred.Samples.wValidBitsPerSample = 16;
    preferred.dwChannelMask = 0x3; // FL | FR
    preferred.SubFormat = SUBTYPE_PCM;

    // 100 ms buffer, event-driven.
    let hns_buffer: i64 = 1_000_000;
    let flags = AUDCLNT_STREAMFLAGS_LOOPBACK | AUDCLNT_STREAMFLAGS_EVENTCALLBACK;

    let mut use_mix_format = false;
    if unsafe {
        client.Initialize(
            AUDCLNT_SHAREMODE_SHARED,
            flags,
            hns_buffer,
            0,
            &preferred.Format,
            None,
        )
    }
    .is_err()
    {
        log::info!("44.1 kHz shared loopback unsupported; falling back to mix format + software resample");
        use_mix_format = true;
    }

    let mut src_rate = SAMPLE_RATE;
    let mut src_channels = CHANNELS as u16;
    let mut mix_format: Option<MixFormat> = None;

    if use_mix_format {
        let mix = unsafe { client.GetMixFormat()? };
        let fmt = unsafe { &*mix };
        // WAVEFORMATEX is packed(1); copy fields before referencing them.
        let (tag, rate, ch, bits, cb) = unsafe {
            (
                std::ptr::read_unaligned(std::ptr::addr_of!(fmt.wFormatTag)),
                std::ptr::read_unaligned(std::ptr::addr_of!(fmt.nSamplesPerSec)),
                std::ptr::read_unaligned(std::ptr::addr_of!(fmt.nChannels)),
                std::ptr::read_unaligned(std::ptr::addr_of!(fmt.wBitsPerSample)),
                std::ptr::read_unaligned(std::ptr::addr_of!(fmt.cbSize)),
            )
        };
        log::info!(
            "mix format: tag=0x{tag:04x} rate={rate} ch={ch} bits={bits} cb={cb}"
        );
        src_rate = rate;
        src_channels = ch;
        mix_format = Some(MixFormat::from_wave_format(fmt));
        unsafe { client.Initialize(AUDCLNT_SHAREMODE_SHARED, flags, hns_buffer, 0, mix, None)? };
        unsafe { CoTaskMemFree(Some(mix as *const _ as *mut _)) };
    }

    let capture: IAudioCaptureClient = unsafe { client.GetService()? };
    let buffer_frames = unsafe { client.GetBufferSize()? } as usize;

    let event: HANDLE = unsafe { CreateEventW(None, false, false, None)? };
    unsafe { client.SetEventHandle(event)? };

    // Engine gives us exactly 44.1k stereo when the preferred format worked.
    let resample = src_rate != SAMPLE_RATE || src_channels != CHANNELS as u16;
    let mut resampler = StereoResampler::new(src_rate as f64, SAMPLE_RATE as f64);
    let mut out_frames: Vec<i16> = Vec::with_capacity(FRAME_SAMPLES * CHANNELS);

    let mut data_ptr: *mut u8;
    let mut num_frames: u32;
    let mut flags_out: u32;

    log::info!(
        "WASAPI loopback: {} Hz {}ch{} buffer={} frames",
        src_rate,
        src_channels,
        if resample { " (resampling to 44100)" } else { "" },
        buffer_frames
    );

    loop {
        let wait = unsafe { WaitForSingleObject(event, INFINITE) };
        if wait != WAIT_OBJECT_0 {
            break;
        }
        loop {
            data_ptr = std::ptr::null_mut();
            num_frames = 0;
            flags_out = 0;
            let hr = unsafe {
                capture.GetBuffer(
                    &mut data_ptr,
                    &mut num_frames,
                    &mut flags_out,
                    None,
                    None,
                )
            };
            if hr.is_err() {
                break; // empty
            }
            let n = num_frames as usize;
            if n == 0 {
                let _ = unsafe { capture.ReleaseBuffer(0) };
                break;
            }
            let silent = flags_out & AUDCLNT_BUFFERFLAGS_SILENT.0 as u32 != 0;

            if resample {
                let mix = mix_format.as_ref().expect("mix format for resample");
                let mut samples: Vec<f64> = Vec::with_capacity(n * src_channels as usize);
                if silent {
                    samples.resize(n * src_channels as usize, 0.0);
                } else {
                    for i in 0..n {
                        for c in 0..src_channels as usize {
                            let v = mix.read_sample(data_ptr, i, c);
                            samples.push(v);
                        }
                    }
                }
                let stereo = resampler.process_stereo(&samples, src_channels as usize);
                push_frames(&mut out_frames, &stereo, &tx);
            } else {
                if silent {
                    let zeros = vec![0i16; n * CHANNELS];
                    push_frames(&mut out_frames, &zeros, &tx);
                } else {
                    let src = unsafe { std::slice::from_raw_parts(data_ptr as *const i16, n * CHANNELS) };
                    push_frames(&mut out_frames, src, &tx);
                }
            }
            unsafe { capture.ReleaseBuffer(num_frames)? };
        }
    }
    Ok(())
}

/// Splits interleaved samples into fixed `FRAME_SAMPLES`-sample frames.
fn push_frames(out: &mut Vec<i16>, samples: &[i16], tx: &Sender<Vec<i16>>) {
    out.extend_from_slice(samples);
    let frame_len = FRAME_SAMPLES * CHANNELS;
    while out.len() >= frame_len {
        let frame: Vec<i16> = out.drain(..frame_len).collect();
        if tx.send(frame).is_err() {
            return; // receiver gone
        }
    }
}

/// Byte layout of the device mix format.
#[derive(Clone, Copy)]
enum MixFormat {
    F32,
    S16,
    S24,
    S32,
}

impl MixFormat {
    fn from_wave_format(fmt: &WAVEFORMATEX) -> Self {
        if fmt.wFormatTag == WAVE_FORMAT_EXTENSIBLE && fmt.cbSize >= 22 {
            let ext = unsafe { &*(fmt as *const WAVEFORMATEX as *const WAVEFORMATEXTENSIBLE) };
            let sub: windows::core::GUID =
                unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(ext.SubFormat)) };
            if sub == SUBTYPE_IEEE_FLOAT {
                return Self::F32;
            }
        }
        match fmt.wBitsPerSample {
            16 => Self::S16,
            24 => Self::S24,
            32 => {
                if fmt.wFormatTag == WAVE_FORMAT_IEEE_FLOAT {
                    Self::F32
                } else {
                    Self::S32
                }
            }
            _ => Self::S16,
        }
    }

    /// Reads one sample normalized to [-1, 1].
    fn read_sample(&self, data: *const u8, frame: usize, channel: usize) -> f64 {
        match self {
            Self::F32 => {
                let off = (frame * 4 + channel * 4) as isize;
                let v = unsafe { std::ptr::read_unaligned(data.offset(off) as *const f32) };
                v as f64
            }
            Self::S16 => {
                let off = (frame * 2 + channel * 2) as isize;
                let v = unsafe { std::ptr::read_unaligned(data.offset(off) as *const i16) };
                v as f64 / 32768.0
            }
            Self::S24 => {
                // 3-byte little-endian signed.
                let off = (frame * 3 + channel * 3) as isize;
                let b0 = unsafe { *data.offset(off) } as i32;
                let b1 = unsafe { *data.offset(off + 1) } as i32;
                let b2 = unsafe { *data.offset(off + 2) } as i32;
                let v = (b0 | (b1 << 8) | (b2 << 16)) << 8 >> 8; // sign-extend 24-bit
                v as f64 / 8388608.0
            }
            Self::S32 => {
                let off = (frame * 4 + channel * 4) as isize;
                let v = unsafe { std::ptr::read_unaligned(data.offset(off) as *const i32) };
                v as f64 / 2147483648.0
            }
        }
    }
}

/// Linear-interpolation stereo resampler with cross-buffer phase state.
struct StereoResampler {
    src_rate: f64,
    dst_rate: f64,
    phase: f64,
    tail: Option<[f64; 2]>,
}

impl StereoResampler {
    fn new(src_rate: f64, dst_rate: f64) -> Self {
        StereoResampler {
            src_rate,
            dst_rate,
            phase: 0.0,
            tail: None,
        }
    }

    /// `samples` is interleaved with `src_channels`; returns interleaved stereo.
    fn process_stereo(&mut self, samples: &[f64], src_channels: usize) -> Vec<i16> {
        if src_channels == 2 {
            self.process(&samples.to_vec())
        } else {
            // Downmix N channels to stereo (simple average of pairs).
            let mut stereo = Vec::with_capacity(samples.len() / src_channels * 2);
            for chunk in samples.chunks(src_channels) {
                let l = chunk[0];
                let r = chunk.get(1).copied().unwrap_or(l);
                stereo.push(l);
                stereo.push(r);
            }
            self.process(&stereo)
        }
    }

    fn process(&mut self, stereo: &[f64]) -> Vec<i16> {
        let ratio = self.src_rate / self.dst_rate;
        let frames = stereo.len() / 2;
        let mut ext = Vec::with_capacity(stereo.len() + 2);
        if let Some(t) = self.tail {
            ext.extend_from_slice(&t);
        }
        ext.extend_from_slice(stereo);

        let mut out: Vec<i16> = Vec::with_capacity((frames as f64 / ratio) as usize * 2);
        // p = source position in ext (tail offset +1). Safe while p+1 < ext_frames.
        while self.phase + 1.0 < frames as f64 {
            let p = self.phase + 1.0;
            let i0 = p.floor() as usize;
            let frac = p - i0 as f64;
            let l = ext[i0 * 2] * (1.0 - frac) + ext[i0 * 2 + 2] * frac;
            let r = ext[i0 * 2 + 1] * (1.0 - frac) + ext[i0 * 2 + 3] * frac;
            out.push(clamp_i16(l));
            out.push(clamp_i16(r));
            self.phase += ratio;
        }
        self.phase -= frames as f64;
        self.tail = Some([stereo[stereo.len() - 2], stereo[stereo.len() - 1]]);
        out
    }
}

fn clamp_i16(v: f64) -> i16 {
    let v = (v * 32767.0).round();
    v.clamp(-32768.0, 32767.0) as i16
}

// Keep CloseHandle referenced (used implicitly on drop paths if ever needed).
#[allow(dead_code)]
fn close(handle: HANDLE) {
    unsafe {
        let _ = CloseHandle(handle);
    }
}
