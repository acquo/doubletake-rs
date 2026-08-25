//! MediaFoundation H.264 encoder via the Windows H.264 encoder MFT
//! (`CLSID_CMSH264EncoderMFT`). The platform MFT negotiates hardware
//! acceleration automatically — on Intel it rides QSV, on NVIDIA NVENC — so a
//! single backend covers most machines. Input is NV12; output is H.264
//! Annex-B.
//!
//! NOTE: This keeps the input as NV12 on a CPU media buffer (simple + robust).
//! The encode still runs on the GPU via the MFT's internal DXVA negotiation;
//! a future zero-copy DXGI-buffer input can be layered on without changing the
//! public API.

use windows::core::Error as WError;
use windows::Win32::Media::MediaFoundation::{
    CMSH264EncoderMFT, IMFMediaBuffer, IMFMediaType, IMFSample, IMFTransform, MFShutdown, MFStartup,
    MFCreateMediaType, MFCreateMemoryBuffer, MFCreateSample, MFT_OUTPUT_DATA_BUFFER,
    MFMediaType_Video, MFVideoFormat_H264, MFVideoFormat_NV12, MFVideoInterlace_Progressive,
    MF_MT_AVG_BITRATE, MF_MT_FRAME_RATE, MF_MT_FRAME_SIZE, MF_MT_INTERLACE_MODE, MF_MT_MAJOR_TYPE,
    MF_MT_SUBTYPE, MF_VERSION,
};
use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};

#[derive(thiserror::Error, Debug)]
pub enum MfError {
    #[error("COM/MF: {0}")]
    Windows(String),
    #[error("MF encoder produced no output")]
    NoOutput,
    #[error("media type negotiation failed: {0}")]
    MediaType(String),
}

impl From<WError> for MfError {
    fn from(e: WError) -> Self {
        MfError::Windows(e.to_string())
    }
}

const OUTPUT_BUFFER_BYTES: u32 = 8 * 1024 * 1024;

pub struct MediaFoundationEncoder {
    transform: IMFTransform,
    width: u32,
    height: u32,
    frame_index: i64,
    output_sample: Option<IMFSample>,
    initialized: bool,
}

impl MediaFoundationEncoder {
    pub fn new(width: u32, height: u32, fps: u32, bitrate: u32) -> Result<Self, MfError> {
        unsafe {
            MFStartup(MF_VERSION, 0)?;
        }

        let transform: IMFTransform = unsafe {
            CoCreateInstance(&CMSH264EncoderMFT, None, CLSCTX_INPROC_SERVER)?
        };

        // ---- Output media type: H.264 / video / progressive.
        let out_type: IMFMediaType = unsafe { MFCreateMediaType()? };
        unsafe {
            out_type.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            out_type.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)?;
            out_type.SetUINT32(&MF_MT_AVG_BITRATE, bitrate)?;
            out_type.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
            // MF_MT_FRAME_SIZE packs (height << 32) | width (u64).
            out_type.SetUINT64(&MF_MT_FRAME_SIZE, ((height as u64) << 32) | width as u64)?;
            // MF_MT_FRAME_RATE packs (num << 32) | den (u64).
            out_type.SetUINT64(&MF_MT_FRAME_RATE, ((fps as u64) << 32) | 1)?;
            transform.SetOutputType(0, Some(&out_type), 0)?;
        }

        // ---- Input media type: NV12 / video.
        let in_type: IMFMediaType = unsafe { MFCreateMediaType()? };
        unsafe {
            in_type.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            in_type.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)?;
            in_type.SetUINT64(&MF_MT_FRAME_SIZE, ((height as u64) << 32) | width as u64)?;
            in_type.SetUINT64(&MF_MT_FRAME_RATE, ((fps as u64) << 32) | 1)?;
            transform.SetInputType(0, Some(&in_type), 0)?;
        }

        Ok(MediaFoundationEncoder {
            transform,
            width,
            height,
            frame_index: 0,
            output_sample: None,
            initialized: true,
        })
    }

    /// Encodes one NV12 frame (`width*height + width*height/2` bytes).
    pub fn encode_nv12(&mut self, nv12: &[u8], _force_idr: bool) -> Result<Vec<u8>, MfError> {
        let w = self.width as usize;
        let h = self.height as usize;
        let frame_bytes = w * h * 3 / 2;
        if nv12.len() < frame_bytes {
            return Err(MfError::MediaType(format!(
                "nv12 buffer {} bytes, need {frame_bytes}",
                nv12.len()
            )));
        }

        unsafe {
            // Use a simple contiguous memory buffer for NV12 (avoids the D3D
            // aligned pitch that MFCreate2DMediaBuffer imposes).
            let buffer: IMFMediaBuffer = MFCreateMemoryBuffer(frame_bytes as u32)?;
            let mut data_ptr = std::ptr::null_mut();
            let mut max_len = 0u32;
            buffer.Lock(&mut data_ptr, Some(&mut max_len), None)?;
            let dst_len = frame_bytes.min(max_len as usize);
            std::ptr::copy_nonoverlapping(nv12.as_ptr(), data_ptr, dst_len);
            buffer.SetCurrentLength(dst_len as u32)?;
            buffer.Unlock()?;

            let sample: IMFSample = MFCreateSample()?;
            sample.AddBuffer(&buffer)?;
            sample.SetSampleTime(self.frame_index)?;
            sample.SetSampleDuration(1i64)?;
            self.transform.ProcessInput(0, Some(&sample), 0)?;
        }

        self.frame_index += 1;
        self.drain_output()
    }

    fn drain_output(&mut self) -> Result<Vec<u8>, MfError> {
        let mut out = Vec::new();
        unsafe {
            for _ in 0..16 {
                let sample: IMFSample = match &self.output_sample {
                    Some(s) => s.clone(),
                    None => {
                        let s: IMFSample = MFCreateSample()?;
                        let buf: IMFMediaBuffer = MFCreateMemoryBuffer(OUTPUT_BUFFER_BYTES)?;
                        s.AddBuffer(&buf)?;
                        self.output_sample = Some(s.clone());
                        s
                    }
                };
                sample.RemoveAllBuffers()?;
                let buf: IMFMediaBuffer = MFCreateMemoryBuffer(OUTPUT_BUFFER_BYTES)?;
                sample.AddBuffer(&buf)?;

                let mut status = 0u32;
                let mut output = MFT_OUTPUT_DATA_BUFFER::default();
                output.dwStreamID = 0;
                let sample_clone = sample.clone();
                output.pSample = std::mem::ManuallyDrop::new(Some(sample_clone));

                let hr = self
                    .transform
                    .ProcessOutput(0, std::slice::from_mut(&mut output), &mut status);
                if let Err(e) = hr {
                    let code = e.code().0 as u32;
                    // MFT says it needs more input (not enough data). Not fatal.
                    if code == 0x800703E9 || code == 0x80070492 || code == 0x80070057 {
                        break;
                    }
                    return Err(MfError::Windows(e.to_string()));
                }

                if let Some(inner) = std::mem::ManuallyDrop::into_inner(output.pSample).take() {
                    let bytes = read_sample_bytes(&inner)?;
                    if !bytes.is_empty() {
                        out.extend_from_slice(&bytes);
                    }
                }
                // Drain until the MFT reports it has no more output for this input.
                if output.dwStatus == 0 {
                    break;
                }
            }
        }
        Ok(out)
    }
}

impl Drop for MediaFoundationEncoder {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                let _ = MFShutdown();
            }
        }
    }
}

fn read_sample_bytes(sample: &IMFSample) -> Result<Vec<u8>, MfError> {
    unsafe {
        let b = sample.GetBufferByIndex(0)?;
        let mut ptr = std::ptr::null_mut();
        let mut cur = 0u32;
        b.Lock(&mut ptr, None, Some(&mut cur))?;
        let bytes = std::slice::from_raw_parts(ptr as *const u8, cur as usize).to_vec();
        b.Unlock()?;
        Ok(bytes)
    }
}
