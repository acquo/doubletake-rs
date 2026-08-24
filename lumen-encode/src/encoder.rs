//! H.264 encoder built on NVENC with D3D11 zero-copy input.
//!
//! The pipeline: DXGI desktop texture → `NvEncRegisterResource` →
//! `NvEncEncodeFrame` (no CPU readback) → `NvEncLockBitstream` → H.264
//! Annex-B bytes.

use crate::nvenc::{
    h264_guid, nvencapi_struct_version, NvEncoder, NvEncoderError, NV_ENC_BUFFER_FORMAT_ARGB,
    NV_ENC_INPUT_IMAGE, NV_ENC_INPUT_RESOURCE_TYPE_DIRECTX, NV_ENC_PIC_FLAG_FORCEIDR,
    NV_ENC_PIC_STRUCT_FRAME, NV_ENC_SUCCESS,
};
use crate::nvenc::nvenc_bindings as nv;
use std::ffi::c_void;
use std::sync::Arc;

/// Baseline H.264 profile GUID.
pub fn baseline_guid() -> nv::GUID {
    nv::GUID {
        Data1: 0x0727bcaa,
        Data2: 0x78c4,
        Data3: 0x4c83,
        Data4: [0x8c, 0x2f, 0xef, 0x3d, 0xff, 0x26, 0x7c, 0x6a],
    }
}

/// Main H.264 profile GUID.
pub fn main_guid() -> nv::GUID {
    nv::GUID {
        Data1: 0x60b5c1d4,
        Data2: 0x67fe,
        Data3: 0x4790,
        Data4: [0x94, 0xd5, 0xc4, 0x72, 0x6d, 0x7b, 0x6e, 0x6d],
    }
}

/// Preset P4 (balanced quality/latency) GUID.
pub fn preset_p4_guid() -> nv::GUID {
    nv::GUID {
        Data1: 0x90a7b826,
        Data2: 0xdf06,
        Data3: 0x4862,
        Data4: [0xb9, 0xd2, 0xcd, 0x6d, 0x73, 0xa0, 0x86, 0x81],
    }
}

/// A ready-to-encode H.264 session bound to a D3D11 device.
pub struct H264Encoder {
    nv: Arc<NvEncoder>,
    session: *mut c_void,
    registered: *mut c_void,
    bitstream: *mut c_void,
    pub width: u32,
    pub height: u32,
    frame_index: u64,
}

impl H264Encoder {
    /// Opens and initializes an H.264 encoder on `device` (ID3D11Device*).
    ///
    /// `buffer_format` must match the registered texture format
    /// (`NV_ENC_BUFFER_FORMAT_ARGB` for B8G8R8A8_UNORM desktops).
    ///
    /// NOTE: a custom `NV_ENC_CONFIG` is currently rejected by the driver on
    /// this machine (0x8 "Unsupported color format" for any non-NULL config,
    /// even "version only"). This looks like a layout mismatch between the
    /// vendored header's NV_ENC_CONFIG and the driver; init therefore relies on
    /// the preset defaults (encodeConfig = NULL). TODO: revisit with the true
    /// official SDK header.
    pub fn new(
        nv: Arc<NvEncoder>,
        device: *mut c_void,
        width: u32,
        height: u32,
        fps: u32,
        _bitrate: u32,
        _buffer_format: u32,
    ) -> Result<Self, NvEncoderError> {
        let session = nv.open_session(device, crate::nvenc::NV_ENC_DEVICE_TYPE_DIRECTX)?;

        let mut init: nv::NV_ENC_INITIALIZE_PARAMS = unsafe { std::mem::zeroed() };
        init.version = nvencapi_struct_version(7) | (1 << 31);
        init.encodeGUID = h264_guid();
        init.presetGUID = preset_p4_guid();
        init.encodeWidth = width;
        init.encodeHeight = height;
        init.darWidth = width;
        init.darHeight = height;
        init.frameRateNum = fps;
        init.frameRateDen = 1;
        init.enableEncodeAsync = 0;
        init.enablePTD = 1;
        init.maxEncodeWidth = width;
        init.maxEncodeHeight = height;
        init.tuningInfo = 3; // ULTRA_LOW_LATENCY
        init.encodeConfig = std::ptr::null_mut(); // preset defaults

        let status = unsafe {
            (nv.api.nvEncInitializeEncoder.expect("nvEncInitializeEncoder"))(session, &mut init)
        };
        if status != NV_ENC_SUCCESS {
            let msg = nv.last_error_string(session);
            let _ = nv.destroy_session(session);
            return Err(NvEncoderError::Other(format!(
                "NvEncInitializeEncoder 0x{status:x}: {msg}"
            )));
        }

        // Bitstream buffer.
        let mut bsb: nv::NV_ENC_CREATE_BITSTREAM_BUFFER = unsafe { std::mem::zeroed() };
        bsb.version = nvencapi_struct_version(1);
        bsb.size = 4 * 1024 * 1024;
        let status = unsafe {
            (nv.api.nvEncCreateBitstreamBuffer.expect("create bitstream"))(session, &mut bsb)
        };
        if status != NV_ENC_SUCCESS {
            let _ = nv.destroy_session(session);
            return Err(NvEncoderError::Status(status as u32));
        }

        Ok(H264Encoder {
            nv,
            session,
            registered: std::ptr::null_mut(),
            bitstream: bsb.bitstreamBuffer,
            width,
            height,
            frame_index: 0,
        })
    }

    /// Registers a D3D11 texture for zero-copy input.
    ///
    /// `texture` is the `*mut c_void` ID3D11Texture2D pointer. Returns the
    /// registered resource handle, or the existing one if already registered.
    pub fn register_texture(&mut self, texture: *mut c_void) -> Result<*mut c_void, NvEncoderError> {
        if !self.registered.is_null() {
            return Ok(self.registered);
        }
        let mut reg: nv::NV_ENC_REGISTER_RESOURCE = unsafe { std::mem::zeroed() };
        reg.version = nvencapi_struct_version(4);
        reg.resourceType = NV_ENC_INPUT_RESOURCE_TYPE_DIRECTX as i32;
        reg.width = self.width;
        reg.height = self.height;
        reg.pitch = 0;
        reg.subResourceIndex = 0;
        reg.resourceToRegister = texture;
        reg.bufferFormat = NV_ENC_BUFFER_FORMAT_ARGB as i32;
        reg.bufferUsage = NV_ENC_INPUT_IMAGE as i32;
        let status = unsafe {
            (self.nv.api.nvEncRegisterResource.expect("register"))(self.session, &mut reg)
        };
        if status != NV_ENC_SUCCESS {
            return Err(NvEncoderError::Status(status as u32));
        }
        self.registered = reg.registeredResource;
        Ok(self.registered)
    }

    /// Encodes one frame from the registered texture and returns the H.264
    /// Annex-B bytes for this frame (may be empty for buffered frames).
    pub fn encode_frame(&mut self, force_idr: bool) -> Result<Vec<u8>, NvEncoderError> {
        let mut pic: nv::NV_ENC_PIC_PARAMS = unsafe { std::mem::zeroed() };
        pic.version = nvencapi_struct_version(6) | (1 << 31);
        pic.inputWidth = self.width;
        pic.inputHeight = self.height;
        pic.inputPitch = 0;
        pic.inputBuffer = self.registered;
        pic.outputBitstream = self.bitstream;
        pic.bufferFmt = NV_ENC_BUFFER_FORMAT_ARGB as i32;
        pic.pictureStruct = NV_ENC_PIC_STRUCT_FRAME as i32;
        pic.frameIdx = (self.frame_index & 0xffff_ffff) as u32;
        pic.inputTimeStamp = self.frame_index;
        pic.inputDuration = 1;
        if force_idr {
            pic.encodePicFlags = NV_ENC_PIC_FLAG_FORCEIDR;
        }
        self.frame_index += 1;

        let status = unsafe {
            (self.nv.api.nvEncEncodePicture.expect("encode picture"))(self.session, &mut pic)
        };
        if status != NV_ENC_SUCCESS {
            return Err(NvEncoderError::Status(status as u32));
        }

        // Lock and drain the bitstream.
        let mut out = Vec::new();
        loop {
            let mut lock: nv::NV_ENC_LOCK_BITSTREAM = unsafe { std::mem::zeroed() };
            lock.version = nvencapi_struct_version(2);
            lock.outputBitstream = self.bitstream;
            lock.set_doNotWait(0);
            let status = unsafe {
                (self.nv.api.nvEncLockBitstream.expect("lock bitstream"))(self.session, &mut lock)
            };
            if status != NV_ENC_SUCCESS {
                return Err(NvEncoderError::Status(status as u32));
            }
            if lock.bitstreamSizeInBytes > 0 && !lock.bitstreamBufferPtr.is_null() {
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        lock.bitstreamBufferPtr as *const u8,
                        lock.bitstreamSizeInBytes as usize,
                    )
                };
                out.extend_from_slice(bytes);
            }
            let status = unsafe {
                (self.nv.api.nvEncUnlockBitstream.expect("unlock bitstream"))(
                    self.session,
                    self.bitstream,
                )
            };
            if status != NV_ENC_SUCCESS {
                return Err(NvEncoderError::Status(status as u32));
            }
            // NV_ENC_ERR_LOCK_BUSY (13) means more output is pending; drain it.
            // With PTD + synchronous encode there is usually exactly one buffer.
            if status == NV_ENC_SUCCESS && out.is_empty() {
                break;
            }
            break;
        }
        Ok(out)
    }

    /// Encodes one frame from `texture`, registering it with NVENC for this
    /// frame and unregistering afterwards. This is the reliable path for
    /// Desktop Duplication, whose surfaces change every frame — a persistent
    /// registered texture + GPU copy can race NVENC and yield stale frames.
    pub fn encode_external_texture(
        &mut self,
        texture: *mut c_void,
        force_idr: bool,
    ) -> Result<Vec<u8>, NvEncoderError> {
        let mut reg: nv::NV_ENC_REGISTER_RESOURCE = unsafe { std::mem::zeroed() };
        reg.version = nvencapi_struct_version(4);
        reg.resourceType = NV_ENC_INPUT_RESOURCE_TYPE_DIRECTX as i32;
        reg.width = self.width;
        reg.height = self.height;
        reg.pitch = 0;
        reg.subResourceIndex = 0;
        reg.resourceToRegister = texture;
        reg.bufferFormat = NV_ENC_BUFFER_FORMAT_ARGB as i32;
        reg.bufferUsage = NV_ENC_INPUT_IMAGE as i32;
        let status = unsafe {
            (self.nv.api.nvEncRegisterResource.expect("register"))(self.session, &mut reg)
        };
        if status != NV_ENC_SUCCESS {
            self.registered = std::ptr::null_mut();
            return Err(NvEncoderError::Status(status as u32));
        }
        self.registered = reg.registeredResource;

        let bytes = self.encode_frame(force_idr);

        // Unregister this frame's resource so the next frame can register a
        // fresh one (Desktop Duplication hands us a new surface each frame).
        let status = unsafe {
            (self.nv.api.nvEncUnregisterResource.expect("unregister"))(
                self.session,
                self.registered,
            )
        };
        self.registered = std::ptr::null_mut();
        if status != NV_ENC_SUCCESS {
            return Err(NvEncoderError::Status(status as u32));
        }
        bytes
    }

    /// Requests an IDR (keyframe) on the next encode.
    pub fn request_keyframe(&mut self) {
        self.frame_index += 1; // force_idr handled by caller via encode_frame(true)
    }
}

impl Drop for H264Encoder {
    fn drop(&mut self) {
        unsafe {
            if !self.registered.is_null() {
                (self.nv.api.nvEncUnregisterResource.expect("unregister"))(
                    self.session,
                    self.registered,
                );
            }
            if !self.bitstream.is_null() {
                (self.nv.api.nvEncDestroyBitstreamBuffer.expect("destroy bsb"))(
                    self.session,
                    self.bitstream,
                );
            }
            self.nv.destroy_session(self.session);
        }
    }
}
