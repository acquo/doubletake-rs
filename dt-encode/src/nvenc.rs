//! NVENC FFI wrapper.
//!
//! Bindings are generated from the vendored nv-codec-headers (SDK 12.0.16.0,
//! MIT). The FFmpeg-maintained header omits separate D3D11 device/resource
//! enum values: empirically (driver 591.86) an encode session for a D3D11
//! device opens with `NV_ENC_DEVICE_TYPE_DIRECTX` (0), which in the current
//! SDK denotes a DirectX (D3D11) device.

pub mod nvenc_bindings {
    // Generated bindgen output: silence every lint (transmute hints from
    // newer rustc, unused items, naming style, etc.).
    #![allow(warnings)]
    include!(concat!(env!("OUT_DIR"), "/nvenc_bindings.rs"));
}

use libloading::{Library, Symbol};
use nvenc_bindings as nv;
use std::ffi::c_void;

/// Encode device type for a D3D11 device. The current SDK consolidated D3D11
/// under `DIRECTX` (0); verified empirically against driver 591.86.
pub const NV_ENC_DEVICE_TYPE_DIRECTX: u32 = 0x0;
/// D3D11 input resource type used with `NvEncRegisterResource` (not present
/// in the FFmpeg-reduced header; D3D11 resources register as DIRECTX).
pub const NV_ENC_INPUT_RESOURCE_TYPE_DIRECTX: u32 = 0x0;

// Clean aliases for the bindgen-mangled enum values used by the encoder.
/// Constant bitrate rate control.
pub const NV_ENC_PARAMS_RC_CBR: u32 = 0x2;
/// Variable bitrate rate control.
pub const NV_ENC_PARAMS_RC_VBR: u32 = 0x1;
/// CABAC entropy coding for H.264.
pub const NV_ENC_H264_ENTROPY_CODING_MODE_CABAC: u32 = 0x1;
/// 32-bit BGRA (byte order) input, matches DXGI_FORMAT_B8G8R8A8_UNORM.
pub const NV_ENC_BUFFER_FORMAT_ARGB: u32 = 0x0100_0000;
/// Registering a resource for input images.
pub const NV_ENC_INPUT_IMAGE: u32 = 0x0;
/// Progressive frame picture structure.
pub const NV_ENC_PIC_STRUCT_FRAME: u32 = 0x01;
/// Force the next picture to be an IDR.
pub const NV_ENC_PIC_FLAG_FORCEIDR: u32 = 0x2;

/// NVENCAPI_STRUCT_VERSION(ver): version field layout for API structs.
pub const fn nvencapi_struct_version(ver: u32) -> u32 {
    let api = nv::NVENCAPI_MAJOR_VERSION | (nv::NVENCAPI_MINOR_VERSION << 24);
    api | (ver << 16) | (0x7 << 28)
}

/// Success status (NVENCSTATUS enum value 0).
pub const NV_ENC_SUCCESS: i32 = 0;

#[derive(Debug, thiserror::Error)]
pub enum NvEncoderError {
    #[error("load nvEncodeAPI: {0}")]
    Load(String),
    #[error("NVENC status 0x{0:x}")]
    Status(u32),
    #[error("{0}")]
    Other(String),
}

impl From<libloading::Error> for NvEncoderError {
    fn from(e: libloading::Error) -> Self {
        NvEncoderError::Load(e.to_string())
    }
}

/// Handle to the loaded NVENC API (function list + DLL keepalive).
pub struct NvEncoder {
    _lib: Library,
    pub api: nv::NV_ENCODE_API_FUNCTION_LIST,
}

impl NvEncoder {
    /// Loads nvEncodeAPI64.dll and retrieves the API function list.
    pub fn load() -> Result<Self, NvEncoderError> {
        unsafe {
            let lib = Library::new("nvEncodeAPI64.dll")?;
            let create: Symbol<unsafe extern "C" fn(*mut c_void) -> i32> =
                lib.get(b"NvEncodeAPICreateInstance")?;
            let mut fn_list: nv::NV_ENCODE_API_FUNCTION_LIST = std::mem::zeroed();
            fn_list.version = nvencapi_struct_version(2);
            let status = create(&mut fn_list as *mut _ as *mut c_void);
            if status != NV_ENC_SUCCESS {
                return Err(NvEncoderError::Status(status as u32));
            }
            Ok(NvEncoder { _lib: lib, api: fn_list })
        }
    }

    /// Queries the largest NvEncodeAPI version the driver supports
    /// (lower 4 bits = minor, rest = major).
    pub fn driver_max_version(&self) -> Result<u32, NvEncoderError> {
        unsafe {
            let get: Symbol<unsafe extern "C" fn(*mut u32) -> i32> =
                self._lib.get(b"NvEncodeAPIGetMaxSupportedVersion")?;
            let mut version: u32 = 0;
            let status = get(&mut version);
            if status != NV_ENC_SUCCESS {
                return Err(NvEncoderError::Status(status as u32));
            }
            Ok(version)
        }
    }

    /// Raw function-list version field.
    pub fn api_version(&self) -> u32 {
        self.api.version
    }

    /// NVENC API major/minor decoded from the function list version.
    pub fn major_minor(&self) -> (u32, u32) {
        (
            nv::NVENCAPI_MAJOR_VERSION,
            nv::NVENCAPI_MINOR_VERSION,
        )
    }
}

/// H.264 encode GUID (from nv-codec-headers `NV_ENC_CODEC_H264_GUID`).
pub fn h264_guid() -> nv::GUID {
    nv::GUID {
        Data1: 0x6bc82762,
        Data2: 0x4e63,
        Data3: 0x4ca4,
        Data4: [0xaa, 0x85, 0x1e, 0x50, 0xf3, 0x21, 0xf6, 0xbf],
    }
}

/// HEVC encode GUID (from nv-codec-headers `NV_ENC_CODEC_HEVC_GUID`).
pub fn hevc_guid() -> nv::GUID {
    nv::GUID {
        Data1: 0x6bc82764,
        Data2: 0x4e63,
        Data3: 0x4ca4,
        Data4: [0xaa, 0x85, 0x1e, 0x50, 0xf3, 0x21, 0xf6, 0xbf],
    }
}

/// Queries an encode capability. `encoder` may be NULL to query the
/// default device (SDK 11+); otherwise pass a session handle. `guid` selects
/// the codec (e.g. [`h264_guid`]).
pub fn get_encode_caps_with_guid(
    api: &nv::NV_ENCODE_API_FUNCTION_LIST,
    encoder: *mut c_void,
    guid: nv::GUID,
    cap: i32,
) -> Result<i32, NvEncoderError> {
    unsafe {
        let mut params: nv::NV_ENC_CAPS_PARAM = std::mem::zeroed();
        params.version = nvencapi_struct_version(1);
        params.capsToQuery = cap as nv::NV_ENC_CAPS;
        let mut value: i32 = 0;
        let status = (api.nvEncGetEncodeCaps.expect("nvEncGetEncodeCaps"))(
            encoder,
            guid,
            &mut params,
            &mut value,
        );
        if status != NV_ENC_SUCCESS {
            return Err(NvEncoderError::Status(status as u32));
        }
        Ok(value)
    }
}

impl NvEncoder {

    /// Opens an encode session bound to `device` (an ID3D11Device pointer).
    pub fn open_session(
        &self,
        device: *mut c_void,
        device_type: u32,
    ) -> Result<*mut c_void, NvEncoderError> {
        unsafe {
            let mut params: nv::NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS = std::mem::zeroed();
            params.version = nvencapi_struct_version(1);
            params.device = device;
            params.deviceType = device_type as i32;
            params.apiVersion = nv::NVENCAPI_MAJOR_VERSION | (nv::NVENCAPI_MINOR_VERSION << 24);
            let mut encoder: *mut c_void = std::ptr::null_mut();
            let status = (self.api.nvEncOpenEncodeSessionEx.expect("nvEncOpenEncodeSessionEx"))(
                &mut params,
                &mut encoder,
            );
            if status != NV_ENC_SUCCESS {
                return Err(NvEncoderError::Status(status as u32));
            }
            Ok(encoder)
        }
    }

    /// Destroys an encode session.
    pub fn destroy_session(&self, encoder: *mut c_void) {
        if !encoder.is_null() {
            unsafe {
                (self.api.nvEncDestroyEncoder.expect("nvEncDestroyEncoder"))(encoder);
            }
        }
    }

    /// Returns the driver's last error string for `encoder` (debugging aid).
    pub fn last_error_string(&self, encoder: *mut c_void) -> String {
        let ptr = unsafe {
            (self.api.nvEncGetLastErrorString.expect("nvEncGetLastErrorString"))(encoder)
        };
        if ptr.is_null() {
            return String::new();
        }
        unsafe {
            let mut len = 0usize;
            while *ptr.add(len) != 0 {
                len += 1;
            }
            let bytes = std::slice::from_raw_parts(ptr as *const u8, len);
            String::from_utf8_lossy(bytes).to_string()
        }
    }
}
