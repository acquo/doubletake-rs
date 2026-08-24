//! dt-encode — video encoding pipeline for doubletake-rs.
//!
//! M1: NVENC with D3D11 zero-copy input on Windows.
//! M2: OpenH264 software encoder (fully configurable, no GPU dependency).

pub mod encoder;
pub mod nvenc;
pub mod openh264;

pub use encoder::{baseline_guid, main_guid, preset_p4_guid, H264Encoder};
pub use nvenc::{
    NvEncoder, NvEncoderError, NV_ENC_BUFFER_FORMAT_ARGB, NV_ENC_DEVICE_TYPE_DIRECTX,
    NV_ENC_INPUT_RESOURCE_TYPE_DIRECTX, NV_ENC_PIC_FLAG_FORCEIDR, NV_ENC_PIC_STRUCT_FRAME,
};
pub use openh264::{
    annexb_nals, extract_sps_pps, strip_start_code, Complexity, Level, OpenH264Config,
    OpenH264Encoder, Profile, UsageType,
};
