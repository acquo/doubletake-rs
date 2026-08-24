//! NVENC usability spike: load the API, query H.264-related caps, create a
//! D3D11 device, and find the device type that opens an encode session.

use lumen_encode::nvenc::{
    get_encode_caps_with_guid, h264_guid, NvEncoder, NV_ENC_DEVICE_TYPE_DIRECTX, NV_ENC_SUCCESS,
};
use lumen_encode::nvenc::nvenc_bindings as nv;
use std::ffi::c_void;
use windows::core::Interface;
use windows::Win32::Graphics::Direct3D::{
    D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_10_0, D3D_FEATURE_LEVEL_11_0,
};
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, D3D11_CREATE_DEVICE_FLAG, D3D11_SDK_VERSION, ID3D11Device,
};

fn caps_name(cap: i32) -> &'static str {
    match cap {
        c if c == nv::_NV_ENC_CAPS_NV_ENC_CAPS_WIDTH_MAX as i32 => "WIDTH_MAX",
        c if c == nv::_NV_ENC_CAPS_NV_ENC_CAPS_HEIGHT_MAX as i32 => "HEIGHT_MAX",
        c if c == nv::_NV_ENC_CAPS_NV_ENC_CAPS_SUPPORTED_RATECONTROL_MODES as i32 => "RATECONTROL_MODES",
        c if c == nv::_NV_ENC_CAPS_NV_ENC_CAPS_SUPPORT_CABAC as i32 => "SUPPORT_CABAC",
        c if c == nv::_NV_ENC_CAPS_NV_ENC_CAPS_NUM_MAX_BFRAMES as i32 => "NUM_MAX_BFRAMES",
        _ => "?",
    }
}

const CAPS: [i32; 5] = [
    nv::_NV_ENC_CAPS_NV_ENC_CAPS_WIDTH_MAX as i32,
    nv::_NV_ENC_CAPS_NV_ENC_CAPS_HEIGHT_MAX as i32,
    nv::_NV_ENC_CAPS_NV_ENC_CAPS_SUPPORTED_RATECONTROL_MODES as i32,
    nv::_NV_ENC_CAPS_NV_ENC_CAPS_SUPPORT_CABAC as i32,
    nv::_NV_ENC_CAPS_NV_ENC_CAPS_NUM_MAX_BFRAMES as i32,
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let enc = NvEncoder::load()?;
    let (major, minor) = enc.major_minor();
    println!("=== NVENC API ===");
    println!("function list version: 0x{:08x} (NVENC API {}.{})", enc.api_version(), major, minor);

    println!("\n=== H.264 caps (default device, encoder=NULL) ===");
    for cap in CAPS {
        match get_encode_caps_with_guid(&enc.api, std::ptr::null_mut(), h264_guid(), cap) {
            Ok(v) => println!("  {}: {}", caps_name(cap), v),
            Err(e) => println!("  {}: {}", caps_name(cap), e),
        }
    }

    println!("\n=== D3D11 device ===");
    let mut device: Option<ID3D11Device> = None;
    unsafe {
        D3D11CreateDevice(
            None,
            D3D_DRIVER_TYPE_HARDWARE,
            None,
            D3D11_CREATE_DEVICE_FLAG(0),
            Some(&[D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0]),
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            None,
        )?;
    }
    let device = device.ok_or("D3D11CreateDevice returned no device")?;
    let raw_device = device.as_raw() as *mut c_void;
    println!("  D3D11 device created (raw {:?})", raw_device);

    println!("\n=== open encode session (device type probe) ===");
    let mut winner: Option<(u32, *mut c_void)> = None;
    for device_type in [0u32, 1, 2, 3, 4, 5, NV_ENC_DEVICE_TYPE_DIRECTX] {
        match enc.open_session(raw_device, device_type) {
            Ok(session) => {
                println!("  deviceType {device_type}: SUCCESS (session {:?})", session);
                winner = Some((device_type, session));
                break;
            }
            Err(e) => println!("  deviceType {device_type}: {e}"),
        }
    }

    let Some((device_type, session)) = winner else {
        eprintln!("\nFAILED: no device type opened an encode session with the D3D11 device");
        std::process::exit(1);
    };
    println!("\n=== H.264 caps via opened session (deviceType {device_type}) ===");
    for cap in CAPS {
        match get_encode_caps_with_guid(&enc.api, session, h264_guid(), cap) {
            Ok(v) => println!("  {}: {}", caps_name(cap), v),
            Err(e) => println!("  {}: {}", caps_name(cap), e),
        }
    }

    // Count encode GUIDs (H.264 support is one of them).
    println!("\n=== encode GUID count ===");
    let mut guid_count: u32 = 0;
    unsafe {
        let status = (enc.api.nvEncGetEncodeGUIDCount.expect("count"))(session, &mut guid_count);
        if status == NV_ENC_SUCCESS {
            println!("  {guid_count} encode GUIDs");
            let mut guids: Vec<nv::GUID> = Vec::with_capacity(guid_count as usize);
            guids.resize(guid_count as usize, std::mem::zeroed());
            let status = (enc.api.nvEncGetEncodeGUIDs.expect("guids"))(
                session,
                guids.as_mut_ptr(),
                guid_count,
                &mut guid_count,
            );
            if status == NV_ENC_SUCCESS {
                for g in &guids {
                    // GUID Data1..Data4 carry the 4-char codec tag (e.g. "H264").
                    let tag: [u8; 4] = [
                        g.Data1 as u8,
                        g.Data2 as u8,
                        g.Data3 as u8,
                        g.Data4[0],
                    ];
                    println!("  GUID: {:?}", String::from_utf8_lossy(&tag));
                }
            } else {
                println!("  NvEncGetEncodeGUIDs failed: 0x{status:x}");
            }
        } else {
            println!("  NvEncGetEncodeGUIDCount failed: 0x{status:x}");
        }
    }

    enc.destroy_session(session);
    println!("\nRESULT: NVENC is USABLE — D3D11 device accepted at deviceType={device_type}");
    Ok(())
}
