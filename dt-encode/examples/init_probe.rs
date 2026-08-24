//! Init probe v8: sweep presets and presetCfg versions for GetEncodePresetConfig.

use dt_encode::nvenc::{h264_guid, nvencapi_struct_version, NvEncoder, NV_ENC_DEVICE_TYPE_DIRECTX};
use dt_encode::nvenc::nvenc_bindings as nv;
use std::ffi::c_void;
use std::sync::Arc;
use windows::core::Interface;
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_11_0};
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, D3D11_CREATE_DEVICE_FLAG, D3D11_SDK_VERSION, ID3D11Device,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut device: Option<ID3D11Device> = None;
    unsafe {
        D3D11CreateDevice(
            None,
            D3D_DRIVER_TYPE_HARDWARE,
            None,
            D3D11_CREATE_DEVICE_FLAG(0x20),
            Some(&[D3D_FEATURE_LEVEL_11_0]),
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            None,
        )?;
    }
    let device = device.expect("device");
    let raw = unsafe { device.as_raw() as *mut c_void };
    let nv = Arc::new(NvEncoder::load()?);
    let session = nv.open_session(raw, NV_ENC_DEVICE_TYPE_DIRECTX)?;

    unsafe {
        let mut preset_count: u32 = 0;
        (nv.api.nvEncGetEncodePresetCount.expect("pc"))(session, h264_guid(), &mut preset_count);
        let mut presets: Vec<nv::GUID> = vec![std::mem::zeroed(); preset_count as usize];
        (nv.api.nvEncGetEncodePresetGUIDs.expect("pg"))(session, h264_guid(), presets.as_mut_ptr(), preset_count, &mut preset_count);

        for (i, p) in presets.iter().enumerate() {
            let mut ok = false;
            for cfg_ver in [7u32, 8, 9, 10] {
                let mut pc: nv::NV_ENC_PRESET_CONFIG = std::mem::zeroed();
                pc.version = nvencapi_struct_version(5) | (1 << 31);
                pc.presetCfg.version = nvencapi_struct_version(cfg_ver) | (1 << 31);
                let s = (nv.api.nvEncGetEncodePresetConfig.expect("pcfg"))(session, h264_guid(), *p, &mut pc);
                if s == 0 {
                    println!("preset[{i}] cfg_ver {cfg_ver}: OK! gop={} rc={}", pc.presetCfg.gopLength, pc.presetCfg.rcParams.rateControlMode);
                    ok = true;
                    break;
                }
            }
            if !ok {
                println!("preset[{i}]: all cfg_ver failed");
            }
        }
        println!("done");
    }
    Ok(())
}
