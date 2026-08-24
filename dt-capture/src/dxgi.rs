//! DXGI Desktop Duplication capture.
//!
//! Produces `ID3D11Texture2D` surfaces that can be registered with NVENC
//! directly (zero-copy, no CPU readback).

use windows::core::{Interface, Result as WinResult};
use windows::Win32::Foundation::RECT;
use windows::Win32::Graphics::Direct3D::{
    D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_10_0, D3D_FEATURE_LEVEL_11_0,
};
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, D3D11_CREATE_DEVICE_FLAG, D3D11_SDK_VERSION, ID3D11Device,
    ID3D11DeviceContext, ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::{
    IDXGIAdapter, IDXGIDevice, IDXGIOutput, IDXGIOutput1, IDXGIOutputDuplication, IDXGIResource,
    DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
};
use std::ffi::c_void;

#[derive(Debug, thiserror::Error)]
pub enum DxgiError {
    #[error("windows: {0}")]
    Windows(#[from] windows::core::Error),
    #[error("duplication surface lost")]
    AccessLost,
    #[error("no output at index {0}")]
    NoOutput(u32),
}

/// Captures the desktop via DXGI Desktop Duplication.
pub struct DesktopDuplicator {
    device: ID3D11Device,
    _context: ID3D11DeviceContext,
    duplication: IDXGIOutputDuplication,
    pub width: u32,
    pub height: u32,
}

impl DesktopDuplicator {
    /// Captures the desktop on `output_index` (0 = primary monitor).
    pub fn new(output_index: u32) -> Result<Self, DxgiError> {
        let mut device: Option<ID3D11Device> = None;
        let mut context: Option<ID3D11DeviceContext> = None;
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
                Some(&mut context),
            )?;
        }
        let device = device.expect("D3D11CreateDevice returned no device");
        let context = context.expect("D3D11CreateDevice context");

        let dxgi_device: IDXGIDevice = device.cast()?;
        let adapter: IDXGIAdapter = unsafe { dxgi_device.GetAdapter()? };
        let output: IDXGIOutput = unsafe { adapter.EnumOutputs(output_index) }
            .map_err(|_| DxgiError::NoOutput(output_index))?;
        let desc = unsafe { output.GetDesc()? };
        let width = (desc.DesktopCoordinates.right - desc.DesktopCoordinates.left) as u32;
        let height = (desc.DesktopCoordinates.bottom - desc.DesktopCoordinates.top) as u32;

        // DuplicateOutput is a DXGI 1.1 (IDXGIOutput1) method.
        let output1: IDXGIOutput1 = output.cast()?;
        let duplication = unsafe { output1.DuplicateOutput(&device)? };

        Ok(DesktopDuplicator {
            device,
            _context: context,
            duplication,
            width,
            height,
        })
    }

    /// The D3D11 device that owns captured textures (shared with NVENC).
    pub fn device_raw(&self) -> *mut c_void {
        unsafe { self.device.as_raw() as *mut c_void }
    }

    /// Waits up to `timeout_ms` for a new desktop frame. Returns the texture
    /// (valid until [`DesktopDuplicator::release_frame`]).
    pub fn acquire_frame(&mut self, timeout_ms: u32) -> Result<Option<ID3D11Texture2D>, DxgiError> {
        let mut info: DXGI_OUTDUPL_FRAME_INFO = unsafe { std::mem::zeroed() };
        let mut resource: Option<IDXGIResource> = None;
        match unsafe { self.duplication.AcquireNextFrame(timeout_ms, &mut info, &mut resource) } {
            Ok(()) => {}
            Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => return Ok(None),
            Err(e) if e.code() == DXGI_ERROR_ACCESS_LOST => return Err(DxgiError::AccessLost),
            Err(e) => return Err(DxgiError::Windows(e)),
        }
        let Some(resource) = resource else {
            return Ok(None);
        };
        let texture: ID3D11Texture2D = resource.cast()?;
        Ok(Some(texture))
    }

    /// Releases the last acquired frame (required before the next acquire).
    pub fn release_frame(&mut self) {
        unsafe {
            let _ = self.duplication.ReleaseFrame();
        }
    }

    /// Helper: extracts the desktop bounds rect (kept for diagnostics).
    #[allow(dead_code)]
    fn rect_size(r: &RECT) -> (u32, u32) {
        ((r.right - r.left) as u32, (r.bottom - r.top) as u32)
    }
}
