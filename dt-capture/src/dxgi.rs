//! DXGI Desktop Duplication capture.
//!
//! Two consumers:
//! - [`DesktopDuplicator::acquire_frame`]: `ID3D11Texture2D` surfaces, for the
//!   NVENC zero-copy path (no CPU readback).
//! - [`DesktopDuplicator::acquire_frame_cpu`]: tightly-packed BGRA8 frames
//!   read back to the CPU, for software encoders (e.g. OpenH264).

use windows::core::Interface;
use windows::Win32::Foundation::RECT;
use windows::Win32::Graphics::Direct3D::{
    D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_10_0, D3D_FEATURE_LEVEL_11_0,
};
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_FLAG, D3D11_MAP_READ,
    D3D11_MAPPED_SUBRESOURCE, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
    ID3D11Device, ID3D11DeviceContext, ID3D11Resource, ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT, DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC,
};
use windows::Win32::Graphics::Dxgi::{
    IDXGIAdapter, IDXGIDevice, IDXGIOutput, IDXGIOutput1, IDXGIOutputDuplication, IDXGIResource,
    DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
};
use std::ffi::c_void;

use crate::cursor::CursorOverlay;

#[derive(Debug, thiserror::Error)]
pub enum DxgiError {
    #[error("windows: {0}")]
    Windows(#[from] windows::core::Error),
    #[error("duplication surface lost")]
    AccessLost,
    #[error("no output at index {0}")]
    NoOutput(u32),
    #[error("unsupported surface format {0:?} for CPU readback (only B8G8R8A8_UNORM)")]
    UnsupportedFormat(DXGI_FORMAT),
}

/// A desktop frame read back to the CPU.
#[derive(Debug)]
pub struct CpuFrame {
    /// Tightly packed `[B,G,R,A]` pixels, `width * 4` bytes per row.
    pub bgra: Vec<u8>,
    pub width: u32,
    pub height: u32,
    /// Source surface format (always `B8G8R8A8_UNORM` today).
    pub format: DXGI_FORMAT,
}

/// Captures the desktop via DXGI Desktop Duplication.
pub struct DesktopDuplicator {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    duplication: IDXGIOutputDuplication,
    /// Lazily-created staging texture for CPU readback.
    staging: Option<ID3D11Texture2D>,
    /// Cursor shape/position overlay (blended into CPU frames).
    cursor: CursorOverlay,
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
            context,
            duplication,
            staging: None,
            cursor: CursorOverlay::default(),
            width,
            height,
        })
    }

    /// The D3D11 device that owns captured textures (shared with NVENC).
    pub fn device_raw(&self) -> *mut c_void {
        self.device.as_raw() as *mut c_void
    }

    /// Waits up to `timeout_ms` for a new desktop frame. Returns the texture
    /// (valid until [`DesktopDuplicator::release_frame`]).
    pub fn acquire_frame(&mut self, timeout_ms: u32) -> Result<Option<ID3D11Texture2D>, DxgiError> {
        Ok(self.acquire_with_info(timeout_ms)?.map(|(t, _)| t))
    }

    fn acquire_with_info(
        &mut self,
        timeout_ms: u32,
    ) -> Result<Option<(ID3D11Texture2D, DXGI_OUTDUPL_FRAME_INFO)>, DxgiError> {
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
        Ok(Some((texture, info)))
    }

    /// Releases the last acquired frame (required before the next acquire).
    pub fn release_frame(&mut self) {
        unsafe {
            let _ = self.duplication.ReleaseFrame();
        }
    }

    /// Waits up to `timeout_ms` for a new desktop frame, read back to the CPU
    /// as tightly-packed BGRA8 with the mouse cursor blended in (for software
    /// encoders).
    ///
    /// `Ok(None)` means the timeout elapsed without a new frame.
    pub fn acquire_frame_cpu(&mut self, timeout_ms: u32) -> Result<Option<CpuFrame>, DxgiError> {
        let Some((texture, info)) = self.acquire_with_info(timeout_ms)? else {
            return Ok(None);
        };
        let result = self.readback_cpu(&texture);
        if let Ok(mut frame) = result {
            // Track the pointer (position/shape) and draw it into the frame.
            if let Err(e) = self.cursor.update(&info, &self.duplication) {
                log::warn!("cursor update failed: {e}");
            }
            self.cursor.draw(&mut frame.bgra, frame.width, frame.height);
            self.release_frame();
            return Ok(Some(frame));
        }
        self.release_frame();
        result.map(Some)
    }

    /// Copies `texture` into a staging texture and reads the pixels back.
    fn readback_cpu(&mut self, texture: &ID3D11Texture2D) -> Result<CpuFrame, DxgiError> {
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        unsafe { texture.GetDesc(&mut desc) };
        if desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM {
            return Err(DxgiError::UnsupportedFormat(desc.Format));
        }

        // (Re)create the staging texture when the surface size/format changed.
        let need_create = match &self.staging {
            Some(s) => {
                let mut sd = D3D11_TEXTURE2D_DESC::default();
                unsafe { s.GetDesc(&mut sd) };
                sd.Width != desc.Width || sd.Height != desc.Height || sd.Format != desc.Format
            }
            None => true,
        };
        if need_create {
            let staging_desc = D3D11_TEXTURE2D_DESC {
                Width: desc.Width,
                Height: desc.Height,
                MipLevels: 1,
                ArraySize: 1,
                Format: desc.Format,
                SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
                Usage: D3D11_USAGE_STAGING,
                BindFlags: 0,
                CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
                MiscFlags: 0,
            };
            let mut staging: Option<ID3D11Texture2D> = None;
            unsafe { self.device.CreateTexture2D(&staging_desc, None, Some(&mut staging))? };
            self.staging = staging;
        }
        let staging = self.staging.as_ref().expect("staging created above");

        unsafe {
            let src: ID3D11Resource = texture.cast()?;
            let dst: ID3D11Resource = staging.cast()?;
            self.context.CopyResource(&dst, &src);
        }

        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        unsafe { self.context.Map(staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))? };
        let row_pitch = mapped.RowPitch as usize;
        let width = desc.Width as usize;
        let height = desc.Height as usize;
        let bytes = unsafe {
            std::slice::from_raw_parts(mapped.pData as *const u8, row_pitch * height)
        };
        let mut bgra = vec![0u8; width * 4 * height];
        for y in 0..height {
            let src = &bytes[y * row_pitch..y * row_pitch + width * 4];
            bgra[y * width * 4..(y + 1) * width * 4].copy_from_slice(src);
        }
        unsafe {
            self.context.Unmap(staging, 0);
        }

        Ok(CpuFrame {
            bgra,
            width: desc.Width,
            height: desc.Height,
            format: desc.Format,
        })
    }

    /// Helper: extracts the desktop bounds rect (kept for diagnostics).
    #[allow(dead_code)]
    fn rect_size(r: &RECT) -> (u32, u32) {
        ((r.right - r.left) as u32, (r.bottom - r.top) as u32)
    }
}
