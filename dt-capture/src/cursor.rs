//! Mouse cursor overlay for DXGI Desktop Duplication.
//!
//! Desktop Duplication delivers the desktop image WITHOUT the cursor; the
//! pointer shape comes separately via `GetFramePointerShape`. This module
//! tracks the latest shape/position and blends it into the BGRA frame before
//! encoding, so the receiver sees the cursor like a real sender.

use windows::Win32::Graphics::Dxgi::{
    IDXGIOutputDuplication, DXGI_OUTDUPL_FRAME_INFO, DXGI_OUTDUPL_POINTER_SHAPE_INFO,
    DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR, DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR,
    DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME,
};

/// A captured pointer shape (bitmap + metadata).
#[derive(Clone, Debug)]
pub struct PointerShape {
    shape_type: i32,
    width: u32,
    height: u32,
    /// Byte pitch of the color plane (COLOR/MASKED_COLOR).
    color_pitch: u32,
    /// Hot spot inside the shape bitmap (relative to top-left).
    hot_spot: (i32, i32),
    /// Shape buffer: color data (+AND mask for masked/monochrome).
    data: Vec<u8>,
}

/// Tracks the cursor and blends it into captured frames.
#[derive(Default)]
pub struct CursorOverlay {
    shape: Option<PointerShape>,
    /// Hot-spot position in desktop (surface) coordinates.
    position: Option<(i32, i32)>,
    visible: bool,
}

impl CursorOverlay {
    /// Consumes the frame's pointer metadata; fetches a new shape when the
    /// receiver reports one.
    ///
    /// # Errors
    ///
    /// Fails if `GetFramePointerShape` fails unexpectedly (MORE_DATA is
    /// handled internally).
    pub fn update(
        &mut self,
        info: &DXGI_OUTDUPL_FRAME_INFO,
        duplication: &IDXGIOutputDuplication,
    ) -> Result<(), windows::core::Error> {
        // LastMouseUpdateTime == 0 → pointer did not change this frame.
        if info.LastMouseUpdateTime == 0 {
            return Ok(());
        }
        self.visible = info.PointerPosition.Visible.as_bool();
        self.position = Some((info.PointerPosition.Position.x, info.PointerPosition.Position.y));
        if info.PointerShapeBufferSize > 0 {
            self.shape = Some(fetch_shape(info.PointerShapeBufferSize, duplication)?);
        }
        Ok(())
    }

    /// Blends the cursor into a tightly-packed BGRA frame (`width * 4` bytes
    /// per row). No-op when there is no shape or the cursor is hidden.
    pub fn draw(&self, bgra: &mut [u8], width: u32, height: u32) {
        let Some(shape) = &self.shape else { return };
        let Some((hx, hy)) = self.position else { return };
        if !self.visible {
            return;
        }
        // The hot spot of the shape sits at the pointer position.
        let left = hx - shape.hot_spot.0;
        let top = hy - shape.hot_spot.1;
        let (fw, fh) = (width as i64, height as i64);
        let (sw, sh) = (shape.width as i64, shape.height as i64);
        let (sx0, sy0) = (left as i64, top as i64);
        if sx0 >= fw || sy0 >= fh || sx0 + sw <= 0 || sy0 + sh <= 0 {
            return;
        }

        match shape.shape_type {
            t if t == DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR.0 => {
                let color_pitch = shape.color_pitch as usize;
                for y in 0..sh {
                    let dy = sy0 + y;
                    if dy < 0 || dy >= fh {
                        continue;
                    }
                    for x in 0..sw {
                        let dx = sx0 + x;
                        if dx < 0 || dx >= fw {
                            continue;
                        }
                        let ci = y as usize * color_pitch + x as usize * 4;
                        if ci + 4 > shape.data.len() {
                            continue;
                        }
                        let fi = (dy as usize * width as usize + dx as usize) * 4;
                        blend_pixel(
                            bgra, fi, shape.data[ci + 2], shape.data[ci + 1], shape.data[ci],
                            shape.data[ci + 3],
                        );
                    }
                }
            }
            t if t == DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR.0 => {
                let color_pitch = shape.color_pitch as usize;
                // AND mask rows are DWORD-aligned like Windows bitmaps.
                let mask_pitch = ((shape.width as usize + 31) / 32) * 4;
                let color_bytes = color_pitch * shape.height as usize;
                for y in 0..sh {
                    let dy = sy0 + y;
                    if dy < 0 || dy >= fh {
                        continue;
                    }
                    for x in 0..sw {
                        let dx = sx0 + x;
                        if dx < 0 || dx >= fw {
                            continue;
                        }
                        let mask_off = color_bytes + y as usize * mask_pitch + (x as usize >> 3);
                        let masked = mask_off < shape.data.len()
                            && shape.data[mask_off] & (0x80u8 >> (x & 7)) != 0;
                        if masked {
                            continue;
                        }
                        let ci = y as usize * color_pitch + x as usize * 4;
                        if ci + 4 > shape.data.len() {
                            continue;
                        }
                        let fi = (dy as usize * width as usize + dx as usize) * 4;
                        blend_pixel(
                            bgra, fi, shape.data[ci + 2], shape.data[ci + 1], shape.data[ci],
                            shape.data[ci + 3],
                        );
                    }
                }
            }
            t if t == DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME.0 => {
                // Empirically (32x64 I-beam, 256-byte buffer): the buffer is
                // [AND plane][XOR plane], each with mask_pitch = len/2/height
                // bytes per row; the mask width (mask_pitch*8) may be smaller
                // than the reported width (2:1 here), so scale x accordingly.
                let height = shape.height as usize;
                let mask_pitch = (shape.data.len() / 2 / height.max(1)).max(1);
                let mask_width = mask_pitch * 8;
                let scale_x = ((shape.width as usize + mask_width - 1) / mask_width).max(1);
                let and_bytes = mask_pitch * height;
                if shape.data.len() < and_bytes * 2 {
                    log::warn!(
                        "monochrome cursor buffer too small: {} bytes for {}x{} pitch {}",
                        shape.data.len(),
                        shape.width,
                        shape.height,
                        mask_pitch
                    );
                    return;
                }
                for y in 0..sh {
                    let dy = sy0 + y;
                    if dy < 0 || dy >= fh {
                        continue;
                    }
                    for x in 0..sw {
                        let dx = sx0 + x;
                        if dx < 0 || dx >= fw {
                            continue;
                        }
                        let mx = (x as usize / scale_x) as u32;
                        let bit = 0x80u8 >> (mx & 7);
                        let byte_off = y as usize * mask_pitch + (mx as usize >> 3);
                        let transparent = shape.data[byte_off] & bit != 0;
                        if transparent {
                            continue;
                        }
                        let xor_on = shape.data[and_bytes + byte_off] & bit != 0;
                        let fi = (dy as usize * width as usize + dx as usize) * 4;
                        if xor_on {
                            // Inverted pixel (white-on-black style).
                            bgra[fi] = 255u8.wrapping_sub(bgra[fi]);
                            bgra[fi + 1] = 255u8.wrapping_sub(bgra[fi + 1]);
                            bgra[fi + 2] = 255u8.wrapping_sub(bgra[fi + 2]);
                        } else {
                            // Black pixel (outline).
                            bgra[fi] = 0;
                            bgra[fi + 1] = 0;
                            bgra[fi + 2] = 0;
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Alpha-blends an RGBA pixel (in BGRA byte order) into the frame.
fn blend_pixel(bgra: &mut [u8], fi: usize, r: u8, g: u8, b: u8, a: u8) {
    if a == 255 {
        bgra[fi] = b;
        bgra[fi + 1] = g;
        bgra[fi + 2] = r;
        return;
    }
    if a == 0 {
        return;
    }
    let a = a as u32;
    bgra[fi] = ((b as u32 * a + bgra[fi] as u32 * (255 - a)) / 255) as u8;
    bgra[fi + 1] = ((g as u32 * a + bgra[fi + 1] as u32 * (255 - a)) / 255) as u8;
    bgra[fi + 2] = ((r as u32 * a + bgra[fi + 2] as u32 * (255 - a)) / 255) as u8;
}

/// Fetches the pointer shape buffer described by the frame info.
fn fetch_shape(
    hint_size: u32,
    duplication: &IDXGIOutputDuplication,
) -> Result<PointerShape, windows::core::Error> {
    let mut required: u32 = hint_size.max(64);
    let mut shape_info = DXGI_OUTDUPL_POINTER_SHAPE_INFO::default();

    loop {
        let mut buf = vec![0u8; required as usize];
        let res = unsafe {
            duplication.GetFramePointerShape(
                required,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                &mut required,
                &mut shape_info,
            )
        };
        match res {
            Ok(()) => {
                log::debug!(
                    "pointer shape: type={} {}x{} pitch={} hot=({},{}), {} bytes",
                    shape_info.Type,
                    shape_info.Width,
                    shape_info.Height,
                    shape_info.Pitch,
                    shape_info.HotSpot.x,
                    shape_info.HotSpot.y,
                    buf.len()
                );
                return Ok(PointerShape {
                    shape_type: shape_info.Type as i32,
                    width: shape_info.Width,
                    height: shape_info.Height,
                    color_pitch: shape_info.Pitch,
                    hot_spot: (shape_info.HotSpot.x, shape_info.HotSpot.y),
                    data: buf,
                });
            }
            Err(e) if e.code() == windows::Win32::Graphics::Dxgi::DXGI_ERROR_MORE_DATA => {
                // required has been updated to the needed size; retry.
            }
            Err(e) => return Err(e),
        }
    }
}
