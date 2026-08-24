//! dt-capture — screen capture for doubletake-rs.
//!
//! M1: DXGI Desktop Duplication on Windows, feeding ID3D11Texture2D surfaces
//! straight to the NVENC zero-copy path.
//! M2: CPU readback (BGRA8) + mouse cursor overlay for software encoders.

pub mod cursor;
pub mod dxgi;

pub use cursor::CursorOverlay;
pub use dxgi::{CpuFrame, DesktopDuplicator, DxgiError};
