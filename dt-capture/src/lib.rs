//! dt-capture — screen capture for doubletake-rs.
//!
//! M1: DXGI Desktop Duplication on Windows, feeding ID3D11Texture2D surfaces
//! straight to the NVENC zero-copy path.

pub mod dxgi;

pub use dxgi::{DesktopDuplicator, DxgiError};
