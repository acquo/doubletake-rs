//! dt-encode — video encoding pipeline for doubletake-rs.
//!
//! M1: NVENC with D3D11 zero-copy input on Windows.

pub mod nvenc;

pub use nvenc::{NvEncoder, NvEncoderError};
