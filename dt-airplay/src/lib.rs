//! dt-airplay — AirPlay mirroring protocol layer.
//!
//! Rust port of the protocol/auth code from
//! <https://github.com/omarroth/doubletake> (GPL-3.0).

pub mod credentials;
pub mod digest;
pub mod error;
pub mod info;
pub mod pairing;
pub mod plist_types;
pub mod tlv8;
pub mod transport;
pub mod uuid;

pub use error::{Error, Result};
