//! lumen-airplay — AirPlay mirroring protocol layer.
//!
//! Rust port of the protocol/auth code from
//! <https://github.com/omarroth/lumen> (GPL-3.0).

pub mod audio;
pub mod client;
pub mod credentials;
pub mod digest;
pub mod error;
pub mod event_channel;
pub mod fairplay;
pub mod fairplay_md5;
pub mod fairplay_message;
pub mod fairplay_sap;
pub mod fp_tables_generated;
pub mod fpsap;
pub mod h264;
pub mod info;
pub mod latency;
pub mod mirror;
pub mod mirror_cipher;
pub mod pairing;
pub mod plist_types;
pub mod receiver;
pub mod tlv8;
pub mod transport;
pub mod uuid;

pub use error::{Error, Result};
