//! dt-airplay — AirPlay mirroring protocol layer.
//!
//! Rust port of the protocol/auth code from
//! <https://github.com/omarroth/doubletake> (GPL-3.0).

pub mod digest;
pub mod plist_types;
pub mod tlv8;

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert!(true);
    }
}
