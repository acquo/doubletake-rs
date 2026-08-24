//! `ReceiverInfo` — the capabilities returned by `GET /info`.
//!
//! Port of `ReceiverInfo` and the feature/status flag helpers from upstream
//! doubletake (`client.go`, `discovery.go`).

use crate::plist_types::{PlistData, PlistFlag, PlistNumber};
use serde::Deserialize;

/// AirPlay receiver feature bits.
pub const FEATURE_SCREEN: u64 = 1 << 8;
pub const FEATURE_AUDIO: u64 = 1 << 10;
pub const FEATURE_FPSAP25: u64 = 1 << 14;
pub const FEATURE_HOMEKIT_PAIRING: u64 = 1 << 17;
pub const FEATURE_SYSTEM_PAIRING: u64 = 1 << 43;
pub const FEATURE_TRANSIENT_PAIRING: u64 = 1 << 48;
pub const FEATURE_UDP_MIRRORING: u64 = 1 << 49;

// These masks mirror the receiver classification used by Apple's sender.
const FEATURE_THIRD_PARTY_RECEIVER_MASK: u64 = (1 << 26) | (1 << 51);
const FEATURE_CORE_UTILS_PAIRING_MASK: u64 = (1 << 38) | (1 << 43) | (1 << 46) | (1 << 48);

/// AirPlay receiver status flags used to choose one authentication prompt.
pub const STATUS_FLAG_PASSWORD_REQUIRED: u64 = 1 << 7;
pub const STATUS_FLAG_PIN_REQUIRED_FOR_PAIRING: u64 = 1 << 9;

/// A display advertised by the receiver in `/info`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct DisplayInfo {
    #[serde(rename = "width", default)]
    pub width: PlistNumber,
    #[serde(rename = "height", default)]
    pub height: PlistNumber,
    #[serde(rename = "widthPixels", default)]
    pub width_pixels: PlistNumber,
    #[serde(rename = "heightPixels", default)]
    pub height_pixels: PlistNumber,
}

/// Capabilities returned by the receiver's `/info` endpoint.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct ReceiverInfo {
    #[serde(rename = "name", default)]
    pub name: String,
    #[serde(rename = "model", default)]
    pub model: String,
    #[serde(rename = "manufacturer", default)]
    pub manufacturer: String,
    #[serde(rename = "deviceID", default)]
    pub device_id: String,
    #[serde(rename = "protocolVersion", default)]
    pub protocol_version: String,
    #[serde(rename = "sourceVersion", default)]
    pub source_version: String,
    #[serde(rename = "features", default)]
    pub features: u64,
    #[serde(rename = "statusFlags", default)]
    pub status_flags: u64,
    #[serde(rename = "pk", default)]
    pub pk: PlistData,
    #[serde(rename = "hasUDPMirroringSupport", default)]
    pub has_udp_mirroring: bool,
    #[serde(rename = "receiverHDRCapability", default)]
    pub hdr_capability: String,
    #[serde(rename = "volumeControlType", default)]
    pub volume_control_type: PlistNumber,
    #[serde(rename = "initialVolume", default)]
    pub initial_volume: f64,
    #[serde(rename = "keepAliveSendStatsAsBody", default)]
    pub keep_alive_send_stats_as_body: PlistFlag,
    #[serde(rename = "psi", default)]
    pub psi: String,
    #[serde(rename = "pi", default)]
    pub pi: String,
    #[serde(rename = "macAddress", default)]
    pub mac_address: String,
    #[serde(rename = "displays", default)]
    pub displays: Vec<DisplayInfo>,
}

impl ReceiverInfo {
    /// Whether the receiver has a configured playback password.
    pub fn requires_password(&self) -> bool {
        self.status_flags & STATUS_FLAG_PASSWORD_REQUIRED != 0
    }

    /// Whether the receiver requires one-time pairing with an onscreen PIN.
    pub fn requires_pin_pairing(&self) -> bool {
        self.status_flags & STATUS_FLAG_PIN_REQUIRED_FOR_PAIRING != 0
    }

    /// Whether the receiver advertises transient (PIN-less) pairing support.
    pub fn supports_transient_pairing(&self) -> bool {
        self.features & (FEATURE_TRANSIENT_PAIRING | FEATURE_SYSTEM_PAIRING) != 0
    }

    /// Whether the receiver can use the first-party CoreUtils/HAP profile
    /// directly (as opposed to third-party receivers that copy the bits).
    pub fn uses_modern_pairing(&self) -> bool {
        self.features & FEATURE_CORE_UTILS_PAIRING_MASK != 0
            && self.features & FEATURE_THIRD_PARTY_RECEIVER_MASK == 0
    }

    /// Whether protocol probing classified the receiver for the original
    /// HKP type 3 pairing flow.
    pub fn prefers_legacy_pairing(&self) -> bool {
        !self.uses_modern_pairing()
    }

    /// Whether the receiver advertises FairPlay SAP (feature bit 14).
    pub fn supports_fairplay_sap(&self) -> bool {
        self.features & FEATURE_FPSAP25 != 0
    }

    /// Returns the receiver's primary display size in pixels, or (0, 0).
    pub fn display_size(&self) -> (i64, i64) {
        let Some(d) = self.displays.first() else {
            return (0, 0);
        };
        let (mut w, mut h) = (d.width_pixels.0, d.height_pixels.0);
        if w <= 0 || h <= 0 {
            w = d.width.0;
            h = d.height.0;
        }
        if w <= 0 || h <= 0 {
            return (0, 0);
        }
        (w, h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feature mask used by Roku receivers (from upstream test).
    const ROKU_FEATURES: u64 = 0x38bcf46007f8ad0;

    #[test]
    fn modern_apple_receiver() {
        let info = ReceiverInfo {
            features: FEATURE_SYSTEM_PAIRING | FEATURE_TRANSIENT_PAIRING,
            ..Default::default()
        };
        assert!(info.uses_modern_pairing());
        assert!(!info.prefers_legacy_pairing());
        assert!(info.supports_transient_pairing());
    }

    #[test]
    fn roku_receiver_is_legacy() {
        let info = ReceiverInfo {
            features: ROKU_FEATURES,
            ..Default::default()
        };
        assert!(!info.uses_modern_pairing());
        assert!(info.prefers_legacy_pairing());
    }

    #[test]
    fn empty_info_is_legacy() {
        let info = ReceiverInfo::default();
        assert!(info.prefers_legacy_pairing());
    }

    #[test]
    fn status_flag_helpers() {
        let info = ReceiverInfo {
            status_flags: STATUS_FLAG_PASSWORD_REQUIRED,
            ..Default::default()
        };
        assert!(info.requires_password());
        assert!(!info.requires_pin_pairing());
    }

    #[test]
    fn parses_info_plist() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>name</key><string>Living Room</string>
    <key>deviceID</key><string>AA:BB:CC:DD:EE:FF</string>
    <key>features</key><integer>21990589900544</integer>
    <key>statusFlags</key><integer>0</integer>
    <key>pk</key><data>AQID</data>
    <key>displays</key>
    <array>
        <dict>
            <key>width</key><integer>1920</integer>
            <key>height</key><integer>1080</integer>
            <key>widthPixels</key><integer>1920</integer>
            <key>heightPixels</key><integer>1080</integer>
        </dict>
    </array>
</dict>
</plist>"#;
        let info: ReceiverInfo = plist::from_bytes(xml.as_bytes()).expect("parse /info plist");
        assert_eq!(info.name, "Living Room");
        assert_eq!(info.device_id, "AA:BB:CC:DD:EE:FF");
        assert_eq!(info.features, 21990589900544);
        assert_eq!(info.pk.as_slice(), &[0x01, 0x02, 0x03]);
        assert_eq!(info.display_size(), (1920, 1080));
    }
}
