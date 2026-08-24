//! plist helper types mirroring `plist_types.go` from upstream doubletake.
//!
//! AirPlay receivers are sloppy with plist types: they send `<data>` blobs as
//! either binary data or hex strings, integers sometimes as reals, and booleans
//! sometimes as 0/1 integers. These wrapper types absorb that sloppiness.

use serde::de::{self, Deserialize, Deserializer, Visitor};
use std::fmt;

/// A plist `<data>` blob, which some receivers send as a hex string instead.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlistData(pub Vec<u8>);

impl PlistData {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for PlistData {
    fn from(v: Vec<u8>) -> Self {
        PlistData(v)
    }
}

impl From<&[u8]> for PlistData {
    fn from(v: &[u8]) -> Self {
        PlistData(v.to_vec())
    }
}

impl From<PlistData> for Vec<u8> {
    fn from(v: PlistData) -> Self {
        v.0
    }
}

impl<'de> Deserialize<'de> for PlistData {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PlistDataVisitor;

        impl<'de> Visitor<'de> for PlistDataVisitor {
            type Value = PlistData;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a plist data blob or a hex-encoded string")
            }

            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                Ok(PlistData(v))
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(PlistData(v.to_vec()))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                let bytes = hex::decode(v).map_err(de::Error::custom)?;
                Ok(PlistData(bytes))
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_byte_buf(PlistDataVisitor)
    }
}

/// An integer, which some receivers send as a real (float) instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PlistNumber(pub i64);

impl From<i64> for PlistNumber {
    fn from(v: i64) -> Self {
        PlistNumber(v)
    }
}

impl<'de> Deserialize<'de> for PlistNumber {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PlistNumberVisitor;

        impl<'de> Visitor<'de> for PlistNumberVisitor {
            type Value = PlistNumber;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an integer (or a real)")
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(PlistNumber(v))
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(PlistNumber(v as i64))
            }

            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                Ok(PlistNumber(v as i64))
            }
        }

        deserializer.deserialize_any(PlistNumberVisitor)
    }
}

/// A boolean, which some receivers send as 0/1 instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PlistFlag(pub bool);

impl From<bool> for PlistFlag {
    fn from(v: bool) -> Self {
        PlistFlag(v)
    }
}

impl<'de> Deserialize<'de> for PlistFlag {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PlistFlagVisitor;

        impl<'de> Visitor<'de> for PlistFlagVisitor {
            type Value = PlistFlag;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a boolean (or a 0/1 integer)")
            }

            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(PlistFlag(v))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(PlistFlag(v != 0))
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(PlistFlag(v != 0))
            }
        }

        deserializer.deserialize_any(PlistFlagVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize, Debug, PartialEq)]
    struct Sample {
        #[serde(rename = "data")]
        data: PlistData,
        #[serde(rename = "hex")]
        hex: PlistData,
        #[serde(rename = "num")]
        num: PlistNumber,
        #[serde(rename = "real")]
        real: PlistNumber,
        #[serde(rename = "flag")]
        flag: PlistFlag,
        #[serde(rename = "zero")]
        zero: PlistFlag,
    }

    const XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>data</key><data>AAECAwQ=</data>
    <key>hex</key><string>0a0b0c</string>
    <key>num</key><integer>42</integer>
    <key>real</key><real>7.0</real>
    <key>flag</key><true/>
    <key>zero</key><integer>0</integer>
</dict>
</plist>"#;

    #[test]
    fn parses_lenient_types() {
        let s: Sample = plist::from_bytes(XML.as_bytes()).expect("parse plist");
        assert_eq!(s.data, PlistData(vec![0x00, 0x01, 0x02, 0x03, 0x04]));
        assert_eq!(s.hex, PlistData(vec![0x0a, 0x0b, 0x0c]));
        assert_eq!(s.num, PlistNumber(42));
        assert_eq!(s.real, PlistNumber(7));
        assert_eq!(s.flag, PlistFlag(true));
        assert_eq!(s.zero, PlistFlag(false));
    }
}
