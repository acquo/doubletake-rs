//! HomeKit-style TLV8 encoding, mirroring `pairing.go` from upstream doubletake.

use std::collections::HashMap;

/// TLV8 types for HomeKit-style pairing.
pub const TLV_METHOD: u8 = 0x00;
pub const TLV_IDENTIFIER: u8 = 0x01;
pub const TLV_SALT: u8 = 0x02;
pub const TLV_PUBLIC_KEY: u8 = 0x03;
pub const TLV_PROOF: u8 = 0x04;
pub const TLV_ENCRYPTED_DATA: u8 = 0x05;
pub const TLV_STATE: u8 = 0x06;
pub const TLV_ERROR: u8 = 0x07;
pub const TLV_SIGNATURE: u8 = 0x0A;
pub const TLV_ACL: u8 = 0x12;
pub const TLV_FLAGS: u8 = 0x13;

/// An ordered tag-value pair for deterministic encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv8Item {
    pub tag: u8,
    pub value: Vec<u8>,
}

impl Tlv8Item {
    pub fn new(tag: u8, value: impl Into<Vec<u8>>) -> Self {
        Tlv8Item {
            tag,
            value: value.into(),
        }
    }
}

/// Encodes TLV8 items in the given order, splitting values >255 bytes into
/// repeated (tag, len, chunk) records, matching the Go implementation.
pub fn encode_ordered(items: &[Tlv8Item]) -> Vec<u8> {
    let mut buf = Vec::new();
    for item in items {
        let value = &item.value;
        if value.is_empty() {
            buf.push(item.tag);
            buf.push(0);
            continue;
        }
        let mut rest = value.as_slice();
        while !rest.is_empty() {
            let chunk = if rest.len() > 255 { &rest[..255] } else { rest };
            buf.push(item.tag);
            buf.push(chunk.len() as u8);
            buf.extend_from_slice(chunk);
            rest = &rest[chunk.len()..];
        }
    }
    buf
}

/// Decodes TLV8 bytes into a tag → value map, concatenating chunks of the same
/// tag (matching Go's `append` semantics).
pub fn decode(data: &[u8]) -> HashMap<u8, Vec<u8>> {
    let mut result: HashMap<u8, Vec<u8>> = HashMap::new();
    let mut rest = data;
    while rest.len() >= 2 {
        let tag = rest[0];
        let length = rest[1] as usize;
        rest = &rest[2..];
        if length > rest.len() {
            break;
        }
        result.entry(tag).or_default().extend_from_slice(&rest[..length]);
        rest = &rest[length..];
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_short_values() {
        let items = vec![
            Tlv8Item::new(TLV_METHOD, vec![0x00]),
            Tlv8Item::new(TLV_STATE, vec![0x01]),
            Tlv8Item::new(TLV_PUBLIC_KEY, vec![0xAA; 32]),
        ];
        let encoded = encode_ordered(&items);
        let decoded = decode(&encoded);
        assert_eq!(decoded[&TLV_METHOD], vec![0x00]);
        assert_eq!(decoded[&TLV_STATE], vec![0x01]);
        assert_eq!(decoded[&TLV_PUBLIC_KEY], vec![0xAA; 32]);
    }

    #[test]
    fn splits_values_over_255_bytes() {
        let big = vec![0x77; 600];
        let encoded = encode_ordered(&[Tlv8Item::new(TLV_SALT, big.clone())]);
        // 600 bytes → three records: 255 + 255 + 90
        let mut expected = Vec::new();
        for len in [255usize, 255, 90] {
            expected.push(TLV_SALT);
            expected.push(len as u8);
            expected.extend_from_slice(&big[..len]);
        }
        assert_eq!(encoded, expected);
        let decoded = decode(&encoded);
        assert_eq!(decoded[&TLV_SALT], big);
    }

    #[test]
    fn empty_value_encodes_as_zero_length() {
        let encoded = encode_ordered(&[Tlv8Item::new(TLV_FLAGS, vec![])]);
        assert_eq!(encoded, vec![TLV_FLAGS, 0]);
        let decoded = decode(&encoded);
        assert_eq!(decoded[&TLV_FLAGS], Vec::<u8>::new());
    }

    #[test]
    fn malformed_tail_is_ignored() {
        // Record claims 5 bytes but only 2 remain → stop, like Go.
        let data = [TLV_METHOD, 5, 0x01, 0x02];
        let decoded = decode(&data);
        assert!(!decoded.contains_key(&TLV_METHOD));
    }
}
