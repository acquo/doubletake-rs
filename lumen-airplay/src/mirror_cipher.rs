//! Mirroring stream encryption, ported from `client.go` (mirrorCipher) and
//! `mirror.go` (key derivation).

use crate::error::{Error, Result};
use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes128;
use ctr::Ctr128BE;
use sha2::{Digest, Sha512};

/// AES-128-CTR stream cipher implementing the AirPlay mirroring encryption
/// scheme matching the receiver's `mirror_buffer_decrypt` exactly:
///
/// 1. XOR the first `next_crypt_count` bytes with cached keystream left over
///    from the previous frame's trailing partial block.
/// 2. Advance CTR to the next 16-byte boundary.
/// 3. Encrypt full 16-byte blocks.
/// 4. Pad the trailing partial block to 16 bytes, encrypt, use the needed
///    bytes, and cache the remaining keystream for the next frame.
pub struct MirrorCipher {
    stream: Ctr128BE<Aes128>,
    block_offset: usize,
    og: [u8; 16],
    next_crypt_count: usize,
}

impl MirrorCipher {
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Result<Self> {
        let stream = Ctr128BE::<Aes128>::new(key.into(), iv.into());
        Ok(MirrorCipher {
            stream,
            block_offset: 0,
            og: [0u8; 16],
            next_crypt_count: 0,
        })
    }

    /// Encrypts one video frame payload.
    pub fn encrypt_frame(&mut self, payload: &[u8]) -> Vec<u8> {
        let input_len = payload.len();
        let mut out = vec![0u8; input_len];
        let mut pos = 0;

        // Step 1: prefix from cached keystream of the previous frame's tail.
        if self.next_crypt_count > 0 {
            let n = self.next_crypt_count.min(input_len);
            let og_start = 16 - self.next_crypt_count;
            for i in 0..n {
                out[i] = payload[i] ^ self.og[og_start + i];
            }
            pos = n;
        }

        // Step 2: advance CTR to the next 16-byte boundary.
        if self.block_offset > 0 {
            let mut waste = vec![0u8; 16 - self.block_offset];
            self.stream.apply_keystream(&mut waste);
            self.block_offset = 0;
        }

        let remaining = input_len - pos;

        // Step 3: full 16-byte blocks.
        let full_blocks = (remaining / 16) * 16;
        if full_blocks > 0 {
            let mut block_buf = payload[pos..pos + full_blocks].to_vec();
            self.stream.apply_keystream(&mut block_buf);
            out[pos..pos + full_blocks].copy_from_slice(&block_buf);
            pos += full_blocks;
        }

        // Step 4: trailing partial block.
        let rest_len = remaining % 16;
        self.next_crypt_count = 0;
        if rest_len > 0 {
            let mut padded = [0u8; 16];
            padded[..rest_len].copy_from_slice(&payload[pos..pos + rest_len]);
            self.stream.apply_keystream(&mut padded);
            out[pos..pos + rest_len].copy_from_slice(&padded[..rest_len]);
            self.og = padded;
            self.next_crypt_count = 16 - rest_len;
            self.block_offset = 0;
        }

        out
    }
}

/// Derives the AES-128-CTR key/IV for video encryption:
/// SHA-512("AirPlayStreamKey<id>" + shk)[:16] and
/// SHA-512("AirPlayStreamIV<id>" + shk)[:16].
pub fn derive_video_keys(shk: &[u8], stream_connection_id: u64) -> ([u8; 16], [u8; 16]) {
    let mut key_h = Sha512::new();
    key_h.update(format!("AirPlayStreamKey{stream_connection_id}").as_bytes());
    key_h.update(shk);
    let mut key = [0u8; 16];
    key.copy_from_slice(&key_h.finalize()[..16]);

    let mut iv_h = Sha512::new();
    iv_h.update(format!("AirPlayStreamIV{stream_connection_id}").as_bytes());
    iv_h.update(shk);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&iv_h.finalize()[..16]);

    (key, iv)
}

/// Derives the 32-byte ChaCha20-Poly1305 key for the encrypted video data
/// stream: HKDF-SHA512 with IKM = pair-verify shared secret (or raw FP key),
/// salt = "DataStream-Salt<id>", info = "DataStream-Output-Encryption-Key".
pub fn derive_chacha_key(ikm: &[u8], stream_connection_id: u64) -> Result<[u8; 32]> {
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha512>::new(
        Some(format!("DataStream-Salt{stream_connection_id}").as_bytes()),
        ikm,
    );
    let mut key = [0u8; 32];
    hk.expand(b"DataStream-Output-Encryption-Key", &mut key)
        .map_err(|e| Error::Crypto(format!("hkdf expand: {e}")))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_against_decrypt() {
        // A single frame, no cross-frame carry.
        let key = [1u8; 16];
        let iv = [2u8; 16];
        let mut cipher = MirrorCipher::new(&key, &iv).unwrap();
        let payload: Vec<u8> = (0..100u8).collect();
        let encrypted = cipher.encrypt_frame(&payload);

        // Decrypt with the same scheme (XOR is its own inverse).
        let mut decryptor = MirrorCipher::new(&key, &iv).unwrap();
        let decrypted = decryptor.encrypt_frame(&encrypted);
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn multi_frame_carry() {
        let key = [3u8; 16];
        let iv = [4u8; 16];
        let mut cipher = MirrorCipher::new(&key, &iv).unwrap();
        let mut decryptor = MirrorCipher::new(&key, &iv).unwrap();

        // Frame sizes chosen to leave trailing partial blocks (33, then 10).
        for size in [33usize, 10, 48, 7] {
            let payload: Vec<u8> = (0..size as u8).cycle().take(size).collect();
            let encrypted = cipher.encrypt_frame(&payload);
            let decrypted = decryptor.encrypt_frame(&encrypted);
            assert_eq!(decrypted, payload, "size {size}");
        }
    }

    #[test]
    fn derive_keys_deterministic() {
        let (k1, v1) = derive_video_keys(b"key-material", 42);
        let (k2, v2) = derive_video_keys(b"key-material", 42);
        assert_eq!(k1, k2);
        assert_eq!(v1, v2);
        assert_eq!(k1.len(), 16);
        // Different stream IDs → different keys.
        let (k3, _) = derive_video_keys(b"key-material", 43);
        assert_ne!(k1, k3);
    }

    #[test]
    fn chacha_key_derivation() {
        let k = derive_chacha_key(&[9u8; 32], 1234).unwrap();
        assert_eq!(k.len(), 32);
        let k2 = derive_chacha_key(&[9u8; 32], 1234).unwrap();
        assert_eq!(k, k2);
        let k3 = derive_chacha_key(&[9u8; 32], 1235).unwrap();
        assert_ne!(k, k3);
    }
}
