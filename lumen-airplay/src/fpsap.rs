//! FPSAP session and white-box networks, ported from `fpsap.go` and
//! `fpsap_tables.go`.

use crate::error::{Error, Result};
use aes::cipher::{BlockEncrypt, KeyInit};
use crate::fairplay_message::{
    decrypt_fairplay_message, encrypt_fairplay_message, FAIRPLAY_MESSAGE_MODE_COUNT,
};
use crate::fairplay_md5::{
    fairplay_md5_compress, fairplay_words_big_endian, fairplay_words_from_little_endian,
    FairplayMd5Mutation,
};
use crate::fairplay_sap::fairplay_sap_hash;
use crate::fp_tables_generated::{
    FAIRPLAY_INITIAL_SESSION_KEY, FPSAP_DESCRIPTOR_PREFIX, FPSAP_DESCRIPTOR_SUFFIX,
    FPSAP_FIRST_INPUT_MASK, FPSAP_FIRST_POSITION_MAP, FPSAP_FIRST_TABLES, FPSAP_FIXED_BLOCK,
    FPSAP_M3_LABEL, FPSAP_MIX_BASES, FPSAP_SECOND_OUTPUT_MASK, FPSAP_SECOND_POSITION_MAP,
    FPSAP_SECOND_TABLES, FPSAP_SUBSTITUTION_BASES, FpsapByteLookup, FpsapNetworkTables,
};

/// m1 capability byte: bit mask, not the message mode.
pub const FPSAP_M1_CAPABILITIES: u8 = 3;

impl FpsapByteLookup {
    fn substitute(&self, value: u8) -> u8 {
        FPSAP_SUBSTITUTION_BASES[self.table as usize][(value ^ self.input_xor) as usize]
            ^ self.output_xor
    }

    fn mix(&self, value: u8) -> u8 {
        FPSAP_MIX_BASES[self.table as usize][(value ^ self.input_xor) as usize] ^ self.output_xor
    }
}

/// Stateful FPSAP lifecycle: one context is created before m1 and reused for
/// m3 and key wrapping.
#[derive(Debug, Clone)]
pub struct FpsapSession {
    pub local_sap: [u8; 128],
    pub remote_sap: [u8; 128],
    pub m3: [u8; 164],
    pub has_m3: bool,
}

impl FpsapSession {
    /// Creates a session; `entropy` must supply 126 opaque SAP bytes.
    pub fn new(entropy: &[u8]) -> Result<Self> {
        if entropy.len() < 126 {
            return Err(Error::Protocol("initialize local SAP: short entropy".into()));
        }
        let mut local_sap = [0u8; 128];
        local_sap[1] = 1;
        local_sap[2..].copy_from_slice(&entropy[..126]);
        Ok(FpsapSession {
            local_sap,
            remote_sap: [0u8; 128],
            m3: [0u8; 164],
            has_m3: false,
        })
    }

    /// The m1 record: FPLY header + capability payload. The capability byte
    /// is a bit mask (`FPSAP_M1_CAPABILITIES`), not the message mode.
    pub fn message1(&self) -> Vec<u8> {
        let mut m1 = new_fpsap_record(1, 4);
        m1[12..16].copy_from_slice(&[0x02, 0x00, FPSAP_M1_CAPABILITIES, 0xbb]);
        m1
    }

    /// Processes m2, producing m3 (FPLY type 3, 152-byte payload).
    pub fn exchange_m3(&mut self, m2: &[u8]) -> Result<Vec<u8>> {
        validate_fpsap_record(m2, 2, 130)?;
        if m2[12] != 2 {
            return Err(Error::Protocol(format!("invalid m2 payload marker {}", m2[12])));
        }
        let mode = m2[13];
        if mode as usize >= FAIRPLAY_MESSAGE_MODE_COUNT {
            return Err(Error::Protocol(format!("m2 selected unsupported mode {mode}")));
        }

        let mut m3 = new_fpsap_record(3, 152);
        m3[12] = mode;
        m3[13..16].copy_from_slice(&FPSAP_M3_LABEL);
        let mut body = [0u8; 128];
        encrypt_fairplay_message(mode, &self.local_sap, &mut body)?;
        m3[16..144].copy_from_slice(&body);

        let mut m2_ciphertext = [0u8; 128];
        m2_ciphertext.copy_from_slice(&m2[14..142]);
        let m2_sap = decrypt_fpsap_body(mode, m2_ciphertext)?;
        let tail = fpsap_exchange_for_sap(&self.local_sap, &m2_sap);
        m3[144..].copy_from_slice(&tail);

        self.remote_sap = m2_sap;
        self.m3.copy_from_slice(&m3);
        self.has_m3 = true;
        Ok(m3)
    }

    /// Confirms m4 against the stored m3.
    pub fn confirm_m4(&self, m4: &[u8]) -> Result<()> {
        if !self.has_m3 {
            return Err(Error::Protocol("m3 has not been generated".into()));
        }
        validate_fpsap_m4(m4, &self.m3)
    }

    /// Wraps `raw_key` in the 72-byte AirPlay v3 ekey record using `mask` as
    /// the per-key random mask.
    pub fn wrap_key(&self, raw_key: [u8; 16], mask: [u8; 16]) -> Result<[u8; 72]> {
        if !self.has_m3 {
            return Err(Error::Protocol("m3 has not been generated".into()));
        }
        wrap_fair_play_key(&self.remote_sap, &self.m3, raw_key, mask)
    }
}

/// Decrypts the 128-byte FPSAP body of an m2/m3 payload.
pub fn decrypt_fpsap_body(mode: u8, payload: [u8; 128]) -> Result<[u8; 128]> {
    if mode as usize >= FAIRPLAY_MESSAGE_MODE_COUNT {
        return Err(Error::Protocol(format!("unsupported FairPlay mode {mode}")));
    }
    let mut message = [0u8; 144];
    message[12] = mode;
    message[16..].copy_from_slice(&payload);
    let mut out = [0u8; 128];
    decrypt_fairplay_message(&message, &mut out);
    Ok(out)
}

/// Derives the 20-byte white-box seed from both halves of an exchange.
pub fn fpsap_descriptor_for_sap(m3_sap: &[u8; 128], m2_sap: &[u8; 128]) -> [u8; 20] {
    let mut padded = [0u8; 320];
    let mut offset = 0;
    offset += copy_into(&mut padded[offset..], &FPSAP_DESCRIPTOR_PREFIX);
    offset += copy_into(&mut padded[offset..], m3_sap);
    offset += copy_into(&mut padded[offset..], m2_sap);
    offset += copy_into(&mut padded[offset..], &FPSAP_DESCRIPTOR_SUFFIX);
    padded[offset] = 0x80;
    padded[312..320].copy_from_slice(&((offset as u64) * 8).to_le_bytes());

    let mut state = fairplay_words_from_little_endian(&FAIRPLAY_INITIAL_SESSION_KEY);
    let mut first_final = [0u32; 4];
    for block_offset in (0..padded.len()).step_by(64) {
        let block = &padded[block_offset..block_offset + 64];
        let add = fairplay_sap_hash(block);
        for i in 0..4 {
            state[i] = state[i].wrapping_add(u32::from_le_bytes([
                add[i * 4],
                add[i * 4 + 1],
                add[i * 4 + 2],
                add[i * 4 + 3],
            ]));
        }
        state = fairplay_md5_compress(state, block, FairplayMd5Mutation::FpsapCycle);
        if block_offset == padded.len() - 64 {
            first_final = state;
            state = fairplay_md5_compress(state, block, FairplayMd5Mutation::FpsapCycle);
        }
    }

    let mut out = [0u8; 20];
    out[..4].copy_from_slice(&first_final[0].to_be_bytes());
    let tail = fairplay_words_big_endian(state);
    out[4..].copy_from_slice(&tail);
    out
}

fn copy_into(dst: &mut [u8], src: &[u8]) -> usize {
    dst[..src.len()].copy_from_slice(src);
    src.len()
}

/// Nine 16-byte masks derived from the exchange seed.
pub fn fpsap_masks(seed: &[u8; 20]) -> [[u8; 16]; 9] {
    let state = [0x1d4a4587u32, 0x92f39fcc, 0x1d87d836, 0xcdc86697];
    let suffix: [u8; 15] = [
        0x57, 0xd8, 0xee, 0xcb, 0xde, 0xfb, 0xcf, 0x59, 0x1c, 0x27, 0xa2, 0xcf, 0xbe, 0xb0, 0x89,
    ];
    let mut masks = [[0u8; 16]; 9];
    for (i, mask) in masks.iter_mut().enumerate() {
        let mut block = [0u8; 64];
        block[..20].copy_from_slice(seed);
        block[20] = i as u8;
        block[21..36].copy_from_slice(&suffix);
        block[36] = 0x80;
        block[56..60].copy_from_slice(&0x320u32.to_le_bytes());
        *mask = fairplay_words_big_endian(fairplay_md5_compress(
            state,
            &block,
            FairplayMd5Mutation::FpsapSwap,
        ));
    }
    masks
}

/// A 16-byte digest of two 16-byte inputs.
fn fpsap_digest32(left: &[u8; 16], right: &[u8; 16]) -> [u8; 16] {
    let mut block = [0u8; 64];
    block[..16].copy_from_slice(left);
    block[16..32].copy_from_slice(right);
    block[32] = 0x80;
    block[56..60].copy_from_slice(&0x100u32.to_le_bytes());
    let state = [0xb9f3dcdcu32, 0xfbdc740b, 0x60f77f86, 0x51907216];
    fairplay_words_big_endian(fairplay_md5_compress(state, &block, FairplayMd5Mutation::FpsapSwap))
}

fn fpsap_first_network(masks: &[[u8; 16]; 9]) -> [u8; 16] {
    let mut state = FPSAP_FIXED_BLOCK;
    for i in 0..16 {
        state[i] ^= FPSAP_FIRST_INPUT_MASK[i];
    }
    for bank in 0..9 {
        let mut substituted = [0u8; 16];
        for (output, &input) in FPSAP_FIRST_POSITION_MAP.iter().enumerate() {
            substituted[output] =
                FPSAP_FIRST_TABLES.round_substitution[bank][input as usize].substitute(state[input as usize]);
        }
        fpsap_mix(&FPSAP_FIRST_TABLES, &mut state, substituted);
        for i in 0..16 {
            state[i] ^= masks[bank][i];
        }
    }
    let mut out = [0u8; 16];
    for (output, &input) in FPSAP_FIRST_POSITION_MAP.iter().enumerate() {
        out[output] = FPSAP_FIRST_TABLES.final_substitution[input as usize]
            .substitute(state[input as usize]);
    }
    out
}

fn fpsap_second_network(state: [u8; 16], masks: &[[u8; 16]; 9]) -> [u8; 16] {
    let mut state = state;
    for bank in (0..9).rev() {
        let mut substituted = [0u8; 16];
        for (output, &input) in FPSAP_SECOND_POSITION_MAP.iter().enumerate() {
            substituted[output] = FPSAP_SECOND_TABLES.round_substitution[bank][output]
                .substitute(state[input as usize])
                ^ masks[bank][output];
        }
        fpsap_mix(&FPSAP_SECOND_TABLES, &mut state, substituted);
    }
    let mut out = [0u8; 16];
    for (output, &input) in FPSAP_SECOND_POSITION_MAP.iter().enumerate() {
        out[output] = FPSAP_SECOND_TABLES.final_substitution[output]
            .substitute(state[input as usize])
            ^ FPSAP_SECOND_OUTPUT_MASK[output];
    }
    out
}

fn fpsap_mix(tables: &FpsapNetworkTables, state: &mut [u8; 16], substituted: [u8; 16]) {
    for word in 0..4 {
        let offset = word * 4;
        for output_byte in 0..4 {
            let mut mixed = 0u8;
            for input_byte in 0..4 {
                mixed ^= tables.mix_columns[input_byte][output_byte].mix(substituted[offset + input_byte]);
            }
            state[offset + output_byte] = mixed;
        }
    }
}

/// The 20-byte exchange value derived from both SAP halves.
pub fn fpsap_exchange_for_sap(m3_sap: &[u8; 128], m2_sap: &[u8; 128]) -> [u8; 20] {
    fpsap_exchange_seed(&fpsap_descriptor_for_sap(m3_sap, m2_sap))
}

fn fpsap_exchange_seed(seed: &[u8; 20]) -> [u8; 20] {
    let masks = fpsap_masks(seed);
    let intermediate = fpsap_first_network(&masks);
    let left = fpsap_digest32(&intermediate, &FPSAP_FIXED_BLOCK);
    let whitebox_output = fpsap_second_network(left, &masks);
    let digest = fpsap_digest32(&left, &whitebox_output);

    let mut out = [0u8; 20];
    out[..4].copy_from_slice(&whitebox_output[..4]);
    out[4..].copy_from_slice(&digest);
    out
}

/// Builds an FPLY record header with the given payload length.
pub fn new_fpsap_record(message_type: u8, payload_length: usize) -> Vec<u8> {
    let mut record = vec![0u8; 12 + payload_length];
    record[..4].copy_from_slice(b"FPLY");
    record[4..8].copy_from_slice(&[3, 1, message_type, 0]);
    record[8..12].copy_from_slice(&(payload_length as u32).to_be_bytes());
    record
}

/// Validates an FPLY record's header and length.
pub fn validate_fpsap_record(record: &[u8], message_type: u8, payload_length: usize) -> Result<()> {
    let want_length = 12 + payload_length;
    if record.len() != want_length {
        return Err(Error::Protocol(format!(
            "length {}, want {}",
            record.len(),
            want_length
        )));
    }
    if &record[..4] != b"FPLY" {
        return Err(Error::Protocol(format!("invalid magic {:02x?}", &record[..4])));
    }
    if record[4] != 3 || record[5] != 1 || record[6] != message_type || record[7] != 0 {
        return Err(Error::Protocol(format!(
            "invalid version/type {:02x?}",
            &record[4..8]
        )));
    }
    let got = u32::from_be_bytes(record[8..12].try_into().expect("4 bytes")) as usize;
    if got != payload_length {
        return Err(Error::Protocol(format!(
            "declared payload length {got}, want {payload_length}"
        )));
    }
    Ok(())
}

/// Validates an m4 record's confirmation against m3.
pub fn validate_fpsap_m4(m4: &[u8], m3: &[u8]) -> Result<()> {
    validate_fpsap_record(m4, 4, 20)?;
    if m3.len() != 164 {
        return Err(Error::Protocol(format!("invalid m3 length {}", m3.len())));
    }
    if m4[12..] != m3[144..] {
        return Err(Error::Protocol("m4 confirmation does not match m3".into()));
    }
    Ok(())
}

/// Wraps `raw_key` in the 72-byte AirPlay v3 ekey record:
///
/// [0:16]  FPLY encrypted-key header
/// [16:32] per-key random mask
/// [32:36] big-endian raw-key length (16)
/// [36:56] HMAC-SHA1(session MAC key, record[0:36] || raw key)
/// [56:72] AES-wrapped (raw key XOR mask)
pub fn wrap_fair_play_key(
    receiver_sap: &[u8; 128],
    m3: &[u8],
    raw_key: [u8; 16],
    mask: [u8; 16],
) -> Result<[u8; 72]> {
    let mut ekey = [0u8; 72];
    validate_fpsap_record(m3, 3, 152)?;
    let mode = m3[12];
    if mode as usize >= FAIRPLAY_MESSAGE_MODE_COUNT {
        return Err(Error::Protocol(format!("unsupported FairPlay mode {mode}")));
    }

    ekey[..16].copy_from_slice(&[
        b'F', b'P', b'L', b'Y', 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00,
        0x00, 0x00,
    ]);
    ekey[16..32].copy_from_slice(&mask);
    ekey[32..36].copy_from_slice(&(raw_key.len() as u32).to_be_bytes());

    let wrapping_key = derive_fairplay_wrapping_key(receiver_sap, m3);
    let mut masked = [0u8; 16];
    for i in 0..16 {
        masked[i] = raw_key[i] ^ ekey[16 + i];
    }
    let cipher = aes::Aes128::new_from_slice(&wrapping_key)
        .map_err(|e| Error::Crypto(format!("create FairPlay wrapping cipher: {e}")))?;
    let mut block = aes::Block::from(masked);
    cipher.encrypt_block(&mut block);
    ekey[56..72].copy_from_slice(&block);

    let mut sender_sap = [0u8; 128];
    let mut sender_sap_buf = [0u8; 128];
    decrypt_fairplay_message(m3, &mut sender_sap_buf);
    sender_sap.copy_from_slice(&sender_sap_buf);
    let mac_key = fpsap_descriptor_for_sap(&sender_sap, receiver_sap);

    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&mac_key)
        .map_err(|e| Error::Crypto(format!("hmac key: {e}")))?;
    mac.update(&ekey[..36]);
    mac.update(&raw_key);
    ekey[36..56].copy_from_slice(&mac.finalize().into_bytes());

    Ok(ekey)
}

/// Derives the 16-byte FairPlay wrapping key from a receiver SAP and message.
pub fn derive_fairplay_wrapping_key(receiver_sap: &[u8; 128], message: &[u8]) -> [u8; 16] {
    let mut decrypted = [0u8; 128];
    decrypt_fairplay_message(message, &mut decrypted);

    // KDF input: 290-byte protocol record followed by MD5 padding.
    let mut material = [0u8; 320];
    let mut offset = 0;
    offset += copy_into(&mut material[offset..], &crate::fp_tables_generated::FAIRPLAY_KDF_PREFIX);
    offset += copy_into(&mut material[offset..], &decrypted);
    offset += copy_into(&mut material[offset..], receiver_sap);
    offset += copy_into(&mut material[offset..], &crate::fp_tables_generated::FAIRPLAY_KDF_SUFFIX);
    material[offset] = 0x80;
    material[312..320].copy_from_slice(&((offset as u64) * 8).to_le_bytes());

    let mut state = fairplay_words_from_little_endian(&crate::fp_tables_generated::FAIRPLAY_INITIAL_SESSION_KEY);
    for block_offset in (0..material.len()).step_by(64) {
        let block = &material[block_offset..block_offset + 64];
        let modified = fairplay_md5_compress(state, block, FairplayMd5Mutation::FairplayKdf);
        let hashed = fairplay_sap_hash(block);
        for word in 0..4 {
            state[word] = modified[word].wrapping_add(u32::from_le_bytes([
                hashed[word * 4],
                hashed[word * 4 + 1],
                hashed[word * 4 + 2],
                hashed[word * 4 + 3],
            ]));
        }
    }
    fairplay_words_big_endian(state)
}
