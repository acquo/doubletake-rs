//! FairPlay message encryption, ported from `fairplay_message.go`.
//!
//! Uses the standard inverse AES round operations but with custom middle
//! round keys rather than AES key schedules, so `aes` cannot represent this
//! block transform.

use crate::error::{Error, Result};
use crate::fp_tables_generated::{
    FAIRPLAY_MESSAGE_IV, FAIRPLAY_MESSAGE_MIDDLE_KEYS, FAIRPLAY_MESSAGE_ROUND_KEY_0,
    FAIRPLAY_MESSAGE_ROUND_KEY_10, INVERSE_AES_SBOX,
};

/// Number of supported FairPlay message modes.
pub const FAIRPLAY_MESSAGE_MODE_COUNT: usize = 4;

/// Forward S-box: inverse of `INVERSE_AES_SBOX`.
fn forward_aes_sbox() -> [u8; 256] {
    let mut table = [0u8; 256];
    for (encrypted, &plaintext) in INVERSE_AES_SBOX.iter().enumerate() {
        table[plaintext as usize] = encrypted as u8;
    }
    table
}

/// Decrypts a FairPlay message body. `message` is the 12+128 byte record;
/// `plaintext` receives 128 bytes.
pub fn decrypt_fairplay_message(message: &[u8], plaintext: &mut [u8]) {
    let mode = message[12];
    for step in 0..8usize {
        let mut block = step;
        if mode == 3 {
            // Mode 3 historically traverses the CBC chain backwards.
            block = 7 - step;
        }
        let start = 16 + block * 16;
        let mut state = [0u8; 16];
        state.copy_from_slice(&message[start..start + 16]);
        decrypt_fairplay_message_block(&mut state, mode);

        let chain: &[u8] = if block > 0 {
            &message[start - 16..start]
        } else {
            &FAIRPLAY_MESSAGE_IV[mode as usize]
        };
        for i in 0..16 {
            plaintext[block * 16 + i] = state[i] ^ chain[i];
        }
    }
}

fn decrypt_fairplay_message_block(state: &mut [u8; 16], mode: u8) {
    xor_aes_round_key(state, &FAIRPLAY_MESSAGE_ROUND_KEY_10);
    for round in (1..10).rev() {
        inverse_aes_shift_rows(state);
        for b in state.iter_mut() {
            *b = INVERSE_AES_SBOX[*b as usize];
        }
        xor_aes_round_key(state, &FAIRPLAY_MESSAGE_MIDDLE_KEYS[mode as usize][round - 1]);
        inverse_aes_mix_columns(state);
    }
    inverse_aes_shift_rows(state);
    for b in state.iter_mut() {
        *b = INVERSE_AES_SBOX[*b as usize];
    }
    xor_aes_round_key(state, &FAIRPLAY_MESSAGE_ROUND_KEY_0);
}

/// Applies the inverse of [`decrypt_fairplay_message`] to one 128-byte SAP
/// value, producing the encrypted body stored at bytes 16:144 of an FPLY
/// message.
pub fn encrypt_fairplay_message(mode: u8, plaintext: &[u8; 128], encrypted: &mut [u8; 128]) -> Result<()> {
    if mode as usize >= FAIRPLAY_MESSAGE_MODE_COUNT {
        return Err(Error::Protocol(format!("unsupported FairPlay mode {mode}")));
    }
    let sbox = forward_aes_sbox();
    let mut chain: [u8; 16] = FAIRPLAY_MESSAGE_IV[mode as usize];
    for block in 0..8usize {
        let start = block * 16;
        let mut state = [0u8; 16];
        for i in 0..16 {
            state[i] = plaintext[start + i] ^ chain[i];
        }
        encrypt_fairplay_message_block(&mut state, mode, &sbox);
        encrypted[start..start + 16].copy_from_slice(&state);
        chain = state;
    }
    Ok(())
}

fn encrypt_fairplay_message_block(state: &mut [u8; 16], mode: u8, sbox: &[u8; 256]) {
    xor_aes_round_key(state, &FAIRPLAY_MESSAGE_ROUND_KEY_0);
    for b in state.iter_mut() {
        *b = sbox[*b as usize];
    }
    aes_shift_rows(state);
    for round in 0..9usize {
        aes_mix_columns(state);
        xor_aes_round_key(state, &FAIRPLAY_MESSAGE_MIDDLE_KEYS[mode as usize][round]);
        for b in state.iter_mut() {
            *b = sbox[*b as usize];
        }
        aes_shift_rows(state);
    }
    xor_aes_round_key(state, &FAIRPLAY_MESSAGE_ROUND_KEY_10);
}

fn xor_aes_round_key(state: &mut [u8; 16], key: &[u8; 16]) {
    for (s, k) in state.iter_mut().zip(key.iter()) {
        *s ^= k;
    }
}

fn inverse_aes_shift_rows(state: &mut [u8; 16]) {
    let previous = *state;
    for row in 0..4 {
        for column in 0..4 {
            state[4 * column + row] = previous[4 * ((column + 4 - row) & 3) + row];
        }
    }
}

fn aes_shift_rows(state: &mut [u8; 16]) {
    let previous = *state;
    for row in 0..4 {
        for column in 0..4 {
            state[4 * column + row] = previous[4 * ((column + row) & 3) + row];
        }
    }
}

fn inverse_aes_mix_columns(state: &mut [u8; 16]) {
    for column in 0..4 {
        let offset = column * 4;
        let (a, b, c, d) = (
            state[offset],
            state[offset + 1],
            state[offset + 2],
            state[offset + 3],
        );
        state[offset] = gf_mul(a, 14) ^ gf_mul(b, 11) ^ gf_mul(c, 13) ^ gf_mul(d, 9);
        state[offset + 1] = gf_mul(a, 9) ^ gf_mul(b, 14) ^ gf_mul(c, 11) ^ gf_mul(d, 13);
        state[offset + 2] = gf_mul(a, 13) ^ gf_mul(b, 9) ^ gf_mul(c, 14) ^ gf_mul(d, 11);
        state[offset + 3] = gf_mul(a, 11) ^ gf_mul(b, 13) ^ gf_mul(c, 9) ^ gf_mul(d, 14);
    }
}

fn aes_mix_columns(state: &mut [u8; 16]) {
    for column in 0..4 {
        let offset = column * 4;
        let (a, b, c, d) = (
            state[offset],
            state[offset + 1],
            state[offset + 2],
            state[offset + 3],
        );
        state[offset] = gf_mul(a, 2) ^ gf_mul(b, 3) ^ c ^ d;
        state[offset + 1] = a ^ gf_mul(b, 2) ^ gf_mul(c, 3) ^ d;
        state[offset + 2] = a ^ b ^ gf_mul(c, 2) ^ gf_mul(d, 3);
        state[offset + 3] = gf_mul(a, 3) ^ b ^ c ^ gf_mul(d, 2);
    }
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    product
}
