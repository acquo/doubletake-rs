//! FairPlay's modified MD5 compression, ported from `fairplay_md5.go`.
//!
//! Standard MD5 rounds and constants, but message words are read big-endian
//! and the message schedule is mutated after round 31. These differences mean
//! the stock `md-5` crate cannot implement these compressions.

use crate::fp_tables_generated::{FAIRPLAY_MD5_CONSTANT, FAIRPLAY_MD5_SHIFT};

/// How the message schedule is mutated after round 31.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FairplayMd5Mutation {
    /// FPSAP swap mutation.
    FpsapSwap,
    /// FPSAP cycle mutation.
    FpsapCycle,
    /// FairPlay KDF mutation.
    FairplayKdf,
}

/// One modified-MD5 compression of a 64-byte block.
pub fn fairplay_md5_compress(
    state: [u32; 4],
    block: &[u8],
    mutation: FairplayMd5Mutation,
) -> [u32; 4] {
    debug_assert_eq!(block.len(), 64);
    // Message words are read big-endian.
    let mut message = [0u32; 16];
    for (i, m) in message.iter_mut().enumerate() {
        *m = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().expect("64-byte block"));
    }

    let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
    for round in 0..64usize {
        let (f, word) = match round {
            0..=15 => ((b & c) | (!b & d), round),
            16..=31 => ((d & b) | (!d & c), (5 * round + 1) & 15),
            32..=47 => (b ^ c ^ d, (3 * round + 5) & 15),
            _ => (c ^ (b | !d), (7 * round) & 15),
        };

        let next_a = d;
        let next_b = b.wrapping_add(
            a.wrapping_add(f)
                .wrapping_add(FAIRPLAY_MD5_CONSTANT[round])
                .wrapping_add(message[word])
                .rotate_left(FAIRPLAY_MD5_SHIFT[round] as u32),
        );
        d = c;
        c = b;
        b = next_b;
        a = next_a;

        if round == 31 {
            mutate_fairplay_md5_message(&mut message, a, b, c, d, mutation);
        }
    }

    [
        state[0].wrapping_add(a),
        state[1].wrapping_add(b),
        state[2].wrapping_add(c),
        state[3].wrapping_add(d),
    ]
}

fn mutate_fairplay_md5_message(
    message: &mut [u32; 16],
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    mutation: FairplayMd5Mutation,
) {
    match mutation {
        FairplayMd5Mutation::FpsapSwap => {
            let indices = [
                (a & 15) as usize, (b & 15) as usize, (c & 15) as usize, (d & 15) as usize,
                ((a >> 4) & 15) as usize, ((b >> 4) & 15) as usize, ((c >> 4) & 15) as usize,
                ((d >> 4) & 15) as usize,
            ];
            for (i, &j) in indices.iter().enumerate() {
                message.swap(i, j);
            }
        }
        FairplayMd5Mutation::FpsapCycle => {
            let indices = [
                (a & 15) as usize, (b & 15) as usize, (c & 15) as usize, (d & 15) as usize,
                ((a >> 4) & 15) as usize, ((b >> 4) & 15) as usize, ((c >> 4) & 15) as usize,
                ((d >> 4) & 15) as usize,
            ];
            let first = message[indices[0]];
            for i in 0..indices.len() - 1 {
                message[indices[i]] = message[indices[i + 1]];
            }
            message[indices[indices.len() - 1]] = first;
        }
        FairplayMd5Mutation::FairplayKdf => {
            message.swap((a & 15) as usize, (b & 15) as usize);
            message.swap((c & 15) as usize, (d & 15) as usize);
            let mut shift = 4u32;
            while shift <= 12 {
                message.swap(((a >> shift) & 15) as usize, ((b >> shift) & 15) as usize);
                shift += 4;
            }
        }
    }
}

/// Reads a 16-byte key as four little-endian words.
pub fn fairplay_words_from_little_endian(input: &[u8; 16]) -> [u32; 4] {
    let mut out = [0u32; 4];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u32::from_le_bytes(input[i * 4..i * 4 + 4].try_into().expect("16-byte input"));
    }
    out
}

/// Writes four words big-endian into 16 bytes.
pub fn fairplay_words_big_endian(words: [u32; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, w) in words.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}
